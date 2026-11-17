"""B0 denied request; B1 behavior; B2 bounded operational context.

This is a batch detector, not a credential-theft oracle. A finding is a reason
to investigate. 403 means the request was rejected, never that it succeeded.
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta

from .events import Event, iso_time, parse_time
from .policy import digest, validate_policy


MODES = ("b0", "b1", "b2")
RULES = {"R0": "권한 거부", "R1": "Secret 읽기 시도", "R2": "Pod 원격 실행 API", "R3": "짧은 시간의 다종 리소스 조회"}


@dataclass
class Detection:
    mode: str
    policy_sha256: str
    inspected_events: int = 0
    out_of_scope: int = 0
    findings: list[dict] = field(default_factory=list)
    suppressed: list[dict] = field(default_factory=list)

    @property
    def prediction(self) -> str:
        return "alert" if self.findings else "normal"


def _approved(event: Event, policy: dict) -> dict | None:
    if not 200 <= event.code < 300 or event.actor != event.caller:
        return None
    fields = ("actor", "namespace", "api_group", "resource", "subresource", "name", "verb")
    for approval in policy["approvals"]:
        if all(getattr(event, key) == approval[key] for key in fields) and parse_time(approval["not_before"]) <= event.time < parse_time(approval["not_after"]):
            return approval
    return None


def _burst_threshold(window: list[Event], policy: dict, mode: str) -> int:
    base = policy["burst"]["request_threshold"]
    if mode != "b2":
        return base
    first = window[0]
    for profile in policy["monitor_profiles"]:
        if (profile["actor"], profile["namespace"]) != first.key:
            continue
        if all(e.actor == e.caller and e.api_group == "" and not e.subresource and e.resource in profile["resources"] and e.verb in profile["verbs"] and 200 <= e.code < 300 for e in window):
            return profile["request_threshold"]
    return base


def detect(events: list[Event], policy: dict, mode: str = "b2", disabled: frozenset[str] = frozenset()) -> Detection:
    policy = validate_policy(policy)
    if mode not in MODES or disabled - RULES.keys():
        raise ValueError("invalid detector mode/rule")
    result = Detection(mode=mode, policy_sha256=digest(policy))
    window_size = timedelta(seconds=policy["burst"]["window_seconds"])
    windows: dict[tuple[str, str], deque] = defaultdict(deque)
    last_burst: dict[tuple[str, str], object] = {}

    def emit(rule: str, evidence: list[Event], extra: dict | None = None) -> None:
        current = evidence[-1]
        # IDs, time and safe metadata are sufficient to trace each decision.
        result.findings.append({
            "rule": rule, "title": RULES[rule], "actor": current.actor,
            "caller": current.caller, "namespace": current.namespace,
            "time": iso_time(current.time),
            "outcome": "denied_attempt" if current.code == 403 else "observed_api_activity",
            "evidence_count": len(evidence), "evidence": [e.metadata() for e in evidence],
            **(extra or {}),
        })

    for event in sorted(events, key=lambda e: (e.time, e.audit_id)):
        scope = policy["scope"]
        if event.namespace not in scope["namespaces"] or (scope["service_accounts_only"] and not event.actor.startswith("system:serviceaccount:")):
            result.out_of_scope += 1
            continue
        result.inspected_events += 1
        if mode == "b0":
            if event.code == 403 and "R0" not in disabled:
                emit("R0", [event])
            continue
        if event.api_group == "" and event.resource == "secrets" and not event.subresource and event.verb in {"get", "list", "watch"} and "R1" not in disabled:
            approval = _approved(event, policy) if mode == "b2" else None
            if approval:
                result.suppressed.append({"rule": "R1", "audit_id": event.audit_id, "approval_id": approval["id"], "reason": approval["reason"]})
            else:
                emit("R1", [event])
        if event.api_group == "" and event.resource == "pods" and event.subresource == "exec" and event.verb in {"get", "create"} and "R2" not in disabled:
            emit("R2", [event])
        if event.verb not in {"get", "list"} or event.subresource or "R3" in disabled:
            continue
        window = windows[event.key]
        window.append(event)
        # Closed interval [t-W, t]; equality counts and is regression-tested.
        while window and event.time - window[0].time > window_size:
            window.popleft()
        threshold = _burst_threshold(list(window), policy, mode)
        diversity = len({(e.api_group, e.resource) for e in window})
        if len(window) >= threshold and diversity >= policy["burst"]["resource_threshold"]:
            previous = last_burst.get(event.key)
            if previous is None or event.time - previous >= window_size:
                emit("R3", list(window), {"window_seconds": window_size.total_seconds(), "request_threshold": threshold, "resource_count": diversity})
                last_burst[event.key] = event.time
    return result
