"""Multi-window detection and credential-bound, budgeted work approvals.

B3 uses conservative Secret alerts and long-window enumeration.
B4 additionally matches independently issued work approvals to API-verified
credential IDs. Missing context fails closed (alert), not silently normal.
"""

from collections import defaultdict, deque
from copy import deepcopy
from datetime import timedelta
import re

from .detector import detect
from .events import iso_time, parse_time
from .policy import digest


def validate_context(context):
    if (not isinstance(context, dict) or not {"version", "long_window", "intents"} <= set(context)
            or set(context) - {"version", "long_window", "intents", "resource_profiles"} or context["version"] != 1):
        raise ValueError("invalid advanced context")
    window = context["long_window"]
    if set(window) != {"window_seconds", "request_threshold", "resource_threshold", "monitor_threshold"}:
        raise ValueError("invalid long window")
    for key, maximum in (("window_seconds", 3600), ("request_threshold", 10000),
                         ("resource_threshold", 100), ("monitor_threshold", 10000)):
        if type(window[key]) is not int or not 1 <= window[key] <= maximum:
            raise ValueError("invalid long window " + key)
    if window["monitor_threshold"] < window["request_threshold"]:
        raise ValueError("monitor threshold below base")
    if not isinstance(context["intents"], list):
        raise ValueError("intents must be a list")
    profiles = context.get("resource_profiles", [])
    if not isinstance(profiles, list):
        raise ValueError("invalid resource profiles")
    seen_profiles = set()
    for profile in profiles:
        if set(profile) != {"actor", "namespace", "resource", "request_threshold"}:
            raise ValueError("invalid resource profile keys")
        key = (profile["actor"], profile["namespace"], profile["resource"])
        if (not all(isinstance(x, str) and x and "*" not in x for x in key)
                or profile["resource"] not in {"pods", "services", "configmaps"}
                or key in seen_profiles or type(profile["request_threshold"]) is not int
                or not 1 <= profile["request_threshold"] <= 10000):
            raise ValueError("invalid or duplicate resource profile")
        seen_profiles.add(key)
    ids, credentials = set(), set()
    for intent in context["intents"]:
        required = {"id", "actor", "namespace", "credential_id_hash", "not_before",
                    "not_after", "max_requests", "actions", "reason"}
        if set(intent) != required:
            raise ValueError("invalid intent keys")
        for key in ("id", "actor", "namespace", "reason"):
            if not isinstance(intent[key], str) or not intent[key] or "*" in intent[key]:
                raise ValueError("intent requires exact fields")
        if not re.fullmatch(r"[0-9a-f]{64}", intent["credential_id_hash"]):
            raise ValueError("invalid credential hash")
        if intent["id"] in ids or intent["credential_id_hash"] in credentials:
            raise ValueError("duplicate intent/credential")
        ids.add(intent["id"])
        credentials.add(intent["credential_id_hash"])
        if parse_time(intent["not_before"]) >= parse_time(intent["not_after"]):
            raise ValueError("invalid intent validity")
        if type(intent["max_requests"]) is not int or not 1 <= intent["max_requests"] <= 100:
            raise ValueError("invalid intent budget")
        if not isinstance(intent["actions"], list) or not intent["actions"]:
            raise ValueError("empty intent actions")
        for action in intent["actions"]:
            if set(action) != {"resource", "verb", "name"} or not all(isinstance(v, str) and "*" not in v for v in action.values()):
                raise ValueError("invalid intent action")
            if action["resource"] == "secrets":
                if action["verb"] != "get" or not action["name"]:
                    raise ValueError("only named Secret GET can be approved")
            elif action["resource"] not in {"pods", "services", "configmaps"} or action["verb"] not in {"get", "list"}:
                raise ValueError("intent cannot approve sensitive/write APIs")
            if action["verb"] == "get" and not action["name"]:
                raise ValueError("GET intent needs an exact object")
            if action["verb"] == "list" and action["name"]:
                raise ValueError("LIST intent cannot have an object name")
    return deepcopy(context)


def intent_match(event, intent):
    return (
        event.actor == event.caller == intent["actor"]
        and event.namespace == intent["namespace"]
        and event.credential_id_hash == intent["credential_id_hash"]
        and not event.api_group and not event.subresource
        and 200 <= event.code < 300
        and parse_time(intent["not_before"]) <= event.time < parse_time(intent["not_after"])
        and {"resource": event.resource, "verb": event.verb, "name": event.name} in intent["actions"]
    )


def detect_advanced(events, policy, context, mode="b4", disabled=frozenset()):
    if mode not in {"b3", "b4"} or disabled - {"long_window", "credential_intents", "resource_profile"}:
        raise ValueError("invalid advanced mode/ablation")
    context = validate_context(context)
    # Weak actor-only approvals are never used by either new configuration.
    conservative = deepcopy(policy)
    conservative["approvals"] = []
    events = sorted(events, key=lambda e: (e.time, e.audit_id))
    accepted, retained, budget_alerts = [], [], []
    usage = defaultdict(int)
    for event in events:
        matched = None
        in_scope = (event.namespace in policy["scope"]["namespaces"]
                    and (not policy["scope"]["service_accounts_only"] or event.actor.startswith("system:serviceaccount:")))
        if in_scope and mode == "b4" and "credential_intents" not in disabled:
            matched = next((i for i in context["intents"] if intent_match(event, i)), None)
        if matched and usage[matched["id"]] < matched["max_requests"]:
            usage[matched["id"]] += 1
            accepted.append({"rule": "I1", "audit_id": event.audit_id,
                             "intent_id": matched["id"], "credential_id_hash": event.credential_id_hash,
                             "reason": "exact credential, action, time and remaining budget",
                             "used": usage[matched["id"]], "budget": matched["max_requests"]})
        else:
            retained.append(event)
            if matched:
                budget_alerts.append({"rule": "R5", "title": "승인 토큰 요청 한도 초과",
                                     "actor": event.actor, "namespace": event.namespace,
                                     "time": iso_time(event.time), "evidence": [event.metadata()],
                                     "evidence_count": 1, "intent_id": matched["id"]})
    result = detect(retained, conservative, "b2")
    result.mode = mode
    result.policy_sha256 = digest({"policy": policy, "context": context})
    result.inspected_events += len(accepted)
    result.suppressed.extend(accepted)
    result.findings.extend(budget_alerts)
    spec = context["long_window"]
    horizon = timedelta(seconds=spec["window_seconds"])
    windows, last, resource_windows, resource_last = defaultdict(deque), {}, defaultdict(deque), {}
    for event in retained:
        if (event.namespace not in policy["scope"]["namespaces"]
                or (policy["scope"]["service_accounts_only"] and not event.actor.startswith("system:serviceaccount:"))
                or event.api_group or event.subresource or event.verb != "list"
                or event.resource not in {"pods", "services", "configmaps"}):
            continue
        window = windows[event.key]
        window.append(event)
        while event.time - window[0].time > horizon:
            window.popleft()
        limit = spec["request_threshold"]
        for profile in policy["monitor_profiles"]:
            if ((profile["actor"], profile["namespace"]) == event.key
                    and all(e.actor == e.caller and 200 <= e.code < 300
                            and e.resource in profile["resources"] and e.verb in profile["verbs"] for e in window)):
                limit = spec["monitor_threshold"]
        resources = len({e.resource for e in window})
        if "long_window" not in disabled and len(window) >= limit and resources >= spec["resource_threshold"]:
            if event.key not in last or event.time - last[event.key] >= horizon:
                result.findings.append({"rule": "R4", "title": "장기 누적 다종 목록 조회",
                                       "actor": event.actor, "namespace": event.namespace,
                                       "time": iso_time(event.time), "evidence_count": len(window),
                                       "evidence": [e.metadata() for e in window],
                                       "window_seconds": spec["window_seconds"], "request_threshold": limit,
                                       "resource_count": resources})
                last[event.key] = event.time
        if "resource_profile" in disabled:
            continue
        resource_key = (*event.key, event.resource)
        profile = next((p for p in context.get("resource_profiles", [])
                        if (p["actor"], p["namespace"], p["resource"]) == resource_key), None)
        if profile:
            resource_window = resource_windows[resource_key]
            resource_window.append(event)
            while event.time - resource_window[0].time > horizon:
                resource_window.popleft()
            if len(resource_window) >= profile["request_threshold"]:
                if resource_key not in resource_last or event.time - resource_last[resource_key] >= horizon:
                    result.findings.append({"rule": "R6", "title": "계정·리소스별 정상 조회 한도 초과",
                        "actor": event.actor, "namespace": event.namespace, "time": iso_time(event.time),
                        "evidence_count": len(resource_window), "evidence": [e.metadata() for e in resource_window],
                        "window_seconds": spec["window_seconds"], "request_threshold": profile["request_threshold"]})
                    resource_last[resource_key] = event.time
    return result
