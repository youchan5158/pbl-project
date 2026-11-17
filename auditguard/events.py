"""Normalize audit JSONL; only explicitly selected metadata can reach findings.

File names, labels, annotations, request bodies and query parameters are never
features. Offline input is sorted by request time. A final stage supersedes a
ResponseStarted stage for the same auditID, so streaming requests count once.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import hashlib
from pathlib import Path
from typing import Iterable


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp must include a UTC offset")
    return result.astimezone(timezone.utc)


def iso_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class Event:
    audit_id: str
    time: datetime
    actor: str
    caller: str
    namespace: str
    api_group: str
    resource: str
    subresource: str
    name: str
    verb: str
    code: int
    stage: str
    source_ips: tuple[str, ...]
    user_agent: str
    credential_id_hash: str = ""

    @property
    def key(self) -> tuple[str, str]:
        return self.actor, self.namespace

    def metadata(self) -> dict:
        result = asdict(self)
        if not self.credential_id_hash:
            result.pop("credential_id_hash")
        result["time"] = iso_time(self.time)
        result["source_ips"] = list(self.source_ips)
        return result


@dataclass
class ReadStats:
    lines: int = 0
    decoded: int = 0
    malformed: int = 0
    ignored_stage: int = 0
    non_resource: int = 0
    duplicates: int = 0
    conflicting_ids: int = 0
    events: int = 0
    # Never include malformed source text: it could contain a credential.
    errors: list[dict] = field(default_factory=list)


STAGES = {"ResponseStarted": 1, "ResponseComplete": 2, "Panic": 3}


def _string(obj: dict, key: str, required: bool = False) -> str:
    value = obj.get(key, "")
    if not isinstance(value, str) or (required and not value):
        raise ValueError("invalid " + key)
    return value


def normalize(raw: dict) -> Event | None:
    if not isinstance(raw, dict) or raw.get("kind") != "Event":
        raise ValueError("expected an audit Event")
    if raw.get("apiVersion") != "audit.k8s.io/v1":
        raise ValueError("expected audit.k8s.io/v1")
    if raw.get("stage") not in STAGES:
        return None
    ref = raw.get("objectRef", {})
    if not isinstance(ref, dict):
        raise ValueError("invalid objectRef")
    if not ref.get("resource"):
        return None
    user = raw.get("user", {})
    effective = raw.get("impersonatedUser", user)
    if not isinstance(user, dict) or not isinstance(effective, dict):
        raise ValueError("invalid user")
    status = raw.get("responseStatus", {})
    if not isinstance(status, dict):
        raise ValueError("invalid responseStatus")
    code = status.get("code")
    if type(code) is not int or not 100 <= code <= 599:
        raise ValueError("invalid response code")
    ips = raw.get("sourceIPs", [])
    if not isinstance(ips, list) or not all(isinstance(x, str) for x in ips):
        raise ValueError("invalid sourceIPs")
    # Only the API authenticator's credential identifier is accepted. Never
    # derive identity from userAgent, request annotations or a bearer token.
    extra = effective.get("extra", {})
    if not isinstance(extra, dict):
        raise ValueError("invalid user extra")
    credential = extra.get("authentication.kubernetes.io/credential-id", [])
    if not isinstance(credential, list) or len(credential) > 1 or not all(isinstance(x, str) and x for x in credential):
        raise ValueError("invalid credential identifier")
    credential_hash = hashlib.sha256(credential[0].encode()).hexdigest() if credential else ""
    return Event(
        audit_id=_string(raw, "auditID", True),
        time=parse_time(raw.get("requestReceivedTimestamp")),
        actor=_string(effective, "username", True),
        caller=_string(user, "username", True),
        namespace=_string(ref, "namespace"),
        api_group=_string(ref, "apiGroup"),
        resource=_string(ref, "resource", True),
        subresource=_string(ref, "subresource"),
        name=_string(ref, "name"),
        verb=_string(raw, "verb", True),
        code=code,
        stage=raw["stage"],
        source_ips=tuple(ips),
        user_agent=_string(raw, "userAgent"),
        credential_id_hash=credential_hash,
    )


def read_events(path: str | Path) -> tuple[list[Event], ReadStats]:
    stats = ReadStats()
    by_id: dict[str, Event] = {}
    conflicts: set[str] = set()
    with Path(path).open(encoding="utf-8-sig") as handle:
        for line_number, line in enumerate(handle, 1):
            stats.lines += 1
            if not line.strip():
                continue
            try:
                decoded = json.loads(line)
                # Kubernetes webhook batches may contain EventList objects.
                items = decoded.get("items") if isinstance(decoded, dict) and decoded.get("kind") == "EventList" else [decoded]
                if not isinstance(items, list):
                    raise ValueError("invalid EventList")
            except (ValueError, TypeError):
                stats.malformed += 1
                stats.errors.append({"line": line_number, "reason": "invalid JSON/EventList"})
                continue
            for raw in items:
                stats.decoded += 1
                try:
                    event = normalize(raw)
                except (ValueError, TypeError, AttributeError):
                    stats.malformed += 1
                    stats.errors.append({"line": line_number, "reason": "invalid audit fields"})
                    continue
                if event is None:
                    if isinstance(raw, dict) and raw.get("stage") not in STAGES:
                        stats.ignored_stage += 1
                    else:
                        stats.non_resource += 1
                    continue
                if event.audit_id in conflicts:
                    continue
                previous = by_id.get(event.audit_id)
                if previous:
                    stats.duplicates += 1
                    # Same ID may have different response code/stage, but must
                    # still describe the same request, identity and object.
                    identity = lambda e: (e.time, e.actor, e.caller, e.namespace, e.api_group, e.resource, e.subresource, e.name, e.verb, e.credential_id_hash)
                    if identity(previous) != identity(event):
                        conflicts.add(event.audit_id)
                        stats.conflicting_ids += 1
                        del by_id[event.audit_id]
                        continue
                    if previous.stage == event.stage and previous.code != event.code:
                        conflicts.add(event.audit_id)
                        stats.conflicting_ids += 1
                        del by_id[event.audit_id]
                        continue
                    if STAGES[event.stage] <= STAGES[previous.stage]:
                        continue
                by_id[event.audit_id] = event
    result = sorted(by_id.values(), key=lambda e: (e.time, e.audit_id))
    stats.events = len(result)
    return result, stats


def write_json(path: str | Path, value: object) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")


def write_jsonl(path: str | Path, values: Iterable[dict]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("w", encoding="utf-8", newline="\n") as handle:
        for value in values:
            handle.write(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n")
