"""Validate operator-supplied context separately from event labels."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path

from .events import parse_time


def digest(value: object) -> str:
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def _keys(value: dict, required: set[str], optional: set[str] = frozenset()) -> None:
    if not isinstance(value, dict) or not required <= value.keys() or value.keys() - required - optional:
        raise ValueError("invalid policy keys; required=" + ",".join(sorted(required)))


def _texts(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(isinstance(x, str) and bool(x) and "*" not in x for x in value)


def validate_policy(policy: dict) -> dict:
    _keys(policy, {"version", "scope", "burst", "monitor_profiles", "approvals"})
    if policy["version"] != 1:
        raise ValueError("unsupported policy version")
    _keys(policy["scope"], {"namespaces", "service_accounts_only"})
    if not _texts(policy["scope"]["namespaces"]) or type(policy["scope"]["service_accounts_only"]) is not bool:
        raise ValueError("invalid scope")
    _keys(policy["burst"], {"window_seconds", "request_threshold", "resource_threshold"})
    for key, limit in (("window_seconds", 3600), ("request_threshold", 10000), ("resource_threshold", 100)):
        val = policy["burst"][key]
        if type(val) is not int or not 1 <= val <= limit:
            raise ValueError("invalid burst " + key)
    if not isinstance(policy["monitor_profiles"], list) or not isinstance(policy["approvals"], list):
        raise ValueError("profiles and approvals must be arrays")
    seen = set()
    for profile in policy["monitor_profiles"]:
        _keys(profile, {"actor", "namespace", "resources", "verbs", "request_threshold"})
        for key in ("actor", "namespace"):
            if not isinstance(profile[key], str) or not profile[key] or "*" in profile[key]:
                raise ValueError("monitor profile must have exact identity/namespace")
        if not _texts(profile["resources"]) or not _texts(profile["verbs"]):
            raise ValueError("invalid monitor profile resources/verbs")
        if not set(profile["resources"]) <= {"pods", "services", "configmaps"} or not set(profile["verbs"]) <= {"get", "list"}:
            raise ValueError("monitor profile permits only non-sensitive read APIs")
        threshold = profile["request_threshold"]
        if type(threshold) is not int or not policy["burst"]["request_threshold"] <= threshold <= 10000:
            raise ValueError("invalid monitor threshold")
        key = (profile["actor"], profile["namespace"])
        if key in seen:
            raise ValueError("duplicate monitor profile")
        seen.add(key)
    ids = set()
    for approval in policy["approvals"]:
        _keys(approval, {"id", "actor", "namespace", "api_group", "resource", "subresource", "name", "verb", "not_before", "not_after", "reason"})
        for key, value in approval.items():
            if not isinstance(value, str) or "*" in value:
                raise ValueError("approval fields must be exact strings")
            if not value and key not in {"api_group", "subresource"}:
                raise ValueError("empty approval " + key)
        if approval["resource"] != "secrets" or approval["subresource"] or approval["api_group"] or approval["verb"] != "get":
            raise ValueError("only a named core Secret GET can be approved")
        if parse_time(approval["not_before"]) >= parse_time(approval["not_after"]):
            raise ValueError("approval must have a bounded, positive validity period")
        if approval["id"] in ids:
            raise ValueError("duplicate approval id")
        ids.add(approval["id"])
    return deepcopy(policy)


def load_policy(path: str | Path) -> dict:
    return validate_policy(json.loads(Path(path).read_text(encoding="utf-8-sig")))
