"""B5 audit normalization: all identities/scopes, bounded structural features.

Secret values, token strings, environment values and raw exec commands never
enter findings. The original B4 parser remains unchanged for fair comparison.
"""

from dataclasses import asdict, dataclass, field
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, unquote, urlsplit

from .events import Event, ReadStats, STAGES, normalize as old_normalize
from .policy import digest

PREFIXES = {"pods": ("spec",), "deployments": ("spec", "template", "spec"),
            "daemonsets": ("spec", "template", "spec"), "replicasets": ("spec", "template", "spec"),
            "statefulsets": ("spec", "template", "spec"), "jobs": ("spec", "template", "spec"),
            "cronjobs": ("spec", "jobTemplate", "spec", "template", "spec")}
VALID_GROUPS = {"pods": "", "deployments": "apps", "daemonsets": "apps", "replicasets": "apps",
                "statefulsets": "apps", "jobs": "batch", "cronjobs": "batch"}


@dataclass(frozen=True)
class BehaviorEvent(Event):
    uri_path: str = ""
    groups: tuple[str, ...] = ()
    features: dict = field(default_factory=dict)
    body_available: bool = False
    request_fingerprint: str = ""

    def metadata(self):
        result = asdict(self)
        from .events import iso_time
        result["time"] = iso_time(self.time)
        return result


def walk(value, path=()):
    if len(path) > 30:
        raise ValueError("request nesting too deep")
    if isinstance(value, dict):
        for key, child in value.items():
            yield from walk(child, path + (str(key),))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk(child, path + (str(index),))
    else:
        yield path, value


def leaves(body):
    if isinstance(body, dict):
        return list(walk(body))
    result = []
    if isinstance(body, list):
        for op in body:
            if not isinstance(op, dict) or op.get("op") not in {"add", "replace", "remove", "test", "copy", "move"}:
                raise ValueError("invalid JSON Patch operation")
            if op["op"] in {"add", "replace"}:
                pointer = op.get("path", "")
                if not isinstance(pointer, str) or not pointer.startswith("/"):
                    raise ValueError("invalid JSON Patch pointer")
                path = tuple(p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/"))
                result.extend(walk(op.get("value"), path))
    return result


def role_rules(body):
    if isinstance(body, dict):
        rules = body.get("rules", [])
        if not isinstance(rules, list):
            raise ValueError("invalid role rules")
        for r in rules:
            if not isinstance(r, dict) or any(not isinstance(v, list) or not all(isinstance(x, str) for x in v)
                    for k, v in r.items() if k in {"apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs"}):
                raise ValueError("invalid role permission fields")
        return [{k: deepcopy(r[k]) for k in ("apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs") if k in r} for r in rules]
    result = []
    for op in body if isinstance(body, list) else []:
        if op.get("op") in {"add", "replace"} and str(op.get("path", "")).startswith("/rules"):
            value = op.get("value")
            if isinstance(value, dict):
                result.extend(role_rules({"rules": [value]}))
            elif isinstance(value, list) and all(isinstance(x, dict) for x in value):
                result.extend(role_rules({"rules": value}))
            elif str(op.get("path", "")).split("/")[3:4] == ["verbs"]:
                # Delegation verbs are meaningful even without the previous role.
                verbs = [value] if isinstance(value, str) else value
                if isinstance(verbs, list) and all(isinstance(x, str) for x in verbs):
                    result.append({"verbs": verbs})
    return result


def extract_features(raw, resource, group, subresource):
    body = raw.get("requestObject")
    if body is not None and not isinstance(body, (dict, list)):
        raise ValueError("invalid request body shape")
    features = {}
    query = parse_qs(urlsplit(raw.get("requestURI", "")).query, keep_blank_values=True)
    if query:
        features["query_sha256"] = digest(query)
    if resource in PREFIXES and group == VALID_GROUPS[resource]:
        flags, capabilities, images, paths = set(), set(), set(), set()
        execution = []
        prefix = PREFIXES[resource]
        for path, value in leaves(body):
            if path[:len(prefix)] != prefix:
                continue
            tail = path[len(prefix):]
            if tail and (tail[0] in {"serviceAccountName", "automountServiceAccountToken", "volumes", "hostAliases", "securityContext"}
                or len(tail) >= 3 and tail[0] in {"containers", "initContainers", "ephemeralContainers"}
                and tail[2] in {"name", "command", "args", "env", "envFrom", "volumeMounts", "securityContext"}):
                execution.append((tail, value))
            if tail in {("hostPID",), ("hostIPC",), ("hostNetwork",)} and value is True:
                flags.add(tail[0])
            if len(tail) >= 3 and tail[0] in {"containers", "initContainers", "ephemeralContainers"}:
                if tail[2:] == ("securityContext", "privileged") and value is True:
                    flags.add("privileged")
                if len(tail) == 6 and tail[2:5] == ("securityContext", "capabilities", "add") and isinstance(value, str):
                    capabilities.add(value)
                if tail[2:] == ("image",) and isinstance(value, str):
                    images.add(value)
            if len(tail) == 4 and tail[0] == "volumes" and tail[2:] == ("hostPath", "path") and isinstance(value, str):
                paths.add(value)
                flags.add("hostPath")
        features.update(workload_flags=sorted(flags), capabilities=sorted(capabilities),
                        images=sorted(images), host_paths=sorted(paths), execution_spec_sha256=digest(sorted(execution)))
    if group == "rbac.authorization.k8s.io" and resource in {"roles", "clusterroles"}:
        features["role_rules"] = role_rules(body)
        features["rbac_patch_partial"] = raw.get("verb") == "patch"
        features["role_rules_available"] = isinstance(body, list) or isinstance(body, dict) and "rules" in body
    if group == "rbac.authorization.k8s.io" and resource in {"rolebindings", "clusterrolebindings"} and isinstance(body, dict):
        ref = body.get("roleRef", {})
        features["role_ref"] = {k: ref.get(k, "") for k in ("apiGroup", "kind", "name")}
        features["subjects"] = [{k: s.get(k, "") for k in ("kind", "name", "namespace")} for s in body.get("subjects", []) if isinstance(s, dict)]
    if not group and resource == "serviceaccounts" and subresource == "token" and isinstance(body, dict):
        spec = body.get("spec", {})
        features["token_expiration"] = spec.get("expirationSeconds")
        features["token_audiences"] = spec.get("audiences") or []
        features["token_bound_object_sha256"] = digest(spec.get("boundObjectRef"))
    if not group and resource == "secrets" and isinstance(body, dict):
        features["secret_type"] = body.get("type", "")
    if group == "certificates.k8s.io" and resource == "certificatesigningrequests" and isinstance(body, dict):
        features["signer_name"] = body.get("spec", {}).get("signerName", "")
    if resource == "pods" and subresource in {"exec", "attach"}:
        query = parse_qs(urlsplit(raw.get("requestURI", "")).query)
        if "command" in query:
            features["command_sha256"] = digest(query["command"])
    if isinstance(body, list) and any(op.get("op") in {"copy", "move"} for op in body if isinstance(op, dict)):
        features["unresolved_patch"] = True
    return features


def normalize(raw):
    if not isinstance(raw, dict):
        raise ValueError("expected audit Event")
    ref = raw.get("objectRef", {})
    if not isinstance(ref, dict):
        raise ValueError("invalid objectRef")
    candidate = raw
    non_resource = not ref.get("resource")
    uri = raw.get("requestURI", "")
    if not isinstance(uri, str):
        raise ValueError("invalid requestURI")
    if non_resource:
        if not uri.startswith("/"):
            raise ValueError("non-resource request requires a path")
        candidate = dict(raw, objectRef={"resource": "__nonresource__"})
    base = old_normalize(candidate)
    if base is None:
        return None
    groups = raw.get("user", {}).get("groups", [])
    if not isinstance(groups, list) or not all(isinstance(x, str) for x in groups):
        raise ValueError("invalid user groups")
    features = extract_features(raw, base.resource, base.api_group, base.subresource)
    path = unquote(urlsplit(uri).path)
    # The fingerprint covers the request, not its response or any label.
    fingerprint = digest({"resource": base.resource, "api_group": base.api_group, "namespace": base.namespace,
                          "name": base.name, "subresource": base.subresource, "verb": base.verb,
                          "uri_path": path, "features": features})
    return BehaviorEvent(**asdict(base), uri_path=path, groups=tuple(groups), features=features,
                         body_available="requestObject" in raw, request_fingerprint=fingerprint)


def read_events(path):
    stats, by_id, rejected = ReadStats(), {}, set()
    with Path(path).open(encoding="utf-8-sig") as stream:
        for line_number, line in enumerate(stream, 1):
            stats.lines += 1
            if not line.strip():
                continue
            try:
                raw = json.loads(line)
                items = raw.get("items") if isinstance(raw, dict) and raw.get("kind") == "EventList" else [raw]
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
                except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
                    stats.malformed += 1
                    stats.errors.append({"line": line_number, "reason": "invalid audit fields"})
                    continue
                if event is None:
                    stats.ignored_stage += 1
                    continue
                if event.resource == "__nonresource__":
                    stats.non_resource += 1  # counted AND retained in B5
                if event.audit_id in rejected:
                    continue
                previous = by_id.get(event.audit_id)
                if previous:
                    stats.duplicates += 1
                    identity = lambda e: (e.actor, e.caller, e.time, e.request_fingerprint, e.credential_id_hash, e.source_ips, e.user_agent, e.groups)
                    if identity(previous) != identity(event) or (previous.stage == event.stage and previous.code != event.code):
                        rejected.add(event.audit_id)
                        stats.conflicting_ids += 1
                        del by_id[event.audit_id]
                        continue
                    if STAGES[event.stage] <= STAGES[previous.stage]:
                        continue
                by_id[event.audit_id] = event
    events = sorted(by_id.values(), key=lambda e: (e.time, e.audit_id))
    stats.events = len(events)
    return events, stats
