"""B5: five behavior families, bounded approvals and evidence, no case labels."""

import argparse
from collections import defaultdict, deque
from copy import deepcopy
from dataclasses import asdict
from datetime import timedelta
import json
from pathlib import Path
import re

from .advanced import detect_advanced
from .behavior_events import read_events, PREFIXES, VALID_GROUPS
from .events import parse_time, iso_time, write_json
from .policy import digest, load_policy


def validate_config(config):
    if not isinstance(config, dict) or config.get("version") != 1:
        raise ValueError("invalid B5 config")
    for key in ("scan_window_seconds", "scan_min_requests", "scan_min_targets", "enumeration_window_seconds",
                "enumeration_min_requests", "enumeration_min_resources", "sequence_window_seconds"):
        if type(config.get(key)) is not int or not 1 <= config[key] <= 10000:
            raise ValueError("invalid B5 threshold: " + key)
    if not isinstance(config.get("dangerous_capabilities"), list) or not all(isinstance(x, str) for x in config["dangerous_capabilities"]):
        raise ValueError("invalid capabilities")
    if not isinstance(config.get("role_inventory"), list) or not isinstance(config.get("work_orders"), list):
        raise ValueError("invalid B5 context")
    inventory_keys = set()
    for role in config["role_inventory"]:
        if not isinstance(role, dict) or set(role) != {"kind", "namespace", "name", "rules"}:
            raise ValueError("invalid role inventory entry")
        key = (role["kind"], role["namespace"], role["name"])
        if (not all(isinstance(x, str) for x in key) or role["kind"] not in {"Role", "ClusterRole"}
                or not role["name"] or key in inventory_keys or not isinstance(role["rules"], list)
                or any(not isinstance(r, dict) or any(not isinstance(v, list) or not all(isinstance(x, str) for x in v)
                    for k, v in r.items() if k in {"apiGroups", "resources", "verbs", "resourceNames", "nonResourceURLs"}) for r in role["rules"])):
            raise ValueError("invalid role inventory")
        inventory_keys.add(key)
    seen, credentials = set(), set()
    for order in config["work_orders"]:
        required = {"id", "actor", "credential_id_hash", "not_before", "not_after", "max_requests", "fingerprints", "reason"}
        if not isinstance(order, dict) or set(order) != required:
            raise ValueError("invalid work order fields")
        if (not isinstance(order["id"], str) or not order["id"] or order["id"] in seen
            or not isinstance(order["actor"], str) or not order["actor"] or "*" in order["actor"]
            or not isinstance(order["reason"], str) or not order["reason"]):
            raise ValueError("invalid work order identity")
        seen.add(order["id"])
        if (not isinstance(order["credential_id_hash"], str) or not re.fullmatch("[0-9a-f]{64}", order["credential_id_hash"])
                or order["credential_id_hash"] in credentials):
            raise ValueError("work order requires verified credential ID hash")
        credentials.add(order["credential_id_hash"])
        if type(order["max_requests"]) is not int or not 1 <= order["max_requests"] <= 100:
            raise ValueError("invalid work order budget")
        if parse_time(order["not_before"]) >= parse_time(order["not_after"]):
            raise ValueError("invalid work order time")
        if not isinstance(order["fingerprints"], list) or not order["fingerprints"] or not all(isinstance(f, str) and re.fullmatch("[0-9a-f]{64}", f) for f in order["fingerprints"]):
            raise ValueError("invalid work order fingerprint")
    return deepcopy(config)


def risky_rules(rules):
    risks = set()
    for rule in rules:
        verbs, resources = set(rule.get("verbs", [])), set(rule.get("resources", []))
        groups = set(rule.get("apiGroups", []))
        if "*" in verbs and "*" in resources:
            risks.add("wildcard_permissions")
        if verbs & {"escalate", "bind", "impersonate"}:
            risks.add("permission_delegation")
        if groups & {"", "*"} and resources & {"secrets", "*"} and verbs & {"get", "list", "watch", "*"}:
            risks.add("credential_read_permission")
        if groups & {"", "*"} and resources & {"serviceaccounts/token", "*"} and verbs & {"create", "*"}:
            risks.add("token_mint_permission")
    return sorted(risks)


def detect(events, policy, legacy_context, config):
    config = validate_config(config)
    events = sorted(events, key=lambda e: (e.time, e.audit_id))
    accepted, retained, exhausted = [], [], []
    usage = defaultdict(int)
    for e in events:
        order = next((o for o in config["work_orders"] if e.actor == e.caller == o["actor"]
            and e.credential_id_hash == o["credential_id_hash"]
            and e.request_fingerprint in o["fingerprints"]
            and parse_time(o["not_before"]) <= e.time < parse_time(o["not_after"])
            and e.code not in {401, 403} and e.code < 500), None)
        if order and usage[order["id"]] < order["max_requests"]:
            usage[order["id"]] += 1
            accepted.append({"audit_id": e.audit_id, "rule": "I5", "order_id": order["id"], "used": usage[order["id"]]})
        else:
            retained.append(e)
            if order:
                exhausted.append(e)
    scoped = deepcopy(policy)
    scoped["scope"] = {"namespaces": sorted({e.namespace for e in events if e.namespace}) or policy["scope"]["namespaces"],
                       "service_accounts_only": False}
    legacy = deepcopy(legacy_context)
    # General work orders own their complete budget; never spend it again in B4.
    delegated = {o["credential_id_hash"] for o in config["work_orders"]}
    legacy["intents"] = [i for i in legacy["intents"] if i["credential_id_hash"] not in delegated]
    result = detect_advanced([e for e in retained if e.namespace and e.resource != "__nonresource__"], scoped, legacy, "b4")
    result.mode = "b5"
    result.policy_sha256 = digest({"policy": policy, "legacy": legacy_context, "behavior": config})
    result.inspected_events, result.out_of_scope = len(events), 0
    result.suppressed.extend(accepted)
    accepted_ids = {a["audit_id"] for a in result.suppressed if a["rule"] in {"I1", "I5"}}
    retained = [e for e in retained if e.audit_id not in accepted_ids]
    observations = []
    def emit(rule, family, evidence, detail):
        last = evidence[-1]
        result.findings.append({"rule": rule, "family": family, "title": detail,
            "actor": last.actor, "caller": last.caller, "namespace": last.namespace, "time": iso_time(last.time),
            "outcome": "denied_attempt" if last.code in {401, 403} else "observed_api_activity",
            "evidence": [e.metadata() for e in evidence], "evidence_count": len(evidence)})
    for e in exhausted:
        emit("G0", "credential", [e], "사전 승인 작업의 요청 예산 초과")
    # Cluster-wide resources must not fall out of the inherited namespaced rules.
    for e in retained:
        if not e.namespace and not e.api_group and e.resource == "secrets" and e.verb in {"get", "list", "watch"}:
            emit("G1", "credential", [e], "클러스터 범위 Secret 읽기")
    inventory = {(r["kind"], r.get("namespace", ""), r["name"]): r["rules"] for r in config["role_inventory"]}
    failures, lists = defaultdict(deque), defaultdict(deque)
    recent_families, emitted_windows = defaultdict(deque), {}
    for e in events:
        feature, family = e.features, None
        if e.code >= 500:
            observations.append({"audit_id": e.audit_id, "reason": "server_error"})
            continue
        # Approved role writes still change the trusted state for later bindings.
        approved = e.audit_id in accepted_ids
        if not approved and (not e.api_group and e.resource == "serviceaccounts" and e.subresource == "token" and e.verb == "create"
            or not e.api_group and e.resource == "secrets" and e.verb in {"create", "update", "patch"} and feature.get("secret_type") == "kubernetes.io/service-account-token"
            or e.api_group == "certificates.k8s.io" and e.resource == "certificatesigningrequests" and e.verb == "create"
            and feature.get("signer_name") == "kubernetes.io/kube-apiserver-client"):
            emit("G1", "credential", [e], "승인되지 않은 자격 증명 발급/지속성 요청")
            family = "credential"
        if e.api_group == "rbac.authorization.k8s.io" and e.verb in {"create", "update", "patch"}:
            risks = risky_rules(feature.get("role_rules", []))
            ref = feature.get("role_ref")
            if ref:
                key = (ref["kind"], e.namespace if ref["kind"] == "Role" else "", ref["name"])
                rules = inventory.get(key)
                if rules is not None:
                    risks += risky_rules(rules)
                else:
                    observations.append({"audit_id": e.audit_id, "reason": "unknown_role_reference"})
            if risks and not approved:
                emit("G4", "privilege", [e], "고권한 RBAC 변경: " + ", ".join(sorted(set(risks))))
                family = "privilege"
            if feature.get("role_rules") is not None and 200 <= e.code < 300:
                kind = "ClusterRole" if e.resource == "clusterroles" else "Role"
                key = (kind, "" if kind == "ClusterRole" else e.namespace, e.name)
                if feature.get("rbac_patch_partial") or not feature.get("role_rules_available"):
                    inventory.pop(key, None)  # partial patches cannot prove the final role state
                    observations.append({"audit_id": e.audit_id, "reason": "partial_role_patch_inventory_invalidated"})
                else:
                    inventory[key] = feature["role_rules"]
            if not e.body_available:
                observations.append({"audit_id": e.audit_id, "reason": "rbac_body_unavailable"})
        if e.api_group == "rbac.authorization.k8s.io" and e.verb == "delete" and 200 <= e.code < 300:
            kind = {"clusterroles": "ClusterRole", "roles": "Role"}.get(e.resource)
            if kind:
                inventory.pop((kind, e.namespace, e.name), None)
        if approved:
            continue
        if e.resource in PREFIXES and e.api_group == VALID_GROUPS[e.resource] and e.verb in {"create", "update", "patch"}:
            risks = feature.get("workload_flags", []) + sorted(set(feature.get("capabilities", [])) & set(config["dangerous_capabilities"]))
            if risks:
                emit("G5", "workload", [e], "위험한 워크로드 보안 속성: " + ", ".join(risks))
                family = "workload"
            elif not e.body_available:
                observations.append({"audit_id": e.audit_id, "reason": "workload_body_unavailable"})
        if feature.get("unresolved_patch"):
            observations.append({"audit_id": e.audit_id, "reason": "patch_requires_previous_object"})
        identity = (e.actor, e.caller, e.source_ips[:1])
        if e.code in {401, 403}:
            window = failures[identity]
            window.append(e)
            while e.time - window[0].time > timedelta(seconds=config["scan_window_seconds"]):
                window.popleft()
            diversity = len({x.uri_path for x in window})
            key = ("G3", identity)
            if len(window) >= config["scan_min_requests"] and diversity >= config["scan_min_targets"]:
                if key not in emitted_windows or e.time - emitted_windows[key] >= timedelta(seconds=config["scan_window_seconds"]):
                    emit("G3", "discovery", list(window), "여러 API 경로에 반복된 인증/인가 실패")
                    emitted_windows[key] = e.time
                    family = "discovery"
        if e.verb == "list" and not e.subresource and e.resource not in {"__nonresource__", "events"}:
            window = lists[identity]
            window.append(e)
            while e.time - window[0].time > timedelta(seconds=config["enumeration_window_seconds"]):
                window.popleft()
            diversity = len({(x.api_group, x.resource) for x in window})
            key = ("G3-list", identity)
            # Existing trusted monitor profiles still govern their bounded read workload.
            profiled = any(p["actor"] == e.actor and all(x.actor == x.caller and x.namespace == p["namespace"]
                and not x.api_group and 200 <= x.code < 300 and x.resource in p["resources"] and x.verb in p["verbs"]
                for x in window) for p in policy["monitor_profiles"])
            if not profiled and len(window) >= config["enumeration_min_requests"] and diversity >= config["enumeration_min_resources"]:
                if key not in emitted_windows or e.time - emitted_windows[key] >= timedelta(seconds=config["enumeration_window_seconds"]):
                    emit("G3-list", "discovery", list(window), "namespace/API group을 넘는 다종 목록 조회")
                    emitted_windows[key] = e.time
                    family = "discovery"
        if not e.api_group and e.resource == "secrets" and e.verb in {"get", "list", "watch"}:
            family = "credential"
        if not e.api_group and e.resource == "pods" and e.subresource in {"exec", "attach"}:
            family = "execution"
            if e.subresource == "attach":
                emit("G2", "execution", [e], "승인되지 않은 Pod attach")
        if family:
            chain = recent_families[identity]
            chain.append((e, family))
            while e.time - chain[0][0].time > timedelta(seconds=config["sequence_window_seconds"]):
                chain.popleft()
            if len({f for _, f in chain}) >= 2:
                observations.append({"audit_id": e.audit_id, "reason": "multiple_behavior_families",
                                     "families": sorted({f for _, f in chain}), "audit_ids": [x.audit_id for x, _ in chain]})
    return result, observations


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--policy", type=Path, default=Path("config/live-policy.json"))
    p.add_argument("--legacy-context", type=Path, default=Path("config/advanced.json"))
    p.add_argument("--config", type=Path, default=Path("config/behavior.json"))
    args = p.parse_args()
    events, stats = read_events(args.input)
    if stats.malformed or stats.conflicting_ids or not events:
        write_json(args.output / "status.json", {"status": "invalid", "read_stats": asdict(stats)})
        return 2
    result, observations = detect(events, load_policy(args.policy), json.loads(args.legacy_context.read_text(encoding="utf-8")), json.loads(args.config.read_text(encoding="utf-8")))
    write_json(args.output / "findings.json", result.findings)
    write_json(args.output / "observations.json", observations)
    write_json(args.output / "suppressed.json", result.suppressed)
    summary = {"status": "complete", "mode": "b5", "prediction": result.prediction, "alerts": len(result.findings),
               "inspected_events": result.inspected_events, "read_stats": asdict(stats), "config_sha256": result.policy_sha256}
    write_json(args.output / "status.json", summary)
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
