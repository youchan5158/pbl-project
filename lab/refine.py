"""Fresh API experiments for multi-window and credential-bound detection.

An admin-authenticated issuer creates short-lived work tokens and records their
TokenReview credential IDs BEFORE requests. The detector receives neither
scenario labels nor raw tokens. Negative controls exercise unavoidable errors.
"""

import argparse
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import time
from urllib.error import URLError
from urllib.parse import quote

from auditguard.benchmark import APP, MONITOR, NS, OPERATOR, Request, Scenario, identity, scenarios
from auditguard.events import iso_time, write_json, write_jsonl
from auditguard.policy import digest, load_policy
from auditguard.advanced import validate_context
from auditguard.refinement import compare
from .live import Api, setup, fetch_audit

CREDENTIAL_KEY = "authentication.kubernetes.io/credential-id"


@dataclass(frozen=True)
class Case:
    scenario: Scenario
    workflow: str = "ordinary"


def cases():
    result = [Case(s, "approved_secret" if s.id == "N2" else "ordinary") for s in scenarios()]
    allowed = ("pods", "services", "configmaps")
    result += [
        Case(Scenario("N4", "normal", APP, "이름을 지정한 ConfigMap 반복 GET", tuple(Request("configmaps", "get", name="demo-config", delay=.3) for _ in range(12)))),
        Case(Scenario("N5", "normal", APP, "단일 종류 목록의 정상 폴링", tuple(Request("configmaps", delay=.3) for _ in range(12)))),
        Case(Scenario("N6", "normal", APP, "토큰별 승인과 요청 한도를 가진 인벤토리 작업", tuple(Request(r, delay=1) for _ in range(2) for r in allowed)), "approved_inventory"),
        Case(Scenario("N7", "normal", APP, "승인 정보가 없는 정상 인벤토리: 오탐 음성 대조군", tuple(Request(r, delay=1) for _ in range(2) for r in allowed))),
        Case(Scenario("H5", "attack", OPERATOR, "정상 1회 사용 뒤 같은 승인 토큰 재사용", tuple(Request("secrets", "get", name="demo-secret") for _ in range(2)), True), "replayed_secret"),
        Case(Scenario("H6", "attack", OPERATOR, "승인 토큰을 정상 작업보다 먼저 사용: 관측 불가능 대조군", (Request("secrets", "get", name="demo-secret"),), True), "stolen_approval"),
        Case(Scenario("H7", "attack", APP, "단일 종류만 조회해 다양성 규칙을 피하는 정찰", tuple(Request("pods", delay=.3) for _ in range(12)), True)),
        Case(Scenario("H9", "attack", APP, "다른 간격과 길이의 느린 다종 정찰", tuple(Request(r, delay=5.5) for _ in range(3) for r in allowed), True)),
    ]
    return result


def issue(admin, server, ca, account):
    status, response, issuance_id = admin.call("POST", f"/api/v1/namespaces/{NS}/serviceaccounts/{account}/token",
        {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}})
    if status != 201:
        raise ValueError("temporary token issuance failed")
    token = response["status"]["token"]
    status, review, review_id = admin.call("POST", "/apis/authentication.k8s.io/v1/tokenreviews",
        {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token}})
    user = review.get("status", {}).get("user", {})
    ids = user.get("extra", {}).get(CREDENTIAL_KEY, [])
    if status != 201 or not review.get("status", {}).get("authenticated") or user.get("username") != identity(account) or len(ids) != 1:
        raise ValueError("server-authenticated credential identifier unavailable")
    credential_hash = hashlib.sha256(ids[0].encode()).hexdigest()
    return Api(server, ca, token=token), credential_hash, {"issuance_audit_id": issuance_id, "review_audit_id": review_id,
        "credential_id_hash": credential_hash, "actor": user["username"], "expires": response["status"]["expirationTimestamp"]}


def prepare_intent(context, workflow, credential_hash, account, number):
    now = datetime.now(timezone.utc)
    if workflow == "approved_inventory":
        actions = [{"resource": r, "verb": "list", "name": ""} for r in ("pods", "services", "configmaps")]
        budget, reason = 6, "사전 승인된 1회 인벤토리 작업"
    else:
        actions = [{"resource": "secrets", "verb": "get", "name": "demo-secret"}]
        budget, reason = 1, "사전 승인된 단일 더미 Secret 조회"
    # No case ID or attack/normal label is provided to the detector.
    context["intents"].append({"id": f"WORK-{number:04d}", "actor": identity(account),
        "namespace": NS, "credential_id_hash": credential_hash, "actions": actions,
        "not_before": iso_time(now - timedelta(seconds=1)),
        "not_after": iso_time(now + timedelta(minutes=5)), "max_requests": budget, "reason": reason})
    validate_context(context)


def collect(args, scenario, client):
    expected, observations, errors = [], [], []
    for spec in scenario.requests:
        time.sleep(spec.delay)
        path = f"/api/v1/namespaces/{NS}/{spec.resource}"
        if spec.name:
            path += "/" + quote(spec.name, safe="")
        if spec.subresource:
            path += "/" + spec.subresource + "?command=id&stdout=true&stderr=true"
        method = {"get": "GET", "list": "GET", "create": "POST", "patch": "PATCH"}[spec.verb]
        payload = {"metadata": {"annotations": {"auditguard-check": "true"}}} if spec.verb == "patch" else None
        try:
            code, _, audit_id = client.call(method, path, payload, patch=spec.verb == "patch")
        except (URLError, OSError, TimeoutError):
            code, audit_id = 0, ""
        observations.append({"audit_id": audit_id, "expected_code": spec.code, "actual_code": code})
        if code != spec.code:
            errors.append(f"expected_{spec.code}_got_{code}")
        if not audit_id:
            errors.append("missing_audit_id")
        else:
            expected.append(audit_id)
    captured = {}
    for _ in range(20):
        captured = fetch_audit(args)
        if all(key in captured for key in expected):
            break
        time.sleep(.5)
    if len(expected) != len(set(expected)):
        errors.append("duplicate_audit_id")
    records = []
    for audit_id in expected:
        if audit_id not in captured:
            errors.append("missing_completed_event")
            continue
        raw = captured[audit_id]
        safe = {k: raw[k] for k in ("kind", "apiVersion", "level", "auditID", "stage", "verb", "sourceIPs",
                "userAgent", "objectRef", "responseStatus", "requestReceivedTimestamp", "stageTimestamp") if k in raw}
        credential = raw.get("user", {}).get("extra", {}).get(CREDENTIAL_KEY)
        if not isinstance(credential, list) or len(credential) != 1:
            errors.append("missing_authenticated_credential_id")
        safe["user"] = {"username": raw.get("user", {}).get("username", ""),
                        "extra": {CREDENTIAL_KEY: credential or []}}
        records.append(safe)
    return records, observations, errors


def run(args):
    if not 1 <= args.repetitions <= 5:
        raise ValueError("repetitions must be 1..5")
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists():
        raise ValueError("choose a fresh output directory")
    admin = Api(args.server, args.ca, args.cert, args.key)
    if admin.call("GET", "/readyz")[0] != 200:
        raise ValueError("API not ready")
    setup(admin)
    policy = load_policy(args.policy)
    context = validate_context(json.loads(args.context.read_text(encoding="utf-8")))
    if context["intents"]:
        raise ValueError("input context must not contain stale work approvals")
    now = datetime.now(timezone.utc)
    for approval in policy["approvals"]:
        expired = approval["actor"].endswith("-expired")
        approval["not_before"] = iso_time(now - timedelta(hours=2) if expired else now - timedelta(seconds=5))
        approval["not_after"] = iso_time(now - timedelta(hours=1) if expired else now + timedelta(hours=2))
    selected = cases()
    if args.smoke:
        selected = [c for c in selected if c.scenario.id in {"N2", "N6", "N7", "H4", "H5", "H6"}]
    if args.normal_development:
        selected = [c for c in selected if c.scenario.id in {"N0", "N1", "N2", "N3", "N4", "N5", "N6"}]
    pairs = [(c, i) for c in selected for i in range(1, args.repetitions + 1)]
    random.Random(args.seed).shuffle(pairs)
    manifest = {"schema_version": 1, "dataset_id": args.output.name, "source_type": "live",
        "split": "development" if args.smoke or args.normal_development else "evaluation", "seed": args.seed, "runs": []}
    freeze = {"created_before_requests": iso_time(now), "policy_sha256": digest(policy),
        "context_without_intents_sha256": digest(context), "seed": args.seed, "repetitions": args.repetitions,
        "scenarios": [{"id": c.scenario.id, "label": c.scenario.label, "workflow": c.workflow,
                      "requests": [r.__dict__ for r in c.scenario.requests]} for c in selected],
        "evaluation_plan": "All B0..B4 on identical requests. Include N7 false-positive and H6/H7 blind-spot controls. No post-evaluation tuning."}
    write_json(args.output / "freeze.json", freeze)
    write_json(args.output / "policy.json", policy)
    write_json(args.output / "context.json", context)
    _, version, _ = admin.call("GET", "/version")
    _, nodes, _ = admin.call("GET", "/api/v1/nodes")
    write_json(args.output / "environment.json", {"api_version": version, "node_count": len(nodes.get("items", [])),
        "started_at": iso_time(now), "collection": "Actual Audit-ID matched API metadata plus authenticated credential ID; no bearer tokens",
        "scope": "agentless K3s API/RBAC only; no running Pods or successful exec"})
    receipts = []
    for index, (case, repeat) in enumerate(pairs, 1):
        scenario = case.scenario
        account = OPERATOR + "-expired" if scenario.expired_approval else scenario.account
        client, credential_hash, receipt = issue(admin, args.server, args.ca, account)
        receipts.append(receipt)
        if case.workflow != "ordinary":
            prepare_intent(context, case.workflow, credential_hash, account, index)
            write_json(args.output / "context.json", context)
        write_json(args.output / "issuance-receipts.json", receipts)
        start = datetime.now(timezone.utc)
        run_id = f"{scenario.id}-{repeat:02d}"
        context_before = digest(context)
        print(f"[{index}/{len(pairs)}] {run_id} requests={len(scenario.requests)}", flush=True)
        records, observations, errors = collect(args, scenario, client)
        for record in records:
            found = record["user"]["extra"][CREDENTIAL_KEY]
            if found and hashlib.sha256(found[0].encode()).hexdigest() != credential_hash:
                errors.append("unexpected_credential_id")
        path = args.output / "logs" / f"{run_id}.jsonl"
        write_jsonl(path, records)
        manifest["runs"].append({"run_id": run_id, "scenario": scenario.id, "label": scenario.label,
            "description": scenario.description, "path": "logs/" + path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "expected_events": len(scenario.requests),
            "status": "complete" if not errors else "invalid", "collection_errors": errors,
            "actor": identity(account), "start": iso_time(start), "end": iso_time(datetime.now(timezone.utc)),
            "context_before_requests_sha256": context_before, "observations": observations})
        write_json(manifest_path, manifest)
        if errors:
            print("INVALID: " + ", ".join(set(errors)), flush=True)
    summary = compare(manifest_path, policy, context, args.output / "evaluation")
    print(json.dumps(summary["configurations"], indent=2), flush=True)
    return 2 if any(r["status"] != "complete" for r in manifest["runs"]) else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", default="https://127.0.0.1:16443")
    p.add_argument("--ca", type=Path, default=Path("lab/private/ca.crt"))
    p.add_argument("--cert", type=Path, default=Path("lab/private/admin.crt"))
    p.add_argument("--key", type=Path, default=Path("lab/private/admin.key"))
    p.add_argument("--audit-url", default="http://127.0.0.1:18081/audit.log")
    p.add_argument("--audit-file", type=Path)
    p.add_argument("--policy", type=Path, default=Path("config/live-policy.json"))
    p.add_argument("--context", type=Path, default=Path("config/advanced.json"))
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--seed", type=int, default=87123)
    p.add_argument("--smoke", action="store_true")
    p.add_argument("--normal-development", action="store_true")
    args = p.parse_args()
    try:
        return run(args)
    except (ValueError, OSError) as error:
        print("Refinement lab error: " + str(error), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
