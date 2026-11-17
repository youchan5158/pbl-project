"""Fresh bounded API requests for B5. No detector predictions during collection.

Only the isolated loopback lab is supported. Work tokens stay in memory.
Plans, issuance receipts and approvals are persisted before measured requests.
"""

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import random
import time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from auditguard.behavior_events import normalize
from auditguard.behavior import validate_config
from auditguard.events import iso_time, write_json, write_jsonl
from auditguard.policy import digest
from .behavior_scenarios import definitions, workload
from .live import Api, fetch_audit
from .refine import CREDENTIAL_KEY

ROOT = Path(__file__).resolve().parents[1]


class Client(Api):
    def call(self, method, path, body=None, patch=False):
        if method != "PATCH":
            return super().call(method, path, body, patch)
        headers = {"User-Agent": "pbl-lab-client/1.0", "Accept": "application/json",
                   "Content-Type": "application/json-patch+json" if isinstance(body, list) else "application/merge-patch+json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        request = Request(self.server + path, data=json.dumps(body).encode(), headers=headers, method=method)
        try:
            response = urlopen(request, context=self.context, timeout=45)
        except HTTPError as error:
            response = error
        with response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}, response.headers.get("Audit-ID", "")


def create(admin, path, body, existing=False):
    code, _, _ = admin.call("POST", path, body)
    if code != 201 and not (existing and code == 409):
        raise ValueError(f"setup {body['kind']} returned {code}")


def setup(admin, namespace, other):
    rbac = "/apis/rbac.authorization.k8s.io/v1"
    wide = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]
    create(admin, rbac + "/clusterroles", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRole",
           "metadata": {"name": "lab-wide"}, "rules": wide}, existing=True)
    for ns in (namespace, other):
        create(admin, "/api/v1/namespaces", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}})
        core = "/api/v1/namespaces/" + ns
        for account in ("reader", "operator", "admin", "worker"):
            create(admin, core + "/serviceaccounts", {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account}})
        rules = [{"apiGroups": [""], "resources": ["pods", "services", "configmaps"], "verbs": ["get", "list"]}]
        for role, permissions in (("reader", rules), ("operator", [
            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]},
            {"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["get", "create"]},
            {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]}])):
            path = rbac + f"/namespaces/{ns}"
            create(admin, path + "/roles", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": role}, "rules": permissions})
            create(admin, path + "/rolebindings", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding", "metadata": {"name": role},
                   "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": role},
                   "subjects": [{"kind": "ServiceAccount", "namespace": namespace, "name": role}]})
        create(admin, core + "/secrets", {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "demo-secret"}, "stringData": {"dummy": "NOT-A-REAL-CREDENTIAL"}})
        create(admin, core + "/pods", workload("Pod", "diagnostic"))
        create(admin, f"/apis/apps/v1/namespaces/{ns}/deployments", workload("Deployment", "editable"))
        create(admin, rbac + f"/namespaces/{ns}/roles", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role", "metadata": {"name": "editable"}, "rules": rules})
    create(admin, rbac + "/clusterrolebindings", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "ClusterRoleBinding", "metadata": {"name": namespace + "-operator"},
           "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "ClusterRole", "name": "cluster-admin"},
           "subjects": [{"kind": "ServiceAccount", "namespace": namespace, "name": "admin"}]})


def issue(admin, args, namespace, account):
    if account == "anonymous":
        return Client(args.server, args.ca), "", {"actor": "system:anonymous", "credential_id_hash": ""}
    actor = f"system:serviceaccount:{namespace}:{account}"
    status, response, issuance_id = admin.call("POST", f"/api/v1/namespaces/{namespace}/serviceaccounts/{account}/token",
        {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 600}})
    if status != 201:
        raise ValueError("temporary token issuance failed")
    token = response["status"]["token"]
    status, review, review_id = admin.call("POST", "/apis/authentication.k8s.io/v1/tokenreviews",
        {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview", "spec": {"token": token}})
    user = review.get("status", {}).get("user", {})
    ids = user.get("extra", {}).get(CREDENTIAL_KEY, [])
    if status != 201 or not review.get("status", {}).get("authenticated") or user.get("username") != actor or len(ids) != 1:
        raise ValueError("verified credential ID unavailable")
    credential = hashlib.sha256(ids[0].encode()).hexdigest()
    return Client(args.server, args.ca, token=token), credential, {"actor": actor, "credential_id_hash": credential,
        "issued_at": iso_time(datetime.now(timezone.utc)), "issuance_audit_id": issuance_id, "review_audit_id": review_id,
        "expires": response["status"]["expirationTimestamp"]}


def inventory(admin, namespaces):
    out = []
    for kind, ns, path in [("ClusterRole", "", "/apis/rbac.authorization.k8s.io/v1/clusterroles")] + [
        ("Role", ns, f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}/roles") for ns in namespaces]:
        code, response, _ = admin.call("GET", path)
        if code != 200:
            raise ValueError("could not snapshot role permissions")
        out.extend({"kind": kind, "namespace": ns, "name": r["metadata"]["name"], "rules": r.get("rules", [])}
                   for r in response.get("items", []))
    return out


def planned_event(request, actor):
    path = urlsplit(request["path"]).path
    parts = path.strip("/").split("/")
    ref = {}
    if parts[0] in {"api", "apis"}:
        offset = 2 if parts[0] == "api" else 3
        group = "" if parts[0] == "api" else parts[1]
        tail = parts[offset:]
        if len(tail) >= 2 and tail[0] == "namespaces":
            ref["namespace"], tail = tail[1], tail[2:]
        if tail:
            ref.update(resource=tail[0], apiGroup=group)
            if len(tail) > 1:
                ref["name"] = tail[1]
            if len(tail) > 2:
                ref["subresource"] = tail[2]
    method = request["method"]
    verb = {"POST": "create", "PATCH": "patch", "PUT": "update", "DELETE": "delete", "GET": "get"}[method]
    if method == "GET" and ref.get("resource") and not ref.get("name"):
        verb = "list"
    body = request["body"]
    if method == "POST" and isinstance(body, dict) and body.get("metadata", {}).get("name"):
        ref["name"] = body["metadata"]["name"]
    raw = {"kind": "Event", "apiVersion": "audit.k8s.io/v1", "auditID": "planned", "stage": "ResponseComplete",
           "requestReceivedTimestamp": "2026-01-01T00:00:00Z", "user": {"username": actor}, "objectRef": ref,
           "verb": verb, "requestURI": request["path"], "responseStatus": {"code": request["expected_codes"][0]}}
    if body is not None:
        raw["requestObject"] = body
    return normalize(raw)


def prepare_context(args, case, actor, credential, role_inventory, now):
    config = json.loads((ROOT / "config/behavior.json").read_text(encoding="utf-8"))
    context = json.loads((ROOT / "config/advanced.json").read_text(encoding="utf-8"))
    config["role_inventory"] = role_inventory
    if case["approval"] != "none":
        requests = deepcopy(case["steps"])
        if case["approval"] == "different_command":
            requests[0]["path"] = requests[0]["path"].replace("command=hostname", "command=id")
        events = [planned_event(r, actor) for r in requests]
        order = {"id": "authorized-work", "actor": actor, "credential_id_hash": credential,
                 "not_before": iso_time(now - timedelta(seconds=2)), "not_after": iso_time(now + timedelta(minutes=5)),
                 "max_requests": len(requests), "fingerprints": sorted({e.request_fingerprint for e in events}),
                 "reason": "사전에 발급한 범위·요청 수 제한 작업 승인"}
        config["work_orders"] = [order]
        # Give B4 the same approval where its supported action schema permits it.
        if all(not e.api_group and not e.subresource and (e.resource in {"pods", "services", "configmaps"}
               and e.verb in {"get", "list"} or e.resource == "secrets" and e.verb == "get" and e.name) for e in events):
            intent = {k: v for k, v in order.items() if k != "fingerprints"}
            intent["namespace"] = events[0].namespace
            intent["actions"] = list({(e.resource, e.verb, e.name): {"resource": e.resource, "verb": e.verb, "name": e.name} for e in events}.values())
            context["intents"] = [intent]
    return validate_config(config), context


def freeze(output, split, seed, repetitions):
    paths = ["auditguard/behavior.py", "auditguard/behavior_events.py", "config/behavior.json",
             "lab/behavior_scenarios.py", "lab/behavior_live.py", "lab/windows.py", "lab/behavior-audit-policy.yaml",
             "data/behavior-plan/scenarios.json"]
    paths += sorted(json.loads((ROOT / "data/external/splunk-v1/freeze.json").read_text(encoding="utf-8"))["files"])
    for optional in ("scripts/evaluate_behavior.py",):
        if (ROOT / optional).exists():
            paths.append(optional)
    document = {"created_before_requests": iso_time(datetime.now(timezone.utc)), "split": split, "seed": seed,
                "repetitions": repetitions, "files": {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths},
                "scenarios": definitions(split), "policy": "No tuning after final evaluation. Author-designed cases, not a blind independent benchmark."}
    write_json(output / "freeze.json", document)


def run(args):
    if not 1 <= args.repetitions <= 3 or args.output.exists():
        raise ValueError("use a fresh output path and 1..3 repetitions")
    freeze(args.output, args.split, args.seed, args.repetitions)
    admin = Client(args.server, args.ca, args.cert, args.key)
    if admin.call("GET", "/readyz")[0] != 200:
        raise ValueError("API not ready")
    _, version, _ = admin.call("GET", "/version")
    _, nodes, _ = admin.call("GET", "/api/v1/nodes")
    write_json(args.output / "environment.json", {"api_version": version, "node_count": len(nodes.get("items", [])),
        "scope": "agentless K3s; actual API/RBAC and audit events; no container execution or successful exec",
        "collection": "Audit-ID matched Request/Metadata; no response bodies or bearer tokens"})
    manifest = {"schema_version": 1, "dataset_id": args.output.name, "split": args.split, "source_type": "live", "runs": []}
    rng = random.Random(args.seed)
    prefix = ("bd" if args.split == "development" else "be") + "-" + datetime.now(timezone.utc).strftime("%H%M%S")
    pairs = []
    for repeat in range(1, args.repetitions + 1):
        ns, other = f"{prefix}-{repeat}", f"{prefix}-{repeat}-peer"
        setup(admin, ns, other)
        for template in definitions(args.split):
            suffix = f"{prefix}-{rng.getrandbits(48):012x}"
            case = next(c for c in definitions(args.split, ns, other, suffix) if c["id"] == template["id"])
            pairs.append((case, repeat, ns, other))
    rng.shuffle(pairs)
    write_json(args.output / "request-plan.json", [{"run_id": f"{c['id']}-{r:02d}", "case": c} for c, r, _, _ in pairs])
    for index, (case, repeat, ns, other) in enumerate(pairs, 1):
        run_id = f"{case['id']}-{repeat:02d}"
        client, credential, receipt = issue(admin, args, ns, case["actor_role"])
        roles = inventory(admin, (ns, other))
        before = datetime.now(timezone.utc)
        with urlopen(Request(args.server + "/readyz"), context=admin.context, timeout=30) as response:
            server_time = parsedate_to_datetime(response.headers["Date"])
        config, context = prepare_context(args, case, receipt["actor"], credential, roles, server_time)
        context_path = args.output / "contexts" / run_id
        write_json(context_path / "behavior.json", config)
        write_json(context_path / "legacy.json", context)
        write_json(context_path / "issuance.json", receipt)
        hashes = {name: hashlib.sha256((context_path / (name + ".json")).read_bytes()).hexdigest() for name in ("behavior", "legacy", "issuance")}
        # This persisted receipt precedes the first measured API request.
        write_json(context_path / "before.json", {"time": iso_time(before), "server_date_before_requests": iso_time(server_time), "sha256": hashes})
        print(f"[{index}/{len(pairs)}] {run_id} requests={len(case['steps'])}", flush=True)
        observations, errors, ids = [], [], []
        for request in case["steps"]:
            if request["delay"]:
                time.sleep(request["delay"])
            code, _, audit_id = client.call(request["method"], request["path"], request["body"])
            observations.append({"audit_id": audit_id, "code": code, "expected_codes": request["expected_codes"]})
            if code not in request["expected_codes"]:
                errors.append(f"unexpected_http_{code}")
            if not audit_id:
                errors.append("missing_audit_id")
            ids.append(audit_id)
        captured = {}
        for _ in range(20):
            captured = fetch_audit(args)
            if all(i in captured for i in ids):
                break
            time.sleep(.5)
        records = []
        for audit_id in ids:
            if audit_id not in captured:
                errors.append("missing_completed_event")
                continue
            raw = captured[audit_id]
            safe = {k: raw[k] for k in ("kind", "apiVersion", "level", "auditID", "stage", "verb", "requestURI", "sourceIPs",
                "userAgent", "objectRef", "requestReceivedTimestamp", "stageTimestamp", "requestObject") if k in raw}
            safe["responseStatus"] = {"code": raw.get("responseStatus", {}).get("code")}
            user = raw.get("user", {})
            extra = user.get("extra", {}).get(CREDENTIAL_KEY, [])
            safe["user"] = {"username": user.get("username", ""), "groups": user.get("groups", []), "extra": {CREDENTIAL_KEY: extra}}
            if user.get("username") != receipt["actor"] or (credential and (len(extra) != 1 or hashlib.sha256(extra[0].encode()).hexdigest() != credential)):
                errors.append("identity_mismatch")
            records.append(safe)
        path = args.output / "logs" / (run_id + ".jsonl")
        write_jsonl(path, records)
        manifest["runs"].append({"run_id": run_id, "scenario": case["id"], "label": case["label"], "family": case["family"],
            "description": case["description"], "limitation_control": case["limitation_control"], "path": "logs/" + path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "expected_events": len(case["steps"]),
            "status": "invalid" if errors else "complete", "collection_errors": sorted(set(errors)),
            "contexts": "contexts/" + run_id, "context_sha256": hashes,
            "start": iso_time(before), "end": iso_time(datetime.now(timezone.utc)), "observations": observations})
        write_json(args.output / "manifest.json", manifest)
        if errors:
            print("INVALID " + ", ".join(sorted(set(errors))), flush=True)
    return 2 if any(r["status"] != "complete" for r in manifest["runs"]) else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--split", choices=("development", "evaluation"), required=True)
    p.add_argument("--repetitions", type=int, default=1)
    p.add_argument("--seed", type=int, default=416901)
    p.add_argument("--server", default="https://127.0.0.1:16443")
    p.add_argument("--ca", type=Path, default=Path("lab/private/ca.crt"))
    p.add_argument("--cert", type=Path, default=Path("lab/private/admin.crt"))
    p.add_argument("--key", type=Path, default=Path("lab/private/admin.key"))
    p.add_argument("--audit-url", default="http://127.0.0.1:18081/audit.log")
    p.add_argument("--audit-file", type=Path)
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
