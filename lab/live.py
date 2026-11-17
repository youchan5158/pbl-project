"""Measure requests against an isolated Kubernetes API server.

Requires a loopback API endpoint, CA and admin client certificate. It provisions
only pbl-security test resources and sends bounded requests with three low-
privilege ServiceAccounts. Collection matches the server's Audit-ID response
headers, not guessed timestamps. Tokens remain in process memory.

Example:
python -m lab.live --server https://127.0.0.1:16443 --ca lab/private/ca.crt \
  --cert lab/private/admin.crt --key lab/private/admin.key \
  --audit-url http://127.0.0.1:18081/audit.log --output data/live --repetitions 5
"""

import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import ssl
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlparse
from urllib.request import Request as HttpRequest, urlopen

from auditguard.benchmark import APP, MONITOR, NS, OPERATOR, identity, scenarios
from auditguard.evaluate import evaluate
from auditguard.events import iso_time, write_json, write_jsonl
from auditguard.policy import load_policy


def require_loopback(url: str) -> None:
    parsed = urlparse(url)
    if parsed.hostname not in {"127.0.0.1", "localhost", "::1"} or parsed.username or parsed.password:
        raise ValueError("this lab client requires a loopback endpoint/tunnel")


class Api:
    def __init__(self, server, ca, cert=None, key=None, token=None):
        require_loopback(server)
        if urlparse(server).scheme != "https":
            raise ValueError("Kubernetes API must use verified HTTPS")
        self.server = server.rstrip("/")
        self.context = ssl.create_default_context(cafile=str(ca))
        if cert:
            self.context.load_cert_chain(str(cert), str(key))
        self.token = token

    def call(self, method, path, body=None, patch=False):
        headers = {"User-Agent": "pbl-lab-client/1.0", "Accept": "application/json"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        data = None if body is None else json.dumps(body).encode()
        if data is not None:
            headers["Content-Type"] = "application/merge-patch+json" if patch else "application/json"
        request = HttpRequest(self.server + path, data=data, headers=headers, method=method)
        try:
            response = urlopen(request, context=self.context, timeout=45)
        except HTTPError as response_error:
            response = response_error
        with response:
            raw = response.read()
            try:
                content = json.loads(raw) if raw else {}
            except ValueError:
                content = {}
            return response.status, content, response.headers.get("Audit-ID", "")


def setup(admin: Api):
    base = f"/api/v1/namespaces/{NS}"

    def create(path, kind, name, extra=None, group="v1", allow_existing=False):
        body = {"apiVersion": group, "kind": kind, "metadata": {"name": name, "labels": {"app.kubernetes.io/managed-by": "pbl-auditguard"}}, **(extra or {})}
        code, _, _ = admin.call("POST", path, body)
        if code == 409:
            check, existing, _ = admin.call("GET", path + "/" + name)
            if check == 200 and (allow_existing or existing.get("metadata", {}).get("labels", {}).get("app.kubernetes.io/managed-by") == "pbl-auditguard"):
                return
            raise ValueError("existing resource is not managed by this lab: " + name)
        if code != 201:
            raise ValueError(f"setup {kind}/{name} returned {code}")

    create("/api/v1/namespaces", "Namespace", NS, allow_existing=True)
    for account in (APP, MONITOR, OPERATOR, OPERATOR + "-expired"):
        create(base + "/serviceaccounts", "ServiceAccount", account, allow_existing=account == APP)
        rules = ([{"apiGroups": [""], "resources": ["secrets"], "resourceNames": ["demo-secret"], "verbs": ["get"]}]
                 if account.startswith(OPERATOR) else [{"apiGroups": [""], "resources": ["pods", "services", "configmaps"], "verbs": ["get", "list"]}])
        rbac = f"/apis/rbac.authorization.k8s.io/v1/namespaces/{NS}"
        create(rbac + "/roles", "Role", "auditguard-" + account, {"rules": rules}, "rbac.authorization.k8s.io/v1")
        create(rbac + "/rolebindings", "RoleBinding", "auditguard-" + account,
               {"roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "auditguard-" + account}, "subjects": [{"kind": "ServiceAccount", "name": account, "namespace": NS}]}, "rbac.authorization.k8s.io/v1")
    create(base + "/configmaps", "ConfigMap", "demo-config", {"data": {"purpose": "auditguard-lab"}})
    create(base + "/secrets", "Secret", "demo-secret", {"type": "Opaque", "stringData": {"dummy": "NOT-A-REAL-CREDENTIAL"}})
    for name in ("frontend-demo", "backend-demo"):
        create(base + "/pods", "Pod", name, {"spec": {"automountServiceAccountToken": False, "containers": [{"name": "demo", "image": "busybox:1.36.1", "command": ["sleep", "3600"]}], "restartPolicy": "Never"}})


def fetch_audit(args):
    if args.audit_file:
        text = args.audit_file.read_text(encoding="utf-8")
    else:
        require_loopback(args.audit_url)
        with urlopen(args.audit_url, timeout=30) as response:
            text = response.read().decode("utf-8")
    result = {}
    for line in text.splitlines():
        try:
            raw = json.loads(line)
            if raw.get("stage") in {"ResponseComplete", "Panic"}:
                result[raw["auditID"]] = raw
        except (ValueError, KeyError):
            # A concurrent append may leave one partial last line; retry at
            # collection, never report this as a complete target request.
            continue
    return result


def run(args):
    if not 1 <= args.repetitions <= 10:
        raise ValueError("repetitions must be 1..10")
    args.output.mkdir(parents=True, exist_ok=True)
    manifest_path = args.output / "manifest.json"
    if manifest_path.exists():
        raise ValueError("output already contains a run; choose a fresh directory")
    admin = Api(args.server, args.ca, args.cert, args.key)
    ready, _, _ = admin.call("GET", "/readyz")
    if ready != 200:
        raise ValueError("API server is not ready")
    _, version, _ = admin.call("GET", "/version")
    setup(admin)
    clients = {}
    for account in (APP, MONITOR, OPERATOR, OPERATOR + "-expired"):
        code, content, _ = admin.call("POST", f"/api/v1/namespaces/{NS}/serviceaccounts/{account}/token", {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest", "spec": {"expirationSeconds": 3600}})
        if code != 201:
            raise ValueError("could not issue temporary lab token")
        clients[account] = Api(args.server, args.ca, token=content["status"]["token"])
    policy = load_policy(args.policy)
    now = datetime.now(timezone.utc)
    # These declarations precede all scenario requests, are stored and hashed,
    # and do not change in response to a detector decision.
    approval = policy["approvals"][0]
    approval["not_before"] = iso_time(now - timedelta(seconds=5))
    approval["not_after"] = iso_time(now + timedelta(hours=1))
    approval["reason"] = "사전에 승인한 실습용 단일 더미 Secret GET"
    expired = deepcopy(approval)
    expired.update(id="LAB-EXPIRED", actor=identity(OPERATOR + "-expired"), not_before=iso_time(now - timedelta(hours=2)), not_after=iso_time(now - timedelta(hours=1)), reason="실습 시작 전 만료된 운영 승인")
    policy["approvals"] = [a for a in policy["approvals"] if a["id"] != "LAB-EXPIRED"] + [expired]
    write_json(args.output / "policy.json", policy)
    selected = [s for s in scenarios() if not args.core_only or not s.evaluation_only]
    pairs = [(s, repeat) for s in selected for repeat in range(1, args.repetitions + 1)]
    random.Random(args.seed).shuffle(pairs)
    manifest = {"schema_version": 1, "dataset_id": args.output.name, "source_type": "live", "split": "evaluation", "environment": "isolated Kubernetes API server; see environment.json", "seed": args.seed, "runs": []}
    _, nodes, _ = admin.call("GET", "/api/v1/nodes")
    write_json(args.output / "environment.json", {"api_version": version, "node_count": len(nodes.get("items", [])), "started_at": iso_time(now), "collection": "Audit-ID header matched to server audit file; Metadata only", "h2_identity": identity(OPERATOR + "-expired"), "timing": "sequential HTTP requests plus predefined delays; actual API latency is included"})
    for index, (scenario, repeat) in enumerate(pairs, 1):
        account = OPERATOR + "-expired" if scenario.expired_approval else scenario.account
        client = clients[account]
        run_id = f"{scenario.id}-{repeat:02d}"
        start = datetime.now(timezone.utc)
        expected_ids, observations, errors = [], [], []
        print(f"[{index}/{len(pairs)}] {run_id} requests={len(scenario.requests)}", flush=True)
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
            except (URLError, TimeoutError, OSError):
                code, audit_id = 0, ""
            if code != spec.code:
                errors.append(f"expected_http_{spec.code}_got_{code}")
            if not audit_id:
                errors.append("missing_audit_id")
            else:
                expected_ids.append(audit_id)
            observations.append({"audit_id": audit_id, "method": method, "resource": spec.resource, "subresource": spec.subresource, "expected_code": spec.code, "actual_code": code})
        end = datetime.now(timezone.utc)
        captured = {}
        for _ in range(30):
            try:
                captured = fetch_audit(args)
            except (URLError, TimeoutError, OSError):
                # Preserve an invalid manifest if collection never recovers.
                time.sleep(1)
                continue
            if all(audit_id in captured for audit_id in expected_ids):
                break
            time.sleep(1)
        if len(expected_ids) != len(set(expected_ids)):
            errors.append("duplicate_response_audit_id")
        if any(audit_id not in captured for audit_id in expected_ids):
            errors.append("missing_completed_audit_event")
        records = []
        for audit_id in expected_ids:
            if audit_id not in captured:
                continue
            raw = captured[audit_id]
            # Preserve measured API metadata, omit credential IDs, groups,
            # annotations and bodies from distributable research data.
            safe = {key: raw[key] for key in ("kind", "apiVersion", "level", "auditID", "stage", "requestURI", "verb", "sourceIPs", "userAgent", "objectRef", "responseStatus", "requestReceivedTimestamp", "stageTimestamp") if key in raw}
            safe["user"] = {"username": raw.get("user", {}).get("username", "")}
            records.append(safe)
        path = args.output / "logs" / (run_id + ".jsonl")
        write_jsonl(path, records)
        manifest["runs"].append({"run_id": run_id, "scenario": scenario.id, "label": scenario.label, "description": scenario.description, "path": "logs/" + path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "expected_events": len(scenario.requests), "status": "complete" if not errors else "invalid", "collection_errors": errors, "actor": identity(account), "start": iso_time(start), "end": iso_time(end), "observations": observations})
        write_json(manifest_path, manifest)
        if errors:
            print("  INVALID: " + ", ".join(sorted(set(errors))), flush=True)
    summary = evaluate(manifest_path, policy, args.output / "evaluation")
    print(json.dumps(summary["configurations"], indent=2), flush=True)
    return 2 if any(r["status"] != "complete" for r in manifest["runs"]) else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--server", required=True)
    p.add_argument("--ca", type=Path, required=True)
    p.add_argument("--cert", type=Path, required=True)
    p.add_argument("--key", type=Path, required=True)
    source = p.add_mutually_exclusive_group(required=True)
    source.add_argument("--audit-url")
    source.add_argument("--audit-file", type=Path)
    p.add_argument("--policy", type=Path, default=Path("config/policy.json"))
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--repetitions", type=int, default=5)
    p.add_argument("--seed", type=int, default=5291)
    p.add_argument("--core-only", action="store_true")
    args = p.parse_args()
    try:
        return run(args)
    except (ValueError, OSError) as error:
        print("Lab error: " + str(error), flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
