"""Collect real execution and permission-effect evidence in the isolated VM.

Examples: python -m lab.integration_live --output data/integration-smoke --split development --cases X01,W03,R03
          python -m lab.integration_live --output data/integration-eval --split evaluation --repetitions 2
"""

import argparse
import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
from pathlib import Path
import random
import re
import time
from urllib.request import Request, urlopen

from auditguard.behavior import validate_config
from auditguard.events import iso_time, write_json, write_jsonl
from .behavior_live import Client, create, issue, inventory, planned_event, CREDENTIAL_KEY
from .integration_scenarios import definitions, workload, exec_path, MARKER
from .integration_stream import execute
from .integration_windows import PRIVATE, ROOT, SERVER
from .live import fetch_audit


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pod_evidence(pod):
    return {"name": pod["metadata"]["name"], "uid": pod["metadata"]["uid"],
            "namespace": pod["metadata"]["namespace"], "node": pod.get("spec", {}).get("nodeName"),
            "spec": pod.get("spec", {}), "status": pod.get("status", {})}


def wait_pod(admin, ns, name=None, label=None, timeout=150):
    deadline = time.monotonic() + timeout
    latest = {}
    while time.monotonic() < deadline:
        path = f"/api/v1/namespaces/{ns}/pods" + ("/" + name if name else "?labelSelector=integration%3D" + label)
        code, data, _ = admin.call("GET", path)
        pods = [data] if name and code == 200 else data.get("items", [])
        if pods:
            latest = pod_evidence(pods[0])
            status = latest["status"]
            containers = status.get("containerStatuses", [])
            if latest["node"] and status.get("phase") == "Running" and containers and all(
                c.get("ready") and c.get("state", {}).get("running") and c.get("containerID", "").startswith("containerd://") for c in containers):
                return latest
        time.sleep(1)
    raise RuntimeError("Pod failed to become Running/Ready: " + json.dumps(latest, ensure_ascii=True))


def setup(admin, ns):
    create(admin, "/api/v1/namespaces", {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns,
           "labels": {"app.kubernetes.io/managed-by": "auditguard-integration"}}})
    core, rbac = f"/api/v1/namespaces/{ns}", f"/apis/rbac.authorization.k8s.io/v1/namespaces/{ns}"
    for account in ("admin", "operator", "reader", "r01-subject", "r02-subject", "r03-subject"):
        create(admin, core + "/serviceaccounts", {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": account}})
    rules = {
        "admin": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
        "operator": [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["get", "create"]}],
        "reader": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
        "pod-reader": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
        "secret-reader": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]}
    for name, permissions in rules.items():
        create(admin, rbac + "/roles", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
               "metadata": {"name": name}, "rules": permissions})
        if name in {"admin", "operator", "reader"}:
            create(admin, rbac + "/rolebindings", {"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                   "metadata": {"name": name}, "roleRef": {"kind": "Role", "apiGroup": "rbac.authorization.k8s.io", "name": name},
                   "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": ns}]})
    create(admin, core + "/secrets", {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "demo-secret"},
           "stringData": {"dummy": "NOT-A-REAL-CREDENTIAL"}})
    create(admin, core + "/pods", workload("Pod", "diagnostic"))
    return wait_pod(admin, ns, name="diagnostic")


def context(case, receipts, roles, now, ns):
    config, legacy = read(ROOT / "config/behavior.json"), read(ROOT / "config/advanced.json")
    config["role_inventory"] = roles
    if case["approval"] != "none":
        for key, receipt in receipts.items():
            requests = deepcopy([s for s in case["steps"] if s["client"] == key])
            if case["approval"] == "different_command":
                requests[0]["path"] = exec_path(ns, "diagnostic", ["id"])
            events = [planned_event(r, receipt["actor"]) for r in requests]
            if not events:
                continue
            order = {"id": "authorized-" + key, "actor": receipt["actor"], "credential_id_hash": receipt["credential_id_hash"],
                     "not_before": iso_time(now - timedelta(seconds=2)), "not_after": iso_time(now + timedelta(minutes=6)),
                     "max_requests": len(events), "fingerprints": sorted({e.request_fingerprint for e in events}),
                     "reason": "측정 전에 등록한 범위·시간·횟수 제한 작업 승인"}
            config["work_orders"].append(order)
            if all(not e.api_group and not e.subresource and e.resource in {"pods", "secrets"} and e.verb == "get" and e.name for e in events):
                intent = {k: v for k, v in order.items() if k != "fingerprints"}
                intent["namespace"] = ns
                intent["actions"] = list({(e.resource, e.verb, e.name): {"resource": e.resource, "verb": e.verb, "name": e.name} for e in events}.values())
                legacy["intents"].append(intent)
    return validate_config(config), legacy


def safe_event(raw):
    result = {k: raw[k] for k in ("kind", "apiVersion", "level", "auditID", "stage", "verb", "requestURI", "sourceIPs",
        "userAgent", "objectRef", "requestReceivedTimestamp", "stageTimestamp", "requestObject") if k in raw}
    result["responseStatus"] = {"code": raw.get("responseStatus", {}).get("code")}
    user = raw.get("user", {})
    result["user"] = {"username": user.get("username", ""), "groups": user.get("groups", []),
                      "extra": {CREDENTIAL_KEY: user.get("extra", {}).get(CREDENTIAL_KEY, [])}}
    return result


def workload_proof(admin, ns, case):
    pod = wait_pod(admin, ns, label=case["workload_name"])
    command = "printf 'WORKLOAD_CONFIRMED\\n'; id -u; sed -n 's/^CapEff:[[:space:]]*/CapEff=/p' /proc/self/status"
    if case["risk"] == "hostpid":
        command += "; printf 'PID1='; cat /proc/1/comm"
    if case["risk"] == "hostpath":
        command += "; cat /fixture/marker.txt"
    proof = execute(admin, exec_path(ns, pod["name"], ["sh", "-c", command]))
    return {"kind": "workload", "pod": pod, "verifier_exec": proof,
            "verifier_scope": "admin execution proof only; excluded from measured actor audit dataset",
            "risk": case["risk"]}


def execution_errors(case, proof):
    errors = []
    if case["proof"] in {"exec", "exec_denied"}:
        execution = proof.get("exec", {})
        if case["proof"] == "exec_denied":
            if execution.get("http_code") != 403 or execution.get("exit_code") is not None:
                errors.append("exec_denial_not_proven")
        elif not (execution.get("http_code") == 101 and execution.get("exit_code") == 0 and execution.get("closed")
                  and execution.get("stdout") == case["expected_stdout"]):
            errors.append("exec_success_not_proven")
    if case["proof"] in {"exec", "exec_denied", "workload"}:
        pod = proof.get("pod", {})
        containers = pod.get("status", {}).get("containerStatuses", [])
        if not pod.get("uid") or not pod.get("node") or pod.get("status", {}).get("phase") != "Running" or not containers or not all(
            c.get("ready") and c.get("state", {}).get("running") and c.get("containerID", "").startswith("containerd://") for c in containers):
            errors.append("container_running_not_proven")
    if case["proof"] == "workload":
        execution = proof.get("verifier_exec", {})
        if execution.get("http_code") != 101 or execution.get("exit_code") != 0 or not execution.get("closed") or not execution.get("stdout", "").startswith("WORKLOAD_CONFIRMED\n0\n"):
            errors.append("workload_execution_not_proven")
        spec, out = proof.get("pod", {}).get("spec", {}), execution.get("stdout", "")
        if case["risk"] == "privileged":
            cap = re.search(r"CapEff=([0-9a-f]+)", out)
            if not any(c.get("securityContext", {}).get("privileged") is True for c in spec.get("containers", [])) or not cap or not int(cap[1], 16) & (1 << 21):
                errors.append("privileged_effect_not_proven")
        if case["risk"] == "hostpid" and (spec.get("hostPID") is not True or "PID1=init\n" not in out):
            errors.append("hostpid_effect_not_proven")
        if case["risk"] == "hostpath" and (MARKER + "\n" not in out or not any(v.get("hostPath", {}).get("path") == "/var/lib/auditguard-fixtures" for v in spec.get("volumes", []))):
            errors.append("hostpath_effect_not_proven")
    if case["proof"] == "rbac_access":
        if proof.get("codes") != [403, 201, 200] or not proof.get("same_subject_credential") or not proof.get("object_verified"):
            errors.append("permission_effect_not_proven")
    return errors


def run(args):
    if args.output.exists() or not 1 <= args.repetitions <= 3:
        raise ValueError("choose a new output directory and 1..3 repetitions")
    selected = set(args.cases.split(",")) if args.cases else {c["id"] for c in definitions()}
    if args.split == "evaluation" and args.cases:
        raise ValueError("formal evaluation must include every predeclared case")
    templates = [c for c in definitions() if c["id"] in selected]
    if selected != {c["id"] for c in templates}:
        raise ValueError("unknown case ID")
    old = read(ROOT / "data/behavior-eval/freeze.json")
    for name, expected in old["files"].items():
        if sha(ROOT / name) != expected:
            raise ValueError("B5 baseline changed: " + name)
    paths = sorted(set(old["files"]) | {"lab/integration_scenarios.py", "lab/integration_live.py", "lab/integration_stream.py",
        "lab/integration_windows.py", "lab/integration-bootstrap.sh", "lab/integration-image.json",
        "scripts/evaluate_integration.py", "tests/test_integration.py", "data/integration-baseline/preserved-files.json"})
    freeze = {"created_before_requests": iso_time(datetime.now(timezone.utc)), "split": args.split,
              "repetitions": args.repetitions, "seed": args.seed, "scenarios": templates,
              "files": {p: sha(ROOT / p) for p in paths}, "policy": "Frozen B4/B5; integration collection/proof validation; no detector tuning"}
    write_json(args.output / "freeze.json", freeze)
    admin = Client(args.server, args.ca, args.cert, args.key)
    _, version, _ = admin.call("GET", "/version")
    _, nodes, _ = admin.call("GET", "/api/v1/nodes")
    environment = {"api_version": version, "nodes": [{"name": n["metadata"]["name"], "uid": n["metadata"]["uid"],
        "conditions": n["status"].get("conditions", []), "node_info": n["status"].get("nodeInfo", {}),
        "capacity": n["status"].get("capacity", {})} for n in nodes.get("items", [])],
        "image_lock": read(ROOT / "lab/integration-image.json"), "isolation": "single QEMU VM, no host shares; loopback API/export",
        "scope": "real kubelet/containerd; successful exec, running risky workloads, RBAC access effects; harmless commands only"}
    write_json(args.output / "environment.json", environment)
    if not environment["nodes"]:
        raise ValueError("no real worker available")
    prefix = "int-" + datetime.now(timezone.utc).strftime("%H%M%S")
    rng, pairs = random.Random(args.seed), []
    for repeat in range(1, args.repetitions + 1):
        ns = f"{prefix}-{repeat}"
        print("Preparing real Pod in " + ns, flush=True)
        setup(admin, ns)
        for case in definitions(ns, f"{rng.getrandbits(40):010x}"):
            if case["id"] in selected:
                pairs.append((case, repeat, ns))
    rng.shuffle(pairs)
    write_json(args.output / "request-plan.json", [{"run_id": f"{c['id']}-{r:02d}", "case": c} for c, r, _ in pairs])
    freeze["request_plan_sha256"] = sha(args.output / "request-plan.json")
    freeze["environment_sha256"] = sha(args.output / "environment.json")
    write_json(args.output / "freeze.json", freeze)
    manifest = {"schema_version": 1, "dataset_id": args.output.name, "split": args.split, "source_type": "live", "runs": []}
    for index, (case, repeat, ns) in enumerate(pairs, 1):
        run_id = f"{case['id']}-{repeat:02d}"
        print(f"[{index}/{len(pairs)}] {run_id}: {case['proof']}", flush=True)
        clients, receipts = {}, {}
        for key, role in [("actor", case["actor_role"])] + ([("subject", case["subject"])] if "subject" in case else []):
            client, _, receipt = issue(admin, args, ns, role)
            clients[key], receipts[key] = client, receipt
        roles = [r for r in inventory(admin, (ns,)) if r["kind"] == "Role"]
        with urlopen(Request(args.server + "/readyz"), context=admin.context, timeout=30) as response:
            server_time = parsedate_to_datetime(response.headers["Date"])
        before = datetime.now(timezone.utc)
        config, legacy = context(case, receipts, roles, server_time, ns)
        ctx = args.output / "contexts" / run_id
        for name, value in (("behavior", config), ("legacy", legacy), ("issuance", receipts)):
            write_json(ctx / (name + ".json"), value)
        hashes = {name: sha(ctx / (name + ".json")) for name in ("behavior", "legacy", "issuance")}
        write_json(ctx / "before.json", {"time": iso_time(before), "server_date_before_requests": iso_time(server_time), "sha256": hashes})
        ids, observations, errors, bodies = [], [], [], []
        proof = {"kind": case["proof"]}
        if case["proof"].startswith("exec"):
            proof["pod"] = wait_pod(admin, ns, name="diagnostic")
        for step in case["steps"]:
            client = clients[step["client"]]
            if step["operation"] == "exec":
                execution = execute(client, step["path"])
                proof["exec"] = execution
                code, audit_id, body = execution["http_code"], execution["audit_id"], {}
                # Successful proxied exec does not return Audit-ID. Use a fresh
                # random request marker, exact URI, then verify actor/JTI below.
                # Labels/case IDs are never sent as markers or inference input.
                if not audit_id:
                    for _ in range(20):
                        matches = [e for e in fetch_audit(args).values() if e.get("userAgent") == execution["correlation_user_agent"] and e.get("requestURI") == step["path"]]
                        if len(matches) == 1:
                            audit_id = matches[0]["auditID"]
                            execution["audit_id"] = audit_id
                            execution["audit_id_source"] = "unique_random_user_agent_and_exact_uri_then_actor_credential_verification"
                            break
                        if len(matches) > 1:
                            errors.append("ambiguous_exec_correlation")
                            break
                        time.sleep(.5)
            else:
                code, body, audit_id = client.call(step["method"], step["path"], step["body"])
            bodies.append(body)
            observations.append({"audit_id": audit_id, "code": code, "expected_codes": step["expected_codes"], "client": step["client"]})
            ids.append(audit_id)
            if code not in step["expected_codes"]:
                errors.append("unexpected_http_" + str(code))
            if not audit_id:
                errors.append("missing_audit_id")
        if case["proof"] == "workload":
            try:
                proof = workload_proof(admin, ns, case)
            except (RuntimeError, OSError, ValueError) as error:
                proof["failure"] = str(error)
                errors.append("workload_proof_failed")
        elif case["proof"] == "rbac_access":
            target = bodies[-1]
            verified = (target.get("kind") == "Pod" and target.get("metadata", {}).get("name") == "diagnostic" and target.get("status", {}).get("phase") == "Running") if case["role"] == "pod-reader" else (
                target.get("kind") == "Secret" and target.get("metadata", {}).get("name") == "demo-secret" and
                target.get("data", {}).get("dummy") == base64.b64encode(b"NOT-A-REAL-CREDENTIAL").decode())
            proof.update(codes=[o["code"] for o in observations], same_subject_credential=True, object_verified=verified,
                resource_kind=target.get("kind"), resource_uid=target.get("metadata", {}).get("uid"),
                subject_credential_id_hash=receipts["subject"]["credential_id_hash"], secret_values_persisted=False)
        errors += execution_errors(case, proof)
        captured = {}
        for _ in range(30):
            captured = fetch_audit(args)
            if all(i in captured for i in ids):
                break
            time.sleep(.5)
        records = []
        for audit_id, step in zip(ids, case["steps"]):
            if audit_id not in captured:
                errors.append("missing_completed_event")
                continue
            raw = captured[audit_id]
            receipt = receipts[step["client"]]
            extra = raw.get("user", {}).get("extra", {}).get(CREDENTIAL_KEY, [])
            if raw.get("user", {}).get("username") != receipt["actor"] or len(extra) != 1 or hashlib.sha256(extra[0].encode()).hexdigest() != receipt["credential_id_hash"]:
                errors.append("identity_mismatch")
            if raw.get("responseStatus", {}).get("code") != observations[len(records)]["code"]:
                errors.append("transport_audit_code_mismatch")
            records.append(safe_event(raw))
        path = args.output / "logs" / (run_id + ".jsonl")
        proof_path = args.output / "proofs" / (run_id + ".json")
        write_jsonl(path, records)
        write_json(proof_path, proof)
        manifest["runs"].append({"run_id": run_id, "scenario": case["id"], "label": case["label"], "family": case["family"],
            "description": case["description"], "limitation_control": case["limitation_control"], "path": "logs/" + path.name,
            "sha256": sha(path), "expected_events": len(case["steps"]), "status": "invalid" if errors else "complete",
            "collection_errors": sorted(set(errors)), "contexts": "contexts/" + run_id, "context_sha256": hashes,
            "proof_path": "proofs/" + proof_path.name, "proof_sha256": sha(proof_path),
            "start": iso_time(before), "end": iso_time(datetime.now(timezone.utc)), "observations": observations})
        write_json(args.output / "manifest.json", manifest)
        print("  " + ("INVALID: " + ",".join(sorted(set(errors))) if errors else "execution/audit verified"), flush=True)
    return 2 if any(r["status"] != "complete" for r in manifest["runs"]) else 0


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--split", choices=("development", "evaluation"), required=True)
    p.add_argument("--cases", default="")
    p.add_argument("--repetitions", type=int, default=1)
    p.add_argument("--seed", type=int, default=631905)
    p.add_argument("--server", default=SERVER)
    p.add_argument("--ca", type=Path, default=PRIVATE / "ca.crt")
    p.add_argument("--cert", type=Path, default=PRIVATE / "admin.crt")
    p.add_argument("--key", type=Path, default=PRIVATE / "admin.key")
    p.add_argument("--audit-url", default="http://127.0.0.1:28081/audit.log")
    p.add_argument("--audit-file", type=Path)
    return run(p.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
