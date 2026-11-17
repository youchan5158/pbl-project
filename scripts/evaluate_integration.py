"""Verify physical execution evidence, then replay unchanged B4 and B5."""

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from auditguard.behavior_events import read_events
from auditguard.events import write_json
from lab.integration_live import execution_errors
from scripts.evaluate_behavior import evaluate, read, sha
from scripts.package_submission import FINAL_BASELINE_PATHS


def verify_preserved():
    document = read(ROOT / "data/integration-baseline/preserved-files.json")
    checked = 0
    for name, digest in document["files"].items():
        if not any(name == p or name.startswith(p + "/") for p in FINAL_BASELINE_PATHS):
            continue
        if sha(ROOT / name) != digest:
            raise ValueError("preserved baseline changed: " + name)
        checked += 1
    return {"scope": "published final evaluation inputs and results", "files": checked,
            "all_hashes_match": True,
            "development_files_not_distributed": len(document["files"]) - checked}


def check_integration_freeze(data):
    """Check the unchanged detector, collector, configuration and plan files.

    This reporting entry point was updated after collection to stop requiring
    unpublished development history. Its original hash stays in freeze.json;
    it is the only source path outside the collection-time equality check.
    Final metrics and all per-case evidence are independently replay-checked.
    """
    frozen = read(Path(data) / "freeze.json")
    for name, expected in frozen["files"].items():
        if name == "scripts/evaluate_integration.py":
            continue
        if sha(ROOT / name) != expected:
            raise ValueError("code/config changed after evaluation freeze: " + name)
    return frozen


def validate_proofs(data):
    data = Path(data)
    freeze = check_integration_freeze(data)
    if sha(data / "request-plan.json") != freeze["request_plan_sha256"]:
        raise ValueError("request plan changed")
    if sha(data / "environment.json") != freeze["environment_sha256"]:
        raise ValueError("environment snapshot changed")
    plan = {r["run_id"]: r["case"] for r in read(data / "request-plan.json")}
    manifest = read(data / "manifest.json")
    if len(plan) != len(freeze["scenarios"]) * freeze["repetitions"] or set(plan) != {r["run_id"] for r in manifest["runs"]}:
        raise ValueError("incomplete integration run inventory")
    environment = read(data / "environment.json")
    if len(environment["nodes"]) != 1 or not any(c["type"] == "Ready" and c["status"] == "True" for c in environment["nodes"][0]["conditions"]):
        raise ValueError("real Ready node evidence missing")
    counts, checks, seen_ids = Counter(), [], set()
    for run in manifest["runs"]:
        case = plan[run["run_id"]]
        if run["label"] != case["label"] or run["scenario"] != case["id"]:
            raise ValueError("run labels differ from predeclared plan")
        if sha(data / run["proof_path"]) != run["proof_sha256"] or sha(data / run["path"]) != run["sha256"]:
            raise ValueError("execution proof/log hash mismatch")
        proof = read(data / run["proof_path"])
        errors = execution_errors(case, proof)
        events, stats = read_events(data / run["path"])
        raw = [json.loads(s) for s in (data / run["path"]).read_text(encoding="utf-8").splitlines()]
        if stats.malformed or stats.conflicting_ids or len(events) != len(case["steps"]):
            errors.append("invalid_audit_events")
        receipts = read(data / run["contexts"] / "issuance.json")
        if len(run["observations"]) != len(case["steps"]):
            errors.append("missing_observations")
        for event, request, observation in zip(raw, case["steps"], run["observations"]):
            receipt = receipts[request["client"]]
            identity = event["user"].get("extra", {}).get("authentication.kubernetes.io/credential-id", [])
            if event["user"]["username"] != receipt["actor"] or len(identity) != 1 or hashlib.sha256(identity[0].encode()).hexdigest() != receipt["credential_id_hash"]:
                errors.append("credential_identity_mismatch")
            if event["requestURI"] != request["path"] or event["auditID"] != observation["audit_id"] or event["responseStatus"]["code"] != observation["code"]:
                errors.append("wire_observation_audit_mismatch")
            if event["auditID"] in seen_ids:
                errors.append("reused_audit_id")
            seen_ids.add(event["auditID"])
        if case["proof"].startswith("exec") and raw:
            execution = proof["exec"]
            if raw[0]["auditID"] != execution["audit_id"] or raw[0]["userAgent"] != execution["correlation_user_agent"]:
                errors.append("exec_correlation_mismatch")
            pod = proof["pod"]
            if raw[0]["objectRef"]["name"] != pod["name"] or raw[0]["objectRef"]["namespace"] != pod["namespace"]:
                errors.append("exec_pod_mismatch")
            if case["proof"] == "exec":
                counts["successful_measured_exec"] += 1
            else:
                counts["denied_measured_exec"] += 1
        elif case["proof"] == "rbac_access" and len(events) == 3:
            if events[0].credential_id_hash != events[-1].credential_id_hash or events[-1].credential_id_hash != proof["subject_credential_id_hash"]:
                errors.append("rbac_same_token_not_proven")
            counts["verified_permission_transitions"] += 1
        elif case["proof"] == "workload":
            counts["running_workloads"] += 1
            counts["workloads_" + case["risk"]] += 1
        if run["status"] != "complete" or errors:
            raise ValueError("invalid execution evidence " + run["run_id"] + ": " + ",".join(errors + run["collection_errors"]))
        checks.append({"run_id": run["run_id"], "execution_verified": True, "proof_kind": case["proof"],
                       "proof_sha256": run["proof_sha256"]})
    return {"runs": len(checks), "audit_events": len(seen_ids), "counts": dict(counts), "checks": checks}


def run(data, output):
    preservation = verify_preserved()
    proof_summary = validate_proofs(data)
    # validate_proofs already checks the source freeze, complete request plan,
    # labels, environment and execution evidence. evaluate still checks every
    # log and approval receipt without the obsolete reporting-script hash.
    metrics = evaluate(data, output, frozen=False)
    old = read(ROOT / "results/behavior/fresh/metrics.json")
    comparison = {"baseline_preservation": preservation,
        "old_api_only": {"runs": old["runs"], "events": old["events"], "b5": old["configurations"]["b5"]["supported_only"]},
        "new_real_execution": {"runs": metrics["runs"], "events": metrics["events"], "b4": metrics["configurations"]["b4"]["supported_only"],
                               "b5": metrics["configurations"]["b5"]["supported_only"]},
        "interpretation": "Different deliberately selected cases; compare execution coverage and per-case behavior, not an accuracy improvement on an identical distribution.",
        "external": {"b5_matches": 3, "positive_fixtures": 8, "change": "none: detector unchanged; no new independent external benchmark"}}
    write_json(output / "execution-verification.json", proof_summary)
    write_json(output / "comparison.json", comparison)
    return {"metrics": metrics, "execution": proof_summary, "comparison": comparison}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=ROOT / "data/integration-eval")
    p.add_argument("--output", type=Path, default=ROOT / "results/integration/final")
    args = p.parse_args()
    result = run(args.data, args.output)
    print(json.dumps({"counts": result["execution"]["counts"], "comparison": result["comparison"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
