"""Compare frozen B4 and B5 on identical logs; labels enter only scoring."""

import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from auditguard.advanced import detect_advanced
from auditguard.behavior import detect
from auditguard.behavior_events import read_events
from auditguard.events import read_events as old_read, write_json, parse_time
from auditguard.evaluate import metrics, save_csv
from auditguard.policy import load_policy


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def check_freeze(data):
    frozen = read(data / "freeze.json")
    for name, expected in frozen["files"].items():
        if sha(ROOT / name) != expected:
            raise ValueError("code/config changed after evaluation freeze: " + name)
    return frozen


def score(rows):
    supported = metrics([dict(r, valid=True) for r in rows if r["status"] == "complete"])
    good = [r for r in rows if r["status"] != "invalid"]
    attacks = [r for r in good if r["label"] == "attack"]
    normal = [r for r in good if r["label"] == "normal"]
    return {"runs": len(rows), "invalid": sum(r["status"] == "invalid" for r in rows),
        "unsupported_attack": sum(r["status"] == "unsupported" for r in attacks),
        "unsupported_normal": sum(r["status"] == "unsupported" for r in normal),
        "attacks": len(attacks), "normal": len(normal), "attack_alerts": sum(r["prediction"] == "alert" for r in attacks),
        "normal_alerts": sum(r["prediction"] == "alert" for r in normal),
        "missed_attacks_including_unsupported": sum(r["prediction"] != "alert" for r in attacks),
        "attack_alert_coverage": sum(r["prediction"] == "alert" for r in attacks) / len(attacks) if attacks else None,
        "normal_alert_rate": sum(r["prediction"] == "alert" for r in normal) / len(normal) if normal else None,
        "supported_only": supported}


def evaluate(data, output, frozen=True):
    data, output = Path(data), Path(output)
    manifest = read(data / "manifest.json")
    modern = (data / "request-plan.json").exists()
    if modern and frozen:
        plan = check_freeze(data)
        requests = read(data / "request-plan.json")
        if len(manifest["runs"]) != len(plan["scenarios"]) * plan["repetitions"] or {r["run_id"] for r in requests} != {r["run_id"] for r in manifest["runs"]}:
            raise ValueError("incomplete evaluation plan")
    policy = load_policy(data / "policy.json" if (data / "policy.json").exists() else ROOT / "config/live-policy.json")
    base = read(ROOT / "config/behavior.json")
    rows, evidence = [], []
    for run in manifest["runs"]:
        path = data / run["path"]
        errors = []
        if sha(path) != run["sha256"]:
            raise ValueError("log hash mismatch: " + run["run_id"])
        if run["status"] != "complete":
            errors.append("collection_incomplete")
        new_events, new_stats = read_events(path)
        if new_stats.malformed or new_stats.conflicting_ids or len(new_events) != run["expected_events"]:
            errors.append("invalid_event_input")
        if modern:
            context_path = data / run["contexts"]
            config, legacy = read(context_path / "behavior.json"), read(context_path / "legacy.json")
            before = read(context_path / "before.json")
            if before["sha256"] != run["context_sha256"]:
                raise ValueError("pre-request receipt mismatch")
            for name, value in run["context_sha256"].items():
                if sha(context_path / (name + ".json")) != value:
                    raise ValueError("approval changed after requests")
            # QEMU RTC and host time differed by ~0.5 s during development.
            # Final runs record the API's own HTTP Date before measurement.
            clock = parse_time(before["server_date_before_requests"]) if "server_date_before_requests" in before else parse_time(before["time"]) - timedelta(seconds=2)
            if manifest["split"] == "evaluation" and "server_date_before_requests" not in before:
                raise ValueError("missing API clock receipt")
            if any(e.time < clock for e in new_events):
                raise ValueError("approval receipt not before measured request")
        else:
            config, legacy = deepcopy(base), read(data / "context.json")
        for mode in ("b4", "b5"):
            if mode == "b5":
                events, stats = new_events, new_stats
                result, observations = detect(events, policy, legacy, config)
            else:
                events, stats = old_read(path)
                scoped = deepcopy(policy)
                scoped["scope"] = {"namespaces": sorted({e.namespace for e in events if e.namespace}) or policy["scope"]["namespaces"], "service_accounts_only": False}
                result, observations = detect_advanced(events, scoped, legacy, "b4"), []
            status = "invalid" if errors or stats.malformed or stats.conflicting_ids else "unsupported" if not result.inspected_events else "complete"
            # Labels, descriptions and case IDs are attached only AFTER inference.
            rows.append({"run_id": run["run_id"], "scenario": run["scenario"], "label": run["label"],
                "family": run.get("family", "legacy"), "mode": mode, "status": status,
                "prediction": result.prediction if status == "complete" else status,
                "events": len(events), "inspected": result.inspected_events, "alerts": len(result.findings),
                "suppressed": len(result.suppressed), "rules": ",".join(sorted({f["rule"] for f in result.findings})),
                "description": run["description"], "errors": ",".join(errors)})
            evidence.append({"run_id": run["run_id"], "mode": mode, "status": status, "findings": result.findings,
                "suppressed": result.suppressed, "observations": observations, "read_stats": asdict(stats)})
    summary = {"dataset": manifest["dataset_id"], "split": manifest["split"], "distinct_cases": len({r["scenario"] for r in manifest["runs"]}),
        "runs": len(manifest["runs"]), "events": sum(r["expected_events"] for r in manifest["runs"]),
        "configurations": {mode: score([r for r in rows if r["mode"] == mode]) for mode in ("b4", "b5")},
        "by_family": {f: {mode: score([r for r in rows if r["mode"] == mode and r["family"] == f]) for mode in ("b4", "b5")}
                      for f in sorted({r["family"] for r in rows})}}
    write_json(output / "metrics.json", summary)
    write_json(output / "findings.json", evidence)
    save_csv(output / "cases.csv", rows)
    return summary


def external(output):
    data = ROOT / "data/external/splunk-v1"
    fixtures = read(ROOT / "results/external/splunk-v1/fixtures.json")
    policy, legacy, config = load_policy(ROOT / "config/live-policy.json"), read(ROOT / "config/advanced.json"), read(ROOT / "config/behavior.json")
    rows, evidence = [], []
    for f in fixtures:
        path = data / "logs" / Path(f["source_path"]).name
        if sha(path) != f["sha256"]:
            raise ValueError("external source changed")
        events, stats = read_events(path)
        result, observations = detect(events, policy, legacy, config)
        matching = {e["audit_id"] for finding in result.findings for e in finding["evidence"]} & set(f["target_audit_ids"])
        status = "invalid" if stats.malformed or stats.conflicting_ids else "unsupported" if not events else result.prediction
        rows.append({"case": f["case_id"], "title": f["title"], "events": len(events), "status": status,
            "target_match": bool(matching), "rules": ",".join(sorted({a["rule"] for a in result.findings}))})
        evidence.append({"case": f["case_id"], "findings": result.findings, "observations": observations, "read_stats": asdict(stats)})
    summary = {"purpose": "known external regression fixtures, already inspected before B5 design", "cases": len(rows),
        "events": sum(r["events"] for r in rows), "target_matches": sum(r["target_match"] for r in rows),
        "statuses": dict(Counter(r["status"] for r in rows)), "normal_controls": 0, "precision": None, "f1": None, "fpr": None}
    write_json(output / "metrics.json", summary)
    write_json(output / "findings.json", evidence)
    save_csv(output / "cases.csv", rows)
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=ROOT / "data/behavior-eval")
    p.add_argument("--output", type=Path, default=ROOT / "results/behavior/fresh")
    p.add_argument("--development", action="store_true", help="explicitly allow development code changes")
    p.add_argument("--external", action="store_true")
    args = p.parse_args()
    if args.development and read(args.data / "manifest.json")["split"] != "development":
        p.error("--development cannot bypass final evaluation freeze")
    summary = external(args.output) if args.external else evaluate(args.data, args.output, frozen=not args.development)
    print(json.dumps(summary.get("configurations", summary), indent=2))


if __name__ == "__main__":
    main()
