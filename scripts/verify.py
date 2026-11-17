"""Verify the original course files and reproduce the submitted final results."""

import argparse
import hashlib
import json
from pathlib import Path
import platform
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditguard.events import write_json
from auditguard.policy import load_policy
from auditguard.behavior import detect
from auditguard.behavior_events import read_events
from scripts.evaluate_behavior import evaluate, external, read
from scripts.evaluate_integration import run as evaluate_integration
from scripts.package_submission import files as submission_files
from scripts.evaluate_components import run as evaluate_components


def compare_files(actual, expected, names):
    for name in names:
        a = (actual / name).read_bytes().replace(b"\r\n", b"\n")
        b = (expected / name).read_bytes().replace(b"\r\n", b"\n")
        if a != b:
            raise ValueError("published result differs: " + str(expected / name))


def build_final_summary():
    def measurement(name):
        value = read(ROOT / name)
        selected = value["configurations"]["b5"]
        return {"distinct_cases": value["distinct_cases"], "runs": value["runs"],
                "audit_events": value["events"], "normal_runs": selected["normal"],
                "attack_runs": selected["attacks"], **selected["supported_only"]}
    provided = read(ROOT / "results/behavior/provided.json")
    public = read(ROOT / "results/behavior/external/metrics.json")
    return {"detector": "AuditGuard", "classification_unit": "scenario run",
        "provided_examples": {"cases": len(provided), "events": sum(x["events"] for x in provided),
            "matching_predictions": sum(x["prediction"] == x["expected"] for x in provided)},
        "api_scope_evaluation": measurement("results/behavior/fresh/metrics.json"),
        "runtime_integration_evaluation": measurement("results/integration/final/metrics.json"),
        "external_positive_fixtures": {"cases": public["cases"], "events": public["events"],
            "alerted_cases": public["target_matches"], "normal_controls": public["normal_controls"],
            "precision": None, "f1": None, "fpr": None}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/local/verification.json")
    args = parser.parse_args()
    checks = []
    upstream = read(ROOT / "config/upstream-files.json")
    for entry in upstream["files"]:
        content = (ROOT / entry["local_path"]).read_bytes().replace(b"\r\n", b"\n")
        actual = hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()
        if actual != entry["git_blob_sha1"]:
            raise ValueError("upstream file changed: " + entry["local_path"])
    checks.append({"check": "upstream", "passed": True, "files": len(upstream["files"]), "commit": upstream["commit"]})

    tests = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
                           cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if tests.returncode:
        print(tests.stdout + tests.stderr)
        return tests.returncode
    count = int(re.search(r"Ran (\d+) tests", tests.stderr).group(1))
    checks.append({"check": "unittest", "passed": True, "tests": count})

    with tempfile.TemporaryDirectory(prefix="auditguard-verify-") as folder:
        target = Path(folder)
        fresh = evaluate(ROOT / "data/behavior-eval", target / "api")
        compare_files(target / "api", ROOT / "results/behavior/fresh", ("metrics.json", "findings.json", "cases.csv"))
        if any(v["invalid"] for v in fresh["configurations"].values()):
            raise ValueError("invalid final API evaluation run")
        checks.append({"check": "final_api_replay_and_freeze", "passed": True, "runs": fresh["runs"]})

        measured = external(target / "external")
        compare_files(target / "external", ROOT / "results/behavior/external", ("metrics.json", "findings.json", "cases.csv"))
        if measured["normal_controls"] or any(measured[k] is not None for k in ("precision", "f1", "fpr")):
            raise ValueError("positive-only external fixtures cannot establish classification metrics")
        checks.append({"check": "external_source_integrity_and_replay", "passed": True, "cases": measured["cases"]})

        integration = evaluate_integration(ROOT / "data/integration-eval", target / "integration")
        compare_files(target / "integration", ROOT / "results/integration/final",
                      ("metrics.json", "findings.json", "cases.csv", "execution-verification.json", "comparison.json"))
        checks.append({"check": "integration_execution_proofs_and_replay", "passed": True,
                       "runs": integration["execution"]["runs"], "audit_events": integration["execution"]["audit_events"]})
        checks.append({"check": "published_final_baseline_preserved", "passed": True,
                       **integration["comparison"]["baseline_preservation"]})

        components = evaluate_components(target / "components")
        compare_files(target / "components", ROOT / "results/components/final",
                      ("metrics.json", "cases.csv", "changes.json"))
        checks.append({"check": "final_component_exclusion_replay", "passed": True,
                       "source_runs": sum(d["runs"] for d in components["datasets"].values()),
                       "configurations": len(components["variants"]), "new_live_runs": 0})

    provided = []
    for path in sorted((ROOT / "category3/logs").glob("*.log")):
        events, stats = read_events(path)
        result, _ = detect(events, load_policy(ROOT / "config/live-policy.json"),
                           read(ROOT / "config/advanced.json"), read(ROOT / "config/behavior.json"))
        provided.append({"file": path.relative_to(ROOT).as_posix(), "events": len(events), "prediction": result.prediction,
                         "malformed": stats.malformed, "expected": "normal" if path.stem == "normal" else "alert"})
    if provided != read(ROOT / "results/behavior/provided.json") or len(provided) != 4:
        raise ValueError("provided example regression")
    if any(r["prediction"] != r["expected"] or r["malformed"] for r in provided):
        raise ValueError("provided example prediction mismatch")
    checks.append({"check": "provided_examples", "passed": True, "cases": 4})

    if build_final_summary() != read(ROOT / "results/final-summary.json"):
        raise ValueError("final summary differs from measured results")
    checks.append({"check": "final_result_summary", "passed": True})

    required = ["README.md"]
    for name in required:
        if not (ROOT / name).is_file() or not (ROOT / name).stat().st_size:
            raise ValueError("missing final document: " + name)
    checks.append({"check": "final_documents", "passed": True, "files": len(required)})

    exposed = []
    for path in submission_files():
        if path.suffix in {".json", ".jsonl", ".log", ".md", ".py", ".yaml"}:
            data = path.read_text(encoding="utf-8-sig")
            if re.search(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", data):
                exposed.append(str(path.relative_to(ROOT)))
            if path.suffix in {".json", ".jsonl", ".log"} and re.search(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", data):
                exposed.append(str(path.relative_to(ROOT)))
    if exposed:
        raise ValueError("credential found in submission paths: " + ",".join(exposed))
    checks.append({"check": "private_key_scan", "passed": True})
    result = {"python": platform.python_version(), "platform": platform.platform(), "checks": checks, "status": "passed"}
    write_json(args.output, result)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
