"""Replay final evidence with one component excluded; never change the detector."""

import argparse
from collections import Counter
from copy import deepcopy
import csv
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditguard.behavior import detect
from auditguard.behavior_events import read_events
from auditguard.events import write_json
from auditguard.evaluate import metrics, save_csv
from auditguard.policy import load_policy
from scripts.evaluate_behavior import evaluate, read, sha
from scripts.evaluate_integration import validate_proofs, verify_preserved


VARIANTS = {
    "full": {
        "title": "최종 전체 구성",
        "method": "기존 코드·설정으로 재생하고 공개된 실행별 판정과 대조한다.",
    },
    "without_approvals": {
        "title": "작업 승인 제외",
        "method": "복사한 설정의 work_orders, intents, approvals를 비운 뒤 다시 탐지한다.",
    },
    "without_temporal_alerts": {
        "title": "시간 누적 경보 제외",
        "method": "최종 경보에서 R3/R4/R6/G3/G3-list만 제외하고 판정을 다시 계산한다. 처리 속도 실험이 아니다.",
    },
    "without_role_inventory": {
        "title": "사전 Role 정보 제외",
        "method": "복사한 설정의 role_inventory를 비운다. 요청 본문의 Role 검사와 실행 중 상태 갱신은 유지한다.",
    },
    "without_workload_alerts": {
        "title": "워크로드 보안 속성 경보 제외",
        "method": "최종 경보에서 G5만 제외하고 판정을 다시 계산한다. 승인·다른 행동군 경보는 유지한다.",
    },
}

EXCLUDED_RULES = {
    "without_temporal_alerts": frozenset({"R3", "R4", "R6", "G3", "G3-list"}),
    "without_workload_alerts": frozenset({"G5"}),
}

DATASETS = {
    "api_scope": ("data/behavior-eval", "results/behavior/fresh"),
    "runtime_integration": ("data/integration-eval", "results/integration/final"),
}


def infer(events, policy, legacy, config, variant):
    """Only detection inputs enter here; labels and scenario descriptions do not."""
    if variant not in VARIANTS:
        raise ValueError("unknown component configuration")
    policy, legacy, config = deepcopy((policy, legacy, config))
    if variant == "without_approvals":
        policy["approvals"] = []
        legacy["intents"] = []
        config["work_orders"] = []
    elif variant == "without_role_inventory":
        config["role_inventory"] = []
    result, observations = detect(events, policy, legacy, config)
    excluded = EXCLUDED_RULES.get(variant, frozenset())
    # These rules do not feed another alarm. Cross-family observations are
    # explanatory only, so excluding their alarms isolates the binary decision.
    result.findings = [f for f in result.findings if f["rule"] not in excluded]
    return result, observations


def finding_keys(findings):
    return {(f["rule"], tuple(e["audit_id"] for e in f["evidence"])) for f in findings}


def outcome(label, prediction):
    return {("attack", "alert"): "TP", ("normal", "alert"): "FP",
            ("attack", "normal"): "FN", ("normal", "normal"): "TN"}[(label, prediction)]


def collect_sources(data):
    paths = [data / name for name in ("manifest.json", "freeze.json", "request-plan.json", "policy.json")]
    manifest = read(data / "manifest.json")
    for run in manifest["runs"]:
        paths.append(data / run["path"])
        paths.extend((data / run["contexts"]).glob("*.json"))
        if "proof_path" in run:
            paths.append(data / run["proof_path"])
    paths.extend(ROOT / name for name in read(data / "freeze.json")["files"]
                 if name.startswith(("auditguard/", "config/")))
    return {p.relative_to(ROOT).as_posix(): sha(p) for p in sorted(set(paths)) if p.is_file()}


def run(output):
    output = Path(output)
    rows, changes, datasets, sources = [], [], {}, {}
    verify_preserved()
    with tempfile.TemporaryDirectory(prefix="auditguard-components-") as folder:
        for name, (data_name, published_name) in DATASETS.items():
            data, published = ROOT / data_name, ROOT / published_name
            if name == "runtime_integration":
                validate_proofs(data)
            replay = evaluate(data, Path(folder) / name, frozen=name == "api_scope")
            original = read(published / "metrics.json")
            if replay != original:
                raise ValueError("original evaluation no longer reproduces: " + name)
            with (published / "cases.csv").open(encoding="utf-8-sig", newline="") as stream:
                original_cases = {r["run_id"]: r for r in csv.DictReader(stream) if r["mode"] == "b5"}
            sources.update(collect_sources(data))
            manifest = read(data / "manifest.json")
            policy = load_policy(data / "policy.json" if (data / "policy.json").exists()
                                 else ROOT / "config/live-policy.json")
            for measurement in manifest["runs"]:
                events, stats = read_events(data / measurement["path"])
                if stats.malformed or stats.conflicting_ids or len(events) != measurement["expected_events"]:
                    raise ValueError("invalid component input")
                context = data / measurement["contexts"]
                config, legacy = read(context / "behavior.json"), read(context / "legacy.json")
                baseline, baseline_observations = infer(events, policy, legacy, config, "full")
                expected = original_cases[measurement["run_id"]]
                if (baseline.prediction != expected["prediction"]
                    or len(baseline.findings) != int(expected["alerts"])
                    or len(baseline.suppressed) != int(expected["suppressed"])
                    or ",".join(sorted({f["rule"] for f in baseline.findings})) != expected["rules"]):
                    raise ValueError("published per-run result changed")
                for variant in VARIANTS:
                    result, observations = ((baseline, baseline_observations) if variant == "full"
                                            else infer(events, policy, legacy, config, variant))
                    lost = finding_keys(baseline.findings) - finding_keys(result.findings)
                    added = finding_keys(result.findings) - finding_keys(baseline.findings)
                    # Attach ground truth only after inference has finished.
                    row = {"dataset": name, "variant": variant, "run_id": measurement["run_id"],
                           "scenario": measurement["scenario"], "label": measurement["label"],
                           "description": measurement["description"], "valid": True,
                           "prediction": result.prediction, "outcome": outcome(measurement["label"], result.prediction),
                           "full_outcome": outcome(measurement["label"], baseline.prediction),
                           "alerts": len(result.findings), "suppressed": len(result.suppressed),
                           "rules": ",".join(sorted({f["rule"] for f in result.findings})),
                           "lost_findings": len(lost), "added_findings": len(added),
                           "unknown_role_references": sum(o["reason"] == "unknown_role_reference" for o in observations)}
                    rows.append(row)
                    if lost or added or baseline.prediction != result.prediction:
                        changes.append({"dataset": name, "variant": variant, "run_id": measurement["run_id"],
                            "description": measurement["description"], "from": row["full_outcome"], "to": row["outcome"],
                            "log": (data / measurement["path"]).relative_to(ROOT).as_posix(),
                            "lost": [{"rule": rule, "audit_ids": ids} for rule, ids in sorted(lost)],
                            "added": [{"rule": rule, "audit_ids": ids} for rule, ids in sorted(added)]})
            selected = [r for r in rows if r["dataset"] == name]
            configurations = {}
            for variant in VARIANTS:
                subset = [r for r in selected if r["variant"] == variant]
                configurations[variant] = {**metrics(subset),
                    "transitions": dict(sorted(Counter(r["full_outcome"] + "->" + r["outcome"]
                        for r in subset if r["full_outcome"] != r["outcome"]).items())),
                    "runs_with_lost_findings": sum(r["lost_findings"] > 0 for r in subset),
                    "unknown_role_references": sum(r["unknown_role_references"] for r in subset)}
            datasets[name] = {"distinct_cases": replay["distinct_cases"], "runs": replay["runs"],
                              "events": replay["events"], "configurations": configurations}
    if any(sha(ROOT / path) != value for path, value in sources.items()):
        raise ValueError("evidence changed during replay")
    summary = {"purpose": "component exclusion on existing final evaluation evidence",
               "new_live_runs": 0, "independent_generalization_test": False,
               "classification_unit": "scenario run", "variants": VARIANTS, "datasets": datasets,
               "runner_sha256": sha(Path(__file__)), "source_sha256": sources}
    write_json(output / "metrics.json", summary)
    write_json(output / "changes.json", changes)
    save_csv(output / "cases.csv", rows)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/components/final")
    args = parser.parse_args()
    print(json.dumps(run(args.output)["datasets"], ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
