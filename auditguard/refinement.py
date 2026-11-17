"""Development-only long-window selection and same-dataset B0..B4 comparison."""

from collections import deque, defaultdict
from copy import deepcopy
from datetime import timedelta
import hashlib
from pathlib import Path

from .advanced import detect_advanced, validate_context
from .evaluate import evaluate_loaded, load_dataset, metrics, save_csv, write_report
from .events import write_json, write_jsonl
from .policy import digest


def calibrate(manifest_path, policy, output):
    manifest, loaded = load_dataset(manifest_path)
    if manifest.get("split") != "development" or any(errors for _, _, _, errors in loaded):
        raise ValueError("valid development data required")
    rows = []
    for seconds in (30, 60, 90, 120):
        for count in (6, 9, 12):
            normal_peak = 0
            for run, events, _, _ in loaded:
                if run["label"] != "normal":
                    continue
                for profile in policy["monitor_profiles"]:
                    window = deque()
                    for event in events:
                        if event.key != (profile["actor"], profile["namespace"]) or event.verb != "list" or event.resource not in profile["resources"]:
                            continue
                        window.append(event)
                        while event.time - window[0].time > timedelta(seconds=seconds):
                            window.popleft()
                        normal_peak = max(normal_peak, len(window))
            context = {"version": 1, "long_window": {"window_seconds": seconds, "request_threshold": count,
                       "resource_threshold": 3, "monitor_threshold": max(count, 2 * normal_peak + 1)}, "intents": []}
            predictions, _ = evaluate_loaded(loaded, policy, "b3",
                detector=lambda events, p, m, d: detect_advanced(events, p, context, m, d))
            rows.append({"window_seconds": seconds, "request_threshold": count,
                         "monitor_threshold": context["long_window"]["monitor_threshold"], **metrics(predictions)})
    winner = min(rows, key=lambda r: (r["fn"], r["fp"], r["window_seconds"], -r["request_threshold"]))
    selected = {"version": 1, "long_window": {k: winner[k] for k in ("window_seconds", "request_threshold", "monitor_threshold")} | {"resource_threshold": 3}, "intents": []}
    output = Path(output)
    save_csv(output / "grid.csv", rows)
    write_json(output / "selected-context.json", selected)
    summary = {"source_manifest_sha256": hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(),
               "split": "development", "selection_rule": "min FN, then FP, then window, then max count",
               "winner": winner, "context_sha256": digest(selected)}
    write_json(output / "selection.json", summary)
    return selected


def compare(manifest_path, policy, context, output):
    context = validate_context(context)
    manifest, loaded = load_dataset(manifest_path)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": 1, "dataset_id": manifest["dataset_id"],
               "source_type": manifest["source_type"], "split": manifest.get("split"),
               "evaluation_unit": "scenario_run", "policy_sha256": digest(policy),
               "context_sha256": digest(context),
               "manifest_sha256": hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(),
               "configurations": {}}
    predictions = {}
    configs = [(m, m, frozenset()) for m in ("b0", "b1", "b2", "b3", "b4")]
    configs += [("b4_without_" + name, "b4", frozenset([name])) for name in ("long_window", "credential_intents", "resource_profile")]
    for name, mode, disabled in configs:
        detector = None if mode in {"b0", "b1", "b2"} else lambda events, p, m, d: detect_advanced(events, p, context, m, d)
        rows, findings = evaluate_loaded(loaded, policy, mode, disabled, detector)
        summary["configurations"][name] = metrics(rows)
        predictions[name] = rows
        save_csv(output / f"predictions-{name}.csv", rows)
        write_jsonl(output / f"findings-{name}.jsonl", findings)
    write_json(output / "metrics.json", summary)
    write_json(output / "policy.json", policy)
    write_json(output / "context.json", context)
    write_report(output, summary, predictions)
    with (output / "report.md").open("a", encoding="utf-8") as stream:
        stream.write("\n## 추가 구성\n\nB3: Secret 경보 유지 + 장기 목록 조회 누적. B4: B3 + 서버가 인증한 토큰 식별자에 묶인 작업별 승인·횟수 제한. 승인 토큰 자체의 첫 사용 탈취와 한도 이하 정찰은 놓칠 수 있다. 승인되지 않은 정상 대량 조회는 오탐일 수 있다.\n")
    page = output / "index.html"
    page.write_text(page.read_text(encoding="utf-8").replace("B2 운영 맥락 적용 · without", "B2 계정 승인 · B3 장기 누적 · B4 토큰별 작업 승인 · without"), encoding="utf-8")
    return summary


def calibrate_resources(manifest_path, context, output):
    manifest, loaded = load_dataset(manifest_path)
    if manifest.get("split") != "development" or any(errors or run["label"] != "normal" for run, _, _, errors in loaded):
        raise ValueError("valid NORMAL development data required")
    context = deepcopy(context)
    peaks = defaultdict(int)
    for _, events, _, _ in loaded:
        windows = defaultdict(deque)
        for event in events:
            if event.api_group or event.subresource or event.verb != "list" or not 200 <= event.code < 300 or event.resource not in {"pods", "services", "configmaps"}:
                continue
            key = (*event.key, event.resource)
            window = windows[key]
            window.append(event)
            while event.time - window[0].time > timedelta(seconds=context["long_window"]["window_seconds"]):
                window.popleft()
            peaks[key] = max(peaks[key], len(window))
    if not peaks:
        raise ValueError("no normal list observations for resource profiles")
    context["resource_profiles"] = [{"actor": key[0], "namespace": key[1], "resource": key[2],
        "request_threshold": max(6, 2 * peak + 1)} for key, peak in sorted(peaks.items())]
    validate_context(context)
    output = Path(output)
    write_json(output / "selected-context.json", context)
    write_json(output / "resource-calibration.json", {
        "manifest_sha256": hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(),
        "split": "development", "selection_rule": "normal data only; max(6, 2 * per-resource peak + 1)",
        "peaks": [{"actor": k[0], "namespace": k[1], "resource": k[2], "normal_peak": v} for k, v in sorted(peaks.items())],
        "context_sha256": digest(context)})
    return context
