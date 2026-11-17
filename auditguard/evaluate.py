"""Scenario-run evaluation, integrity checks, dev-only parameter search."""

from collections import Counter
from copy import deepcopy
from dataclasses import asdict
import csv
import hashlib
import html
import json
from pathlib import Path

from .detector import detect, MODES
from .events import read_events, write_json, write_jsonl
from .policy import digest, validate_policy


def metrics(rows: list[dict]) -> dict:
    good = [r for r in rows if r["valid"]]
    counts = Counter((r["label"], r["prediction"]) for r in good)
    tp, fp = counts["attack", "alert"], counts["normal", "alert"]
    fn, tn = counts["attack", "normal"], counts["normal", "normal"]
    ratio = lambda a, b: a / b if b else None
    return {"valid_runs": len(good), "invalid_runs": len(rows) - len(good),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": ratio(tp, tp + fp), "recall": ratio(tp, tp + fn),
            "f1": ratio(2 * tp, 2 * tp + fp + fn), "fpr": ratio(fp, fp + tn)}


def load_dataset(path: str | Path) -> tuple[dict, list[tuple[dict, list, object, list[str]]]]:
    path = Path(path)
    manifest = json.loads(path.read_text(encoding="utf-8-sig"))
    if manifest.get("schema_version") != 1 or manifest.get("source_type") not in {"provided_example", "synthetic", "live"} or not isinstance(manifest.get("runs"), list) or not manifest["runs"]:
        raise ValueError("invalid dataset manifest")
    seen = set()
    loaded = []
    for run in manifest["runs"]:
        if not isinstance(run.get("run_id"), str) or run["run_id"] in seen or run.get("label") not in {"normal", "attack"} or not isinstance(run.get("scenario"), str):
            raise ValueError("duplicate/invalid run or label")
        seen.add(run["run_id"])
        errors = []
        events, stats = [], None
        source = path.parent / run["path"]
        if run.get("status") != "complete":
            errors.append("collection_not_complete")
        try:
            if hashlib.sha256(source.read_bytes()).hexdigest() != run.get("sha256"):
                errors.append("sha256_mismatch")
            events, stats = read_events(source)
        except (OSError, UnicodeError):
            errors.append("unreadable_log")
        if stats and (stats.malformed or stats.conflicting_ids):
            errors.append("malformed_or_conflicting_events")
        if not events:
            errors.append("no_events")
        if type(run.get("expected_events")) is not int or len(events) != run["expected_events"]:
            errors.append("event_count_mismatch")
        if run.get("actor") and any(e.actor != run["actor"] for e in events):
            errors.append("unexpected_actor")
        loaded.append((run, events, stats, errors))
    return manifest, loaded


def evaluate_loaded(loaded: list, policy: dict, mode: str, disabled: frozenset[str] = frozenset(), detector=None) -> tuple[list[dict], list[dict]]:
    rows, findings = [], []
    for run, events, stats, input_errors in loaded:
        errors = list(input_errors)
        detection = (detector or detect)(events, policy, mode, disabled)
        if detection.inspected_events == 0:
            errors.append("no_in_scope_events")
        # Case identifiers are attached AFTER detection. The detector only
        # receives normalized audit metadata and independently supplied policy.
        rows.append({"run_id": run["run_id"], "scenario": run["scenario"], "label": run["label"],
                     "prediction": detection.prediction if not errors else "invalid",
                     "valid": not errors, "errors": ";".join(errors), "events": len(events),
                     "alerts": len(detection.findings), "suppressed": len(detection.suppressed),
                     "rules": ",".join(sorted({f["rule"] for f in detection.findings})),
                     "duplicates": stats.duplicates if stats else 0})
        findings.append({"run_id": run["run_id"], "valid": not errors, "mode": mode,
                         "findings": detection.findings, "suppressed": detection.suppressed,
                         "read_stats": asdict(stats) if stats else None})
    return rows, findings


def save_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]) if rows else [])
        writer.writeheader()
        writer.writerows(rows)


def fmt(value: object) -> str:
    return "N/A" if value is None else f"{value:.3f}" if isinstance(value, float) else str(value)


def write_report(output: Path, summary: dict, predictions: dict) -> None:
    lines = ["# 실험 결과", "", f"- 데이터: `{summary['dataset_id']}`", f"- 출처 구분: **{summary['source_type']}**", f"- 정책 SHA-256: `{summary['policy_sha256']}`", "- 평가 단위: 시나리오 실행 1회. 알림이 한 개 이상이면 alert.", "- 합성/제공 예제의 반복 재생 결과는 실제 운영 환경 성능을 뜻하지 않는다.", "", "| 구성 | TP | FP | FN | TN | Precision | Recall | F1 | FPR | 무효 실행 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for name, value in summary["configurations"].items():
        lines.append("| " + " | ".join([name] + [fmt(value[key]) for key in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr", "invalid_runs")]) + " |")
    visible_modes = [m for m in predictions if "_without_" not in m]
    lines += ["", "## 시나리오별 결과", "", "| 시나리오 | 정답 | " + " | ".join(m.upper() + " 알림/유효" for m in visible_modes) + " |", "|---|---|" + "---:|" * len(visible_modes)]
    cases = sorted({r["scenario"] for r in predictions["b0"]})
    for case in cases:
        cells = [case, next(r["label"] for r in predictions["b0"] if r["scenario"] == case)]
        for mode in visible_modes:
            good = [r for r in predictions[mode] if r["scenario"] == case and r["valid"]]
            cells.append(f"{sum(r['prediction'] == 'alert' for r in good)}/{len(good)}")
        lines.append("| " + " | ".join(cells) + " |")
    lines += ["", "## 해석", "", "B0는 모든 403을 의심한다. B1은 Secret 읽기, exec, 다종 조회 폭증을 탐지한다. B2는 명시된 정상 모니터링 한도와 대상·시간이 일치하는 Secret GET 승인을 적용한다.", "", "FP는 정상 실행에 알림을 낸 경우, FN은 공격 시나리오에 알림을 내지 못한 경우다. 403은 실패한 접근 시도이며, 200이라는 사실만으로 요청 의도가 정상이라고 판단할 수 없다.", "", "승인 작업과 동일한 계정·대상·시간·행동의 악용, 낮은 빈도의 허용 API 정찰은 Audit 메타데이터만으로 구분하기 어렵다. 예외 정책은 오탐을 줄이지만 탐지 범위도 줄일 수 있다."]
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    esc = html.escape
    metric_rows = "".join("<tr><th>" + esc(name) + "</th>" + "".join("<td>" + fmt(value[k]) + "</td>" for k in ("tp", "fp", "fn", "tn", "precision", "recall", "f1", "fpr")) + "</tr>" for name, value in summary["configurations"].items())
    case_rows = []
    for mode in visible_modes:
        for row in predictions[mode]:
            outcome = "INVALID" if not row["valid"] else ("TP" if row["label"] == "attack" else "FP") if row["prediction"] == "alert" else ("FN" if row["label"] == "attack" else "TN")
            case_rows.append(f'<tr data-outcome="{outcome}"><td>{mode.upper()}</td><td>{esc(row["run_id"])}</td><td>{esc(row["label"])}</td><td>{esc(row["prediction"])}</td><td class="{outcome}">{outcome}</td><td>{row["events"]}</td><td>{esc(row["rules"])}</td><td>{row["suppressed"]}</td></tr>')
    document = '''<!doctype html><html lang="ko"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AuditGuard 실험 결과</title>
<style>body{font:16px/1.6 system-ui,sans-serif;background:#f2f5f8;color:#182b3b;margin:0}main{max-width:1100px;margin:auto;padding:40px 24px}h1{font-size:32px}h2{margin-top:36px}.badge{display:inline-block;background:#e2ecff;padding:6px 14px;border-radius:20px}table{border-collapse:collapse;background:white;width:100%;font-size:14px}th,td{padding:10px 12px;border-bottom:1px solid #e1e7ec;text-align:left}th{background:#e9eff5}code{overflow-wrap:anywhere}.FP,.FN,.INVALID{color:#b22424;font-weight:bold}select{font:inherit;padding:6px;margin:12px 0}aside{padding:16px 20px;border-left:4px solid #3a69b4;background:white}.scroll{overflow:auto}</style>
<main><span class="badge">Kubernetes Audit Log · 재현 가능한 평가</span><h1>API 자격 증명 악용 탐지</h1>'''
    document += f'<p>데이터: <strong>{esc(summary["dataset_id"])}</strong> / 출처: <strong>{esc(summary["source_type"])}</strong></p><aside>합성·제공 예제 결과는 실제 환경 성능 추정치가 아닙니다. 403은 차단된 시도입니다. 승인과 동일한 행위의 악용은 탐지 한계가 있습니다.</aside><h2>구성 비교</h2><p>B0 모든 403 · B1 행위 규칙 · B2 운영 맥락 적용 · without 구성은 해당 규칙 제거 실험</p><div class="scroll"><table><tr><th>구성</th><th>TP</th><th>FP</th><th>FN</th><th>TN</th><th>Precision</th><th>Recall</th><th>F1</th><th>FPR</th></tr>{metric_rows}</table></div><h2>실행별 판정</h2><label>결과 필터 <select id="filter"><option value="all">전체</option><option>FP</option><option>FN</option><option>TP</option><option>TN</option><option>INVALID</option></select></label><div class="scroll"><table id="runs"><tr><th>구성</th><th>실행</th><th>정답</th><th>예측</th><th>결과</th><th>이벤트</th><th>규칙</th><th>승인 적용</th></tr>{"".join(case_rows)}</table></div><p>정책 SHA-256: <code>{summary["policy_sha256"]}</code></p><p>상세 근거: 같은 폴더의 findings-*.jsonl · 집계: metrics.json · 보고서: report.md</p></main>'
    document += '<script>document.getElementById("filter").onchange=function(){document.querySelectorAll("#runs tr[data-outcome]").forEach(r=>{r.hidden=this.value!=="all"&&r.dataset.outcome!==this.value})}</script></html>'
    (output / "index.html").write_text(document, encoding="utf-8")


def evaluate(manifest_path: str | Path, policy: dict, output: str | Path, ablation: bool = True) -> dict:
    policy = validate_policy(policy)
    manifest, loaded = load_dataset(manifest_path)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    summary = {"schema_version": 1, "dataset_id": manifest["dataset_id"], "source_type": manifest["source_type"], "split": manifest.get("split"), "evaluation_unit": "scenario_run", "policy_sha256": digest(policy), "manifest_sha256": hashlib.sha256(Path(manifest_path).read_bytes()).hexdigest(), "configurations": {}}
    predictions = {}
    configurations = [(m, m, frozenset()) for m in MODES]
    if ablation:
        configurations += [("b2_without_" + r, "b2", frozenset([r])) for r in ("R1", "R2", "R3")]
    for name, mode, disabled in configurations:
        rows, findings = evaluate_loaded(loaded, policy, mode, disabled)
        predictions[name] = rows
        summary["configurations"][name] = metrics(rows)
        save_csv(output / ("predictions-" + name + ".csv"), rows)
        write_jsonl(output / ("findings-" + name + ".jsonl"), findings)
    write_json(output / "metrics.json", summary)
    write_json(output / "policy.json", policy)
    write_report(output, summary, predictions)
    return summary


def tune(manifest_path: str | Path, policy: dict, output: str | Path, calibrate_context: bool = False) -> dict:
    manifest, loaded = load_dataset(manifest_path)
    if manifest.get("split") != "development":
        raise ValueError("tuning is allowed only on the development split")
    if any(errors for _, _, _, errors in loaded):
        raise ValueError("development data contains invalid runs")
    rows = []
    for window in (2, 5, 10, 30):
        for threshold in (6, 10, 14, 20):
            candidate = deepcopy(policy)
            candidate["burst"].update(window_seconds=window, request_threshold=threshold)
            predictions, _ = evaluate_loaded(loaded, candidate, "b1")
            score = metrics(predictions)
            rows.append({"window_seconds": window, "request_threshold": threshold, **score})
    # Fixed selection before evaluating the evaluation set: F1, FP, smaller
    # window (less cross-activity mixing), then larger count threshold.
    rows.sort(key=lambda r: (-(r["f1"] or 0), r["fp"], r["window_seconds"], -r["request_threshold"]))
    winner = rows[0]
    frozen = deepcopy(policy)
    frozen["burst"].update({k: winner[k] for k in ("window_seconds", "request_threshold")})
    calibration = []
    if calibrate_context:
        from collections import deque
        from datetime import timedelta
        for profile in frozen["monitor_profiles"]:
            peak = 0
            for run, events, _, errors in loaded:
                if errors or run["label"] != "normal" or run.get("actor") != profile["actor"]:
                    continue
                window_events = deque()
                for event in events:
                    if event.namespace != profile["namespace"] or event.resource not in profile["resources"] or event.verb not in profile["verbs"] or event.api_group or event.subresource or not 200 <= event.code < 300:
                        continue
                    window_events.append(event)
                    while event.time - window_events[0].time > timedelta(seconds=winner["window_seconds"]):
                        window_events.popleft()
                    peak = max(peak, len(window_events))
            if not peak:
                raise ValueError("no valid normal monitor data for calibration")
            # Fixed headroom rule, chosen before final live evaluation.
            # It uses NORMAL development observations only.
            profile["request_threshold"] = max(winner["request_threshold"], 2 * peak + 1)
            calibration.append({"actor": profile["actor"], "normal_peak": peak, "request_threshold": profile["request_threshold"], "formula": "max(base, 2 * normal_peak + 1)"})
    validate_policy(frozen)
    output = Path(output)
    save_csv(output / "grid.csv", rows)
    write_json(output / "selected-policy.json", frozen)
    result = {"split": "development", "source_type": manifest["source_type"], "selection_rule": "max F1, min FP, min window, max count", "winner": winner, "policy_sha256": digest(frozen), "context_calibration": calibration}
    write_json(output / "selection.json", result)
    return result
