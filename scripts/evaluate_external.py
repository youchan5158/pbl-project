"""Replay pinned external positive fixtures without tuning AuditGuard.

The units are vendor test files, not independent incidents. No normal controls
are provided, so precision, F1 and false-positive rate are intentionally absent.
No source event fields are rewritten. Case labels are used only after detection.
"""

import argparse
from collections import Counter
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from auditguard.advanced import detect_advanced
from auditguard.detector import detect
from auditguard.evaluate import save_csv
from auditguard.events import read_events, write_json
from auditguard.policy import load_policy

DATA = ROOT / "data/external/splunk-v1"
MODES = ("b0", "b1", "b3", "b4")
CASES = {
    "kube_audit_get_secret": ("E01", "Secret 조회", "secrets/get"),
    "kubernetes_scanning": ("E02", "익명 API 스캔", "unauthenticated/403"),
    "kubernetes_privileged_pod": ("E03", "특권 Pod 생성", "pods/create/privileged"),
    "kubernetes_audit_cron_job_creation": ("E04", "CronJob 생성", "cronjobs/create"),
    "kubernetes_audit_daemonset_created": ("E05", "DaemonSet 생성", "daemonsets/create"),
    "kube_audit_create_node_port_service": ("E06", "NodePort 생성", "services/create/NodePort"),
    "kubernetes_audit_pull_image": ("E07", "이미지 Pull 이벤트", "events/Pulling image"),
    "kubernetes_unauthorized_access": ("E08", "권한 없는 Job 생성 시도", "create/403"),
}
STATUS = {"alert": "탐지", "no_alert": "미탐", "out_of_scope": "설정 범위 밖",
          "unsupported_input": "입력 미지원", "invalid_input": "입력 오류"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def check_hashes(base, files):
    for name, expected in files.items():
        if sha((base / name).read_bytes()) != expected:
            raise ValueError("integrity mismatch: " + name)


def target(record, case):
    """Scoring-only target evidence check, based on the published test intent.

    This does not run Splunk SPL or claim to reproduce its model/allowlists.
    It never participates in AuditGuard inference or changes the input records.
    """
    ref = record.get("objectRef", {})
    verb, resource = record.get("verb"), ref.get("resource")
    obj = record.get("requestObject", {})
    if case == "E01":
        return resource == "secrets" and verb == "get"
    if case == "E02":
        return (record.get("responseStatus", {}).get("code") == 403
                and "system:unauthenticated" in record.get("user", {}).get("groups", []))
    if case == "E03":
        return resource == "pods" and verb in {"create", "update"} and any(
            c.get("securityContext", {}).get("privileged") is True
            for c in obj.get("spec", {}).get("containers", []))
    if case == "E04":
        return resource == "cronjobs" and verb == "create"
    if case == "E05":
        return resource == "daemonsets" and verb == "create"
    if case == "E06":
        return resource == "services" and verb == "create" and obj.get("spec", {}).get("type") == "NodePort"
    if case == "E07":
        return obj.get("message", "").startswith("Pulling image")
    if case == "E08":
        return verb == "create" and record.get("responseStatus", {}).get("code") == 403
    raise ValueError("unknown external case")


def verdict(stats, result):
    if stats.malformed or stats.conflicting_ids:
        return "invalid_input"
    if not stats.events:
        return "unsupported_input"
    if not result.inspected_events:
        return "out_of_scope"
    return "alert" if result.findings else "no_alert"


def reason(case, status):
    if status == "invalid_input":
        return "원본 입력 검증 실패; 정상으로 채점하지 않음"
    if status == "out_of_scope":
        return "수업용 네임스페이스·ServiceAccount 제한에 해당하지 않음"
    if case == "E01":
        return "R1이 원본 Secret GET을 탐지"
    if case == "E02":
        return "objectRef.resource 없는 비리소스 URL 요청 7건을 현재 정규화기가 제외"
    if case == "E08":
        return "403 Job 생성은 Secret·exec·조회량 규칙에 해당하지 않음; B0만 탐지"
    return "현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작"


def report(output, summary, rows, fixtures):
    at = {(r["case_id"], r["track"], r["mode"]): r for r in rows}
    lines = ["# 외부 공개 로그 보충 평가", "",
        "Splunk가 공개한 Kubernetes 탐지 규칙의 양성 시험 자료를 AuditGuard에 재생했다. "
        "Splunk 제품이나 SPL 규칙을 실행한 결과는 아니다. 원본 로그·타임스탬프·사용자·리소스를 수정하지 않았고 탐지 로직과 임계값도 변경하지 않았다.", "",
        f"- 평가 단위: 서로 다른 원본 파일 {len(fixtures)}개, 각 1회. 같은 파일을 참조한 여러 규칙은 중복 표본으로 세지 않는다.",
        f"- 원시 이벤트 {summary['raw_events']}개 / 정규화된 리소스 이벤트 {summary['normalized_events']}개.",
        "- 정상 대조군 없음. Precision·F1·오탐률은 계산하지 않는다. 벤더의 True Positive Test라는 출처를 사용하며 실제 침해 사고 정답 데이터라고 주장하지 않는다.",
        "- 단일 이벤트 파일이 많아 시간창·연속 공격 탐지의 성능을 평가하기에는 매우 작다.", "",
        "## 설정과 결과", "",
        "원래 배포 설정은 pbl-security의 ServiceAccount만 검사한다. 별도 portable_scope 시험에서는 "
        "원본에 등장하는 비어 있지 않은 네임스페이스 전체와 모든 사용자 유형을 검사 대상으로 지정했다. "
        "검사 범위 외의 정책·승인·프로필·임계값은 동일하다. 이 범위 조정은 배포 기본 설정에 반영하지 않았다.", "",
        "| 사례 | 원시 이벤트 | 배포 설정 B4 | 범위 조정 B0 | B1 | B3 | B4 |",
        "|---|---:|---|---|---|---|---|"]
    for f in fixtures:
        case = f["case_id"]
        cells = [f"{case} {f['title']}", str(f["raw_events"]),
                 STATUS[at[case, "deployment_default", "b4"]["status"]]]
        cells += [STATUS[at[case, "portable_scope", mode]["status"]] for mode in MODES]
        lines.append("| " + " | ".join(cells) + " |")
    counts = summary["tracks"]["portable_scope"]["b4"]
    lines += ["", f"범위 조정 B4: 전체 {len(fixtures)}개 중 대상 근거와 연결된 탐지 {counts['target_matches']}개, "
              f"검사 후 미탐 {counts['no_alert']}개, 입력 미지원 {counts['unsupported_input']}개, "
              f"설정 범위 밖 {counts['out_of_scope']}개, 입력 오류 {counts['invalid_input']}개. "
              "미지원 사례를 분모에서 지워 높은 탐지율로 표시하지 않는다.", "",
              "## 사례별 해석", ""]
    for f in fixtures:
        row = at[f["case_id"], "portable_scope", "b4"]
        lines.append(f"- **{f['case_id']} {f['title']}**: {reason(f['case_id'], row['status'])}.")
    lines += ["", "## 이 결과가 뒷받침하는 범위", "",
        "외부 환경에서 수집된 Secret 조회에 기존 R1이 작동한다는 좁은 근거다. "
        "반면 익명 비리소스 API 스캔은 입력 단계에서 빠지고, Job·Pod·CronJob·DaemonSet·Service 생성과 "
        "이미지 Pull 이벤트에 대한 탐지 범위가 부족함을 확인했다. 보편적인 Kubernetes 공격 탐지 성능의 검증으로 해석하지 않는다.", "",
        "원본에는 우리 작업 승인 정보가 없고 개별 토큰 식별자도 없어 B4의 토큰별 승인 효과를 검증하지 못한다. "
        "외부 사용자에게 해당하는 정상 프로필도 없으므로 B1·B3·B4 결과가 같다는 사실은 개선 기능의 효과나 무효를 입증하지 않는다. "
        "기존 63회 실습 결과와 합산하지 않는다.", "",
        "## 재현", "", "```powershell", "python scripts/evaluate_external.py",
        "python scripts/verify.py", "```", "",
        "로그가 없는 환경에서 원본을 다시 받으려면 `python scripts/fetch_external.py`를 실행한다. "
        "고정 커밋의 Git LFS SHA-256/크기를 확인한다. 재생 시 원본 로그, 출처 문서, 탐지 소스와 설정 해시를 모두 검사한다.", "",
        "- 상세 수치: metrics.json / cases.csv", "- 알림별 auditID 근거: findings.json", "",
        "## 출처", "",
        f"- [Splunk attack_data 고정 커밋](https://github.com/splunk/attack_data/tree/{summary['attack_data_commit']})",
        f"- [Splunk security_content 고정 커밋](https://github.com/splunk/security_content/tree/{summary['security_content_commit']})",
        "- [Kubernetes Security 공식 설명](https://research.splunk.com/stories/kubernetes_security/)", ""]
    for f in fixtures:
        lines.append(f"- [{f['case_id']} {f['title']}](https://github.com/splunk/attack_data/blob/{summary['attack_data_commit']}/{f['source_path']})")
    (output / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def evaluate(output):
    frozen = json.loads((DATA / "freeze.json").read_text(encoding="utf-8"))
    sources = json.loads((DATA / "sources.json").read_text(encoding="utf-8"))
    downloads = json.loads((DATA / "downloads.json").read_text(encoding="utf-8"))
    check_hashes(ROOT, frozen["files"])
    check_hashes(DATA, {"frozen-policy.json": frozen["files"]["config/live-policy.json"],
                       "frozen-context.json": frozen["files"]["config/advanced.json"]})
    check_hashes(DATA / "upstream-detections", {Path(d["path"]).name: d["sha256"] for d in downloads["detections"]})
    if {x["path"] for x in downloads["datasets"]} != set(sources["data_paths"]):
        raise ValueError("download inventory differs from the fixed source inventory")
    loaded, namespaces = [], set()
    for item in downloads["datasets"]:
        path = DATA / "logs" / Path(item["path"]).name
        if sha(path.read_bytes()) != item["sha256"]:
            raise ValueError("external source changed: " + path.name)
        records = [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip()]
        case, title, intent = CASES[path.stem]
        targets = {r["auditID"] for r in records if target(r, case)}
        if not targets:
            raise ValueError("source lacks the described target action: " + case)
        events, stats = read_events(path)
        namespaces.update(e.namespace for e in events if e.namespace)
        loaded.append((item, case, title, intent, records, targets, events, stats))
    policy = load_policy(DATA / "frozen-policy.json")
    context = json.loads((DATA / "frozen-context.json").read_text(encoding="utf-8"))
    portable = deepcopy(policy)
    portable["scope"] = {"namespaces": sorted(namespaces), "service_accounts_only": False}
    policies = {"deployment_default": policy, "portable_scope": portable}
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "portable-policy.json", portable)
    rows, evidence, fixtures = [], [], []
    for item, case, title, intent, records, targets, events, stats in loaded:
        fixtures.append({"case_id": case, "title": title, "target_description": intent,
                         "source_path": item["path"], "sha256": item["sha256"],
                         "raw_events": len(records), "normalized_events": len(events),
                         "target_audit_ids": sorted(targets), "read_stats": asdict(stats)})
        for track, selected in policies.items():
            for mode in MODES:
                result = detect_advanced(events, selected, context, mode) if mode in {"b3", "b4"} else detect(events, selected, mode)
                status = verdict(stats, result)
                observed = {e["audit_id"] for f in result.findings for e in f.get("evidence", [])}
                matched = sorted(targets & observed)
                rows.append({"case_id": case, "title": title, "track": track, "mode": mode,
                             "status": status, "target_match": bool(matched) and status == "alert",
                             "raw_events": len(records), "normalized_events": len(events),
                             "inspected_events": result.inspected_events, "out_of_scope_events": result.out_of_scope,
                             "alerts": len(result.findings), "rules": ",".join(sorted({f["rule"] for f in result.findings})),
                             "non_resource_events": stats.non_resource, "malformed": stats.malformed})
                evidence.append({"case_id": case, "track": track, "mode": mode, "status": status,
                                 "matched_target_audit_ids": matched, "findings": result.findings,
                                 "suppressed": result.suppressed})
    summary = {"schema_version": 1, "source_type": "external_vendor_positive_fixtures",
               "attack_data_commit": sources["attack_data_commit"], "security_content_commit": sources["security_content_commit"],
               "case_count": len(fixtures), "raw_events": sum(f["raw_events"] for f in fixtures),
               "normalized_events": sum(f["normalized_events"] for f in fixtures),
               "events_with_credential_identifier": sum(bool(e.credential_id_hash) for item in loaded for e in item[6]),
               "normal_controls": 0, "precision": None, "f1": None, "fpr": None,
               "rules_unchanged": True, "thresholds_unchanged": True,
               "harness_sha256": sha(Path(__file__).read_bytes()), "tracks": {}}
    for track in policies:
        summary["tracks"][track] = {}
        for mode in MODES:
            selected_rows = [r for r in rows if r["track"] == track and r["mode"] == mode]
            counts = Counter(r["status"] for r in selected_rows)
            summary["tracks"][track][mode] = {**{k: counts[k] for k in STATUS},
                "target_matches": sum(r["target_match"] for r in selected_rows),
                "total_fixtures": len(selected_rows)}
    check_hashes(ROOT, frozen["files"])
    write_json(output / "metrics.json", summary)
    write_json(output / "fixtures.json", fixtures)
    write_json(output / "findings.json", evidence)
    save_csv(output / "cases.csv", rows)
    report(output, summary, rows, fixtures)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "results/external/splunk-v1")
    args = parser.parse_args()
    summary = evaluate(args.output)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
