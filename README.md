# AuditGuard B5: Kubernetes API/Credential 악용 탐지

자격 증명·원격 실행·정찰·RBAC 권한 변경·위험한 워크로드의 **5개 행동군**을 다룬다. 요청의 보안 속성과 개별 토큰에 묶인 사전 승인을 결합한 Python 프로젝트다.

먼저 [이해 가이드](docs/UNDERSTAND.md)를 읽고 [실제 실행 통합 보고서](docs/INTEGRATION_REPORT.md)에서 최신 결과와 한계를 확인한다. [이전 API 단계 보고서](docs/REPORT.md)는 보존했다.

## 실제 컨테이너 통합 검증 추가

실행 노드 1개에 kubelet·containerd를 구성하고 **16종 × 2회 = 32회**, 44개 실제 API 감사 이벤트를 수집했다. 성공한 측정 exec 8회, RBAC 거부 exec 2회, 실제 Running 워크로드 16개, 같은 토큰의 권한 변경 전후 `403 → 201 → 200` 전이 6회를 검증했다. 무효 0회다.

탐지 코드는 기존 B5 그대로다. 동일한 새 32회에서 B4는 TP 10·FP 4·FN 6·TN 12, **B5는 TP 14·FP 4·FN 2·TN 12**였다. B5 Precision 77.8%, Recall 87.5%, F1 0.824다. 승인 누락 정상 관리 작업과 정상적인 변경 전 거부 점검이 오탐을, 승인 토큰·동일 명령 도용이 미탐을 만들었다.

아래 66회와 사례 구성이 다르므로 수치를 직접적인 성능 증감으로 해석하지 않는다. 자체 설계 통합 실험이며, 운영 환경의 일반적인 탐지율을 뜻하지 않는다. 실제 명령 출력·종료 코드·Pod UID·컨테이너 ID를 [실행 증거](data/integration-eval/proofs)에 보존했다. [상세 결과와 한계](docs/INTEGRATION_REPORT.md) · [재현 방법](docs/INTEGRATION_LAB.md).

## 보존한 API 단계 평가 결과

개발과 분리한 33종(정상 15종·공격 18종)을 새 토큰으로 2회씩 실행했다. 총 66회·158개 실제 Kubernetes 감사 이벤트, 무효 0회. 구현과 기준을 고정한 뒤 수집했다. 이 환경은 노드가 없는 API 단계 평가였으며 성공한 컨테이너 실행을 입증하지 않는다.

| 같은 새 로그의 결과 | B4 | B5 |
|---|---:|---:|
| 공격 탐지 / 36회 | 10 | 32 |
| 정상 작업 오탐 / 30회 | 4 | 2 |
| 탐지 못한 공격(미지원 포함) | 26 | 4 |
| 위 미탐 중 입력·범위 미지원 | 8 | 0 |
| 정상 입력·범위 미지원 | 6 | 0 |

B5: **TP 32 · FP 2 · FN 4 · TN 28**, Precision 94.1%, Recall 88.9%, F1 0.914. B4 미탐지 26회는 검사 후 미탐 18회와 미지원 8회다. 미지원 정상 요청은 TN으로 계산하지 않는다.

작성자가 설계한 소규모 평가다. 반복 66회는 독립 공격 66종이 아니다. 알려진 외부 Splunk 자료는 B4 1/8, B5 3/8 경보였다. 외부 정상 자료가 없어 외부 F1·오탐률은 계산하지 않는다.

## 실행

Python 3.10 이상. 저장 로그 재생에는 별도 VM·Docker·추가 패키지가 필요 없다.

```powershell
python scripts/evaluate_integration.py
python scripts/verify.py
python -m auditguard.behavior --input data/behavior-eval/logs/A13-01.jsonl --output results/local/b5-demo
```

**새 B5 명령은 `python -m auditguard.behavior`**다. 기존 `python -m auditguard scan`은 B4 비교용으로 보존했다. 새 단일 로그에 작업 승인이 필요하면 `--config`에 해당 작업의 신뢰된 승인·Role 권한 스냅샷을 지정한다. 설정이 없으면 보수적으로 경보한다.

## 제출 자료

| 자료 | 위치 |
|---|---|
| 최신 통합 검증 보고서 | [docs/INTEGRATION_REPORT.md](docs/INTEGRATION_REPORT.md) |
| 실제 실행 증거·새 감사 로그 | [data/integration-eval](data/integration-eval) |
| 통합 결과·이전 결과 비교 | [results/integration/final](results/integration/final) |
| 실제 노드 재현 안내 | [docs/INTEGRATION_LAB.md](docs/INTEGRATION_LAB.md) |
| 이해 가이드 | [docs/UNDERSTAND.md](docs/UNDERSTAND.md) |
| 결과·사례·한계 보고서 | [docs/REPORT.md](docs/REPORT.md) |
| 최종 수치·사례별 근거 | [results/behavior/fresh](results/behavior/fresh) |
| 고정 기록·새 실제 로그 | [data/behavior-eval](data/behavior-eval) |
| 실험 방법·사전 계획 | [통합 평가 방법](docs/INTEGRATION_PROTOCOL.md), [요청 계획](data/integration-eval/request-plan.json) |

## 한계

기존 66회에서 남은 오류는 승인 없는 정상 인벤토리(FP 2), 승인 토큰 최초 사용 도용(FN 2), 단발 저빈도 정찰(FN 2)이다. 새 32회의 오류는 위 통합 결과에 별도로 보고했다. 실제 실행 증거는 보완했지만 실제 침해·컨테이너 탈출·장기 운영 분포·실시간 차단은 검증하지 않았다. 탐지는 수집한 로그에 대한 배치 판정이다.

## 패키지 생성

```powershell
python scripts/verify.py
python scripts/package_submission.py
```

`output/submission/auditguard-integration-pbl.zip`에 코드·실측 로그·실행 증거·출처·결과·문서·파일별 SHA-256이 들어간다. VM 런타임·개인 키·bearer token과 발표자료는 포함하지 않는다.

[공통 저장소](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)의 Category 1·2·3, workload, 설치 스크립트와 원본 문서를 그대로 보존했다. 원래 한국어 README는 [UPSTREAM_README.md](docs/UPSTREAM_README.md)에 있다. 원본 39개 파일의 해시를 검증한다. [출처·추가 구현 범위](docs/PROVENANCE.md).

추가 구현에는 최종 코드, 최종 평가 로그·실행 증거·결과와 사용 문서만 포함한다. 중간 실험, smoke test, 개발 노트, 중간 보고서와 로컬 검증 출력은 Git·제출 ZIP에서 제외한다. 검증 출력은 `results/local/verification.json`에 저장된다.
