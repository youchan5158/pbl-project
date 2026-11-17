# Kubernetes API/Credential 악용 탐지

Kubernetes 감사 로그에서 **자격 증명 접근, 원격 실행, 정찰, 권한 변경, 위험한 워크로드**를 탐지한다. API 요청의 위험 속성과 사전에 승인한 작업을 함께 검사하고, 경보 또는 억제 이유를 남기는 Python 배치 탐지기다.

## 탐지 방식

| 행동군 | 확인하는 행위 | 정상과 구분하는 근거 |
|---|---|---|
| 자격 증명 | Secret 조회, ServiceAccount 토큰 발급 등 | 민감 리소스·발급 동작과 승인 범위 |
| 원격 실행 | Pod exec / attach | 호출자·토큰·대상·명령 지문의 일치 |
| 정찰 | 반복 실패, 여러 리소스 목록 조회 | 시간 창·횟수·대상 다양성과 정상 조회 프로필 |
| 권한 변경 | Role / RoleBinding 등의 변경 | 연결된 역할의 실제 권한 내용 |
| 위험 워크로드 | privileged, hostPID, hostPath, 위험 capability 등 | Pod 및 컨트롤러 템플릿의 보안 속성 |

정상 승인은 작업자, 개별 토큰 식별자, 요청 지문, 시간, 횟수를 제한한다. API 권한이 있다고 해서 정상 업무로 판단하지 않는다. 401/403 요청은 승인으로 억제하지 않는 보수적 정책을 사용한다.

## 실행

Python 3.10 이상. 저장 로그 재생에는 VM·Docker·추가 Python 패키지가 필요 없다.

```powershell
python scripts/verify.py
python scripts/evaluate_integration.py --output results/local/integration
python -m auditguard.behavior --input data/integration-eval/logs/X02-01.jsonl --output results/local/exec-demo
```

단일 로그를 정상 작업 승인과 함께 분석하려면 해당 실행의 `--config`와 `--legacy-context` 파일을 지정한다. 정확한 예시는 [이해 가이드](docs/UNDERSTAND.md)에 있다. 승인 정보가 없으면 위험 요청을 보수적으로 경보한다.

## 실험 결과

모든 행은 같은 최종 탐지기를 서로 다른 자료에 적용한 결과다. 평가 목적과 사례 구성이 달라 합산하지 않는다.

| 평가 | 규모 | 최종 결과 | 검증 범위 |
|---|---|---|---|
| 수업 기본 예제 | 정상 1·공격 3개, 24개 이벤트 | 4개 모두 예상 판정과 일치 | 제공 예제 호환성 |
| API 동작 범위 평가 | 33종 × 2회, 158개 이벤트 | TP 32 / FP 2 / FN 4 / TN 28 | 5개 행동군의 API 패턴 |
| 실제 실행 통합 평가 | 16종 × 2회, 44개 이벤트 | TP 14 / FP 4 / FN 2 / TN 12 | 컨테이너 실행과 권한 효과 |
| 외부 공개 로그 | 공격 양성 8개, 14개 이벤트 | 3개 사례에서 경보 | 외부 작성 로그에 대한 보충 검증 |

실제 실행 통합 평가의 **Precision은 77.8%, Recall은 87.5%, F1은 0.824**다. 정상 16회 중 4회를 오탐했고, 공격 16회 중 2회를 놓쳤다. 승인 등록이 없는 정상 관리 작업과 정상적인 거부 점검이 오탐을, 정상 승인과 동일한 토큰·명령의 도용 가정이 미탐을 만들었다.

API 동작 범위 평가의 Precision은 94.1%, Recall은 88.9%, F1은 0.914다. 이 자료는 실행 노드가 없는 환경의 API 로그이므로 컨테이너 명령 성공을 입증하지 않는다. 실제 실행 통합 평가는 별도로 Ready 노드 1개에서 수행했다. 외부 자료에는 정상 대조군이 없어 Precision·F1·오탐률을 계산하지 않는다.

수치와 단위는 [최종 결과 요약](results/final-summary.json), 자세한 사례와 한계는 [평가 보고서](docs/REPORT.md)와 [실제 실행 보고서](docs/INTEGRATION_REPORT.md)에 있다. 자체 설계 소규모 실험이며 운영 환경의 일반적인 탐지율을 뜻하지 않는다.

## 평가 데이터의 출처와 생성

수업 예제는 [cclab-inu/Practical-Cloud-Security-PBL](https://github.com/cclab-inu/Practical-Cloud-Security-PBL/tree/270bf2df9ae1eddfb26e8dc88cb92326c54a99a8/category3/logs)의 제공 로그다. 자체 API·실행 실험은 **OpenAI Codex의 `gpt-6-astra`가 시나리오·의도 라벨·수집 코드를 작성**하고, 이를 실제 K3s에서 실행해 감사 로그와 실행 증거를 수집했다. 사전에 정상·공격 의도와 승인을 정의하고 실제 요청을 보낸 다음, 응답과 감사 이벤트를 연결해 해시와 함께 저장했다. 위 실측 결과는 AI가 로그 문장을 합성한 데이터로 계산한 수치가 아니다.

외부 자료는 **Splunk Attack Data의 Kubernetes Security 관련 True Positive Test 로그 8개**다. [attack_data](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c)와 [security_content](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)의 고정 버전을 사용했고, 원본 파일의 해시를 확인한 뒤 그대로 재생했다. 정상 대조군 없는 벤더 시험 자료이므로 표준 성능 벤치마크와 구분한다. 파일별 출처, AI 사용 범위, 생성·수집 절차는 [데이터 출처 문서](docs/PROVENANCE.md#평가-데이터의-출처와-생성-방법)에 정리했다.

## 각 기능이 필요한 이유

최종 구성에서 한 요소씩 제외해 같은 로그를 재생했다. 작업 승인을 제외하면 실제 실행 자료의 오탐이 4회에서 10회로 늘었고, 워크로드 보안 속성 경보를 제외하면 미탐이 2회에서 8회로 늘었다. API 동작 범위 자료에서는 시간 누적 경보 제외 시 미탐이 4회에서 10회로, 사전 Role 정보 제외 시 8회로 늘었다.

승인을 제외하면 동일 승인 토큰 도용 가정도 경보해 미탐이 줄어드는 절충점이 있다. Role 정보가 없어도 다른 경보 때문에 전체 점수는 유지될 수 있으므로, 실행별 판정과 사라진 근거를 함께 분석했다. [기능별 필요성과 비교 결과](docs/COMPONENT_EVALUATION.md)는 최종 설계의 기여를 설명하는 기존 로그의 사후 분석이다.

## 자료 안내

| 목적 | 문서·폴더 |
|---|---|
| 프로젝트를 처음 이해하기 | [UNDERSTAND.md](docs/UNDERSTAND.md) |
| 탐지 기준·전체 평가·한계 | [REPORT.md](docs/REPORT.md) |
| 기능별 설계 이유와 제외 실험 | [COMPONENT_EVALUATION.md](docs/COMPONENT_EVALUATION.md) |
| 실제 실행 증거와 사례별 판정 | [INTEGRATION_REPORT.md](docs/INTEGRATION_REPORT.md) |
| 실험 환경 재현 | [INTEGRATION_LAB.md](docs/INTEGRATION_LAB.md) |
| 실험 단위와 증거 기준 | [INTEGRATION_PROTOCOL.md](docs/INTEGRATION_PROTOCOL.md) |
| 출처와 구현 범위 | [PROVENANCE.md](docs/PROVENANCE.md) |
| API 로그·사전 승인 | [data/behavior-eval](data/behavior-eval) |
| 컨테이너 실행 증거·감사 로그 | [data/integration-eval](data/integration-eval) |

## 제출 패키지

```powershell
python scripts/verify.py
python scripts/package_submission.py
```

`output/submission/auditguard-integration-pbl.zip`에 코드·평가 증거·결과·문서·파일별 SHA-256을 담는다. VM, 개인 키, bearer token, 발표자료와 중간 실험 기록은 포함하지 않는다. 검증 출력은 Git에서 제외한 `results/local/verification.json`에 저장한다.

[수업 공통 저장소](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)의 Category 1·2·3, workload, 설치 스크립트와 원본 문서 39개를 그대로 보존한다. 원래 한국어 README는 [UPSTREAM_README.md](docs/UPSTREAM_README.md)에 있다.
