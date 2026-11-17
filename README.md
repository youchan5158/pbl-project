# Kubernetes API/Credential 악용 탐지

Kubernetes 감사 로그에서 **자격 증명 접근, 원격 실행, 정찰, 권한 변경, 위험한 워크로드**를 탐지한다. API 요청의 위험 속성과 사전에 승인한 작업을 함께 검사하고, 경보 또는 억제 이유를 남기는 Python 배치 탐지기다.

## 탐지 방식

| 행동군 | 확인하는 행위 | 정상과 구분하는 근거 |
|---|---|---|
| 자격 증명 | Secret 조회, ServiceAccount 토큰 발급 등 | 민감한 대상에 대한 접근 또는 발급이 승인 범위에 맞는지 |
| 원격 실행 | Pod exec / attach | 작업자, 토큰, 대상, 명령이 승인과 일치하는지 |
| 정찰 | 반복 실패, 여러 리소스 목록 조회 | 일정 시간의 횟수와 대상 다양성, 평소 허용된 조회 범위 |
| 권한 변경 | Role / RoleBinding 등의 변경 | 연결된 역할이 실제로 어떤 작업을 허용하는지 |
| 위험 워크로드 | privileged, hostPID, hostPath, 위험 capability 등 | Pod와 자동 배포 설정에 위험한 보안 속성이 있는지 |

정상 승인은 작업자, 개별 토큰 식별자, 요청 내용, 시간, 횟수를 제한한다. API 실행 권한과 업무 승인을 따로 확인하며, 승인 범위를 벗어나면 경보한다. 인증 실패(401)와 권한 거부(403)는 실행 시도로 경보하므로 정상 권한 점검에서도 오탐이 생길 수 있다.

## 실행

Python 3.10 이상에서 프로젝트 루트의 명령을 실행한다. 저장 로그 재생에는 VM, Docker, 추가 Python 패키지가 필요 없다.

전체 검증과 실제 실행 자료의 평가:

```powershell
python -X utf8 scripts/verify.py
python -X utf8 scripts/evaluate_integration.py --output results/local/integration
```

업무 승인 없는 exec 분석:

```powershell
python -X utf8 -m auditguard.behavior --input data/integration-eval/logs/X02-01.jsonl --output results/local/attack-demo
```

승인된 정상 exec 분석:

```powershell
python -X utf8 -m auditguard.behavior --input data/integration-eval/logs/X01-01.jsonl --config data/integration-eval/contexts/X01-01/behavior.json --legacy-context data/integration-eval/contexts/X01-01/legacy.json --output results/local/normal-demo
```

출력 폴더의 `status.json`은 최종 판정, `findings.json`은 경보 근거, `suppressed.json`은 승인으로 경보를 억제한 이유다. 정상 작업을 분석할 때는 해당 실행의 승인 설정을 함께 지정해야 한다.

## 실험 결과

각 평가에 같은 최종 탐지기를 적용했다. 채점 단위는 시나리오 실행이며, 경보가 하나라도 나오면 해당 실행을 경보한 것으로 센다. TP는 공격 탐지, FP는 정상 작업의 오탐, FN은 공격 미탐, TN은 정상 판정이다.

| 평가 | 규모 | 결과 | 검증 범위 |
|---|---|---|---|
| 수업 기본 시나리오 | 정상 1개, 공격 3개, 24개 이벤트 | 정상 1개 정상 판정, 공격 3개 경보 | 제공 로그 재생 |
| API 동작 범위 평가 | 33종을 2회씩 실행, 158개 이벤트 | TP 32 / FP 2 / FN 4 / TN 28 | 5개 행동군의 API 요청과 응답 |
| 실제 실행 통합 평가 | 16종을 2회씩 실행, 44개 이벤트 | TP 14 / FP 4 / FN 2 / TN 12 | 컨테이너 실행과 권한 변경 효과 |
| 외부 공개 로그 | 공격 시나리오 파일 8개, 14개 이벤트 | 3개 파일에서 경보 | 외부에서 작성한 로그 적용 |

실제 실행 통합 평가의 **Precision은 77.8%, Recall은 87.5%, F1은 0.824**다. 정상 16회 중 4회를 오탐했고, 공격 16회 중 2회를 놓쳤다. API 동작 범위 평가의 Precision은 94.1%, Recall은 88.9%, F1은 0.914다. 전체 수치는 [최종 결과 요약](results/final-summary.json)에 있다.

API 동작 범위 평가는 실행 노드가 없는 API 서버 환경에서 요청과 응답을 수집했다. 실제 실행 통합 평가는 Ready 노드 1개에서 명령 실행, 서버 파일 접근, 권한 변경 후 조회를 확인했다. 두 평가는 목적과 사례 구성이 달라 별도로 해석한다. 외부 자료에는 정상 대조군이 없어 Precision, F1, 오탐률을 계산하지 않는다.

### 오탐과 미탐

- **통합 평가의 오탐 4회:** 승인을 등록하지 않은 정상 관리 작업 2회와, 접근 거부 응답을 확인하는 정상 권한 점검 2회다.
- **통합 평가의 미탐 2회:** 승인된 토큰으로 동일한 명령을 보내는 도용 상황을 가정했다. 탐지기가 보는 토큰과 요청 조건이 정상 승인과 일치했다.
- **API 평가의 오탐 2회와 미탐 4회:** 정상 조회가 등록된 범위를 벗어나 오탐했고, 동일 토큰 도용 가정과 요청 수가 적은 정찰을 각각 2회 놓쳤다.
- **외부 로그의 미경보 5개:** 정찰 1개는 시간 내 요청 수가 기준에 못 미쳤다. 나머지 4개는 객체 생성, 이미지 가져오기, 단일 거부 요청에서 위험성을 구분하지 못했다.

자체 평가는 제한된 시나리오를 반복한 실험이다. 운영 환경에 적용하려면 장기간의 정상 업무 자료로 승인과 조회 기준을 검증하고, 동일 토큰 도용과 느린 정찰을 구분할 추가 정보를 연결해야 한다.

## 평가 데이터의 출처와 생성

수업 기본 시나리오는 [cclab-inu/Practical-Cloud-Security-PBL의 Category 3 로그](https://github.com/cclab-inu/Practical-Cloud-Security-PBL/tree/270bf2df9ae1eddfb26e8dc88cb92326c54a99a8/category3/logs)를 그대로 재생했다.

자체 실험은 **OpenAI Codex의 `gpt-6-astra`가 시나리오, 정상과 공격의 의도 라벨, 수집 코드를 작성**했다. 정상과 공격의 의도 및 승인 조건을 먼저 정하고 실제 K3s에 요청을 보냈다. K3s는 실습에 사용한 경량 Kubernetes다. API 서버가 기록한 감사 로그를 응답과 연결하고, 컨테이너 실행 자료에는 명령 출력과 권한 변경 결과를 함께 저장했다. 파일별 SHA-256으로 자료의 변경 여부를 확인한다.

자체 자료의 [API 요청 계획](data/behavior-eval/request-plan.json)과 [실제 실행 요청 계획](data/integration-eval/request-plan.json)에 사전에 정한 작업이 있고, [실행 증거](data/integration-eval/proofs)에 컨테이너 상태와 실행 결과가 있다. 탐지 후 이 의도 라벨과 판정을 비교해 채점한다.

외부 자료는 **Splunk Attack Data의 Kubernetes Security 관련 True Positive Test 로그 8개**다. [attack_data](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c)와 [security_content](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)의 고정 버전을 사용했다. 원본 파일의 해시를 확인한 뒤 그대로 재생한 벤더 공개 양성 시험 자료다. 파일별 원본 경로는 [sources.json](data/external/splunk-v1/sources.json), 다운로드 URL과 해시는 [downloads.json](data/external/splunk-v1/downloads.json)에 있다.

## 각 기능이 필요한 이유

같은 평가 로그에서 한 기능씩 제외하고 결과를 비교했다.

- **작업 승인:** 정상 운영자도 위험한 API를 사용한다. 승인을 제외하면 통합 평가의 오탐이 4회에서 10회로 늘었다.
- **시간 누적:** 요청을 모아서 반복 정찰을 찾는다. 누적 경보를 제외하면 API 평가의 미탐이 4회에서 10회로 늘었다.
- **Role 권한 정보:** 역할 이름을 실제 허용 권한으로 해석한다. 사전 Role 정보를 제외하면 API 평가의 미탐이 4회에서 8회로 늘었다.
- **워크로드 보안 속성:** 배포 요청 안의 위험한 실행 설정을 찾는다. 관련 경보를 제외하면 통합 평가의 미탐이 2회에서 8회로 늘었다.

승인을 제외하면 정상 승인과 같은 토큰을 사용하는 도용 가정도 경보해 미탐이 줄어든다. 오탐과 미탐을 함께 비교한 전체 결과는 [기능별 평가 수치](results/components/final/metrics.json)와 [실행별 판정 변화](results/components/final/changes.json)에 있다.

## 저장소 구성

- [auditguard](auditguard), [config](config): 탐지 코드와 정책 설정.
- [lab](lab): 시나리오 정의, VM 실행, API 요청과 증거 수집 코드.
- [scripts](scripts), [tests](tests): 평가, 검증, 제출 패키지 생성과 단위 테스트.
- [data/behavior-eval](data/behavior-eval): API 평가 로그와 사전 승인 자료.
- [data/integration-eval](data/integration-eval): 컨테이너 실행 로그와 증거.
- [data/external/splunk-v1](data/external/splunk-v1): 외부 원본 로그와 출처 및 라이선스.
- [results](results): 저장된 평가 결과와 실행별 판정.

[수업 공통 저장소](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)의 `category1/`, `category2/`, `category3/`, `workload/`, `install.sh`, `README_EN.md`를 보존한다. 원래 한국어 안내는 [공통 저장소 README](https://github.com/cclab-inu/Practical-Cloud-Security-PBL/blob/270bf2df9ae1eddfb26e8dc88cb92326c54a99a8/README.md)에서 확인할 수 있다. 원본 파일의 검증 해시는 [config/upstream-files.json](config/upstream-files.json)에 있다.

<details>
<summary>실제 컨테이너 환경을 다시 구성하려면</summary>

Windows용 자동 실행기는 QEMU VM에 RAM 4 GiB와 2 vCPU를 할당한다. 처음에는 런타임과 이미지 다운로드가 필요하다. 새 수집에는 기존 결과와 다른 출력 경로를 지정한다.

```powershell
python -X utf8 -m lab.windows prepare
python -X utf8 -m lab.integration_assets
python -X utf8 -m lab.integration_windows start
python -X utf8 -m lab.integration_live --output results/local/my-integration-data --split evaluation --repetitions 2 --seed 246831
python -X utf8 scripts/evaluate_integration.py --data results/local/my-integration-data --output results/local/my-integration
python -X utf8 -m lab.integration_windows stop
```

</details>

## 제출 패키지

```powershell
python -X utf8 scripts/verify.py
python -X utf8 scripts/package_submission.py
```

`output/submission/auditguard-integration-pbl.zip`에 코드, 평가 자료, 결과, README, 파일별 SHA-256을 담는다. 검증 출력은 `results/local/verification.json`에 저장한다. 로컬 문서, VM, 개인 키, 토큰 원문, 발표자료와 중간 실험 기록은 패키지에서 제외한다.
