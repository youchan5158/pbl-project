# 출처와 구현 범위

## 수업 공통 자료

기반 저장소는 [cclab-inu/Practical-Cloud-Security-PBL](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)이며 기준 커밋은 `270bf2df9ae1eddfb26e8dc88cb92326c54a99a8`이다.

`category1/`, `category2/`, `category3/`, `workload/`, `install.sh`, `README_EN.md`를 원본 그대로 유지한다. 원래 한국어 README는 [UPSTREAM_README.md](UPSTREAM_README.md)에 있다. `upstream-files.json`의 Git blob 해시로 원본 39개 파일을 확인한다. 공통 로그·스크립트를 이 프로젝트의 자체 구현으로 표시하지 않는다. 원본 저장소에 별도 LICENSE가 확인되지 않아 임의로 재배포 권리를 확대하는 라이선스를 부여하지 않는다.

## 자체 구현

Python 기반 탐지기, 탐지 설정, 작업 승인·권한 스냅샷 처리, 실제 요청·컨테이너 실행 수집기, 평가·검증 도구, 설명 문서를 구현했다. Category 3의 API 요청과 권한 모델을 바탕으로 다섯 행동군의 탐지와 정상 대조군을 구성했다.

핵심 위치는 `auditguard/behavior.py`, `behavior_events.py`, `advanced.py`, `config/`, `lab/`, `scripts/`다. 규칙은 관측한 보안 속성과 승인 정보를 읽고, 사례의 의도 라벨은 판정 후 평가에만 사용한다.

## 평가 데이터의 출처와 생성 방법

### 수업 기본 예제: 제공 파일 재생

[수업 공통 저장소의 Category 3 로그](https://github.com/cclab-inu/Practical-Cloud-Security-PBL/tree/270bf2df9ae1eddfb26e8dc88cb92326c54a99a8/category3/logs)를 사용했다. `normal.log`와 `abnormal_1.log`~`abnormal_3.log`의 **4개 파일, 24개 이벤트**이며 정상 1개·공격 3개다. 제공 파일을 그대로 읽어 호환성을 평가했다. 이 프로젝트에서 새로 생성하거나 AI로 작성한 데이터로 표시하지 않는다. 제공자의 로그 생성 세부 과정과 AI 사용 여부는 이 프로젝트에서 확인하지 않았다.

### 자체 실험: AI가 설계한 시나리오를 실제 K3s에서 실행

**시나리오·의도 라벨·요청 및 수집 코드 작성에는 OpenAI Codex의 `gpt-6-astra` 모델을 사용했다.** 모델명은 해당 파일을 작성하던 당시 Codex 실행 기록의 모델 식별자와 대조했다. AI가 정상·공격 상황과 실행 코드를 구성했고, 평가용 감사 로그는 2026-11-17에 그 코드를 실행한 **K3s API 서버가 기록한 실측 데이터**다. 로그 내용 자체를 LLM의 텍스트 출력으로 생성한 합성 평가가 아니다.

생성·수집 절차는 다음과 같다.

1. 정상·공격 의도, 요청 내용, 기대 응답, 승인 여부를 사례 정의에 기록한다. 승인된 exec와 미승인 exec, 정상 관리용 특권 Pod와 승인 없는 배포처럼 비교할 상황을 함께 작성한다.
2. 요청 계획을 저장하고 각 실행 전에 토큰 식별 영수증·승인·Role 스냅샷을 고정한다. 실험용 계정으로 실제 K3s API 요청을 보낸다.
3. API 응답과 연결되는 감사 이벤트를 수집한다. API 동작 범위 평가는 Audit-ID로 연결하고, 실행 통합 평가는 exec 출력·컨테이너 상태·권한 변경 후 조회 결과도 확인한다.
4. 공개 가능한 필드를 추려 JSONL로 저장하고, 수집 로그·승인 자료·실행 증거에 SHA-256을 남긴다. 정상·공격 라벨은 사전에 정한 모의 작업 의도이며 탐지 후 채점에만 사용한다. 토큰 원문과 Secret 값은 공개하지 않는다.

**API 동작 범위 자료**는 정상 15종·공격 18종을 각각 두 번 실행한 **66회, 158개 감사 이벤트**다. [사례 정의](../lab/behavior_scenarios.py), [수집 코드](../lab/behavior_live.py), [요청 계획](../data/behavior-eval/request-plan.json), [실행 목록](../data/behavior-eval/manifest.json)을 제공한다. worker가 0개인 환경에서 API 요청과 RBAC 결과를 수집했으므로 성공한 컨테이너 명령 실행을 증명하지 않는다.

**실제 실행 통합 자료**는 정상 8종·공격 8종을 각각 두 번 실행한 **32회, 44개 감사 이벤트**다. [사례 정의](../lab/integration_scenarios.py), [수집 코드](../lab/integration_live.py), [요청 계획](../data/integration-eval/request-plan.json), [실행 목록](../data/integration-eval/manifest.json), [실행 증거](../data/integration-eval/proofs)를 제공한다. 전용 QEMU VM의 Ready 노드 1개에서 무해한 exec, privileged·hostPID·hostPath 설정, RoleBinding 전후 접근을 실행했다. Secret과 hostPath 파일은 실험용 더미 자료다.

두 자료는 같은 프로젝트에서 설계한 제한된 사례의 실측 평가다. 설계자와 환경이 제한되어 독립 기관의 맹검 벤치마크가 아니다. 같은 사례의 반복을 독립 공격 종류로 세지 않으며 두 평가의 점수를 합산하지 않는다. 초기 개발용 모의 로그는 발표의 위 실측 성능 수치에 포함하지 않았다.

### 외부 자료: Splunk Attack Data의 Kubernetes 양성 시험 로그

외부 자료의 명칭은 **Splunk Attack Data의 Kubernetes Security 관련 True Positive Test 자료**다. [Splunk attack_data](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c)가 원본 로그를 제공하고, [Splunk security_content](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)의 탐지 시험 정의가 해당 로그를 양성 시험으로 지정한다. [Secret 조회 시험 정의](https://github.com/splunk/security_content/blob/a9ef36bfc90fc79eb54828f0310e681eba6a3eca/detections/cloud/kubernetes_abuse_of_secret_by_unusual_user_name.yml)에서 `True Positive Test`와 원본 파일 연결을 확인할 수 있다.

2026-11-17에 확인한 Kubernetes Security 관련 시험에서 감사 로그 파일을 추리고, 같은 파일을 참조하는 규칙은 중복 제거했다. Falco·네트워크 자료와 로그가 없는 규칙을 제외한 **8개 파일, 14개 이벤트**를 고정 커밋에서 내려받았다. Git LFS의 SHA-256·파일 크기를 확인한 뒤 원본 바이트를 바꾸지 않고 탐지기에 재생했다. 파일별 원본 경로는 [sources.json](../data/external/splunk-v1/sources.json), 다운로드 URL과 해시는 [downloads.json](../data/external/splunk-v1/downloads.json), 수집 절차는 [fetch_external.py](../scripts/fetch_external.py)에 있다.

이 프로젝트에서 외부 로그를 AI로 생성하거나 원래 공격을 다시 실행하지 않았다. 원저자가 각 파일을 만든 전체 실행 절차나 AI 사용 여부까지 검증한 것은 아니다. **표준 성능 벤치마크가 아닌 벤더 공개 양성 시험 자료의 재생 검증**이며, Splunk 제품·SPL 탐지기를 실행한 비교 실험도 아니다. 정상 대조군이 없어 외부 Precision·F1·오탐률을 계산하지 않는다. 이미 참고한 공개 사례이므로 독립 맹검 평가로 표현하지 않는다.

### 구성 요소 제외 실험: 기존 자료 재사용

[기능별 필요성 평가](COMPONENT_EVALUATION.md)는 위 API 66회와 실제 실행 32회의 로그·승인 자료를 그대로 재사용했다. 같은 98회에 다섯 구성을 적용해 비교했으며 새로운 데이터 생성이나 실환경 실행은 없었다. 490개의 구성별 판정 행을 490개의 독립 사례로 세지 않는다.

## 외부 로그와 라이선스

원본 로그는 [Splunk attack_data](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c), 시험 의도는 [Splunk security_content](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)에서 확인했다. `data/external/splunk-v1`에 고정 커밋, 원본 SHA-256, Apache-2.0 라이선스를 보존한다. 외부 원본 로그를 수정하지 않았다.

참고한 공개 사례의 재생 검증이며, 새롭고 독립적인 블라인드 평가라고 표현하지 않는다. 정상 데이터가 없어 외부 Precision·F1·오탐률을 계산하지 않는다.

## 공식 기술 근거

- [ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/): 프로그램 신원과 토큰.
- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/), [Audit v1](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/): 감사 이벤트와 수집 정책.
- [RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/), [권한 관리 지침](https://kubernetes.io/docs/concepts/security/rbac-good-practices/): 역할·권한과 민감 접근.
- [KEP-4193](https://www.kubernetes.dev/resources/keps/4193/), [v1.35.2 토큰 구현](https://github.com/kubernetes/kubernetes/blob/v1.35.2/pkg/serviceaccount/claims.go): 개별 토큰 식별자와 감사 연결.
- [ServiceAccount 관리](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/): 발급·검증 의미.
- [K3s agentless 환경](https://docs.k3s.io/advanced#running-agentless-servers-experimental): 실행 노드 없는 환경의 범위.
- [Kubernetes 스트리밍 구현](https://github.com/kubernetes/client-go/blob/master/tools/remotecommand/v4.go): 명령 종료 상태 해석.
- [QEMU](https://www.qemu.org/download/#windows), [Alpine Linux](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/): 실험 VM 런타임.

실제 실험 버전과 이미지 digest는 각 환경 JSON과 `lab/integration-image.json`에 기록한다. 로그·경보에 bearer token, Secret 원문, 개인 키를 공개하지 않는다. 관리자 인증 정보는 Git에서 제외한 `lab/private/`에 둔다.
