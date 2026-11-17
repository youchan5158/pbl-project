# 출처와 구현 경계

추가한 실제 실행 통합 검증은 `data/integration-eval`의 자체 설계 16종×2회, 44개 감사 이벤트와 실행 증거다. kubelet·containerd가 있는 단일 노드에서 수집했으며, 아래 66회 API 단계 평가와 합산하지 않는다. 최신 실행 결과와 한계는 [통합 보고서](INTEGRATION_REPORT.md)에 있다.

현재 B5의 실제 데이터는 `data/behavior-eval`(33종×2회, 158개 이벤트)이며, 작성자가 정의한 정상·공격 의도에 따라 직접 격리 API 서버에서 수집했다. 외부에서 제공받은 정답 벤치마크가 아니다. 개발 12종과 최종 33종은 분리했지만 설계자는 같으므로 독립 블라인드 평가를 주장하지 않는다. 개발·실패 기록은 공개 저장소에 포함하지 않는다. 최종 실험의 사전 계획과 원본 해시, 요청 전 승인은 평가 증거에 포함한다.

B5는 `auditguard/behavior.py`, `behavior_events.py`, `lab/behavior_live.py`, `behavior_scenarios.py`와 관련 평가·검증 도구를 추가했다. 기존 B4 소스·설정과 공통 원본은 변경하지 않았다. Splunk 자료는 이미 분석한 알려진 외부 회귀 시험으로만 사용한다. 최신 결과는 [최종 보고서](REPORT.md)에 있다.

공통 실습 저장소: [cclab-inu/Practical-Cloud-Security-PBL](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)

기준 커밋: `270bf2df9ae1eddfb26e8dc88cb92326c54a99a8`.

원래 저장소의 `category1/`, `category2/`, `category3/`, `workload/`, `install.sh`, `README_EN.md`를 원본 그대로 보존했다. 원래 한국어 README는 [UPSTREAM_README.md](UPSTREAM_README.md)에 보존했다. `docs/upstream-files.json`의 원본 Git blob 해시로 39개 파일을 검증한다. 이 프로젝트의 자체 실험 환경은 `lab/`에 있다. 원본 로그와 스크립트의 수업 출처를 유지하며 본 프로젝트 구현으로 표시하지 않는다. 원본 저장소에서 별도의 LICENSE 파일은 확인하지 못했으므로 원본 자료의 재배포 권리를 임의로 확대하는 라이선스를 부여하지 않는다.

이 프로젝트에서 추가한 부분은 auditguard Python 패키지, config, tests, lab의 추가 수집 도구, scripts의 재현/검증 도구, 평가 결과와 한국어 문서이다. 공식 Category 3의 API 요청 및 권한 모델을 기반으로 독립적인 탐지·평가 구현과 추가 시나리오를 구성했다.

## 데이터 구분

| source_type | 뜻 | 해석 |
|---|---|---|
| provided_example | 공통 저장소에 제공된 4개 로그, 총 24개 이벤트 | 예제 호환성 검증 |
| synthetic | 본 프로젝트 생성기로 만든 정해진 시나리오 | 규칙 동작·경계·한계 검증. 실제 수집 아님 |
| live | 실제 Kubernetes API 서버의 감사 이벤트 | 해당 실습 환경에서의 관측 결과. 배포 형태와 노드 수를 함께 공개 |

각 manifest에 출처, 실행별 라벨, 파일 해시와 이벤트 수를 저장한다. 제출 데이터에는 실제 서비스의 자격 증명이나 Secret 내용이 없다. 실습용 임시 관리자 인증서는 `lab/private/`에 두며 Git 및 배포 패키지에서 제외한다.

## 공식 기술 문서

- [Kubernetes ServiceAccounts](https://kubernetes.io/docs/concepts/security/service-accounts/): 프로그램의 API 신원과 토큰.
- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/): 감사 단계, 수집 정책, 백엔드.
- [Audit v1 schema](https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/): Event 필드와 정책 형식.
- [RBAC good practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/): 최소 권한과 민감 리소스 접근.
- [K3s agentless servers](https://docs.k3s.io/advanced#running-agentless-servers-experimental): 노드 에이전트 없는 API 검증 환경의 제약.
- [QEMU 공식 다운로드 안내](https://www.qemu.org/download/#windows), [Windows 배포처](https://qemu.weilnetz.de/w64/2026/): 격리 실습 런타임.
- [Alpine Linux 공식 배포처](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/x86_64/): 실습 VM의 Linux.

검토 기준일: 2026-11-17. 기술 문서와 원본 저장소는 이후 변경될 수 있어 커밋과 도구 버전을 별도로 기록한다.

## 추가 개선의 공식 근거

개별 토큰 식별자와 감사 연결은 [KEP-4193](https://www.kubernetes.dev/resources/keps/4193/) 및 [Kubernetes v1.35.2 구현](https://github.com/kubernetes/kubernetes/blob/v1.35.2/pkg/serviceaccount/claims.go)을 확인했다. 발급·검증 의미는 [ServiceAccount 관리 문서](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/)를 참고했다. 업무별 예산을 연결하는 탐지·평가 코드는 이 프로젝트에서 구현했다.

공개 평가 자료는 66회 API 단계 평가, 32회 실제 실행 통합 평가, 외부 공격 로그로 구분한다. 중간 개발·보정 실험을 최종 점수에 합산하지 않는다.

## 외부 공개 로그 보충 평가

data/external/splunk-v1의 원본 로그는 [Splunk attack_data](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c), 시험 의도는 [Splunk security_content](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)에서 가져왔다. 두 저장소의 고정 커밋, 각 파일 SHA-256과 Apache-2.0 라이선스를 함께 보존한다. 원본 로그를 수정하지 않았다.

source_type=external_vendor_positive_fixtures이며, 본 프로젝트가 수집한 live 데이터와 구분한다. 시험 단위는 서로 다른 원본 파일 8개이고 원시 이벤트는 14개다. 정상 대조군 없이 오탐률이나 F1을 산출하지 않는다. scripts/evaluate_external.py와 평가 해석은 이 프로젝트에서 추가한 부분이다.
