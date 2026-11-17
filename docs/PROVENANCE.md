# 출처와 구현 범위

## 수업 공통 자료

기반 저장소는 [cclab-inu/Practical-Cloud-Security-PBL](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)이며 기준 커밋은 `270bf2df9ae1eddfb26e8dc88cb92326c54a99a8`이다.

`category1/`, `category2/`, `category3/`, `workload/`, `install.sh`, `README_EN.md`를 원본 그대로 유지한다. 원래 한국어 README는 [UPSTREAM_README.md](UPSTREAM_README.md)에 있다. `upstream-files.json`의 Git blob 해시로 원본 39개 파일을 확인한다. 공통 로그·스크립트를 이 프로젝트의 자체 구현으로 표시하지 않는다. 원본 저장소에 별도 LICENSE가 확인되지 않아 임의로 재배포 권리를 확대하는 라이선스를 부여하지 않는다.

## 자체 구현

AuditGuard Python 패키지, 탐지 설정, 작업 승인·권한 스냅샷 처리, 실제 요청·컨테이너 실행 수집기, 평가·검증 도구, 설명 문서를 구현했다. Category 3의 API 요청과 권한 모델을 바탕으로 다섯 행동군의 탐지와 정상 대조군을 구성했다.

핵심 위치는 `auditguard/behavior.py`, `behavior_events.py`, `advanced.py`, `config/`, `lab/`, `scripts/`다. 규칙은 관측한 보안 속성과 승인 정보를 읽고, 사례의 의도 라벨은 판정 후 평가에만 사용한다.

## 평가 데이터

| 자료 | 출처와 단위 | 해석 |
|---|---|---|
| 수업 기본 예제 | 공통 저장소 4개 로그·24개 이벤트 | 제공 예제 호환성 |
| API 동작 범위 | 자체 설계 33종×2회·158개 실제 감사 이벤트 | 실행 노드 없는 API 패턴 검증 |
| 실제 실행 통합 | 자체 설계 16종×2회·44개 실제 감사 이벤트와 실행 증거 | 단일 실행 노드의 exec·워크로드·권한 효과 |
| 외부 공개 로그 | Splunk의 양성 파일 8개·14개 이벤트 | 정상 대조군 없는 보충 검증 |

자체 실험은 설계자와 환경이 제한되어 독립 기관의 맹검 벤치마크가 아니다. 반복 횟수를 독립 공격 종류 수로 세지 않는다. 최종 평가의 요청 계획·원본 해시·사전 승인·실행 증거는 보존하고 서로 다른 평가를 합산하지 않는다.

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
