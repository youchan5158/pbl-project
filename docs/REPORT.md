# AuditGuard B5 최종 보고서

보존한 66회 **API 단계** 평가 보고서다. 이후 실제 컨테이너 실행을 포함한 32회 검증을 추가했으며, 최신 실행 근거·결과·한계는 [INTEGRATION_REPORT.md](INTEGRATION_REPORT.md)에 별도로 정리했다. 아래 수치는 이전 결과 그대로다.

## 연구 질문과 결과

Kubernetes의 정상 관리 작업과 API/Credential 악용은 같은 API를 사용한다. 이 프로젝트는 요청 내용의 위험 속성, 시간에 따른 조회 패턴, 개별 토큰에 묶인 사전 승인을 결합한다. 기존 Secret·exec·조회량 중심 B4를 보존하고, 5개 행동군을 다루는 B5를 별도 구현했다.

새 실제 평가 **33종 × 2회 = 66회, 158개 감사 이벤트**에서 B5의 TP=32, FP=2, FN=4, TN=28이었다. 정상 15종·공격 18종을 각각 두 번 수행했다. 두 반복의 사례별 판정은 같았으며, 서로 다른 공격 66종이나 독립 침해 사고 66건이라는 뜻이 아니다.

| 같은 새 로그의 결과 | B4 | B5 |
|---|---:|---:|
| 공격 탐지 / 36회 | 10 | 32 |
| 정상 작업 오탐 / 30회 | 4 | 2 |
| 탐지 못한 공격(미지원 포함) | 26 | 4 |
| 위 미탐 중 입력·범위 미지원 | 8 | 0 |
| 정상 입력·범위 미지원 | 6 | 0 |

B4의 순수 미탐은 검사한 공격 중 18회이며, 처리하지 못한 공격 8회를 합쳐 미탐지 26회다. 미지원 정상 6회는 TN에 넣지 않는다. B4는 기존 규칙·임계값을 유지하고 관측된 namespace와 사용자 유형에만 범위를 맞춘 비교다. B4가 지원하는 Secret GET·인벤토리 승인은 같은 사전 승인 정보를 제공했다. exec·토큰 발급·권한·배포의 세밀한 승인은 B5에서 추가한 기능이다.

B5는 66회 모두 입력을 처리했다. **Precision 94.1%, Recall 88.9%, F1 0.914, 정상 오탐률 6.7%**. 이 수치는 작성자가 구성한 소규모 실험의 결과이며 실운영 성능 추정치가 아니다. B4의 지원 사례만 계산한 F1과 B5의 전체 F1은 분모가 달라 직접 비교하지 않는다.

## 1. 다섯 행동군과 구현

| 행동군 | 판단 근거 | 정상 작업 구분 |
|---|---|---|
| 자격 증명 | Secret 읽기, serviceaccounts/token 발급. 필드가 있을 때 legacy token Secret·client CSR도 해석 | 토큰 ID·행위 지문·유효 시간·횟수가 맞는 업무 승인 |
| 원격 실행 | pods/exec의 GET·POST, attach | query의 명령·컨테이너 등도 해시로 승인에 연결 |
| API 탐색·정찰 | 기존 짧은/긴 조회 창, namespace를 넘는 다종 조회, 여러 URL의 401·403 누적 | 단발 오류·health check는 경보하지 않음. 승인 인벤토리는 제한적으로 허용 |
| RBAC 권한 변경 | wildcard·escalate/bind/impersonate·Secret 읽기·토큰 발급 권한, RoleBinding의 실제 참조 권한 | 이름이 아니라 사전에 가져온 Role/ClusterRole 권한을 해석. 승인 고권한 작업 예외 |
| 위험한 워크로드 | privileged, hostPID/IPC/Network, hostPath, 위험 capability. Pod 및 중첩 controller template·JSON Patch | 일반 CronJob·DaemonSet·NodePort 생성만으로 경보하지 않음. 승인 인프라 배포 예외 |

여러 행동군이 같은 신원·출발지에서 이어지면 상관 근거를 기록한다. 이를 별도 독립 공격 탐지 성능으로 세지는 않는다. R1~R6은 보존한 기존 규칙, G1~G5는 확장 규칙, G0은 승인 예산 초과다.

기본 설정은 `config/behavior.json`이다. 실패 경로 스캔: 90초·5건·3경로. namespace를 넘는 목록 정찰: 180초·8건·3종류. 기존 B4의 90초·6건·3종류 규칙도 유지한다. 기존 임계값은 이전 개발 데이터에서 정했으며, 새로운 임계값은 구현 전에 설정했다. 최종 평가 후 재조정하지 않았다.

승인은 로그 속 요청자가 주장하는 이름이나 annotation으로 만들어지지 않는다. 별도의 신뢰할 수 있는 발급자가 TokenReview로 확인한 credential-id 해시와 예정 작업의 보안 관련 지문, 시간, 요청 예산을 저장한다. 같은 계정의 다른 토큰은 승인을 이어받지 않는다. 지문은 API 대상·동작·query·추출한 보안 속성·명령/환경 설정 해시를 포함하며 전체 manifest의 완전한 의미 동등성 검사는 아니다.

## 2. 평가 절차와 오염 방지

1. `data/behavior-plan/scenarios.json`에 개발·평가 사례와 의도를 구현 전에 기록했다. 사례 코드는 탐지기를 import하지 않는다.
2. 개발 12종과 경계 테스트로 구현·수집을 확인했다. 개발 실험은 최종 평가와 분리했고 공개 제출 자료에는 포함하지 않는다.
3. 최종 수집 전에 소스·설정·수집기·평가기·사례의 SHA-256을 `data/behavior-eval/freeze.json`에 기록했다.
4. 개발과 다른 namespace·리소스 이름, 실행별 새 토큰, 고정 seed의 섞인 순서로 33종을 두 번 수집했다. 각 요청 전에 승인·권한 스냅샷·API 시계 기준을 저장했다.
5. 실제 응답의 Audit-ID로 완료 감사 이벤트를 찾았다. 무효 실행 0회, 이벤트 누락 0건이었다. 라벨은 탐지 후 채점 단계에서만 붙였다.
6. 같은 로그를 B4/B5에 재생했다. 최종 결과를 보고 동결된 파일을 바꾸지 않았다. `scripts/verify.py`가 해시와 재생 결과를 검사한다.

**작성자가 평가 사례도 설계했다.** 파일명·사례 ID를 규칙에 넣지 않았고 새 변형을 고정 후 실행했지만, 이 사실만으로 데이터셋 과적합이나 평가 편향이 없다고 입증하지는 못한다. 새로운 기관·클러스터의 정상 업무 분포로 하는 독립 검증이 필요하다.

## 3. 행동군별 결과

| 행동군 | 공격 TP / FN | 정상 FP / TN |
|---|---:|---:|
| 자격 증명 접근·발급 | 4 / 2 | 0 / 4 |
| 원격 실행 | 4 / 0 | 0 / 4 |
| API 탐색·정찰 | 6 / 2 | 2 / 6 |
| RBAC 권한 변경 | 8 / 0 | 0 / 6 |
| 위험한 워크로드 설정 | 10 / 0 | 0 / 8 |

새 평가에서 정상 exec 오탐은 줄고 토큰 발급·권한 변경·위험한 controller 설정의 누락이 줄었다. 예를 들어 개발에서는 privileged Pod와 일반 Deployment를 보았고, 평가에서는 CronJob hostPath, StatefulSet initContainer, Deployment JSON Patch, SYS_ADMIN capability, DaemonSet hostNetwork를 실행했다. 코드가 특정 객체 이름 대신 구조적 속성을 읽는 근거다. 충분히 넓은 일반화를 입증하는 근거는 아니다.

## 4. 남은 오탐과 미탐

| 사례 | 횟수 | 왜 틀렸나 | 추가로 필요한 정보 |
|---|---:|---|---|
| N08 정상 인벤토리 | FP 2 | 승인이 없으면 다종 조회가 정찰과 비슷하다 | 신뢰할 수 있는 업무 일정·승인 또는 충분한 정상 이력 |
| H01 승인 토큰 최초 사용 탈취 | FN 2 | 같은 토큰으로 같은 승인 작업을 먼저 하면 로그가 정상 작업과 같다 | 토큰 사용 주체의 실행 환경·발급/전달 경로·워크로드 신원 |
| H02 단일 저빈도 정찰 | FN 2 | 단 한 번의 정상적인 Pod 조회만으로 의도를 판별할 수 없다 | 더 긴 연속 로그와 주변 행동·자산 민감도 |

이 세 사례는 전체 수치에 포함했다. 정상 요청을 모두 경보하거나 계정 전체를 예외 처리해 한쪽 오류만 줄이지 않는다. 현재는 batch 실행 내에서만 상태와 예산을 유지한다. 여러 파일·프로세스 사이의 지속 예산, 재시작 복구, 실시간 경보 시스템은 구현하지 않았다.

## 5. 기존 데이터와 외부 공개 자료

공통 저장소의 4개 기본 사례도 자동 검증에 포함한다. 중간 실험을 이 66회의 점수에 합산하지 않는다.

이미 확인한 Splunk 양성 시험 자료 8개·14개 이벤트를 원본 그대로 다시 재생했다. **대상 근거에 연결된 경보는 B4 1/8 → B5 3/8**. B5가 14개 이벤트를 모두 읽지만, 읽을 수 있다는 것이 모두 탐지했다는 뜻은 아니다.

| 외부 자료 | B5 | 해석 |
|---|---|---|
| E01 Secret 조회 | 경보 R1 | 기존 기능 |
| E02 익명 API 스캔 | 경보 없음 | 각 출발지/90초 창에 최대 3건. 현재 5건 기준 미달. 시간축을 압축하지 않음 |
| E03 특권 Pod | 경보 G5 | privileged 속성 |
| E04 CronJob 생성 | 경보 없음 | 주기 작업 생성 자체를 공격으로 단정하지 않음 |
| E05 DaemonSet 생성 | 경보 G5 | `/var/log` hostPath. 정상 수집 에이전트도 가질 수 있는 속성 |
| E06 NodePort 생성 | 경보 없음 | 서비스 노출 설정만으로 악성 의도를 판단하지 않음 |
| E07 이미지 Pull 이벤트 | 경보 없음 | 이미지 평판·실행 분석 미구현 |
| E08 거부된 Job 생성 1회 | 경보 없음 | 단발 403만으로 공격 확정하지 않음. 위험 요청 본문도 부족 |

외부 자료는 벤더의 탐지 규칙 시험용 양성 자료이며 실제 침해 사건 정답 세트가 아니다. 특히 hostPath 경보도 공격의 확증이 아니다. 정상 대조군이 없으므로 외부 Precision/F1/오탐률을 계산하지 않는다. 이미 내용을 본 **회귀 시험**이며 새로운 독립 벤치마크라고 표현하지 않는다. 원본 출처는 [PROVENANCE.md](PROVENANCE.md), 원본 로그·라이선스는 [외부 자료 폴더](../data/external/splunk-v1)에 보존했다.

## 6. 관측과 적용의 한계

- 환경은 QEMU/Alpine의 agentless K3s v1.35.2+k3s1이다. worker는 0개다. 실제 API/RBAC/객체 생성·수정·감사 로그를 측정했으며 성공한 컨테이너 명령 실행·컨테이너 탈출·실제 토큰 탈취를 입증하지 않았다. 정상 exec는 권한 검증 후 실행할 노드가 없어 HTTP 400이었다. 공격 exec 중 403은 차단된 시도다.
- RBAC 위험 변경은 현재 주체가 실제로 더 강한 권한을 얻었는지 계산하는 완전한 권한 그래프가 아니다. 이미 관리자 권한을 가진 실험 토큰으로 고위험 변경 요청을 재현한 경우도 있다. label은 실험의 사전 의도이다.
- Request 본문이 없으면 workload/RBAC 내용 판정이 제한된다. 알 수 없는 Role 참조, 일부 patch, 서버 오류는 `observations.json`에 남긴다. 경보 없음은 안전 보증이 아니다. JSON Patch add/replace의 명시 값은 읽지만 copy/move나 이전 상태가 필요한 변경은 완전히 복원하지 않는다.
- Secret·TokenReview는 Metadata로 수집하여 값을 남기지 않는다. 따라서 이 수집 정책에서 legacy token Secret의 type 기반 탐지는 검증하지 못한다. CSR·attach·ephemeralContainer 등 보조 구현 중 실제 33종에 없는 기능은 라이브 검증 완료로 주장하지 않는다.
- 승인은 정확하고 보호된 외부 정보라는 가정이 필요하다. 운영 규모의 정상 분포, 장기 오탐, 처리량/지연, 여러 사용자·클러스터·버전, 승인 발급기 침해, 로그 유실/위조는 추가 평가 대상이다.

현재 수준은 **다섯 행동군을 실제 API 로그로 재현·비교하고 실패 이유까지 설명할 수 있는 수업 제출용 프로토타입**이다.

## 7. 재현과 파일

Python 3.10 이상. 탐지·재생·단위 테스트는 표준 라이브러리만 사용한다.

```powershell
python scripts/evaluate_behavior.py
python scripts/evaluate_behavior.py --external --output results/behavior/external
python scripts/verify.py
python -m auditguard.behavior --input data/behavior-eval/logs/A13-01.jsonl --output results/local/b5-demo
python scripts/package_submission.py
```

새 결과: `results/behavior/fresh/metrics.json`, `cases.csv`, `findings.json`.
입력·사전 승인·권한 스냅샷: `data/behavior-eval/`.
탐지기: `auditguard/behavior.py`, 정규화: `auditguard/behavior_events.py`.
기존 B4 CLI는 비교·호환용으로 그대로 두었다. **B5는 `python -m auditguard.behavior`로 실행한다.**

## 8. 사례 목록

아래 33종은 각각 두 번 실행했다. 상세 시간·코드·근거 auditID는 CSV와 findings JSON에서 확인한다.

| 사례 | 실제 의도 | 내용 | B5 결과 |
|---|---|---|---|
| A01 | 공격 | 허용된 권한으로 Secret 열거 | 탐지 |
| A02 | 공격 | 다른 SA 토큰의 승인 없는 발급 | 탐지 |
| A03 | 공격 | GET 방식의 미승인 exec | 탐지 |
| A04 | 공격 | 승인한 명령과 다른 exec 요청 | 탐지 |
| A05 | 공격 | 익명 비리소스 경로 정찰 | 탐지 |
| A06 | 공격 | 간격을 둔 다종 리소스 정찰 | 탐지 |
| A07 | 공격 | 두 namespace를 가로지르는 정찰 | 탐지 |
| A08 | 공격 | 새 이름으로 wildcard 역할 생성 | 탐지 |
| A09 | 공격 | 이름만으로 알 수 없는 고권한 역할 연결 | 탐지 |
| A10 | 공격 | JSON Patch로 Role 권한 확장 | 탐지 |
| A11 | 공격 | cluster-admin 역할 연결 | 탐지 |
| A12 | 공격 | CronJob 템플릿에 호스트 경로 추가 | 탐지 |
| A13 | 공격 | StatefulSet initContainer 특권 실행 설정 | 탐지 |
| A14 | 공격 | Deployment PATCH로 hostPID 활성화 | 탐지 |
| A15 | 공격 | Pod에 위험한 capability 부여 | 탐지 |
| A16 | 공격 | DaemonSet 호스트 네트워크 공유 | 탐지 |
| H01 | 공격 | 승인 토큰의 최초 사용을 공격자가 차지 | 경보 없음 (미탐) |
| H02 | 공격 | 정상 조회와 같은 단일 저빈도 정찰 | 경보 없음 (미탐) |
| N01 | 정상 | 승인된 단일 Secret 조회 | 경보 없음 |
| N02 | 정상 | 업무용 단기 토큰 발급 | 경보 없음 |
| N03 | 정상 | 운영자 승인 exec POST 시도 | 경보 없음 |
| N04 | 정상 | 잘못된 Pod 로그 접근 한 번 | 경보 없음 |
| N05 | 정상 | 반복 health check | 경보 없음 |
| N06 | 정상 | 한 번의 비리소스 권한 오류 | 경보 없음 |
| N07 | 정상 | 승인된 인벤토리 조회 | 경보 없음 |
| N08 | 정상 | 승인 정보 없는 정상 인벤토리 | 탐지 (오탐) |
| N09 | 정상 | 읽기 전용 ClusterRole 연결 | 경보 없음 |
| N10 | 정상 | 사전 승인된 고권한 역할 연결 | 경보 없음 |
| N11 | 정상 | 최소권한 Role 생성 | 경보 없음 |
| N12 | 정상 | 일반 CronJob 생성 | 경보 없음 |
| N13 | 정상 | 일반 DaemonSet 생성 | 경보 없음 |
| N14 | 정상 | 정상 NodePort 서비스 | 경보 없음 |
| N15 | 정상 | 승인된 인프라 특권 DaemonSet | 경보 없음 |

## 공식 개념과 원본 출처

- [공통 실습 저장소](https://github.com/cclab-inu/Practical-Cloud-Security-PBL), 고정 커밋 `270bf2df9ae1eddfb26e8dc88cb92326c54a99a8`. [구현·출처 구분](PROVENANCE.md).
- [Kubernetes RBAC](https://kubernetes.io/docs/reference/access-authn-authz/rbac/): 권한과 binding 의미.
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/): host namespace, privileged, hostPath, capability 등 위험 속성.
- [Kubernetes Auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/): Metadata와 Request의 관측 범위.
- [Splunk attack_data 고정 커밋](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c): 외부 원본.
