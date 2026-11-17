# 외부 공개 로그 보충 평가

Splunk가 공개한 Kubernetes 탐지 규칙의 양성 시험 자료를 AuditGuard에 재생했다. Splunk 제품이나 SPL 규칙을 실행한 결과는 아니다. 원본 로그·타임스탬프·사용자·리소스를 수정하지 않았고 탐지 로직과 임계값도 변경하지 않았다.

- 평가 단위: 서로 다른 원본 파일 8개, 각 1회. 같은 파일을 참조한 여러 규칙은 중복 표본으로 세지 않는다.
- 원시 이벤트 14개 / 정규화된 리소스 이벤트 7개.
- 정상 대조군 없음. Precision·F1·오탐률은 계산하지 않는다. 벤더의 True Positive Test라는 출처를 사용하며 실제 침해 사고 정답 데이터라고 주장하지 않는다.
- 단일 이벤트 파일이 많아 시간창·연속 공격 탐지의 성능을 평가하기에는 매우 작다.

## 설정과 결과

원래 배포 설정은 pbl-security의 ServiceAccount만 검사한다. 별도 portable_scope 시험에서는 원본에 등장하는 비어 있지 않은 네임스페이스 전체와 모든 사용자 유형을 검사 대상으로 지정했다. 검사 범위 외의 정책·승인·프로필·임계값은 동일하다. 이 범위 조정은 배포 기본 설정에 반영하지 않았다.

| 사례 | 원시 이벤트 | 배포 설정 B4 | 범위 조정 B0 | B1 | B3 | B4 |
|---|---:|---|---|---|---|---|
| E01 Secret 조회 | 1 | 설정 범위 밖 | 미탐 | 탐지 | 탐지 | 탐지 |
| E02 익명 API 스캔 | 7 | 입력 미지원 | 입력 미지원 | 입력 미지원 | 입력 미지원 | 입력 미지원 |
| E03 특권 Pod 생성 | 1 | 설정 범위 밖 | 미탐 | 미탐 | 미탐 | 미탐 |
| E04 CronJob 생성 | 1 | 설정 범위 밖 | 미탐 | 미탐 | 미탐 | 미탐 |
| E05 DaemonSet 생성 | 1 | 설정 범위 밖 | 미탐 | 미탐 | 미탐 | 미탐 |
| E06 NodePort 생성 | 1 | 설정 범위 밖 | 미탐 | 미탐 | 미탐 | 미탐 |
| E07 이미지 Pull 이벤트 | 1 | 설정 범위 밖 | 미탐 | 미탐 | 미탐 | 미탐 |
| E08 권한 없는 Job 생성 시도 | 1 | 설정 범위 밖 | 탐지 | 미탐 | 미탐 | 미탐 |

범위 조정 B4: 전체 8개 중 대상 근거와 연결된 탐지 1개, 검사 후 미탐 6개, 입력 미지원 1개, 설정 범위 밖 0개, 입력 오류 0개. 미지원 사례를 분모에서 지워 높은 탐지율로 표시하지 않는다.

## 사례별 해석

- **E01 Secret 조회**: R1이 원본 Secret GET을 탐지.
- **E02 익명 API 스캔**: objectRef.resource 없는 비리소스 URL 요청 7건을 현재 정규화기가 제외.
- **E03 특권 Pod 생성**: 현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작.
- **E04 CronJob 생성**: 현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작.
- **E05 DaemonSet 생성**: 현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작.
- **E06 NodePort 생성**: 현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작.
- **E07 이미지 Pull 이벤트**: 현재 규칙의 Secret·exec·조회량 탐지 범위에 없는 쓰기/이벤트 동작.
- **E08 권한 없는 Job 생성 시도**: 403 Job 생성은 Secret·exec·조회량 규칙에 해당하지 않음; B0만 탐지.

## 이 결과가 뒷받침하는 범위

외부 환경에서 수집된 Secret 조회에 기존 R1이 작동한다는 좁은 근거다. 반면 익명 비리소스 API 스캔은 입력 단계에서 빠지고, Job·Pod·CronJob·DaemonSet·Service 생성과 이미지 Pull 이벤트에 대한 탐지 범위가 부족함을 확인했다. 보편적인 Kubernetes 공격 탐지 성능의 검증으로 해석하지 않는다.

원본에는 우리 작업 승인 정보가 없고 개별 토큰 식별자도 없어 B4의 토큰별 승인 효과를 검증하지 못한다. 외부 사용자에게 해당하는 정상 프로필도 없으므로 B1·B3·B4 결과가 같다는 사실은 개선 기능의 효과나 무효를 입증하지 않는다. 기존 63회 실습 결과와 합산하지 않는다.

## 재현

```powershell
python scripts/evaluate_external.py
python scripts/verify.py
```

로그가 없는 환경에서 원본을 다시 받으려면 `python scripts/fetch_external.py`를 실행한다. 고정 커밋의 Git LFS SHA-256/크기를 확인한다. 재생 시 원본 로그, 출처 문서, 탐지 소스와 설정 해시를 모두 검사한다.

- 상세 수치: metrics.json / cases.csv
- 알림별 auditID 근거: findings.json

## 출처

- [Splunk attack_data 고정 커밋](https://github.com/splunk/attack_data/tree/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c)
- [Splunk security_content 고정 커밋](https://github.com/splunk/security_content/tree/a9ef36bfc90fc79eb54828f0310e681eba6a3eca)
- [Kubernetes Security 공식 설명](https://research.splunk.com/stories/kubernetes_security/)

- [E01 Secret 조회](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1552.007/kube_audit_get_secret/kube_audit_get_secret.json)
- [E02 익명 API 스캔](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1046/kubernetes_scanning/kubernetes_scanning.json)
- [E03 특권 Pod 생성](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json)
- [E04 CronJob 생성](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1053.007/kubernetes_audit_cron_job_creation/kubernetes_audit_cron_job_creation.json)
- [E05 DaemonSet 생성](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.json)
- [E06 NodePort 생성](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1204/kube_audit_create_node_port_service/kube_audit_create_node_port_service.json)
- [E07 이미지 Pull 이벤트](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1526/kubernetes_audit_pull_image/kubernetes_audit_pull_image.json)
- [E08 권한 없는 Job 생성 시도](https://github.com/splunk/attack_data/blob/eb3ab7424aaa4bd7ac8e97fd0af6c1d29944d23c/datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json)
