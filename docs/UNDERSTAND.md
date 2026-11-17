# AuditGuard를 이해하고 설명하기

## 무엇을 만들었나

Kubernetes 관리 API의 감사 로그를 읽어 위험한 행동을 찾고, 사전에 허용한 작업과 비교하는 탐지기다. 출력에는 경보 규칙, 근거 이벤트, 정상 승인으로 억제한 이유가 포함된다. 수집한 로그를 분석하는 배치 프로그램이며 실시간 차단기는 아니다.

## 알아야 할 개념

| 개념 | 의미 |
|---|---|
| Pod | 컨테이너를 실행하는 단위 |
| API 서버 | 조회·배포·권한 변경 요청을 받는 관리 창구 |
| ServiceAccount / 토큰 | 프로그램의 신원 / 그 신원을 증명하는 자격 증명 |
| Secret | 암호·키 등을 담을 수 있는 Kubernetes 리소스 |
| Role / RoleBinding | 허용할 작업 목록 / 그 권한을 사용할 신원과의 연결 |
| 감사 로그 | 누가 언제 무엇을 요청했고 어떤 응답을 받았는지 남긴 기록 |

인증은 ‘누구인가’, 인가는 ‘이 작업의 API 권한이 있는가’를 확인한다. 유효한 토큰을 도용하면 둘 다 통과할 수 있다. HTTP 200/201은 요청 성공이지 정상 목적의 증거가 아니다. 403은 거부된 시도다.

## 처리 순서

1. 감사 이벤트를 읽고 중복 단계를 정리한다.
2. 행위자·토큰 식별자·대상·응답·명령과 보안 설정의 지문을 추출한다.
3. 신뢰된 작업 승인과 일치하는 요청을 확인한다.
4. 승인되지 않은 요청에 다섯 행동군과 조회량 규칙을 적용한다.
5. 경보, 억제 이유, 추가 확인이 필요한 관측을 기록한다.

사례 이름과 정상·공격 정답은 탐지 후 평가에만 사용한다. 요청에 적힌 이름을 보고 실험 정답을 맞추는 방식이 아니다.

## 다섯 행동군

**자격 증명:** Secret 읽기, ServiceAccount TokenRequest, 토큰용 Secret 또는 API 클라이언트 인증서 발급 요청을 확인한다. 승인되지 않은 민감 접근·발급은 위험 신호다. 토큰을 훔친 순간이나 외부 유출 완료를 직접 관측한 것은 아니다.

**원격 실행:** Pod exec/attach를 확인한다. 정상 진단도 같은 API를 쓰므로 작업자·토큰·대상·명령 지문을 승인과 비교한다. API 권한이 있어 실행되더라도 업무 승인이 없으면 경보한다. 거부된 실행 시도와 성공한 명령 실행을 구분한다.

**정찰:** 여러 API 경로의 반복 실패와 다종 목록 조회를 시간 창으로 모은다. 주요 조건은 90초 동안 실패 5회·경로 3개 이상, 180초 동안 목록 조회 8회·리소스 종류 3개 이상이다. 짧은 조회 급증, 누적 조회와 계정·리소스별 정상 기준도 함께 검사한다. 천천히 한 번씩 조회하면 구별하기 어렵다.

**권한 변경:** Role/ClusterRole의 권한 내용과 RoleBinding/ClusterRoleBinding의 연결 대상을 검사한다. roleRef는 신뢰된 Role 스냅샷으로 해석한다. Secret 읽기, 토큰 발급, 광범위 권한이나 권한 위임이 승인 없이 연결되면 경보한다. 알 수 없는 역할 참조는 별도 관측으로 남긴다.

**위험 워크로드:** Pod와 Deployment·DaemonSet·StatefulSet·Job·CronJob 등의 Pod 템플릿에서 privileged, 호스트 공간 공유, hostPath, 위험 capability를 찾는다. 리소스 이름이나 단순한 생성 여부만으로 공격이라 하지 않는다. 정상 관리에도 필요한 속성이므로 승인 정보가 중요하다.

## 정상 작업을 인정하는 근거

승인은 ‘이 사용자면 모두 허용’이 아니다. **이 작업자가, 이 토큰으로, 이 요청을, 정해진 시간 안에, 정해진 횟수만큼** 수행하는 조건이다. 요청 지문에는 대상·동작·쿼리·명령과 선택한 보안 관련 속성이 포함된다. 모든 객체 필드의 의미를 완전히 증명하는 것은 아니다.

명령·대상·토큰이 다르거나 시간·횟수를 넘기면 승인으로 억제하지 않는다. 401/403도 억제하지 않으므로 정상 권한 점검을 오탐할 수 있다. 공격자가 승인된 토큰으로 같은 요청을 보내면 현재 정보만으로 정상 사용자와 구별할 수 없다.

## 결과를 읽는 방법

| 실제 작업 의도 | 경보 있음 | 경보 없음 |
|---|---|---|
| 공격 | TP: 탐지 | FN: 미탐 |
| 정상 | FP: 오탐 | TN: 정상 판단 |

실제 실행 통합 평가에서는 공격 16회 중 14회를 탐지했고, 정상 16회 중 4회를 경보했다. Precision 77.8%는 경보가 발생한 18개 실행 중 14개가 공격이었다는 뜻이다. Recall 87.5%는 공격 16개 실행 중 14개를 찾았다는 뜻이다. 정상 오탐률은 4/16=25%다. 경보 개수나 로그 줄 수를 독립 사례 수로 세지 않는다.

오탐은 승인 누락 정상 privileged 작업 2회와 정상 Secret 접근 거부 점검 2회다. 미탐은 승인 토큰·동일 명령 도용을 가정한 2회다. API 동작 범위 평가와 외부 공개 로그 검증의 수치는 [평가 보고서](REPORT.md)에 별도로 설명한다.

## 직접 실행해 보기

승인 없는 exec 분석:

```powershell
python -m auditguard.behavior --input data/integration-eval/logs/X02-01.jsonl --output results/local/attack-demo
```

승인된 정상 exec 분석:

```powershell
python -m auditguard.behavior --input data/integration-eval/logs/X01-01.jsonl --config data/integration-eval/contexts/X01-01/behavior.json --legacy-context data/integration-eval/contexts/X01-01/legacy.json --output results/local/normal-demo
```

각 폴더의 `status.json`, `findings.json`, `suppressed.json`을 비교한다. 정상 예에서 승인 설정을 생략하면 탐지기가 작업 승인을 알 수 없다. 실행 증거는 `data/integration-eval/proofs/X01-01.json`에 있다.

## 코드를 읽는 순서

1. `config/behavior.json`: 행동군 임계값과 승인 형식.
2. `auditguard/behavior_events.py`: 감사 로그 정규화와 보안 속성 추출.
3. `auditguard/behavior.py`: 승인·행동군 판정과 근거 생성.
4. `auditguard/advanced.py`: 민감 접근·exec·조회량의 공통 규칙.
5. `lab/integration_scenarios.py`: 정상·공격 실험 정의.
6. `lab/integration_live.py`, `integration_stream.py`: 실제 요청·실행 증거 수집.
7. `scripts/verify.py`: 최종 결과와 원본 자료의 재현 검증.
