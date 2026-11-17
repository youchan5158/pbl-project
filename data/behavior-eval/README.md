# B5 동결 후 실제 API 평가

작성자가 사전에 정의한 33종(정상 15종·공격 18종), 각 2회, 66회·158개 감사 이벤트다. 실제 K3s API/RBAC 로그이며 worker는 0개다. 성공한 컨테이너 실행·실제 침해 사고 자료가 아니다.

- `freeze.json`: 첫 평가 요청 전에 고정한 코드·설정·수집기·평가기·사례 해시.
- `request-plan.json`: 실행 순서와 요청·의도. 탐지기에는 주지 않는다.
- `contexts/<run-id>/`: 해당 실행 전의 토큰 ID 확인 영수증, B5 승인, B4 호환 승인, Role 권한 스냅샷, API 서버 시계와 해시.
- `logs/`: 응답 Audit-ID로 연결한 감사 이벤트. 토큰 원문·Secret 값·응답 본문을 포함하지 않는다.
- `manifest.json`: 라벨·관측 응답·상태·로그 해시. 라벨은 탐지 후 채점에만 사용한다.
- `environment.json`: 실제 버전과 노드 수.

재생: 프로젝트 루트에서 `python scripts/evaluate_behavior.py`.
최신 결과는 `results/behavior/fresh`와 `docs/REPORT.md`에 있다.
모든 자료가 같은 설계자·같은 실험 환경에서 나왔으므로 독립 블라인드 평가를 주장하지 않는다.
