# 실행과 평가 재현

## 저장 로그로 검증

Python 3.10 이상에서 프로젝트 루트의 다음 명령을 실행한다. 추가 Python 패키지나 실행 중인 클러스터는 필요 없다.

```powershell
python -X utf8 scripts/verify.py
python -X utf8 scripts/evaluate_integration.py --output results/local/integration
python -X utf8 scripts/package_submission.py
python -X utf8 scripts/package_submission.py --check output/submission/auditguard-integration-pbl.zip
```

`verify.py`는 수업 원본 파일, 단위 테스트, API 평가 66회, 실제 실행 평가 32회, 외부 로그 8개, 기본 예제 4개의 최종 결과와 해시를 확인한다. 출력은 `results/local/verification.json`이다. 통합 평가 명령은 실제 실행 증거를 확인하고 최종 탐지기의 수치를 출력한다. 평가 점수는 로그의 이벤트 수가 아니라 사례 실행 단위다.

최종 수치만 보려면 [final-summary.json](../results/final-summary.json)을 읽는다. 자세한 오류와 한계는 [평가 보고서](REPORT.md)에 있다. 설명 문서의 문장과 원본 측정 로그·실행 증거는 서로 다른 자료로 관리한다.

## 실제 컨테이너 환경 재구성

자동 실행기는 Windows용이다. QEMU 소프트웨어 가상화를 사용하며 VM에 RAM 4 GiB, 2 vCPU를 할당한다. 처음에는 공개 런타임과 이미지 다운로드가 필요하다.

```powershell
python -X utf8 -m lab.windows prepare
python -X utf8 -m lab.integration_assets
python -X utf8 -m lab.integration_windows start
python -X utf8 -m lab.integration_live --output data/my-integration --split evaluation --repetitions 2 --seed 246831
python -X utf8 scripts/evaluate_integration.py --data data/my-integration --output results/local/my-integration
python -X utf8 -m lab.integration_windows stop
```

`prepare`는 QEMU·Alpine·K3s 런타임을 SHA-256으로 확인한다. `integration_assets`는 airgap 이미지와 digest로 고정한 BusyBox 이미지를 준비한다. K3s server와 kubelet·containerd·scheduler를 함께 실행하며 native snapshotter, flannel host-gw, nft 모드를 사용한다. 단일 노드 환경이므로 다중 노드 네트워크 검증을 뜻하지 않는다.

API는 `https://127.0.0.1:26443`, 로그 전달은 `127.0.0.1:28081`, 관리 포트는 `127.0.0.1:43221`이다. 준비 중 파일 전달 포트 28080은 준비 완료 후 닫힌다. API TLS를 검증하고 인증서·키는 `lab/private/integration`에 저장한다. Windows 폴더는 VM에 공유하지 않는다.

새 수집에는 새 디렉터리를 지정한다. 기존 출력이 있으면 수집기가 중단한다. VM 재시작은 새 가상 디스크와 클러스터를 만들며 과거 디스크·증거를 자동 삭제하지 않는다. `stop`은 저장된 PID가 이 프로젝트의 QEMU인지 확인한다.

## 증거를 읽는 순서

1. `request-plan.json`: 요청·라벨·기대 실행 조건.
2. `contexts/<사례>/before.json`: 요청 전 시각과 승인·권한·토큰 영수증의 해시.
3. `logs/<사례>.jsonl`: 실제 API 감사 이벤트.
4. `proofs/<사례>.json`: 컨테이너 상태, stdout·종료 코드, 권한 효과.
5. 결과의 `cases.csv`, `findings.json`: 탐지 결과와 근거.

HTTP 101만으로 명령 성공을 판단하지 않고 stdout·종료 코드·연결 종료를 함께 확인한다. Secret은 더미 값과 일치하는지 확인하되 원문을 저장하지 않는다. 공격 라벨은 무해한 실험 동작의 사전 의도이며 토큰 탈취·호스트 탈출·악성 코드 실행 성공을 뜻하지 않는다.
