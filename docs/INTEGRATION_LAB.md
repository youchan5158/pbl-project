# 통합 검증 재현

## VM 없이 결과 검증

Python 3.10 이상, 추가 패키지 없이 프로젝트 루트에서 실행한다.

```powershell
python -X utf8 scripts/evaluate_integration.py
python -X utf8 scripts/verify.py
python -X utf8 scripts/package_submission.py
python -X utf8 scripts/package_submission.py --check output/submission/auditguard-integration-pbl.zip
```

첫 명령은 원본 로그·실행 증거·탐지 및 수집 코드의 해시를 확인하고 같은 결과를 재생한다. 결과는 `results/integration/final/`, 전체 검증 출력은 Git에서 제외한 `results/local/verification.json`에 기록된다. ZIP 이름은 **auditguard-integration-pbl.zip**이다. 중간 개발 기록 없이 공개 저장소만으로 검증할 수 있다.

## 실제 컨테이너 환경을 다시 만들기

현재 제공하는 자동 실행기는 Windows용이다. QEMU 소프트웨어 가상화를 사용하며 Windows 가상화 기능·서비스를 변경하지 않는다. VM에 4 GiB RAM, 2 vCPU를 할당하므로 그 이상의 여유 메모리와 디스크가 필요하다. 처음에는 공개 런타임과 이미지 다운로드가 필요하다.

```powershell
python -X utf8 -m lab.windows prepare
python -X utf8 -m lab.integration_assets
python -X utf8 -m lab.integration_windows start
python -X utf8 -m lab.integration_live --output data/my-integration --split evaluation --repetitions 2 --seed 246831
python -X utf8 scripts/evaluate_integration.py --data data/my-integration --output results/local/my-integration
python -X utf8 -m lab.integration_windows stop
```

`prepare`는 기존에 제공한 QEMU·Alpine·K3s 런타임을 SHA-256으로 검사한다. `integration_assets`는 추가 airgap 이미지와 digest로 고정한 BusyBox 이미지를 준비한다. 새 VM은 full K3s server로 kubelet·containerd·scheduler를 함께 실행한다. native snapshotter, flannel host-gw, nft 모드를 사용한다. [K3s의 공식 iptables 모드 선택 구현](https://github.com/k3s-io/k3s-root/blob/master/iptables-detect/iptables-detect.sh)에 따라 `IPTABLES_MODE=nft`를 지정했다. host-gw는 이번 단일 노드 환경에서 사용한 설정이며 다중 노드 네트워크 검증을 뜻하지 않는다.

API는 `https://127.0.0.1:26443`, 감사 로그 전달은 `127.0.0.1:28081`, 시리얼 관리 포트는 `127.0.0.1:43221`이다. 부팅 중 파일 전달 포트 `28080`은 준비 완료 후 닫힌다. API TLS를 검증하며 관리 인증서와 키는 `lab/private/integration`에만 저장한다. 로그에는 Secret 응답·bearer token을 저장하지 않는다. 역할 부여와 위험 설정은 전용 VM·전용 namespace 안에서만 수행한다.

실험 경로는 반드시 새 디렉터리를 사용한다. 기존 출력이 있으면 수집기는 중단하므로 과거 원본을 덮어쓰지 않는다. VM을 중지한 뒤 `start`하면 새 가상 디스크와 클러스터를 만든다. 과거 VM 디스크와 수집 증거는 자동 삭제하지 않는다. `stop`은 저장한 PID가 이 프로젝트의 QEMU인지 확인한 뒤 해당 VM만 종료한다.

## 파일을 읽는 순서

1. `data/integration-eval/request-plan.json`: 실제 실행 전에 고정한 요청·라벨·기대 실행 조건.
2. `contexts/<사례>/before.json`: 측정 전 시각과 승인·권한·발급 영수증의 해시.
3. `logs/<사례>.jsonl`: 실제 API 서버가 만든 완료 감사 이벤트의 보존 필드.
4. `proofs/<사례>.json`: Pod/컨테이너 상태, exec 출력·종료 코드 또는 권한 전후 접근 증거.
5. `results/integration/final/cases.csv`와 `findings.json`: 탐지 결과, 승인으로 억제된 이유.

공격 라벨은 무해한 실험 동작에 부여한 사전 의도이며, 토큰 탈취·호스트 탈출·악성 코드 실행까지 성공했다는 의미가 아니다. 실행 검증과 탐지 점수는 분리해 확인한다.
