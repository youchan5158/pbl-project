# Splunk 공개 시험 자료

이 폴더의 logs/는 Splunk attack_data에서 고정한 커밋으로 내려받은 원본 8개를 바이트 그대로 보존한다. upstream-detections/는 해당 시험의 의도와 데이터 경로를 확인할 수 있는 Splunk security_content 문서 12개다. 여러 문서가 같은 로그를 참조하므로 이를 중복 사례로 세지 않는다. 1개 문서에는 시험 로그가 없다.

- 출처·커밋: sources.json
- 원본 파일 SHA-256 및 Git LFS 검증 기록: downloads.json
- 프로젝트 탐지 소스·설정의 평가 전 해시: freeze.json
- 당시 설정 복사본: frozen-policy.json / frozen-context.json
- 라이선스: LICENSE-Splunk.txt / LICENSE-SecurityContent.txt

두 외부 저장소의 자료는 각각 동봉된 Apache-2.0 라이선스를 따른다. 외부 자료를 이 프로젝트가 수집하거나 직접 작성한 것으로 표시하지 않는다. Splunk가 제공한 양성 시험 자료이며 별도의 정상 대조군은 없다.

평가기가 만드는 portable-policy.json은 이 프로젝트가 외부 환경의 네임스페이스·사용자 유형에 맞춰 검사 범위만 변경한 별도 평가 설정이다. 원본 로그나 배포 기본 설정을 변경한 것이 아니다.
