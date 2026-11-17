# Splunk 공개 공격 로그

`logs/`에는 Splunk attack_data의 고정 커밋에서 가져온 원본 파일 8개, 총 14개 이벤트가 있다. 원본 바이트를 유지한다. `upstream-detections/`에는 시험 의도와 로그 경로를 확인할 수 있는 Splunk security_content 자료 12개가 있다. 여러 문서가 같은 로그를 참조하므로 독립 사례 수를 늘리지 않는다.

- `sources.json`: 출처와 고정 커밋.
- `downloads.json`: 원본 SHA-256과 Git LFS 검증 정보.
- `LICENSE-Splunk.txt`, `LICENSE-SecurityContent.txt`: 각 자료의 Apache-2.0 라이선스.
- 설정·해시 JSON: 평가 입력과 검사 범위를 확인하기 위한 메타데이터.

최종 탐지기는 8개 중 3개에서 경보했다. [사례별 결과](../../../results/behavior/external/cases.csv)와 [해석](../../../docs/REPORT.md)을 함께 읽는다. 정상 대조군이 없는 양성 시험 자료이므로 Precision·F1·오탐률을 계산하지 않는다. 참고한 공개 사례의 재생 검증이며 독립 맹검 평가가 아니다.

외부 원본을 이 프로젝트가 수집하거나 작성한 것으로 표시하지 않는다. 두 외부 저장소 자료의 사용 조건은 동봉한 라이선스를 따른다.
