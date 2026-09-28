# Test Fixtures

| 경로 | 출처 | 비고 |
|---|---|---|
| `nvd_records/*.json` | [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) (2026-09-28 취득) | NVD CVE API 2.0 의 `vulnerabilities[].cve` 객체를 그대로 보존한 **비공식 미러**. 개발 컨테이너에서 NVD 직접 접속이 차단되어 사용. 테스트에서 API 응답 Envelope(`resultsPerPage`, `startIndex`, `totalResults`, `vulnerabilities[]`)로 감싸서 사용 |
| `kev_sample.json` | [cisagov/kev-data](https://github.com/cisagov/kev-data) (CISA 공식 GitHub, catalogVersion 2026.09.27) | 전체 카탈로그 중 테스트 대상 CVE만 발췌 |
| `epss_*.json`, `epss_sample.csv.gz` | **합성 데이터** | FIRST EPSS API/CSV 공개 형식을 따른 테스트용 값. 실제 점수 아님 |

실제 외부 API 응답과의 호환성은 Windows PoC 환경에서 `python -m scripts.collect` 실행으로 최종 검증한다.
