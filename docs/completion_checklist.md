# 1차 PoC 완료 조건 점검표 (요구사항 §24)

- 기준일: 2026-09-28
- 확인 구분
  - **Windows 실측**: 사용자 Windows PC에서 실제 인터넷 데이터로 실행해 결과를 확인한 항목
  - **자동화 테스트**: `python -m pytest` (355건 통과) — 실제 NVD 레코드 Fixture + 가짜 외부 서버
  - **개발환경 실행**: 개발 컨테이너에서 서버를 띄워 브라우저로 확인 (외부 데이터는 Fixture)
  - **Windows 확인 필요**: 사용자 PC에서의 확인 결과를 아직 받지 못한 항목

| # | 완료 조건 | 확인 방법 | 상태 |
|---|---|---|---|
| 1 | Windows 로컬 PC에서 서버 실행 | `uvicorn app.main:app --host 127.0.0.1 --port 8000` | 개발환경 실행 ✓ / **Windows 확인 필요** (CLI 실행은 Windows 실측 ✓) |
| 2 | Dashboard 접속 | http://127.0.0.1:8000 로그인 → Dashboard | 개발환경 실행 ✓ (화면 캡처 확인), 자동화 테스트 ✓ / **Windows 확인 필요** |
| 3 | sample_assets.xlsx 업로드 | 웹 업로드 또는 `scripts.import_assets` | Windows 실측 ✓ (CLI), 자동화 테스트 ✓ (웹·CLI) |
| 4 | 자산 목록 확인 | 자산 메뉴 / `import_assets` 출력 | Windows 실측 ✓ (CLI 출력), 개발환경 실행 ✓ |
| 5 | "취약점 정보 수집" 실행 | 수집 → [지금 취약점 정보 수집] / `scripts.collect` | Windows 실측 ✓ (CLI) / 웹 버튼은 자동화 테스트 ✓ |
| 6 | 실제 NVD 취약점 수집 | 수집 이력 NVD `success` | **Windows 실측 ✓** (16,522건) |
| 7 | EPSS 정보 결합 | 수집 이력 EPSS `success`, 상세 화면 Initial/Current EPSS | **Windows 실측 ✓** (CSV 302 → API 대체 후 성공) |
| 8 | CPE + Version 기반 자산 매핑 | `scripts.run_matching` / Dashboard | 자동화 테스트 ✓ (샘플 기대값 11건 + 범위 제외 4건) / **Windows 확인 필요** |
| 9 | 취약 자산 자동 식별 | KPI "취약 자산" | 자동화 테스트 ✓, 개발환경 실행 ✓ / **Windows 확인 필요** |
| 10 | 긴급 / 우선 / 주의 자동 분류 | 등급 배지, 정책 테스트 | 자동화 테스트 ✓ (필수 5종 + 경계값) |
| 11 | 경계면 / 내부 기준 조치기한 자동 계산 | 상세 화면 조치기한·계산방법 | 자동화 테스트 ✓ (72시간/14일/45일/30일/90일) |
| 12 | 담당자 표시 | 목록·상세 담당자 | 자동화 테스트 ✓, 개발환경 실행 ✓ |
| 13 | 상세화면에서 매핑근거 확인 | 상세 → 매핑근거 | 자동화 테스트 ✓, 개발환경 실행 ✓ (화면 캡처) |
| 14 | 취약점 상태 변경 | 상세 → 상태 변경 | 자동화 테스트 ✓ |
| 15 | Audit Log 생성 확인 | 관리자 → 감사로그 (+ 무결성 검증) | 자동화 테스트 ✓ (필수 이벤트 전체) |
| 16 | Excel 취약점 현황 Export | Dashboard → Excel 다운로드 / `scripts.export_report` | 자동화 테스트 ✓, 개발환경 실행 ✓ (CLI) |
| 17 | 자동화 테스트 통과 | `python -m pytest` | 개발환경 ✓ 355건 / **Windows 확인 필요** |
| 18 | 외부 통신 목적지 목록 생성 | `docs/external_communications.md`, `scripts.report_endpoints` | 문서 작성 ✓ / 실측 목록은 Windows에서 `python -m scripts.report_endpoints` 실행 필요 |

## Windows에서 남은 확인 (약 15분)

```cmd
git pull
pip install -r requirements-dev.txt
python -m scripts.init_db
python -m pytest
python -m scripts.import_assets sample_data\sample_assets.xlsx
python -m scripts.collect
python -m scripts.run_matching
python -m scripts.report_endpoints --out docs\external_communications_measured.md
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
웹에서: Dashboard → CVE 상세(매핑근거) → 상태 변경 → 매핑 검토 승인 → Excel 다운로드 → 감사로그(무결성 검증)
