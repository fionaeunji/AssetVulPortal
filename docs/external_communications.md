# 외부 통신 목록 (방화벽/프록시 정책 신청용)

- 작성일: 2026-09-28
- 근거: 코드의 Endpoint Allowlist(`app/config/endpoints.py`) + Windows PoC PC에서의 실제 수집 성공 확인(2026-09-28, NVD·EPSS·KEV 모두 `success`)
- **실측 목록 재생성**: `python -m scripts.report_endpoints --out docs\external_communications_measured.md`
  (수집 이력 `collection_history.endpoints_called` 에 기록된 실제 호출 Host/Port/Path/횟수 집계)
- 정책은 IP가 아닌 **FQDN 기반 허용**을 권고합니다 (NVD/CISA/FIRST 모두 CDN·클라우드를 사용하여 IP가 바뀔 수 있음).

## 1. 운영 중 통신 (애플리케이션)

| Source Component | Destination FQDN | Port | Protocol | Purpose | Direction | Frequency | Required / Optional |
|---|---|---|---|---|---|---|---|
| nvd_client (Collector) | `services.nvd.nist.gov` | 443 | HTTPS (TLS) | CVE·CVSS·CPE 구성·버전 범위 수집 — `GET /rest/json/cves/2.0` (`virtualMatchString`, `lastModStartDate/EndDate`, `resultsPerPage`, `startIndex`) | Outbound | 1일 2회(09:00·14:00 KST) + 수동. 1회당 수집 대상 제품 수 × 페이지 수 (API Key 없으면 요청 간 6초) | **Required** |
| epss_client (Collector) | `api.first.org` | 443 | HTTPS (TLS) | EPSS 점수 조회 — `GET /data/v1/epss?cve=…` (100건 단위). CSV 실패 시 대체 경로 | Outbound | 1일 2회 + 수동. 보유 CVE 수 ÷ 100 요청 | **Required** (CSV와 택1) |
| epss_client (Collector) | `epss.empiricalsecurity.com` | 443 | HTTPS (TLS) | EPSS 전체 CSV — `GET /epss_scores-current.csv.gz` (보유 CVE ≥ `EPSS_CSV_THRESHOLD` 시) | Outbound | 1일 2회 + 수동, 1요청 | Optional (API와 택1) |
| kev_client (Collector) | `www.cisa.gov` | 443 | HTTPS (TLS) | CISA KEV 카탈로그 — `GET /sites/default/files/feeds/known_exploited_vulnerabilities.json` (화면 표시용, 등급 판정 미사용) | Outbound | 1일 2회 + 수동, 1요청 | Optional |

비고
- **EPSS CSV 리다이렉트**: PoC PC에서 `epss.empiricalsecurity.com` 이 HTTP 302를 반환했습니다. 애플리케이션은 Allowlist 내 목적지로만 Redirect를 따르며, 허용 밖이면 목적지 Host를 오류에 표시하고 `api.first.org` 로 자동 대체합니다. 302의 목적지 Host는 이번 PoC에서 확인하지 못했습니다 → 필요 시 수집 이력의 오류 메시지로 확인 후 Allowlist·방화벽에 추가 여부 결정. **`api.first.org` 만 허용해도 기능상 문제 없음.**
- 인증: NVD API Key(선택)는 HTTP 헤더 `apiKey` 로만 전송. 그 외 인증 없음.
- TLS: 인증서 검증을 끄지 않음. 기본은 OS 인증서 저장소(`TLS_TRUST_STORE=system`) — 회사 SSL 검사 장비 환경에서 동작 확인.
- 사내 Proxy 경유 시 `HTTPS_PROXY` 환경변수 사용.
- Redirect 자동 추적 금지, 사용자 입력 URL 요청 기능 없음(SSRF 방지).

## 2. 통신이 없는 구성요소

| 구성요소 | 외부 통신 |
|---|---|
| 웹 포털(브라우저 화면) | **없음** — CSS/JS 모두 로컬 제공, CDN·웹폰트·분석 스크립트 미사용 |
| Scheduler (offline 모드) | **없음** — `data\bundles\inbox` 파일만 처리 |
| DB (SQLite) | 없음 (로컬 파일). PostgreSQL 전환 시 내부망 DB 포트만 필요 |

## 3. 내부 통신 (VDI 운영)

| Source | Destination | Port | Protocol | Purpose |
|---|---|---|---|---|
| 사용자 브라우저 | Portal 서버 | 8000(변경 가능) → 운영은 443 권장(리버스 프록시) | HTTP/HTTPS | 포털 사용 |
| Portal | PostgreSQL (전환 시) | 5432 | TCP | DB |

## 4. 설치·개발 단계 통신 (운영 중에는 불필요)

| 목적 | Destination FQDN | Port | 비고 |
|---|---|---|---|
| Python 패키지 설치 | `pypi.org`, `files.pythonhosted.org` | 443 | VDI는 인터넷 PC에서 wheel을 내려받아 반입 (`docs/vdi_migration.md`) |
| 소스 코드 받기 | `github.com` | 443 | VDI는 소스 압축 파일 반입 |
| 의존성 취약점 조회(`pip-audit`) | `pypi.org` (pip-audit 기본 조회 서비스) | 443 | 반입 전 인터넷 PC에서 실행 |
| Python 설치 파일 | `www.python.org` | 443 | 설치 파일 반입 |
