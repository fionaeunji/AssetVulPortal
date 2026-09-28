# IT자산 취약점 관리 포털 (PoC)

외부 취약점 데이터(NVD / FIRST EPSS / CISA KEV)를 수집하고 Excel 자산관리대장과 매핑하여
취약 자산을 식별·분류·기한관리하는 사내망용 포털의 PoC입니다.

- 설계서: [`docs/00_design.md`](docs/00_design.md)
- 진행 상태: **Phase 2 완료** (NVD / EPSS / KEV Collector + Bundle Import). 전체 README는 Phase 10에서 완성합니다.

## 실행 방법 (Windows PowerShell)

```powershell
# 1) Python 3.12+ 설치 확인
py -3.12 --version

# 2) 가상환경
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3) 의존성
pip install -r requirements-dev.txt

# 4) 환경변수 파일
copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
#   → 출력값을 .env 의 APP_SECRET_KEY= 뒤에 붙여넣기

# 5) DB 초기화 (Alembic migration + 무결성 Trigger)
python -m scripts.init_db

# 6) 관리자 계정 생성 (비밀번호는 대화형 입력)
python -m scripts.create_user --username admin --role admin

# 7) 서버 실행 (로컬 바인딩)
uvicorn app.main:app --host 127.0.0.1 --port 8000
#   → http://127.0.0.1:8000/healthz

# 8) 테스트
python -m pytest
```

## 수동 취약점 수집 (Phase 2)

```powershell
# 등록 자산 기준 수집 (자산 업로드는 Phase 3에서 제공)
python -m scripts.collect

# 자산 등록 전, 특정 제품으로 실제 수집 검증
python -m scripts.collect --product a:apache:http_server --product a:apache:tomcat
```

- 결과: `data\bundles\bundle_*.json` 생성 → 검증 후 DB 반영, `collection_history`/`audit_logs` 기록
- 출력의 `sources[].status` 로 Source별 성공/실패 확인. 실패해도 기존 데이터는 삭제되지 않습니다.
- NVD API Key가 없으면 요청 간 6초 간격(5 req/30s)이 적용됩니다. `.env` 의 `NVD_API_KEY` 설정 시 0.6초.
- 사내 Proxy/사설 인증서: `HTTPS_PROXY`, `SSL_CERT_FILE` 환경변수 사용 (httpx 표준)

### 수집 방식

| Source | 방식 | Endpoint |
|---|---|---|
| NVD | 자산 CPE의 제품(`part:vendor:product`) 단위 `virtualMatchString` 조회. 첫 수집은 전체 이력, 이후 `lastModStartDate/EndDate` 증분(120일 단위 분할) | `services.nvd.nist.gov/rest/json/cves/2.0` |
| EPSS | 보유 CVE 수 < `EPSS_CSV_THRESHOLD` 면 API 100건 단위 조회, 이상이면 Bulk CSV | `api.first.org/data/v1/epss`, `epss.empiricalsecurity.com/epss_scores-current.csv.gz` |
| KEV | 카탈로그 전체 JSON | `www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` |

- **Initial EPSS**: 시스템이 해당 CVE의 EPSS를 최초 관측한 값. 이후 변경 불가(DB Trigger로 강제). **Current EPSS**는 더 최신 score date일 때만 갱신, 날짜별 이력은 `epss_history`.
- **CVSS**: NVD가 제공한 모든 점수를 `cvss_metrics`에 원본 보존, 판정용 점수는 정책의 `cvss.source_priority`(v3.1 NVD → v3.1 CNA → v4.0 → v3.0) 로 선택.
- **KEV**: CISA 카탈로그 우선, 없으면 NVD 레코드의 `cisaExploitAdd`로 표시 (`kev_source`). 등급 판정에는 미반영.

### VDI(인터넷 차단) 분리 운영

```powershell
# [내부 Portal] 수집 대상 파일 생성 (자산 IP/담당자 미포함, 제품키와 CVE ID만)
python -m scripts.export_targets --out targets.json
# [외부 Collector PC] DB 없이 수집 → Bundle 파일
python -m scripts.collect --targets-file targets.json --out-dir .\out
# [내부 Portal] 반입된 Bundle 검증(SHA-256, 선택적 HMAC) 후 Import  (.env: COLLECTOR_MODE=offline)
python -m scripts.import_bundle .\out\bundle_xxx.json
```

## Phase 1 구현 범위

| 항목 | 위치 |
|---|---|
| 설정(.env, Secret 필수·강도 검증) | `app/config/settings.py` |
| 외부 Endpoint Allowlist (SSRF 방지) | `app/config/endpoints.py` |
| ORM 모델 16개 테이블 | `app/models/` |
| UTC 저장 타입 (naive datetime 거부) | `app/models/types.py` |
| Append-only / 불변 컬럼 DB Trigger + ORM Guard | `app/models/guards.py` |
| 감사로그 Hash chain 기록·검증 | `app/services/audit.py` |
| 인증 Layer (AuthProvider, scrypt, 로그인 잠금, RBAC 레벨) | `app/security/` |
| 보안 헤더, Stack trace 비노출, 로그 Secret 마스킹 | `app/main.py`, `app/config/logging.py` |
| Alembic Migration | `migrations/versions/0001_initial_schema.py` |

## Dependency 사용 이유

| 패키지 | 이유 |
|---|---|
| fastapi, uvicorn | Web/API 서버 |
| SQLAlchemy, alembic | ORM(SQL Injection 방지, PostgreSQL 전환), 스키마 Migration |
| pydantic, pydantic-settings | 입력·외부응답 검증, `.env` 설정 로딩 |
| httpx | 외부 API 호출(타임아웃·Redirect 제어) |
| openpyxl, defusedxml | Excel 읽기/쓰기, XML 공격(XXE/Bomb) 방어 |
| APScheduler | 09:00/14:00 Asia/Seoul 자동수집 |
| Jinja2 | 서버 렌더링 (autoescape) |
| python-multipart | FastAPI 파일 업로드/폼 처리 |
| itsdangerous | 서명 세션 쿠키 |
| PyYAML | 정책 파일 (`safe_load`만 사용) |
| tzdata | Windows에서 `Asia/Seoul` 시간대 DB 제공 |
| pytest (dev) | 자동화 테스트 |
