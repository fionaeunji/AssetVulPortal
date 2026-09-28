# IT자산 취약점 관리 포털 (PoC)

외부 취약점 데이터(NVD / FIRST EPSS / CISA KEV)를 수집하고 Excel 자산관리대장과 매핑하여
취약 자산을 식별·분류·기한관리하는 사내망용 포털의 PoC입니다.

- 설계서: [`docs/00_design.md`](docs/00_design.md)
- 진행 상태: **Phase 5 완료** (매칭 엔진 + 정책 엔진/조치기한). 전체 README는 Phase 10에서 완성합니다.

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

## 매핑·판정 (Phase 4·5)

자산 업로드와 취약점 수집이 끝나면 **자동으로** 매핑·판정이 실행됩니다. 수동 재실행/결과 확인:

```powershell
python -m scripts.run_matching                 # 매핑·판정 실행 + 결과표 + 검토 대기 목록
python -m scripts.review_mapping approve 3 --comment "담당자 확인"   # 후보 승인
python -m scripts.review_mapping reject 4       # 후보 거부
```

### 매칭 규칙 (False Positive 최소화)

| Level | 대상 | 방법 | 결과 |
|---|---|---|---|
| 1 | CPE가 있는 제품 | NVD `configurations` 를 3값 논리(참/거짓/판단불가)로 평가. `versionStart/End Including/Excluding` 경계 처리, `update`·`sw_edition` 등 속성 비교, AND 구성의 플랫폼(OS/하드웨어) 조건 평가 | 참 → **취약 확정**, 판단불가 → **검토 필요(L3)** |
| 2 | CPE가 없거나 잘못된 제품 | Vendor/Product/Version 으로 후보 CPE 제안 (`config/product_aliases.yaml` + 수집된 CPE 사전) | **자동 확정 안 함** → [매핑 승인] 시 저장·재사용 |
| 3 | Level 1 판단불가 | 예: 자산 CPE에 update 미기재, 버전 표기 비교 불가(`19c` vs `19.3`), 플랫폼 정보 없음 | 사람이 승인해야 취약 확정 |

- 버전 비교가 불확실하면(예: `2.4.x`, Tomcat `-M1` vs Cisco `M` train) 비교 불가로 처리하여 자동 판정하지 않습니다.
- 승인된 제품 매핑(`asset_product_mapping`)은 같은 Vendor/Product 의 다른 자산에 자동 재사용되고, 매핑 근거에 승인자·승인일이 남습니다.
- 거부된 후보는 다시 제안되지 않습니다. 자산 버전이 바뀌어 더 이상 매칭되지 않는 건은 삭제하지 않고 `재검증 필요`로 표시합니다.

**Match Confidence (Level 2 전용, 규칙 합산 — 임의 숫자 아님)**

| 규칙 | 점수 |
|---|---|
| Vendor 일치 (특수문자 제거 후 동일) / 별칭 사전 일치 | 30 / 20 |
| Product 일치 / 별칭 사전 일치 / 토큰 겹침(Jaccard ≥ 0.5) | 40 / 25 / 10 |
| 수집된 CVE 조건과 버전 비교가 결정적으로 가능 | 20 |
| 별칭 사전(`product_aliases.yaml`)에 등록된 제품 | 10 |

합계 50점 이상 후보만 상위 3개 제시. Level 1은 결정적 규칙이므로 Confidence를 표시하지 않고 매칭유형(CPE_EXACT/CPE_RANGE/…)과 근거를 표시합니다. Level 3은 "산정불가"로 표시합니다.

### 정책 설정 (`config/policy.yaml`)

- 등급 규칙은 위에서부터 순서대로 평가해 처음 만족하는 규칙을 적용합니다 (긴급 → 우선 → 주의).
- 정책 변경: 파일 수정 후 **`version` 값을 반드시 변경** → 다음 매핑 실행 시 새 정책 버전으로 재판정. 과거 판정은 `vulnerability_assessments` 에 정책 버전과 함께 보존되고, 최초 조치기한(`initial_due_at`)은 바뀌지 않습니다. (관리자 화면 정책 적용은 Phase 6)
- **EPSS 미발행 CVE**(`missing_behavior: pending`): CVSS가 EPSS 조건 규칙(≥ 9.0)에 해당하면 `EPSS 대기`로 판정보류, 최초 EPSS 관측 시 그 값이 Initial EPSS가 되어 재판정됩니다.
- CVSS 선택: `cvss.source_priority` (v3.1 NVD → v3.1 CNA → v4.0 → v3.0). CVSS가 없는 CVE는 "관리대상 아님"으로 표시하되 사유(CVSS 미제공)를 기록합니다.

**조치기한 계산 방법 (현재 적용)**

- 기산점: 시스템이 해당 자산-CVE 매핑을 최초 확정한 시각(탐지일, UTC 저장 / 화면 KST)
- `month_mode: fixed_days`, `days_per_month: 30` → **1개월 = 30일, 1.5개월 = 45일, 3개월 = 90일** (사용자 결정 Q1)
- `hours`/`days` 는 그대로 가산 (72시간, 14일)
- 대안 `month_mode: calendar`: 정수 개월은 달력 기준(말일 보정, 예: 1/31 + 1개월 = 2/28) + 소수부 × 30일

## 자산관리대장 Import (Phase 3)

```powershell
python -m scripts.import_assets sample_data\sample_assets.xlsx
python -m scripts.collect          # 업로드된 자산의 CPE 제품 기준으로 실제 수집
```

- 샘플: `sample_data/sample_assets.xlsx` — 가상 자산 23개/제품 24개 (IP는 RFC 5737 문서용 대역, 담당자·부서는 가상 명칭). `비고` 열에 매칭 기대값 기재. 재생성: `python -m scripts.generate_sample_assets`
- 필수 컬럼: `Asset ID, 자산명, 자산구분(경계면/내부), IP, Vendor, Product, Version, CPE, 중요도(상/중/하), 담당자, 부서` (그 외 열은 무시)
- 같은 Asset ID를 여러 행에 쓰면 한 자산의 여러 제품(OS+앱 등)으로 등록
- **오류 행이 하나라도 있으면 파일 전체를 반영하지 않고** 행/열별 오류를 보여줍니다. 잘못된 CPE는 오류가 아닌 경고(해당 제품은 CPE 매칭 제외, 후보 매칭 대상)
- 재업로드 시: 파일에서 빠진 자산/제품은 삭제하지 않고 비활성화, 버전이 바뀐 제품의 기존 매핑은 `재검증 필요` 표시, 담당자 변경은 감사로그(OWNER_CHANGE)
- 업로드 보안검증: `.xlsx` 확장자 + ZIP 서명 + OOXML 구조(매크로/VBA/ActiveX/외부연결/포함개체 거부) + Zip bomb·경로조작 검사 + 크기 제한(기본 5MB) + 수식 셀 거부. 원본 파일명은 표시용으로만 쓰고 `data\uploads\<UUID>.xlsx` 로 저장
- 웹 업로드 화면은 Phase 6에서 같은 처리 흐름으로 제공합니다.

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
- 사내 Proxy: `HTTPS_PROXY` 환경변수 사용 (httpx 표준)
- **회사 SSL 검사(복호화) 환경**: 기본값 `TLS_TRUST_STORE=system` 으로 **Windows 인증서 저장소**를 사용하므로
  회사 루트 CA가 PC에 배포되어 있으면 추가 설정 없이 동작합니다(`truststore` 패키지).
  별도 CA 파일이 있으면 `SSL_CERT_FILE=C:\경로\ca.pem` 으로 추가 신뢰. 인증서 검증을 끄는 옵션은 제공하지 않습니다.

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
| truststore | OS(Windows) 인증서 저장소로 TLS 검증 — 회사 SSL 검사 장비 환경 대응 |
| pytest (dev) | 자동화 테스트 |
