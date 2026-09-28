# IT자산 취약점 관리 포털 (PoC)

외부 취약점 데이터(NVD / FIRST EPSS / CISA KEV)를 수집하고 Excel 자산관리대장과 매핑하여
취약 자산을 식별·분류·기한관리하는 사내망용 포털의 PoC입니다.

- 설계서: [`docs/00_design.md`](docs/00_design.md)
- 진행 상태: **Phase 1 완료** (Skeleton + DB Schema + 인증/감사 기반). 전체 README는 Phase 10에서 완성합니다.

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
