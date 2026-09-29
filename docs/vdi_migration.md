# VDI(인터넷 차단 사내망) 이전 가이드

## 1. 목표 구조

```mermaid
flowchart LR
  subgraph INTERNET["인터넷 구간 (Collector PC)"]
    C["python -m scripts.collect<br/>--targets-file targets.json"]
    NVD[(NVD)] --> C
    EPSS[(FIRST EPSS)] --> C
    KEV[(CISA KEV)] --> C
    C --> B["bundle_*.json<br/>SHA-256 + HMAC"]
  end
  B -- "보안 전송구간<br/>(망연계/승인 반입)" --> IN
  subgraph INTERNAL["내부망 (VDI)"]
    IN["data\\bundles\\inbox"] --> S["Scheduler (offline)<br/>검증 후 Import"]
    S --> DB[(DB)]
    P["Portal (웹)"] --> DB
    T["python -m scripts.export_targets"] -- "targets.json<br/>(제품키·CVE ID만)" --> OUT["반출 → Collector PC"]
  end
```

- Portal은 인터넷에 연결되지 않습니다. `COLLECTOR_MODE=offline` 이면 외부 수집 코드가 실행되지 않고 웹의 [지금 수집] 버튼도 비활성화됩니다.
- Collector와 Portal은 **같은 소스**를 사용하며, Collector는 DB 없이 동작합니다(`app/services/collector.py` 는 DB 비의존).
- Portal ↔ Collector 간 교환 데이터
  - 반출(내부 → 외부): `targets.json` — 제품 키(`a:apache:tomcat` 등)와 증분 커서, 보유 CVE ID 목록. **자산명·IP·담당자 미포함**
  - 반입(외부 → 내부): `bundle_*.json` — 공개 취약점 데이터(NVD/EPSS/KEV)의 정규화 결과 + manifest(SHA-256, 선택 HMAC)

## 2. 설치 파일 반입 (오프라인 설치)

인터넷 PC(내부 VDI와 **같은 Windows·Python 버전**)에서:

```cmd
git clone -b claude/vulnerability-management-poc-qthd3d https://github.com/fionaeunji/AssetVulPortal.git
cd AssetVulPortal
py -3.12 -m pip download -r requirements.txt -d wheels
py -3.12 -m pip install pip-audit
py -3.12 -m pip_audit -r requirements.txt
certutil -hashfile wheels\<파일명> SHA256     (반입 신청서에 해시 기재 시)
```

반입 대상: 소스 폴더(`.git`, `.venv`, `data` 제외), `wheels\`, Python 설치 파일.

VDI에서:

```cmd
py -3.12 -m venv .venv
.venv\Scripts\activate.bat
pip install --no-index --find-links wheels -r requirements.txt
```

## 3. VDI 설정 (`.env`)

```
APP_ENV=prod                     # HTTPS 리버스 프록시 뒤에서 운영 시 (Secure 쿠키, HSTS)
APP_SECRET_KEY=<32자 이상 난수>
COLLECTOR_MODE=offline
BUNDLE_HMAC_KEY=<Collector PC와 동일한 32자 이상 난수>   # 반입 Bundle 위변조 검증 (필수 권장)
DATABASE_URL=sqlite:///./data/portal.db                  # 또는 PostgreSQL
```

Collector PC의 `.env` 에는 `COLLECTOR_MODE=online`, 동일한 `BUNDLE_HMAC_KEY`, 필요 시 `NVD_API_KEY`, `HTTPS_PROXY` 를 설정합니다.

```cmd
python -m scripts.init_db
python -m scripts.create_user --username admin --role admin
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000        (운영은 리버스 프록시 뒤 127.0.0.1 바인딩 권장)
python -m app.scheduler                                 (별도 창 / Windows 서비스)
```

## 4. 운영 절차 (1일 2회 권장)

| 단계 | 위치 | 명령 |
|---|---|---|
| ① 수집 대상 반출 (자산 변경 시) | VDI | `python -m scripts.export_targets --out targets.json` |
| ② 수집 | Collector PC | `python -m scripts.collect --targets-file targets.json --out-dir out` |
| ③ 반입 | 망연계 | `out\bundle_*.json` → VDI `data\bundles\inbox\` |
| ④ Import·매핑·판정 | VDI | Scheduler(09:00/14:00)가 자동 처리 → `processed\` / `failed\` 이동. 수동: `python -m scripts.import_bundle <파일>` |
| ⑤ 확인 | VDI 웹 | 수집 메뉴 이력(source=BUNDLE), Dashboard |

- 증분 커서는 **Portal DB가 관리**합니다. Import 성공 시에만 커서가 전진하므로, Bundle이 유실·실패하면 다음 `targets.json` 이 자동으로 같은 구간을 다시 요청합니다.
- 처음 반입하는 제품은 전체 이력을 수집하므로 Bundle이 큽니다(PoC 실측: 샘플 자산 기준 약 1.6만 CVE). 반입 용량 제한이 있으면 `targets.json` 의 `targets` 항목을 여러 파일로 나눠 수집하면 됩니다.
- 반입 파일은 Import 전에 스키마·SHA-256·HMAC 검증을 통과해야 하며, 실패 파일은 `failed\` 로 이동하고 감사로그·수집이력에 남습니다(기존 데이터 변경 없음).

## 5. PostgreSQL 전환

1. 드라이버 반입: `psycopg[binary]` wheel 추가 → `requirements.txt` 에 명시
2. `DATABASE_URL=postgresql+psycopg://vulportal:<pw>@<host>:5432/vulportal`
3. `python -m scripts.init_db` — 동일 Alembic migration + PostgreSQL용 무결성 Trigger(`app/models/guards.py`) 설치 (**PoC에서는 SQLite만 검증, PostgreSQL은 미검증 — 전환 시 테스트 필요**)
4. 권한 최소화: 애플리케이션 계정에서 `audit_logs`, `vulnerability_assessments`, `status_history` 의 `UPDATE/DELETE` 를 `REVOKE`
5. 감사로그 Hash chain은 다중 Writer 환경에서 advisory lock 적용 권장(현재 코드 주석 참고)
6. SQLite 데이터 이관이 필요하면 Bundle 재Import + 자산대장 재업로드로 재구성하는 방식을 권장(판정 이력까지 이관하려면 별도 이관 스크립트 필요 — 미구현)

## 6. 운영 전 점검 목록

| 구분 | 항목 |
|---|---|
| 인증 | 사내 SSO 연동(`app/security/auth.py` 의 `AuthProvider` 구현 교체), 초기 관리자 비밀번호 변경 |
| 전송 | 사내 인증서 HTTPS, `APP_ENV=prod` |
| 망연계 | Bundle 반입 절차 승인, `BUNDLE_HMAC_KEY` 별도 보관(양쪽 `.env` 외 저장 금지) |
| 시간 | 서버 시간 동기화(NTP) — 조치기한·스케줄·감사로그 기준 |
| 백업 | `data\portal.db`(또는 PostgreSQL), `data\bundles\processed`, `data\uploads`, `data\logs` 정기 백업 |
| 로그 | `data\logs\app.log` 순환(10MB×5), SIEM 전송 검토 |
| 파일 권한 | `data\` 폴더는 서비스 계정만 접근 |
| 정책 | `config\policy.yaml` 변경은 관리자 화면 적용(버전 변경 필수) — 변경 이력은 `policy_versions`·감사로그 |
| 취약점 | 반입 전 `pip-audit`, 정기적 의존성 갱신 |
