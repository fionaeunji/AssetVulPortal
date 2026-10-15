# VDI 소스 반입 가이드 (개발 소스 그대로 옮기기)

- 목적: 인터넷 PC에서 개발·검증한 **Git 커밋 그대로의 소스**를 VDI(인터넷 차단망)에 반입해 설치·운영한다.
- 원칙
  - 반입본은 **Git 커밋 1개와 1:1** — 커밋 안 된 변경이 있으면 패키지 생성이 거부된다.
  - 반입 zip의 SHA-256(반입 신청서) + zip 내부 파일별 SHA-256(`SHA256SUMS.txt`) 2단계로 변조·누락을 확인한다.
  - 소스 폴더와 데이터 폴더를 분리해, 업데이트 때 소스만 교체하고 DB·업로드·로그는 유지한다.
  - VDI에서 소스를 직접 수정하지 않는다. 수정은 인터넷 PC에서 커밋 → 재반입.

## 1. 반입물

| 파일 | 내용 | 비고 |
|---|---|---|
| `AssetVulPortal-<날짜>-<커밋>.zip` | 소스(커밋된 파일만) + `wheels\`(오프라인 설치 파일) + `SHA256SUMS.txt` + `PACKAGE_INFO.txt` | 약 9MB (2026-10-15 개발환경에서 Python 3.12 대상으로 생성해 측정) |
| Python 설치 파일 | VDI에 Python이 없을 때만 | python.org Windows installer (64-bit) |

포함되지 않는 것: `.env`(비밀값), `data\`(DB·업로드·Bundle·로그), `.venv\`, `.git\`. 

## 2. 인터넷 PC — 패키지 만들기

※ 패키지는 **Windows PC**에서 생성하세요. pip는 Windows 전용 의존성(예: pytest의 colorama)을 실행 중인 OS 기준으로 판단하므로, 다른 OS에서 만들면 일부 wheel이 빠질 수 있습니다.

① VDI의 Python 버전 확인 (VDI 명령창 `python --version`, 없으면 반입할 버전으로 결정. 3.12 이상)

② 패키지 생성
```cmd
cd <저장소 폴더>
git checkout main
git pull
git status                                  ← "nothing to commit" 이어야 함
python -m pip_audit -r requirements.txt     ← (권장) 알려진 취약점 점검, 없으면 pip install pip-audit
python tools\build_vdi_package.py --python-version 3.12
```
출력 예:
```
패키지: ...\dist\AssetVulPortal-20261015-fc8c70d.zip (9.0 MB)
SHA-256: 85c4...8641
```
- `--python-version` 은 **VDI의 Python 버전**(예: 3.12, 3.13, 3.14). 다르면 VDI에서 설치가 실패한다.
- Python 설치 파일도 반입한다면: `certutil -hashfile python-3.x.x-amd64.exe SHA256`

③ 반입 신청서 기재: 파일명, SHA-256, Git 커밋(파일명의 7자리), 용도

## 3. VDI — 최초 설치

권장 폴더 구조
```
C:\VulPortal\
  AssetVulPortal-20261015-fc8c70d\   ← 소스 (버전별 폴더, 업데이트 시 새 폴더)
  data\                               ← DB·업로드·Bundle·로그 (유지)
```

① 반입 파일 해시 대조 — 신청서 값과 같아야 함
```cmd
certutil -hashfile AssetVulPortal-20261015-fc8c70d.zip SHA256
```

② 압축 해제 → `C:\VulPortal\` (zip 안의 최상위 폴더가 그대로 생김), 내부 파일 검증
```cmd
cd /d C:\VulPortal\AssetVulPortal-20261015-fc8c70d
python -I tools\verify_package.py
```
→ `검증 성공: N개 파일 해시 일치` 확인. 실패 시 설치 중단, 재반입.

③ 오프라인 설치
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install --no-index --find-links wheels -r requirements.txt pytest
```

④ 설정 — `copy .env.example .env` 후 메모장으로 수정
```
APP_SECRET_KEY=<32자 이상 난수: python -c "import secrets; print(secrets.token_urlsafe(48))">
APP_ENV=dev                                   # HTTPS 리버스 프록시 뒤에서 운영하면 prod
COLLECTOR_MODE=offline
BUNDLE_HMAC_KEY=<외부망 Collector와 같은 값>
DATA_DIR=C:/VulPortal/data
DATABASE_URL=sqlite:///C:/VulPortal/data/portal.db
```

⑤ 동작 확인·초기화
```cmd
python -m pytest                              ← 자동화 테스트 (네트워크 불필요)
python -m scripts.init_db
python -m scripts.create_user --username admin --role admin
python -m scripts.import_assets <자산대장.xlsx>
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
python -m app.scheduler                       ← 별도 창 (09:00/14:00 Bundle Import)
```
이후 취약점 데이터 반입 절차는 `docs/vdi_migration.md` §4 (targets 반출 → Collector 수집 → Bundle 반입).

## 4. VDI — 업데이트 (새 버전 반입)

1. 인터넷 PC에서 §2로 새 패키지 생성·반입, VDI에서 §3 ①② (해시 대조·검증)
2. 서버·Scheduler 창 종료
3. **백업**: `C:\VulPortal\data` 폴더 복사 (예: `data_backup_20261015`)
4. 새 폴더에서
   ```cmd
   copy ..\AssetVulPortal-<이전버전>\.env .env
   python -m venv .venv
   .venv\Scripts\activate.bat
   pip install --no-index --find-links wheels -r requirements.txt pytest
   python -m pytest
   python -m scripts.init_db                  ← DB 구조 변경(migration)이 있으면 적용, 없으면 변화 없음
   ```
5. 새 폴더에서 서버·Scheduler 재시작 → 로그인·Dashboard 확인
6. 이전 버전 폴더는 다음 업데이트까지 보관

**되돌리기(Rollback)**: 서버 종료 → `data` 를 3번 백업으로 복원 → 이전 버전 폴더에서 서버 재시작. (새 버전의 `init_db` 가 DB 구조를 바꿨을 수 있으므로 DB 복원 필수)

## 5. 점검표

| # | 확인 | 방법 |
|---|---|---|
| 1 | 반입본 = Git 커밋 | `PACKAGE_INFO.txt` 의 Git 커밋이 GitHub main 커밋과 일치 |
| 2 | 반입 중 변조 없음 | `certutil` 값 = 신청서 SHA-256, `verify_package.py` 성공 |
| 3 | 비밀값 미포함 | zip 안에 `.env` 없음 (패키지 생성 시 자동 제외) |
| 4 | 오프라인 설치 | `pip install --no-index` 성공 |
| 5 | 외부 통신 없음 | `.env` 의 `COLLECTOR_MODE=offline`, 웹 [지금 수집] 버튼 비활성 |
| 6 | 데이터 분리 | `.env` 의 `DATA_DIR`·`DATABASE_URL` 이 소스 폴더 밖 |
| 7 | 동작 | `python -m pytest` 통과(패키지 생성 테스트 1건은 .git 이 없어 skip 정상), 웹 로그인·Dashboard |

## 6. 자주 생기는 문제

| 증상 | 원인 / 조치 |
|---|---|
| `pip install` 에서 `No matching distribution found` | 패키지의 Python 버전(`PACKAGE_INFO.txt`)과 VDI Python 버전이 다름 → 맞는 `--python-version` 으로 재생성 |
| `verify_package.py` 에서 `해시 불일치` / `목록에 없는 파일` | 반입 중 손상, 백신 격리, 압축 해제 도구 문제, 또는 VDI에서 소스 수정 → 원본 zip으로 다시 해제, 계속되면 재반입 |
| 패키지 생성 시 `커밋되지 않은 변경이 있습니다` | `git status` 의 변경을 커밋하거나 되돌린 후 재실행 |
| `UnicodeDecodeError` (cp949) | `.env` 를 UTF-8로 저장 (메모장 → 다른 이름으로 저장 → 인코딩 UTF-8) |

## 7. 개발환경 시험 결과 (2026-10-15)

- `tools\build_vdi_package.py --python-version 3.12` → zip 9.0MB, 소스 158개 + wheel 38개, Windows(win_amd64) Python 3.12·3.13·3.14 wheel 다운로드 모두 성공
- 압축 해제 폴더(.git 없음) + offline `.env` + 소스 밖 `DATA_DIR` 로 `python -m pytest` 통과(1건 skip), `init_db` 시 DB가 `DATA_DIR` 에 생성됨
- 압축 해제 후 파일 1개를 수정하자 `verify_package.py` 가 `해시 불일치` 로 검출
- Windows 실제 설치(`pip install --no-index`)는 사용자 PC에서 확인 필요
