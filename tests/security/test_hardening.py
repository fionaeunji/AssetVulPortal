"""Phase 9: Secure Coding 보완 사항 + 정적 규칙 회귀 방지."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.config.settings import Settings
from app.main import create_app
from app.models import AuditLog
from app.security.auth import LoginRateLimiter
from tests.web.test_web import PW, csrf_of, portal  # noqa: F401

ROOT = Path(__file__).resolve().parents[2]
APP_FILES = [p for p in (ROOT / "app").rglob("*") if p.suffix in (".py", ".html") and "__pycache__" not in p.parts]


# ---------------- 정적 규칙 (금지 패턴이 코드에 다시 들어오지 않도록) ----------------
@pytest.mark.parametrize("pattern,why", [
    (r"\|\s*safe\b", "Jinja |safe 금지 (XSS)"),
    (r"\bMarkup\(", "Markup 금지 (XSS)"),
    (r"innerHTML", "innerHTML 금지 (XSS)"),
    (r"<script>[^<]", "인라인 스크립트 금지 (CSP)"),
    (r"\sstyle=\"", "인라인 style 금지 (CSP)"),
    (r"\beval\(|\bexec\(", "eval/exec 금지"),
    (r"yaml\.load\(", "yaml.safe_load 만 허용"),
    (r"\bpickle\b|\bsubprocess\b|os\.system|shell=True", "명령 실행/역직렬화 금지"),
    (r"verify\s*=\s*False", "TLS 검증 비활성화 금지"),
    (r"\btext\(\s*f[\"']|\bexecute\(\s*f[\"']|\.format\(.*(SELECT|INSERT|UPDATE|DELETE)", "SQL 문자열 조합 금지"),
    (r"follow_redirects\s*=\s*True", "자동 Redirect 추적 금지 (SSRF)"),
])
def test_forbidden_patterns_absent(pattern, why):
    hits = []
    for p in APP_FILES:
        for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(pattern, line):
                hits.append(f"{p.relative_to(ROOT)}:{i}")
    assert not hits, f"{why}: {hits}"


def test_env_not_tracked_and_example_has_no_secret():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in gi.splitlines()
    ex = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert re.search(r"^APP_SECRET_KEY=\s*$", ex, re.M) and re.search(r"^NVD_API_KEY=\s*$", ex, re.M)


def test_external_urls_only_in_allowlist_module():
    """코드에 등장하는 외부 URL은 Allowlist Host(설명 주석)나 예시 도메인뿐이어야 한다."""
    from urllib.parse import urlsplit

    from app.config.endpoints import ALLOWED_HOSTS
    for p in APP_FILES:
        if p.name == "endpoints.py" or p.suffix != ".py":
            continue
        for m in re.finditer(r"https?://[^\s\"')]+", p.read_text(encoding="utf-8")):
            host = urlsplit(m.group(0)).hostname or ""
            assert host in ALLOWED_HOSTS or host.endswith("example") or "example." in host \
                or host == "schemas.openxmlformats.org", \
                f"{p.name}: 외부 URL은 app/config/endpoints.py 에서만 정의 ({m.group(0)})"


# ---------------- 요청 크기 제한 우회(chunked) ----------------
def test_post_without_content_length_rejected(portal):  # noqa: F811
    app, _, _ = portal
    c = TestClient(app)
    c.get("/login")

    def gen():
        yield b"username=op1&password=x&csrf_token=y"
    r = c.post("/login", content=gen(), headers={"content-type": "application/x-www-form-urlencoded"})
    assert r.status_code == 411


def test_large_form_rejected(portal):  # noqa: F811
    app, _, _ = portal
    c = TestClient(app)
    r = c.post("/login", data={"username": "a" * 70000, "password": "x", "csrf_token": "y"})
    assert r.status_code == 413


# ---------------- HSTS ----------------
def test_hsts_only_in_prod(tmp_path, engine):
    from sqlalchemy.orm import sessionmaker
    f = sessionmaker(bind=engine)
    dev = TestClient(create_app(Settings(_env_file=None, data_dir=tmp_path / "a"), f))
    prod = TestClient(create_app(Settings(_env_file=None, data_dir=tmp_path / "b", app_env="prod"), f))
    assert "strict-transport-security" not in dev.get("/healthz").headers
    assert prod.get("/healthz").headers["strict-transport-security"] == "max-age=31536000"


# ---------------- 로그인 시도 제한 ----------------
def test_ip_rate_limit_blocks_even_correct_password(portal):  # noqa: F811
    app, factory, _ = portal
    app.state.login_limiter = LoginRateLimiter(max_failures=3, window_seconds=600)
    c = TestClient(app)
    tok = csrf_of(c.get("/login").text)
    for user in ("op1", "admin1", "nobody"):       # 여러 계정 대상 시도
        assert c.post("/login", data={"username": user, "password": "bad", "csrf_token": tok}).status_code == 401
    r = c.post("/login", data={"username": "op1", "password": PW, "csrf_token": tok})
    assert r.status_code == 429
    with factory() as s:
        assert s.execute(select(AuditLog).where(AuditLog.result == "rate_limited")).scalar_one()


def test_rate_limiter_window_and_reset():
    now = [1000.0]                                   # 가짜 시계 (OS 시계 해상도와 무관하게 결정적)
    lim = LoginRateLimiter(max_failures=2, window_seconds=600, clock=lambda: now[0])
    lim.failure("1.1.1.1")
    assert not lim.blocked("1.1.1.1")
    lim.failure("1.1.1.1")
    assert lim.blocked("1.1.1.1") and not lim.blocked("2.2.2.2")
    lim.success("1.1.1.1")
    assert not lim.blocked("1.1.1.1")
    lim.failure("3.3.3.3")
    lim.failure("3.3.3.3")
    assert lim.blocked("3.3.3.3")
    now[0] += 600                                    # 창 경계: 아직 유효
    assert lim.blocked("3.3.3.3")
    now[0] += 1                                      # 창 밖으로 벗어남 → 만료
    assert not lim.blocked("3.3.3.3")


def test_failed_login_username_sanitized_in_audit(portal):  # noqa: F811
    app, factory, _ = portal
    c = TestClient(app)
    tok = csrf_of(c.get("/login").text)
    c.post("/login", data={"username": "evil‮\x07<script>", "password": "x", "csrf_token": tok})
    with factory() as s:
        log = s.execute(select(AuditLog).where(AuditLog.action == "LOGIN_FAILURE")).scalar_one()
        assert "‮" not in log.actor and "\x07" not in log.actor
