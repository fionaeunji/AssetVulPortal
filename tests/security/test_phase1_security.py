from __future__ import annotations

import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.config.endpoints import ENDPOINTS, is_allowed_url
from app.config.settings import Settings
from app.models import User
from app.models.enums import Role
from app.security.auth import MAX_FAILED_LOGINS, LocalAuthProvider
from app.security.passwords import (
    WeakPasswordError,
    hash_password,
    validate_password_strength,
    verify_password,
)
from app.security.redaction import RedactingFilter


def test_password_hash_and_verify():
    h = hash_password("Correct-Horse-9")
    assert h.startswith("scrypt$") and "Correct" not in h
    assert verify_password("Correct-Horse-9", h)
    assert not verify_password("wrong", h)
    assert not verify_password("x", "garbage")


@pytest.mark.parametrize("pw", ["short1!", "alllowercaseletters", "NoDigitsOrSymbols"])
def test_weak_passwords_rejected(pw):
    with pytest.raises(WeakPasswordError):
        validate_password_strength(pw)


def test_login_lockout(db):
    db.add(User(username="op1", password_hash=hash_password("Good-Pass-123"), role=Role.OPERATOR))
    db.commit()
    p = LocalAuthProvider()
    for _ in range(MAX_FAILED_LOGINS):
        assert p.authenticate(db, "op1", "bad") is None
    db.commit()
    # 잠금 이후에는 올바른 비밀번호도 거부
    assert p.authenticate(db, "op1", "Good-Pass-123") is None
    assert p.authenticate(db, "nouser", "x") is None


def test_login_success_and_role(db):
    db.add(User(username="v1", password_hash=hash_password("Good-Pass-123"), role=Role.VIEWER))
    db.commit()
    pr = LocalAuthProvider().authenticate(db, "v1", "Good-Pass-123")
    assert pr and pr.has_role(Role.VIEWER) and not pr.has_role(Role.OPERATOR)


def test_secret_key_required_and_strength(monkeypatch):
    monkeypatch.delenv("APP_SECRET_KEY", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)
    with pytest.raises(ValidationError):
        Settings(_env_file=None, app_secret_key="short")


def test_ssrf_allowlist():
    for url in ENDPOINTS.values():
        assert is_allowed_url(url)
    for bad in ["http://services.nvd.nist.gov/x", "https://evil.example.com/",
                "https://services.nvd.nist.gov:8443/", "https://user:pw@api.first.org/",
                "https://169.254.169.254/latest/meta-data", "file:///etc/passwd"]:
        assert not is_allowed_url(bad)


def test_log_redaction(caplog):
    f = RedactingFilter(["S3cr3tValue-XYZ"])
    rec = logging.LogRecord("t", logging.INFO, __file__, 1,
                            "call apiKey=abcd1234 with S3cr3tValue-XYZ password: hunter2", None, None)
    f.filter(rec)
    msg = rec.getMessage()
    assert "abcd1234" not in msg and "S3cr3tValue-XYZ" not in msg and "hunter2" not in msg


@pytest.fixture()
def client():
    from app.main import create_app

    app = create_app()

    @app.get("/_boom")
    def boom():
        raise RuntimeError("internal detail /secret/path")

    return TestClient(app, raise_server_exceptions=False)


def test_security_headers(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"


def test_no_stack_trace_exposed(client):
    r = client.get("/_boom")
    assert r.status_code == 500
    body = r.text
    assert "Traceback" not in body and "secret/path" not in body and "RuntimeError" not in body
    assert "error_id" in r.json()
