"""웹 공통 의존성: DB 세션, 인증/인가(RBAC), CSRF, 템플릿, Flash 메시지."""
from __future__ import annotations

import hmac
import secrets
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from fastapi import Depends, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.models.enums import Role
from app.security.auth import Principal

TEMPLATES_DIR = Path(__file__).resolve().parents[1] / "templates"
KST = ZoneInfo("Asia/Seoul")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))   # .html 은 autoescape 기본 활성


# ---------------- 템플릿 필터 ----------------
def _kst(dt: datetime | None, fmt: str = "%Y-%m-%d %H:%M") -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(KST).strftime(fmt)


def remaining(due: datetime | None, now: datetime | None = None) -> dict:
    if due is None:
        return {"text": "-", "overdue": False}
    now = now or datetime.now(timezone.utc)
    delta = due - now
    secs = int(delta.total_seconds())
    over = secs < 0
    secs = abs(secs)
    d, h = secs // 86400, (secs % 86400) // 3600
    txt = f"{d}일 {h}시간" if d else f"{h}시간 {(secs % 3600) // 60}분"
    return {"text": ("초과 " if over else "") + txt, "overdue": over}


def _epss(v: float | None) -> str:
    return "-" if v is None else f"{v:.4f}"


templates.env.filters["kst"] = _kst
templates.env.filters["epss"] = _epss
templates.env.globals["remaining"] = remaining


# ---------------- DB ----------------
def get_db(request: Request) -> Iterator[Session]:
    session = request.app.state.session_factory()
    try:
        yield session
    finally:
        session.close()


# ---------------- 인증 ----------------
class LoginRequired(Exception):
    pass


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def login_session(request: Request, principal: Principal) -> None:
    request.session.clear()   # 세션 고정 방지: 로그인 시 기존 세션 내용 폐기
    request.session.update({"user": principal.username, "role": principal.role.value,
                            "csrf": secrets.token_urlsafe(32), "last_seen": int(time.time()),
                            "flash": []})


def current_principal(request: Request, db: Session = Depends(get_db)) -> Principal:
    sess = request.session
    username = sess.get("user")
    if not username:
        raise LoginRequired()
    idle = request.app.state.settings.session_idle_minutes * 60
    if int(time.time()) - int(sess.get("last_seen", 0)) > idle:
        sess.clear()
        raise LoginRequired()
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user is None or not user.is_active:
        sess.clear()
        raise LoginRequired()
    sess["last_seen"] = int(time.time())
    return Principal(username=user.username, role=user.role)   # 권한은 매 요청 DB 기준


def require(role: Role):
    def _dep(principal: Principal = Depends(current_principal)) -> Principal:
        if not principal.has_role(role):
            raise HTTPException(status_code=403, detail="권한이 없습니다.")
        return principal
    return _dep


# ---------------- CSRF ----------------
def csrf_token(request: Request) -> str:
    tok = request.session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        request.session["csrf"] = tok
    return tok


async def verify_csrf(request: Request) -> None:
    """상태 변경 요청(POST)의 Synchronizer Token 검증 (SameSite=Strict 쿠키와 이중 방어)."""
    form = await request.form()
    sent = form.get("csrf_token")
    expected = request.session.get("csrf")
    if not isinstance(sent, str) or not expected or not hmac.compare_digest(sent, expected):
        raise HTTPException(status_code=403, detail="요청이 유효하지 않습니다. 페이지를 새로고침 후 다시 시도하세요.")


# ---------------- Flash ----------------
def flash(request: Request, message: str, kind: str = "info") -> None:
    msgs = request.session.get("flash") or []
    msgs.append({"kind": kind if kind in ("info", "error", "ok") else "info", "msg": message[:300]})
    request.session["flash"] = msgs[-5:]


def render(request: Request, name: str, ctx: dict, status_code: int = 200):
    flashes = request.session.pop("flash", []) if "user" in request.session else []
    if "user" in request.session:
        request.session["flash"] = []
    base = {"request": request, "csrf": csrf_token(request), "flashes": flashes,
            "user": request.session.get("user"), "role": request.session.get("role"),
            "collector_mode": request.app.state.settings.collector_mode.value}
    return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)
