"""FastAPI 애플리케이션 팩토리."""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session, sessionmaker
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config.logging import configure_logging
from app.config.settings import AppEnv, Settings, get_settings
from app.web.deps import TEMPLATES_DIR, LoginRequired, render

logger = logging.getLogger("app")

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}
STATIC_DIR = TEMPLATES_DIR.parent / "static"
MAX_FORM_BYTES = 64 * 1024


def _wants_html(request: Request) -> bool:
    return "text/html" in request.headers.get("accept", "") and not request.url.path.startswith("/api/")


def create_app(settings: Settings | None = None,
               session_factory: sessionmaker[Session] | None = None) -> FastAPI:
    settings = settings or get_settings()
    settings.ensure_dirs()
    configure_logging(settings)
    if session_factory is None:
        from app.db import get_sessionmaker
        session_factory = get_sessionmaker()

    is_prod = settings.app_env == AppEnv.PROD
    app = FastAPI(title="IT자산 취약점 관리 포털 (PoC)", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings
    app.state.session_factory = session_factory
    from app.services.vulnerability_collector import run_online_collection
    app.state.collection_runner = run_online_collection
    from app.security.auth import LoginRateLimiter
    app.state.login_limiter = LoginRateLimiter()

    @app.middleware("http")
    async def _limits_and_headers(request: Request, call_next):
        # 요청 본문 크기 제한 (업로드는 설정값 + 여유, 그 외 폼은 64KB)
        if request.method == "POST":
            limit = settings.upload_max_bytes + 64 * 1024 if request.url.path == "/assets/upload" \
                else MAX_FORM_BYTES
            cl = request.headers.get("content-length")
            if cl is None or not cl.isdigit():
                # chunked 전송으로 크기 제한을 우회하지 못하도록 Content-Length 필수 (브라우저 폼은 항상 전송)
                return PlainTextResponse("Length Required", status_code=411)
            if int(cl) > limit:
                return PlainTextResponse("요청 크기 제한을 초과했습니다.", status_code=413)
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if is_prod:   # 운영(HTTPS 뒤)에서만 HSTS
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
        return response

    # SessionMiddleware 는 가장 바깥에서 동작해야 하므로 마지막에 추가
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.app_secret_key.get_secret_value(),
        session_cookie="vp_session",
        max_age=settings.session_idle_minutes * 60,
        same_site="strict",
        https_only=is_prod,
    )

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, _exc: LoginRequired):
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc(request: Request, exc: StarletteHTTPException):
        # detail 은 서버가 정의한 메시지만 사용 (내부 정보 미포함)
        detail = exc.detail if isinstance(exc.detail, str) else "요청을 처리할 수 없습니다."
        if exc.status_code == 404 and detail == "Not Found":
            detail = "페이지를 찾을 수 없습니다."
        if _wants_html(request):
            return render(request, "error.html", {"code": exc.status_code, "message": detail},
                          status_code=exc.status_code)
        return JSONResponse({"error": detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(request: Request, exc: RequestValidationError):
        fields = [".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()]
        if _wants_html(request):
            return render(request, "error.html", {"code": 422, "message": "입력값이 올바르지 않습니다."},
                          status_code=422)
        return JSONResponse({"error": "입력값이 올바르지 않습니다.", "fields": fields}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:12]
        logger.exception("unhandled error id=%s path=%s", error_id, request.url.path)
        msg = "처리 중 오류가 발생했습니다. 관리자에게 오류 ID를 전달하세요."
        if _wants_html(request):
            return render(request, "error.html", {"code": 500, "message": msg, "error_id": error_id},
                          status_code=500)
        return JSONResponse({"error": msg, "error_id": error_id}, status_code=500)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    from app.web import routes_main, routes_ops
    app.include_router(routes_main.router)
    app.include_router(routes_ops.router)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    return app


_app: FastAPI | None = None


def __getattr__(name: str):
    """`uvicorn app.main:app` 지원 — import 시점이 아닌 첫 접근 시 생성 (.env 없이 import 가능)."""
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(name)
