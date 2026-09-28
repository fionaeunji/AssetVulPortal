"""FastAPI 애플리케이션 팩토리."""
from __future__ import annotations

import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config.logging import configure_logging
from app.config.settings import AppEnv, get_settings

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


def create_app() -> FastAPI:
    settings = get_settings()
    settings.ensure_dirs()
    configure_logging(settings)

    is_prod = settings.app_env == AppEnv.PROD
    app = FastAPI(
        title="IT자산 취약점 관리 포털 (PoC)",
        docs_url=None if is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if is_prod else "/openapi.json",
    )
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.app_secret_key.get_secret_value(),
        session_cookie="vp_session",
        max_age=settings.session_idle_minutes * 60,
        same_site="strict",
        https_only=is_prod,
    )

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    @app.exception_handler(StarletteHTTPException)
    async def _http_exc(_request: Request, exc: StarletteHTTPException):
        # detail은 서버가 정의한 메시지만 사용 (내부 정보 미포함)
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation_exc(_request: Request, exc: RequestValidationError):
        fields = [".".join(str(p) for p in e.get("loc", ())) for e in exc.errors()]
        return JSONResponse({"error": "입력값이 올바르지 않습니다.", "fields": fields}, status_code=422)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        error_id = uuid.uuid4().hex[:12]
        logger.exception("unhandled error id=%s path=%s", error_id, request.url.path)
        return JSONResponse(
            {"error": "처리 중 오류가 발생했습니다. 관리자에게 오류 ID를 전달하세요.", "error_id": error_id},
            status_code=500,
        )

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    return app


app = create_app()
