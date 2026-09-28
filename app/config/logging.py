"""로깅 설정: 파일(data/logs) + 콘솔, 모든 핸들러에 Secret 마스킹 필터 적용."""
from __future__ import annotations

import logging
import logging.handlers

from app.config.settings import Settings
from app.security.redaction import RedactingFilter

_configured = False


def configure_logging(settings: Settings) -> None:
    global _configured
    if _configured:
        return
    secrets = [settings.app_secret_key.get_secret_value()]
    if settings.nvd_api_key:
        secrets.append(settings.nvd_api_key.get_secret_value())
    redacting = RedactingFilter(secrets)

    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(
        settings.log_dir / "app.log", maxBytes=10 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    console = logging.StreamHandler()
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for h in (file_handler, console):
        h.setFormatter(fmt)
        h.addFilter(redacting)
        root.addHandler(h)
    # httpx는 요청 URL을 INFO로 남기므로 WARNING으로 제한 (쿼리 파라미터 노출 방지)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    _configured = True
