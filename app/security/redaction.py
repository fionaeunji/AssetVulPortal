"""로그/감사로그에서 민감정보 마스킹."""
from __future__ import annotations

import logging
import re
from typing import Any

SENSITIVE_KEYS = frozenset(
    {"password", "passwd", "secret", "apikey", "api_key", "token", "authorization",
     "cookie", "session", "app_secret_key", "nvd_api_key", "csrf_token"}
)
MASK = "***"

_PATTERNS = [
    re.compile(r"(?i)(apiKey|api_key|password|secret|token|authorization)(\s*[=:]\s*)([^\s&,;\"']+)"),
]


def _norm_key(k: str) -> str:
    return k.lower().replace("-", "_")


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            k: (MASK if isinstance(k, str) and _norm_key(k) in SENSITIVE_KEYS else redact(v))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_text(text: str) -> str:
    for p in _PATTERNS:
        text = p.sub(lambda m: f"{m.group(1)}{m.group(2)}{MASK}", text)
    return text


class RedactingFilter(logging.Filter):
    """모든 로그 레코드의 메시지에서 Secret 패턴을 마스킹."""

    def __init__(self, secrets: list[str] | None = None) -> None:
        super().__init__()
        self._secrets = [s for s in (secrets or []) if s and len(s) >= 8]

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        for s in self._secrets:
            msg = msg.replace(s, MASK)
        record.msg = redact_text(msg)
        record.args = None
        return True
