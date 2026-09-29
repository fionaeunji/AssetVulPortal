"""Server-side 입력 검증 (Allowlist 기반)."""
from __future__ import annotations

import ipaddress
import math
import re
import unicodedata

CVE_ID_RE = re.compile(r"^CVE-(19|20)\d{2}-\d{4,7}$")


class ValidationError(ValueError):
    pass


def validate_cve_id(value: str) -> str:
    if not isinstance(value, str):
        raise ValidationError("CVE ID must be a string")
    v = value.strip().upper()
    if not CVE_ID_RE.fullmatch(v):
        raise ValidationError("invalid CVE ID format")
    return v


def _finite_float(value, name: str) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        raise ValidationError(f"{name} must be a number") from None
    if math.isnan(f) or math.isinf(f):
        raise ValidationError(f"{name} must be finite")
    return f


def validate_cvss(value) -> float:
    f = _finite_float(value, "CVSS")
    if not 0.0 <= f <= 10.0:
        raise ValidationError("CVSS must be between 0.0 and 10.0")
    return round(f, 1)


def validate_probability(value, name: str = "EPSS") -> float:
    f = _finite_float(value, name)
    if not 0.0 <= f <= 1.0:
        raise ValidationError(f"{name} must be between 0.0 and 1.0")
    return f


def validate_ip(value: str) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        raise ValidationError("invalid IP address") from None


_CONTROL = {"Cc", "Cf"}


def clean_text(value, max_len: int, *, allow_newline: bool = False) -> str | None:
    """제어문자 제거, 길이 제한. 빈 값은 None."""
    if value is None:
        return None
    s = str(value)
    s = "".join(
        ch for ch in s
        if unicodedata.category(ch) not in _CONTROL or (allow_newline and ch == "\n")
    ).strip()
    if not s:
        return None
    if len(s) > max_len:
        raise ValidationError(f"text longer than {max_len} characters")
    return s
