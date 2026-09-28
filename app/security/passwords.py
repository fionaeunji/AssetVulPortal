"""비밀번호 해시 (표준 라이브러리 hashlib.scrypt — 추가 의존성 없음)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P, _DKLEN = 2**14, 8, 1, 32
_PREFIX = "scrypt"
MIN_PASSWORD_LENGTH = 10


class WeakPasswordError(ValueError):
    pass


def validate_password_strength(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(f"password must be at least {MIN_PASSWORD_LENGTH} characters")
    classes = sum(
        [any(c.islower() for c in password), any(c.isupper() for c in password),
         any(c.isdigit() for c in password), any(not c.isalnum() for c in password)]
    )
    if classes < 3:
        raise WeakPasswordError("password must contain 3 of: lower, upper, digit, symbol")


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"{_PREFIX}${_N}${_R}${_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: str) -> bool:
    try:
        prefix, n, r, p, salt_b64, dk_b64 = stored.split("$")
        if prefix != _PREFIX:
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p),
                            dklen=len(expected))
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(dk, expected)


# 존재하지 않는 사용자 로그인 시에도 동일한 연산을 수행해 Timing으로 계정 존재 여부가 드러나지 않게 함
DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
