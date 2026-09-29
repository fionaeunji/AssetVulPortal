"""Authentication Layer.

`AuthProvider` 인터페이스로 분리하여, 운영 전환 시 사내 SSO(SAML/OIDC/리버스프록시 헤더 등)
구현체로 교체할 수 있게 한다. PoC는 로컬 DB 계정(`LocalAuthProvider`)을 사용한다.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import timedelta
from typing import Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import User
from app.models.enums import Role
from app.models.types import utcnow
from app.security.passwords import DUMMY_HASH, verify_password

MAX_FAILED_LOGINS = 5
LOCKOUT_MINUTES = 15

ROLE_LEVEL = {Role.VIEWER: 1, Role.OPERATOR: 2, Role.ADMIN: 3}


@dataclass(frozen=True)
class Principal:
    username: str
    role: Role

    def has_role(self, required: Role) -> bool:
        return ROLE_LEVEL[self.role] >= ROLE_LEVEL[required]


class AuthProvider(Protocol):
    def authenticate(self, session: Session, username: str, password: str) -> Principal | None: ...


class LocalAuthProvider:
    """로컬 계정 인증: scrypt 검증, 실패 횟수 잠금, 계정 존재여부 비노출."""

    def authenticate(self, session: Session, username: str, password: str) -> Principal | None:
        user = session.execute(select(User).where(User.username == username)).scalar_one_or_none()
        if user is None:
            verify_password(password, DUMMY_HASH)
            return None
        now = utcnow()
        if not user.is_active or (user.locked_until and user.locked_until > now):
            verify_password(password, DUMMY_HASH)
            return None
        if not verify_password(password, user.password_hash):
            user.failed_login_count += 1
            if user.failed_login_count >= MAX_FAILED_LOGINS:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                user.failed_login_count = 0
            return None
        user.failed_login_count = 0
        user.locked_until = None
        user.last_login_at = now
        return Principal(username=user.username, role=user.role)


class LoginRateLimiter:
    """IP 단위 로그인 실패 제한 (Sliding window, 프로세스 메모리). 운영 다중 인스턴스는 공용 저장소로 교체."""

    def __init__(self, max_failures: int = 20, window_seconds: int = 600, clock=time.monotonic) -> None:
        self.max_failures = max_failures
        self.window = window_seconds
        self._clock = clock
        self._fails: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        q = self._fails.setdefault(key, deque())
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def blocked(self, key: str | None) -> bool:
        if not key:
            return False
        with self._lock:
            return len(self._prune(key, self._clock())) >= self.max_failures

    def failure(self, key: str | None) -> None:
        if not key:
            return
        with self._lock:
            now = self._clock()
            self._prune(key, now).append(now)
            if len(self._fails) > 10000:          # 메모리 상한
                self._fails.pop(next(iter(self._fails)))

    def success(self, key: str | None) -> None:
        if key:
            with self._lock:
                self._fails.pop(key, None)
