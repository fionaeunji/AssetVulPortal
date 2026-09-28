"""수집 이력, 정책 버전, 사용자, 감사로그, Job Lock."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.enums import (
    CollectionSource,
    CollectionStatus,
    CollectionTrigger,
    Role,
    str_enum,
)
from app.models.types import UTCDateTime, utcnow


class CollectionHistory(Base):
    __tablename__ = "collection_history"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    source: Mapped[CollectionSource] = mapped_column(str_enum(CollectionSource, "ck_coll_source"))
    trigger: Mapped[CollectionTrigger] = mapped_column(str_enum(CollectionTrigger, "ck_coll_trigger"))
    requested_by: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
    status: Mapped[CollectionStatus] = mapped_column(
        str_enum(CollectionStatus, "ck_coll_status"), default=CollectionStatus.RUNNING
    )
    params: Mapped[dict] = mapped_column(JSON, default=dict)
    endpoints_called: Mapped[list] = mapped_column(JSON, default=list)  # 실측 외부통신 목적지
    items_fetched: Mapped[int] = mapped_column(Integer, default=0)
    items_inserted: Mapped[int] = mapped_column(Integer, default=0)
    items_updated: Mapped[int] = mapped_column(Integer, default=0)
    error_summary: Mapped[str | None] = mapped_column(String(1000))  # Secret 미포함 요약
    bundle_sha256: Mapped[str | None] = mapped_column(String(64))


class PolicyVersion(Base):
    """정책 불변 버전. 정책 변경 = 새 행 추가."""

    __tablename__ = "policy_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    version: Mapped[str] = mapped_column(String(64), unique=True)
    content_yaml: Mapped[str] = mapped_column(Text)
    content_sha256: Mapped[str] = mapped_column(String(64))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    role: Mapped[Role] = mapped_column(str_enum(Role, "ck_user_role"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(UTCDateTime)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(UTCDateTime)


class AuditLog(Base):
    """Append-only 감사로그. ORM 이벤트 + DB Trigger로 UPDATE/DELETE 차단, Hash chain으로 위변조 탐지."""

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(64), index=True)
    actor_role: Mapped[str | None] = mapped_column(String(16))
    action: Mapped[str] = mapped_column(String(64), index=True)
    target_type: Mapped[str | None] = mapped_column(String(64))
    target_id: Mapped[str | None] = mapped_column(String(128))
    before: Mapped[dict | None] = mapped_column(JSON)
    after: Mapped[dict | None] = mapped_column(JSON)
    client_ip: Mapped[str | None] = mapped_column(String(45))
    result: Mapped[str] = mapped_column(String(16), default="success")
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64), unique=True)


class JobLock(Base):
    """프로세스 간 중복 실행 방지 Lease Lock."""

    __tablename__ = "job_locks"

    name: Mapped[str] = mapped_column(String(64), primary_key=True)
    holder: Mapped[str] = mapped_column(String(128))
    acquired_at: Mapped[datetime] = mapped_column(UTCDateTime)
    expires_at: Mapped[datetime] = mapped_column(UTCDateTime)
