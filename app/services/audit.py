"""감사로그 기록/검증 (Append-only + SHA-256 Hash chain)."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AuditLog
from app.models.types import utcnow
from app.security.redaction import redact

GENESIS_HASH = "0" * 64


class AuditAction:
    """감사 대상 이벤트 (요구사항 §15 Audit Log)."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    EXCEL_UPLOAD = "EXCEL_UPLOAD"
    ASSET_CHANGE = "ASSET_CHANGE"
    MAPPING_APPROVE = "MAPPING_APPROVE"
    MAPPING_REJECT = "MAPPING_REJECT"
    STATUS_CHANGE = "STATUS_CHANGE"
    OWNER_CHANGE = "OWNER_CHANGE"
    POLICY_CHANGE = "POLICY_CHANGE"
    COLLECTION_MANUAL = "COLLECTION_MANUAL"
    COLLECTION_SCHEDULED = "COLLECTION_SCHEDULED"
    BUNDLE_IMPORT = "BUNDLE_IMPORT"
    EXPORT = "EXPORT"
    USER_CHANGE = "USER_CHANGE"


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def compute_hash(prev_hash: str, row: AuditLog) -> str:
    payload = {
        "occurred_at": _iso(row.occurred_at),
        "actor": row.actor,
        "actor_role": row.actor_role,
        "action": row.action,
        "target_type": row.target_type,
        "target_id": row.target_id,
        "before": row.before,
        "after": row.after,
        "client_ip": row.client_ip,
        "result": row.result,
    }
    return hashlib.sha256((prev_hash + _canonical(payload)).encode("utf-8")).hexdigest()


def record(
    session: Session,
    *,
    actor: str,
    action: str,
    actor_role: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    before: dict | None = None,
    after: dict | None = None,
    client_ip: str | None = None,
    result: str = "success",
) -> AuditLog:
    """감사로그 1건 추가. 호출자의 트랜잭션에 포함되어 업무 변경과 함께 commit/rollback 된다.

    NOTE: PostgreSQL 다중 Writer 환경에서는 Chain 분기를 막기 위해 advisory lock 적용이 필요(운영 전환 시).
    """
    last = session.execute(
        select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1).with_for_update()
    ).scalar_one_or_none()
    prev_hash = last or GENESIS_HASH
    row = AuditLog(
        occurred_at=utcnow(),
        actor=actor,
        actor_role=actor_role,
        action=action,
        target_type=target_type,
        target_id=None if target_id is None else str(target_id),
        before=redact(before) if before else None,
        after=redact(after) if after else None,
        client_ip=client_ip,
        result=result,
        prev_hash=prev_hash,
    )
    row.hash = compute_hash(prev_hash, row)
    session.add(row)
    session.flush()
    return row


@dataclass
class ChainVerification:
    ok: bool
    checked: int
    broken_at_id: int | None = None


def verify_chain(session: Session) -> ChainVerification:
    prev = GENESIS_HASH
    count = 0
    for row in session.execute(select(AuditLog).order_by(AuditLog.id)).scalars():
        if row.prev_hash != prev or compute_hash(prev, row) != row.hash:
            return ChainVerification(ok=False, checked=count, broken_at_id=row.id)
        prev = row.hash
        count += 1
    return ChainVerification(ok=True, checked=count)
