from __future__ import annotations

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DatabaseError

from app.models import AuditLog
from app.models.guards import AppendOnlyViolation
from app.services import audit


def test_audit_hash_chain_valid(db):
    for i in range(3):
        audit.record(db, actor="op1", action=audit.AuditAction.STATUS_CHANGE,
                     target_type="asset_vulnerability", target_id=i,
                     before={"status": "신규"}, after={"status": "확인중"})
    db.commit()
    res = audit.verify_chain(db)
    assert res.ok and res.checked == 3


def test_audit_orm_update_blocked(db):
    row = audit.record(db, actor="op1", action=audit.AuditAction.EXPORT)
    db.commit()
    row.actor = "attacker"
    with pytest.raises(AppendOnlyViolation):
        db.flush()
    db.rollback()


def test_audit_orm_delete_blocked(db):
    row = audit.record(db, actor="op1", action=audit.AuditAction.EXPORT)
    db.commit()
    db.delete(row)
    with pytest.raises(AppendOnlyViolation):
        db.flush()
    db.rollback()


def test_audit_sql_update_and_delete_blocked(db):
    audit.record(db, actor="op1", action=audit.AuditAction.EXPORT)
    db.commit()
    with pytest.raises(DatabaseError):
        db.execute(text("UPDATE audit_logs SET actor='x'"))
    db.rollback()
    with pytest.raises(DatabaseError):
        db.execute(text("DELETE FROM audit_logs"))
    db.rollback()


def test_audit_tamper_detected(engine, db):
    audit.record(db, actor="op1", action=audit.AuditAction.EXPORT)
    audit.record(db, actor="op2", action=audit.AuditAction.EXPORT)
    db.commit()
    # 공격자가 Trigger를 우회(DROP)해 변조한 상황을 가정
    with engine.begin() as conn:
        conn.exec_driver_sql("DROP TRIGGER trg_audit_logs_no_update")
        conn.exec_driver_sql("UPDATE audit_logs SET actor='attacker' WHERE id=1")
    db.expire_all()
    res = audit.verify_chain(db)
    assert not res.ok and res.broken_at_id == 1


def test_audit_redacts_secrets(db):
    row = audit.record(db, actor="admin", action=audit.AuditAction.USER_CHANGE,
                       after={"username": "u1", "password": "Secret!234", "nested": {"apiKey": "k"}})
    db.commit()
    stored = db.get(AuditLog, row.id).after
    assert stored["password"] == "***" and stored["nested"]["apiKey"] == "***"
    assert stored["username"] == "u1"
