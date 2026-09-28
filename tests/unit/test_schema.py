"""Phase 1: 스키마, 제약조건, 불변/Append-only 보호 검증."""
from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import DatabaseError, IntegrityError, StatementError

from app.models import (
    Asset,
    AssetProduct,
    AssetVulnerability,
    PolicyVersion,
    StatusHistory,
    Vulnerability,
)
from app.models.enums import AssessmentState, Criticality, MatchType, Zone
from app.models.guards import AppendOnlyViolation
from app.models.types import utcnow

REQUIRED_TABLES = {
    "assets", "asset_products", "vulnerabilities", "epss_history", "vulnerability_products",
    "asset_vulnerabilities", "asset_product_mapping", "collection_history", "audit_logs",
    # 추가 테이블
    "users", "policy_versions", "vulnerability_assessments", "status_history",
    "mapping_candidates", "import_batches", "job_locks",
}


def test_required_tables_exist(engine):
    assert REQUIRED_TABLES <= set(inspect(engine).get_table_names())


def test_asset_vulnerabilities_has_required_columns(engine):
    cols = {c["name"] for c in inspect(engine).get_columns("asset_vulnerabilities")}
    assert {"asset_id", "cve_id", "severity", "detected_at", "due_at", "owner", "status",
            "match_type", "match_confidence"} <= cols


def _asset(db, code="SRV-001"):
    a = Asset(asset_code=code, name="web01", zone=Zone.PERIMETER, ip="10.0.0.1",
              criticality=Criticality.HIGH, owner_name="테스트담당")
    db.add(a)
    db.flush()
    return a


def test_duplicate_cve_rejected(db):
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_score=9.8))
    db.commit()
    db.add(Vulnerability(cve_id="CVE-2024-0001", cvss_score=7.0))
    with pytest.raises(IntegrityError):
        db.commit()


def test_cvss_and_epss_range_check(db):
    db.add(Vulnerability(cve_id="CVE-2024-0002", cvss_score=11.0))
    with pytest.raises(IntegrityError):
        db.commit()
    db.rollback()
    db.add(Vulnerability(cve_id="CVE-2024-0003", epss_current=1.5))
    with pytest.raises(IntegrityError):
        db.commit()


def test_invalid_enum_value_rejected(db):
    with pytest.raises((StatementError, LookupError)):
        db.add(Asset(asset_code="X", name="x", zone="DMZ", criticality=Criticality.LOW))
        db.flush()


def test_epss_initial_is_immutable_at_db_level(db):
    v = Vulnerability(cve_id="CVE-2024-0004", cvss_score=9.8, epss_initial=0.2,
                      epss_initial_date=date(2026, 9, 1), epss_first_seen_at=utcnow())
    db.add(v)
    db.commit()
    # current 갱신은 허용
    v.epss_current = 0.5
    db.commit()
    # initial 변경은 차단 (직접 SQL로도)
    with pytest.raises(DatabaseError):
        db.execute(text("UPDATE vulnerabilities SET epss_initial=0.9 WHERE cve_id='CVE-2024-0004'"))
    db.rollback()
    assert db.get(Vulnerability, "CVE-2024-0004").epss_initial == 0.2


def test_epss_initial_can_be_set_once_from_null(db):
    v = Vulnerability(cve_id="CVE-2024-0005", cvss_score=9.8)
    db.add(v)
    db.commit()
    v.epss_initial = 0.33
    v.epss_initial_date = date(2026, 9, 2)
    v.epss_first_seen_at = utcnow()
    db.commit()
    assert db.get(Vulnerability, "CVE-2024-0005").epss_initial == 0.33


def test_initial_due_at_immutable(db):
    a = _asset(db)
    p = AssetProduct(asset_id=a.id, vendor_norm="apache", product_norm="http_server",
                     version_norm="2.4.49")
    db.add_all([p, Vulnerability(cve_id="CVE-2021-41773", cvss_score=7.5)])
    db.flush()
    due = utcnow() + timedelta(days=30)
    av = AssetVulnerability(asset_id=a.id, asset_product_id=p.id, cve_id="CVE-2021-41773",
                            assessment_state=AssessmentState.ASSESSED, severity="주의",
                            initial_due_at=due, due_at=due, match_type=MatchType.CPE_RANGE)
    db.add(av)
    db.commit()
    av.due_at = due + timedelta(days=10)  # 현재 기한 변경은 허용
    db.commit()
    with pytest.raises(DatabaseError):
        db.execute(text("UPDATE asset_vulnerabilities SET initial_due_at=CURRENT_TIMESTAMP"))
    db.rollback()


def test_status_history_append_only(db):
    a = _asset(db)
    p = AssetProduct(asset_id=a.id, vendor_norm="x", product_norm="y", version_norm="1")
    db.add_all([p, Vulnerability(cve_id="CVE-2024-0006")])
    db.flush()
    av = AssetVulnerability(asset_id=a.id, asset_product_id=p.id, cve_id="CVE-2024-0006",
                            assessment_state=AssessmentState.ASSESSED, match_type=MatchType.CPE_EXACT)
    db.add(av)
    db.flush()
    h = StatusHistory(asset_vulnerability_id=av.id, from_status="신규", to_status="확인중",
                      changed_by="op1")
    db.add(h)
    db.commit()
    h.to_status = "오탐"
    with pytest.raises(AppendOnlyViolation):
        db.flush()
    db.rollback()
    with pytest.raises(DatabaseError):
        db.execute(text("DELETE FROM status_history"))
    db.rollback()


def test_policy_version_content_immutable(db):
    pv = PolicyVersion(version="v1", content_yaml="a: 1", content_sha256="0" * 64, created_by="admin")
    db.add(pv)
    db.commit()
    pv.is_active = True  # 활성화 플래그 변경은 허용
    db.commit()
    with pytest.raises(DatabaseError):
        db.execute(text("UPDATE policy_versions SET content_yaml='a: 2'"))
    db.rollback()


def test_datetime_roundtrip_is_utc(db):
    kst = timezone(timedelta(hours=9))
    a = _asset(db)
    a.created_at = datetime(2026, 9, 28, 9, 0, tzinfo=kst)
    db.commit()
    db.expire_all()
    got = db.get(Asset, a.id).created_at
    assert got.tzinfo is not None
    assert got == datetime(2026, 9, 28, 0, 0, tzinfo=timezone.utc)


def test_naive_datetime_rejected(db):
    a = _asset(db)
    a.created_at = datetime(2026, 9, 28, 9, 0)
    with pytest.raises(StatementError):
        db.flush()
