"""Phase 5: 정책 엔진(등급) / 조치기한 테스트. 정책 값은 config/policy.yaml 에서 읽는다."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from app.models.enums import AssessmentState, Zone
from app.services.policy_engine import add_duration, compute_due, decide_severity
from app.services.policy_loader import PolicyError, load_policy_file, parse_policy_text

ROOT = Path(__file__).resolve().parents[2]
POLICY, _, _ = load_policy_file(ROOT / "config" / "policy.yaml")
BASE = datetime(2026, 1, 31, 0, 0, tzinfo=timezone.utc)


# ---- 요구사항 필수 케이스 ----
@pytest.mark.parametrize("cvss,epss,expected", [
    (9.8, 0.40, "긴급"),
    (9.8, 0.20, "우선"),
    (9.8, 0.05, "주의"),
    (7.5, None, "주의"),
    (7.5, 0.90, "주의"),
    (6.9, 0.99, "관리대상 아님"),
])
def test_required_severity_cases(cvss, epss, expected):
    assert decide_severity(POLICY, cvss, epss).name == expected


@pytest.mark.parametrize("cvss,epss,expected", [
    (9.0, 0.30, "긴급"), (9.0, 0.2999, "우선"), (9.0, 0.10, "우선"), (9.0, 0.0999, "주의"),
    (8.99, 0.9, "주의"), (7.0, 0.0, "주의"), (6.99, 0.0, "관리대상 아님"), (10.0, 1.0, "긴급"),
])
def test_boundaries(cvss, epss, expected):
    assert decide_severity(POLICY, cvss, epss).name == expected


def test_priority_order_emergency_first():
    d = decide_severity(POLICY, 9.8, 0.5)   # 긴급/우선/주의 모두 만족
    assert d.name == "긴급" and d.rank == 0 and "Initial EPSS" in d.reason


def test_epss_missing_pending_for_high_cvss():
    d = decide_severity(POLICY, 9.8, None)
    assert d.state == AssessmentState.EPSS_PENDING and d.name is None


def test_epss_missing_irrelevant_for_mid_cvss():
    d = decide_severity(POLICY, 8.1, None)
    assert d.state == AssessmentState.ASSESSED and d.name == "주의"


def test_epss_missing_zero_behavior():
    text = (ROOT / "config" / "policy.yaml").read_text(encoding="utf-8").replace(
        "missing_behavior: pending", "missing_behavior: zero")
    p = parse_policy_text(text)
    assert decide_severity(p, 9.8, None).name == "주의"


def test_missing_cvss():
    d = decide_severity(POLICY, None, 0.9)
    assert d.name == "관리대상 아님" and "CVSS" in d.reason


# ---- 조치기한 ----
@pytest.mark.parametrize("cvss,epss,zone,delta", [
    (9.8, 0.4, Zone.PERIMETER, timedelta(hours=72)),
    (9.8, 0.4, Zone.INTERNAL, timedelta(days=45)),     # 1.5개월 = 45일 (fixed_days)
    (9.8, 0.2, Zone.PERIMETER, timedelta(days=14)),
    (9.8, 0.2, Zone.INTERNAL, timedelta(days=45)),
    (7.5, None, Zone.PERIMETER, timedelta(days=30)),   # 1개월 = 30일
    (7.5, None, Zone.INTERNAL, timedelta(days=90)),    # 3개월 = 90일
])
def test_deadlines(cvss, epss, zone, delta):
    d = decide_severity(POLICY, cvss, epss)
    due, how = compute_due(POLICY, d, zone, BASE)
    assert due - BASE == delta and how


def test_no_deadline_for_unmanaged():
    assert compute_due(POLICY, decide_severity(POLICY, 5.0, 0.1), Zone.INTERNAL, BASE) == (None, None)


def test_calendar_month_mode():
    text = (ROOT / "config" / "policy.yaml").read_text(encoding="utf-8").replace(
        "month_mode: fixed_days", "month_mode: calendar")
    p = parse_policy_text(text)
    from app.schemas.policy import Duration
    due, how = add_duration(p, BASE, Duration(months=1.5))     # 1/31 + 1개월 → 2/28, + 15일 → 3/15
    assert due == datetime(2026, 3, 15, tzinfo=timezone.utc) and "calendar" in how
    due3, _ = add_duration(p, BASE, Duration(months=3))
    assert due3 == datetime(2026, 4, 30, tzinfo=timezone.utc)


# ---- 정책 파일 검증 (하드코딩 금지 → 설정 변경만으로 동작) ----
def test_policy_change_without_code_change():
    text = (ROOT / "config" / "policy.yaml").read_text(encoding="utf-8").replace(
        "epss_initial_min: 0.30", "epss_initial_min: 0.50").replace('version: "2026.09-01"', 'version: "test-2"')
    p = parse_policy_text(text)
    assert decide_severity(p, 9.8, 0.40).name == "우선"


@pytest.mark.parametrize("bad", [
    "version: x\ncvss: {source_priority: ['9.9:Primary']}\nrules: []",
    "version: x\ncvss: {source_priority: ['3.1:Primary']}\nrules: [{key: a, name: A, cvss_min: 11, deadline: {perimeter: {days: 1}, internal: {days: 1}}}]",
    "version: x\ncvss: {source_priority: ['3.1:Primary']}\nrules: [{key: a, name: A, cvss_min: 9, epss_initial_min: 1.5, deadline: {perimeter: {days: 1}, internal: {days: 1}}}]",
    "version: x\ncvss: {source_priority: ['3.1:Primary']}\nrules: [{key: a, name: A, cvss_min: 9, deadline: {perimeter: {days: 1, hours: 2}, internal: {days: 1}}}]",
    "!!python/object/apply:os.system ['echo pwned']",
    "version: x\ncvss: {source_priority: ['3.1:Primary']}\nrules: [{key: a, name: A, cvss_min: 9, deadline: {perimeter: {days: 1}, internal: {days: 1}}}]\nunknown_field: 1",
])
def test_invalid_policy_rejected(bad):
    with pytest.raises(PolicyError):
        parse_policy_text(bad)
