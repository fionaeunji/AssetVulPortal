"""정책 엔진: 등급 판정 + 조치기한 계산. 정책 값은 전부 Policy(설정파일/DB)에서 온다."""
from __future__ import annotations

import calendar
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.models.enums import AssessmentState, Zone
from app.schemas.bundle import CvssMetric
from app.schemas.policy import Duration, EpssMissingBehavior, MonthMode, Policy, SeverityRule
from app.services.normalizer import select_cvss


@dataclass(frozen=True)
class SeverityDecision:
    state: AssessmentState
    rule: SeverityRule | None
    name: str | None      # 등급명 (EPSS 대기 시 None)
    rank: int | None      # 규칙 순서 (0 = 최우선), 관리대상 아님 = len(rules)
    reason: str


def _fmt(x: float | None) -> str:
    return "없음" if x is None else f"{x:g}"


def decide_severity(policy: Policy, cvss: float | None, epss_initial: float | None) -> SeverityDecision:
    if cvss is None:
        return SeverityDecision(AssessmentState.ASSESSED, None, policy.default_name, len(policy.rules),
                                "CVSS 점수 미제공(NVD 분석 대기 등) — 정책 조건 평가 불가")
    epss = epss_initial
    if epss is None:
        needs_epss = any(r.epss_initial_min is not None and cvss >= r.cvss_min for r in policy.rules)
        if needs_epss and policy.epss.missing_behavior == EpssMissingBehavior.PENDING:
            return SeverityDecision(AssessmentState.EPSS_PENDING, None, None, None,
                                    f"CVSS {_fmt(cvss)} — EPSS 미발행으로 판정보류 (최초 EPSS 관측 시 재판정)")
        if policy.epss.missing_behavior == EpssMissingBehavior.ZERO:
            epss = 0.0
    for idx, r in enumerate(policy.rules):
        if cvss < r.cvss_min:
            continue
        if r.epss_initial_min is not None and (epss is None or epss < r.epss_initial_min):
            continue
        cond = f"CVSS {_fmt(cvss)} ≥ {r.cvss_min:g}"
        if r.epss_initial_min is not None:
            cond += f" AND Initial EPSS {_fmt(epss)} ≥ {r.epss_initial_min:g}"
        return SeverityDecision(AssessmentState.ASSESSED, r, r.name, idx, f"{r.name}: {cond}")
    return SeverityDecision(AssessmentState.ASSESSED, None, policy.default_name, len(policy.rules),
                            f"{policy.default_name}: CVSS {_fmt(cvss)}, Initial EPSS {_fmt(epss_initial)} — 어떤 규칙에도 해당 안 됨")


def _add_months_calendar(base: datetime, months: int) -> datetime:
    m = base.month - 1 + months
    y, m = base.year + m // 12, m % 12 + 1
    d = min(base.day, calendar.monthrange(y, m)[1])
    return base.replace(year=y, month=m, day=d)


def add_duration(policy: Policy, base: datetime, d: Duration) -> tuple[datetime, str]:
    if d.hours is not None:
        return base + timedelta(hours=d.hours), f"{d.hours:g}시간"
    if d.days is not None:
        return base + timedelta(days=d.days), f"{d.days:g}일"
    months = d.months
    dpm = policy.deadline.days_per_month
    if policy.deadline.month_mode == MonthMode.FIXED_DAYS:
        days = months * dpm
        return base + timedelta(days=days), f"{months:g}개월 = {days:g}일 (fixed_days, 1개월={dpm}일)"
    whole = int(months)
    frac_days = (months - whole) * dpm
    due = _add_months_calendar(base, whole) + timedelta(days=frac_days)
    return due, f"{months:g}개월 = 달력 {whole}개월 + {frac_days:g}일 (calendar, 소수부 1개월={dpm}일)"


def compute_due(policy: Policy, decision: SeverityDecision, zone: Zone,
                base: datetime) -> tuple[datetime | None, str | None]:
    if decision.rule is None:
        return None, None
    dl = decision.rule.deadline.perimeter if zone == Zone.PERIMETER else decision.rule.deadline.internal
    due, how = add_duration(policy, base, dl)
    return due, f"{zone.value} {decision.rule.name}: {how}"


def choose_cvss(policy: Policy, metrics: list[dict] | None, fallback_score: float | None,
                fallback_version: str | None, fallback_source: str | None) -> tuple[float | None, str | None, str | None]:
    """정책의 source_priority 로 판정용 CVSS 선택 (정책 변경 시에도 원본 metrics 에서 재선택)."""
    if metrics:
        parsed = [CvssMetric(**m) for m in metrics]
        m = select_cvss(parsed, list(policy.cvss.source_priority))
        if m:
            return m.score, m.version, f"{m.source} ({m.type})"
        return None, None, None
    return fallback_score, fallback_version, fallback_source
