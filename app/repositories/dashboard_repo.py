"""Dashboard/목록 조회 (ORM + 바인드 파라미터만 사용)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import and_, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.models import Asset, AssetProduct, AssetVulnerability, Vulnerability
from app.models.enums import AssessmentState, RemediationStatus, Zone
from app.services.vuln_status import CLOSED_STATUSES

PAGE_SIZE = 50
EPSS_PENDING_LABEL = "EPSS 대기"


@dataclass
class VulnFilter:
    q: str | None = None
    severities: list[str] = field(default_factory=list)   # 등급명 또는 'EPSS 대기'
    kev: bool = False
    zone: Zone | None = None
    overdue: bool = False
    owner: str | None = None
    status: RemediationStatus | None = None
    include_closed: bool = False
    include_unmanaged: bool = False
    revalidation: bool = False
    page: int = 1


def _open_cond():
    return AssetVulnerability.status.not_in(list(CLOSED_STATUSES))


def managed_names(rule_names: list[str]) -> list[str]:
    return list(rule_names)


def kpis(session: Session, rule_names: list[str], now: datetime) -> dict:
    base = and_(AssetVulnerability.needs_revalidation.is_(False), _open_cond())
    managed = or_(AssetVulnerability.severity.in_(rule_names),
                  AssetVulnerability.assessment_state == AssessmentState.EPSS_PENDING)
    total_assets = session.execute(select(func.count()).select_from(Asset)
                                   .where(Asset.is_active.is_(True))).scalar()
    vuln_assets = session.execute(select(func.count(distinct(AssetVulnerability.asset_id)))
                                  .join(Asset, Asset.id == AssetVulnerability.asset_id)
                                  .where(base, managed, Asset.is_active.is_(True))).scalar()
    by_sev = dict(session.execute(select(AssetVulnerability.severity, func.count())
                                  .where(base, AssetVulnerability.severity.in_(rule_names))
                                  .group_by(AssetVulnerability.severity)).all())
    pending = session.execute(select(func.count()).select_from(AssetVulnerability).where(
        base, AssetVulnerability.assessment_state == AssessmentState.EPSS_PENDING)).scalar()
    overdue = session.execute(select(func.count()).select_from(AssetVulnerability).where(
        base, AssetVulnerability.due_at.is_not(None), AssetVulnerability.due_at < now)).scalar()
    return {"total_assets": total_assets, "vulnerable_assets": vuln_assets,
            "by_severity": {n: by_sev.get(n, 0) for n in rule_names}, "epss_pending": pending,
            "overdue": overdue}


def list_vulns(session: Session, f: VulnFilter, rule_names: list[str], now: datetime,
               page_size: int = PAGE_SIZE, limit_all: bool = False):
    stmt = (select(AssetVulnerability, Asset, AssetProduct, Vulnerability)
            .join(Asset, Asset.id == AssetVulnerability.asset_id)
            .join(AssetProduct, AssetProduct.id == AssetVulnerability.asset_product_id)
            .join(Vulnerability, Vulnerability.cve_id == AssetVulnerability.cve_id)
            .where(Asset.is_active.is_(True)))
    conds = []
    if not f.include_closed:
        conds.append(_open_cond())
    if f.revalidation:
        conds.append(AssetVulnerability.needs_revalidation.is_(True))
    else:
        conds.append(AssetVulnerability.needs_revalidation.is_(False))
    sev_conds = []
    names = [s for s in f.severities if s in rule_names]
    if names:
        sev_conds.append(AssetVulnerability.severity.in_(names))
    if EPSS_PENDING_LABEL in f.severities:
        sev_conds.append(AssetVulnerability.assessment_state == AssessmentState.EPSS_PENDING)
    if sev_conds:
        conds.append(or_(*sev_conds))
    elif not f.include_unmanaged:
        conds.append(or_(AssetVulnerability.severity.in_(rule_names),
                         AssetVulnerability.assessment_state == AssessmentState.EPSS_PENDING))
    if f.kev:
        conds.append(Vulnerability.kev.is_(True))
    if f.zone:
        conds.append(Asset.zone == f.zone)
    if f.overdue:
        conds.append(and_(AssetVulnerability.due_at.is_not(None), AssetVulnerability.due_at < now,
                          _open_cond()))
    if f.owner:
        conds.append(AssetVulnerability.owner == f.owner)
    if f.status:
        conds.append(AssetVulnerability.status == f.status)
    if f.q:
        q = f.q
        conds.append(or_(
            AssetVulnerability.cve_id.contains(q.upper(), autoescape=True),
            Asset.ip.contains(q, autoescape=True),
            Asset.name.contains(q, autoescape=True),
            Asset.asset_code.contains(q, autoescape=True),
            AssetProduct.product_raw.contains(q, autoescape=True),
            AssetProduct.product_norm.contains(q.lower(), autoescape=True),
            AssetVulnerability.owner.contains(q, autoescape=True),
        ))
    stmt = stmt.where(*conds)
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    stmt = stmt.order_by(func.coalesce(AssetVulnerability.severity_rank, -1),
                         AssetVulnerability.due_at.is_(None), AssetVulnerability.due_at,
                         Vulnerability.cvss_score.desc(), Asset.asset_code, AssetVulnerability.cve_id)
    if not limit_all:
        stmt = stmt.offset((f.page - 1) * page_size).limit(page_size)
    return total, session.execute(stmt).all()


def owners(session: Session) -> list[str]:
    return [o for (o,) in session.execute(select(AssetVulnerability.owner)
                                          .where(AssetVulnerability.owner.is_not(None))
                                          .distinct().order_by(AssetVulnerability.owner)).all()]
