"""매핑·판정 실행 및 매핑 승인/거부 (DB 반영).

run_mapping():
  1) 승인된 제품 매핑을 CPE 없는 제품에 재사용 적용
  2) Level 1 평가 → VULNERABLE: asset_vulnerabilities upsert + 정책 판정(Snapshot)
                   → REVIEW    : mapping_candidates(level 3)
  3) CPE 없는 제품 → Level 2 후보(mapping_candidates level 2)
  4) 더 이상 매칭되지 않는 기존 매핑 → 삭제하지 않고 needs_revalidation 표시
  5) EPSS 대기 건 재판정, 정책 버전 변경 시 재판정
"""
from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetProduct,
    AssetProductMapping,
    AssetVulnerability,
    MappingCandidate,
    PolicyVersion,
    Vulnerability,
    VulnerabilityAssessment,
    VulnerabilityProduct,
)
from app.models.enums import (
    AssessmentState,
    CandidateStatus,
    MappingDecision,
    MatchType,
    RemediationStatus,
)
from app.models.types import utcnow
from app.schemas.policy import Policy
from app.services import audit
from app.services.cpe import CPE, parse_cpe, try_parse_cpe
from app.services.matching_engine import (
    AssetCpe,
    Candidate,
    MatchRow,
    Verdict,
    evaluate_cve,
    generate_candidates,
)
from app.services.policy_engine import choose_cvss, compute_due, decide_severity
from app.services.product_aliases import AliasBook, apply_version_rules, get_aliases

logger = logging.getLogger(__name__)


class MappingError(ValueError):
    pass


@dataclass
class MappingSummary:
    assets: int = 0
    vulnerable_new: int = 0
    vulnerable_total: int = 0
    review_new: int = 0
    candidates_new: int = 0
    revalidation_flagged: int = 0
    assessments_written: int = 0
    mappings_applied: int = 0
    by_severity: dict = field(default_factory=lambda: defaultdict(int))


def _row(vp: VulnerabilityProduct) -> MatchRow:
    return MatchRow(vp.config_index, vp.config_operator, vp.config_negate, vp.node_index, vp.node_operator,
                    vp.node_negate, vp.match_index, vp.vulnerable, vp.criteria,
                    vp.version_start_including, vp.version_start_excluding,
                    vp.version_end_including, vp.version_end_excluding)


def build_cpe_for_mapping(m: AssetProductMapping | tuple[str, str, str], version: str | None,
                          aliases: AliasBook) -> tuple[str | None, str | None]:
    """승인된 매핑 + 자산 버전(벤더 표기 변환 규칙 적용)으로 자산 CPE 생성."""
    part, vendor, product = (m.cpe_part, m.cpe_vendor, m.cpe_product) if isinstance(m, AssetProductMapping) else m
    entry = aliases.for_cpe(part, vendor, product)
    ver, upd, note = apply_version_rules(entry, version)
    cand = Candidate(part, vendor, product, ver, upd, 0, {}, [])
    cpe, _ = try_parse_cpe(cand.proposed_cpe)
    return (cpe.to_string() if cpe else None), note


# ---------------------------------------------------------------------------
# 판정 (Phase 5)
# ---------------------------------------------------------------------------
def assess(session: Session, av: AssetVulnerability, vuln: Vulnerability, asset: Asset,
           pv: PolicyVersion, policy: Policy, now: datetime) -> bool:
    """정책 적용. 결과가 직전 Snapshot과 다를 때만 새 Snapshot을 추가. 변경 여부 반환."""
    cvss, cvss_ver, cvss_src = choose_cvss(policy, vuln.cvss_metrics, vuln.cvss_score,
                                           vuln.cvss_version, vuln.cvss_source)
    decision = decide_severity(policy, cvss, vuln.epss_initial)
    due, how = compute_due(policy, decision, asset.zone, av.detected_at)
    changed = (av.assessment_state, av.severity, av.due_at, av.policy_version_id) != \
              (decision.state, decision.name, due, pv.id)
    av.assessment_state = decision.state
    av.severity = decision.name
    av.severity_rank = decision.rank
    av.due_at = due
    av.policy_version_id = pv.id
    if not av.owner_override:
        av.owner = asset.owner_name
    if av.initial_due_at is None and due is not None:
        av.initial_due_at = due      # 최초 조치기한 (이후 불변, DB Trigger)
    if changed:
        session.add(VulnerabilityAssessment(
            asset_vulnerability_id=av.id, policy_version_id=pv.id, assessment_state=decision.state,
            severity=decision.name, zone=asset.zone, cvss_score_used=cvss, cvss_version_used=cvss_ver,
            cvss_source_used=cvss_src, epss_initial_used=vuln.epss_initial,
            epss_current_at_assessment=vuln.epss_current, base_time=av.detected_at,
            due_at_computed=due, calc_method=how, reason=decision.reason[:512], assessed_at=now))
    return changed


# ---------------------------------------------------------------------------
# 매핑 실행
# ---------------------------------------------------------------------------
def _apply_approved_mappings(session: Session, aliases: AliasBook, summary: MappingSummary) -> None:
    approved = {(m.vendor_norm, m.product_norm): m for m in session.execute(
        select(AssetProductMapping).where(AssetProductMapping.decision == MappingDecision.APPROVED)).scalars()}
    if not approved:
        return
    for p in session.execute(select(AssetProduct).where(
            AssetProduct.is_active.is_(True),
            or_(AssetProduct.cpe_normalized.is_(None), AssetProduct.cpe_source == "mapping"))).scalars():
        m = approved.get((p.vendor_norm, p.product_norm))
        if m is None:
            continue
        cpe_str, _ = build_cpe_for_mapping(m, p.version_norm, aliases)
        if cpe_str and p.cpe_normalized != cpe_str:
            p.cpe_normalized = cpe_str
            p.cpe_source = "mapping"
            summary.mappings_applied += 1


def run_mapping(session: Session, *, pv: PolicyVersion, policy: Policy, actor: str = "system",
                aliases: AliasBook | None = None, now: datetime | None = None) -> MappingSummary:
    now = now or utcnow()
    aliases = aliases or get_aliases()
    summary = MappingSummary()
    _apply_approved_mappings(session, aliases, summary)
    session.flush()

    rejected_pairs = {(m.vendor_norm, m.product_norm, m.cpe_part, m.cpe_vendor, m.cpe_product)
                      for m in session.execute(select(AssetProductMapping).where(
                          AssetProductMapping.decision == MappingDecision.REJECTED)).scalars()}
    existing_cands = {(c.asset_product_id, c.cve_id, c.proposed_cpe): c for c in
                      session.execute(select(MappingCandidate)).scalars()}
    dictionary = {tuple(r) for r in session.execute(
        select(VulnerabilityProduct.part, VulnerabilityProduct.vendor, VulnerabilityProduct.product)
        .where(VulnerabilityProduct.vulnerable.is_(True)).distinct())}

    approved_by_pair = {(m.vendor_norm, m.product_norm): m for m in session.execute(
        select(AssetProductMapping).where(AssetProductMapping.decision == MappingDecision.APPROVED)).scalars()}
    assets = session.execute(select(Asset).where(Asset.is_active.is_(True))).scalars().all()
    summary.assets = len(assets)
    for asset in assets:
        products = [p for p in asset.products if p.is_active]
        asset_cpes: list[AssetCpe] = []
        for p in products:
            cpe, _ = try_parse_cpe(p.cpe_normalized)
            if cpe:
                asset_cpes.append(AssetCpe(p.id, cpe, p.cpe_source or "excel"))
        by_pid = {p.id: p for p in products}

        # ---- Level 1 ----
        results = {}
        if asset_cpes:
            conds = [and_(VulnerabilityProduct.part == c.cpe.part, VulnerabilityProduct.vendor == c.key[1],
                          VulnerabilityProduct.product == c.key[2]) for c in asset_cpes]
            cve_ids = set(session.execute(select(VulnerabilityProduct.cve_id).where(or_(*conds))
                                          .distinct()).scalars())
            rows_by_cve: dict[str, list[MatchRow]] = defaultdict(list)
            ids = sorted(cve_ids)
            for i in range(0, len(ids), 500):
                for vp in session.execute(select(VulnerabilityProduct).where(
                        VulnerabilityProduct.cve_id.in_(ids[i:i + 500]))).scalars():
                    rows_by_cve[vp.cve_id].append(_row(vp))
            for cve_id, rows in rows_by_cve.items():
                results[cve_id] = evaluate_cve(cve_id, rows, asset_cpes)

        current = {(av.asset_product_id, av.cve_id): av for av in session.execute(
            select(AssetVulnerability).where(AssetVulnerability.asset_id == asset.id)).scalars()}
        still_vulnerable = set()
        for cve_id, res in results.items():
            if res.verdict == Verdict.VULNERABLE:
                p = by_pid[res.product_id]
                key = (p.id, cve_id)
                still_vulnerable.add(key)
                mt = MatchType.APPROVED_MAPPING if p.cpe_source == "mapping" else res.match_type
                evidence = {**res.evidence, "level": 1, "asset_cpe": p.cpe_normalized,
                            "cpe_source": p.cpe_source}
                approver = None
                if p.cpe_source == "mapping":
                    m = approved_by_pair.get((p.vendor_norm, p.product_norm))
                    approver = m.decided_by if m else None
                    evidence["mapping_approved_by"] = approver
                    evidence["mapping_approved_at"] = m.decided_at.isoformat() if m else None
                av = current.get(key)
                if av is None:
                    av = AssetVulnerability(
                        asset_id=asset.id, asset_product_id=p.id, cve_id=cve_id,
                        assessment_state=AssessmentState.ASSESSED, detected_at=now,
                        owner=asset.owner_name, status=RemediationStatus.NEW, match_type=mt,
                        match_confidence=None, match_evidence=evidence, mapping_approved_by=approver)
                    session.add(av)
                    session.flush()
                    current[key] = av
                    summary.vulnerable_new += 1
                else:
                    av.match_type, av.match_evidence, av.needs_revalidation = mt, evidence, False
                    av.mapping_approved_by = approver
            elif res.verdict == Verdict.REVIEW and res.product_id:
                p = by_pid[res.product_id]
                key = (p.id, cve_id, p.cpe_normalized)
                if (p.id, cve_id) in current:
                    if not current[(p.id, cve_id)].match_evidence.get("manual"):
                        current[(p.id, cve_id)].needs_revalidation = True
                    continue
                reason = "; ".join(res.review_reasons)[:512]
                prev = existing_cands.get(key)
                if prev is None:
                    prev = MappingCandidate(
                        asset_product_id=p.id, cve_id=cve_id, proposed_cpe=p.cpe_normalized, level=3,
                        confidence=None, breakdown={"note": "결정적 규칙으로 판정 불가 — 점수 산정 안 함"},
                        reason=reason, created_at=now)
                    session.add(prev)
                    existing_cands[key] = prev
                    summary.review_new += 1
                elif prev.status == CandidateStatus.PENDING and prev.reason != reason:
                    prev.reason = reason

        # 더 이상 매칭되지 않는 기존 매핑 (수동 승인 건 제외)
        for key, av in current.items():
            if key not in still_vulnerable and not (av.match_evidence or {}).get("manual") \
                    and not av.needs_revalidation:
                av.needs_revalidation = True
                summary.revalidation_flagged += 1

        # ---- Level 2 ----
        for p in products:
            if p.cpe_normalized:
                continue
            rows_by_product: dict[tuple[str, str, str], list[MatchRow]] = {}
            cands = generate_candidates(p.vendor_norm, p.product_norm, p.version_norm, aliases,
                                        dictionary, rows_by_product)
            # 버전 판단 가능 여부 점수를 위해 후보 제품의 수집 행을 적재 후 재계산
            if cands:
                for c in cands:
                    vps = session.execute(select(VulnerabilityProduct).where(
                        VulnerabilityProduct.part == c.part, VulnerabilityProduct.vendor == c.vendor,
                        VulnerabilityProduct.product == c.product,
                        VulnerabilityProduct.vulnerable.is_(True)).limit(2000)).scalars()
                    rows_by_product[(c.part, c.vendor, c.product)] = [_row(v) for v in vps]
                cands = generate_candidates(p.vendor_norm, p.product_norm, p.version_norm, aliases,
                                            dictionary, rows_by_product)
            for c in cands:
                if (p.vendor_norm, p.product_norm, c.part, c.vendor, c.product) in rejected_pairs:
                    continue
                key = (p.id, None, c.proposed_cpe)
                breakdown = {"rules": c.breakdown, "notes": c.notes}
                prev = existing_cands.get(key)
                if prev is not None:
                    # 대기 중 후보는 최신 수집 데이터 기준으로 점수 갱신 (처리된 후보는 그대로 보존)
                    if prev.status == CandidateStatus.PENDING and \
                            (prev.confidence, prev.breakdown) != (c.score, breakdown):
                        prev.confidence, prev.breakdown = c.score, breakdown
                    continue
                cand = MappingCandidate(
                    asset_product_id=p.id, cve_id=None, proposed_cpe=c.proposed_cpe, level=2,
                    confidence=c.score, breakdown=breakdown,
                    reason=(f"CPE 미기재 제품 '{p.vendor_raw} {p.product_raw} {p.version_raw}' → "
                            f"{c.part}:{c.vendor}:{c.product} 후보")[:512], created_at=now)
                session.add(cand)
                existing_cands[key] = cand
                summary.candidates_new += 1
    session.flush()

    # ---- 판정 (신규/EPSS 대기/정책 변경/재수집 반영) ----
    avs = session.execute(select(AssetVulnerability)).scalars().all()
    for av in avs:
        vuln = session.get(Vulnerability, av.cve_id)
        asset = session.get(Asset, av.asset_id)
        if assess(session, av, vuln, asset, pv, policy, now):
            summary.assessments_written += 1
        if not av.needs_revalidation:
            summary.vulnerable_total += 1
            summary.by_severity[av.severity or "EPSS 대기"] += 1
    audit.record(session, actor=actor, action=audit.AuditAction.MAPPING_RUN, target_type="mapping",
                 after={"policy_version": pv.version, "vulnerable_new": summary.vulnerable_new,
                        "review_new": summary.review_new, "candidates_new": summary.candidates_new,
                        "revalidation_flagged": summary.revalidation_flagged,
                        "assessments_written": summary.assessments_written})
    session.flush()
    return summary


# ---------------------------------------------------------------------------
# 매핑 승인 / 거부
# ---------------------------------------------------------------------------
def decide_candidate(session: Session, candidate_id: int, *, approve: bool, actor: str,
                     actor_role: str | None, reason: str | None = None,
                     client_ip: str | None = None) -> MappingCandidate:
    c = session.get(MappingCandidate, candidate_id)
    if c is None:
        raise MappingError("후보를 찾을 수 없습니다.")
    if c.status != CandidateStatus.PENDING:
        raise MappingError("이미 처리된 후보입니다.")
    p = session.get(AssetProduct, c.asset_product_id)
    now = utcnow()
    cpe: CPE = parse_cpe(c.proposed_cpe)
    c.status = CandidateStatus.APPROVED if approve else CandidateStatus.REJECTED
    c.decided_by, c.decided_at = actor, now
    reason = (reason or "")[:512] or None

    if c.level == 2:
        pair = dict(vendor_norm=p.vendor_norm, product_norm=p.product_norm, cpe_part=cpe.part,
                    cpe_vendor=cpe.vendor, cpe_product=cpe.product)
        m = session.execute(select(AssetProductMapping).filter_by(**pair)).scalar_one_or_none()
        decision = MappingDecision.APPROVED if approve else MappingDecision.REJECTED
        if m is None:
            m = AssetProductMapping(**pair, decision=decision, decided_by=actor, decided_at=now, reason=reason)
            session.add(m)
        else:
            m.decision, m.decided_by, m.decided_at, m.reason = decision, actor, now, reason
        if approve:
            # 같은 제품의 다른 대기 후보는 대체됨
            for other in session.execute(select(MappingCandidate).where(
                    MappingCandidate.asset_product_id == p.id, MappingCandidate.level == 2,
                    MappingCandidate.status == CandidateStatus.PENDING,
                    MappingCandidate.id != c.id)).scalars():
                other.status, other.decided_by, other.decided_at = CandidateStatus.REJECTED, actor, now
    elif approve:   # level 3: 해당 CVE 취약 확정 (사람 판단)
        asset = session.get(Asset, p.asset_id)
        av = session.execute(select(AssetVulnerability).where(
            AssetVulnerability.asset_product_id == p.id,
            AssetVulnerability.cve_id == c.cve_id)).scalar_one_or_none()
        evidence = {"level": 3, "manual": True, "approved_by": actor, "review_reason": c.reason,
                    "asset_cpe": p.cpe_normalized, "comment": reason}
        if av is None:
            av = AssetVulnerability(asset_id=asset.id, asset_product_id=p.id, cve_id=c.cve_id,
                                    assessment_state=AssessmentState.ASSESSED, detected_at=now,
                                    owner=asset.owner_name, status=RemediationStatus.NEW,
                                    match_type=MatchType.APPROVED_MAPPING, match_evidence=evidence,
                                    mapping_approved_by=actor)
            session.add(av)
        else:
            av.match_type, av.match_evidence, av.mapping_approved_by = MatchType.APPROVED_MAPPING, evidence, actor
            av.needs_revalidation = False
    session.flush()
    audit.record(session, actor=actor, actor_role=actor_role,
                 action=audit.AuditAction.MAPPING_APPROVE if approve else audit.AuditAction.MAPPING_REJECT,
                 target_type="mapping_candidate", target_id=c.id, client_ip=client_ip,
                 after={"level": c.level, "asset_product_id": p.id, "cve_id": c.cve_id,
                        "proposed_cpe": c.proposed_cpe, "confidence": c.confidence, "comment": reason})
    return c


def run_mapping_with_active_policy(session: Session, *, actor: str, policy_file) -> MappingSummary:
    """활성 정책으로 매핑·판정 실행 (활성 정책이 없으면 정책 파일을 등록)."""
    from app.services.policy_loader import apply_policy_file, get_active_policy
    active = get_active_policy(session)
    if active is None:
        apply_policy_file(session, policy_file, actor="system")
        active = get_active_policy(session)
    pv, policy = active
    return run_mapping(session, pv=pv, policy=policy, actor=actor)
