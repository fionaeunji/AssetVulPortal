"""자산-취약점 매핑 및 정책 판정 실행 (수집·자산 업로드 후 자동 실행되며, 수동 재실행용).

사용: python -m scripts.run_matching [--limit 50]
"""
from __future__ import annotations

import argparse
import sys
from zoneinfo import ZoneInfo

from sqlalchemy import func, select

from app.config.logging import configure_logging
from app.config.settings import get_settings
from app.db import session_scope
from app.models import Asset, AssetProduct, AssetVulnerability, MappingCandidate, Vulnerability
from app.models.enums import CandidateStatus
from app.services.mapping_service import run_mapping_with_active_policy


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--limit", type=int, default=40, help="출력할 취약 매핑 수")
    args = ap.parse_args()
    settings = get_settings()
    settings.ensure_dirs()
    configure_logging(settings)
    tz = ZoneInfo(settings.display_timezone)
    with session_scope() as s:
        sm = run_mapping_with_active_policy(s, actor="cli", policy_file=settings.policy_file)
    print(f"매핑 완료: 자산 {sm.assets}개, 신규 취약 매핑 {sm.vulnerable_new}건, 유효 매핑 {sm.vulnerable_total}건, "
          f"검토필요(L3) 신규 {sm.review_new}건, 후보(L2) 신규 {sm.candidates_new}건, "
          f"재검증 표시 {sm.revalidation_flagged}건, 자동 종료된 검토 후보 {sm.review_closed}건, "
          f"판정 Snapshot {sm.assessments_written}건")
    print("등급별:", dict(sm.by_severity))
    with session_scope() as s:
        q = (select(AssetVulnerability, Asset, AssetProduct, Vulnerability)
             .join(Asset, Asset.id == AssetVulnerability.asset_id)
             .join(AssetProduct, AssetProduct.id == AssetVulnerability.asset_product_id)
             .join(Vulnerability, Vulnerability.cve_id == AssetVulnerability.cve_id)
             .where(AssetVulnerability.needs_revalidation.is_(False))
             .order_by(func.coalesce(AssetVulnerability.severity_rank, -1), AssetVulnerability.due_at,
                       Asset.asset_code)
             .limit(args.limit))
        print(f"\n{'등급':<6}{'CVE':<17}{'자산':<11}{'구분':<5}{'CVSS':>5} {'EPSS(I)':>8}{'KEV':>4}  "
              f"{'조치기한(KST)':<17}{'매칭':<17}제품")
        for av, a, p, v in s.execute(q):
            due = av.due_at.astimezone(tz).strftime("%Y-%m-%d %H:%M") if av.due_at else "-"
            sev = av.severity or "EPSS대기"
            print(f"{sev:<6}{v.cve_id:<17}{a.asset_code:<11}{a.zone.value:<5}{v.cvss_score or 0:>5.1f} "
                  f"{(v.epss_initial if v.epss_initial is not None else float('nan')):>8.4f}{'Y' if v.kev else '':>4}  "
                  f"{due:<17}{av.match_type.value:<17}{p.product_raw} {p.version_norm}")
        pend = s.execute(select(MappingCandidate).where(MappingCandidate.status == CandidateStatus.PENDING)
                         .order_by(MappingCandidate.level, MappingCandidate.confidence.desc())
                         .limit(15)).scalars().all()
        if pend:
            print("\n[매핑 검토 필요]")
            for c in pend:
                p = s.get(AssetProduct, c.asset_product_id)
                a = s.get(Asset, p.asset_id)
                conf = f"{c.confidence}%" if c.confidence is not None else "산정불가"
                print(f"  #{c.id} L{c.level} {a.asset_code} {p.product_raw} {p.version_raw} → {c.proposed_cpe}"
                      f" {c.cve_id or ''} (Confidence {conf})")
                print(f"      근거: {c.reason[:150]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
