"""취약점 현황 Excel Export CLI (웹 [Excel 다운로드]와 동일한 무해화 적용).

사용: python -m scripts.export_report --out report.xlsx [--all]
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app.config.settings import get_settings
from app.db import session_scope
from app.models.types import utcnow
from app.repositories import dashboard_repo as repo
from app.services import audit
from app.services.exporter import MAX_EXPORT_ROWS, build_workbook
from app.services.policy_loader import apply_policy_file, get_active_policy
from app.services.vuln_status import CLOSED_STATUSES


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--all", action="store_true", help="종결·관리대상 아님 포함")
    args = ap.parse_args()
    with session_scope() as s:
        if get_active_policy(s) is None:
            apply_policy_file(s, get_settings().policy_file, actor="system")
        pv, policy = get_active_policy(s)
        names = [r.name for r in policy.rules]
        now = utcnow()
        f = repo.VulnFilter(include_closed=args.all, include_unmanaged=args.all)
        total, rows = repo.list_vulns(s, f, names, now, limit_all=True)
        data = build_workbook(rows, now=now, exported_by="cli", policy_version=pv.version,
                              filter_desc="all" if args.all else "", kpi=repo.kpis(s, names, now),
                              closed_statuses={x.value for x in CLOSED_STATUSES})
        audit.record(s, actor="cli", action=audit.AuditAction.EXPORT, target_type="report",
                     after={"rows": min(total, MAX_EXPORT_ROWS), "file": args.out.name})
    args.out.write_bytes(data)
    print(f"Export 완료: {args.out} ({min(total, MAX_EXPORT_ROWS)}행)")


if __name__ == "__main__":
    main()
