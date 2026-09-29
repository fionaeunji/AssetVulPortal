"""(VDI) 내부 Portal → 외부 Collector 로 전달할 수집 대상 파일 생성. 자산 IP/담당자 등은 포함하지 않는다.

사용: python -m scripts.export_targets --out targets.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from sqlalchemy import select

from app.db import session_scope
from app.models import Vulnerability
from app.services.vulnerability_collector import build_targets


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()
    with session_scope() as s:
        targets = build_targets(s)
        known = sorted(s.execute(select(Vulnerability.cve_id)).scalars())
    data = {
        "targets": [{"product_key": t.product_key,
                     "last_mod_start": t.last_mod_start.isoformat() if t.last_mod_start else None}
                    for t in targets],
        "known_cve_ids": known,
    }
    args.out.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"대상 {len(targets)}개 제품, 보유 CVE {len(known)}건 → {args.out}")


if __name__ == "__main__":
    main()
