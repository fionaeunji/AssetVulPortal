"""실측 외부 통신 목록 생성 — collection_history.endpoints_called (실제 호출 기록) 집계.

사용: python -m scripts.report_endpoints [--out docs\\external_communications_measured.md]
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path

from sqlalchemy import select

from app.config.endpoints import ENDPOINTS
from app.db import session_scope
from app.models import CollectionHistory

PURPOSE = {
    "services.nvd.nist.gov": ("nvd_client", "CVE / CVSS / CPE 수집 (NVD CVE API 2.0)", "Required"),
    "api.first.org": ("epss_client", "EPSS 조회 (API, 100건 단위)", "Required (CSV와 택1)"),
    "epss.empiricalsecurity.com": ("epss_client", "EPSS Bulk CSV (1일 1회 갱신 파일)", "Optional (API와 택1)"),
    "www.cisa.gov": ("kev_client", "CISA KEV 카탈로그 (화면 표시용)", "Optional"),
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    agg: dict[tuple, dict] = defaultdict(lambda: {"requests": 0, "runs": set(), "first": None, "last": None})
    with session_scope() as s:
        runs = s.execute(select(CollectionHistory).order_by(CollectionHistory.id)).scalars().all()
        for h in runs:
            for e in h.endpoints_called or []:
                key = (e["host"], e["port"], e["scheme"], e["path"])
                a = agg[key]
                a["requests"] += e["requests"]
                a["runs"].add(h.id)
                a["first"] = a["first"] or h.started_at
                a["last"] = h.started_at
    lines = ["# 외부 통신 목록 (실측)", "",
             f"- 근거: `collection_history.endpoints_called` (실행 {len(runs)}회 집계)",
             "- 방향: 모두 Outbound (Portal/Collector → 인터넷), 인바운드 없음", "",
             "| Source Component | Destination FQDN | Port | Protocol | Path | Purpose | Direction | 호출 수(누적) | 수집 실행 수 | 최초 / 최근 (UTC) | Required / Optional |",
             "|---|---|---|---|---|---|---|---|---|---|---|"]
    for (host, port, scheme, path), a in sorted(agg.items()):
        comp, purpose, req = PURPOSE.get(host, ("(미분류)", "(Allowlist 외 — 확인 필요)", "?"))
        lines.append(f"| {comp} | {host} | {port} | {scheme.upper()} | {path} | {purpose} | Outbound | "
                     f"{a['requests']} | {len(a['runs'])} | {a['first']:%Y-%m-%d %H:%M} / {a['last']:%Y-%m-%d %H:%M} | {req} |")
    if not agg:
        lines.append("| (수집 이력 없음 — `python -m scripts.collect` 실행 후 다시 생성) | | | | | | | | | | |")
    lines += ["", "설정된 Allowlist (`app/config/endpoints.py`):", ""]
    lines += [f"- `{k}`: {v}" for k, v in ENDPOINTS.items()]
    text = "\n".join(lines) + "\n"
    if args.out:
        args.out.write_text(text, encoding="utf-8")
        print(f"작성: {args.out}")
    else:
        print(text)


if __name__ == "__main__":
    main()
