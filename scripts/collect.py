"""취약점 수집 CLI.

[PoC / online] Portal DB 대상 수집 + Import:
    python -m scripts.collect
    python -m scripts.collect --product a:apache:http_server --product o:fortinet:fortios

[VDI 분리 운영 / 외부망 Collector] DB 없이 대상 파일로 수집 → Bundle 파일 생성:
    python -m scripts.collect --targets-file targets.json --out-dir .\\bundles
    (targets.json 은 내부 Portal 에서 `python -m scripts.export_targets` 로 생성)
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from app.config.settings import get_settings
from app.models.enums import CollectionTrigger

PRODUCT_KEY_RE = re.compile(r"^[aoh]:[a-z0-9._\-~\\/!]+:[a-z0-9._\-~\\/!]+$")


def _validate_key(k: str) -> str:
    k = k.strip().lower()
    if not PRODUCT_KEY_RE.fullmatch(k) or len(k) > 300:
        raise argparse.ArgumentTypeError(f"invalid product key: {k!r} (예: a:apache:http_server)")
    return k


def main() -> int:
    ap = argparse.ArgumentParser(description="NVD / EPSS / KEV 수집")
    ap.add_argument("--product", action="append", type=_validate_key, default=[],
                    help="추가 수집 대상 part:vendor:product")
    ap.add_argument("--targets-file", type=Path, help="(외부망 Collector) 대상 JSON 파일")
    ap.add_argument("--out-dir", type=Path, help="(외부망 Collector) Bundle 출력 디렉터리")
    args = ap.parse_args()
    from app.config.logging import configure_logging
    from app.config.settings import get_settings as _gs

    _gs().ensure_dirs()
    configure_logging(_gs())
    settings = get_settings()

    if args.targets_file:
        from app.services.bundle import write_bundle
        from app.services.collector import NvdTarget, collect
        from app.services.http_client import DestinationRecorder, build_client

        data = json.loads(args.targets_file.read_text(encoding="utf-8"))
        targets = [NvdTarget(_validate_key(t["product_key"]),
                             datetime.fromisoformat(t["last_mod_start"]) if t.get("last_mod_start") else None)
                   for t in data.get("targets", [])]
        targets += [NvdTarget(k, None) for k in args.product]
        known = set(data.get("known_cve_ids", []))
        rec = DestinationRecorder()
        with build_client(rec) as http:
            bundle = collect(
                targets, known, http=http,
                nvd_api_key=settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None,
                epss_csv_threshold=settings.epss_csv_threshold,
                hmac_key=settings.bundle_hmac_key.get_secret_value() if settings.bundle_hmac_key else None,
                collector_name="external-cli",
            )
        path = write_bundle(bundle, args.out_dir or settings.bundle_dir)
        print(f"Bundle 생성: {path}")
        for s in bundle.manifest.sources:
            print(f"  {s.source:5s} {s.status:8s} count={s.count} {s.error or ''}")
        print("호출 목적지:", json.dumps(rec.as_list(), ensure_ascii=False))
        return 0

    from app.services.vulnerability_collector import CollectionBusy, run_online_collection

    try:
        out = run_online_collection(CollectionTrigger.MANUAL, actor="cli",
                                    extra_product_keys=args.product)
    except CollectionBusy:
        print("이미 수집이 실행 중입니다.", file=sys.stderr)
        return 1
    print(f"수집 종료: id={out.collection_id} status={out.status.value}")
    print(json.dumps(out.summary, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
