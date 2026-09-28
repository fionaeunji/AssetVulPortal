"""자산관리대장(.xlsx) Import CLI (웹 업로드와 동일한 보안검증·처리 흐름 사용).

사용: python -m scripts.import_assets sample_data\\sample_assets.xlsx
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sqlalchemy import select

from app.config.logging import configure_logging
from app.config.settings import get_settings
from app.db import get_sessionmaker
from app.models import Asset, AssetProduct
from app.services.asset_importer import import_asset_upload


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file", type=Path)
    args = ap.parse_args()
    settings = get_settings()
    settings.ensure_dirs()
    configure_logging(settings)
    if not args.file.is_file():
        print("파일을 찾을 수 없습니다.", file=sys.stderr)
        return 2
    data = args.file.read_bytes()
    out = import_asset_upload(get_sessionmaker(), filename=args.file.name, data=data, actor="cli",
                              actor_role="admin", upload_dir=settings.upload_dir,
                              max_bytes=settings.upload_max_bytes)
    print(out.message)
    for e in out.errors:
        print(f"  [오류] {e.row}행 {e.column}: {e.message}")
    for w in out.warnings:
        print(f"  [경고] {w.row}행 {w.column}: {w.message}")
    if not out.ok:
        return 1
    s = out.summary
    print(f"  자산 {out.asset_count}개 (신규 {s.assets_created}, 변경 {s.assets_updated}, 비활성화 {s.assets_deactivated})")
    print(f"  제품 신규 {s.products_created}, 변경 {s.products_updated}, 비활성화 {s.products_deactivated}, "
          f"재검증 표시 {s.revalidation_flagged}")
    with get_sessionmaker()() as db:
        print("\n  Asset ID    자산명            구분    IP              제품 / 버전 / CPE")
        for a in db.execute(select(Asset).where(Asset.is_active.is_(True)).order_by(Asset.asset_code)).scalars():
            for p in db.execute(select(AssetProduct).where(AssetProduct.asset_id == a.id,
                                                           AssetProduct.is_active.is_(True))).scalars():
                cpe = p.cpe_normalized or ("CPE 오류" if p.cpe_error else "CPE 없음")
                print(f"  {a.asset_code:<11} {a.name:<17} {a.zone.value:<5} {a.ip or '':<15} "
                      f"{p.product_raw or p.product_norm} / {p.version_norm} / {cpe}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
