"""(VDI) 외부 Collector가 만든 Bundle 파일을 검증 후 Import.

사용: python -m scripts.import_bundle path\\to\\bundle_xxx.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.services.bundle import BundleError
from app.services.vulnerability_collector import CollectionBusy, import_bundle_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("bundle", type=Path)
    args = ap.parse_args()
    from app.config.logging import configure_logging
    from app.config.settings import get_settings as _gs

    _gs().ensure_dirs()
    configure_logging(_gs())
    try:
        out = import_bundle_file(args.bundle, actor="cli")
    except BundleError as e:
        print(f"Bundle 검증 실패: {e}", file=sys.stderr)
        return 2
    except CollectionBusy:
        print("이미 수집/Import가 실행 중입니다.", file=sys.stderr)
        return 1
    print(f"Import 종료: id={out.collection_id} status={out.status.value}")
    print(json.dumps(out.summary, ensure_ascii=False, indent=2, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
