"""매핑 후보 승인/거부 (웹 화면은 Phase 6).

사용: python -m scripts.review_mapping approve 12 --comment "확인함"
      python -m scripts.review_mapping reject 13
"""
from __future__ import annotations

import argparse
import sys

from app.config.settings import get_settings
from app.db import session_scope
from app.services.mapping_service import MappingError, decide_candidate, run_mapping_with_active_policy


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["approve", "reject"])
    ap.add_argument("candidate_id", type=int)
    ap.add_argument("--comment", default=None)
    args = ap.parse_args()
    try:
        with session_scope() as s:
            c = decide_candidate(s, args.candidate_id, approve=args.action == "approve", actor="cli",
                                 actor_role="operator", reason=args.comment)
            print(f"후보 #{c.id} → {c.status.value}")
        with session_scope() as s:
            sm = run_mapping_with_active_policy(s, actor="cli", policy_file=get_settings().policy_file)
            print(f"재매핑: 신규 취약 매핑 {sm.vulnerable_new}건")
    except MappingError as e:
        print(str(e), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
