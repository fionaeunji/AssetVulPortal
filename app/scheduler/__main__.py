"""Scheduler 프로세스 진입점 (Web 서버와 별도 실행).

사용:
  python -m app.scheduler              # 상주 실행 (매일 09:00, 14:00 Asia/Seoul)
  python -m app.scheduler --next       # 다음 실행 예정 시각 확인
  python -m app.scheduler --run-once   # 지금 1회 실행 (스케줄 경로 점검용)
"""
from __future__ import annotations

import argparse
import logging
import sys

from app.config.logging import configure_logging
from app.config.settings import get_settings
from app.scheduler.jobs import TIMEZONE, build_scheduler, next_fire_times, scheduled_collection

logger = logging.getLogger("app.scheduler")


def main() -> int:
    ap = argparse.ArgumentParser(description="취약점 수집 Scheduler")
    ap.add_argument("--next", action="store_true", help="다음 실행 예정 시각 출력")
    ap.add_argument("--run-once", action="store_true", help="즉시 1회 실행 후 종료")
    args = ap.parse_args()
    settings = get_settings()
    settings.ensure_dirs()
    configure_logging(settings)

    if args.next:
        for t in next_fire_times(4):
            print(t.strftime(f"%Y-%m-%d %H:%M ({TIMEZONE})"))
        return 0
    if args.run_once:
        r = scheduled_collection(settings)
        print(f"mode={r.mode} status={r.status} {r.detail}")
        return 0 if r.status not in ("failed",) else 1

    sched = build_scheduler(settings)
    nxt = next_fire_times(1)[0]
    logger.info("scheduler started (mode=%s, next=%s)", settings.collector_mode.value, nxt.isoformat())
    print(f"Scheduler 시작 — 모드: {settings.collector_mode.value}, 다음 실행: "
          f"{nxt.strftime('%Y-%m-%d %H:%M')} ({TIMEZONE}). 종료: Ctrl+C")
    try:
        sched.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("scheduler stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
