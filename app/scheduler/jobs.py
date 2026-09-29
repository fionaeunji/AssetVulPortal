"""스케줄 작업 정의 (Web 애플리케이션과 분리된 프로세스에서 실행).

online  모드: NVD/EPSS/KEV 수집 → Bundle → Import → 매핑·판정
offline 모드: 외부 통신 없이 DATA_DIR/bundles/inbox 의 Bundle 파일을 검증 후 Import
              (성공 → processed/, 실패 → failed/ 로 이동, 원본 삭제 안 함)
중복 실행은 수집 서비스의 DB Lease Lock 으로 방지된다 (Web 수동 실행과도 상호 배제).
"""
from __future__ import annotations

import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger

from app.config.settings import CollectorMode, Settings
from app.models.enums import CollectionTrigger

logger = logging.getLogger(__name__)

SCHEDULE_HOURS = "9,14"          # 09:00, 14:00
SCHEDULE_MINUTE = 0
TIMEZONE = "Asia/Seoul"
SCHEDULER_ACTOR = "scheduler"


def make_trigger() -> CronTrigger:
    return CronTrigger(hour=SCHEDULE_HOURS, minute=SCHEDULE_MINUTE, timezone=ZoneInfo(TIMEZONE))


def next_fire_times(n: int = 4, now: datetime | None = None) -> list[datetime]:
    trig = make_trigger()
    tz = ZoneInfo(TIMEZONE)
    cur = now.astimezone(tz) if now else datetime.now(tz)
    out, prev = [], None
    for _ in range(n):
        nxt = trig.get_next_fire_time(prev, cur)
        out.append(nxt)
        prev, cur = nxt, nxt
    return out


@dataclass
class JobResult:
    mode: str
    status: str
    detail: dict = field(default_factory=dict)


def inbox_dirs(settings: Settings) -> tuple[Path, Path, Path]:
    base = settings.bundle_dir
    dirs = (base / "inbox", base / "processed", base / "failed")
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    return dirs


def scheduled_collection(settings: Settings, factory=None, runner=None, importer=None) -> JobResult:
    """스케줄 1회 실행. 예외를 밖으로 던지지 않고(스케줄러 유지) 결과를 반환/로그로 남긴다."""
    from app.services.bundle import BundleError
    from app.services.vulnerability_collector import (
        CollectionBusy,
        import_bundle_file,
        run_online_collection,
    )
    runner = runner or run_online_collection
    importer = importer or import_bundle_file
    if settings.collector_mode == CollectorMode.ONLINE:
        try:
            out = runner(CollectionTrigger.SCHEDULE, SCHEDULER_ACTOR, factory=factory, settings=settings)
            logger.info("scheduled collection finished: id=%s status=%s", out.collection_id, out.status.value)
            return JobResult("online", out.status.value, {"collection_id": out.collection_id})
        except CollectionBusy:
            logger.warning("scheduled collection skipped: another collection is running")
            return JobResult("online", "skipped_busy")
        except Exception as e:  # noqa: BLE001
            logger.exception("scheduled collection failed")
            return JobResult("online", "failed", {"error": e.__class__.__name__})

    inbox, processed, failed = inbox_dirs(settings)
    results = {}
    for path in sorted(inbox.glob("*.json")):
        try:
            out = importer(path, SCHEDULER_ACTOR, factory=factory, settings=settings)
            shutil.move(str(path), processed / path.name)
            results[path.name] = out.status.value
        except CollectionBusy:
            results[path.name] = "skipped_busy"
            break
        except (BundleError, Exception) as e:  # noqa: BLE001
            logger.exception("bundle import failed: %s", path.name)
            shutil.move(str(path), failed / path.name)
            results[path.name] = f"failed:{e.__class__.__name__}"
    return JobResult("offline", "done" if results else "no_bundle", results)


def build_scheduler(settings: Settings) -> BlockingScheduler:
    sched = BlockingScheduler(timezone=ZoneInfo(TIMEZONE))
    sched.add_job(scheduled_collection, trigger=make_trigger(), args=[settings], id="vuln_collection",
                  name="취약점 정보 자동 수집", max_instances=1, coalesce=True, misfire_grace_time=3600,
                  replace_existing=True)
    return sched
