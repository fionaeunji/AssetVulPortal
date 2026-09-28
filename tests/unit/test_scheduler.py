"""Phase 7: Scheduler (09:00/14:00 Asia/Seoul, 중복 방지, 오프라인 Bundle Inbox) + 감사로그 이벤트."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.config.settings import Settings
from app.models import AuditLog, CollectionHistory
from app.models.enums import CollectionStatus, CollectionTrigger
from app.scheduler.jobs import build_scheduler, next_fire_times, scheduled_collection
from app.services import job_lock
from app.services.nvd_client import NvdClient
from app.services.vulnerability_collector import LOCK_NAME, run_online_collection
from tests.fakes import FakeExternal

KST = ZoneInfo("Asia/Seoul")


def test_schedule_times_are_0900_and_1400_kst():
    now = datetime(2026, 9, 28, 8, 59, tzinfo=KST)
    t = next_fire_times(4, now)
    assert [x.strftime("%m-%d %H:%M") for x in t] == ["09-28 09:00", "09-28 14:00", "09-29 09:00", "09-29 14:00"]
    assert all(x.utcoffset() == timedelta(hours=9) for x in t)


def test_schedule_uses_kst_even_when_now_is_utc():
    now_utc = datetime(2026, 9, 28, 0, 30, tzinfo=timezone.utc)      # = 09:30 KST
    assert next_fire_times(1, now_utc)[0] == datetime(2026, 9, 28, 14, 0, tzinfo=KST)
    now_utc2 = datetime(2026, 9, 28, 5, 0, tzinfo=timezone.utc)      # = 14:00 KST (정각 이후 다음)
    assert next_fire_times(1, now_utc2 + timedelta(seconds=1))[0] == datetime(2026, 9, 29, 9, 0, tzinfo=KST)


def test_scheduler_job_config(tmp_path):
    s = Settings(_env_file=None, data_dir=tmp_path)
    sched = build_scheduler(s)
    job = sched.get_job("vuln_collection")
    assert job.max_instances == 1 and job.coalesce is True and job.misfire_grace_time == 3600
    assert str(job.trigger.timezone) == "Asia/Seoul"
    assert "hour='9,14'" in str(job.trigger) and "minute='0'" in str(job.trigger)


@pytest.fixture()
def factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


def _runner(fake):
    def run(trigger, actor, factory=None, settings=None):
        return run_online_collection(trigger, actor, factory=factory, settings=settings,
                                     transport=fake.transport(),
                                     nvd_client_factory=lambda h: NvdClient(h, sleep=lambda x: None),
                                     extra_product_keys=["a:apache:http_server"])
    return run


def test_scheduled_online_collection_recorded(factory, tmp_path):
    s = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "d")
    r = scheduled_collection(s, factory=factory, runner=_runner(FakeExternal()))
    assert r.mode == "online" and r.status == "success"
    with factory() as db:
        h = db.execute(select(CollectionHistory)).scalar_one()
        assert h.trigger == CollectionTrigger.SCHEDULE and h.requested_by == "scheduler"
        assert db.execute(select(AuditLog).where(AuditLog.action == "COLLECTION_SCHEDULED")).scalar_one()


def test_scheduled_run_skips_when_manual_collection_running(factory, tmp_path):
    s = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "d")
    assert job_lock.acquire(factory, LOCK_NAME, "web-manual", timedelta(minutes=30))
    r = scheduled_collection(s, factory=factory, runner=_runner(FakeExternal()))
    assert r.status == "skipped_busy"
    with factory() as db:
        assert db.execute(select(CollectionHistory)).first() is None


def test_scheduler_survives_collection_errors(factory, tmp_path):
    s = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "d")

    def boom(*a, **k):
        raise RuntimeError("unexpected")
    assert scheduled_collection(s, factory=factory, runner=boom).status == "failed"   # 예외 전파 안 함


def test_offline_inbox_import(factory, tmp_path):
    online = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "ext")
    _runner(FakeExternal())(CollectionTrigger.MANUAL, "ext", factory=factory, settings=online)
    bundle = next(online.bundle_dir.glob("bundle_*.json"))

    off = Settings(_env_file=None, collector_mode="offline", data_dir=tmp_path / "vdi")
    inbox = off.bundle_dir / "inbox"
    inbox.mkdir(parents=True)
    (inbox / "good.json").write_bytes(bundle.read_bytes())
    bad = json.loads(bundle.read_text(encoding="utf-8"))
    bad["payload"]["vulnerabilities"][0]["description"] = "tampered"
    (inbox / "bad.json").write_text(json.dumps(bad), encoding="utf-8")

    r = scheduled_collection(off, factory=factory)
    assert r.mode == "offline"
    assert r.detail["good.json"] == CollectionStatus.SUCCESS.value
    assert r.detail["bad.json"].startswith("failed")
    assert (off.bundle_dir / "processed" / "good.json").exists()
    assert (off.bundle_dir / "failed" / "bad.json").exists()
    assert not any(inbox.iterdir())
    assert scheduled_collection(off, factory=factory).status == "no_bundle"
