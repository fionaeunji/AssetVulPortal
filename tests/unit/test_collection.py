"""수집 → Bundle → Import 통합 테스트 (MockTransport + 실제 Migration 스키마)."""
from __future__ import annotations

import json
from datetime import date

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.config.settings import Settings
from app.models import (
    Asset,
    AssetProduct,
    AuditLog,
    CollectionHistory,
    EpssHistory,
    SyncState,
    Vulnerability,
    VulnerabilityProduct,
)
from app.models.enums import CollectionStatus, CollectionTrigger, Criticality, Zone
from app.services import job_lock
from app.services.bundle import BundleError
from app.services.nvd_client import NvdClient
from app.services.vulnerability_collector import (
    LOCK_NAME,
    CollectionBusy,
    CollectionNotAllowed,
    import_bundle_file,
    run_online_collection,
)
from tests.fakes import FakeExternal

EPSS = {
    "CVE-2021-41773": (0.94, 0.999), "CVE-2021-42013": (0.94, 0.999),
    "CVE-2020-1938": (0.20, 0.97), "CVE-2024-24549": (0.05, 0.80),
}


@pytest.fixture()
def factory(engine):
    return sessionmaker(bind=engine, expire_on_commit=False)


@pytest.fixture()
def settings(tmp_path):
    return Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "data",
                    epss_csv_threshold=1000)


@pytest.fixture()
def seeded(factory):
    with factory() as s:
        a = Asset(asset_code="WEB-01", name="web01", zone=Zone.PERIMETER, ip="192.0.2.10",
                  criticality=Criticality.HIGH, owner_name="가상담당자")
        s.add(a)
        s.flush()
        s.add_all([
            AssetProduct(asset_id=a.id, vendor_norm="apache", product_norm="http_server",
                         version_norm="2.4.49",
                         cpe_normalized="cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"),
            AssetProduct(asset_id=a.id, vendor_norm="apache", product_norm="tomcat",
                         version_norm="9.0.30",
                         cpe_normalized="cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*"),
        ])
        s.commit()


def _run(fake, factory, settings, **kw):
    return run_online_collection(
        CollectionTrigger.MANUAL, "op1", factory=factory, settings=settings,
        transport=fake.transport(),
        nvd_client_factory=lambda http: NvdClient(http, None, sleep=lambda s: None), **kw)


def _count(s, model):
    return s.execute(select(func.count()).select_from(model)).scalar()


def test_full_collection_stores_source_data(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS)
    out = _run(fake, factory, settings)
    assert out.status == CollectionStatus.SUCCESS
    with factory() as s:
        v = s.get(Vulnerability, "CVE-2021-41773")
        assert (v.cvss_score, v.cvss_version, v.cvss_type) == (9.8, "3.1", "Primary")
        assert v.cvss_vector.startswith("CVSS:3.1/")
        assert v.published_at and v.last_modified_at and v.description
        assert v.kev and v.kev_source == "CISA_KEV" and v.kev_date_added == date(2021, 11, 3)
        assert v.epss_initial == 0.94 and v.epss_current == 0.94
        assert v.epss_initial_date == date(2026, 9, 27) and v.epss_first_seen_at
        # Tomcat CVE: 범위 조건 저장
        vp = s.execute(select(VulnerabilityProduct).where(
            VulnerabilityProduct.cve_id == "CVE-2020-1938",
            VulnerabilityProduct.product == "tomcat",
            VulnerabilityProduct.version_start_including == "9.0.0")).scalars().first()
        assert vp and vp.version_end_excluding
        # KEV 아님 (카탈로그에도 없고 NVD cisaExploitAdd도 없음)
        assert s.get(Vulnerability, "CVE-2024-24549").kev is False
        # 이력/커서/감사
        h = s.get(CollectionHistory, out.collection_id)
        assert h.status == CollectionStatus.SUCCESS and h.bundle_sha256 and h.finished_at
        hosts = {e["host"] for e in h.endpoints_called}
        assert hosts == {"services.nvd.nist.gov", "api.first.org", "www.cisa.gov"}
        assert s.get(SyncState, "nvd:a:apache:http_server") is not None
        assert s.execute(select(AuditLog).where(AuditLog.action == "COLLECTION_MANUAL")).scalar_one()
    assert list(settings.bundle_dir.glob("bundle_*.json"))


def test_recollection_is_idempotent_and_preserves_initial_epss(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS)
    _run(fake, factory, settings)
    with factory() as s:
        n_v, n_vp, n_e = _count(s, Vulnerability), _count(s, VulnerabilityProduct), _count(s, EpssHistory)
    # 다음날 EPSS 변경
    fake.epss = {**EPSS, "CVE-2021-41773": (0.50, 0.95)}
    fake.epss_date = date(2026, 9, 28)
    _run(fake, factory, settings)
    with factory() as s:
        assert _count(s, Vulnerability) == n_v            # 중복 CVE 없음
        assert _count(s, VulnerabilityProduct) == n_vp
        assert _count(s, EpssHistory) == n_e + len(EPSS)  # 날짜별 이력 추가
        v = s.get(Vulnerability, "CVE-2021-41773")
        assert v.epss_initial == 0.94 and v.epss_initial_date == date(2026, 9, 27)  # 보존
        assert v.epss_current == 0.50 and v.epss_current_date == date(2026, 9, 28)  # 갱신
    # 같은 날짜 재수집: 이력 중복 없음
    _run(fake, factory, settings)
    with factory() as s:
        assert _count(s, EpssHistory) == n_e + len(EPSS)
    # 두 번째 이후 NVD 조회는 증분(lastMod) 파라미터 사용
    assert "lastModStartDate" in fake.calls[-1].url.params or any(
        "lastModStartDate" in c.url.params for c in fake.calls if c.url.host == "services.nvd.nist.gov")


def test_older_epss_does_not_overwrite_current(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS, epss_date=date(2026, 9, 27))
    _run(fake, factory, settings)
    fake.epss = {**EPSS, "CVE-2021-41773": (0.10, 0.5)}
    fake.epss_date = date(2026, 9, 20)
    _run(fake, factory, settings)
    with factory() as s:
        v = s.get(Vulnerability, "CVE-2021-41773")
        assert v.epss_current == 0.94 and v.epss_current_date == date(2026, 9, 27)


def test_epss_missing_then_first_seen_becomes_initial(factory, settings, seeded):
    fake = FakeExternal(epss={})
    _run(fake, factory, settings)
    with factory() as s:
        assert s.get(Vulnerability, "CVE-2021-41773").epss_initial is None
    fake.epss = EPSS
    _run(fake, factory, settings)
    with factory() as s:
        assert s.get(Vulnerability, "CVE-2021-41773").epss_initial == 0.94


def test_all_sources_fail_keeps_existing_data(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS)
    _run(fake, factory, settings)
    with factory() as s:
        before = (_count(s, Vulnerability), s.get(Vulnerability, "CVE-2021-41773").epss_current)
        cursor_before = s.get(SyncState, "nvd:a:apache:http_server").value
    fake.fail = {"nvd", "epss", "kev"}
    out = _run(fake, factory, settings)
    assert out.status == CollectionStatus.FAILED
    with factory() as s:
        assert (_count(s, Vulnerability), s.get(Vulnerability, "CVE-2021-41773").epss_current) == before
        assert s.get(Vulnerability, "CVE-2021-41773").kev is True     # KEV 실패해도 기존 플래그 유지
        assert s.get(SyncState, "nvd:a:apache:http_server").value == cursor_before  # 커서 전진 안 함


def test_partial_failure_status(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS)
    fake.fail = {"kev"}
    out = _run(fake, factory, settings)
    assert out.status == CollectionStatus.PARTIAL


def test_import_error_rolls_back(factory, settings, seeded, monkeypatch):
    import app.services.bundle_importer as bi

    def boom(*a, **k):
        raise RuntimeError("simulated failure during EPSS apply")

    monkeypatch.setattr(bi.repo, "apply_epss", boom)
    with pytest.raises(RuntimeError):
        _run(FakeExternal(epss=EPSS), factory, settings)
    with factory() as s:
        assert _count(s, Vulnerability) == 0          # 부분 반영 없음
        h = s.execute(select(CollectionHistory)).scalar_one()
        assert h.status == CollectionStatus.FAILED and "simulated" in h.error_summary
    assert job_lock.acquire(factory, LOCK_NAME, "x", __import__("datetime").timedelta(minutes=1))


def test_duplicate_run_prevented(factory, settings, seeded):
    from datetime import timedelta
    assert job_lock.acquire(factory, LOCK_NAME, "other-process", timedelta(minutes=30))
    with pytest.raises(CollectionBusy):
        _run(FakeExternal(epss=EPSS), factory, settings)
    with factory() as s:
        assert s.execute(select(AuditLog).where(AuditLog.result == "rejected")).scalar_one()


def test_expired_lock_is_taken_over(factory, settings, seeded):
    from datetime import timedelta
    assert job_lock.acquire(factory, LOCK_NAME, "dead-process", timedelta(seconds=-1))
    out = _run(FakeExternal(epss=EPSS), factory, settings)
    assert out.status == CollectionStatus.SUCCESS


def test_offline_mode_blocks_external_collection(factory, tmp_path, seeded):
    s = Settings(_env_file=None, collector_mode="offline", data_dir=tmp_path / "d")
    with pytest.raises(CollectionNotAllowed):
        run_online_collection(CollectionTrigger.MANUAL, "op1", factory=factory, settings=s)


def test_offline_bundle_import_and_tamper(factory, settings, seeded, tmp_path):
    # 외부망에서 생성된 Bundle 을 다른(내부) DB로 Import 하는 흐름
    _run(FakeExternal(epss=EPSS), factory, settings)
    bundle_path = next(settings.bundle_dir.glob("bundle_*.json"))
    off = Settings(_env_file=None, collector_mode="offline", data_dir=tmp_path / "vdi")
    out = import_bundle_file(bundle_path, "admin", factory=factory, settings=off)
    assert out.status == CollectionStatus.SUCCESS
    data = json.loads(bundle_path.read_text(encoding="utf-8"))
    data["payload"]["epss"][0]["epss"] = 0.0001
    bad = tmp_path / "tampered.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BundleError):
        import_bundle_file(bad, "admin", factory=factory, settings=off)
    with factory() as s:
        last = s.execute(select(CollectionHistory).order_by(CollectionHistory.id.desc())).scalars().first()
        assert last.status == CollectionStatus.FAILED


def test_unchanged_record_with_missing_cpe_rows_is_repaired(factory, settings, seeded):
    fake = FakeExternal(epss=EPSS)
    _run(fake, factory, settings)
    with factory() as s:
        n = _count(s, VulnerabilityProduct)
        s.execute(VulnerabilityProduct.__table__.delete().where(
            VulnerabilityProduct.cve_id == "CVE-2021-41773"))
        s.commit()
    _run(fake, factory, settings, full=True)
    with factory() as s:
        assert _count(s, VulnerabilityProduct) == n
