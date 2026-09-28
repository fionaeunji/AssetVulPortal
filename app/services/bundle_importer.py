"""Portal 측 Bundle Import (단일 트랜잭션, Idempotent)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import SyncState
from app.models.types import utcnow
from app.repositories import vulnerability_repo as repo
from app.schemas.bundle import Bundle

NVD_CURSOR_PREFIX = "nvd:"


@dataclass
class ImportResult:
    vulnerabilities: repo.UpsertStats = field(default_factory=repo.UpsertStats)
    epss: repo.UpsertStats = field(default_factory=repo.UpsertStats)
    kev: repo.UpsertStats = field(default_factory=repo.UpsertStats)
    cursors_advanced: int = 0

    def summary(self) -> dict:
        s = lambda st: {"inserted": st.inserted, "updated": st.updated,  # noqa: E731
                        "unchanged": st.unchanged, "skipped": st.skipped}
        return {"vulnerabilities": s(self.vulnerabilities), "epss": s(self.epss), "kev": s(self.kev),
                "cursors_advanced": self.cursors_advanced,
                "warnings": (self.vulnerabilities.warnings + self.epss.warnings)[:20]}


def _advance_cursor(session: Session, product_key: str, end: datetime) -> bool:
    key = NVD_CURSOR_PREFIX + product_key
    st = session.get(SyncState, key)
    iso = end.isoformat()
    if st is None:
        session.add(SyncState(key=key, value=iso))
        return True
    if datetime.fromisoformat(st.value) < end:
        st.value = iso
        return True
    return False


def get_cursor(session: Session, product_key: str) -> datetime | None:
    st = session.get(SyncState, NVD_CURSOR_PREFIX + product_key)
    return datetime.fromisoformat(st.value) if st else None


def import_bundle(session: Session, bundle: Bundle, *, cvss_priority: list[str],
                  collection_id: int | None) -> ImportResult:
    """호출자 트랜잭션 안에서 실행. 예외 발생 시 호출자가 rollback → 기존 데이터 보존."""
    now = utcnow()
    result = ImportResult()
    p = bundle.payload
    for rec in p.vulnerabilities:
        repo.upsert_vulnerability(session, rec, cvss_priority, now, result.vulnerabilities)
    session.flush()
    if p.kev:
        repo.apply_kev(session, p.kev, p.kev_catalog_version, now, result.kev)
    repo.refresh_kev_flags(session)
    repo.apply_epss(session, p.epss, now, collection_id, result.epss)
    for t in p.nvd_targets:
        if t.status == "success" and _advance_cursor(session, t.product_key, t.last_mod_end):
            result.cursors_advanced += 1
    session.flush()
    return result
