"""External Vulnerability Collector (DB 비의존).

입력: 수집 대상 제품 목록(+증분 커서), 이미 보유한 CVE 목록
출력: 검증된 정규화 Bundle

Portal DB에 접근하지 않으므로 VDI 운영 시 인터넷 구간의 별도 PC/서버에서 단독 실행할 수 있다.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import httpx

from app.models.types import utcnow
from app.schemas.bundle import (
    Bundle,
    BundlePayload,
    EpssRecord,
    KevRecord,
    NvdTargetResult,
    SourceInfo,
    VulnerabilityRecord,
)
from app.security.redaction import redact_text
from app.services.bundle import build_bundle
from app.services.epss_client import EpssClient
from app.services.kev_client import KevClient
from app.services.normalizer import NormalizationError, normalize_nvd_cve
from app.services.nvd_client import NvdClient

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class NvdTarget:
    product_key: str               # 'a:apache:http_server'
    last_mod_start: datetime | None  # None → 전체 이력 조회


def _err(e: Exception) -> str:
    return redact_text(f"{e.__class__.__name__}: {e}")[:500]


def collect(
    targets: list[NvdTarget],
    known_cve_ids: set[str],
    *,
    http: httpx.Client,
    nvd_api_key: str | None,
    epss_csv_threshold: int,
    hmac_key: str | None = None,
    collector_name: str = "online",
    nvd_client: NvdClient | None = None,
) -> Bundle:
    now = utcnow()
    sources: list[SourceInfo] = []
    nvd = nvd_client or NvdClient(http, nvd_api_key)

    # 1) KEV
    kev_records: list[KevRecord] = []
    kev_version: str | None = None
    kev = KevClient(http)
    try:
        kev_version, kev_records = kev.fetch()
        sources.append(SourceInfo(source="KEV", endpoint=kev.url, fetched_at=utcnow(),
                                  status="success", count=len(kev_records)))
    except Exception as e:  # noqa: BLE001 - 개별 Source 실패는 전체 수집을 중단하지 않음
        logger.warning("KEV collection failed: %s", _err(e))
        sources.append(SourceInfo(source="KEV", endpoint=kev.url, fetched_at=utcnow(),
                                  status="failed", error=_err(e)))

    # 2) NVD (제품 단위)
    vulns: dict[str, VulnerabilityRecord] = {}
    target_results: list[NvdTargetResult] = []
    rejected = invalid = 0
    for t in targets:
        try:
            raws = nvd.fetch_product(t.product_key, t.last_mod_start, now)
        except Exception as e:  # noqa: BLE001
            logger.warning("NVD collection failed for %s: %s", t.product_key, _err(e))
            target_results.append(NvdTargetResult(product_key=t.product_key,
                                                  last_mod_start=t.last_mod_start,
                                                  last_mod_end=now, status="failed"))
            continue
        for raw in raws:
            try:
                rec = normalize_nvd_cve(raw)
            except NormalizationError:
                invalid += 1
                continue
            if rec is None:
                rejected += 1
                continue
            prev = vulns.get(rec.cve_id)
            if prev is None or rec.last_modified_at > prev.last_modified_at:
                vulns[rec.cve_id] = rec
        target_results.append(NvdTargetResult(product_key=t.product_key,
                                              last_mod_start=t.last_mod_start, last_mod_end=now,
                                              status="success", count=len(raws)))
    failed_targets = [r for r in target_results if r.status == "failed"]
    nvd_status = ("skipped" if not targets else "failed" if len(failed_targets) == len(targets)
                  else "partial" if failed_targets or invalid else "success")
    sources.append(SourceInfo(
        source="NVD", endpoint=nvd.url, fetched_at=utcnow(), status=nvd_status, count=len(vulns),
        error=(f"failed_targets={len(failed_targets)}, invalid_records={invalid}, "
               f"rejected_cves={rejected}") if (failed_targets or invalid or rejected) else None,
    ))

    # 3) EPSS (보유 CVE + 이번 수집 CVE)
    wanted = set(known_cve_ids) | set(vulns)
    epss_records: list[EpssRecord] = []
    epss = EpssClient(http)
    if wanted:
        use_csv = len(wanted) >= epss_csv_threshold
        endpoint = epss.csv_url if use_csv else epss.api_url
        try:
            epss_records = epss.fetch_csv(wanted) if use_csv else epss.fetch_api(wanted)
            sources.append(SourceInfo(source="EPSS", endpoint=endpoint, fetched_at=utcnow(),
                                      status="success", count=len(epss_records)))
        except Exception as e:  # noqa: BLE001
            logger.warning("EPSS collection failed: %s", _err(e))
            sources.append(SourceInfo(source="EPSS", endpoint=endpoint, fetched_at=utcnow(),
                                      status="failed", error=_err(e)))
    else:
        sources.append(SourceInfo(source="EPSS", endpoint=epss.api_url, fetched_at=utcnow(),
                                  status="skipped"))

    payload = BundlePayload(
        vulnerabilities=sorted(vulns.values(), key=lambda r: r.cve_id),
        epss=epss_records, kev=kev_records, kev_catalog_version=kev_version,
        nvd_targets=target_results,
    )
    return build_bundle(payload, sources, collector=collector_name, hmac_key=hmac_key)
