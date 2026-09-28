"""NVD raw `cve` 객체 → 정규화 VulnerabilityRecord."""
from __future__ import annotations

import hashlib
import json
from datetime import date, datetime, timezone

from app.schemas.bundle import CpeMatchRow, CvssMetric, VulnerabilityRecord
from app.schemas.nvd import NvdCve

REJECTED_STATUS = "Rejected"


class NormalizationError(ValueError):
    pass


def parse_nvd_datetime(value: str) -> datetime:
    """NVD 시각('2021-10-05T09:15:07.593', UTC 기준)을 tz-aware UTC로 변환."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def raw_sha256(raw: dict) -> str:
    canon = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def normalize_nvd_cve(raw: dict) -> VulnerabilityRecord | None:
    """정규화. Rejected CVE는 None. 형식 오류는 NormalizationError."""
    try:
        cve = NvdCve.model_validate(raw)
    except Exception as e:  # pydantic.ValidationError
        raise NormalizationError(f"invalid NVD CVE record: {e.__class__.__name__}") from None
    if cve.vulnStatus == REJECTED_STATUS:
        return None

    desc = next((d.value for d in cve.descriptions if d.lang == "en"), None)
    metrics: list[CvssMetric] = []
    for version, items in (("4.0", cve.metrics.cvssMetricV40), ("3.1", cve.metrics.cvssMetricV31),
                           ("3.0", cve.metrics.cvssMetricV30)):
        for m in items:
            metrics.append(CvssMetric(version=version, type=m.type, source=m.source,
                                      score=m.cvssData.baseScore, vector=m.cvssData.vectorString))

    rows: list[CpeMatchRow] = []
    for ci, cfg in enumerate(cve.configurations):
        for ni, node in enumerate(cfg.nodes):
            for mi, cm in enumerate(node.cpeMatch):
                rows.append(CpeMatchRow(
                    config_index=ci, config_operator=cfg.operator, config_negate=cfg.negate,
                    node_index=ni, node_operator=node.operator, node_negate=node.negate,
                    match_index=mi, vulnerable=cm.vulnerable, criteria=cm.criteria,
                    match_criteria_id=cm.matchCriteriaId,
                    version_start_including=cm.versionStartIncluding,
                    version_start_excluding=cm.versionStartExcluding,
                    version_end_including=cm.versionEndIncluding,
                    version_end_excluding=cm.versionEndExcluding,
                ))

    try:
        kev_add = date.fromisoformat(cve.cisaExploitAdd) if cve.cisaExploitAdd else None
        return VulnerabilityRecord(
            cve_id=cve.id,
            description=desc,
            published_at=parse_nvd_datetime(cve.published),
            last_modified_at=parse_nvd_datetime(cve.lastModified),
            vuln_status=(cve.vulnStatus or "")[:32] or None,
            cvss_metrics=metrics,
            cpe_matches=rows,
            nvd_cisa_exploit_add=kev_add,
            raw_sha256=raw_sha256(raw),
        )
    except ValueError as e:
        raise NormalizationError(f"invalid NVD CVE field: {e.__class__.__name__}") from None


def select_cvss(metrics: list[CvssMetric], priority: list[str]) -> CvssMetric | None:
    """정책의 source_priority 순서로 판정용 CVSS 1개를 선택 (없으면 None)."""
    for key in priority:
        version, typ = key.split(":")
        cands = [m for m in metrics if m.version == version and m.type == typ]
        if cands:
            # Primary는 NVD(nvd@nist.gov) 우선, 그 외는 원본 순서
            cands.sort(key=lambda m: m.source != "nvd@nist.gov")
            return cands[0]
    return None
