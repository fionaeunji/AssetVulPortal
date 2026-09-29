"""Collector ↔ Portal 간 정규화 데이터 교환 형식 (Bundle).

VDI 운영 시 외부망 Collector가 이 형식의 JSON을 만들고, 내부 Portal은 검증 후 Import만 수행한다.
"""
from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.validators import CVE_ID_RE

BUNDLE_FORMAT = "vulportal-bundle"
BUNDLE_SCHEMA_VERSION = 1


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _check_cve(v: str) -> str:
    if not CVE_ID_RE.fullmatch(v):
        raise ValueError("invalid CVE ID")
    return v


class CvssMetric(_Strict):
    version: Literal["4.0", "3.1", "3.0", "2.0"]
    type: Literal["Primary", "Secondary"]
    source: str = Field(max_length=128)
    score: float = Field(ge=0, le=10)
    vector: str = Field(max_length=256)


class CpeMatchRow(_Strict):
    config_index: int = Field(ge=0)
    config_operator: Literal["AND", "OR"] | None = None
    config_negate: bool = False
    node_index: int = Field(ge=0)
    node_operator: Literal["AND", "OR"]
    node_negate: bool = False
    match_index: int = Field(ge=0)
    vulnerable: bool
    criteria: str = Field(max_length=512)
    match_criteria_id: str | None = Field(None, max_length=64)
    version_start_including: str | None = Field(None, max_length=64)
    version_start_excluding: str | None = Field(None, max_length=64)
    version_end_including: str | None = Field(None, max_length=64)
    version_end_excluding: str | None = Field(None, max_length=64)


class VulnerabilityRecord(_Strict):
    cve_id: str
    description: str | None = Field(None, max_length=20000)
    published_at: datetime
    last_modified_at: datetime
    vuln_status: str | None = Field(None, max_length=32)
    cvss_metrics: list[CvssMetric] = []
    cpe_matches: list[CpeMatchRow] = []
    nvd_cisa_exploit_add: date | None = None
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    _v_cve = field_validator("cve_id")(_check_cve)


class EpssRecord(_Strict):
    cve_id: str
    epss: float = Field(ge=0, le=1)
    percentile: float | None = Field(None, ge=0, le=1)
    score_date: date

    _v_cve = field_validator("cve_id")(_check_cve)


class KevRecord(_Strict):
    cve_id: str
    vendor_project: str | None = Field(None, max_length=256)
    product: str | None = Field(None, max_length=256)
    vulnerability_name: str | None = Field(None, max_length=512)
    date_added: date
    due_date: date | None = None
    known_ransomware: str | None = Field(None, max_length=16)

    _v_cve = field_validator("cve_id")(_check_cve)


class SourceInfo(_Strict):
    source: Literal["NVD", "EPSS", "KEV"]
    endpoint: str = Field(max_length=256)
    fetched_at: datetime
    status: Literal["success", "partial", "failed", "skipped"]
    count: int = Field(0, ge=0)
    error: str | None = Field(None, max_length=1000)


class NvdTargetResult(_Strict):
    """제품(part:vendor:product) 단위 NVD 조회 결과 — Portal의 증분 커서 갱신에 사용."""

    product_key: str = Field(max_length=300)
    last_mod_start: datetime | None = None
    last_mod_end: datetime
    status: Literal["success", "failed"]
    count: int = Field(0, ge=0)


class BundlePayload(_Strict):
    vulnerabilities: list[VulnerabilityRecord] = []
    epss: list[EpssRecord] = []
    kev: list[KevRecord] = []
    kev_catalog_version: str | None = Field(None, max_length=32)
    nvd_targets: list[NvdTargetResult] = []


class BundleManifest(_Strict):
    format: Literal["vulportal-bundle"] = BUNDLE_FORMAT
    schema_version: Literal[1] = BUNDLE_SCHEMA_VERSION
    bundle_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: datetime
    collector: str = Field(max_length=64)
    sources: list[SourceInfo] = []
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    hmac_sha256: str | None = Field(None, pattern=r"^[0-9a-f]{64}$")


class Bundle(_Strict):
    manifest: BundleManifest
    payload: BundlePayload
