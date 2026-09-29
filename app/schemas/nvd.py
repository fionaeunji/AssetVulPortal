"""NVD CVE API 2.0 응답 Schema (필요 필드만, 알 수 없는 필드는 무시).

구조 근거: NVD CVE API 2.0 응답의 `vulnerabilities[].cve` 객체
(tests/fixtures/nvd_records 참고). 외부 데이터이므로 모든 값을 검증한다.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.security.validators import CVE_ID_RE


class _Lenient(BaseModel):
    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class NvdDescription(_Lenient):
    lang: str
    value: str = Field(max_length=20000)


class NvdCvssData(_Lenient):
    version: str
    vectorString: str = Field(max_length=256)
    baseScore: float = Field(ge=0, le=10)


class NvdMetric(_Lenient):
    source: str = Field(max_length=128)
    type: Literal["Primary", "Secondary"]
    cvssData: NvdCvssData


class NvdMetrics(_Lenient):
    cvssMetricV40: list[NvdMetric] = []
    cvssMetricV31: list[NvdMetric] = []
    cvssMetricV30: list[NvdMetric] = []


class NvdCpeMatch(_Lenient):
    vulnerable: bool
    criteria: str = Field(max_length=512)
    matchCriteriaId: str | None = Field(None, max_length=64)
    versionStartIncluding: str | None = Field(None, max_length=64)
    versionStartExcluding: str | None = Field(None, max_length=64)
    versionEndIncluding: str | None = Field(None, max_length=64)
    versionEndExcluding: str | None = Field(None, max_length=64)


class NvdNode(_Lenient):
    operator: Literal["AND", "OR"]
    negate: bool = False
    cpeMatch: list[NvdCpeMatch] = []


class NvdConfiguration(_Lenient):
    operator: Literal["AND", "OR"] | None = None
    negate: bool = False
    nodes: list[NvdNode]


class NvdCve(_Lenient):
    id: str
    published: str
    lastModified: str
    vulnStatus: str | None = None
    descriptions: list[NvdDescription] = []
    metrics: NvdMetrics = NvdMetrics()
    configurations: list[NvdConfiguration] = []
    cisaExploitAdd: str | None = None
    cisaActionDue: str | None = None

    @field_validator("id")
    @classmethod
    def _cve_id(cls, v: str) -> str:
        if not CVE_ID_RE.fullmatch(v):
            raise ValueError("invalid CVE ID")
        return v


class NvdVulnerabilityItem(_Lenient):
    cve: dict   # 항목 단위로 개별 검증 (한 건 오류가 전체 수집을 막지 않도록)


class NvdCveResponse(_Lenient):
    resultsPerPage: int = Field(ge=0)
    startIndex: int = Field(ge=0)
    totalResults: int = Field(ge=0)
    vulnerabilities: list[NvdVulnerabilityItem] = []
