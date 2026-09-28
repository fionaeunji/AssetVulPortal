"""취약점 정책 파일 Schema. 정책 값은 코드가 아닌 YAML/DB에서 관리한다."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class MonthMode(str, Enum):
    FIXED_DAYS = "fixed_days"   # months × days_per_month 일
    CALENDAR = "calendar"       # 달력 월 (정수부) + 소수부 × days_per_month 일


class EpssMissingBehavior(str, Enum):
    PENDING = "pending"   # 판정보류 → 최초 EPSS 관측 시 재판정
    ZERO = "zero"         # EPSS 0으로 간주


class Duration(_Strict):
    hours: float | None = Field(None, gt=0, le=24 * 365)
    days: float | None = Field(None, gt=0, le=3650)
    months: float | None = Field(None, gt=0, le=120)

    @model_validator(mode="after")
    def _exactly_one(self):
        if sum(v is not None for v in (self.hours, self.days, self.months)) != 1:
            raise ValueError("deadline must specify exactly one of hours/days/months")
        return self


class ZoneDeadlines(_Strict):
    perimeter: Duration
    internal: Duration


class SeverityRule(_Strict):
    key: str = Field(pattern=r"^[a-z][a-z0-9_]{1,31}$")
    name: str = Field(min_length=1, max_length=32)
    cvss_min: float = Field(ge=0, le=10)
    epss_initial_min: float | None = Field(None, ge=0, le=1)
    deadline: ZoneDeadlines


class CvssConfig(_Strict):
    # "<version>:<type>" 예: "3.1:Primary" (Primary = NVD, Secondary = CNA)
    source_priority: list[str] = Field(min_length=1)

    @field_validator("source_priority")
    @classmethod
    def _valid_keys(cls, v: list[str]) -> list[str]:
        allowed = {f"{ver}:{t}" for ver in ("4.0", "3.1", "3.0", "2.0") for t in ("Primary", "Secondary")}
        bad = [x for x in v if x not in allowed]
        if bad:
            raise ValueError(f"unknown CVSS source keys: {bad}")
        if len(set(v)) != len(v):
            raise ValueError("duplicate CVSS source keys")
        return v


class EpssConfig(_Strict):
    missing_behavior: EpssMissingBehavior = EpssMissingBehavior.PENDING


class DeadlineConfig(_Strict):
    month_mode: MonthMode = MonthMode.FIXED_DAYS
    days_per_month: int = Field(30, ge=28, le=31)


class Policy(_Strict):
    version: str = Field(pattern=r"^[A-Za-z0-9._-]{1,64}$")
    cvss: CvssConfig
    epss: EpssConfig = EpssConfig()
    deadline: DeadlineConfig = DeadlineConfig()
    rules: list[SeverityRule] = Field(min_length=1)   # 순서 = 우선순위
    default_name: str = Field("관리대상 아님", max_length=32)

    @field_validator("rules")
    @classmethod
    def _unique(cls, v: list[SeverityRule]) -> list[SeverityRule]:
        if len({r.key for r in v}) != len(v) or len({r.name for r in v}) != len(v):
            raise ValueError("rule keys and names must be unique")
        return v
