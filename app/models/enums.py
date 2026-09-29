"""도메인 열거형. DB에는 CHECK 제약이 있는 문자열로 저장된다 (PostgreSQL 이식성)."""
from __future__ import annotations

from enum import Enum

from sqlalchemy import Enum as SAEnum


class Zone(str, Enum):
    PERIMETER = "경계면"
    INTERNAL = "내부"


class Criticality(str, Enum):
    HIGH = "상"
    MEDIUM = "중"
    LOW = "하"


class Role(str, Enum):
    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class RemediationStatus(str, Enum):
    NEW = "신규"
    CHECKING = "확인중"
    PLANNED = "조치예정"
    IN_PROGRESS = "조치중"
    DONE = "조치완료"
    EXCEPTION = "예외처리"
    FALSE_POSITIVE = "오탐"


class MatchType(str, Enum):
    CPE_EXACT = "CPE_EXACT"                  # 구체 버전 CPE 일치
    CPE_RANGE = "CPE_RANGE"                  # versionStart/End 범위 일치
    CPE_ALL_VERSIONS = "CPE_ALL_VERSIONS"    # criteria version='*' 이고 범위 없음
    APPROVED_MAPPING = "APPROVED_MAPPING"    # 사용자 승인 매핑으로 생성한 CPE 기반


class CandidateStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


class MappingDecision(str, Enum):
    APPROVED = "approved"
    REJECTED = "rejected"


class AssessmentState(str, Enum):
    ASSESSED = "assessed"          # 등급 산정 완료
    EPSS_PENDING = "epss_pending"  # EPSS 미발행으로 판정보류 (정책 Q2)


class CollectionSource(str, Enum):
    NVD = "NVD"
    EPSS = "EPSS"
    KEV = "KEV"
    BUNDLE = "BUNDLE"
    ALL = "ALL"


class CollectionTrigger(str, Enum):
    SCHEDULE = "schedule"
    MANUAL = "manual"
    IMPORT = "import"


class CollectionStatus(str, Enum):
    RUNNING = "running"
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


def str_enum(enum_cls: type[Enum], name: str) -> SAEnum:
    """값(value)을 저장하는 비-native Enum + CHECK 제약."""
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        validate_strings=True,
        values_callable=lambda e: [m.value for m in e],
        length=max(len(m.value) for m in enum_cls) + 8,
    )
