from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base
from app.models.enums import CandidateStatus, MappingDecision, str_enum
from app.models.types import UTCDateTime, utcnow


class AssetProductMapping(Base):
    """사용자가 승인/거부한 '정규화 제품 → CPE vendor:product' 매핑 사전 (재사용)."""

    __tablename__ = "asset_product_mapping"
    __table_args__ = (
        UniqueConstraint("vendor_norm", "product_norm", "cpe_part", "cpe_vendor", "cpe_product",
                         name="uq_product_mapping"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    vendor_norm: Mapped[str] = mapped_column(String(128), index=True)
    product_norm: Mapped[str] = mapped_column(String(128), index=True)
    cpe_part: Mapped[str] = mapped_column(String(1))
    cpe_vendor: Mapped[str] = mapped_column(String(128))
    cpe_product: Mapped[str] = mapped_column(String(128))
    decision: Mapped[MappingDecision] = mapped_column(str_enum(MappingDecision, "ck_mapping_decision"))
    decided_by: Mapped[str] = mapped_column(String(64))
    decided_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    reason: Mapped[str | None] = mapped_column(String(512))


class MappingCandidate(Base):
    """Level 2/3: 자동 확정하지 않고 사람 검토를 기다리는 후보."""

    __tablename__ = "mapping_candidates"
    __table_args__ = (
        UniqueConstraint("asset_product_id", "cve_id", "proposed_cpe", name="uq_candidate"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_product_id: Mapped[int] = mapped_column(
        ForeignKey("asset_products.id", ondelete="CASCADE"), index=True
    )
    cve_id: Mapped[str | None] = mapped_column(ForeignKey("vulnerabilities.cve_id"), index=True)
    proposed_cpe: Mapped[str] = mapped_column(String(512))
    level: Mapped[int] = mapped_column(Integer)          # 2 또는 3
    confidence: Mapped[int | None] = mapped_column(Integer)  # 규칙 기반 점수, 산정불가 시 NULL
    breakdown: Mapped[dict] = mapped_column(JSON, default=dict)  # 점수 근거
    reason: Mapped[str] = mapped_column(String(512))
    status: Mapped[CandidateStatus] = mapped_column(
        str_enum(CandidateStatus, "ck_candidate_status"), default=CandidateStatus.PENDING
    )
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    decided_by: Mapped[str | None] = mapped_column(String(64))
    decided_at: Mapped[datetime | None] = mapped_column(UTCDateTime)
