from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base
from app.models.enums import Criticality, Zone, str_enum
from app.models.types import UTCDateTime, utcnow


class ImportBatch(Base):
    """Excel 자산관리대장 업로드 이력."""

    __tablename__ = "import_batches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    stored_file_id: Mapped[str] = mapped_column(String(36), unique=True)  # UUID4, 서버 저장 파일명
    original_filename: Mapped[str] = mapped_column(String(255))            # 표시용(정제된 값)
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    row_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    uploaded_by: Mapped[str] = mapped_column(String(64))
    uploaded_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_code: Mapped[str] = mapped_column(String(64), unique=True, index=True)  # Excel "Asset ID"
    name: Mapped[str] = mapped_column(String(128), index=True)                    # 자산명(Hostname)
    zone: Mapped[Zone] = mapped_column(str_enum(Zone, "ck_asset_zone"))
    ip: Mapped[str | None] = mapped_column(String(45), index=True)
    criticality: Mapped[Criticality] = mapped_column(str_enum(Criticality, "ck_asset_criticality"))
    owner_name: Mapped[str | None] = mapped_column(String(64), index=True)
    department: Mapped[str | None] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    import_batch_id: Mapped[int | None] = mapped_column(ForeignKey("import_batches.id"))
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, default=utcnow, onupdate=utcnow)

    products: Mapped[list[AssetProduct]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )


class AssetProduct(Base):
    """자산에 설치된 제품(OS/애플리케이션). 원본 입력값과 정규화 값을 분리 저장."""

    __tablename__ = "asset_products"
    __table_args__ = (
        UniqueConstraint("asset_id", "vendor_norm", "product_norm", "version_norm",
                         name="uq_asset_product"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    # SOURCE (Excel 원본)
    vendor_raw: Mapped[str | None] = mapped_column(String(128))
    product_raw: Mapped[str | None] = mapped_column(String(128))
    version_raw: Mapped[str | None] = mapped_column(String(64))
    cpe_raw: Mapped[str | None] = mapped_column(String(512))
    # CALCULATED (정규화)
    vendor_norm: Mapped[str | None] = mapped_column(String(128), index=True)
    product_norm: Mapped[str | None] = mapped_column(String(128), index=True)
    version_norm: Mapped[str | None] = mapped_column(String(64))
    update_norm: Mapped[str | None] = mapped_column(String(64))
    cpe_normalized: Mapped[str | None] = mapped_column(String(512), index=True)
    cpe_source: Mapped[str | None] = mapped_column(String(16))  # excel | mapping | None
    cpe_error: Mapped[str | None] = mapped_column(String(255))   # 잘못된 CPE 사유
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)  # 대장에서 빠지면 False (삭제하지 않음)

    asset: Mapped[Asset] = relationship(back_populates="products")
