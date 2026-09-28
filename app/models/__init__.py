"""모든 모델을 import 하여 Base.metadata에 등록한다 (Alembic autogenerate 용)."""
from app.models.asset import Asset, AssetProduct, ImportBatch
from app.models.asset_vulnerability import AssetVulnerability, StatusHistory, VulnerabilityAssessment
from app.models.mapping import AssetProductMapping, MappingCandidate
from app.models.system import AuditLog, CollectionHistory, JobLock, PolicyVersion, SyncState, User
from app.models.vulnerability import EpssHistory, KevEntry, Vulnerability, VulnerabilityProduct

__all__ = [
    "Asset",
    "AssetProduct",
    "AssetProductMapping",
    "AssetVulnerability",
    "AuditLog",
    "CollectionHistory",
    "EpssHistory",
    "ImportBatch",
    "JobLock",
    "KevEntry",
    "MappingCandidate",
    "PolicyVersion",
    "StatusHistory",
    "SyncState",
    "User",
    "Vulnerability",
    "VulnerabilityAssessment",
    "VulnerabilityProduct",
]

# DB/ORM 무결성 보호 등록 (Append-only ORM guard)
from app.models import guards as _guards  # noqa: E402,F401
