"""애플리케이션 설정.

모든 설정은 환경변수 또는 `.env`에서 읽는다. Secret은 소스코드에 기본값을 두지 않는다.
"""
from __future__ import annotations

from enum import Enum
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class AppEnv(str, Enum):
    DEV = "dev"
    PROD = "prod"


class CollectorMode(str, Enum):
    ONLINE = "online"    # PoC: Portal이 직접 외부 Source 호출
    OFFLINE = "offline"  # VDI: Bundle Import만 허용, 외부 통신 없음


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_env: AppEnv = AppEnv.DEV
    app_secret_key: SecretStr = Field(..., description="세션 서명키 (32자 이상)")
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'data' / 'portal.db').as_posix()}"
    data_dir: Path = PROJECT_ROOT / "data"
    collector_mode: CollectorMode = CollectorMode.ONLINE
    nvd_api_key: SecretStr | None = None
    bundle_hmac_key: SecretStr | None = None          # Collector-Portal 공유 비밀 (선택)
    epss_csv_threshold: int = Field(1000, ge=1)        # 대상 CVE 수가 이 값 이상이면 Bulk CSV 사용
    collection_lock_minutes: int = Field(120, ge=5, le=1440)
    upload_max_bytes: int = Field(5 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    session_idle_minutes: int = Field(30, ge=5, le=480)
    policy_file: Path = PROJECT_ROOT / "config" / "policy.yaml"
    display_timezone: str = "Asia/Seoul"

    @field_validator("app_secret_key")
    @classmethod
    def _secret_strength(cls, v: SecretStr) -> SecretStr:
        if len(v.get_secret_value()) < 32:
            raise ValueError("APP_SECRET_KEY must be at least 32 characters")
        return v

    @field_validator("nvd_api_key", "bundle_hmac_key", mode="before")
    @classmethod
    def _empty_key_is_none(cls, v):
        return v or None

    @field_validator("data_dir", "policy_file")
    @classmethod
    def _resolve_path(cls, v: Path) -> Path:
        return v if v.is_absolute() else (PROJECT_ROOT / v).resolve()

    @property
    def upload_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def bundle_dir(self) -> Path:
        return self.data_dir / "bundles"

    @property
    def log_dir(self) -> Path:
        return self.data_dir / "logs"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.upload_dir, self.bundle_dir, self.log_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    return Settings()  # type: ignore[call-arg]
