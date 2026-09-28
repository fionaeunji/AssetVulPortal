"""제품 별칭 사전 로딩 및 벤더 고유 버전 표기 변환 (config/product_aliases.yaml)."""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.config.settings import PROJECT_ROOT

ALIASES_FILE = PROJECT_ROOT / "config" / "product_aliases.yaml"
_TOKEN = r"^[a-z0-9_.\-+]{1,128}$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AliasMatch(_Strict):
    vendor: list[str] = Field(min_length=1)
    product: list[str] = Field(min_length=1)

    @field_validator("vendor", "product")
    @classmethod
    def _tokens(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(_TOKEN, t):
                raise ValueError(f"invalid alias token: {t!r}")
        return v


class AliasCpe(_Strict):
    part: str = Field(pattern=r"^[aoh]$")
    vendor: str = Field(pattern=_TOKEN)
    product: str = Field(pattern=_TOKEN)


class VersionRule(_Strict):
    pattern: str = Field(max_length=200)
    version: str = Field(max_length=64)
    update: str | None = Field(None, max_length=64)

    @field_validator("pattern")
    @classmethod
    def _compiles(cls, v: str) -> str:
        re.compile(v)
        return v


class AliasEntry(_Strict):
    match: AliasMatch
    cpe: AliasCpe
    version_rules: list[VersionRule] = []


class AliasBook(_Strict):
    products: list[AliasEntry] = []

    def find(self, vendor_norm: str | None, product_norm: str | None) -> list[AliasEntry]:
        if not vendor_norm or not product_norm:
            return []
        return [e for e in self.products
                if vendor_norm in e.match.vendor and product_norm in e.match.product]

    def for_cpe(self, part: str, vendor: str, product: str) -> AliasEntry | None:
        return next((e for e in self.products
                     if (e.cpe.part, e.cpe.vendor, e.cpe.product) == (part, vendor, product)), None)


def load_aliases(path: Path = ALIASES_FILE) -> AliasBook:
    if not path.is_file():
        return AliasBook()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AliasBook.model_validate(data)


@lru_cache
def get_aliases() -> AliasBook:
    return load_aliases()


def apply_version_rules(entry: AliasEntry | None, version: str | None) -> tuple[str | None, str | None, str | None]:
    """(version, update, 적용 규칙 설명). 규칙 불일치 시 원본 유지."""
    if not version:
        return None, None, None
    v = version.strip()[:64]
    for rule in (entry.version_rules if entry else []):
        m = re.fullmatch(rule.pattern, v, flags=re.IGNORECASE)
        if m:
            def fill(tpl: str) -> str:
                return re.sub(r"\{(\d)\}", lambda g: m.group(int(g.group(1))).lower(), tpl)
            return fill(rule.version), (fill(rule.update) if rule.update else None), \
                f"버전 표기 변환 규칙 '{rule.pattern}' 적용: {v} → {fill(rule.version)}" + \
                (f" / update {fill(rule.update)}" if rule.update else "")
    return v, None, None
