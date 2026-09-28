"""CPE 2.3 Formatted String 파서.

형식: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
- 백슬래시 이스케이프(`\\:`, `\\/` 등)를 고려하여 분리한다.
- 특수값: `*` = ANY, `-` = NA
"""
from __future__ import annotations

import re
from dataclasses import dataclass

ANY = "*"
NA = "-"

FIELDS = ("part", "vendor", "product", "version", "update", "edition", "language",
          "sw_edition", "target_sw", "target_hw", "other")

_MAX_LEN = 512
# CPE 2.3 formatted string: 영숫자와 `_ . - ~`, 와일드카드 `* ?` 외 특수문자는 반드시 `\` 이스케이프
_ALLOWED_VALUE = re.compile(r"^(?:-|(?:[A-Za-z0-9._\-~*?]|\\[\x21-\x7e])+)$")


class InvalidCPE(ValueError):
    pass


def _split_escaped(s: str) -> list[str]:
    parts, buf, i = [], [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            if i + 1 >= len(s):
                raise InvalidCPE("dangling escape")
            buf.append(s[i:i + 2])
            i += 2
            continue
        if ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return parts


def unescape(value: str) -> str:
    return re.sub(r"\\(.)", r"\1", value)


@dataclass(frozen=True)
class CPE:
    part: str
    vendor: str
    product: str
    version: str = ANY
    update: str = ANY
    edition: str = ANY
    language: str = ANY
    sw_edition: str = ANY
    target_sw: str = ANY
    target_hw: str = ANY
    other: str = ANY

    @property
    def product_key(self) -> str:
        """part:vendor:product (이스케이프 유지) — 수집 대상 키."""
        return f"{self.part}:{self.vendor}:{self.product}"

    def to_string(self) -> str:
        return "cpe:2.3:" + ":".join(getattr(self, f) for f in FIELDS)

    def with_version(self, version: str, update: str | None = None) -> CPE:
        d = {f: getattr(self, f) for f in FIELDS}
        d["version"] = version
        if update is not None:
            d["update"] = update
        return CPE(**d)


def parse_cpe(s: str) -> CPE:
    if not isinstance(s, str) or not s:
        raise InvalidCPE("empty CPE")
    if len(s) > _MAX_LEN:
        raise InvalidCPE("CPE too long")
    if any(ord(c) < 0x21 or ord(c) > 0x7E for c in s):
        raise InvalidCPE("CPE contains whitespace or non-printable/non-ASCII characters")
    parts = _split_escaped(s)
    if len(parts) != 13 or parts[0] != "cpe" or parts[1] != "2.3":
        raise InvalidCPE("CPE 2.3 formatted string must have 13 colon-separated components")
    values = [p.lower() for p in parts[2:]]
    if values[0] not in ("a", "o", "h"):
        raise InvalidCPE("part must be one of a/o/h")
    for name, v in zip(FIELDS, values):
        if not v or not _ALLOWED_VALUE.match(v):
            raise InvalidCPE(f"invalid value in field '{name}'")
    if values[1] in (ANY, NA) or values[2] in (ANY, NA):
        raise InvalidCPE("vendor and product must be specific values")
    return CPE(**dict(zip(FIELDS, values)))


def try_parse_cpe(s: str | None) -> tuple[CPE | None, str | None]:
    if not s:
        return None, None
    try:
        return parse_cpe(s.strip()), None
    except InvalidCPE as e:
        return None, str(e)
