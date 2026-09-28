"""CISA KEV Catalog Client.

필드 근거: CISA 공식 feed JSON (cisagov/kev-data 로 확인, catalogVersion 2026.09.27)
top-level: title, catalogVersion, dateReleased, count, vulnerabilities[]
item: cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription,
      requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes
"""
from __future__ import annotations

import json
import logging
from datetime import date

import httpx
from pydantic import ValidationError

from app.config.endpoints import ENDPOINTS
from app.schemas.bundle import KevRecord
from app.services.http_client import ResponseTooLarge, get_limited

logger = logging.getLogger(__name__)

MAX_KEV_BYTES = 32 * 1024 * 1024


class KevError(RuntimeError):
    pass


def parse_kev(raw: bytes) -> tuple[str | None, list[KevRecord]]:
    if len(raw) > MAX_KEV_BYTES:
        raise KevError("KEV catalog too large")
    try:
        body = json.loads(raw)
        items = body["vulnerabilities"]
        if not isinstance(items, list):
            raise TypeError
    except (ValueError, KeyError, TypeError):
        raise KevError("KEV catalog format invalid") from None
    version = body.get("catalogVersion")
    version = str(version)[:32] if version is not None else None
    out: list[KevRecord] = []
    for it in items:
        if not isinstance(it, dict):
            continue
        try:
            out.append(KevRecord(
                cve_id=str(it.get("cveID", "")).strip(),
                vendor_project=it.get("vendorProject"),
                product=it.get("product"),
                vulnerability_name=it.get("vulnerabilityName"),
                date_added=date.fromisoformat(str(it.get("dateAdded"))),
                due_date=date.fromisoformat(it["dueDate"]) if it.get("dueDate") else None,
                known_ransomware=it.get("knownRansomwareCampaignUse"),
            ))
        except (ValidationError, ValueError, TypeError):
            logger.warning("KEV record rejected (validation): %s", str(it.get("cveID"))[:32])
    return version, out


class KevClient:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client
        self.url = ENDPOINTS["kev_json"]

    def fetch(self) -> tuple[str | None, list[KevRecord]]:
        try:
            status, body = get_limited(self._client, self.url, limit=MAX_KEV_BYTES)
        except ResponseTooLarge:
            raise KevError("KEV catalog too large") from None
        if status != 200:
            raise KevError(f"KEV download failed: HTTP {status}")
        return parse_kev(body)
