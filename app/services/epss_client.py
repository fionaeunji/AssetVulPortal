"""FIRST EPSS Client.

- API: `https://api.first.org/data/v1/epss?cve=CVE-A,CVE-B` (응답 data[]: cve, epss, percentile, date — 값은 문자열)
- Bulk CSV: `epss_scores-current.csv.gz` (첫 줄 `#model_version:...,score_date:...`, 헤더 `cve,epss,percentile`)
"""
from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
from collections.abc import Iterable
from datetime import date

import httpx
from pydantic import ValidationError

from app.config.endpoints import ENDPOINTS
from app.schemas.bundle import EpssRecord
from app.services.http_client import ResponseTooLarge, get_limited

logger = logging.getLogger(__name__)

API_BATCH_SIZE = 100
MAX_API_BYTES = 5 * 1024 * 1024
MAX_CSV_COMPRESSED = 64 * 1024 * 1024
MAX_CSV_DECOMPRESSED = 256 * 1024 * 1024
_SCORE_DATE_RE = re.compile(r"score_date:(\d{4}-\d{2}-\d{2})")


class EpssError(RuntimeError):
    pass


def _parse_record(cve: str, epss, percentile, score_date: date) -> EpssRecord | None:
    try:
        return EpssRecord(cve_id=cve, epss=float(epss),
                          percentile=None if percentile in (None, "") else float(percentile),
                          score_date=score_date)
    except (ValidationError, ValueError, TypeError):
        logger.warning("EPSS record rejected (validation): %s", str(cve)[:32])
        return None


class EpssClient:
    def __init__(self, client: httpx.Client) -> None:
        self._client = client
        self.api_url = ENDPOINTS["epss_api"]
        self.csv_url = ENDPOINTS["epss_csv"]

    def fetch_api(self, cve_ids: Iterable[str]) -> list[EpssRecord]:
        ids = sorted(set(cve_ids))
        out: list[EpssRecord] = []
        for i in range(0, len(ids), API_BATCH_SIZE):
            batch = ids[i:i + API_BATCH_SIZE]
            try:
                status, raw = get_limited(self._client, self.api_url, limit=MAX_API_BYTES,
                                          params={"cve": ",".join(batch), "limit": str(API_BATCH_SIZE)})
            except ResponseTooLarge:
                raise EpssError("EPSS API response too large") from None
            if status != 200:
                raise EpssError(f"EPSS API failed: HTTP {status}")
            try:
                body = json.loads(raw)
                data = body["data"]
                if not isinstance(data, list):
                    raise TypeError
            except (ValueError, KeyError, TypeError):
                raise EpssError("EPSS API response format invalid") from None
            for row in data:
                if not isinstance(row, dict):
                    continue
                try:
                    d = date.fromisoformat(str(row.get("date")))
                except ValueError:
                    continue
                rec = _parse_record(str(row.get("cve")), row.get("epss"), row.get("percentile"), d)
                if rec and rec.cve_id in batch:
                    out.append(rec)
        return out

    def fetch_csv(self, wanted: set[str] | None = None) -> list[EpssRecord]:
        """Bulk CSV 다운로드. wanted가 주어지면 해당 CVE만 반환."""
        try:
            status, raw = get_limited(self._client, self.csv_url, limit=MAX_CSV_COMPRESSED)
        except ResponseTooLarge:
            raise EpssError("EPSS CSV too large") from None
        if status != 200:
            raise EpssError(f"EPSS CSV download failed: HTTP {status}")
        return parse_epss_csv_gz(raw, wanted)


def parse_epss_csv_gz(raw: bytes, wanted: set[str] | None = None) -> list[EpssRecord]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as gz:
            data = gz.read(MAX_CSV_DECOMPRESSED + 1)
    except (OSError, EOFError):
        raise EpssError("EPSS CSV is not valid gzip") from None
    if len(data) > MAX_CSV_DECOMPRESSED:
        raise EpssError("EPSS CSV decompressed size exceeds limit")
    text = data.decode("utf-8", errors="strict")
    lines = text.splitlines()
    score_date: date | None = None
    if lines and lines[0].startswith("#"):
        m = _SCORE_DATE_RE.search(lines[0])
        if m:
            score_date = date.fromisoformat(m.group(1))
        lines = lines[1:]
    if score_date is None:
        raise EpssError("EPSS CSV missing score_date header")
    reader = csv.DictReader(lines)
    if reader.fieldnames is None or not {"cve", "epss", "percentile"} <= set(reader.fieldnames):
        raise EpssError("EPSS CSV header invalid")
    out: list[EpssRecord] = []
    for row in reader:
        cve = row.get("cve") or ""
        if wanted is not None and cve not in wanted:
            continue
        rec = _parse_record(cve, row.get("epss"), row.get("percentile"), score_date)
        if rec:
            out.append(rec)
    return out
