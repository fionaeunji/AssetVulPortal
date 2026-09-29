"""NVD CVE API 2.0 Client.

- Endpoint: app/config/endpoints.py `nvd_cves`
- 인증: 선택적 `apiKey` 요청 헤더 (값은 로그/예외 메시지에 포함하지 않음)
- Rate limit: 키 없음 5 req/30s, 키 있음 50 req/30s → 요청 간 최소 간격 적용
- 페이지: resultsPerPage(최대 2000) + startIndex
- 증분: lastModStartDate/lastModEndDate (둘 다 필요, 최대 120일 구간 → 자동 분할)
- 자산 기반 조회: virtualMatchString (제품 단위 CPE)
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterator
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import ValidationError

from app.config.endpoints import ENDPOINTS
from app.schemas.nvd import NvdCveResponse
from app.services.http_client import ResponseTooLarge, get_limited, is_cert_verification_error

logger = logging.getLogger(__name__)

MAX_RESULTS_PER_PAGE = 2000
MAX_DATE_RANGE = timedelta(days=120)
RETRY_STATUS = {403, 429, 500, 502, 503, 504}   # NVD는 Rate limit 초과 시 403을 반환할 수 있음
MAX_RESPONSE_BYTES = 200 * 1024 * 1024


class NvdError(RuntimeError):
    pass


def format_nvd_datetime(dt: datetime) -> str:
    """NVD 날짜 파라미터 형식 (ISO-8601, 밀리초, UTC offset)."""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")


def split_windows(start: datetime, end: datetime) -> list[tuple[datetime, datetime]]:
    if start >= end:
        return []
    windows, cur = [], start
    while cur < end:
        nxt = min(cur + MAX_DATE_RANGE, end)
        windows.append((cur, nxt))
        cur = nxt
    return windows


def virtual_match_string(product_key: str) -> str:
    """'a:apache:http_server' → 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*'"""
    return f"cpe:2.3:{product_key}:*:*:*:*:*:*:*:*"


class NvdClient:
    def __init__(
        self,
        client: httpx.Client,
        api_key: str | None = None,
        *,
        page_size: int = MAX_RESULTS_PER_PAGE,
        max_retries: int = 4,
        max_pages: int = 200,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self._client = client
        self._api_key = api_key
        self._page_size = min(page_size, MAX_RESULTS_PER_PAGE)
        self._max_retries = max_retries
        self._max_pages = max_pages
        self._sleep = sleep
        self._monotonic = monotonic
        self._min_interval = 0.6 if api_key else 6.0
        self._last_request: float | None = None
        self.url = ENDPOINTS["nvd_cves"]

    def _throttle(self) -> None:
        if self._last_request is not None:
            wait = self._min_interval - (self._monotonic() - self._last_request)
            if wait > 0:
                self._sleep(wait)
        self._last_request = self._monotonic()

    def _get(self, params: dict) -> NvdCveResponse:
        headers = {"apiKey": self._api_key} if self._api_key else {}
        for attempt in range(self._max_retries + 1):
            self._throttle()
            try:
                status, body = get_limited(self._client, self.url, params=params, headers=headers,
                                           limit=MAX_RESPONSE_BYTES)
            except ResponseTooLarge:
                raise NvdError("NVD response too large") from None
            except httpx.TransportError as e:
                if is_cert_verification_error(e):
                    # 인증서 문제는 재시도해도 해결되지 않음 → 즉시 중단 (README 'SSL 검사 환경' 참고)
                    raise NvdError(f"TLS certificate verification failed: {str(e)[:200]}") from None
                status, reason = None, f"{e.__class__.__name__}: {str(e)[:200]}"
            else:
                reason = f"HTTP {status}"
                if status == 200:
                    try:
                        return NvdCveResponse.model_validate_json(body)
                    except ValidationError:
                        raise NvdError("NVD response schema validation failed") from None
                if status not in RETRY_STATUS:
                    raise NvdError(f"NVD request failed: {reason}")
            if attempt < self._max_retries:
                backoff = 2 ** (attempt + 1)
                logger.warning("NVD request retry %d/%d after %ss (%s)",
                               attempt + 1, self._max_retries, backoff, reason)
                self._sleep(backoff)
        raise NvdError(f"NVD request failed after retries: {reason}")

    def iter_cves(self, params: dict) -> Iterator[dict]:
        """페이지를 순회하며 raw `cve` 객체를 반환."""
        start_index = 0
        for _ in range(self._max_pages):
            page = self._get({**params, "resultsPerPage": self._page_size, "startIndex": start_index})
            for item in page.vulnerabilities:
                yield item.cve
            got = len(page.vulnerabilities)
            start_index += got
            if got == 0 or start_index >= page.totalResults:
                return
        raise NvdError("NVD pagination exceeded max_pages safety limit")

    def fetch_product(
        self, product_key: str, last_mod_start: datetime | None, last_mod_end: datetime
    ) -> list[dict]:
        """제품 단위 CVE 조회. last_mod_start가 없으면 전체 이력, 있으면 증분(120일 구간 분할)."""
        # Rejected CVE는 정규화 단계에서 vulnStatus로 제외 (값 없는 파라미터 호환성 이슈 회피)
        base = {"virtualMatchString": virtual_match_string(product_key)}
        if last_mod_start is None:
            return list(self.iter_cves(base))
        out: list[dict] = []
        for ws, we in split_windows(last_mod_start, last_mod_end):
            out.extend(self.iter_cves({**base, "lastModStartDate": format_nvd_datetime(ws),
                                       "lastModEndDate": format_nvd_datetime(we)}))
        return out
