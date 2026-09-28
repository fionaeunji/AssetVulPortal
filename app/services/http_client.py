"""외부 통신용 httpx Client (SSRF 방지 + 목적지 기록).

- 요청 직전 URL이 Allowlist(app/config/endpoints.py)에 있는지 재검증
- Redirect 자동 추적 금지
- 실제 호출한 목적지(scheme/host/port/path)를 기록 → 외부 통신 목록 실측 근거
- 사내 Proxy/사설 CA는 httpx 표준 환경변수(HTTPS_PROXY, SSL_CERT_FILE)로 설정 (trust_env)
"""
from __future__ import annotations

import threading
from urllib.parse import urlsplit

import httpx

from app.config.endpoints import is_allowed_url

USER_AGENT = "VulPortal-PoC/0.1 (+internal vulnerability management)"
DEFAULT_TIMEOUT = httpx.Timeout(30.0, connect=10.0)


class DisallowedDestination(RuntimeError):
    pass


class DestinationRecorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: dict[tuple[str, str, int, str], int] = {}

    def record(self, url: httpx.URL) -> None:
        key = (url.scheme, url.host, url.port or 443, url.path)
        with self._lock:
            self._seen[key] = self._seen.get(key, 0) + 1

    def as_list(self) -> list[dict]:
        with self._lock:
            return [
                {"scheme": s, "host": h, "port": p, "path": path, "requests": n}
                for (s, h, p, path), n in sorted(self._seen.items())
            ]


def build_client(
    recorder: DestinationRecorder | None = None,
    transport: httpx.BaseTransport | None = None,
) -> httpx.Client:
    def _on_request(request: httpx.Request) -> None:
        url = str(request.url.copy_with(query=None))
        if not is_allowed_url(url):
            host = urlsplit(url).hostname
            raise DisallowedDestination(f"destination not in allowlist: {host}")
        if recorder is not None:
            recorder.record(request.url)

    return httpx.Client(
        timeout=DEFAULT_TIMEOUT,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
        event_hooks={"request": [_on_request]},
        transport=transport,
    )


class ResponseTooLarge(RuntimeError):
    pass


def get_limited(client: httpx.Client, url: str, *, limit: int, params: dict | None = None,
                headers: dict | None = None) -> tuple[int, bytes]:
    """스트리밍으로 읽으며 크기 제한 초과 시 즉시 중단 (메모리 고갈 방지). 200 이외는 본문을 읽지 않음."""
    with client.stream("GET", url, params=params, headers=headers) as resp:
        if resp.status_code != 200:
            return resp.status_code, b""
        declared = resp.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ResponseTooLarge("response exceeds size limit")
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf.extend(chunk)
            if len(buf) > limit:
                raise ResponseTooLarge("response exceeds size limit")
        return 200, bytes(buf)
