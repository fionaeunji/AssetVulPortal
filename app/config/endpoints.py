"""외부 통신 Endpoint Allowlist (SSRF 방지).

외부 요청 URL은 이 모듈의 상수로만 구성한다. 사용자 입력으로 URL/Host를 받지 않는다.
Endpoint 변경이 필요하면 이 파일을 수정하고 docs/external_communications.md 를 갱신한다.
"""
from __future__ import annotations

from types import MappingProxyType
from urllib.parse import urlsplit

ENDPOINTS = MappingProxyType(
    {
        "nvd_cves": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "epss_api": "https://api.first.org/data/v1/epss",
        "epss_csv": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        "kev_json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    }
)

ALLOWED_HOSTS = frozenset(urlsplit(u).hostname for u in ENDPOINTS.values())


def is_allowed_url(url: str) -> bool:
    """https + allowlist Host + 기본 포트만 허용."""
    parts = urlsplit(url)
    return (
        parts.scheme == "https"
        and parts.hostname in ALLOWED_HOSTS
        and parts.port in (None, 443)
        and not parts.username
        and not parts.password
    )
