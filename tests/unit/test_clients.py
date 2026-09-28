"""NVD / EPSS / KEV Client, Normalizer, Bundle 단위 테스트 (네트워크 미사용)."""
from __future__ import annotations

import gzip
import json
from datetime import date, datetime, timedelta, timezone

import httpx
import pytest

from app.schemas.bundle import BundlePayload, CvssMetric
from app.services.bundle import BundleError, build_bundle, load_bundle_bytes
from app.services.epss_client import EpssClient, EpssError, parse_epss_csv_gz
from app.services.http_client import DisallowedDestination, build_client
from app.services.kev_client import KevError, parse_kev
from app.services.normalizer import NormalizationError, normalize_nvd_cve, select_cvss
from app.services.nvd_client import (
    NvdClient,
    NvdError,
    format_nvd_datetime,
    split_windows,
    virtual_match_string,
)
from tests.fakes import FIX, FakeExternal, load_nvd_records

PRIORITY = ["3.1:Primary", "3.1:Secondary", "4.0:Primary", "4.0:Secondary", "3.0:Primary", "3.0:Secondary"]


def _nvd(fake, **kw):
    sleeps = []
    client = NvdClient(build_client(transport=fake.transport()), kw.pop("api_key", None),
                       sleep=sleeps.append, **kw)
    return client, sleeps


def _raw(cve_id):
    return next(r for r in load_nvd_records() if r["id"] == cve_id)


# ---------------- NVD ----------------
def test_nvd_pagination_collects_all_pages():
    fake = FakeExternal()
    client, _ = _nvd(fake, page_size=1)
    got = client.fetch_product("a:apache:http_server", None, datetime.now(timezone.utc))
    ids = sorted(r["id"] for r in got)
    assert ids == ["CVE-2021-41773", "CVE-2021-42013"]
    assert len(fake.calls) == 2
    assert fake.calls[0].url.params["virtualMatchString"] == virtual_match_string("a:apache:http_server")


def test_nvd_retry_then_success_and_rate_limit_sleep():
    fake = FakeExternal()
    fake.nvd_status_sequence = [503, 403, 200]
    client, sleeps = _nvd(fake)
    got = client.fetch_product("a:apache:http_server", None, datetime.now(timezone.utc))
    assert len(got) == 2
    assert 2 in sleeps and 4 in sleeps   # 지수 Backoff


def test_nvd_non_retryable_error_raises_without_secret():
    fake = FakeExternal()
    fake.nvd_status_sequence = [404]
    client, _ = _nvd(fake, api_key="SUPER-SECRET-KEY-123")
    with pytest.raises(NvdError) as ei:
        client.fetch_product("a:apache:http_server", None, datetime.now(timezone.utc))
    assert "SUPER-SECRET" not in str(ei.value)
    assert fake.calls[0].headers["apiKey"] == "SUPER-SECRET-KEY-123"


def test_nvd_invalid_schema_raises():
    t = httpx.MockTransport(lambda r: httpx.Response(200, json={"unexpected": True}))
    client = NvdClient(build_client(transport=t), sleep=lambda s: None)
    with pytest.raises(NvdError):
        list(client.iter_cves({}))


def test_nvd_incremental_windows_split_120_days():
    fake = FakeExternal()
    client, _ = _nvd(fake)
    end = datetime(2026, 9, 28, tzinfo=timezone.utc)
    client.fetch_product("a:apache:http_server", end - timedelta(days=300), end)
    lm = [(c.url.params["lastModStartDate"], c.url.params["lastModEndDate"]) for c in fake.calls]
    assert len(lm) == 3
    assert lm[-1][1] == "2026-09-28T00:00:00.000+00:00"
    assert split_windows(end, end) == []
    assert format_nvd_datetime(datetime(2026, 1, 1, 9, tzinfo=timezone(timedelta(hours=9)))) == \
        "2026-01-01T00:00:00.000+00:00"


def test_http_client_blocks_non_allowlisted_destination():
    with build_client(transport=httpx.MockTransport(lambda r: httpx.Response(200))) as c:
        with pytest.raises(DisallowedDestination):
            c.get("https://evil.example.com/steal")
        with pytest.raises(DisallowedDestination):
            c.get("http://services.nvd.nist.gov/rest/json/cves/2.0")


# ---------------- Normalizer ----------------
def test_normalize_real_record():
    rec = normalize_nvd_cve(_raw("CVE-2021-41773"))
    assert rec.cve_id == "CVE-2021-41773"
    assert rec.published_at == datetime(2021, 10, 5, 9, 15, 7, 593000, tzinfo=timezone.utc)
    assert rec.nvd_cisa_exploit_add == date(2021, 11, 3)
    assert any(r.criteria == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*" for r in rec.cpe_matches)
    chosen = select_cvss(rec.cvss_metrics, PRIORITY)
    assert (chosen.version, chosen.type, chosen.score, chosen.source) == ("3.1", "Primary", 9.8, "nvd@nist.gov")


def test_normalize_preserves_version_ranges_and_and_config():
    rec = normalize_nvd_cve(_raw("CVE-2023-27997"))
    rng = [r for r in rec.cpe_matches if r.version_start_including == "6.0.12"]
    assert rng and rng[0].version_end_including == "6.0.16"
    assert any(r.config_operator == "AND" and not r.vulnerable for r in rec.cpe_matches)


def test_normalize_awaiting_analysis_without_configurations():
    rec = normalize_nvd_cve(_raw("CVE-2026-20001"))
    assert rec.cpe_matches == [] and rec.vuln_status == "Awaiting Analysis"


def test_normalize_rejected_and_invalid():
    raw = dict(_raw("CVE-2021-41773"), vulnStatus="Rejected")
    assert normalize_nvd_cve(raw) is None
    with pytest.raises(NormalizationError):
        normalize_nvd_cve(dict(_raw("CVE-2021-41773"), id="CVE-XXXX-1"))
    bad = json.loads(json.dumps(_raw("CVE-2021-41773")))
    bad["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] = 15.0
    with pytest.raises(NormalizationError):
        normalize_nvd_cve(bad)


def test_select_cvss_priority_fallbacks():
    m = [CvssMetric(version="4.0", type="Secondary", source="cna", score=9.3, vector="CVSS:4.0/x"),
         CvssMetric(version="3.1", type="Secondary", source="cna", score=8.1, vector="CVSS:3.1/x")]
    assert select_cvss(m, PRIORITY).score == 8.1        # v3.1 CNA 가 v4.0 보다 우선
    assert select_cvss(m[:1], PRIORITY).score == 9.3    # v3.1 없으면 v4.0
    assert select_cvss([], PRIORITY) is None


# ---------------- EPSS ----------------
def test_epss_api_parse():
    fake = FakeExternal(epss={"CVE-2021-41773": (0.94, 0.999)})
    recs = EpssClient(build_client(transport=fake.transport())).fetch_api(
        ["CVE-2021-41773", "CVE-2099-0001"])
    assert len(recs) == 1 and recs[0].epss == 0.94 and recs[0].score_date == date(2026, 9, 27)


def test_epss_api_batches_of_100():
    ids = [f"CVE-2020-{10000 + i}" for i in range(250)]
    fake = FakeExternal(epss={i: (0.1, 0.5) for i in ids})
    recs = EpssClient(build_client(transport=fake.transport())).fetch_api(ids)
    assert len(recs) == 250 and len(fake.calls) == 3


def test_epss_invalid_values_skipped():
    t = httpx.MockTransport(lambda r: httpx.Response(200, json={"data": [
        {"cve": "CVE-2021-1111", "epss": "1.7", "percentile": "0.5", "date": "2026-09-27"},
        {"cve": "BAD", "epss": "0.1", "percentile": "0.5", "date": "2026-09-27"},
        {"cve": "CVE-2021-2222", "epss": "0.2", "percentile": "0.5", "date": "2026-09-27"}]}))
    recs = EpssClient(build_client(transport=t)).fetch_api(["CVE-2021-1111", "CVE-2021-2222"])
    assert [r.cve_id for r in recs] == ["CVE-2021-2222"]


def test_epss_csv_parse_and_filter():
    fake = FakeExternal(epss={"CVE-2021-41773": (0.5, 0.9), "CVE-2020-1938": (0.9, 0.99)})
    recs = EpssClient(build_client(transport=fake.transport())).fetch_csv({"CVE-2020-1938"})
    assert [(r.cve_id, r.epss, r.score_date) for r in recs] == [("CVE-2020-1938", 0.9, date(2026, 9, 27))]


def test_epss_csv_errors():
    with pytest.raises(EpssError):
        parse_epss_csv_gz(b"not gzip")
    with pytest.raises(EpssError):
        parse_epss_csv_gz(gzip.compress(b"cve,epss,percentile\nCVE-2021-1,0.1,0.2"))  # score_date 없음


# ---------------- KEV ----------------
def test_kev_parse_fixture():
    version, recs = parse_kev((FIX / "kev_sample.json").read_bytes())
    assert version == "2026.09.27"
    by = {r.cve_id: r for r in recs}
    assert by["CVE-2021-44228"].date_added == date(2021, 12, 10)


def test_kev_invalid():
    with pytest.raises(KevError):
        parse_kev(b"<html>")
    with pytest.raises(KevError):
        parse_kev(b'{"vulnerabilities": "x"}')


# ---------------- Bundle ----------------
def _bundle(key=None):
    payload = BundlePayload(vulnerabilities=[normalize_nvd_cve(_raw("CVE-2021-41773"))])
    return build_bundle(payload, [], collector="test", hmac_key=key)


def test_bundle_roundtrip():
    b = _bundle()
    again = load_bundle_bytes(b.model_dump_json().encode())
    assert again.manifest.payload_sha256 == b.manifest.payload_sha256


def test_bundle_tamper_detected():
    data = json.loads(_bundle().model_dump_json())
    data["payload"]["vulnerabilities"][0]["cvss_metrics"][0]["score"] = 1.0
    with pytest.raises(BundleError, match="hash mismatch"):
        load_bundle_bytes(json.dumps(data).encode())


def test_bundle_hmac():
    key = "k" * 32
    b = _bundle(key)
    assert load_bundle_bytes(b.model_dump_json().encode(), key)
    with pytest.raises(BundleError, match="HMAC"):
        load_bundle_bytes(b.model_dump_json().encode(), "other-key-" * 4)
    with pytest.raises(BundleError, match="HMAC"):
        load_bundle_bytes(_bundle().model_dump_json().encode(), key)   # 서명 없는 Bundle 거부


def test_bundle_rejects_unknown_fields_and_bad_values():
    data = json.loads(_bundle().model_dump_json())
    data["payload"]["evil"] = 1
    with pytest.raises(BundleError):
        load_bundle_bytes(json.dumps(data).encode())


def test_oversized_response_rejected():
    from app.services.http_client import ResponseTooLarge, get_limited
    big = b"x" * 2048
    t = httpx.MockTransport(lambda r: httpx.Response(200, content=big))
    with build_client(transport=t) as c:
        with pytest.raises(ResponseTooLarge):
            get_limited(c, "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                        limit=1024)


# ---------------- TLS (회사 SSL 검사 환경 대응) ----------------
def test_ssl_context_verifies_certificates():
    import ssl

    from app.services.http_client import make_ssl_context
    ctx = make_ssl_context("system")
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname
    assert make_ssl_context("certifi") is True
    with pytest.raises(ValueError):
        make_ssl_context("none")


def test_nvd_cert_error_not_retried():
    def handler(req):
        raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
                                 "self-signed certificate in certificate chain")
    sleeps = []
    client = NvdClient(build_client(transport=httpx.MockTransport(handler)), sleep=sleeps.append)
    with pytest.raises(NvdError, match="certificate verification failed"):
        client.fetch_product("a:apache:http_server", None, datetime.now(timezone.utc))
    assert not any(s >= 2 for s in sleeps)   # Backoff 재시도 없음


# ---------------- Redirect / EPSS fallback ----------------
def test_redirect_followed_only_to_allowlisted_host():
    from app.services.http_client import DisallowedDestination, get_limited

    def handler(req):
        if req.url.path.endswith(".csv.gz") and req.url.host == "epss.empiricalsecurity.com":
            return httpx.Response(302, headers={"location": "https://api.first.org/data/v1/epss"})
        return httpx.Response(200, content=b"ok")
    with build_client(transport=httpx.MockTransport(handler)) as c:
        assert get_limited(c, "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
                           limit=100) == (200, b"ok")

    def evil(req):
        return httpx.Response(302, headers={"location": "https://evil.example.net/steal"})
    with build_client(transport=httpx.MockTransport(evil)) as c:
        with pytest.raises(DisallowedDestination, match="evil.example.net"):
            get_limited(c, "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", limit=100)


def test_epss_csv_failure_falls_back_to_api():
    from app.services.collector import collect
    fake = FakeExternal(epss={"CVE-2021-41773": (0.9, 0.99)})
    orig = fake.handle

    def handler(req):
        if req.url.host == "epss.empiricalsecurity.com":
            return httpx.Response(302, headers={"location": "https://blocked.example.org/x"})
        return orig(req)
    with build_client(transport=httpx.MockTransport(handler)) as http:
        b = collect([], {"CVE-2021-41773"}, http=http, nvd_api_key=None, epss_csv_threshold=1,
                    nvd_client=NvdClient(http, sleep=lambda s: None))
    src = {s.source: s for s in b.manifest.sources}["EPSS"]
    assert src.status == "success" and "blocked.example.org" in src.error and "fell back" in src.error
    assert b.payload.epss[0].epss == 0.9
