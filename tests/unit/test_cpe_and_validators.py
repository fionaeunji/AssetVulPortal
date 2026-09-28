from __future__ import annotations

import pytest

from app.security.validators import (
    ValidationError,
    clean_text,
    validate_cve_id,
    validate_cvss,
    validate_ip,
    validate_probability,
)
from app.services.cpe import InvalidCPE, parse_cpe, try_parse_cpe, unescape


def test_parse_valid_cpe():
    c = parse_cpe("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
    assert (c.part, c.vendor, c.product, c.version, c.update) == ("a", "apache", "http_server", "2.4.49", "*")
    assert c.product_key == "a:apache:http_server"
    assert c.to_string() == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_parse_escaped_cpe():
    c = parse_cpe(r"cpe:2.3:o:siemens:simatic_s7-1500_cpu_1518f-4_pn\/dp_mfp_firmware:*:*:*:*:*:*:*:*")
    assert unescape(c.product) == "simatic_s7-1500_cpu_1518f-4_pn/dp_mfp_firmware"
    c2 = parse_cpe(r"cpe:2.3:a:vendor:prod\:uct:1.0:*:*:*:*:*:*:*")
    assert unescape(c2.product) == "prod:uct"


def test_parse_update_field():
    c = parse_cpe("cpe:2.3:a:oracle:jdk:1.8.0:update_401:*:*:*:*:*:*")
    assert c.update == "update_401"


@pytest.mark.parametrize("bad", [
    "", "cpe:2.3:a:apache", "cpe:2.2:a:apache:http_server:2.4:*:*:*:*:*:*:*",
    "cpe:2.3:x:apache:http_server:2.4:*:*:*:*:*:*:*",          # 잘못된 part
    "cpe:2.3:a:*:http_server:2.4:*:*:*:*:*:*:*",               # vendor ANY
    "cpe:2.3:a:apache:http server:2.4:*:*:*:*:*:*:*",          # 공백
    "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*:extra",    # 필드 초과
    "cpe:2.3:a:apache:<script>:2.4:*:*:*:*:*:*:*",             # 미이스케이프 특수문자
    "cpe:2.3:a:아파치:http_server:2.4:*:*:*:*:*:*:*",           # non-ASCII
    "cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:\\",         # dangling escape
    "cpe:2.3:a:apache:http_server:" + "9" * 600 + ":*:*:*:*:*:*:*",
])
def test_invalid_cpe(bad):
    with pytest.raises(InvalidCPE):
        parse_cpe(bad)


def test_try_parse_cpe_returns_error():
    cpe, err = try_parse_cpe("not-a-cpe")
    assert cpe is None and err
    assert try_parse_cpe(None) == (None, None)


@pytest.mark.parametrize("good", ["CVE-2021-44228", "cve-2024-3094", " CVE-2026-1234567 "])
def test_valid_cve_id(good):
    assert validate_cve_id(good).startswith("CVE-")


@pytest.mark.parametrize("bad", ["CVE-21-44228", "CVE-2021-123", "CVE-2021-44228; DROP TABLE",
                                 "2021-44228", "CVE-2021-44228\nCVE-2021-1", "CVE-1899-1234", "", None])
def test_invalid_cve_id(bad):
    with pytest.raises(ValidationError):
        validate_cve_id(bad)


@pytest.mark.parametrize("bad", [-0.1, 10.1, "abc", float("nan"), float("inf"), None])
def test_invalid_cvss(bad):
    with pytest.raises(ValidationError):
        validate_cvss(bad)


def test_valid_cvss():
    assert validate_cvss("9.8") == 9.8 and validate_cvss(0) == 0.0 and validate_cvss(10) == 10.0


@pytest.mark.parametrize("bad", [-0.01, 1.01, "x", float("nan"), None])
def test_invalid_epss(bad):
    with pytest.raises(ValidationError):
        validate_probability(bad)


def test_valid_epss():
    assert validate_probability("0.3") == 0.3


@pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0", "abc", "10.0.0.1/24", "", "1.1.1.1; rm"])
def test_invalid_ip(bad):
    with pytest.raises(ValidationError):
        validate_ip(bad)


def test_valid_ip():
    assert validate_ip(" 10.0.0.1 ") == "10.0.0.1"
    assert validate_ip("2001:db8::1") == "2001:db8::1"


def test_clean_text():
    assert clean_text("  a\x00b‮  ", 10) == "ab"
    assert clean_text("   ", 10) is None
    with pytest.raises(ValidationError):
        clean_text("x" * 11, 10)
