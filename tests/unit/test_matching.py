"""Phase 4: 버전 비교 / CPE 매칭 엔진 / Level 2 후보 테스트."""
from __future__ import annotations

import pytest

from app.models.enums import MatchType
from app.services.cpe import parse_cpe
from app.services.matching_engine import (
    SCORE_RULES,
    AssetCpe,
    MatchRow,
    Verdict,
    evaluate_cve,
    generate_candidates,
)
from app.services.normalizer import normalize_nvd_cve
from app.services.product_aliases import apply_version_rules, load_aliases
from app.services.version_compare import compare_versions, in_range
from tests.fakes import load_nvd_records

ALIASES = load_aliases()


# ---------------- 버전 비교 ----------------
@pytest.mark.parametrize("a,b,expected", [
    ("2.4.49", "2.4.50", -1), ("2.4.62", "2.4.49", 1), ("2.4", "2.4.0", 0),
    ("9.0.30", "9.0.31", -1), ("10.0.20348.2582", "10.0.20348.2655", -1),
    ("116.0.5845.96", "116.0.5845.187", -1),
    ("17.9.3", "17.9.4a", -1), ("17.9.4a", "17.9.4", 1), ("17.9.4", "17.9.4a", -1),
    ("2.0-beta9", "2.0", -1), ("2.0-rc1", "2.0-beta9", 1), ("11.0.0-M1", "11.0.0", None),
    ("15.2(7)e13", "15.2(7)e8", 1), ("8.9", "9.8", -1), ("V2.4.49", "2.4.49", None),
    ("19c", "19.3", None), ("2.4.x", "2.4.49", None), ("7.0 U3", "7.0", None),
    ("8u401", "1.8.0", None), ("1.8.0", "8u401", None),            # 표기 체계 다름 → 비교 불가
    ("15.2(7)e13", "15.2(7)e8", 1),                                 # 양쪽 모두 벤더 표기 → 비교
])
def test_compare_versions(a, b, expected):
    assert compare_versions(a, b) == expected


def test_in_range_boundaries():
    assert in_range("9.0.30", start_incl="9.0.0", end_excl="9.0.31") is True
    assert in_range("9.0.31", start_incl="9.0.0", end_excl="9.0.31") is False       # Excluding 경계
    assert in_range("9.0.31", start_incl="9.0.0", end_incl="9.0.31") is True        # Including 경계
    assert in_range("9.0.0", start_excl="9.0.0", end_incl="9.1") is False           # StartExcluding 경계
    assert in_range("9.0.0", start_incl="9.0.0") is True                            # StartIncluding 경계
    assert in_range("2.4.x", end_excl="2.4.50") is None                             # 비교 불가


# ---------------- CPE 매칭 (실제 NVD 레코드 사용) ----------------
def _rows(cve_id: str) -> list[MatchRow]:
    raw = next(r for r in load_nvd_records() if r["id"] == cve_id)
    rec = normalize_nvd_cve(raw)
    return [MatchRow(r.config_index, r.config_operator, r.config_negate, r.node_index, r.node_operator,
                     r.node_negate, r.match_index, r.vulnerable, r.criteria, r.version_start_including,
                     r.version_start_excluding, r.version_end_including, r.version_end_excluding)
            for r in rec.cpe_matches]


def _asset(*cpes: str) -> list[AssetCpe]:
    return [AssetCpe(i + 1, parse_cpe(c)) for i, c in enumerate(cpes)]


def test_cpe_exact_match():
    r = evaluate_cve("CVE-2021-41773", _rows("CVE-2021-41773"),
                     _asset("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.VULNERABLE and r.match_type == MatchType.CPE_EXACT
    assert r.evidence["criteria"] == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"


def test_exact_version_mismatch_not_affected():
    r = evaluate_cve("CVE-2021-41773", _rows("CVE-2021-41773"),
                     _asset("cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.NOT_AFFECTED


def test_version_range_match():
    r = evaluate_cve("CVE-2020-1938", _rows("CVE-2020-1938"),
                     _asset("cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.VULNERABLE and r.match_type == MatchType.CPE_RANGE
    assert "9.0.30" in r.evidence["rule"] and "< 9.0.31" in r.evidence["rule"]


@pytest.mark.parametrize("cve,cpe", [
    ("CVE-2020-1938", "cpe:2.3:a:apache:tomcat:9.0.31:*:*:*:*:*:*:*"),       # EndExcluding 경계
    ("CVE-2024-21762", "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*"),    # EndExcluding 경계
    ("CVE-2024-38063", "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:*:*"),
    ("CVE-2023-4863", "cpe:2.3:a:google:chrome:129.0.6668.58:*:*:*:*:*:*:*"),
])
def test_version_range_excluded(cve, cpe):
    assert evaluate_cve(cve, _rows(cve), _asset(cpe)).verdict == Verdict.NOT_AFFECTED


@pytest.mark.parametrize("cve,cpe", [
    ("CVE-2024-21762", "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*"),
    ("CVE-2023-20198", "cpe:2.3:o:cisco:ios_xe:17.9.3:*:*:*:*:*:*:*"),        # 17.9 ≤ v < 17.9.4a
    ("CVE-2024-38063", "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2582:*:*:*:*:*:*:*"),
    ("CVE-2021-44228", "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"),
    ("CVE-2024-6387", "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*"),       # EndIncluding 9.8
    ("CVE-2023-39417", "cpe:2.3:a:postgresql:postgresql:13.11:*:*:*:*:*:*:*"),
])
def test_version_range_vulnerable(cve, cpe):
    r = evaluate_cve(cve, _rows(cve), _asset(cpe))
    assert r.verdict == Verdict.VULNERABLE and r.match_type == MatchType.CPE_RANGE


def test_update_field_exact_match():
    vc = "cpe:2.3:a:vmware:vcenter_server:6.5:update1d:*:*:*:*:*:*"
    assert evaluate_cve("CVE-2021-21972", _rows("CVE-2021-21972"), _asset(vc)).verdict == Verdict.VULNERABLE
    other = "cpe:2.3:a:vmware:vcenter_server:6.5:update3q:*:*:*:*:*:*"
    assert evaluate_cve("CVE-2021-21972", _rows("CVE-2021-21972"), _asset(other)).verdict == Verdict.NOT_AFFECTED


def test_unknown_update_goes_to_review_not_vulnerable():
    # 자산 CPE에 update 미기재('*') → criteria 가 update 를 특정하면 확정 불가
    vc = "cpe:2.3:a:vmware:vcenter_server:6.5:*:*:*:*:*:*:*"
    r = evaluate_cve("CVE-2021-21972", _rows("CVE-2021-21972"), _asset(vc))
    assert r.verdict == Verdict.REVIEW and r.review_reasons


def test_and_configuration_with_unknown_hardware_platform_is_review():
    # CVE-2023-27997: FortiOS (vulnerable) AND FortiGate 6000/7000 하드웨어(non-vulnerable) 구성
    rows = [r for r in _rows("CVE-2023-27997") if r.config_operator == "AND"]
    vuln_node = [r for r in rows if r.vulnerable and r.version_start_including == "6.0.12"]
    assert vuln_node
    r = evaluate_cve("CVE-2023-27997", rows, _asset("cpe:2.3:o:fortinet:fortios:6.0.13:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.REVIEW
    assert any("플랫폼 조건 확인 불가" in x for x in r.review_reasons)


def test_and_configuration_with_platform_present_is_vulnerable():
    rows = [r for r in _rows("CVE-2023-27997") if r.config_operator == "AND"]
    r = evaluate_cve("CVE-2023-27997", rows, _asset("cpe:2.3:o:fortinet:fortios:6.0.13:*:*:*:*:*:*:*",
                                                    "cpe:2.3:h:fortinet:fortigate_6000:-:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.VULNERABLE and r.evidence["platform_conditions"]


def test_and_configuration_with_other_hardware_is_not_affected():
    rows = [r for r in _rows("CVE-2023-27997") if r.config_operator == "AND"]
    r = evaluate_cve("CVE-2023-27997", rows, _asset("cpe:2.3:o:fortinet:fortios:6.0.13:*:*:*:*:*:*:*",
                                                    "cpe:2.3:h:fortinet:fortigate_100f:-:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.NOT_AFFECTED


def test_uncomparable_version_is_review():
    rows = [MatchRow(0, None, False, 0, "OR", False, 0, True, "cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
                     version_start_including="19.3", version_end_including="19.14")]
    r = evaluate_cve("CVE-2099-0001", rows, _asset("cpe:2.3:a:oracle:database_server:19c:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.REVIEW


def test_asset_cpe_without_version_is_review():
    r = evaluate_cve("CVE-2020-1938", _rows("CVE-2020-1938"),
                     _asset("cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.REVIEW


def test_negated_node():
    rows = [MatchRow(0, "AND", False, 0, "OR", False, 0, True, "cpe:2.3:a:x:app:*:*:*:*:*:*:*:*"),
            MatchRow(0, "AND", False, 1, "OR", True, 0, False, "cpe:2.3:o:x:os:1.0:*:*:*:*:*:*:*")]
    assert evaluate_cve("CVE-2099-0002", rows, _asset("cpe:2.3:a:x:app:1:*:*:*:*:*:*:*",
                                                      "cpe:2.3:o:x:os:2.0:*:*:*:*:*:*:*")).verdict == Verdict.VULNERABLE
    assert evaluate_cve("CVE-2099-0002", rows, _asset("cpe:2.3:a:x:app:1:*:*:*:*:*:*:*",
                                                      "cpe:2.3:o:x:os:1.0:*:*:*:*:*:*:*")).verdict == Verdict.NOT_AFFECTED


def test_other_product_not_matched():
    r = evaluate_cve("CVE-2021-41773", _rows("CVE-2021-41773"),
                     _asset("cpe:2.3:a:nginx:nginx:1.20:*:*:*:*:*:*:*"))
    assert r.verdict == Verdict.NOT_AFFECTED


# ---------------- Level 2 후보 ----------------
def test_java_version_rule():
    e = ALIASES.for_cpe("a", "oracle", "jdk")
    assert apply_version_rules(e, "8u401")[:2] == ("1.8.0", "update401")
    assert apply_version_rules(e, "17.0.2")[:2] == ("17.0.2", None)


def test_candidate_score_is_rule_based():
    dictionary = {("a", "apache", "tomcat")}
    rows = {("a", "apache", "tomcat"): _rows("CVE-2020-1938")}
    cands = generate_candidates("apache", "tomcat", "8.5.50", ALIASES, dictionary, rows)
    c = cands[0]
    assert (c.part, c.vendor, c.product) == ("a", "apache", "tomcat")
    assert c.breakdown == {"vendor_exact": 30, "product_exact": 40, "alias_registered": 10,
                           "version_decisive": 20}
    assert c.score == sum(c.breakdown.values()) == 100
    assert c.proposed_cpe == "cpe:2.3:a:apache:tomcat:8.5.50:*:*:*:*:*:*:*"


def test_candidate_alias_and_version_rule():
    cands = generate_candidates("oracle", "java_se", "8u401", ALIASES, set(), {})
    c = cands[0]
    assert (c.vendor, c.product, c.version, c.update) == ("oracle", "jdk", "1.8.0", "update401")
    assert c.breakdown == {"vendor_exact": 30, "product_alias": 25, "alias_registered": 10}
    assert any("수집 데이터 없음" in n for n in c.notes)


def test_no_candidate_for_unknown_product():
    assert generate_candidates("example", "mail_gateway", "3.1", ALIASES, {("a", "apache", "tomcat")}, {}) == []


def test_candidate_escapes_unsafe_version():
    c = generate_candidates("vmware", "esxi", "7.0 U3", ALIASES, set(), {})[0]
    assert c.proposed_cpe.startswith("cpe:2.3:o:vmware:esxi:7.0:update3:")
    parse_cpe(c.proposed_cpe)


def test_score_rules_documented_total():
    # 최대 점수 = vendor_exact + product_exact + version_decisive + alias_registered = 100
    assert SCORE_RULES["vendor_exact"] + SCORE_RULES["product_exact"] + \
        SCORE_RULES["version_decisive"] + SCORE_RULES["alias_registered"] == 100


def test_na_criteria_version_is_disjoint_with_specific_version():
    # 실제 NVD CVE-1999-0289: cpe:2.3:a:apache:http_server:-:... (버전 해당없음) — 구체 버전 자산과는 불일치
    rows = [MatchRow(0, None, False, 0, "OR", False, 0, True, "cpe:2.3:a:apache:http_server:-:*:*:*:*:*:*:*")]
    assert evaluate_cve("CVE-1999-0289", rows,
                        _asset("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")).verdict == Verdict.NOT_AFFECTED
    assert evaluate_cve("CVE-1999-0289", rows,
                        _asset("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")).verdict == Verdict.REVIEW


def test_rhel_and_java_version_rules_follow_nvd_notation():
    assert apply_version_rules(ALIASES.for_cpe("o", "redhat", "enterprise_linux"), "8.10")[:2] == ("8.0", None)
    c = generate_candidates("oracle", "java_se", "8u401", ALIASES, set(), {})[0]
    assert c.proposed_cpe.startswith("cpe:2.3:a:oracle:jdk:1.8.0:update401:")


def test_vendor_version_notation_not_scored_as_decisive():
    # 'java_se' 제품 사전에 1.8.0 계열 조건만 있을 때 8u401 은 비교 불가 → 버전 점수 없음
    rows = {("a", "oracle", "java_se"): [MatchRow(0, None, False, 0, "OR", False, 0, True,
                                                  "cpe:2.3:a:oracle:java_se:1.8.0:*:*:*:*:*:*:*")]}
    c = next(x for x in generate_candidates("oracle", "java_se", "8u401", ALIASES,
                                            {("a", "oracle", "java_se")}, rows) if x.product == "java_se")
    assert "version_decisive" not in c.breakdown


# ---------------- '모든 버전' 등록 CVE (사용자 결정: OS만 검토) ----------------
OS_PARTS = frozenset({"o"})


def test_os_all_versions_goes_to_review():
    # 실제 NVD CVE-2022-26937: cpe:2.3:o:microsoft:windows_server_2022:*:... (범위 없음)
    rows = _rows("CVE-2022-26937")
    win = _asset("cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:*:*")
    r = evaluate_cve("CVE-2022-26937", rows, win, OS_PARTS)
    assert r.verdict == Verdict.REVIEW and any("모든 버전" in x for x in r.review_reasons)
    # 정책에서 제외하면 NVD 그대로 자동 확정
    assert evaluate_cve("CVE-2022-26937", rows, win, frozenset()).match_type == MatchType.CPE_ALL_VERSIONS


def test_application_all_versions_still_confirmed():
    rows = [MatchRow(0, None, False, 0, "OR", False, 0, True, "cpe:2.3:a:x:app:*:*:*:*:*:*:*:*")]
    r = evaluate_cve("CVE-2099-0003", rows, _asset("cpe:2.3:a:x:app:1.2:*:*:*:*:*:*:*"), OS_PARTS)
    assert r.verdict == Verdict.VULNERABLE and r.match_type == MatchType.CPE_ALL_VERSIONS


def test_os_all_versions_as_platform_condition_still_matches():
    # 'running on' 플랫폼(비취약) 조건의 OS:* 는 검토 대상이 아님
    rows = [MatchRow(0, "AND", False, 0, "OR", False, 0, True, "cpe:2.3:a:x:app:1.2:*:*:*:*:*:*:*"),
            MatchRow(0, "AND", False, 1, "OR", False, 0, False, "cpe:2.3:o:x:os:*:*:*:*:*:*:*:*")]
    r = evaluate_cve("CVE-2099-0004", rows, _asset("cpe:2.3:a:x:app:1.2:*:*:*:*:*:*:*",
                                                   "cpe:2.3:o:x:os:5.0:*:*:*:*:*:*:*"), OS_PARTS)
    assert r.verdict == Verdict.VULNERABLE
