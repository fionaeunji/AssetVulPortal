"""자산-CVE 매칭 엔진 (DB 비의존 순수 로직).

Level 1: 자산 CPE ↔ NVD configurations(CPE Match + Version Range) 3값 논리 평가
  TRUE    → 취약 확정 (VULNERABLE)
  UNKNOWN → 검토 필요 (REVIEW)  예) 버전 비교 불가, 플랫폼(하드웨어/OS) 조건 확인 불가, 자산 CPE 속성 미기재
  FALSE   → 미해당
Level 2: CPE 없는 제품 → Vendor/Product/Version 기반 후보 CPE 제안 (자동 확정하지 않음)
"""
from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

from app.models.enums import MatchType
from app.services.cpe import ANY, CPE, NA, InvalidCPE, parse_cpe, unescape
from app.services.product_aliases import AliasBook, apply_version_rules
from app.services.version_compare import compare_versions, in_range


class Tri(Enum):
    TRUE = "TRUE"
    FALSE = "FALSE"
    UNKNOWN = "UNKNOWN"


def t_not(x: Tri) -> Tri:
    return {Tri.TRUE: Tri.FALSE, Tri.FALSE: Tri.TRUE, Tri.UNKNOWN: Tri.UNKNOWN}[x]


def t_combine(op: str, vals: Iterable[Tri]) -> Tri:
    vals = list(vals)
    if not vals:
        return Tri.FALSE
    if op == "AND":
        if any(v == Tri.FALSE for v in vals):
            return Tri.FALSE
        return Tri.UNKNOWN if any(v == Tri.UNKNOWN for v in vals) else Tri.TRUE
    if any(v == Tri.TRUE for v in vals):
        return Tri.TRUE
    return Tri.UNKNOWN if any(v == Tri.UNKNOWN for v in vals) else Tri.FALSE


ATTRS = ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other")


@dataclass(frozen=True)
class AssetCpe:
    product_id: int
    cpe: CPE
    source: str = "excel"   # excel | mapping

    @property
    def key(self) -> tuple[str, str, str]:
        return self.cpe.part, unescape(self.cpe.vendor), unescape(self.cpe.product)


@dataclass(frozen=True)
class MatchRow:
    """vulnerability_products 1행 (NVD cpeMatch)."""
    config_index: int
    config_operator: str | None
    config_negate: bool
    node_index: int
    node_operator: str
    node_negate: bool
    match_index: int
    vulnerable: bool
    criteria: str
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None

    @property
    def has_range(self) -> bool:
        return any((self.version_start_including, self.version_start_excluding,
                    self.version_end_including, self.version_end_excluding))

    def range_text(self) -> str:
        parts = []
        if self.version_start_including:
            parts.append(f"≥ {self.version_start_including}")
        if self.version_start_excluding:
            parts.append(f"> {self.version_start_excluding}")
        if self.version_end_including:
            parts.append(f"≤ {self.version_end_including}")
        if self.version_end_excluding:
            parts.append(f"< {self.version_end_excluding}")
        return ", ".join(parts)


@dataclass
class MatchEval:
    value: Tri
    product_id: int | None = None
    match_type: MatchType | None = None
    detail: str = ""


def _v(x: str) -> str:
    return unescape(x).lower()


def eval_match_single(row: MatchRow, crit: CPE, a: AssetCpe,
                      review_all_versions_parts: frozenset[str] = frozenset()) -> MatchEval:
    av = _v(a.cpe.version)
    cv = _v(crit.version)
    mt: MatchType
    # 1) 버전
    if cv == ANY:
        if row.has_range:
            if av in (ANY, NA, ""):
                return MatchEval(Tri.UNKNOWN, a.product_id, None, "자산 CPE에 버전이 없어 범위 비교 불가")
            r = in_range(av, start_incl=row.version_start_including, start_excl=row.version_start_excluding,
                         end_incl=row.version_end_including, end_excl=row.version_end_excluding)
            if r is None:
                return MatchEval(Tri.UNKNOWN, a.product_id, None,
                                 f"버전 비교 불가: 자산 {av} vs 범위 [{row.range_text()}]")
            if not r:
                return MatchEval(Tri.FALSE, a.product_id, None, f"범위 밖: {av} ∉ [{row.range_text()}]")
            mt, detail = MatchType.CPE_RANGE, f"범위 일치: {av} ∈ [{row.range_text()}]"
        else:
            if row.vulnerable and crit.part in review_all_versions_parts and av not in (ANY, NA, ""):
                # 정책(matching.review_all_versions_parts): NVD가 범위 없이 '모든 버전'으로 등록한 경우,
                # 빌드별 패치 여부가 갈리는 제품군(OS 등)은 자동 확정하지 않고 검토로 보냄
                return MatchEval(Tri.UNKNOWN, a.product_id, None,
                                 f"NVD가 버전 범위 없이 '모든 버전'으로 등록 — 자산 버전 {av} 의 패치 여부 확인 필요")
            mt, detail = MatchType.CPE_ALL_VERSIONS, "모든 버전 해당 (criteria version='*', 범위 조건 없음)"
    elif cv == NA:
        # CPE Name Matching(NISTIR 7696): criteria NA('-') 와 구체 버전은 DISJOINT(불일치)
        if av == ANY or av == "":
            return MatchEval(Tri.UNKNOWN, a.product_id, None, "자산 CPE에 버전이 없어 criteria '-' 와 비교 불가")
        if av != NA:
            return MatchEval(Tri.FALSE, a.product_id, None, f"criteria 버전 '-'(해당없음) ≠ 자산 버전 {av}")
        mt, detail = MatchType.CPE_EXACT, "버전 해당없음('-') 일치"
    else:
        if av in (ANY, NA, ""):
            return MatchEval(Tri.UNKNOWN, a.product_id, None, f"자산 CPE에 버전이 없어 {cv} 와 비교 불가")
        c = compare_versions(av, cv)
        if c is None:
            return MatchEval(Tri.UNKNOWN, a.product_id, None, f"버전 비교 불가: 자산 {av} vs {cv}")
        if c != 0:
            return MatchEval(Tri.FALSE, a.product_id, None, f"버전 불일치: {av} ≠ {cv}")
        mt, detail = MatchType.CPE_EXACT, f"버전 일치: {av} = {cv}"
    # 2) 기타 속성 (update, edition, target_sw ...)
    unknown = []
    for attr in ATTRS:
        c_attr, a_attr = _v(getattr(crit, attr)), _v(getattr(a.cpe, attr))
        if c_attr == ANY or c_attr == a_attr:
            continue
        if a_attr == ANY:
            unknown.append(f"{attr}={c_attr} (자산 미기재)")
            continue
        return MatchEval(Tri.FALSE, a.product_id, None, f"{attr} 불일치: {a_attr} ≠ {c_attr}")
    if unknown:
        return MatchEval(Tri.UNKNOWN, a.product_id, None, f"{detail}; 속성 확인 불가: {', '.join(unknown)}")
    return MatchEval(Tri.TRUE, a.product_id, mt, detail)


def eval_match(row: MatchRow, asset_cpes: list[AssetCpe],
               review_all_versions_parts: frozenset[str] = frozenset()) -> MatchEval:
    try:
        crit = parse_cpe(row.criteria)
    except InvalidCPE:
        return MatchEval(Tri.FALSE, detail="criteria 파싱 불가")
    key = (crit.part, unescape(crit.vendor), unescape(crit.product))
    cands = [a for a in asset_cpes if a.key == key]
    if not cands:
        if not row.vulnerable and not any(a.cpe.part == crit.part for a in asset_cpes):
            kind = {"h": "하드웨어", "o": "OS", "a": "애플리케이션"}[crit.part]
            return MatchEval(Tri.UNKNOWN, None, None,
                             f"플랫폼 조건 확인 불가: {kind} {key[1]}:{key[2]} 정보가 자산에 없음")
        return MatchEval(Tri.FALSE)
    evals = [eval_match_single(row, crit, a, review_all_versions_parts) for a in cands]
    for e in evals:
        if e.value == Tri.TRUE:
            return e
    for e in evals:
        if e.value == Tri.UNKNOWN:
            return e
    return evals[0]


class Verdict(str, Enum):
    VULNERABLE = "VULNERABLE"
    REVIEW = "REVIEW"
    NOT_AFFECTED = "NOT_AFFECTED"


@dataclass
class CveResult:
    cve_id: str
    verdict: Verdict
    product_id: int | None = None
    match_type: MatchType | None = None
    evidence: dict = field(default_factory=dict)
    review_reasons: list[str] = field(default_factory=list)


def evaluate_cve(cve_id: str, rows: list[MatchRow], asset_cpes: list[AssetCpe],
                 review_all_versions_parts: frozenset[str] = frozenset()) -> CveResult:
    configs: dict[int, dict[int, list[MatchRow]]] = {}
    for r in rows:
        configs.setdefault(r.config_index, {}).setdefault(r.node_index, []).append(r)
    review: list[str] = []
    review_pid = None
    for ci in sorted(configs):
        nodes = configs[ci]
        first = next(iter(nodes.values()))[0]
        node_vals, node_evals = [], []
        for ni in sorted(nodes):
            nrows = nodes[ni]
            evs = [(r, eval_match(r, asset_cpes, review_all_versions_parts)) for r in nrows]
            val = t_combine(nrows[0].node_operator, [e.value for _, e in evs])
            if nrows[0].node_negate:
                val = t_not(val)
            node_vals.append(val)
            node_evals.append(evs)
        cval = t_combine(first.config_operator or "OR", node_vals)
        if first.config_negate:
            cval = t_not(cval)
        if cval == Tri.TRUE:
            hit = next(((r, e) for evs in node_evals for r, e in evs
                        if r.vulnerable and e.value == Tri.TRUE), None)
            if hit is None:
                continue
            r, e = hit
            platform = [f"{pr.criteria} → {pe.detail or pe.value.value}" for evs in node_evals
                        for pr, pe in evs if not pr.vulnerable and pe.value == Tri.TRUE]
            evidence = {"configuration": ci, "config_operator": first.config_operator or "OR",
                        "criteria": r.criteria, "match_criteria_range": r.range_text() or None,
                        "rule": e.detail, "platform_conditions": platform or None}
            return CveResult(cve_id, Verdict.VULNERABLE, e.product_id, e.match_type, evidence)
        if cval == Tri.UNKNOWN:
            for evs in node_evals:
                for r, e in evs:
                    if e.value == Tri.UNKNOWN and e.detail:
                        review.append(f"[config {ci}] {r.criteria}: {e.detail}")
                        review_pid = review_pid or e.product_id
            if review_pid is None:
                review_pid = next((e.product_id for evs in node_evals for r, e in evs
                                   if r.vulnerable and e.product_id), None)
    if review:
        return CveResult(cve_id, Verdict.REVIEW, review_pid, None,
                         {"reasons": review[:10]}, review[:10])
    return CveResult(cve_id, Verdict.NOT_AFFECTED)


# ---------------------------------------------------------------------------
# Level 2: CPE 없는 제품의 후보 CPE (규칙 기반 점수)
# ---------------------------------------------------------------------------
SCORE_RULES = {
    "vendor_exact": 30, "vendor_alias": 20,
    "product_exact": 40, "product_alias": 25, "product_token_overlap": 10,  # nosec B105 - 점수 규칙명
    "version_decisive": 20, "alias_registered": 10,
}
MIN_CANDIDATE_SCORE = 50
MAX_CANDIDATES = 3


def _compact(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def _jaccard(a: str, b: str) -> float:
    ta, tb = set(filter(None, re.split(r"[_\-.]", a))), set(filter(None, re.split(r"[_\-.]", b)))
    return len(ta & tb) / len(ta | tb) if ta and tb else 0.0


_CPE_SAFE = re.compile(r"[^A-Za-z0-9._\-~]")


def cpe_escape(value: str) -> str:
    return _CPE_SAFE.sub(lambda m: "\\" + m.group(0), re.sub(r"\s+", "_", value.strip()))


@dataclass
class Candidate:
    part: str
    vendor: str
    product: str
    version: str | None
    update: str | None
    score: int
    breakdown: dict
    notes: list[str]

    @property
    def proposed_cpe(self) -> str:
        v = cpe_escape(self.version) if self.version else ANY
        u = cpe_escape(self.update) if self.update else ANY
        return f"cpe:2.3:{self.part}:{self.vendor}:{self.product}:{v}:{u}:*:*:*:*:*:*"


def generate_candidates(vendor_norm: str | None, product_norm: str | None, version: str | None,
                        aliases: AliasBook, dictionary: Iterable[tuple[str, str, str]],
                        rows_by_product: dict[tuple[str, str, str], list[MatchRow]]) -> list[Candidate]:
    """점수 규칙(SCORE_RULES)에 따라 후보를 산출. 합계 50점 이상, 상위 3개."""
    if not vendor_norm or not product_norm:
        return []
    found: dict[tuple[str, str, str], dict] = {}

    def bump(key, name):
        b = found.setdefault(key, {})
        b[name] = SCORE_RULES[name]

    for e in aliases.find(vendor_norm, product_norm):
        key = (e.cpe.part, e.cpe.vendor, e.cpe.product)
        bump(key, "vendor_exact" if _compact(vendor_norm) == _compact(e.cpe.vendor) else "vendor_alias")
        bump(key, "product_exact" if _compact(product_norm) == _compact(e.cpe.product) else "product_alias")
        bump(key, "alias_registered")
    cv, cp = _compact(vendor_norm), _compact(product_norm)
    for part, v, p in dictionary:
        if _compact(v) != cv:
            continue
        key = (part, v, p)
        if _compact(p) == cp:
            bump(key, "vendor_exact")
            bump(key, "product_exact")
        elif _jaccard(p, product_norm) >= 0.5:
            bump(key, "vendor_exact")
            bump(key, "product_token_overlap")

    out: list[Candidate] = []
    for (part, v, p), b in found.items():
        # 동일 항목의 exact/alias 중 높은 점수만 인정
        if "vendor_exact" in b:
            b.pop("vendor_alias", None)
        if "product_exact" in b:
            b.pop("product_alias", None)
            b.pop("product_token_overlap", None)
        elif "product_alias" in b:
            b.pop("product_token_overlap", None)
        entry = aliases.for_cpe(part, v, p)
        ver, upd, rule_note = apply_version_rules(entry, version)
        notes = [rule_note] if rule_note else []
        rows = rows_by_product.get((part, v, p), [])
        if ver and rows:
            probe = AssetCpe(0, CPE(part=part, vendor=v, product=p, version=cpe_escape(ver),
                                    update=cpe_escape(upd) if upd else ANY))
            decisive = any(eval_match(r, [probe]).value != Tri.UNKNOWN for r in rows if r.vulnerable)
            if decisive:
                b["version_decisive"] = SCORE_RULES["version_decisive"]
            else:
                notes.append("수집된 CVE 조건과 버전 비교 불가")
        elif not rows:
            notes.append("해당 제품의 수집 데이터 없음 — 승인 후 다음 수집에서 평가")
        score = sum(b.values())
        if score >= MIN_CANDIDATE_SCORE:
            out.append(Candidate(part, v, p, ver, upd, score, dict(b), notes))
    out.sort(key=lambda c: (-c.score, c.part, c.vendor, c.product))
    return out[:MAX_CANDIDATES]
