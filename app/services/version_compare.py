"""버전 비교.

원칙: 확신할 수 없으면 None(UNCOMPARABLE)을 반환하고, 호출자는 이를 '검토 필요'로 처리한다.

토큰화: 숫자열/문자열 단위로 분리 ('.', '-', '_', '(', ')', '+', '~', ' ' 는 구분자)
  "2.4.49" → [2, 4, 49]     "17.9.4a" → [17, 9, 4, 'a']     "15.2(7)e13" → [15, 2, 7, 'e', 13]
비교 규칙
  - 숫자 vs 숫자: 정수 비교
  - 문자 vs 문자: 둘 다 pre-release 어휘면 어휘 순서, 아니면 사전순
  - 숫자 vs 문자: 문자 쪽이 pre-release 어휘(alpha/beta/rc 등)면 숫자보다 작음, 그 외는 비교 불가
  - 한쪽이 먼저 끝남: 남은 토큰이 모두 0 → 같음 / pre-release 어휘로 시작 → 짧은 쪽이 큼 /
    그 외(숫자 또는 'a','p1' 같은 후속 릴리스 표기) → 긴 쪽이 큼
"""
from __future__ import annotations

import re

_TOKEN_RE = re.compile(r"\d+|[a-z]+")
_SEPARATORS_OK = re.compile(r"^[0-9a-z.\-_()+~ ]+$")

# 정식 릴리스보다 앞서는 표기 (작을수록 먼저)
PRE_RELEASE = {"dev": 0, "snapshot": 0, "alpha": 1, "beta": 2, "milestone": 3, "pre": 4, "preview": 4,
               "rc": 5, "cr": 5}
_PRE_WORDS = frozenset(PRE_RELEASE)
# 의미가 제품마다 다른 표기 (Tomcat '-M1' = milestone(선행), Cisco '15.2(4)M' = train(후속)) → 비교 불가
_AMBIGUOUS = frozenset({"m"})


def tokenize(v: str) -> list[int | str] | None:
    s = v.strip().lower()
    if not s or len(s) > 64 or not _SEPARATORS_OK.match(s):
        return None
    return [int(t) if t.isdigit() else t for t in _TOKEN_RE.findall(s)]


def _has_infix_alpha(tokens: list) -> bool:
    """숫자-문자-숫자 형태(예: 8u401 → [8,'u',401])의 벤더 고유 표기 여부 (pre-release 어휘 제외)."""
    return any(isinstance(tokens[i], str) and not _is_pre(tokens[i])
               and isinstance(tokens[i - 1], int) and isinstance(tokens[i + 1], int)
               for i in range(1, len(tokens) - 1))


def _is_pre(t) -> bool:
    return isinstance(t, str) and t in _PRE_WORDS


def compare_versions(a: str, b: str) -> int | None:
    """a<b → -1, a==b → 0, a>b → 1, 비교 불가 → None."""
    if a is None or b is None:
        return None
    if a.strip().lower() == b.strip().lower():
        return 0
    ta, tb = tokenize(a), tokenize(b)
    if not ta or not tb:
        return None
    # '8u401' vs '1.8.0' 처럼 표기 체계가 다르면 숫자만 비교해 오판할 수 있으므로 비교 불가
    for x, y in ((ta, tb), (tb, ta)):
        if _has_infix_alpha(x) and not any(isinstance(t, str) for t in y):
            return None
    for x, y in zip(ta, tb):
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        elif isinstance(x, str) and isinstance(y, str):
            if x != y:
                if _is_pre(x) and _is_pre(y):
                    return -1 if PRE_RELEASE[x] < PRE_RELEASE[y] else (1 if PRE_RELEASE[x] > PRE_RELEASE[y] else 0)
                if _is_pre(x) != _is_pre(y):
                    return -1 if _is_pre(x) else 1
                return -1 if x < y else 1
        else:
            s = x if isinstance(x, str) else y
            if not _is_pre(s):
                return None
            return -1 if isinstance(x, str) else 1
    if len(ta) == len(tb):
        return 0
    longer, sign = (ta, 1) if len(ta) > len(tb) else (tb, -1)
    rest = longer[min(len(ta), len(tb)):]
    if all(t == 0 for t in rest):
        return 0
    first = rest[0]
    if first in _AMBIGUOUS:
        return None
    if _is_pre(first):
        return -sign
    return sign


def in_range(version: str, *, start_incl: str | None = None, start_excl: str | None = None,
             end_incl: str | None = None, end_excl: str | None = None) -> bool | None:
    """NVD versionStart/End 조건 평가. 비교 불가 시 None."""
    checks = []
    if start_incl:
        checks.append((start_incl, lambda c: c >= 0))
    if start_excl:
        checks.append((start_excl, lambda c: c > 0))
    if end_incl:
        checks.append((end_incl, lambda c: c <= 0))
    if end_excl:
        checks.append((end_excl, lambda c: c < 0))
    result = True
    for bound, ok in checks:
        c = compare_versions(version, bound)
        if c is None:
            return None
        if not ok(c):
            result = False
    return result
