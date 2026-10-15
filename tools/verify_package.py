"""(VDI) 반입 패키지 무결성 검증 — 표준 라이브러리만 사용, 설치 전에 실행.

사용 (패키지 폴더에서):
    python -I tools\\verify_package.py

SHA256SUMS.txt 에 적힌 모든 파일의 해시를 확인하고, 누락·변조·목록에 없는 추가 파일을 보고한다.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

SUMS_NAME = "SHA256SUMS.txt"
# 반입 후 VDI에서 생기는 파일/폴더 (검증 대상 아님)
LOCAL_ONLY = {".env", ".venv", "data", "__pycache__", ".pytest_cache"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def read_sums(sums: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for n, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        digest, sep, rel = line.partition("  ")
        if not sep or len(digest) != 64 or not rel or rel.startswith(("/", "\\")) or ".." in Path(rel).parts:
            raise ValueError(f"{SUMS_NAME} {n}행 형식 오류")
        out[rel] = digest.lower()
    return out


def verify(root: Path) -> list[str]:
    """문제 목록을 반환 (빈 목록 = 정상)."""
    sums = root / SUMS_NAME
    if not sums.is_file():
        return [f"{SUMS_NAME} 없음"]
    expected = read_sums(sums)
    problems: list[str] = []
    for rel, digest in sorted(expected.items()):
        p = root / rel
        if not p.is_file():
            problems.append(f"누락: {rel}")
        elif sha256_file(p) != digest:
            problems.append(f"해시 불일치(변조/손상): {rel}")
    for p in sorted(root.rglob("*")):
        if not p.is_file() or p == sums:
            continue
        rel_parts = p.relative_to(root).parts
        if LOCAL_ONLY.intersection(rel_parts):
            continue
        rel = "/".join(rel_parts)
        if rel not in expected:
            problems.append(f"목록에 없는 파일: {rel}")
    return problems


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    try:
        problems = verify(root)
    except ValueError as e:
        print(f"검증 실패: {e}")
        return 1
    info = root / "PACKAGE_INFO.txt"
    if info.is_file():
        print(info.read_text(encoding="utf-8").strip())
    if problems:
        print(f"\n검증 실패 ({len(problems)}건)")
        for p in problems:
            print("  " + p)
        return 1
    print(f"\n검증 성공: {len(read_sums(root / SUMS_NAME))}개 파일 해시 일치")
    return 0


if __name__ == "__main__":
    sys.exit(main())
