"""(인터넷 PC) VDI 반입용 소스 패키지 생성.

Git에 커밋된 소스 그대로 + 오프라인 설치용 wheel + 해시 목록을 zip 1개로 만든다.
.env, data(DB·업로드·로그), .venv 등 Git에 없는 파일은 포함되지 않는다.

사용 (저장소 폴더에서):
    python tools\\build_vdi_package.py --python-version 3.12
    → dist\\AssetVulPortal-<날짜>-<커밋>.zip  (+ 반입 신청서용 SHA-256 출력)

옵션
    --python-version  VDI에 설치된(또는 함께 반입할) Python 버전 (기본: 현재 Python)
    --platform        기본 win_amd64 (64비트 Windows)
    --out-dir         기본 dist
"""
from __future__ import annotations

import argparse
import hashlib
import io
import re
import shutil
# 고정 인자 목록(git/pip)만 실행하며 shell 을 사용하지 않음
import subprocess  # nosec B404
import sys
import tarfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUMS_NAME = "SHA256SUMS.txt"
INFO_NAME = "PACKAGE_INFO.txt"
PYVER_RE = re.compile(r"^3\.\d{1,2}$")
PLATFORM_RE = re.compile(r"^[a-z0-9_]+$")


class BuildError(RuntimeError):
    pass


def _run(args: list[str], cwd: Path) -> bytes:
    r = subprocess.run(args, cwd=cwd, capture_output=True, check=False)  # nosec B603
    if r.returncode != 0:
        raise BuildError(f"{args[0]} 실패: {r.stderr.decode(errors='replace').strip()[:500]}")
    return r.stdout


def git_head(repo: Path) -> tuple[str, bool]:
    sha = _run(["git", "rev-parse", "HEAD"], repo).decode().strip()
    dirty = bool(_run(["git", "status", "--porcelain"], repo).strip())
    return sha, dirty


def export_git_tree(repo: Path, dest: Path) -> int:
    """커밋된 파일만 dest 로 추출 (작업 중 변경·무시 파일 제외)."""
    raw = _run(["git", "archive", "--format=tar", "HEAD"], repo)
    with tarfile.open(fileobj=io.BytesIO(raw)) as tf:
        members = [m for m in tf.getmembers() if m.isfile() or m.isdir()]
        tf.extractall(dest, members=members, filter="data")
    return sum(1 for m in members if m.isfile())


def _pytest_pin(repo: Path) -> str | None:
    for line in (repo / "requirements-dev.txt").read_text(encoding="utf-8").splitlines():
        if line.strip().lower().startswith("pytest=="):
            return line.strip()
    return None


def download_wheels(repo: Path, dest: Path, python_version: str, platform: str) -> int:
    dest.mkdir(parents=True, exist_ok=True)
    args = [sys.executable, "-m", "pip", "download", "-q", "-r", str(repo / "requirements.txt"),
            "--platform", platform, "--python-version", python_version,
            "--only-binary=:all:", "-d", str(dest)]
    pin = _pytest_pin(repo)
    if pin:
        args.append(pin)   # VDI에서 자동화 테스트 실행용
    _run(args, repo)
    return len(list(dest.glob("*.whl")))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_sums(root: Path) -> int:
    lines = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name != SUMS_NAME:
            lines.append(f"{sha256_file(p)}  {p.relative_to(root).as_posix()}")
    (root / SUMS_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def make_zip(root: Path, zip_path: Path) -> None:
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(root.rglob("*")):
            if p.is_file():
                zf.write(p, f"{root.name}/{p.relative_to(root).as_posix()}")


def build(out_dir: Path, python_version: str, platform: str, *, repo: Path = ROOT,
          with_wheels: bool = True, allow_dirty: bool = False) -> tuple[Path, str]:
    if not PYVER_RE.fullmatch(python_version):
        raise BuildError(f"--python-version 형식 오류: {python_version!r} (예: 3.12)")
    if not PLATFORM_RE.fullmatch(platform):
        raise BuildError(f"--platform 형식 오류: {platform!r}")
    sha, dirty = git_head(repo)
    if dirty and not allow_dirty:
        raise BuildError("커밋되지 않은 변경이 있습니다. 커밋(또는 정리) 후 다시 실행하세요 — "
                         "반입본과 Git 커밋을 1:1로 맞추기 위함")
    now = datetime.now(timezone.utc)
    name = f"AssetVulPortal-{now:%Y%m%d}-{sha[:7]}"
    stage = out_dir / name
    zip_path = out_dir / f"{name}.zip"
    if stage.exists() or zip_path.exists():
        raise BuildError(f"이미 존재합니다: {stage} — 지우고 다시 실행하세요")
    stage.mkdir(parents=True)
    try:
        n_src = export_git_tree(repo, stage)
        n_whl = download_wheels(repo, stage / "wheels", python_version, platform) if with_wheels else 0
        (stage / INFO_NAME).write_text(
            f"패키지: {name}\n"
            f"Git 커밋: {sha}{' (커밋 안 된 변경 있음)' if dirty else ''}\n"
            f"생성 시각(UTC): {now:%Y-%m-%d %H:%M:%S}\n"
            f"대상 Python: {python_version} / {platform}\n"
            f"소스 파일: {n_src}개, wheel: {n_whl}개\n",
            encoding="utf-8")
        write_sums(stage)
        make_zip(stage, zip_path)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        zip_path.unlink(missing_ok=True)
        raise
    shutil.rmtree(stage)
    return zip_path, sha256_file(zip_path)


def main() -> int:
    ap = argparse.ArgumentParser(description="VDI 반입용 소스 패키지 생성")
    ap.add_argument("--python-version", default=f"{sys.version_info.major}.{sys.version_info.minor}")
    ap.add_argument("--platform", default="win_amd64")
    ap.add_argument("--out-dir", type=Path, default=ROOT / "dist")
    args = ap.parse_args()
    try:
        zip_path, digest = build(args.out_dir, args.python_version, args.platform)
    except BuildError as e:
        print(f"오류: {e}", file=sys.stderr)
        return 1
    size_mb = zip_path.stat().st_size / 1024 / 1024
    print(f"패키지: {zip_path} ({size_mb:.1f} MB)")
    print(f"SHA-256: {digest}")
    print("→ 반입 신청서에 파일명과 SHA-256을 기재하세요. VDI에서 certutil -hashfile <zip> SHA256 으로 대조합니다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
