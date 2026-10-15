"""VDI 반입 패키지: 커밋된 소스만 포함, 해시 목록으로 누락·변조·추가 파일 검출."""
from __future__ import annotations

import shutil
import subprocess
import zipfile

import pytest

from tools import build_vdi_package as bp
from tools import verify_package as vp


def _tree(root):
    (root / "app").mkdir(parents=True)
    (root / "app" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "README.md").write_text("# r\n", encoding="utf-8")
    bp.write_sums(root)


def test_verify_ok_and_ignores_local_runtime_files(tmp_path):
    _tree(tmp_path)
    (tmp_path / ".env").write_text("APP_SECRET_KEY=x\n", encoding="utf-8")
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "portal.db").write_bytes(b"db")
    (tmp_path / ".venv" / "Lib").mkdir(parents=True)
    (tmp_path / ".venv" / "Lib" / "x.py").write_text("", encoding="utf-8")
    assert vp.verify(tmp_path) == []


def test_verify_detects_tamper_missing_and_extra(tmp_path):
    _tree(tmp_path)
    (tmp_path / "app" / "main.py").write_text("print('evil')\n", encoding="utf-8")
    (tmp_path / "README.md").unlink()
    (tmp_path / "app" / "planted.py").write_text("", encoding="utf-8")
    problems = vp.verify(tmp_path)
    assert any("해시 불일치" in p and "app/main.py" in p for p in problems)
    assert any("누락" in p and "README.md" in p for p in problems)
    assert any("목록에 없는 파일" in p and "app/planted.py" in p for p in problems)


@pytest.mark.parametrize("line", ["0" * 64 + "  ../outside.txt", "0" * 64 + "  /abs.txt", "zz  a.txt"])
def test_verify_rejects_malformed_or_traversal_entries(tmp_path, line):
    (tmp_path / vp.SUMS_NAME).write_text(line + "\n", encoding="utf-8")
    with pytest.raises(ValueError):
        vp.verify(tmp_path)


@pytest.mark.skipif(not (bp.ROOT / ".git").exists(), reason="Git 저장소에서만 (VDI 반입본에는 .git 없음)")
def test_build_contains_committed_source_only_and_verifies(tmp_path):
    zip_path, digest = bp.build(tmp_path / "dist", "3.12", "win_amd64",
                                with_wheels=False, allow_dirty=True)
    assert digest == bp.sha256_file(zip_path)
    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        top = names[0].split("/")[0]
        rel = {n.split("/", 1)[1] for n in names}
        assert {"app/main.py", "requirements.txt", "tools/verify_package.py",
                bp.SUMS_NAME, bp.INFO_NAME} <= rel
        assert not any(r == ".env" or r.startswith(("data/portal", ".venv/", ".git/")) for r in rel)
        zf.extractall(tmp_path / "vdi")
    assert vp.verify(tmp_path / "vdi" / top) == []
    info = (tmp_path / "vdi" / top / bp.INFO_NAME).read_text(encoding="utf-8")
    assert "Git 커밋:" in info and "3.12 / win_amd64" in info


@pytest.mark.parametrize("ver,plat", [("3.12; rm", "win_amd64"), ("3.12", "win amd64")])
def test_build_rejects_bad_arguments(tmp_path, ver, plat):
    with pytest.raises(bp.BuildError):
        bp.build(tmp_path, ver, plat, with_wheels=False, allow_dirty=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="git 필요")
def test_untracked_files_do_not_block_but_modified_tracked_files_do(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for args in (["init", "-q"], ["config", "user.email", "t@example.invalid"], ["config", "user.name", "t"]):
        subprocess.run(["git", *args], cwd=repo, check=True)
    (repo / "a.txt").write_text("1\n", encoding="utf-8")
    subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-qm", "init"], cwd=repo, check=True)
    (repo / "untracked.md").write_text("x\n", encoding="utf-8")
    assert bp.git_head(repo)[1] == []
    (repo / "a.txt").write_text("2\n", encoding="utf-8")
    assert bp.git_head(repo)[1] == ["a.txt"]
