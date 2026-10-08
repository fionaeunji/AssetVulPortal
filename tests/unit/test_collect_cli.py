"""VDI 외부망 Collector CLI: --targets-file / --split → Bundle 파일 → 내부 Import."""
from __future__ import annotations

import json
import sys

import pytest

import app.config.logging as app_logging
import app.config.settings as app_settings
import app.services.collector as collector_mod
import app.services.http_client as http_client
from app.config.settings import Settings
from app.services.bundle import load_bundle_file
from app.services.nvd_client import NvdClient
from scripts import collect as collect_cli
from tests.fakes import FakeExternal

HMAC_KEY = "k" * 48


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    s = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "d",
                 bundle_hmac_key=HMAC_KEY)
    fake = FakeExternal()
    orig = http_client.build_client
    monkeypatch.setattr(app_settings, "get_settings", lambda: s)
    monkeypatch.setattr(collect_cli, "get_settings", lambda: s)
    monkeypatch.setattr(app_logging, "configure_logging", lambda _s: None)
    monkeypatch.setattr(http_client, "build_client",
                        lambda rec=None, transport=None, trust_store="system":
                        orig(rec, transport=fake.transport(), trust_store=trust_store))
    monkeypatch.setattr(collector_mod, "NvdClient",
                        lambda http, key: NvdClient(http, key, sleep=lambda x: None))
    targets = tmp_path / "targets.json"
    targets.write_text(json.dumps({
        "targets": [{"product_key": "a:apache:http_server", "last_mod_start": None},
                    {"product_key": "o:fortinet:fortios", "last_mod_start": None}],
        "known_cve_ids": ["CVE-2021-44228"],
    }), encoding="utf-8")
    return s, fake, targets, tmp_path / "out"


def _run(monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["collect", *argv])
    return collect_cli.main()


def test_targets_file_creates_single_signed_bundle(cli_env, monkeypatch):
    _s, _fake, targets, out = cli_env
    assert _run(monkeypatch, "--targets-file", str(targets), "--out-dir", str(out)) == 0
    files = list(out.glob("bundle_*.json"))
    assert len(files) == 1
    b = load_bundle_file(files[0], HMAC_KEY)     # HMAC 검증 통과
    assert {t.product_key for t in b.payload.nvd_targets} == {"a:apache:http_server", "o:fortinet:fortios"}


def test_split_creates_one_bundle_per_product(cli_env, monkeypatch):
    _s, fake, targets, out = cli_env
    assert _run(monkeypatch, "--targets-file", str(targets), "--out-dir", str(out), "--split") == 0
    bundles = [load_bundle_file(p, HMAC_KEY) for p in sorted(out.glob("bundle_*.json"))]
    assert len(bundles) == 2
    assert sorted(b.payload.nvd_targets[0].product_key for b in bundles) == \
        ["a:apache:http_server", "o:fortinet:fortios"]
    assert all(len(b.payload.nvd_targets) == 1 for b in bundles)
    # 보유 CVE의 EPSS 조회는 첫 Bundle에서만 (중복 호출 방지)
    epss_calls = [c for c in fake.calls if c.url.host == "api.first.org"]
    assert sum("CVE-2021-44228" in str(c.url) for c in epss_calls) == 1


def test_offline_mode_cli_refuses_online_collection(tmp_path, monkeypatch, capsys):
    s = Settings(_env_file=None, collector_mode="offline", data_dir=tmp_path / "d")
    monkeypatch.setattr(app_settings, "get_settings", lambda: s)
    monkeypatch.setattr(collect_cli, "get_settings", lambda: s)
    monkeypatch.setattr(app_logging, "configure_logging", lambda _s: None)
    import app.services.vulnerability_collector as vc
    monkeypatch.setattr(vc, "get_settings", lambda: s, raising=False)
    assert _run(monkeypatch) == 2
    err = capsys.readouterr().err
    assert "offline" in err and "Traceback" not in err
