"""테스트 공통 설정: 임시 SQLite DB에 Alembic Migration을 적용해 실제 스키마/Trigger로 테스트한다."""
from __future__ import annotations

import os
import secrets
import tempfile
from pathlib import Path

import pytest

_TMP = Path(tempfile.mkdtemp(prefix="vulportal-test-"))
os.environ.setdefault("APP_SECRET_KEY", secrets.token_urlsafe(48))
os.environ["DATABASE_URL"] = f"sqlite:///{(_TMP / 'test.db').as_posix()}"
os.environ["DATA_DIR"] = str(_TMP / "data")
os.environ["COLLECTOR_MODE"] = "offline"

from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from app.db import make_engine  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def _migrate(url: str) -> None:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")


@pytest.fixture()
def engine(tmp_path):
    url = f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}"
    _migrate(url)
    eng = make_engine(url)
    yield eng
    eng.dispose()


@pytest.fixture()
def db(engine):
    with Session(engine, expire_on_commit=False) as s:
        yield s
