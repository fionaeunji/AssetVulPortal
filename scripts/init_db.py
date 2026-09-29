"""DB 초기화: Alembic Migration을 최신 버전으로 적용한다.

사용: python -m scripts.init_db
"""
from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from app.config.settings import get_settings

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    get_settings().ensure_dirs()
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ROOT / "migrations"))
    command.upgrade(cfg, "head")
    print("DB migration 완료")


if __name__ == "__main__":
    main()
