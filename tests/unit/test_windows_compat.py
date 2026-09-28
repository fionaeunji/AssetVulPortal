"""Windows(cp949 로케일) 호환성: locale 인코딩으로 읽히는 설정 파일은 ASCII만 허용."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_alembic_ini_is_ascii():
    # alembic 은 ini 를 encoding="locale" 로 읽으므로 한국어 Windows(cp949)에서 비ASCII가 있으면 실패
    (ROOT / "alembic.ini").read_bytes().decode("ascii")
