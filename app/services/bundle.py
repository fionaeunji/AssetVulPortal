"""Bundle 직렬화/무결성 검증.

payload_sha256 = SHA-256(canonical JSON(payload))
hmac_sha256    = HMAC-SHA256(BUNDLE_HMAC_KEY, payload_sha256)  — 키가 설정된 경우 (Collector-Portal 공유 비밀)
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from pathlib import Path

from pydantic import ValidationError

from app.models.types import utcnow
from app.schemas.bundle import Bundle, BundleManifest, BundlePayload, SourceInfo

MAX_BUNDLE_BYTES = 100 * 1024 * 1024


class BundleError(ValueError):
    pass


def _canonical(payload: BundlePayload) -> bytes:
    return json.dumps(payload.model_dump(mode="json"), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":")).encode("utf-8")


def payload_digest(payload: BundlePayload) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _hmac(key: str, digest: str) -> str:
    return hmac.new(key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256).hexdigest()


def build_bundle(payload: BundlePayload, sources: list[SourceInfo], collector: str,
                 hmac_key: str | None = None) -> Bundle:
    digest = payload_digest(payload)
    manifest = BundleManifest(
        bundle_id=uuid.uuid4().hex, created_at=utcnow(), collector=collector, sources=sources,
        payload_sha256=digest, hmac_sha256=_hmac(hmac_key, digest) if hmac_key else None,
    )
    return Bundle(manifest=manifest, payload=payload)


def write_bundle(bundle: Bundle, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = bundle.manifest.created_at.strftime("%Y%m%dT%H%M%SZ")
    path = out_dir / f"bundle_{ts}_{bundle.manifest.bundle_id[:8]}.json"   # 서버 생성 파일명
    path.write_text(bundle.model_dump_json(), encoding="utf-8")
    return path


def load_bundle_bytes(raw: bytes, hmac_key: str | None = None) -> Bundle:
    if len(raw) > MAX_BUNDLE_BYTES:
        raise BundleError("bundle too large")
    try:
        bundle = Bundle.model_validate_json(raw)
    except ValidationError as e:
        raise BundleError(f"bundle schema validation failed ({e.error_count()} errors)") from None
    digest = payload_digest(bundle.payload)
    if not hmac.compare_digest(digest, bundle.manifest.payload_sha256):
        raise BundleError("bundle payload hash mismatch (tampered or corrupted)")
    if hmac_key:
        sig = bundle.manifest.hmac_sha256
        if not sig or not hmac.compare_digest(sig, _hmac(hmac_key, digest)):
            raise BundleError("bundle HMAC verification failed")
    return bundle


def load_bundle_file(path: Path, hmac_key: str | None = None) -> Bundle:
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise BundleError("bundle too large")
    return load_bundle_bytes(path.read_bytes(), hmac_key)
