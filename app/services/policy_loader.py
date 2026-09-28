"""정책 파일 로딩/검증 및 policy_versions 등록."""
from __future__ import annotations

import hashlib
from pathlib import Path

import yaml
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import PolicyVersion
from app.schemas.policy import Policy
from app.services import audit

MAX_POLICY_BYTES = 64 * 1024


class PolicyError(ValueError):
    pass


def parse_policy_text(text: str) -> Policy:
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        raise PolicyError("policy file too large")
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PolicyError(f"invalid YAML: {e.__class__.__name__}") from None
    if not isinstance(data, dict):
        raise PolicyError("policy must be a mapping")
    try:
        return Policy.model_validate(data)
    except Exception as e:  # pydantic.ValidationError
        raise PolicyError(f"policy validation failed: {e}") from None


def load_policy_file(path: Path) -> tuple[Policy, str, str]:
    text = path.read_text(encoding="utf-8")
    policy = parse_policy_text(text)
    return policy, text, hashlib.sha256(text.encode("utf-8")).hexdigest()


def get_active_policy(session: Session) -> tuple[PolicyVersion, Policy] | None:
    pv = session.execute(
        select(PolicyVersion).where(PolicyVersion.is_active.is_(True))
    ).scalar_one_or_none()
    if pv is None:
        return None
    return pv, parse_policy_text(pv.content_yaml)


def apply_policy_file(session: Session, path: Path, actor: str) -> PolicyVersion:
    """정책 파일을 새 버전으로 등록하고 활성화. 내용이 같으면 기존 버전을 그대로 사용."""
    policy, text, sha = load_policy_file(path)
    existing = session.execute(
        select(PolicyVersion).where(PolicyVersion.version == policy.version)
    ).scalar_one_or_none()
    if existing is not None:
        if existing.content_sha256 != sha:
            raise PolicyError(
                f"policy version '{policy.version}' already exists with different content; "
                "change 'version' when editing the policy"
            )
        pv = existing
    else:
        pv = PolicyVersion(version=policy.version, content_yaml=text, content_sha256=sha,
                           created_by=actor, is_active=False)
        session.add(pv)
        session.flush()
    if not pv.is_active:
        prev = session.execute(
            select(PolicyVersion.version).where(PolicyVersion.is_active.is_(True))
        ).scalar_one_or_none()
        session.execute(update(PolicyVersion).values(is_active=False))
        session.execute(update(PolicyVersion).where(PolicyVersion.id == pv.id).values(is_active=True))
        session.expire(pv)
        audit.record(session, actor=actor, action=audit.AuditAction.POLICY_CHANGE,
                     target_type="policy_version", target_id=pv.version,
                     before={"active_version": prev},
                     after={"active_version": pv.version, "sha256": sha})
    return pv
