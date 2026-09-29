"""조치 상태 / 담당자 변경 (감사로그 + 상태이력 Append-only)."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import AssetVulnerability, StatusHistory
from app.models.enums import RemediationStatus
from app.security.validators import ValidationError, clean_text
from app.services import audit

CLOSED_STATUSES = frozenset({RemediationStatus.DONE, RemediationStatus.EXCEPTION,
                             RemediationStatus.FALSE_POSITIVE})
COMMENT_REQUIRED = frozenset({RemediationStatus.EXCEPTION, RemediationStatus.FALSE_POSITIVE})


class StatusChangeError(ValueError):
    pass


def change_status(session: Session, av_id: int, new_status: str, *, actor: str, actor_role: str,
                  comment: str | None, client_ip: str | None) -> AssetVulnerability:
    av = session.get(AssetVulnerability, av_id)
    if av is None:
        raise StatusChangeError("대상을 찾을 수 없습니다.")
    try:
        target = RemediationStatus(new_status)
    except ValueError:
        raise StatusChangeError("허용되지 않은 상태 값입니다.") from None
    try:
        comment = clean_text(comment, 1000, allow_newline=True)
    except ValidationError:
        raise StatusChangeError("사유는 1000자 이내로 입력하세요.") from None
    if target == av.status:
        raise StatusChangeError("현재 상태와 같습니다.")
    if target in COMMENT_REQUIRED and not comment:
        raise StatusChangeError(f"'{target.value}' 처리는 사유 입력이 필요합니다.")
    before = av.status
    av.status = target
    session.add(StatusHistory(asset_vulnerability_id=av.id, from_status=before.value,
                              to_status=target.value, changed_by=actor, comment=comment))
    audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.STATUS_CHANGE,
                 target_type="asset_vulnerability", target_id=av.id, client_ip=client_ip,
                 before={"status": before.value},
                 after={"status": target.value, "cve_id": av.cve_id, "comment": comment})
    session.flush()
    return av


def change_owner(session: Session, av_id: int, owner: str | None, *, actor: str, actor_role: str,
                 client_ip: str | None) -> AssetVulnerability:
    av = session.get(AssetVulnerability, av_id)
    if av is None:
        raise StatusChangeError("대상을 찾을 수 없습니다.")
    try:
        owner = clean_text(owner, 64)
    except ValidationError:
        raise StatusChangeError("담당자는 64자 이내로 입력하세요.") from None
    if not owner:
        raise StatusChangeError("담당자를 입력하세요.")
    before = av.owner
    av.owner, av.owner_override = owner, True
    audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.OWNER_CHANGE,
                 target_type="asset_vulnerability", target_id=av.id, client_ip=client_ip,
                 before={"owner": before}, after={"owner": owner, "cve_id": av.cve_id})
    session.flush()
    return av
