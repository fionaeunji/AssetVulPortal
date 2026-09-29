"""자산 / 업로드 / 매핑 검토 / 수집 / 감사로그 / 정책."""
from __future__ import annotations

import logging
import threading

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.config.settings import CollectorMode
from app.models import (
    Asset,
    AssetProduct,
    AssetVulnerability,
    AuditLog,
    CollectionHistory,
    JobLock,
    MappingCandidate,
    PolicyVersion,
    Vulnerability,
)
from app.models.enums import CandidateStatus, CollectionTrigger, Role
from app.models.types import utcnow
from app.security.auth import Principal
from app.security.validators import clean_text
from app.services import audit
from app.services.asset_importer import import_asset_upload
from app.services.mapping_service import MappingError, decide_candidate, run_mapping_with_active_policy
from app.services.policy_loader import PolicyError, apply_policy_file, get_active_policy
from app.services.vulnerability_collector import LOCK_NAME, CollectionBusy, run_online_collection
from app.web.deps import client_ip, current_principal, flash, get_db, render, require, verify_csrf

router = APIRouter()
logger = logging.getLogger(__name__)


def _page(request: Request) -> int:
    try:
        return max(1, min(int(request.query_params.get("page", "1")), 10000))
    except ValueError:
        return 1


# ---------------- 자산 ----------------
@router.get("/assets")
def assets(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    q = request.query_params.get("q")
    q = clean_text(q, 100) if q and len(q) <= 100 else None
    stmt = select(Asset).where(Asset.is_active.is_(True))
    if q:
        stmt = stmt.where(Asset.asset_code.contains(q, autoescape=True) | Asset.name.contains(q, autoescape=True)
                          | Asset.ip.contains(q, autoescape=True) | Asset.owner_name.contains(q, autoescape=True))
    rows = db.execute(stmt.order_by(Asset.asset_code)).scalars().all()
    counts = dict(db.execute(select(AssetVulnerability.asset_id, func.count())
                             .where(AssetVulnerability.needs_revalidation.is_(False))
                             .group_by(AssetVulnerability.asset_id)).all())
    return render(request, "assets.html", {"assets": rows, "counts": counts, "q": q or ""})


@router.get("/assets/upload")
def upload_form(request: Request, principal: Principal = Depends(require(Role.OPERATOR))):
    return render(request, "upload.html", {"result": None})


@router.post("/assets/upload", dependencies=[Depends(verify_csrf)])
async def upload(request: Request, file: UploadFile = File(...),
                 principal: Principal = Depends(require(Role.OPERATOR))):
    settings = request.app.state.settings
    data = await file.read(settings.upload_max_bytes + 1)   # 제한 초과분까지만 읽어 크기 판정
    out = import_asset_upload(request.app.state.session_factory, filename=file.filename, data=data,
                              actor=principal.username, actor_role=principal.role.value,
                              upload_dir=settings.upload_dir, max_bytes=settings.upload_max_bytes,
                              client_ip=client_ip(request), policy_file=settings.policy_file)
    return render(request, "upload.html", {"result": out}, status_code=200 if out.ok else 400)


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: int, request: Request, principal: Principal = Depends(current_principal),
                 db: Session = Depends(get_db)):
    a = db.get(Asset, asset_id)
    if a is None:
        raise HTTPException(status_code=404, detail="자산을 찾을 수 없습니다.")
    vulns = db.execute(select(AssetVulnerability, Vulnerability)
                       .join(Vulnerability, Vulnerability.cve_id == AssetVulnerability.cve_id)
                       .where(AssetVulnerability.asset_id == a.id)
                       .order_by(func.coalesce(AssetVulnerability.severity_rank, -1),
                                 AssetVulnerability.due_at)).all()
    return render(request, "asset_detail.html", {"a": a, "vulns": vulns, "now": utcnow()})


# ---------------- 매핑 검토 ----------------
@router.get("/mappings")
def mappings(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    show = request.query_params.get("show", "pending")
    stmt = select(MappingCandidate, AssetProduct, Asset).join(
        AssetProduct, AssetProduct.id == MappingCandidate.asset_product_id).join(
        Asset, Asset.id == AssetProduct.asset_id)
    if show != "all":
        stmt = stmt.where(MappingCandidate.status == CandidateStatus.PENDING)
    rows = db.execute(stmt.order_by(MappingCandidate.level, MappingCandidate.confidence.desc(),
                                    MappingCandidate.id).limit(500)).all()
    return render(request, "mappings.html", {"rows": rows, "show": show,
                                             "can_edit": principal.has_role(Role.OPERATOR)})


@router.post("/mappings/{cand_id}/{action}", dependencies=[Depends(verify_csrf)])
def mapping_decide(cand_id: int, action: str, request: Request, comment: str = Form("", max_length=512),
                   principal: Principal = Depends(require(Role.OPERATOR)), db: Session = Depends(get_db)):
    if action not in ("approve", "reject"):
        raise HTTPException(status_code=404, detail="잘못된 요청입니다.")
    try:
        decide_candidate(db, cand_id, approve=action == "approve", actor=principal.username,
                         actor_role=principal.role.value, reason=clean_text(comment, 512),
                         client_ip=client_ip(request))
        db.commit()
        run_mapping_with_active_policy(db, actor=principal.username,
                                       policy_file=request.app.state.settings.policy_file)
        db.commit()
        flash(request, "매핑을 승인했습니다." if action == "approve" else "매핑을 제외했습니다.", "ok")
    except MappingError as e:
        db.rollback()
        flash(request, str(e), "error")
    return RedirectResponse("/mappings", status_code=303)


# ---------------- 수집 ----------------
def _lock_busy(db: Session) -> bool:
    lk = db.get(JobLock, LOCK_NAME)
    return lk is not None and lk.expires_at > utcnow()


@router.get("/collections")
def collections(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    rows = db.execute(select(CollectionHistory).order_by(CollectionHistory.id.desc()).limit(50)).scalars().all()
    return render(request, "collections.html", {"rows": rows, "busy": _lock_busy(db),
                                                "can_run": principal.has_role(Role.OPERATOR)})


@router.post("/collect", dependencies=[Depends(verify_csrf)])
def collect_now(request: Request, principal: Principal = Depends(require(Role.OPERATOR)),
                db: Session = Depends(get_db)):
    settings = request.app.state.settings
    if settings.collector_mode != CollectorMode.ONLINE:
        flash(request, "오프라인(VDI) 모드에서는 외부 수집을 할 수 없습니다. Bundle Import를 사용하세요.", "error")
        return RedirectResponse("/collections", status_code=303)
    if _lock_busy(db):
        flash(request, "이미 수집이 실행 중입니다.", "error")
        return RedirectResponse("/collections", status_code=303)
    factory = request.app.state.session_factory
    runner = request.app.state.collection_runner

    def _job():
        try:
            runner(CollectionTrigger.MANUAL, principal.username, factory=factory, settings=settings)
        except CollectionBusy:
            pass
        except Exception:  # noqa: BLE001 - 상세는 collection_history / 서버 로그에 기록됨
            logger.exception("manual collection failed")

    threading.Thread(target=_job, name="manual-collection", daemon=True).start()
    flash(request, "취약점 정보 수집을 시작했습니다. 완료까지 수 분이 걸릴 수 있습니다.", "ok")
    return RedirectResponse("/collections", status_code=303)


# ---------------- 관리자: 감사로그 / 정책 ----------------
@router.get("/admin/audit")
def audit_logs(request: Request, principal: Principal = Depends(require(Role.ADMIN)),
               db: Session = Depends(get_db)):
    page = _page(request)
    action = request.query_params.get("action")
    stmt = select(AuditLog)
    if action and action.isupper() and len(action) <= 64:
        stmt = stmt.where(AuditLog.action == action)
    rows = db.execute(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * 100).limit(100)).scalars().all()
    verify = audit.verify_chain(db) if request.query_params.get("verify") == "1" else None
    actions = [a for a in vars(audit.AuditAction) if a.isupper()]
    return render(request, "audit.html", {"rows": rows, "page": page, "verify": verify,
                                          "actions": actions, "action": action})


@router.get("/admin/policy")
def policy_page(request: Request, principal: Principal = Depends(require(Role.ADMIN)),
                db: Session = Depends(get_db)):
    active = get_active_policy(db)
    versions = db.execute(select(PolicyVersion).order_by(PolicyVersion.id.desc())).scalars().all()
    file_text = request.app.state.settings.policy_file.read_text(encoding="utf-8")
    return render(request, "policy.html", {"active": active[0] if active else None,
                                           "policy": active[1] if active else None,
                                           "versions": versions, "file_text": file_text})


@router.post("/admin/policy/apply", dependencies=[Depends(verify_csrf)])
def policy_apply(request: Request, principal: Principal = Depends(require(Role.ADMIN)),
                 db: Session = Depends(get_db)):
    settings = request.app.state.settings
    try:
        pv = apply_policy_file(db, settings.policy_file, actor=principal.username)
        db.commit()
        sm = run_mapping_with_active_policy(db, actor=principal.username, policy_file=settings.policy_file)
        db.commit()
        flash(request, f"정책 {pv.version} 적용 완료 — 재판정 {sm.assessments_written}건", "ok")
    except PolicyError as e:
        db.rollback()
        flash(request, f"정책 적용 실패: {e}", "error")
    return RedirectResponse("/admin/policy", status_code=303)
