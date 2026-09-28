"""로그인 / Dashboard / 취약점 상세·상태 변경."""
from __future__ import annotations

from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import (
    Asset,
    AssetProduct,
    AssetVulnerability,
    PolicyVersion,
    StatusHistory,
    Vulnerability,
    VulnerabilityAssessment,
)
from app.models.enums import RemediationStatus, Role, Zone
from app.models.types import utcnow
from app.repositories import dashboard_repo as repo
from app.security.auth import LocalAuthProvider, Principal
from app.security.validators import clean_text
from app.services import audit
from app.services.policy_loader import apply_policy_file, get_active_policy
from app.services.vuln_status import StatusChangeError, change_owner, change_status
from app.web.deps import client_ip, current_principal, flash, get_db, login_session, render, require, verify_csrf

router = APIRouter()
auth_provider = LocalAuthProvider()


def active_policy(db: Session, request: Request):
    active = get_active_policy(db)
    if active is None:
        apply_policy_file(db, request.app.state.settings.policy_file, actor="system")
        db.commit()
        active = get_active_policy(db)
    return active


# ---------------- 로그인 ----------------
@router.get("/login")
def login_form(request: Request):
    return render(request, "login.html", {})


@router.post("/login")
def login(request: Request, username: str = Form(..., max_length=64), password: str = Form(..., max_length=256),
          csrf_token: str = Form(...), db: Session = Depends(get_db)):
    import hmac
    expected = request.session.get("csrf")
    if not expected or not hmac.compare_digest(csrf_token, expected):
        raise HTTPException(status_code=403, detail="요청이 유효하지 않습니다. 새로고침 후 다시 시도하세요.")
    username = (username or "").strip()
    principal = auth_provider.authenticate(db, username, password)
    ip = client_ip(request)
    if principal is None:
        audit.record(db, actor=username[:64] or "-", action=audit.AuditAction.LOGIN_FAILURE,
                     target_type="user", target_id=username[:64], client_ip=ip, result="failure")
        db.commit()
        return render(request, "login.html", {"error": "아이디 또는 비밀번호가 올바르지 않거나 잠긴 계정입니다."},
                      status_code=401)
    audit.record(db, actor=principal.username, actor_role=principal.role.value,
                 action=audit.AuditAction.LOGIN_SUCCESS, target_type="user", target_id=principal.username,
                 client_ip=ip)
    db.commit()
    login_session(request, principal)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    audit.record(db, actor=principal.username, actor_role=principal.role.value, action=audit.AuditAction.LOGOUT,
                 client_ip=client_ip(request))
    db.commit()
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ---------------- Dashboard ----------------
def _parse_filter(request: Request, rule_names: list[str]) -> repo.VulnFilter:
    qp = request.query_params
    sev = [s for s in qp.getlist("sev") if s in rule_names or s == repo.EPSS_PENDING_LABEL]
    zone = next((z for z in Zone if z.value == qp.get("zone")), None)
    status = next((s for s in RemediationStatus if s.value == qp.get("status")), None)
    try:
        page = max(1, min(int(qp.get("page", "1")), 10000))
    except ValueError:
        page = 1
    q = clean_text(qp.get("q"), 100) if qp.get("q") and len(qp.get("q")) <= 100 else None
    owner = clean_text(qp.get("owner"), 64) if qp.get("owner") and len(qp.get("owner")) <= 64 else None
    return repo.VulnFilter(q=q, severities=sev, kev=qp.get("kev") == "1", zone=zone,
                           overdue=qp.get("overdue") == "1", owner=owner, status=status,
                           include_closed=qp.get("closed") == "1", include_unmanaged=qp.get("all") == "1",
                           revalidation=qp.get("reval") == "1", page=page)


def filter_query(request: Request, **override) -> str:
    items = [(k, v) for k, v in request.query_params.multi_items() if k not in override and k != "page"]
    items += [(k, v) for k, v in override.items() if v is not None]
    return urlencode(items)


@router.get("/")
def dashboard(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    pv, policy = active_policy(db, request)
    rule_names = [r.name for r in policy.rules]
    now = utcnow()
    f = _parse_filter(request, rule_names)
    total, rows = repo.list_vulns(db, f, rule_names, now)
    return render(request, "dashboard.html", {
        "kpi": repo.kpis(db, rule_names, now), "rows": rows, "total": total, "f": f,
        "rule_names": rule_names, "pending_label": repo.EPSS_PENDING_LABEL, "owners": repo.owners(db),
        "zones": [z.value for z in Zone], "statuses": [s.value for s in RemediationStatus],
        "page_size": repo.PAGE_SIZE, "now": now, "policy_version": pv.version,
        "qs": lambda **kw: filter_query(request, **kw),
    })


# ---------------- 취약점 상세 ----------------
@router.get("/vulns/{av_id}")
def vuln_detail(av_id: int, request: Request, principal: Principal = Depends(current_principal),
                db: Session = Depends(get_db)):
    av = db.get(AssetVulnerability, av_id)
    if av is None:
        raise HTTPException(status_code=404, detail="대상을 찾을 수 없습니다.")
    asset = db.get(Asset, av.asset_id)
    product = db.get(AssetProduct, av.asset_product_id)
    vuln = db.get(Vulnerability, av.cve_id)
    history = db.execute(select(StatusHistory).where(StatusHistory.asset_vulnerability_id == av.id)
                         .order_by(StatusHistory.id.desc())).scalars().all()
    assessments = db.execute(select(VulnerabilityAssessment, PolicyVersion.version)
                             .join(PolicyVersion, PolicyVersion.id == VulnerabilityAssessment.policy_version_id)
                             .where(VulnerabilityAssessment.asset_vulnerability_id == av.id)
                             .order_by(VulnerabilityAssessment.id.desc())).all()
    return render(request, "vuln_detail.html", {
        "av": av, "asset": asset, "product": product, "v": vuln, "history": history,
        "assessments": assessments, "statuses": [s.value for s in RemediationStatus],
        "can_edit": principal.has_role(Role.OPERATOR), "now": utcnow(),
    })


@router.post("/vulns/{av_id}/status", dependencies=[Depends(verify_csrf)])
def vuln_status(av_id: int, request: Request, status: str = Form(..., max_length=16),
                comment: str = Form("", max_length=1000),
                principal: Principal = Depends(require(Role.OPERATOR)), db: Session = Depends(get_db)):
    try:
        change_status(db, av_id, status, actor=principal.username, actor_role=principal.role.value,
                      comment=comment, client_ip=client_ip(request))
        db.commit()
        flash(request, f"상태를 '{status}'(으)로 변경했습니다.", "ok")
    except StatusChangeError as e:
        db.rollback()
        flash(request, str(e), "error")
    return RedirectResponse(f"/vulns/{av_id}", status_code=303)


@router.post("/vulns/{av_id}/owner", dependencies=[Depends(verify_csrf)])
def vuln_owner(av_id: int, request: Request, owner: str = Form(..., max_length=64),
               principal: Principal = Depends(require(Role.OPERATOR)), db: Session = Depends(get_db)):
    try:
        change_owner(db, av_id, owner, actor=principal.username, actor_role=principal.role.value,
                     client_ip=client_ip(request))
        db.commit()
        flash(request, "담당자를 변경했습니다.", "ok")
    except StatusChangeError as e:
        db.rollback()
        flash(request, str(e), "error")
    return RedirectResponse(f"/vulns/{av_id}", status_code=303)


# ---------------- Excel Export ----------------
@router.get("/export.xlsx")
def export_xlsx(request: Request, principal: Principal = Depends(current_principal), db: Session = Depends(get_db)):
    from fastapi.responses import Response

    from app.services.exporter import MAX_EXPORT_ROWS, build_workbook, export_filename
    from app.services.vuln_status import CLOSED_STATUSES
    pv, policy = active_policy(db, request)
    rule_names = [r.name for r in policy.rules]
    now = utcnow()
    f = _parse_filter(request, rule_names)
    total, rows = repo.list_vulns(db, f, rule_names, now, limit_all=True)
    filter_desc = "; ".join(f"{k}={v}" for k, v in request.query_params.multi_items() if k != "page")[:500]
    data = build_workbook(rows, now=now, exported_by=principal.username, policy_version=pv.version,
                          filter_desc=filter_desc, kpi=repo.kpis(db, rule_names, now),
                          closed_statuses={s.value for s in CLOSED_STATUSES})
    audit.record(db, actor=principal.username, actor_role=principal.role.value, action=audit.AuditAction.EXPORT,
                 target_type="report", client_ip=client_ip(request),
                 after={"rows": min(total, MAX_EXPORT_ROWS), "filter": filter_desc, "policy_version": pv.version})
    db.commit()
    return Response(content=data,
                    media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    headers={"Content-Disposition": f'attachment; filename="{export_filename(now)}"'})
