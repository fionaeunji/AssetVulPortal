"""Phase 6: 웹 Dashboard / 상세 / 상태변경 / 업로드 / 매핑 검토 / 관리자 화면 + 보안 테스트."""
from __future__ import annotations

import re
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.config.settings import Settings
from app.main import create_app
from app.models import (
    Asset,
    AssetVulnerability,
    AuditLog,
    MappingCandidate,
    StatusHistory,
    User,
    Vulnerability,
)
from app.models.enums import CandidateStatus, CollectionTrigger, Role
from app.models.types import utcnow
from app.security.passwords import hash_password
from app.services.asset_importer import import_asset_upload
from app.services.mapping_service import run_mapping_with_active_policy
from app.services.nvd_client import NvdClient
from app.services.vulnerability_collector import run_online_collection
from tests.fakes import FakeExternal

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "sample_data" / "sample_assets.xlsx"
PW = "Test-Pass-1234"
EPSS = {"CVE-2021-41773": (0.94, 0.99), "CVE-2020-1938": (0.20, 0.97), "CVE-2024-38063": (0.05, 0.9)}


@pytest.fixture()
def portal(engine, tmp_path):
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    settings = Settings(_env_file=None, collector_mode="online", data_dir=tmp_path / "data")
    with factory() as s:
        for name, role in (("viewer1", Role.VIEWER), ("op1", Role.OPERATOR), ("admin1", Role.ADMIN)):
            s.add(User(username=name, password_hash=hash_password(PW), role=role))
        s.commit()
    assert import_asset_upload(factory, filename="sample_assets.xlsx", data=SAMPLE.read_bytes(), actor="seed",
                               actor_role="admin", upload_dir=settings.upload_dir, max_bytes=5 << 20,
                               policy_file=settings.policy_file).ok
    run_online_collection(CollectionTrigger.MANUAL, "seed", factory=factory, settings=settings,
                          transport=FakeExternal(epss=EPSS).transport(),
                          nvd_client_factory=lambda http: NvdClient(http, sleep=lambda s: None))
    app = create_app(settings=settings, session_factory=factory)
    calls = []
    app.state.collection_runner = lambda *a, **k: calls.append((a, k))
    app.state.test_calls = calls
    return app, factory, settings


def csrf_of(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    assert m, "csrf token not found"
    return m.group(1)


def login(app, user: str, pw: str = PW) -> TestClient:
    c = TestClient(app, raise_server_exceptions=False)
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"username": user, "password": pw, "csrf_token": tok}, follow_redirects=False)
    assert r.status_code == 303, r.text
    return c


def page_csrf(c: TestClient, path: str = "/") -> str:
    return csrf_of(c.get(path).text)


def av_id(factory, asset_code: str, cve: str) -> int:
    with factory() as s:
        return s.execute(select(AssetVulnerability.id).join(Asset, Asset.id == AssetVulnerability.asset_id)
                         .where(Asset.asset_code == asset_code, AssetVulnerability.cve_id == cve)).scalar_one()


# ---------------- 인증 ----------------
def test_requires_login(portal):
    app, _, _ = portal
    c = TestClient(app)
    for path in ("/", "/assets", "/vulns/1", "/mappings", "/collections", "/admin/audit"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"] == "/login"


def test_login_failure_audited_and_generic_message(portal):
    app, factory, _ = portal
    c = TestClient(app)
    tok = csrf_of(c.get("/login").text)
    r = c.post("/login", data={"username": "op1", "password": "wrong", "csrf_token": tok})
    assert r.status_code == 401 and "올바르지 않거나" in r.text
    r2 = c.post("/login", data={"username": "nobody", "password": "x", "csrf_token": tok})
    assert r2.status_code == 401 and r.text.count("올바르지") == r2.text.count("올바르지")   # 계정 존재 비노출
    with factory() as s:
        assert len(s.execute(select(AuditLog).where(AuditLog.action == "LOGIN_FAILURE")).all()) == 2


def test_login_without_csrf_rejected(portal):
    app, _, _ = portal
    c = TestClient(app)
    c.get("/login")
    r = c.post("/login", data={"username": "op1", "password": PW, "csrf_token": "forged"})
    assert r.status_code == 403


def test_login_success_audited_and_logout(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    with factory() as s:
        assert s.execute(select(AuditLog).where(AuditLog.action == "LOGIN_SUCCESS")).scalar_one()
    r = c.post("/logout", data={"csrf_token": page_csrf(c)}, follow_redirects=False)
    assert r.status_code == 303
    assert c.get("/", follow_redirects=False).status_code == 303


def test_deactivated_user_loses_access(portal):
    app, factory, _ = portal
    c = login(app, "viewer1")
    with factory() as s:
        s.execute(User.__table__.update().where(User.username == "viewer1").values(is_active=False))
        s.commit()
    assert c.get("/", follow_redirects=False).status_code == 303


# ---------------- Dashboard ----------------
def test_dashboard_kpis_and_columns(portal):
    app, _, _ = portal
    html = login(app, "viewer1").get("/").text
    for label in ("전체 자산", "취약 자산", "긴급 취약점", "우선 취약점", "주의 취약점", "조치기한 초과"):
        assert label in html
    for col in ("등급", "CVE", "자산명", "IP", "제품", "Version", "CVSS", "Initial EPSS", "Current EPSS", "KEV",
                "자산구분", "중요도", "담당자", "탐지일", "조치기한", "남은시간", "상태"):
        assert f"<th>{col}</th>" in html
    assert "CVE-2021-41773" in html and "web-dmz-01" in html


@pytest.mark.parametrize("query,expect,absent", [
    ("q=CVE-2021-41773", "CVE-2021-41773", "CVE-2020-1938"),
    ("q=192.0.2.21", "CVE-2020-1938", "CVE-2021-41773"),          # IP
    ("q=web-dmz-01", "CVE-2021-41773", "CVE-2020-1938"),          # Hostname
    ("q=tomcat", "CVE-2020-1938", "CVE-2021-41773"),              # 제품
    ("q=가상담당자02", "CVE-2020-1938", "CVE-2021-41773"),         # 담당자
    ("sev=긴급", "CVE-2021-41773", "CVE-2020-1938"),
    ("sev=우선", "CVE-2020-1938", "CVE-2021-41773"),
    ("zone=경계면", "CVE-2021-41773", "CVE-2020-1938"),
    ("zone=내부", "CVE-2020-1938", "CVE-2021-41773"),
    ("kev=1&q=CVE-2021-41773", "CVE-2021-41773", "CVE-2024-38063"),
    ("owner=가상담당자01", "CVE-2021-41773", "CVE-2020-1938"),
])
def test_dashboard_search_and_filters(portal, query, expect, absent):
    app, _, _ = portal
    html = login(app, "viewer1").get(f"/?{query}").text
    assert expect in html and absent not in html


def test_overdue_filter(portal):
    app, factory, _ = portal
    with factory() as s:
        av = s.get(AssetVulnerability, av_id(factory, "WAS-001", "CVE-2020-1938"))
        av.due_at = utcnow() - timedelta(days=2)
        s.commit()
    c = login(app, "viewer1")
    html = c.get("/?overdue=1").text
    assert "CVE-2020-1938" in html and "CVE-2021-41773" not in html and "초과" in html


def test_sql_injection_in_search_is_harmless(portal):
    app, _, _ = portal
    c = login(app, "viewer1")
    for q in ("' OR 1=1 --", "%", "%%%", "\" ; DROP TABLE assets; --"):
        r = c.get("/", params={"q": q})
        assert r.status_code == 200 and "조건에 맞는 취약점이 없습니다" in r.text
    # LIKE 와일드카드 문자도 리터럴로 처리 ('_' 는 실제 제품명 http_server 에 포함된 문자로만 일치)
    html = c.get("/", params={"q": "http_server"}).text
    assert "CVE-2021-41773" in html and "CVE-2020-1938" not in html
    assert "CVE-2021-41773" in c.get("/").text      # 데이터 온전


def test_xss_from_excel_and_cve_description_is_escaped(portal):
    app, factory, _ = portal
    with factory() as s:
        a = s.execute(select(Asset).where(Asset.asset_code == "WEB-001")).scalar_one()
        a.name = "<script>alert('x')</script>"
        v = s.get(Vulnerability, "CVE-2021-41773")
        v.description = '<img src=x onerror="alert(1)">'
        s.commit()
    c = login(app, "viewer1")
    for html in (c.get("/").text, c.get(f"/vulns/{av_id(factory, 'WEB-001', 'CVE-2021-41773')}").text):
        assert "<script>alert" not in html and "<img src=x" not in html
        assert "&lt;script&gt;" in html or "&lt;img" in html


def test_invalid_query_params_do_not_error(portal):
    app, _, _ = portal
    c = login(app, "viewer1")
    for q in ("page=abc", "page=-5", "page=999999999", "sev=<x>", "zone=DMZ", "status=hack", "q=" + "a" * 500):
        assert c.get(f"/?{q}").status_code == 200


# ---------------- 상세 / 상태 변경 ----------------
def test_detail_shows_source_and_calculated_data(portal):
    app, factory, _ = portal
    html = login(app, "viewer1").get(f"/vulns/{av_id(factory, 'WEB-001', 'CVE-2021-41773')}").text
    for s in ("CVSS Vector", "CVSS:3.1/AV:N", "Initial EPSS", "Current EPSS", "매핑방식", "매핑근거",
              "CPE_EXACT", "cpe:2.3:a:apache:http_server:2.4.49", "긴급", "경계면", "가상담당자01",
              "72시간", "2026.09-02"):
        assert s in html, s


def test_viewer_cannot_change_status(portal):
    app, factory, _ = portal
    c = login(app, "viewer1")
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    r = c.post(f"/vulns/{i}/status", data={"status": "확인중", "csrf_token": page_csrf(c)})
    assert r.status_code == 403


def test_status_change_requires_csrf(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    assert c.post(f"/vulns/{i}/status", data={"status": "확인중"}).status_code == 403
    assert c.post(f"/vulns/{i}/status", data={"status": "확인중", "csrf_token": "x"}).status_code == 403


def test_status_change_audited_and_history(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    tok = page_csrf(c, f"/vulns/{i}")
    r = c.post(f"/vulns/{i}/status", data={"status": "조치중", "comment": "패치 일정 확정", "csrf_token": tok})
    assert r.status_code == 200 and "변경했습니다" in r.text
    with factory() as s:
        assert s.get(AssetVulnerability, i).status.value == "조치중"
        h = s.execute(select(StatusHistory).where(StatusHistory.asset_vulnerability_id == i)).scalar_one()
        assert (h.from_status, h.to_status, h.changed_by) == ("신규", "조치중", "op1")
        log = s.execute(select(AuditLog).where(AuditLog.action == "STATUS_CHANGE")).scalar_one()
        assert log.before == {"status": "신규"} and log.after["status"] == "조치중" and log.actor == "op1"


def test_exception_status_requires_comment_and_invalid_status_rejected(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    tok = page_csrf(c, f"/vulns/{i}")
    assert "사유 입력이 필요" in c.post(f"/vulns/{i}/status", data={"status": "예외처리", "csrf_token": tok}).text
    assert "허용되지 않은" in c.post(f"/vulns/{i}/status", data={"status": "삭제", "csrf_token": tok}).text
    with factory() as s:
        assert s.get(AssetVulnerability, i).status.value == "신규"


def test_owner_override_survives_remapping(portal):
    app, factory, settings = portal
    c = login(app, "op1")
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    c.post(f"/vulns/{i}/owner", data={"owner": "보안관제담당", "csrf_token": page_csrf(c, f"/vulns/{i}")})
    with factory() as s:
        run_mapping_with_active_policy(s, actor="t", policy_file=settings.policy_file)
        s.commit()
        assert s.get(AssetVulnerability, i).owner == "보안관제담당"
        assert s.execute(select(AuditLog).where(AuditLog.action == "OWNER_CHANGE",
                                                AuditLog.actor == "op1")).scalar_one()


def test_404_page_has_no_internal_details(portal):
    app, _, _ = portal
    r = login(app, "viewer1").get("/vulns/999999", headers={"accept": "text/html"})
    assert r.status_code == 404 and "Traceback" not in r.text and "찾을 수 없습니다" in r.text
    assert "default-src 'self'" in r.headers["content-security-policy"]


# ---------------- 업로드 ----------------
def test_web_upload_by_operator(portal):
    app, _, _ = portal
    c = login(app, "op1")
    tok = page_csrf(c, "/assets/upload")
    r = c.post("/assets/upload", data={"csrf_token": tok},
               files={"file": ("sample_assets.xlsx", SAMPLE.read_bytes(),
                               "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")})
    assert r.status_code == 200 and "반영했습니다" in r.text


def test_web_upload_rejects_malicious_and_viewer(portal):
    app, _, _ = portal
    c = login(app, "op1")
    tok = page_csrf(c, "/assets/upload")
    r = c.post("/assets/upload", data={"csrf_token": tok},
               files={"file": ("../../evil.xlsx", b"MZ\x90\x00payload", "application/octet-stream")})
    assert r.status_code == 400 and "서명" in r.text
    r = c.post("/assets/upload", data={"csrf_token": tok},
               files={"file": ("a.xlsm", SAMPLE.read_bytes(), "application/octet-stream")})
    assert r.status_code == 400
    v = login(app, "viewer1")
    assert v.get("/assets/upload").status_code == 403


def test_oversized_request_rejected(portal):
    app, _, settings = portal
    c = login(app, "op1")
    tok = page_csrf(c, "/assets/upload")
    big = b"PK\x03\x04" + b"0" * (settings.upload_max_bytes + 100 * 1024)
    r = c.post("/assets/upload", data={"csrf_token": tok}, files={"file": ("big.xlsx", big, "x")})
    assert r.status_code == 413


# ---------------- 매핑 검토 ----------------
def test_mapping_review_page_and_approve(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    html = c.get("/mappings").text
    assert "Match Confidence" in html and "매핑 승인" in html and "산정불가" in html
    with factory() as s:
        cid = s.execute(select(MappingCandidate.id).where(
            MappingCandidate.proposed_cpe == "cpe:2.3:a:apache:tomcat:8.5.50:*:*:*:*:*:*:*")).scalar_one()
    r = c.post(f"/mappings/{cid}/approve", data={"comment": "확인", "csrf_token": page_csrf(c, "/mappings")})
    assert r.status_code == 200 and "승인" in r.text
    with factory() as s:
        assert s.get(MappingCandidate, cid).status == CandidateStatus.APPROVED
    assert "CVE-2020-1938" in c.get("/?q=was-app-02").text
    v = login(app, "viewer1")
    assert v.post(f"/mappings/{cid}/reject", data={"csrf_token": page_csrf(v)}).status_code == 403


# ---------------- 수집 ----------------
def test_manual_collection_button(portal):
    app, factory, _ = portal
    c = login(app, "op1")
    html = c.get("/collections").text
    assert "지금 취약점 정보 수집" in html and "services.nvd.nist.gov" in html
    r = c.post("/collect", data={"csrf_token": page_csrf(c, "/collections")})
    assert r.status_code == 200 and "시작했습니다" in r.text
    import time
    for _ in range(50):
        if app.state.test_calls:
            break
        time.sleep(0.05)
    assert app.state.test_calls and app.state.test_calls[0][0][1] == "op1"
    v = login(app, "viewer1")
    assert v.post("/collect", data={"csrf_token": page_csrf(v)}).status_code == 403


def test_collection_blocked_in_offline_mode(portal):
    app, _, settings = portal
    app.state.settings = Settings(_env_file=None, collector_mode="offline", data_dir=settings.data_dir)
    c = login(app, "op1")
    r = c.post("/collect", data={"csrf_token": page_csrf(c, "/collections")})
    assert "오프라인" in r.text and not app.state.test_calls


# ---------------- 관리자 ----------------
def test_admin_pages_rbac(portal):
    app, _, _ = portal
    for user in ("viewer1", "op1"):
        c = login(app, user)
        assert c.get("/admin/audit").status_code == 403
        assert c.get("/admin/policy").status_code == 403
    a = login(app, "admin1")
    html = a.get("/admin/audit?verify=1").text
    assert "무결성 검증 성공" in html and "LOGIN_SUCCESS" in html
    assert "2026.09-02" in a.get("/admin/policy").text


def test_policy_apply_by_admin(portal):
    app, factory, _ = portal
    a = login(app, "admin1")
    r = a.post("/admin/policy/apply", data={"csrf_token": page_csrf(a, "/admin/policy")})
    assert r.status_code == 200 and "적용 완료" in r.text


# ---------------- 감사로그 이벤트 커버리지 (요구사항 §15) ----------------
def test_required_audit_events_recorded_and_immutable(portal):
    app, factory, _ = portal
    op = login(app, "op1")
    # 업로드(→ Excel Upload / Asset 변경), 상태 변경, 담당자 변경, 매핑 승인/거부
    tok = page_csrf(op, "/assets/upload")
    op.post("/assets/upload", data={"csrf_token": tok},
            files={"file": ("sample_assets.xlsx", SAMPLE.read_bytes(), "application/octet-stream")})
    i = av_id(factory, "WEB-001", "CVE-2021-41773")
    op.post(f"/vulns/{i}/status", data={"status": "확인중", "csrf_token": page_csrf(op, f"/vulns/{i}")})
    op.post(f"/vulns/{i}/owner", data={"owner": "보안담당", "csrf_token": page_csrf(op, f"/vulns/{i}")})
    with factory() as s:
        pend = s.execute(select(MappingCandidate.id).where(
            MappingCandidate.status == CandidateStatus.PENDING).order_by(MappingCandidate.id)).scalars().all()
    op.post(f"/mappings/{pend[0]}/approve", data={"csrf_token": page_csrf(op, "/mappings")})
    op.post(f"/mappings/{pend[1]}/reject", data={"csrf_token": page_csrf(op, "/mappings")})
    adm = login(app, "admin1")
    adm.post("/admin/policy/apply", data={"csrf_token": page_csrf(adm, "/admin/policy")})
    with factory() as s:
        actions = set(s.execute(select(AuditLog.action)).scalars())
    required = {"LOGIN_SUCCESS", "EXCEL_UPLOAD", "ASSET_CHANGE", "MAPPING_APPROVE", "MAPPING_REJECT",
                "STATUS_CHANGE", "OWNER_CHANGE", "POLICY_CHANGE", "COLLECTION_MANUAL"}
    assert required <= actions, required - actions
    # 감사로그 수정/삭제 경로 없음 + 무결성 검증
    for method in ("post", "put", "delete", "patch"):
        assert getattr(adm, method)("/admin/audit").status_code in (403, 404, 405)
    assert "무결성 검증 성공" in adm.get("/admin/audit?verify=1").text
