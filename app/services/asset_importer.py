"""자산관리대장(.xlsx) 파싱·검증·반영.

정책
- 파일 단위 원자성: 오류 행이 하나라도 있으면 DB를 변경하지 않고 오류 목록을 반환한다.
- 같은 Asset ID가 여러 행이면 한 자산의 여러 제품(OS + 애플리케이션 등)으로 처리.
  자산 공통 필드(자산명/구분/IP/중요도/담당자/부서)는 행마다 동일해야 한다.
- 파일에 없는 기존 자산/제품은 삭제하지 않고 비활성화한다 (이력·매핑 보존).
- 제품 버전이 바뀌면 기존 매핑을 '재검증 필요'로 표시한다.
- 수식 셀은 거부한다. 모든 값은 텍스트로 취급하고 원본값과 정규화값을 분리 저장한다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from openpyxl import load_workbook
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models import Asset, AssetProduct, AssetVulnerability, ImportBatch
from app.models.enums import Criticality, Zone
from app.security.validators import ValidationError, clean_text, validate_ip
from app.services import audit
from app.services.cpe import try_parse_cpe, unescape

MAX_ROWS = 10_000
MAX_COLS = 60

# 표준 컬럼명 → 내부 키. 대소문자/공백 무시 비교.
COLUMNS = {
    "asset id": "asset_code", "자산명": "name", "자산구분": "zone", "ip": "ip",
    "vendor": "vendor", "product": "product", "version": "version", "cpe": "cpe",
    "중요도": "criticality", "담당자": "owner", "부서": "department",
}
REQUIRED = {"asset_code", "name", "zone", "ip", "vendor", "product", "version", "cpe",
            "criticality", "owner", "department"}
ASSET_CODE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,63}$")
ASSET_FIELDS = ("name", "zone", "ip", "criticality", "owner", "department")


class AssetImportError(ValueError):
    pass


@dataclass
class RowError:
    row: int
    column: str
    message: str


@dataclass
class ParsedProduct:
    row: int
    vendor_raw: str | None
    product_raw: str | None
    version_raw: str | None
    cpe_raw: str | None
    vendor_norm: str | None
    product_norm: str | None
    version_norm: str | None
    update_norm: str | None
    cpe_normalized: str | None
    cpe_error: str | None


@dataclass
class ParsedAsset:
    asset_code: str
    name: str
    zone: Zone
    ip: str
    criticality: Criticality
    owner: str | None
    department: str | None
    products: list[ParsedProduct] = field(default_factory=list)


@dataclass
class ParseResult:
    assets: dict[str, ParsedAsset]
    errors: list[RowError]
    warnings: list[RowError]
    row_count: int


def normalize_token(value: str | None) -> str | None:
    """Vendor/Product 정규화: 소문자, 공백·구분자 → '_', 허용문자 외 제거."""
    if not value:
        return None
    s = re.sub(r"[\s/\\,]+", "_", value.strip().lower())
    s = re.sub(r"[^a-z0-9_.\-+]", "", s)
    s = re.sub(r"_+", "_", s).strip("_")
    return s or None


def normalize_version(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip()
    if len(v) > 1 and v[0] in "vV" and v[1].isdigit():
        v = v[1:]
    return v or None


def _cell_text(cell, row: int, col_name: str, errors: list[RowError], warnings: list[RowError]) -> str | None:
    if cell is None or cell.value is None:
        return None
    if getattr(cell, "data_type", None) == "f":
        errors.append(RowError(row, col_name, "수식 셀은 허용되지 않습니다. 값만 입력하세요."))
        return None
    v = cell.value
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, (int, float)):
        if col_name in ("Version", "IP"):
            warnings.append(RowError(row, col_name, "숫자 형식 셀입니다. 텍스트 형식으로 입력하세요 (예: 8.10 → 8.1 변형 위험)."))
        return str(int(v)) if isinstance(v, float) and v.is_integer() else str(v)
    return str(v)


def parse_workbook(path: Path) -> ParseResult:
    try:
        wb = load_workbook(path, read_only=True, data_only=False, keep_links=False)
    except Exception:  # openpyxl 은 다양한 예외를 던짐 — 내부 상세는 노출하지 않음
        raise AssetImportError("Excel 파일을 읽을 수 없습니다.") from None
    try:
        ws = wb["자산목록"] if "자산목록" in wb.sheetnames else wb.worksheets[0]
        rows = ws.iter_rows(max_col=MAX_COLS)
        header_cells = next(rows, None)
        if header_cells is None:
            raise AssetImportError("빈 시트입니다.")
        colmap: dict[int, str] = {}
        headers_display: dict[str, str] = {}
        for idx, c in enumerate(header_cells):
            if c.value is None:
                continue
            key = COLUMNS.get(str(c.value).strip().lower())
            if key:
                colmap[idx] = key
                headers_display[key] = str(c.value).strip()
        missing = REQUIRED - set(colmap.values())
        if missing:
            inv = {v: k for k, v in COLUMNS.items()}
            raise AssetImportError("필수 컬럼 누락: " + ", ".join(sorted(inv[m] for m in missing)))

        errors: list[RowError] = []
        warnings: list[RowError] = []
        assets: dict[str, ParsedAsset] = {}
        row_count = 0
        for rno, cells in enumerate(rows, start=2):
            if rno - 1 > MAX_ROWS:
                raise AssetImportError(f"행 수 제한({MAX_ROWS})을 초과했습니다.")
            raw: dict[str, str | None] = {}
            for idx, key in colmap.items():
                cell = cells[idx] if idx < len(cells) else None
                raw[key] = _cell_text(cell, rno, headers_display[key], errors, warnings)
            if all(v is None or not str(v).strip() for v in raw.values()):
                continue   # 빈 행
            row_count += 1
            _parse_row(rno, raw, assets, errors, warnings)
        return ParseResult(assets=assets, errors=errors, warnings=warnings, row_count=row_count)
    finally:
        wb.close()


def _parse_row(rno: int, raw: dict, assets: dict[str, ParsedAsset],
               errors: list[RowError], warnings: list[RowError]) -> None:
    def text(key, label, max_len, required=False):
        try:
            v = clean_text(raw.get(key), max_len)
        except ValidationError:
            errors.append(RowError(rno, label, f"{max_len}자를 초과했습니다."))
            return None
        if required and not v:
            errors.append(RowError(rno, label, "필수 값입니다."))
        return v

    n_err = len(errors)
    code = text("asset_code", "Asset ID", 64, True)
    if code and not ASSET_CODE_RE.fullmatch(code):
        errors.append(RowError(rno, "Asset ID", "영문/숫자/_.- 만 사용할 수 있습니다 (최대 64자)."))
    name = text("name", "자산명", 128, True)
    zone_s = text("zone", "자산구분", 8, True)
    zone = next((z for z in Zone if z.value == zone_s), None)
    if zone_s and zone is None:
        errors.append(RowError(rno, "자산구분", "'경계면' 또는 '내부'만 허용됩니다."))
    ip_s = text("ip", "IP", 45, True)
    ip = None
    if ip_s:
        try:
            ip = validate_ip(ip_s)
        except ValidationError:
            errors.append(RowError(rno, "IP", "올바른 IP 주소 형식이 아닙니다."))
    crit_s = text("criticality", "중요도", 4, True)
    crit = next((c for c in Criticality if c.value == crit_s), None)
    if crit_s and crit is None:
        errors.append(RowError(rno, "중요도", "'상', '중', '하'만 허용됩니다."))
    owner = text("owner", "담당자", 64)
    dept = text("department", "부서", 128)
    vendor = text("vendor", "Vendor", 128)
    product = text("product", "Product", 128)
    version = text("version", "Version", 64)
    cpe_raw = text("cpe", "CPE", 512)

    cpe, cpe_err = try_parse_cpe(cpe_raw)
    if cpe_err:
        warnings.append(RowError(rno, "CPE", f"잘못된 CPE — CPE 매칭에서 제외하고 제품정보로 후보 매칭합니다 ({cpe_err})."))
    if not cpe and not product:
        errors.append(RowError(rno, "Product", "CPE가 없으면 Product는 필수입니다."))
    if len(errors) > n_err:
        return

    if cpe:
        vendor_norm, product_norm = unescape(cpe.vendor), unescape(cpe.product)
        version_norm = cpe.version if cpe.version not in ("*", "-") else normalize_version(version)
        update_norm = None if cpe.update in ("*", "-") else cpe.update
        if version and cpe.version not in ("*", "-") and normalize_version(version) != cpe.version:
            warnings.append(RowError(rno, "Version", f"Version({version})과 CPE 버전({cpe.version})이 다릅니다. CPE 값을 사용합니다."))
        if cpe.version in ("*", "-"):
            warnings.append(RowError(rno, "CPE", "CPE에 버전이 없어 버전 비교가 불가합니다 (검토 필요로 처리)."))
    else:
        vendor_norm, product_norm = normalize_token(vendor), normalize_token(product)
        version_norm, update_norm = normalize_version(version), None

    pp = ParsedProduct(rno, vendor, product, version, cpe_raw, vendor_norm, product_norm,
                       version_norm, update_norm, cpe.to_string() if cpe else None, cpe_err)
    a = assets.get(code)
    if a is None:
        assets[code] = ParsedAsset(code, name, zone, ip, crit, owner, dept, [pp])
        return
    for f, v in (("name", name), ("zone", zone), ("ip", ip), ("criticality", crit),
                 ("owner", owner), ("department", dept)):
        if getattr(a, f) != v:
            errors.append(RowError(rno, f, f"같은 Asset ID({code})의 다른 행과 값이 다릅니다."))
            return
    if any((p.vendor_norm, p.product_norm) == (vendor_norm, product_norm) for p in a.products):
        errors.append(RowError(rno, "Product", f"같은 자산에 동일 제품이 중복되었습니다 ({vendor_norm}:{product_norm})."))
        return
    a.products.append(pp)


@dataclass
class ImportSummary:
    batch_id: int
    assets_created: int = 0
    assets_updated: int = 0
    assets_deactivated: int = 0
    products_created: int = 0
    products_updated: int = 0
    products_deactivated: int = 0
    revalidation_flagged: int = 0


def _asset_snapshot(a: Asset) -> dict:
    return {"name": a.name, "zone": a.zone.value, "ip": a.ip, "criticality": a.criticality.value,
            "owner": a.owner_name, "department": a.department, "is_active": a.is_active}


def apply_import(session: Session, parsed: ParseResult, *, actor: str, actor_role: str | None,
                 stored_file_id: str, display_name: str, sha256: str, size: int,
                 client_ip: str | None = None) -> ImportSummary:
    """검증 통과한 결과를 호출자 트랜잭션 안에서 반영."""
    if parsed.errors:
        raise AssetImportError("검증 오류가 있어 반영할 수 없습니다.")
    batch = ImportBatch(stored_file_id=stored_file_id, original_filename=display_name, sha256=sha256,
                        size_bytes=size, row_count=parsed.row_count, error_count=0, uploaded_by=actor)
    session.add(batch)
    session.flush()
    summary = ImportSummary(batch_id=batch.id)

    existing = {a.asset_code: a for a in session.execute(select(Asset)).scalars()}
    for code, pa in parsed.assets.items():
        a = existing.get(code)
        if a is None:
            a = Asset(asset_code=code, name=pa.name, zone=pa.zone, ip=pa.ip, criticality=pa.criticality,
                      owner_name=pa.owner, department=pa.department, is_active=True,
                      import_batch_id=batch.id)
            session.add(a)
            session.flush()
            summary.assets_created += 1
            audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.ASSET_CHANGE,
                         target_type="asset", target_id=code, after=_asset_snapshot(a), client_ip=client_ip)
        else:
            before = _asset_snapshot(a)
            a.name, a.zone, a.ip, a.criticality = pa.name, pa.zone, pa.ip, pa.criticality
            a.owner_name, a.department, a.is_active = pa.owner, pa.department, True
            a.import_batch_id = batch.id
            after = _asset_snapshot(a)
            if before != after:
                summary.assets_updated += 1
                audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.ASSET_CHANGE,
                             target_type="asset", target_id=code, before=before, after=after,
                             client_ip=client_ip)
                if before["owner"] != after["owner"]:
                    # 담당자 변경: 미종결 취약점의 담당자도 갱신 + 별도 감사
                    session.execute(update(AssetVulnerability)
                                    .where(AssetVulnerability.asset_id == a.id,
                                           AssetVulnerability.owner_override.is_(False))
                                    .values(owner=a.owner_name))
                    audit.record(session, actor=actor, actor_role=actor_role,
                                 action=audit.AuditAction.OWNER_CHANGE, target_type="asset",
                                 target_id=code, before={"owner": before["owner"]},
                                 after={"owner": after["owner"]}, client_ip=client_ip)
        _sync_products(session, a, pa, summary)

    for code, a in existing.items():
        if code not in parsed.assets and a.is_active:
            before = _asset_snapshot(a)
            a.is_active = False
            summary.assets_deactivated += 1
            audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.ASSET_CHANGE,
                         target_type="asset", target_id=code, before=before, after=_asset_snapshot(a),
                         client_ip=client_ip)

    audit.record(session, actor=actor, actor_role=actor_role, action=audit.AuditAction.EXCEL_UPLOAD,
                 target_type="import_batch", target_id=batch.id, client_ip=client_ip,
                 after={"file": display_name, "sha256": sha256, "size": size, "rows": parsed.row_count,
                        "summary": {k: v for k, v in summary.__dict__.items() if k != "batch_id"}})
    session.flush()
    return summary


def _sync_products(session: Session, asset: Asset, pa: ParsedAsset, summary: ImportSummary) -> None:
    current = {(p.vendor_norm, p.product_norm): p for p in asset.products}
    seen = set()
    for pp in pa.products:
        key = (pp.vendor_norm, pp.product_norm)
        seen.add(key)
        p = current.get(key)
        if p is None:
            session.add(AssetProduct(
                asset_id=asset.id, vendor_raw=pp.vendor_raw, product_raw=pp.product_raw,
                version_raw=pp.version_raw, cpe_raw=pp.cpe_raw, vendor_norm=pp.vendor_norm,
                product_norm=pp.product_norm, version_norm=pp.version_norm, update_norm=pp.update_norm,
                cpe_normalized=pp.cpe_normalized, cpe_source="excel" if pp.cpe_normalized else None,
                cpe_error=pp.cpe_error, is_active=True))
            summary.products_created += 1
            continue
        changed_identity = (p.version_norm, p.update_norm, p.cpe_normalized) != \
            (pp.version_norm, pp.update_norm, pp.cpe_normalized)
        fields = dict(vendor_raw=pp.vendor_raw, product_raw=pp.product_raw, version_raw=pp.version_raw,
                      cpe_raw=pp.cpe_raw, version_norm=pp.version_norm, update_norm=pp.update_norm,
                      cpe_normalized=pp.cpe_normalized, cpe_error=pp.cpe_error, is_active=True)
        if any(getattr(p, k) != v for k, v in fields.items()):
            for k, v in fields.items():
                setattr(p, k, v)
            p.cpe_source = "excel" if pp.cpe_normalized else p.cpe_source if p.cpe_source == "mapping" else None
            summary.products_updated += 1
        if changed_identity:
            res = session.execute(update(AssetVulnerability)
                                  .where(AssetVulnerability.asset_product_id == p.id)
                                  .values(needs_revalidation=True))
            summary.revalidation_flagged += res.rowcount or 0
    for key, p in current.items():
        if key not in seen and p.is_active:
            p.is_active = False
            summary.products_deactivated += 1
            res = session.execute(update(AssetVulnerability)
                                  .where(AssetVulnerability.asset_product_id == p.id)
                                  .values(needs_revalidation=True))
            summary.revalidation_flagged += res.rowcount or 0


# ---------------------------------------------------------------------------
# 업로드 처리 흐름: 보안검증 → UUID 저장 → 파싱/검증 → (오류 없으면) 단일 트랜잭션 반영
# ---------------------------------------------------------------------------
@dataclass
class AssetUploadOutcome:
    ok: bool
    message: str
    errors: list[RowError] = field(default_factory=list)
    warnings: list[RowError] = field(default_factory=list)
    summary: ImportSummary | None = None
    asset_count: int = 0
    mapping: object | None = None   # MappingSummary


def import_asset_upload(session_factory, *, filename: str | None, data: bytes, actor: str,
                        actor_role: str | None, upload_dir: Path, max_bytes: int,
                        client_ip: str | None = None, policy_file: Path | None = None) -> AssetUploadOutcome:
    from app.security.upload_validator import UploadRejected, store_upload, validate_xlsx_upload

    def _audit_failure(reason: str, display: str | None, sha: str | None) -> None:
        with session_factory() as s:
            audit.record(s, actor=actor, actor_role=actor_role, action=audit.AuditAction.EXCEL_UPLOAD,
                         target_type="upload", client_ip=client_ip, result="failure",
                         after={"file": display, "sha256": sha, "reason": reason[:300]})
            s.commit()

    try:
        v = validate_xlsx_upload(filename, data, max_bytes)
    except UploadRejected as e:
        from app.security.upload_validator import sanitize_display_name
        _audit_failure(str(e), sanitize_display_name(filename), None)
        return AssetUploadOutcome(ok=False, message=str(e))

    stored_id, path = store_upload(data, upload_dir)
    try:
        parsed = parse_workbook(path)
    except AssetImportError as e:
        _audit_failure(str(e), v.display_name, v.sha256)
        return AssetUploadOutcome(ok=False, message=str(e))
    if parsed.errors:
        _audit_failure(f"validation errors: {len(parsed.errors)}", v.display_name, v.sha256)
        return AssetUploadOutcome(ok=False, message=f"검증 오류 {len(parsed.errors)}건 — 반영하지 않았습니다.",
                                  errors=parsed.errors, warnings=parsed.warnings)
    with session_factory() as s:
        try:
            summary = apply_import(s, parsed, actor=actor, actor_role=actor_role, stored_file_id=stored_id,
                                   display_name=v.display_name, sha256=v.sha256, size=v.size,
                                   client_ip=client_ip)
            s.commit()
        except Exception:
            s.rollback()
            raise
    mapping = None
    if policy_file is not None:
        from app.services.mapping_service import run_mapping_with_active_policy
        with session_factory() as s:
            try:
                mapping = run_mapping_with_active_policy(s, actor=actor, policy_file=policy_file)
                s.commit()
            except Exception:  # noqa: BLE001 - 자산 반영은 유지, 매핑은 재실행 가능
                s.rollback()
                import logging
                logging.getLogger(__name__).exception("mapping after asset import failed")
    return AssetUploadOutcome(ok=True, message="자산관리대장을 반영했습니다.", warnings=parsed.warnings,
                              summary=summary, asset_count=len(parsed.assets), mapping=mapping)
