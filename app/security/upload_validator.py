"""Excel(.xlsx) 업로드 보안 검증 및 안전한 저장.

검증 순서 (하나라도 실패하면 거부):
1. 확장자 allowlist (.xlsx)  2. 크기 제한  3. ZIP Signature(PK\\x03\\x04)
4. ZIP 구조: 엔트리 수, 경로(절대경로/..), 암호화, 총 해제크기, 압축비(Zip bomb)
5. OOXML 구조: [Content_Types].xml(defusedxml 파싱) 에 Workbook 본문 타입 존재,
   매크로/VBA/ActiveX/OLE/외부링크 구성요소 거부, xl/workbook.xml 존재
저장: 원본 파일명을 사용하지 않고 UUID 파일명으로 Web root 밖(DATA_DIR/uploads)에 저장
"""
from __future__ import annotations

import hashlib
import io
import os
import posixpath
import unicodedata
import uuid
import zipfile
from dataclasses import dataclass
from pathlib import Path

from defusedxml import ElementTree as DET
from defusedxml.common import DefusedXmlException

ALLOWED_EXTENSIONS = frozenset({".xlsx"})
ZIP_MAGIC = b"PK\x03\x04"
MAX_ENTRIES = 1000
MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_CONTENT_TYPES_BYTES = 1024 * 1024

WORKBOOK_MAIN = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
FORBIDDEN_CONTENT_TYPES = (
    "application/vnd.ms-excel.sheet.macroEnabled.main+xml",      # .xlsm
    "application/vnd.ms-excel.template.macroEnabled.main+xml",   # .xltm
    "application/vnd.ms-excel.addin.macroEnabled.main+xml",      # .xlam
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml",  # .xltx
    "application/vnd.ms-office.vbaProject",
    "application/vnd.ms-office.activeX",
    "application/vnd.ms-excel.sheet.binary.macroEnabled.main",   # .xlsb
)
FORBIDDEN_PARTS = ("vbaproject.bin", "/activex/", "/embeddings/", "/externallinks/", "vbadata.xml")

_CT_NS = "{http://schemas.openxmlformats.org/package/2006/content-types}"


class UploadRejected(ValueError):
    """사용자에게 보여도 되는 거부 사유만 메시지로 가진다."""


@dataclass(frozen=True)
class ValidatedUpload:
    display_name: str
    sha256: str
    size: int


def sanitize_display_name(filename: str | None) -> str:
    """표시/감사용 파일명 정제. 저장 경로로는 절대 사용하지 않는다."""
    name = (filename or "").replace("\\", "/")
    name = posixpath.basename(name)
    name = "".join(ch for ch in name if unicodedata.category(ch)[0] != "C")
    name = name.strip().strip(".")
    return (name or "upload.xlsx")[:255]


def _check_extension(display_name: str) -> None:
    ext = os.path.splitext(display_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise UploadRejected("허용되지 않는 파일 형식입니다. .xlsx 파일만 업로드할 수 있습니다.")


def _check_zip(data: bytes) -> zipfile.ZipFile:
    if not data.startswith(ZIP_MAGIC):
        raise UploadRejected("올바른 Excel(.xlsx) 파일이 아닙니다. (파일 서명 불일치)")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        raise UploadRejected("손상되었거나 올바르지 않은 Excel 파일입니다.") from None
    infos = zf.infolist()
    if not infos or len(infos) > MAX_ENTRIES:
        raise UploadRejected("Excel 파일 구조가 허용 범위를 벗어났습니다.")
    total = 0
    for info in infos:
        n = info.filename
        if n.startswith(("/", "\\")) or ".." in n.replace("\\", "/").split("/") or ":" in n:
            raise UploadRejected("Excel 파일 내부 경로가 올바르지 않습니다.")
        if info.flag_bits & 0x1:
            raise UploadRejected("암호화된 Excel 파일은 업로드할 수 없습니다.")
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise UploadRejected("Excel 파일의 압축 해제 크기가 허용 범위를 초과합니다.")
        if info.compress_size > 0 and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
            raise UploadRejected("비정상적인 압축 비율의 파일입니다.")
        if info.compress_size == 0 and info.file_size > 0:
            raise UploadRejected("비정상적인 압축 구조의 파일입니다.")
    return zf


def _check_ooxml(zf: zipfile.ZipFile) -> None:
    names = {i.filename for i in zf.infolist()}
    lower = [n.lower() for n in names]
    if "[Content_Types].xml" not in names or "xl/workbook.xml" not in names:
        raise UploadRejected("Excel 통합문서 구조가 아닙니다.")
    if any(p in "/" + n for n in lower for p in FORBIDDEN_PARTS):
        raise UploadRejected("매크로·ActiveX·외부연결·포함 개체가 있는 파일은 업로드할 수 없습니다.")
    raw = zf.read("[Content_Types].xml")
    if len(raw) > MAX_CONTENT_TYPES_BYTES:
        raise UploadRejected("Excel 파일 구조가 허용 범위를 벗어났습니다.")
    try:
        root = DET.fromstring(raw)
    except (DefusedXmlException, DET.ParseError):
        raise UploadRejected("Excel 파일 구조(XML)가 올바르지 않습니다.") from None
    types = {el.get("ContentType", "") for el in root.iter()
             if el.tag in (_CT_NS + "Override", _CT_NS + "Default")}
    if any(ct in types for ct in FORBIDDEN_CONTENT_TYPES):
        raise UploadRejected("매크로 포함 또는 허용되지 않는 Excel 형식입니다. .xlsx 파일만 허용됩니다.")
    if WORKBOOK_MAIN not in types:
        raise UploadRejected("일반 Excel 통합문서(.xlsx)가 아닙니다.")


def validate_xlsx_upload(filename: str | None, data: bytes, max_bytes: int) -> ValidatedUpload:
    display = sanitize_display_name(filename)
    _check_extension(display)
    if not data:
        raise UploadRejected("빈 파일입니다.")
    if len(data) > max_bytes:
        raise UploadRejected(f"파일 크기 제한({max_bytes // (1024 * 1024)}MB)을 초과했습니다.")
    with _check_zip(data) as zf:
        _check_ooxml(zf)
    return ValidatedUpload(display_name=display, sha256=hashlib.sha256(data).hexdigest(), size=len(data))


def store_upload(data: bytes, upload_dir: Path) -> tuple[str, Path]:
    """UUID 파일명으로 저장. (stored_id, path) 반환. 경로 이탈과 덮어쓰기를 방지한다."""
    upload_dir = upload_dir.resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    stored_id = str(uuid.uuid4())
    path = (upload_dir / f"{stored_id}.xlsx").resolve()
    if path.parent != upload_dir:
        raise UploadRejected("저장 경로 오류")
    with open(path, "xb") as f:   # 기존 파일 덮어쓰기 금지
        f.write(data)
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - Windows 등
        pass
    return stored_id, path
