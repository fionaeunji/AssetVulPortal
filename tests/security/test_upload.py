"""악성/비정상 Excel 업로드 방어 테스트."""
from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest
from openpyxl import Workbook

from app.security.upload_validator import (
    UploadRejected,
    sanitize_display_name,
    store_upload,
    validate_xlsx_upload,
)

MAX = 5 * 1024 * 1024
SAMPLE = Path(__file__).resolve().parents[2] / "sample_data" / "sample_assets.xlsx"

CT_OK = ('<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
         '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
CT_MACRO = CT_OK.replace("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml",
                         "application/vnd.ms-excel.sheet.macroEnabled.main+xml")


def valid_xlsx() -> bytes:
    wb = Workbook()
    wb.active.append(["a"])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def make_zip(entries: dict[str, bytes | str], compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_valid_xlsx_accepted():
    v = validate_xlsx_upload("자산.xlsx", SAMPLE.read_bytes(), MAX)
    assert v.display_name == "자산.xlsx" and len(v.sha256) == 64


@pytest.mark.parametrize("name", ["a.xls", "a.xlsm", "a.exe", "a.js", "a.html", "a.zip", "a", "a.xlsx.exe"])
def test_disallowed_extensions(name):
    with pytest.raises(UploadRejected):
        validate_xlsx_upload(name, valid_xlsx(), MAX)


def test_renamed_exe_rejected_by_signature():
    with pytest.raises(UploadRejected, match="서명"):
        validate_xlsx_upload("a.xlsx", b"MZ\x90\x00" + b"\x00" * 100, MAX)


def test_renamed_html_js_rejected():
    for payload in (b"<html><script>alert(1)</script></html>", b"alert(1);"):
        with pytest.raises(UploadRejected):
            validate_xlsx_upload("a.xlsx", payload, MAX)


def test_legacy_xls_ole_rejected():
    with pytest.raises(UploadRejected):
        validate_xlsx_upload("a.xlsx", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 512, MAX)


def test_plain_zip_renamed_rejected():
    with pytest.raises(UploadRejected, match="통합문서"):
        validate_xlsx_upload("a.xlsx", make_zip({"readme.txt": "hi"}), MAX)


def test_xlsm_disguised_as_xlsx_rejected():
    data = make_zip({"[Content_Types].xml": CT_MACRO, "xl/workbook.xml": "<workbook/>"})
    with pytest.raises(UploadRejected, match="매크로"):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_vba_project_part_rejected():
    data = make_zip({"[Content_Types].xml": CT_OK, "xl/workbook.xml": "<workbook/>",
                     "xl/vbaProject.bin": b"\x00" * 10})
    with pytest.raises(UploadRejected, match="매크로"):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_external_link_part_rejected():
    data = make_zip({"[Content_Types].xml": CT_OK, "xl/workbook.xml": "<workbook/>",
                     "xl/externalLinks/externalLink1.xml": "<x/>"})
    with pytest.raises(UploadRejected):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_zip_path_traversal_entry_rejected():
    data = make_zip({"[Content_Types].xml": CT_OK, "xl/workbook.xml": "<workbook/>",
                     "../../evil.txt": "x"})
    with pytest.raises(UploadRejected, match="경로"):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_zip_bomb_rejected():
    data = make_zip({"[Content_Types].xml": CT_OK, "xl/workbook.xml": "<workbook/>",
                     "xl/worksheets/sheet1.xml": b"0" * (20 * 1024 * 1024)})
    assert len(data) < MAX
    with pytest.raises(UploadRejected):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_xml_entity_expansion_rejected():
    bomb = ('<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">&lol2;</Types>')
    data = make_zip({"[Content_Types].xml": bomb, "xl/workbook.xml": "<workbook/>"})
    with pytest.raises(UploadRejected, match="XML"):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_xxe_rejected():
    xxe = ('<?xml version="1.0"?><!DOCTYPE t [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">&x;</Types>')
    data = make_zip({"[Content_Types].xml": xxe, "xl/workbook.xml": "<workbook/>"})
    with pytest.raises(UploadRejected):
        validate_xlsx_upload("a.xlsx", data, MAX)


def test_size_limit_and_empty():
    with pytest.raises(UploadRejected, match="크기"):
        validate_xlsx_upload("a.xlsx", valid_xlsx(), 1024)
    with pytest.raises(UploadRejected, match="빈 파일"):
        validate_xlsx_upload("a.xlsx", b"", MAX)


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd.xlsx", "passwd.xlsx"),
    ("..\\..\\windows\\system32\\a.xlsx", "a.xlsx"),
    ("C:\\Users\\x\\자산 대장.xlsx", "자산 대장.xlsx"),
    ("a\x00b\u202e.xlsx", "ab.xlsx"),
    ("", "upload.xlsx"),
    (None, "upload.xlsx"),
])
def test_display_name_sanitized(raw, expected):
    assert sanitize_display_name(raw) == expected


def test_path_traversal_filename_cannot_escape_upload_dir(tmp_path):
    up = tmp_path / "uploads"
    v = validate_xlsx_upload("../../../../evil.xlsx", valid_xlsx(), MAX)
    stored_id, path = store_upload(valid_xlsx(), up)
    assert path.parent == up.resolve()
    assert path.name == f"{stored_id}.xlsx" and "evil" not in path.name
    assert v.display_name == "evil.xlsx"
    assert not (tmp_path / "evil.xlsx").exists()
