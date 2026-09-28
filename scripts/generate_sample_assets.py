"""샘플 자산관리대장(sample_data/sample_assets.xlsx) 생성.

모든 데이터는 가상의 테스트 데이터다.
- IP: 문서/예제 전용 대역(RFC 5737: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)만 사용
- 자산명/담당자/부서: 가상 명칭
- 일부 자산은 실제 NVD CVE와 매칭되도록 취약 버전으로 구성 (매칭 기대값은 '비고' 열)

사용: python -m scripts.generate_sample_assets
"""
from __future__ import annotations

from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill
from openpyxl.worksheet.datavalidation import DataValidation

OUT = Path(__file__).resolve().parents[1] / "sample_data" / "sample_assets.xlsx"

HEADERS = ["Asset ID", "자산명", "자산구분", "IP", "Vendor", "Product", "Version", "CPE",
           "중요도", "담당자", "부서", "비고"]

# (Asset ID, 자산명, 자산구분, IP, Vendor, Product, Version, CPE, 중요도, 담당자, 부서, 비고)
ROWS = [
    ("WEB-001", "web-dmz-01", "경계면", "203.0.113.10", "Apache", "HTTP Server", "2.4.49",
     "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", "상", "가상담당자01", "가상인프라팀",
     "CPE Exact: CVE-2021-41773, CVE-2021-42013"),
    ("WEB-002", "web-dmz-02", "경계면", "203.0.113.11", "Apache", "HTTP Server", "2.4.62",
     "cpe:2.3:a:apache:http_server:2.4.62:*:*:*:*:*:*:*", "상", "가상담당자01", "가상인프라팀",
     "패치된 버전: 41773/42013 미해당 기대"),
    ("WAS-001", "was-app-01", "내부", "192.0.2.21", "Apache", "Tomcat", "9.0.30",
     "cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*", "상", "가상담당자02", "가상개발팀",
     "Version Range: CVE-2020-1938(9.0.0~9.0.31 미만), CVE-2024-24549"),
    ("WAS-002", "was-app-02", "내부", "192.0.2.22", "Apache", "Tomcat", "8.5.50", "",
     "중", "가상담당자02", "가상개발팀", "CPE 없음 → Level 2 후보"),
    ("FW-001", "fw-edge-01", "경계면", "198.51.100.1", "Fortinet", "FortiOS", "7.2.4",
     "cpe:2.3:o:fortinet:fortios:7.2.4:*:*:*:*:*:*:*", "상", "가상담당자03", "가상보안팀",
     "Version Range: CVE-2024-21762(7.2.0~7.2.7 미만)"),
    ("FW-002", "fw-edge-02", "경계면", "198.51.100.2", "Fortinet", "FortiOS", "7.4.3",
     "cpe:2.3:o:fortinet:fortios:7.4.3:*:*:*:*:*:*:*", "상", "가상담당자03", "가상보안팀",
     "Range 제외: CVE-2024-21762(7.4.3 미만) 미해당 기대"),
    ("RT-001", "rt-core-01", "경계면", "198.51.100.5", "Cisco", "IOS XE", "17.9.3",
     "cpe:2.3:o:cisco:ios_xe:17.9.3:*:*:*:*:*:*:*", "상", "가상담당자04", "가상네트워크팀",
     "Version Range: CVE-2023-20198(17.9~17.9.4a 미만)"),
    ("VC-001", "vcenter-01", "내부", "192.0.2.30", "VMware", "vCenter Server", "6.5",
     "cpe:2.3:a:vmware:vcenter_server:6.5:update1d:*:*:*:*:*:*", "상", "가상담당자05", "가상인프라팀",
     "CPE Exact(update 필드): CVE-2021-21972"),
    ("ESX-001", "esxi-01", "내부", "192.0.2.31", "VMware", "ESXi", "7.0 U3", "",
     "중", "가상담당자05", "가상인프라팀", "CPE 없음 → Level 2 후보"),
    ("WIN-001", "win-ad-01", "내부", "192.0.2.40", "Microsoft", "Windows Server 2022", "10.0.20348.2582",
     "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2582:*:*:*:*:*:*:*", "상", "가상담당자06",
     "가상인프라팀", "Version Range: CVE-2024-38063(10.0.20348.2655 미만)"),
    ("WIN-002", "win-file-01", "내부", "192.0.2.41", "Microsoft", "Windows Server 2022", "10.0.20348.2700",
     "cpe:2.3:o:microsoft:windows_server_2022:10.0.20348.2700:*:*:*:*:*:*:*", "중", "가상담당자06",
     "가상인프라팀", "Range 제외: CVE-2024-38063 미해당 기대"),
    ("LNX-001", "ubuntu-app-01", "내부", "192.0.2.50", "Canonical", "Ubuntu Linux", "22.04",
     "cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*", "중", "가상담당자07", "가상개발팀",
     "OS"),
    ("LNX-001", "ubuntu-app-01", "내부", "192.0.2.50", "OpenBSD", "OpenSSH", "8.9",
     "cpe:2.3:a:openbsd:openssh:8.9:p1:*:*:*:*:*:*", "중", "가상담당자07", "가상개발팀",
     "동일 자산 다중 제품: CVE-2024-6387(8.6~9.8), CVE-2023-38408"),
    ("LNX-002", "rhel-db-01", "내부", "192.0.2.51", "Red Hat", "Enterprise Linux", "8.10", "",
     "상", "가상담당자08", "가상DB팀", "CPE 없음 → Level 2 후보"),
    ("DB-001", "pg-db-01", "내부", "192.0.2.60", "PostgreSQL", "PostgreSQL", "13.11",
     "cpe:2.3:a:postgresql:postgresql:13.11:*:*:*:*:*:*:*", "상", "가상담당자08", "가상DB팀",
     "Version Range: CVE-2023-39417(13.0~13.12 미만)"),
    ("DB-002", "ora-db-01", "내부", "192.0.2.61", "Oracle", "Database Server", "19c", "",
     "상", "가상담당자08", "가상DB팀", "CPE 없음 → Level 2 후보"),
    ("APP-001", "app-batch-01", "내부", "192.0.2.70", "Oracle", "Java SE", "8u401", "",
     "중", "가상담당자09", "가상개발팀", "CPE 없음, 벤더 버전표기(8u401) → Level 2/검토"),
    ("APP-002", "app-api-01", "내부", "192.0.2.71", "Oracle", "JDK", "17.0.2",
     "cpe:2.3:a:oracle:jdk:17.0.2:*:*:*:*:*:*:*", "중", "가상담당자09", "가상개발팀",
     "CPE Exact: CVE-2022-21449"),
    ("APP-003", "app-log-01", "내부", "192.0.2.72", "Apache", "Log4j", "2.14.1",
     "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "상", "가상담당자09", "가상개발팀",
     "Version Range: CVE-2021-44228(2.13.0~2.15.0 미만)"),
    ("APP-004", "build-01", "내부", "192.0.2.73", "Tukaani", "XZ Utils", "5.6.0",
     "cpe:2.3:a:tukaani:xz:5.6.0:*:*:*:*:*:*:*", "하", "가상담당자10", "가상개발팀",
     "CPE Exact: CVE-2024-3094"),
    ("PC-001", "vdi-pc-01", "내부", "192.0.2.80", "Google", "Chrome", "116.0.5845.96",
     "cpe:2.3:a:google:chrome:116.0.5845.96:*:*:*:*:*:*:*", "하", "가상담당자11", "가상사무팀",
     "Version Range: CVE-2023-4863(116.0.5845.187 미만)"),
    ("PC-002", "vdi-pc-02", "내부", "192.0.2.81", "Google", "Chrome", "129.0.6668.58",
     "cpe:2.3:a:google:chrome:129.0.6668.58:*:*:*:*:*:*:*", "하", "가상담당자11", "가상사무팀",
     "Range 제외: CVE-2023-4863 미해당 기대"),
    ("MAIL-001", "mail-gw-01", "경계면", "203.0.113.25", "Example", "Mail Gateway", "3.1",
     "cpe:2.3:a:example:mail gateway:3.1", "중", "가상담당자12", "가상보안팀",
     "잘못된 CPE(공백·필드 부족) → 오류 표시 후 Level 2"),
]


def main() -> None:
    wb = Workbook()
    ws = wb.active
    ws.title = "자산목록"
    ws.append(HEADERS)
    for c in ws[1]:
        c.font = Font(bold=True)
        c.fill = PatternFill("solid", fgColor="DDEBF7")
    for row in ROWS:
        ws.append(list(row))
    # 모든 값을 문자열(텍스트) 셀로 저장 — 버전 '8.10' 같은 값이 숫자로 바뀌지 않도록
    for r in ws.iter_rows(min_row=2):
        for c in r:
            c.number_format = "@"
    for col, width in zip("ABCDEFGHIJKL", (10, 16, 8, 15, 12, 22, 16, 62, 6, 12, 14, 50)):
        ws.column_dimensions[col].width = width
    n = len(ROWS) + 1
    zone = DataValidation(type="list", formula1='"경계면,내부"', allow_blank=False)
    crit = DataValidation(type="list", formula1='"상,중,하"', allow_blank=False)
    ws.add_data_validation(zone)
    ws.add_data_validation(crit)
    zone.add(f"C2:C{n + 200}")
    crit.add(f"I2:I{n + 200}")
    ws.freeze_panes = "A2"
    OUT.parent.mkdir(parents=True, exist_ok=True)
    wb.save(OUT)
    print(f"생성: {OUT} (행 {len(ROWS)}, 자산 {len({r[0] for r in ROWS})}개)")


if __name__ == "__main__":
    main()
