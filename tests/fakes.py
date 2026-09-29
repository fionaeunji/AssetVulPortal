"""외부 API를 흉내내는 httpx MockTransport (녹화 Fixture 기반, 네트워크 미사용)."""
from __future__ import annotations

import gzip
import json
from datetime import date
from pathlib import Path

import httpx

FIX = Path(__file__).parent / "fixtures"


def load_nvd_records() -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8"))
            for p in sorted((FIX / "nvd_records").glob("CVE-*.json"))]


def _product_keys(cve: dict) -> set[str]:
    keys = set()
    for cfg in cve.get("configurations", []):
        for node in cfg["nodes"]:
            for m in node["cpeMatch"]:
                keys.add(":".join(m["criteria"].split(":")[2:5]))
    return keys


def make_epss_csv_gz(rows: dict[str, tuple[float, float]], score_date: date) -> bytes:
    lines = [f"#model_version:v2025.03.14,score_date:{score_date.isoformat()}T00:00:00+0000",
             "cve,epss,percentile"]
    lines += [f"{c},{e:.5f},{p:.5f}" for c, (e, p) in rows.items()]
    return gzip.compress("\n".join(lines).encode())


class FakeExternal:
    """호출 기록과 장애 주입을 지원하는 가짜 NVD/EPSS/KEV."""

    def __init__(self, nvd_records: list[dict] | None = None,
                 epss: dict[str, tuple[float, float]] | None = None,
                 epss_date: date = date(2026, 9, 27)) -> None:
        self.nvd_records = nvd_records if nvd_records is not None else load_nvd_records()
        self.epss = epss or {}
        self.epss_date = epss_date
        self.kev_bytes = (FIX / "kev_sample.json").read_bytes()
        self.fail: set[str] = set()          # {"nvd", "epss", "kev"}
        self.nvd_status_sequence: list[int] = []   # 순서대로 반환할 상태코드 (장애 주입)
        self.calls: list[httpx.Request] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        host = req.url.host
        if host == "services.nvd.nist.gov":
            return self._nvd(req)
        if host == "api.first.org":
            if "epss" in self.fail:
                return httpx.Response(503)
            cves = req.url.params.get("cve", "").split(",")
            data = [{"cve": c, "epss": f"{self.epss[c][0]:.9f}", "percentile": f"{self.epss[c][1]:.9f}",
                     "date": self.epss_date.isoformat()} for c in cves if c in self.epss]
            return httpx.Response(200, json={"status": "OK", "status-code": 200, "version": "1.0",
                                             "total": len(data), "offset": 0, "limit": 100, "data": data})
        if host == "epss.empiricalsecurity.com":
            if "epss" in self.fail:
                return httpx.Response(503)
            return httpx.Response(200, content=make_epss_csv_gz(self.epss, self.epss_date))
        if host == "www.cisa.gov":
            if "kev" in self.fail:
                return httpx.Response(500)
            return httpx.Response(200, content=self.kev_bytes)
        return httpx.Response(404)

    def _nvd(self, req: httpx.Request) -> httpx.Response:
        if self.nvd_status_sequence:
            code = self.nvd_status_sequence.pop(0)
            if code != 200:
                return httpx.Response(code)
        if "nvd" in self.fail:
            return httpx.Response(503)
        vms = req.url.params.get("virtualMatchString", "")
        key = ":".join(vms.split(":")[2:5])
        items = [r for r in self.nvd_records if key in _product_keys(r)]
        per = int(req.url.params.get("resultsPerPage", 2000))
        start = int(req.url.params.get("startIndex", 0))
        page = items[start:start + per]
        return httpx.Response(200, json={
            "resultsPerPage": len(page), "startIndex": start, "totalResults": len(items),
            "format": "NVD_CVE", "version": "2.0", "timestamp": "2026-09-28T00:00:00.000",
            "vulnerabilities": [{"cve": r} for r in page],
        })
