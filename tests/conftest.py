"""Shared fixtures. Network calls are replaced by a fake transport that serves
synthetic OSV.dev and CISA KEV data (IDs like CVE-2099-xxxx are made up)."""

from __future__ import annotations

from pathlib import Path

import pytest

from cra_kit import scan as scan_mod

FIXTURES = Path(__file__).parent / "fixtures"

# purl -> advisory IDs that the fake OSV querybatch endpoint returns.
OSV_HITS = {
    "pkg:npm/express@4.18.2": ["GHSA-test-kev1-0001"],
    "pkg:npm/%40babel/core@7.23.0": ["GHSA-test-scop-0003"],
    "pkg:pypi/django@4.2.7": ["PYSEC-TEST-0002"],
}

OSV_VULNS = {
    "GHSA-test-kev1-0001": {
        "id": "GHSA-test-kev1-0001",
        "aliases": ["CVE-2099-0001"],
        "summary": "Synthetic open redirect in express",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"}],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "express", "purl": "pkg:npm/express"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.19.2"}]}],
            },
            {
                "package": {"ecosystem": "npm", "name": "not-express"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
            },
        ],
    },
    "GHSA-test-scop-0003": {
        "id": "GHSA-test-scop-0003",
        "aliases": ["CVE-2099-0003"],
        "summary": "Synthetic code execution in @babel/core",
        "database_specific": {"severity": "CRITICAL"},
        "affected": [
            {
                "package": {"ecosystem": "npm", "name": "@babel/core"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "7.0.0"}, {"fixed": "7.23.2"}]}],
            }
        ],
    },
    "PYSEC-TEST-0002": {
        "id": "PYSEC-TEST-0002",
        "aliases": ["CVE-2099-0002", "GHSA-test-djan-0002"],
        "details": "Synthetic denial of service in Django when parsing very long headers. " * 5,
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Django", "purl": "pkg:pypi/django"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "4.2"}, {"fixed": "4.2.8"}]}],
            }
        ],
    },
}

KEV = {
    "title": "Synthetic KEV catalogue",
    "vulnerabilities": [
        {"cveID": "CVE-2099-0001", "dateAdded": "2026-09-15", "vendorProject": "Example"},
        {"cveID": "CVE-2099-9999", "dateAdded": "2026-01-01", "vendorProject": "Other"},
    ],
}


class FakeTransport:
    def __init__(self, kev_fails: bool = False, osv_fails: bool = False):
        self.calls: list[tuple[str, str]] = []
        self.kev_fails = kev_fails
        self.osv_fails = osv_fails

    def __call__(self, method: str, url: str, body: dict | None = None) -> dict:
        self.calls.append((method, url))
        if url == scan_mod.OSV_BATCH_URL:
            if self.osv_fails:
                raise OSError("network unreachable")
            results = []
            for query in body["queries"]:
                ids = OSV_HITS.get(query["package"]["purl"], [])
                results.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in ids]} if ids else {})
            return {"results": results}
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            return OSV_VULNS[url.rsplit("/", 1)[1]]
        if url == scan_mod.KEV_URL:
            if self.kev_fails:
                raise OSError("KEV feed unavailable")
            return KEV
        raise AssertionError(f"unexpected request {method} {url}")


@pytest.fixture
def transport() -> FakeTransport:
    return FakeTransport()


@pytest.fixture
def offline_scan(monkeypatch):
    """Route the CLI's scans through the fake transport."""
    real_scan = scan_mod.scan
    fake = FakeTransport()

    def patched(purls, transport=None, check_kev=True):
        return real_scan(purls, transport=fake, check_kev=check_kev)

    monkeypatch.setattr(scan_mod, "scan", patched)
    return fake
