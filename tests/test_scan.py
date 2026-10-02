from __future__ import annotations

import pytest

from cra_kit import scan as scan_mod
from cra_kit.scan import osv_query, purl_key, scan, to_markdown

from conftest import FakeTransport

PURLS = [
    "pkg:npm/express@4.18.2",
    "pkg:npm/%40babel/core@7.23.0",
    "pkg:pypi/django@4.2.7",
    "pkg:npm/body-parser@1.20.1",
    "pkg:npm/no-version",  # skipped: advisories need a version
]


def test_scan_findings_and_kev(transport):
    result = scan(PURLS, transport=transport)
    assert result.scanned == 4
    assert result.vulnerable_components == 3
    assert result.kev_checked
    first = result.findings[0]
    assert first.id == "GHSA-test-kev1-0001"  # known exploited sorts first
    assert first.known_exploited and first.kev_date_added == "2026-09-15"
    assert first.fixed_versions == ["4.19.2"]  # other package's range ignored
    assert first.cves == ["CVE-2099-0001"]
    assert first.cvss.startswith("CVSS:3.1/")
    ids = [f.id for f in result.findings]
    assert ids == ["GHSA-test-kev1-0001", "GHSA-test-scop-0003", "PYSEC-TEST-0002"]  # then by severity
    babel = result.findings[1]
    assert babel.fixed_versions == ["7.23.2"]  # scoped npm name matched without an affected purl
    django = result.findings[2]
    assert django.severity == "UNKNOWN"
    assert django.fixed_versions == ["4.2.8"]
    assert len(django.summary) <= 160  # falls back to a trimmed 'details'
    assert result.errors == []


def test_scan_without_kev(transport):
    result = scan(PURLS, transport=transport, check_kev=False)
    assert not result.kev_checked
    assert not any(url == scan_mod.KEV_URL for _, url in transport.calls)
    assert not result.known_exploited


def test_scan_kev_failure_is_reported():
    result = scan(PURLS, transport=FakeTransport(kev_fails=True))
    assert not result.kev_checked
    assert any("KEV" in e for e in result.errors)
    assert len(result.findings) == 3


def test_scan_clean_skips_kev(transport):
    result = scan(["pkg:npm/body-parser@1.20.1"], transport=transport)
    assert result.findings == [] and result.errors == []
    assert [url for _, url in transport.calls] == [scan_mod.OSV_BATCH_URL]


def test_scan_batches(monkeypatch, transport):
    monkeypatch.setattr(scan_mod, "BATCH_SIZE", 2)
    scan(PURLS, transport=transport, check_kev=False)
    assert sum(1 for _, url in transport.calls if url == scan_mod.OSV_BATCH_URL) == 2


def test_to_dict_and_markdown(transport):
    result = scan(PURLS, transport=transport)
    data = result.to_dict()
    assert data["known_exploited_count"] == 1
    assert data["vulnerable_components"] == 3
    assert data["findings"][0]["cves"] == ["CVE-2099-0001"]
    md = to_markdown(result)
    assert "Yes, since 2026-09-15" in md
    assert "24 hours" in md


@pytest.mark.parametrize(
    ("purl", "key"),
    [
        ("pkg:npm/%40babel/core@7.23.0", ("npm", "@babel/core")),
        ("pkg:npm/express", ("npm", "express")),
        ("pkg:pypi/Zope.Interface@6.1?extension=whl", ("pypi", "zope-interface")),
        ("pkg:golang/github.com/gin-gonic/gin@v1.9.1", ("golang", "github.com/gin-gonic/gin")),
    ],
)
def test_purl_key(purl, key):
    assert purl_key(purl) == key


def test_scan_rejects_misaligned_osv_response():
    def short(method, url, body=None):
        return {"results": [{}]}

    with pytest.raises(ValueError, match="returned 1 results for 2 components"):
        scan(["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"], transport=short)


@pytest.mark.parametrize(
    ("purl", "query"),
    [
        ("pkg:npm/%40babel/core@7.23.0", {"package": {"purl": "pkg:npm/%40babel/core@7.23.0"}}),
        ("pkg:golang/github.com/gin-gonic/gin@v1.9.1",
         {"package": {"ecosystem": "Go", "name": "github.com/gin-gonic/gin"}, "version": "1.9.1"}),
        ("pkg:golang/golang.org/x/net@v0.0.0-20210405180319-a5a99cb37ef4",
         {"package": {"ecosystem": "Go", "name": "golang.org/x/net"}, "version": "0.0.0-20210405180319-a5a99cb37ef4"}),
    ],
)
def test_osv_query(purl, query):
    assert osv_query(purl) == query


def test_markdown_cells_neutralise_third_party_text():
    from cra_kit.scan import cell, code

    assert cell("a | b\n<script>alert(1)</script> & c") == "a \\| b &lt;script&gt;alert(1)&lt;/script&gt; &amp; c"
    assert cell("[x](https://e.example) \\") == "\\[x\\](https://e.example) \\\\"
    assert code("pkg:npm/a`b@1\n") == "`pkg:npm/a'b@1`"


def test_markdown_advisory_link_only_for_plain_ids(transport):
    result = scan(PURLS, transport=transport)
    result.findings[0].id = "evil](https://x.example)"
    md = to_markdown(result)
    row = next(line for line in md.splitlines() if "evil" in line)
    assert "evil\\](https://x.example)" in row and "[evil" not in row
