"""Live checks against OSV.dev and the CISA KEV catalogue.

Skipped unless CRA_KIT_LIVE=1. The "Live data" GitHub Actions workflow sets
it on every push to main and weekly, so changes to the upstream APIs show up.
The packages below are old versions with long-published advisories.
"""

from __future__ import annotations

import os

import pytest

from cra_kit.sbom import collect
from cra_kit.scan import scan

from conftest import FIXTURES

pytestmark = pytest.mark.skipif(
    os.environ.get("CRA_KIT_LIVE") != "1", reason="set CRA_KIT_LIVE=1 to call OSV.dev and cisa.gov"
)

PURLS = {
    "npm": "pkg:npm/lodash@4.17.15",
    "pypi": "pkg:pypi/django@3.2.0",
    "cargo": "pkg:cargo/smallvec@1.6.0",
    "golang": "pkg:golang/golang.org/x/net@v0.7.0",
    "maven": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",  # Log4Shell, in CISA KEV
}


@pytest.fixture(scope="module")
def live_result():
    return scan(list(PURLS.values()))


def test_no_errors(live_result):
    assert live_result.errors == []
    assert live_result.kev_checked


@pytest.mark.parametrize("ecosystem", list(PURLS))
def test_each_ecosystem_matches_advisories(live_result, ecosystem):
    purl = PURLS[ecosystem]
    findings = [f for f in live_result.findings if f.purl == purl]
    assert findings, f"no advisories matched for {purl}"
    assert any(f.fixed_versions for f in findings), f"no fixed versions parsed for {purl}"


def test_log4shell_is_flagged_as_known_exploited(live_result):
    log4shell = [f for f in live_result.findings if "CVE-2021-44228" in f.cves]
    assert log4shell, "CVE-2021-44228 not returned for log4j-core 2.14.1"
    assert all(f.known_exploited and f.kev_date_added for f in log4shell)


def test_lockfile_to_scan_end_to_end():
    purls = [c.purl for c in collect(FIXTURES / "npm-v1").deduplicated()]
    result = scan(purls)
    assert result.errors == []
    assert result.vulnerable_components >= 1
