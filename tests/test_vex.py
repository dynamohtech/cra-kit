from __future__ import annotations

import json

import pytest

from cra_kit import vex
from cra_kit.cli import main
from cra_kit.scan import scan

from conftest import FIXTURES

PURLS = ["pkg:npm/express@4.18.2", "pkg:npm/%40babel/core@7.23.0", "pkg:pypi/django@4.2.7"]
PRODUCT = vex.product_id("Example Hub", "2.4.0")


def openvex_schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((FIXTURES / "openvex_json_schema_0.2.0.json").read_text())
    return jsonschema.Draft202012Validator(schema)


def test_product_id_is_a_purl():
    assert PRODUCT == "pkg:generic/Example%20Hub@2.4.0"


@pytest.mark.parametrize(
    ("subject", "purl", "expected"),
    [
        ("pkg:npm/express@4.18.2", "pkg:npm/express@4.18.2", True),
        ("pkg:npm/express", "pkg:npm/express@4.18.2", True),  # no version: every version
        ("pkg:npm/express@4.19.0", "pkg:npm/express@4.18.2", False),
        ("pkg:npm/%40babel/core", "pkg:npm/%40babel/core@7.23.0", True),
        ("pkg:pypi/Django@4.2.7", "pkg:pypi/django@4.2.7", True),  # PyPI names are normalised
        ("pkg:npm/express@4.18.2", "pkg:npm/expressive@4.18.2", False),
    ],
)
def test_purl_matches(subject, purl, expected):
    assert vex.purl_matches(subject, purl) is expected


def test_make_statement_validation():
    with pytest.raises(ValueError, match="justification or --impact"):
        vex.make_statement("CVE-1", "not_affected", "pkg:npm/a@1", PRODUCT)
    with pytest.raises(ValueError, match="--action"):
        vex.make_statement("CVE-1", "affected", "pkg:npm/a@1", PRODUCT)
    with pytest.raises(ValueError, match="package URL"):
        vex.make_statement("CVE-1", "fixed", "express@4", PRODUCT)
    with pytest.raises(ValueError, match="status must be"):
        vex.make_statement("CVE-1", "maybe", "pkg:npm/a@1", PRODUCT)
    with pytest.raises(ValueError, match="justification must be"):
        vex.make_statement("CVE-1", "not_affected", "pkg:npm/a@1", PRODUCT, justification="trust me")


def test_written_documents_are_valid_openvex(tmp_path):
    validator = openvex_schema_validator()
    path = tmp_path / "v.json"
    vex.add(path, vex.make_statement("CVE-2099-0001", "not_affected", "pkg:npm/express@4.18.2", PRODUCT,
                                     justification="vulnerable_code_not_in_execute_path"), "Example Devices BV")
    vex.add(path, vex.make_statement("CVE-2099-0002", "affected", None, PRODUCT, action_statement="Upgrade"), "x")
    vex.add(path, vex.make_statement("CVE-2099-0003", "under_investigation", "pkg:npm/a@1", None), "x")
    doc = json.loads(path.read_text())
    errors = sorted(validator.iter_errors(doc), key=str)
    assert errors == [], [e.message for e in errors]
    assert doc["version"] == 3 and len(doc["statements"]) == 3
    assert doc["author"] == "Example Devices BV"
    assert doc["statements"][0]["products"] == [
        {"@id": PRODUCT, "subcomponents": [{"@id": "pkg:npm/express@4.18.2"}]}]


def test_scan_closes_not_affected_and_keeps_affected(transport, tmp_path):
    path = tmp_path / "v.json"
    vex.add(path, vex.make_statement("CVE-2099-0001", "not_affected", "pkg:npm/express", PRODUCT,
                                     justification="vulnerable_code_not_in_execute_path",
                                     timestamp="2026-10-01T10:00:00Z"), "a")
    vex.add(path, vex.make_statement("GHSA-test-scop-0003", "affected", "pkg:npm/%40babel/core@7.23.0", PRODUCT,
                                     action_statement="Upgrade to 7.23.2"), "a")
    result = scan(PURLS, transport=transport)
    assert vex.apply(result, vex.load(path), {PRODUCT}) == 1
    closed = result.closed_findings
    assert [f.id for f in closed] == ["GHSA-test-kev1-0001"]  # matched through its CVE alias
    assert closed[0].vex["justification"] == "vulnerable_code_not_in_execute_path"
    assert result.known_exploited == []  # the KEV finding is closed, so it no longer counts
    assert result.vulnerable_components == 2
    babel = next(f for f in result.open_findings if "babel" in f.purl)
    assert babel.vex["status"] == "affected"
    data = result.to_dict()
    assert data["closed_by_vex_count"] == 1 and data["open_findings_count"] == 2
    assert data["vex_sources"] == [str(path)]


def test_latest_statement_wins(transport, tmp_path):
    path = tmp_path / "v.json"
    for status, ts in (("not_affected", "2026-10-01T10:00:00Z"), ("under_investigation", "2026-10-02T10:00:00Z")):
        vex.add(path, vex.make_statement("CVE-2099-0001", status, "pkg:npm/express@4.18.2", PRODUCT,
                                         justification="component_not_present" if status == "not_affected" else "",
                                         timestamp=ts), "a")
    result = scan(PURLS, transport=transport)
    vex.apply(result, vex.load(path), {PRODUCT})
    assert result.closed_findings == []
    assert result.known_exploited[0].vex["status"] == "under_investigation"


def test_whole_product_statement(transport, tmp_path):
    path = tmp_path / "v.json"
    vex.add(path, vex.make_statement("CVE-2099-0002", "fixed", None, PRODUCT), "a")
    result = scan(PURLS, transport=transport)
    assert vex.apply(result, vex.load(path), {PRODUCT}) == 1
    other = scan(PURLS, transport=transport)
    assert vex.apply(other, vex.load(path), {vex.product_id("Other", "1")}) == 0


def test_cyclonedx_vex(transport, tmp_path):
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.6",
        "components": [{"bom-ref": "comp-1", "purl": "pkg:pypi/django@4.2.7", "name": "django", "type": "library"}],
        "vulnerabilities": [
            {"id": "CVE-2099-0002", "analysis": {"state": "false_positive", "detail": "Not reachable"},
             "affects": [{"ref": "urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#comp-1"}]},
            {"id": "CVE-2099-0003", "analysis": {"state": "in_triage"}, "affects": [{"ref": "pkg:npm/%40babel/core@7.23.0"}]},
            {"id": "CVE-2099-0009", "affects": [{"ref": "comp-1"}]},  # no analysis: not a decision
        ],
    }
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(bom))
    statements = vex.load(path)
    assert [(s.vulnerability, s.status) for s in statements] == [
        ("CVE-2099-0002", "not_affected"), ("CVE-2099-0003", "under_investigation")]
    result = scan(PURLS, transport=transport)
    assert vex.apply(result, statements) == 1
    assert result.closed_findings[0].purl == "pkg:pypi/django@4.2.7"


def test_load_rejects_other_json(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        vex.load(path)


def test_cli_vex_flow(tmp_path, monkeypatch, offline_scan, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "package.json").write_text('{"name": "demo-app", "version": "1.2.0"}')
    (tmp_path / "package-lock.json").write_text((FIXTURES / "npm-v3" / "package-lock.json").read_text())
    main(["init", "--manufacturer", "Example BV"])
    assert main(["scan", "--fail-on", "kev"]) == 1
    capsys.readouterr()

    assert main(["vex", "add", "--id", "CVE-2099-0001", "--component", "pkg:npm/express@4.18.2",
                 "--status", "not_affected", "--justification", "vulnerable_code_not_in_execute_path"]) == 0
    assert "Recorded CVE-2099-0001 as not_affected" in capsys.readouterr().out
    assert main(["vex", "list"]) == 0
    listing = capsys.readouterr().out
    assert "CVE-2099-0001" in listing and "vulnerable_code_not_in_execute_path" in listing

    assert main(["scan", "--fail-on", "kev"]) == 0  # picked up from cra-kit.vex.json automatically
    captured = capsys.readouterr()
    assert "Using VEX decisions from cra-kit.vex.json" in captured.err
    assert "1 closed by VEX" in captured.out and "Closed by VEX:" in captured.out
    assert main(["scan", "--fail-on", "kev", "--no-vex"]) == 1

    assert main(["scan", "--format", "markdown"]) == 0
    assert "## Closed by VEX" in capsys.readouterr().out
    assert main(["vex", "add", "--id", "X", "--status", "not_affected"]) == 2
    assert main(["scan", "--vex", "missing.json"]) == 2


@pytest.mark.parametrize(
    ("subject", "purl"),
    [
        ("pkg:pypi/torch@2.1.0+cpu", "pkg:pypi/torch@2.1.0%2Bcpu"),  # "+" written literally or encoded
        ("pkg:golang/golang.org/x/net@0.17.0", "pkg:golang/golang.org/x/net@v0.17.0"),  # Go "v" prefix
        ("pkg:golang/github.com/docker/docker@v20.10.24+incompatible",
         "pkg:golang/github.com/docker/docker@v20.10.24%2Bincompatible"),
        ("PKG:npm/foo@1.0.0", "pkg:npm/foo@1.0.0"),
        ("pkg:npm/foo@1.0.0", "pkg:npm/foo@1.0.0?arch=x64"),
    ],
)
def test_purl_matches_equivalent_spellings(subject, purl):
    assert vex.purl_matches(subject, purl)


def test_latest_statement_by_time_not_text():
    older = vex.Statement("CVE-1", "not_affected", subcomponents=["pkg:npm/foo"],
                          timestamp="2024-05-01T09:00:00+02:00")  # 07:00 UTC
    newer = vex.Statement("CVE-1", "affected", subcomponents=["pkg:npm/foo"], timestamp="2024-05-01T08:00:00Z")
    assert vex.find([older, newer], {"CVE-1"}, "pkg:npm/foo@1.0.0").status == "affected"
    frac = vex.Statement("CVE-1", "affected", subcomponents=["pkg:npm/foo"], timestamp="2024-05-01T08:00:00.5Z")
    whole = vex.Statement("CVE-1", "not_affected", subcomponents=["pkg:npm/foo"], timestamp="2024-05-01T08:00:00Z")
    assert vex.find([frac, whole], {"CVE-1"}, "pkg:npm/foo@1.0.0").status == "affected"


def test_cyclonedx_versions_are_respected(tmp_path):
    bom = {"bomFormat": "CycloneDX", "specVersion": "1.5", "vulnerabilities": [{
        "id": "CVE-X", "analysis": {"state": "not_affected"},
        "affects": [{"ref": "pkg:npm/lodash", "versions": [
            {"version": "4.17.21", "status": "unaffected"},
            {"version": "4.17.20", "status": "affected"},
            {"range": "vers:npm/<4.0.0", "status": "unaffected"}]}]}]}
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(bom))
    statements = vex.load(path)
    assert vex.find(statements, {"CVE-X"}, "pkg:npm/lodash@4.17.21")
    assert not vex.find(statements, {"CVE-X"}, "pkg:npm/lodash@4.17.20")
    assert not vex.find(statements, {"CVE-X"}, "pkg:npm/lodash@3.0.0")  # ranges are not evaluated


def test_openvex_v001_documents(tmp_path):
    doc = {"@context": "https://openvex.dev/ns", "@id": "x", "author": "a", "timestamp": "2023-01-01T00:00:00Z",
           "version": "1", "statements": [{"vulnerability": "CVE-2023-1234", "products": ["pkg:npm/foo@1.0.0"],
                                           "subcomponents": ["pkg:npm/bar@2.0.0"], "status": "not_affected",
                                           "justification": "component_not_present"}]}
    path = tmp_path / "v.json"
    path.write_text(json.dumps(doc))
    assert vex.find(vex.load(path), {"CVE-2023-1234"}, "pkg:npm/bar@2.0.0").status == "not_affected"
