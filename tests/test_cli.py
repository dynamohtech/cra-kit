from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from cra_kit import __version__
from cra_kit.cli import main

from conftest import FIXTURES


@pytest.fixture
def project(tmp_path, monkeypatch):
    """A small npm + Python project in a temporary folder, as the current directory."""
    shutil.copy(FIXTURES / "npm-v3" / "package-lock.json", tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo-app", "version": "1.2.0"}))
    (tmp_path / "requirements.txt").write_text("Django==4.2.7\n")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_version_via_python_m():
    out = subprocess.run([sys.executable, "-m", "cra_kit", "--version"], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == f"cra-kit {__version__}"


def test_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage: cra-kit" in capsys.readouterr().out


def test_init_detects_project_and_keeps_files(project, capsys):
    assert main(["init", "--manufacturer", "Example BV"]) == 0
    config = (project / "cra-kit.toml").read_text()
    assert 'name = "demo-app"' in config and 'version = "1.2.0"' in config
    assert 'manufacturer = "Example BV"' in config
    assert (project / "cra-answers.toml").exists()
    assert main(["init"]) == 0
    assert "Kept existing" in capsys.readouterr().out


def test_sbom_command(project, capsys):
    main(["init", "--manufacturer", "Example BV"])
    assert main(["sbom"]) == 0
    bom = json.loads((project / "sbom.cdx.json").read_text())
    assert bom["metadata"]["component"]["name"] == "demo-app"
    assert bom["metadata"]["manufacturer"]["name"] == "Example BV"
    assert len(bom["components"]) == 5
    out = capsys.readouterr().out
    assert "5 components (2 direct, 2 transitive, 1 not stated)" in out
    assert "from 2 dependency file(s)" in out


def test_sbom_missing_path(project, capsys):
    assert main(["sbom", "nowhere"]) == 2
    assert "path not found" in capsys.readouterr().err


def test_scan_table_and_fail_on(project, offline_scan, capsys):
    main(["sbom"])
    assert main(["scan", "sbom.cdx.json"]) == 0
    out = capsys.readouterr().out
    assert "Scanned 5 components: 3 with known vulnerabilities (3 advisories), 1 known exploited" in out
    assert out.index("GHSA-test-kev1-0001") < out.index("GHSA-test-scop-0003")
    assert main(["scan", "sbom.cdx.json", "--fail-on", "kev"]) == 1
    assert main(["scan", ".", "--fail-on", "any"]) == 1  # scanning the folder directly works too


def test_scan_fail_on_kev_needs_kev(project, offline_scan, capsys):
    offline_scan.kev_fails = True
    assert main(["scan", "--fail-on", "kev"]) == 2
    assert "could not be checked" in capsys.readouterr().err


def test_scan_network_error(project, offline_scan, capsys):
    offline_scan.osv_fails = True
    assert main(["scan"]) == 2
    assert "could not reach OSV.dev" in capsys.readouterr().err


def test_full_flow(project, offline_scan, capsys):
    main(["init", "--manufacturer", "Example BV"])
    main(["sbom"])
    assert main(["scan", "--format", "json", "-o", "scan.json"]) == 0
    scan = json.loads((project / "scan.json").read_text())
    assert scan["known_exploited_count"] == 1

    answers = (project / "cra-answers.toml").read_text()
    for key in ("digital_elements", "data_connection", "eu_market", "commercial"):
        answers = answers.replace(f'{key} = ""', f'{key} = "yes"')
    for key in ("saas_only", "open_source", "medical", "vehicle", "aviation", "marine", "defence", "spare_part"):
        answers = answers.replace(f'{key} = ""', f'{key} = "no"')
    (project / "cra-answers.toml").write_text(answers)

    assert main(["assess", "--scan", "scan.json", "-o", "cra-readiness.md"]) == 0
    report = (project / "cra-readiness.md").read_text()
    assert "| Scope | **In scope** |" in report
    assert "CycloneDX 1.6 SBOM: 5 components" in report  # sbom.cdx.json picked up automatically
    err = capsys.readouterr().err
    assert "Scope: In scope" in err and "24 hours" in err

    assert main(["assess", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["scope"] == "in" and data["counts"]

    assert main(["report", "vulnerability", "--aware", "2026-10-01T10:00Z", "--scan", "scan.json",
                 "--advisory", "cve-2099-0001", "-o", "pack.md"]) == 0
    pack = (project / "pack.md").read_text()
    assert "2026-10-02 10:00 UTC" in pack
    assert "GHSA-test-kev1-0001, CVE-2099-0001" in pack
    assert "Deadlines:" in capsys.readouterr().out


def test_assess_without_answers(project, capsys):
    assert main(["assess"]) == 2
    assert "cra-kit init" in capsys.readouterr().err


def test_assess_rejects_non_scan_json(project, capsys):
    main(["init"])
    (project / "x.json").write_text("{}")
    assert main(["assess", "--scan", "x.json"]) == 2
    assert "not the JSON output" in capsys.readouterr().err


def test_report_incident_json(project, capsys):
    assert main(["report", "incident", "--aware", "2027-01-28T09:00Z", "--notified", "2027-01-31T09:00Z",
                 "--format", "json"]) == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    final = next(s for s in data["stages"] if s["key"] == "final_report")
    assert final["due"] == "2027-02-28T09:00:00Z"
    assert "no cra-kit.toml" in captured.err


def test_report_errors(project, capsys):
    assert main(["report", "incident", "--aware", "2026-10-02", "--notified", "2026-10-01"]) == 2
    assert main(["report", "vulnerability", "--aware", "soon"]) == 2
    assert main(["report", "vulnerability", "--aware", "now", "--advisory", "X"]) == 2
    (project / "scan.json").write_text(json.dumps({"vulnerable_components": 0, "findings": []}))
    assert main(["report", "vulnerability", "--aware", "now", "--scan", "scan.json", "--advisory", "X"]) == 2
    err = capsys.readouterr().err
    assert "earlier than --aware" in err and "not an ISO 8601" in err and "not found in the scan file" in err
    assert main(["report"]) == 2


def test_broken_pipe_exits_quietly(tmp_path):
    shutil.copy(FIXTURES / "npm-v3" / "package-lock.json", tmp_path)
    proc = subprocess.Popen([sys.executable, "-m", "cra_kit", "sbom", "-o", str(tmp_path / "s.json"), str(tmp_path)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.stdout.close()  # the reader goes away before cra-kit writes
    _, err = proc.communicate(timeout=60)
    assert b"Traceback" not in err
