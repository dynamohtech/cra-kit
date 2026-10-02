from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from cra_kit import action, vex

from conftest import FIXTURES

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def workspace(tmp_path, monkeypatch, offline_scan):
    shutil.copy(FIXTURES / "npm-v3" / "package-lock.json", tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo-app", "version": "1.2.0"}))
    monkeypatch.chdir(tmp_path)
    env = {"GITHUB_OUTPUT": str(tmp_path / "out.txt"), "GITHUB_STEP_SUMMARY": str(tmp_path / "summary.md")}
    return tmp_path, env


def outputs(path: Path) -> dict:
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def test_action_defaults_fail_on_kev(workspace, capsys):
    tmp, env = workspace
    assert action.run(env) == 1
    out = outputs(tmp / "out.txt")
    assert out == {"sbom-file": "sbom.cdx.json", "scan-file": "cra-scan.json", "components": "4",
                   "vulnerable-components": "2", "open-advisories": "2", "known-exploited": "1", "closed-by-vex": "0"}
    assert (tmp / "sbom.cdx.json").is_file() and (tmp / "cra-scan.json").is_file()
    assert (tmp / "summary.md").read_text().startswith("# Vulnerability scan")
    printed = capsys.readouterr().out
    assert "::error title=Known exploited vulnerability in pkg%3Anpm/express@4.18.2::GHSA-test-kev1-0001" in printed


def test_action_fail_on_none_and_vex(workspace):
    tmp, env = workspace
    vex.add(tmp / "cra-kit.vex.json", vex.make_statement(
        "CVE-2099-0001", "not_affected", "pkg:npm/express@4.18.2", None,
        justification="vulnerable_code_not_in_execute_path"), "a")
    assert action.run(env | {"CRA_FAIL_ON": "kev"}) == 0  # VEX file picked up automatically
    assert outputs(tmp / "out.txt")["closed-by-vex"] == "1"
    (tmp / "out.txt").unlink()
    assert action.run(env | {"CRA_FAIL_ON": "none", "CRA_VEX": "cra-kit.vex.json"}) == 0
    assert action.run(env | {"CRA_FAIL_ON": "any"}) == 1


def test_action_scans_existing_sbom_without_overwriting(workspace):
    tmp, env = workspace
    from cra_kit.cli import main

    main(["sbom", "-o", "given.cdx.json"])
    before = (tmp / "given.cdx.json").read_text()
    assert action.run(env | {"CRA_PATH": "given.cdx.json", "CRA_FAIL_ON": "none"}) == 0
    assert (tmp / "given.cdx.json").read_text() == before
    assert outputs(tmp / "out.txt")["sbom-file"] == "given.cdx.json"
    assert not (tmp / "sbom.cdx.json").exists()


@pytest.mark.parametrize("bad", ["$(touch pwned)", "; touch pwned", "`touch pwned`"])
def test_action_inputs_never_reach_a_shell(workspace, bad, capsys):
    tmp, env = workspace
    assert action.run(env | {"CRA_PATH": bad}) == 2
    assert not (tmp / "pwned").exists()
    assert "::error title=cra-kit::path not found" in capsys.readouterr().out


def test_action_rejects_bad_fail_on(workspace, capsys):
    _, env = workspace
    assert action.run(env | {"CRA_FAIL_ON": "sometimes"}) == 2
    assert "fail-on must be none, any or kev" in capsys.readouterr().out


def test_escaping():
    assert action._escape("50%\nnext") == "50%25%0Anext"
    assert action._escape_property("a:b,c") == "a%3Ab%2Cc"


def test_action_yml_matches_module():
    text = (ROOT / "action.yml").read_text()
    for key in ("CRA_PATH", "CRA_FAIL_ON", "CRA_INCLUDE_DEV", "CRA_VEX", "CRA_CONFIG", "CRA_SBOM_FILE", "CRA_SCAN_FILE"):
        assert key in text
        assert key in (ROOT / "src" / "cra_kit" / "action.py").read_text()
    assert "python -m cra_kit.action" in text
    for output in ("components", "vulnerable-components", "open-advisories", "known-exploited", "closed-by-vex"):
        assert f"steps.check.outputs.{output}" in text
    # no input is interpolated into a shell script
    run_lines = [line for line in text.splitlines() if line.strip().startswith("run:")]
    assert all("${{" not in line for line in run_lines)


def test_action_yml_parses_and_has_marketplace_fields():
    yaml = pytest.importorskip("yaml")
    data = yaml.safe_load((ROOT / "action.yml").read_text())
    assert data["runs"]["using"] == "composite"
    assert data["branding"] == {"icon": "shield", "color": "blue"}
    assert len(data["description"]) <= 125
    assert all("description" in v for v in data["inputs"].values())
