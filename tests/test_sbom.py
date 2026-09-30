from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from cra_kit.model import Component, ParseResult
from cra_kit.sbom import collect, find_dependency_files, parsers
from cra_kit.sbom.cyclonedx import build_bom, read_purls, summarize, write_bom

from conftest import FIXTURES


def by_name(result: ParseResult) -> dict[str, Component]:
    return {c.name: c for c in result.components}


# --- purls -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("component", "purl"),
    [
        (Component("npm", "express", "4.18.2"), "pkg:npm/express@4.18.2"),
        (Component("npm", "@babel/core", "7.23.0"), "pkg:npm/%40babel/core@7.23.0"),
        (Component("pypi", "Zope.Interface", "6.1"), "pkg:pypi/zope-interface@6.1"),
        (Component("pypi", "typing_extensions", "4.8.0"), "pkg:pypi/typing-extensions@4.8.0"),
        (Component("cargo", "serde", "1.0.190"), "pkg:cargo/serde@1.0.190"),
        (Component("golang", "github.com/gin-gonic/gin", "v1.9.1"), "pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
        (Component("npm", "odd", "1.0.0+build.1"), "pkg:npm/odd@1.0.0%2Bbuild.1"),
    ],
)
def test_purls(component, purl):
    assert component.purl == purl


def test_deduplicated_prefers_direct():
    result = ParseResult(components=[
        Component("npm", "a", "1.0.0", direct=False),
        Component("npm", "a", "1.0.0", direct=True),
        Component("pypi", "Foo_Bar", "1.0", direct=None),
        Component("pypi", "foo-bar", "1.0", direct=False),
    ])
    deduped = result.deduplicated()
    assert [(c.purl, c.direct) for c in deduped] == [
        ("pkg:npm/a@1.0.0", True),
        ("pkg:pypi/foo-bar@1.0", None),
    ]


# --- parsers ---------------------------------------------------------------


def test_npm_v3():
    result = parsers.parse_npm_lock(FIXTURES / "npm-v3" / "package-lock.json")
    comps = by_name(result)
    assert set(comps) == {"express", "@babel/core", "body-parser", "debug"}
    assert comps["express"].direct is True
    assert comps["@babel/core"].direct is True
    assert comps["body-parser"].direct is False
    assert comps["debug"].direct is False  # nested under express


def test_npm_v3_include_dev():
    comps = by_name(parsers.parse_npm_lock(FIXTURES / "npm-v3" / "package-lock.json", include_dev=True))
    assert {"jest", "fsevents"} <= set(comps)
    assert comps["jest"].direct is True
    assert "local-lib" not in comps  # workspace link is part of the product


def test_npm_v1_uses_package_json_for_direct():
    comps = by_name(parsers.parse_npm_lock(FIXTURES / "npm-v1" / "package-lock.json"))
    assert set(comps) == {"lodash", "request", "qs", "mime"}
    assert comps["lodash"].direct is True
    assert comps["mime"].direct is False  # hoisted transitive package
    assert comps["qs"].direct is False


def test_npm_v1_without_manifest(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text((FIXTURES / "npm-v1" / "package-lock.json").read_text())
    comps = by_name(parsers.parse_npm_lock(lock))
    assert comps["lodash"].direct is None
    assert comps["qs"].direct is False


def test_requirements():
    result = parsers.parse_requirements(FIXTURES / "requirements" / "requirements.txt")
    comps = {c.purl for c in result.components}
    assert comps == {
        "pkg:pypi/django@4.2.7",
        "pkg:pypi/requests@2.31.0",
        "pkg:pypi/urllib3@2.0.7",
        "pkg:pypi/jinja2@3.1.2",
        "pkg:pypi/zope-interface@6.1",
    }
    assert all(c.direct is None for c in result.components)
    text = " ".join(result.warnings)
    assert "'flask' is not pinned" in text
    assert "editable" in text
    assert "direct URL" in text
    assert len(result.sources) == 2


def test_requirements_include_cycle(tmp_path):
    (tmp_path / "a.txt").write_text("-r b.txt\nsix==1.16.0\n")
    (tmp_path / "b.txt").write_text("-r a.txt\n")
    result = parsers.parse_requirements(tmp_path / "a.txt")
    assert [c.name for c in result.components] == ["six"]


def test_poetry_lock():
    comps = by_name(parsers.parse_poetry_lock(FIXTURES / "poetry" / "poetry.lock"))
    assert set(comps) == {"flask", "werkzeug", "pydantic"}
    assert comps["flask"].direct is True
    assert comps["pydantic"].direct is True
    assert comps["werkzeug"].direct is False


def test_poetry_lock_dev():
    comps = by_name(parsers.parse_poetry_lock(FIXTURES / "poetry" / "poetry.lock", include_dev=True))
    assert "pytest" in comps


def test_pipfile_lock():
    result = parsers.parse_pipfile_lock(FIXTURES / "pipenv" / "Pipfile.lock")
    comps = by_name(result)
    assert set(comps) == {"requests", "certifi"}
    assert comps["requests"].version == "2.31.0"
    assert comps["requests"].direct is True
    assert comps["certifi"].direct is False
    assert any("mylib" in w for w in result.warnings)


def test_uv_lock():
    result = parsers.parse_uv_lock(FIXTURES / "uv" / "uv.lock")
    comps = by_name(result)
    assert set(comps) == {"httpx", "anyio"}
    assert comps["httpx"].direct is True
    assert comps["anyio"].direct is False
    assert any("dev dependencies" in w for w in result.warnings)
    assert "pytest" in by_name(parsers.parse_uv_lock(FIXTURES / "uv" / "uv.lock", include_dev=True))


def test_cargo_lock():
    comps = by_name(parsers.parse_cargo_lock(FIXTURES / "cargo" / "Cargo.lock"))
    assert set(comps) == {"serde", "tokio", "mio"}
    assert comps["serde"].direct is True
    assert comps["mio"].direct is False


def test_go_mod():
    result = parsers.parse_go_mod(FIXTURES / "gomod" / "go.mod")
    comps = by_name(result)
    assert set(comps) == {"github.com/gin-gonic/gin", "golang.org/x/net", "github.com/stretchr/testify"}
    assert comps["golang.org/x/net"].direct is False
    assert comps["github.com/stretchr/testify"].direct is True
    assert any("replace" in w for w in result.warnings)


# --- discovery -------------------------------------------------------------


def test_collect_folder_warns_about_unsupported_files():
    result = collect(FIXTURES / "mixed")
    purls = {c.purl for c in result.deduplicated()}
    assert "pkg:npm/express@4.18.2" in purls
    assert "pkg:pypi/requests@2.31.0" in purls
    assert any("pnpm-lock.yaml" in w and "NOT in the SBOM" in w for w in result.warnings)


def test_requirements_skipped_when_lockfile_present(tmp_path):
    (tmp_path / "poetry.lock").write_text((FIXTURES / "poetry" / "poetry.lock").read_text())
    (tmp_path / "requirements.txt").write_text("flask==3.0.0\n")
    files, _ = find_dependency_files(tmp_path)
    assert [p.name for p, _ in files] == ["poetry.lock"]


def test_collect_skips_node_modules(tmp_path):
    nested = tmp_path / "node_modules" / "x"
    nested.mkdir(parents=True)
    (nested / "package-lock.json").write_text("{}")
    result = collect(tmp_path)
    assert result.components == []
    assert any("no supported dependency files" in w for w in result.warnings)


def test_collect_single_file_and_bad_file(tmp_path):
    assert len(collect(FIXTURES / "cargo" / "Cargo.lock").components) == 3
    bad = tmp_path / "package-lock.json"
    bad.write_text("{not json")
    result = collect(tmp_path)
    assert any("could not be read" in w for w in result.warnings)
    with pytest.raises(ValueError):
        collect(FIXTURES / "cargo" / "Cargo.toml")


# --- CycloneDX -------------------------------------------------------------


def make_bom():
    components = collect(FIXTURES / "npm-v3").deduplicated()
    return build_bom(
        components, "demo-app", "1.2.0", manufacturer="Example Ltd",
        timestamp=datetime(2026, 9, 30, 12, 0, 0, 123, tzinfo=timezone.utc),
        serial="urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
    )


def test_bom_structure():
    bom = make_bom()
    assert bom["specVersion"] == "1.6"
    assert bom["metadata"]["timestamp"] == "2026-09-30T12:00:00Z"
    assert bom["metadata"]["component"]["name"] == "demo-app"
    assert bom["metadata"]["manufacturer"] == {"name": "Example Ltd"}
    refs = {c["bom-ref"] for c in bom["components"]}
    assert bom["dependencies"][0]["ref"] == "product"
    assert set(bom["dependencies"][0]["dependsOn"]) == {"pkg:npm/express@4.18.2", "pkg:npm/%40babel/core@7.23.0"}
    assert set(bom["dependencies"][0]["dependsOn"]) <= refs


def test_bom_validates_against_cyclonedx_1_6_schema():
    validation = pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion

    validator = validation.JsonStrictValidator(SchemaVersion.V1_6)
    errors = validator.validate_str(json.dumps(make_bom()))
    assert errors is None, errors


def test_bom_roundtrip(tmp_path):
    path = tmp_path / "sbom.cdx.json"
    write_bom(make_bom(), path)
    assert read_purls(path) == sorted([
        "pkg:npm/%40babel/core@7.23.0", "pkg:npm/body-parser@1.20.1",
        "pkg:npm/debug@2.6.9", "pkg:npm/express@4.18.2",
    ])
    s = summarize(json.loads(path.read_text()))
    assert s == {"components": 4, "direct": 2, "transitive": 2, "unknown": 0,
                 "spec_version": "1.6", "timestamp": "2026-09-30T12:00:00Z"}


def test_summarize_other_tools_sbom():
    bom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"bom-ref": "root", "name": "x"}},
        "components": [{"bom-ref": "a", "purl": "pkg:npm/a@1"}, {"bom-ref": "b", "purl": "pkg:npm/b@1"}],
        "dependencies": [{"ref": "root", "dependsOn": ["a"]}, {"ref": "a", "dependsOn": ["b"]}],
    }
    s = summarize(bom)
    assert (s["direct"], s["transitive"], s["unknown"]) == (1, 1, 0)
    del bom["dependencies"]
    assert summarize(bom)["unknown"] == 2


def test_read_purls_rejects_other_json(tmp_path):
    path = tmp_path / "x.json"
    path.write_text('{"hello": 1}')
    with pytest.raises(ValueError):
        read_purls(path)
