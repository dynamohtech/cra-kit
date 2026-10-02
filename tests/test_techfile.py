from __future__ import annotations

import json
import shutil
from datetime import date

import pytest

from cra_kit import cra, techfile
from cra_kit.assess import Answers, assess
from cra_kit.cli import main
from cra_kit.config import Product

from conftest import FIXTURES

TODAY = date(2026, 10, 2)
PRODUCT = Product(name="Lock Hub", version="2.4.0", manufacturer="Example Devices BV", type="device",
                  security_contact="psirt@example-devices.test", support_period_end="2031-12-31",
                  manufacturer_address="1 Example Street, Amsterdam", website="https://example-devices.test",
                  intended_purpose="Controls smart door locks in homes.", declaration_url="https://example-devices.test/doc")


def answers(**kw) -> Answers:
    a = Answers(scope={k: "yes" for k in ("digital_elements", "data_connection", "eu_market", "commercial")}
                | {"saas_only": "no", "open_source": "no"},
                exclusions={k: "no" for k, _, _ in cra.EXCLUSIONS})
    for key, value in kw.items():
        setattr(a, key, value)
    return a


def docs_for(**kw) -> dict[str, str]:
    a = assess(kw.pop("answers", answers()), PRODUCT, today=TODAY)
    return techfile.build(techfile.Inputs(product=kw.pop("product", PRODUCT), assessment=a, today=TODAY, **kw))


def test_all_files_and_annex_structure():
    docs = docs_for()
    assert set(docs) == set(techfile.FILES)
    vii = docs["01-technical-documentation.md"]
    for heading in ("## 1. General description", "### (a) Intended purpose", "### (b) Versions of software",
                    "### (c) Hardware", "### (d) User information", "## 2. Design", "### (c) Production and monitoring",
                    "## 3. Cybersecurity risk assessment", "## 4. Support period", "## 5. Harmonised standards",
                    "## 6. Test reports", "## 7. EU declaration of conformity", "## 8. Software bill of materials"):
        assert heading in vii, heading
    for rid, _ in cra.PART_I + cra.PART_II:
        assert f"| {rid} |" in vii
    v = docs["02-eu-declaration-of-conformity.md"]
    for n in range(1, 9):
        assert f"**{n}." in v
    assert "issued under the sole responsibility of the provider" in v
    assert "1 Example Street, Amsterdam" in v
    ii = docs["04-user-information.md"]
    for n in range(1, 10):
        assert f"**{n}." in ii
    for letter in "abcdef":
        assert f"- ({letter})" in ii


def test_prefill_from_settings():
    docs = docs_for()
    assert "Controls smart door locks in homes." in docs["01-technical-documentation.md"]
    assert "psirt@example-devices.test" in docs["04-user-information.md"]
    assert "2031-12-31" in docs["04-user-information.md"]
    vi = docs["03-simplified-declaration.md"]
    assert ("Hereby, Example Devices BV declares that the product with digital elements type Lock Hub 2.4.0 is in "
            "compliance with Regulation (EU) 2024/2847.") in vi
    assert "https://example-devices.test/doc" in vi


def test_missing_values_become_todos():
    bare = Product(name="X", version="1")
    docs = techfile.build(techfile.Inputs(product=bare, today=TODAY))
    assert "**TODO:** postal address" in docs["02-eu-declaration-of-conformity.md"]
    assert "**TODO:** URL (set declaration_url" in docs["03-simplified-declaration.md"]
    assert "| I.1 |" in docs["01-technical-documentation.md"]  # requirement table even without answers
    assert techfile.count_todos(docs) > techfile.count_todos(docs_for())


def test_software_product_has_no_hardware_photos():
    docs = docs_for(product=Product(name="App", version="1", type="application"))
    assert "Not applicable if the product is software only" in docs["01-technical-documentation.md"]


@pytest.mark.parametrize(
    ("kw", "expected"),
    [
        ({}, "Not applicable: internal control (module A)"),
        ({"class_i": [17]}, "which a Class I product may use only"),
        ({"class_ii": [2]}, "(Important product, Class II (Annex III))"),
    ],
)
def test_notified_body_section_follows_category(kw, expected):
    docs = docs_for(answers=answers(**kw))
    assert expected in docs["02-eu-declaration-of-conformity.md"]


def test_evidence_from_sbom_scan_and_vex():
    sbom = {"components": 40, "direct": 8, "transitive": 32, "unknown": 0, "spec_version": "1.6",
            "timestamp": "2026-10-02T10:00:00Z"}
    scan = {"vulnerable_components": 1, "known_exploited_count": 0, "closed_by_vex_count": 2}
    docs = docs_for(sbom_file="sbom.cdx.json", sbom_summary=sbom, scan_file="scan.json", scan_summary=scan,
                    vex_file="cra-kit.vex.json", security_policy="SECURITY.md")
    vii = docs["01-technical-documentation.md"]
    assert "`sbom.cdx.json` (CycloneDX 1.6, 40 components" in vii
    assert "40 in total, 8 direct and 32 transitive" in vii
    assert "1 components with open advisories, 0 known exploited, 2 closed by VEX" in vii
    assert "`cra-kit.vex.json`" in vii and "`SECURITY.md`" in vii
    assert "Dependency vulnerability scan (`scan.json`)" in vii


def test_write_never_overwrites_without_force(tmp_path):
    docs = docs_for()
    written, kept = techfile.write(tmp_path, docs)
    assert len(written) == 5 and kept == []
    (tmp_path / "02-eu-declaration-of-conformity.md").write_text("my edits")
    written, kept = techfile.write(tmp_path, docs)
    assert written == [] and len(kept) == 5
    assert (tmp_path / "02-eu-declaration-of-conformity.md").read_text() == "my edits"
    techfile.write(tmp_path, docs, force=True)
    assert (tmp_path / "02-eu-declaration-of-conformity.md").read_text() != "my edits"


def test_cli_techfile(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["techfile"]) == 2
    assert "cra-kit init" in capsys.readouterr().err
    shutil.copy(FIXTURES / "npm-v3" / "package-lock.json", tmp_path)
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo-app", "version": "1.2.0"}))
    (tmp_path / "SECURITY.md").write_text("# Security\n")
    main(["init", "--manufacturer", "Example BV"])
    main(["sbom"])
    capsys.readouterr()
    assert main(["techfile", "-o", "tf"]) == 0
    out = capsys.readouterr().out
    assert "Prefilled from cra-kit.toml, SBOM sbom.cdx.json, answers cra-answers.toml." in out
    assert "TODO items left" in out
    assert "`SECURITY.md`" in (tmp_path / "tf" / "01-technical-documentation.md").read_text()
    assert main(["techfile", "-o", "tf"]) == 0
    assert "Kept existing" in capsys.readouterr().out
