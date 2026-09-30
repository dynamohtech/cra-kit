from __future__ import annotations

from datetime import date

import pytest

from cra_kit import cra
from cra_kit.assess import Answers, ask_interactively, assess, to_markdown
from cra_kit.config import Product

TODAY = date(2026, 9, 30)
IN_SCOPE = {"digital_elements": "yes", "data_connection": "yes", "eu_market": "yes",
            "commercial": "yes", "saas_only": "no", "open_source": "no"}
NO_EXCLUSIONS = {key: "no" for key, _, _ in cra.EXCLUSIONS}


def answers(**overrides) -> Answers:
    a = Answers(scope=dict(IN_SCOPE), exclusions=dict(NO_EXCLUSIONS))
    for key, value in overrides.items():
        setattr(a, key, value)
    return a


def test_in_scope_default_category():
    result = assess(answers(), today=TODAY)
    assert result.scope == "in"
    assert result.category == "default"
    assert "module A" in result.conformity
    assert len(result.all_requirements) == len(cra.PART_I) + len(cra.PART_II) == 22
    assert result.counts() == {"": 22}


@pytest.mark.parametrize(
    ("field", "value", "scope"),
    [
        ("exclusions", {**NO_EXCLUSIONS, "medical": "yes"}, "out"),
        ("scope", {**IN_SCOPE, "eu_market": "no"}, "out"),
        ("scope", {**IN_SCOPE, "data_connection": "no"}, "out"),
        ("scope", {**IN_SCOPE, "saas_only": "yes"}, "likely-out"),
        ("scope", {**IN_SCOPE, "commercial": "no"}, "likely-out"),
        ("scope", {**IN_SCOPE, "eu_market": "unsure"}, "unclear"),
        ("exclusions", {}, "unclear"),
    ],
)
def test_scope_outcomes(field, value, scope):
    assert assess(answers(**{field: value}), today=TODAY).scope == scope


def test_exclusion_names_legal_basis():
    result = assess(answers(exclusions={**NO_EXCLUSIONS, "marine": "yes"}), today=TODAY)
    assert "2014/90/EU" in result.scope_reasons[0]


def test_classification_takes_highest_category():
    result = assess(answers(class_i=[2], class_ii=[2]), today=TODAY)
    assert result.category == "class_ii"
    assert "Firewalls" in " ".join(result.categories)
    assert assess(answers(class_i=[1], critical=[3]), today=TODAY).category == "critical"
    assert "third-party" in assess(answers(class_i=[3]), today=TODAY).conformity


def test_foss_note_for_open_source_important_products():
    result = assess(answers(scope={**IN_SCOPE, "open_source": "yes"}, class_i=[3]), today=TODAY)
    assert "Article 32(5)" in result.conformity
    assert "Article 32(5)" not in assess(answers(scope={**IN_SCOPE, "open_source": "yes"}), today=TODAY).conformity


def test_sbom_and_scan_evidence():
    sbom = {"components": 40, "direct": 8, "transitive": 32, "unknown": 0, "spec_version": "1.6"}
    scan = {"vulnerable_components": 2, "known_exploited_count": 1}
    result = assess(answers(), sbom_summary=sbom, scan_summary=scan, today=TODAY)
    by_id = {r.id: r for r in result.all_requirements}
    assert by_id["II.1"].status == "partial"
    assert "40 components" in by_id["II.1"].evidence
    assert by_id["I.2a"].status == "at-risk"
    assert "CISA KEV" in by_id["I.2a"].evidence
    assert result.warnings and "24 hours" in result.warnings[0]


def test_sbom_without_direct_info_stays_partial_even_if_marked_done():
    sbom = {"components": 5, "direct": 0, "transitive": 0, "unknown": 5, "spec_version": "1.6"}
    result = assess(answers(requirements={"II.1": "done"}), sbom_summary=sbom, today=TODAY)
    ii1 = next(r for r in result.part_ii if r.id == "II.1")
    assert ii1.status == "partial"
    assert "top-level" in ii1.evidence


def test_clean_scan_keeps_done():
    scan = {"vulnerable_components": 0, "known_exploited_count": 0}
    result = assess(answers(requirements={"I.2a": "done"}), scan_summary=scan, today=TODAY)
    i2a = next(r for r in result.part_i if r.id == "I.2a")
    assert i2a.status == "done"
    assert "your own code is not covered" in i2a.evidence


def test_support_period_and_contact():
    product = Product(name="Box", version="1", security_contact="psirt@box.example.org",
                      support_period_end="2029-01-01")
    result = assess(answers(), product=product, today=TODAY)
    assert "five years" in result.support_note
    assert "psirt@box.example.org" in next(r for r in result.part_ii if r.id == "II.6").evidence
    long = assess(answers(), product=Product(support_period_end="2032-01-01"), today=TODAY)
    assert "five years" not in long.support_note
    placeholder = assess(answers(), product=Product(security_contact="security@example.com"), today=TODAY)
    assert next(r for r in placeholder.part_ii if r.id == "II.6").evidence == ""


def test_answers_file_roundtrip(tmp_path):
    original = answers(class_i=[1, 3], requirements={"I.1": "done", "II.5": "n/a"},
                       notes={"II.5": "Policy at https://example.org/security"})
    path = tmp_path / "answers.toml"
    path.write_text(original.dump())
    loaded = Answers.load(path)
    assert loaded.scope == original.scope
    assert loaded.class_i == [1, 3]
    assert loaded.requirements["I.1"] == "done"
    assert loaded.requirements["II.5"] == "n/a"
    assert loaded.notes["II.5"].startswith("Policy")


def test_blank_template_parses(tmp_path):
    path = tmp_path / "answers.toml"
    path.write_text(Answers().dump())
    loaded = Answers.load(path)
    assert assess(loaded, today=TODAY).scope == "unclear"


def test_interactive(capsys):
    replies = iter(
        ["yes"] * 4 + ["no", "maybe", "no"]  # 'maybe' is rejected and re-asked
        + ["no"] * len(cra.EXCLUSIONS)
        + ["2, 5", "", "x", ""]  # class I; class II; 'x' rejected; Annex IV
        + ["done"] * (len(cra.PART_I) + len(cra.PART_II))
    )
    result = ask_interactively(lambda _prompt: next(replies))
    assert result.scope["open_source"] == "no"
    assert result.class_i == [2, 5]
    assert result.class_ii == [] and result.critical == []
    assert assess(result, today=TODAY).counts() == {"done": 22}
    assert "Please answer one of" in capsys.readouterr().out


def test_markdown_report():
    product = Product(name="Box", version="2.0", manufacturer="Box GmbH")
    scan = {"vulnerable_components": 1, "known_exploited_count": 1}
    md = to_markdown(assess(answers(requirements={"I.1": "no"}), product, scan_summary=scan, today=TODAY), product, TODAY)
    assert md.startswith("# CRA readiness report: Box 2.0")
    assert "| Scope | **In scope** |" in md
    assert "Box GmbH" in md
    assert "Act now" in md
    gaps = md.split("## Gaps to close first")[1].split("## Support period")[0]
    assert gaps.index("I.2a") < gaps.index("I.1")  # at-risk before not started
    assert "not legal advice" in md
