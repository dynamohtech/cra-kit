"""CRA scope check, product classification and readiness report."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Callable

from cra_kit import __version__, cra
from cra_kit.config import Product

YES, NO, UNSURE = "yes", "no", "unsure"
STATUSES = ("done", "partial", "no", "n/a")
STATUS_LABEL = {
    "done": "Done",
    "partial": "Partial",
    "no": "Not started",
    "n/a": "Not applicable",
    "at-risk": "At risk",
    "": "Not answered",
}

SCOPE_QUESTIONS = [
    ("digital_elements", "Is it software, or hardware with software in it (a 'product with digital elements')?"),
    ("data_connection", "Is it intended, or reasonably expected, to connect directly or indirectly to a device or network? (Article 2(1))"),
    ("eu_market", "Is it, or will it be, made available on the EU market?"),
    ("commercial", "Is it supplied in the course of a commercial activity (sold, or free but monetised, e.g. through support or data)?"),
    ("saas_only", "Is it ONLY a service you run in the cloud, with no software or device delivered to customers?"),
    ("open_source", "Is it free and open-source software?"),
]

TEMPLATE_HEADER = f"""# cra-kit readiness answers. Fill in, then run:
#   cra-kit assess --answers this-file.toml [--sbom sbom.cdx.json] [--scan scan.json]
# Scope answers: "yes", "no" or "unsure".
# Requirement answers: "done", "partial", "no" or "n/a".
# This is a structured checklist, not legal advice. Regulation text:
# {cra.REGULATION_URL}
"""


# ---------------------------------------------------------------------------
# Answers
# ---------------------------------------------------------------------------


@dataclass
class Answers:
    scope: dict[str, str] = field(default_factory=dict)
    exclusions: dict[str, str] = field(default_factory=dict)
    class_i: list[int] = field(default_factory=list)
    class_ii: list[int] = field(default_factory=list)
    critical: list[int] = field(default_factory=list)
    requirements: dict[str, str] = field(default_factory=dict)
    notes: dict[str, str] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "Answers":
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        cls_data = data.get("classification", {})
        return cls(
            scope={k: _norm(v) for k, v in data.get("scope", {}).items()},
            exclusions={k: _norm(v) for k, v in data.get("exclusions", {}).items()},
            class_i=[int(x) for x in cls_data.get("annex_iii_class_i", [])],
            class_ii=[int(x) for x in cls_data.get("annex_iii_class_ii", [])],
            critical=[int(x) for x in cls_data.get("annex_iv", [])],
            requirements={k: _norm(v) for k, v in data.get("requirements", {}).items()},
            notes={k: str(v) for k, v in data.get("notes", {}).items()},
        )

    def dump(self) -> str:
        lines = [TEMPLATE_HEADER, "[scope]"]
        for key, question in SCOPE_QUESTIONS:
            lines += [f"# {question}", f'{key} = "{self.scope.get(key, "")}"']
        lines += ["", "[exclusions]", "# Article 2: products covered by these rules are outside the CRA."]
        for key, question, basis in cra.EXCLUSIONS:
            lines += [f"# {question} ({basis})", f'{key} = "{self.exclusions.get(key, "")}"']
        lines += ["", "[classification]",
                  "# List the numbers of any category that matches the product's CORE functionality."]
        lines.append("# Annex III, Class I:")
        lines += [f"#  {i}. {t}" for i, t in enumerate(cra.ANNEX_III_CLASS_I, 1)]
        lines.append(f"annex_iii_class_i = {self.class_i}")
        lines.append("# Annex III, Class II:")
        lines += [f"#  {i}. {t}" for i, t in enumerate(cra.ANNEX_III_CLASS_II, 1)]
        lines.append(f"annex_iii_class_ii = {self.class_ii}")
        lines.append("# Annex IV, critical:")
        lines += [f"#  {i}. {t}" for i, t in enumerate(cra.ANNEX_IV, 1)]
        lines.append(f"annex_iv = {self.critical}")
        lines += ["", "[requirements]", "# Annex I, Part I: product properties"]
        for rid, text in cra.PART_I:
            lines += [f"# {text}", f'"{rid}" = "{self.requirements.get(rid, "")}"']
        lines += ["# Annex I, Part II: vulnerability handling"]
        for rid, text in cra.PART_II:
            lines += [f"# {text}", f'"{rid}" = "{self.requirements.get(rid, "")}"']
        lines += ["", "[notes]", "# Optional evidence per requirement, e.g.", '# "II.5" = "Policy at https://example.com/security"']
        for rid, note in self.notes.items():
            lines.append(f'"{rid}" = "{note}"')
        return "\n".join(lines) + "\n"


def _norm(value: object) -> str:
    text = str(value).strip().lower()
    return {"y": YES, "true": YES, "n": NO, "false": NO, "?": UNSURE, "na": "n/a"}.get(text, text)


def ask_interactively(ask: Callable[[str], str] = input) -> Answers:
    """Walk through every question on the terminal."""
    answers = Answers()

    def choose(prompt: str, allowed: tuple[str, ...]) -> str:
        while True:
            reply = _norm(ask(f"{prompt} [{'/'.join(allowed)}] ").strip())
            if reply in allowed:
                return reply
            print(f"  Please answer one of: {', '.join(allowed)}")

    def numbers(prompt: str, maximum: int) -> list[int]:
        while True:
            reply = ask(f"{prompt} (comma-separated numbers, blank for none) ").strip()
            if not reply:
                return []
            try:
                picked = sorted({int(x) for x in reply.replace(" ", "").split(",") if x})
            except ValueError:
                print("  Numbers only, e.g. 2,5")
                continue
            if all(1 <= n <= maximum for n in picked):
                return picked
            print(f"  Pick numbers between 1 and {maximum}")

    print("\nScope\n-----")
    for key, question in SCOPE_QUESTIONS:
        answers.scope[key] = choose(question, (YES, NO, UNSURE))
    print("\nExclusions (Article 2)\n----------------------")
    for key, question, basis in cra.EXCLUSIONS:
        answers.exclusions[key] = choose(f"{question} ({basis})", (YES, NO, UNSURE))
    print("\nClassification: does the product's CORE function match any of these?\n")
    for title, items, attr in (
        ("Annex III, Class I", cra.ANNEX_III_CLASS_I, "class_i"),
        ("Annex III, Class II", cra.ANNEX_III_CLASS_II, "class_ii"),
        ("Annex IV, critical", cra.ANNEX_IV, "critical"),
    ):
        print(title)
        for i, text in enumerate(items, 1):
            print(f"  {i:>2}. {text}")
        setattr(answers, attr, numbers(title, len(items)))
    print("\nEssential requirements (Annex I)\n--------------------------------")
    for rid, text in cra.PART_I + cra.PART_II:
        answers.requirements[rid] = choose(f"{rid} {text}", STATUSES)
    return answers


# ---------------------------------------------------------------------------
# Assessment
# ---------------------------------------------------------------------------


@dataclass
class RequirementResult:
    id: str
    text: str
    status: str
    evidence: str = ""


@dataclass
class Assessment:
    scope: str  # "in", "out", "likely-out", "unclear"
    scope_reasons: list[str]
    category: str  # default | class_i | class_ii | critical
    categories: list[str]
    conformity: str
    part_i: list[RequirementResult]
    part_ii: list[RequirementResult]
    support_note: str
    warnings: list[str] = field(default_factory=list)

    @property
    def all_requirements(self) -> list[RequirementResult]:
        return self.part_i + self.part_ii

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for r in self.all_requirements:
            out[r.status] = out.get(r.status, 0) + 1
        return out


CATEGORY_LABEL = {
    "default": "Default (not listed in Annex III or IV)",
    "class_i": "Important product, Class I (Annex III)",
    "class_ii": "Important product, Class II (Annex III)",
    "critical": "Critical product (Annex IV)",
}


def assess(
    answers: Answers,
    product: Product | None = None,
    sbom_summary: dict | None = None,
    scan_summary: dict | None = None,
    today: date | None = None,
) -> Assessment:
    today = today or date.today()
    scope, reasons = _scope(answers)

    categories: list[str] = []
    categories += [f"Annex IV: {cra.ANNEX_IV[i - 1]}" for i in answers.critical if 1 <= i <= len(cra.ANNEX_IV)]
    categories += [f"Annex III Class II: {cra.ANNEX_III_CLASS_II[i - 1]}" for i in answers.class_ii if 1 <= i <= len(cra.ANNEX_III_CLASS_II)]
    categories += [f"Annex III Class I: {cra.ANNEX_III_CLASS_I[i - 1]}" for i in answers.class_i if 1 <= i <= len(cra.ANNEX_III_CLASS_I)]
    if answers.critical:
        category = "critical"
    elif answers.class_ii:
        category = "class_ii"
    elif answers.class_i:
        category = "class_i"
    else:
        category = "default"
    conformity = cra.CONFORMITY[category]
    if category in ("class_i", "class_ii") and answers.scope.get("open_source") == YES:
        conformity += " " + cra.FOSS_NOTE

    def result(rid: str, text: str) -> RequirementResult:
        status = answers.requirements.get(rid, "")
        if status not in STATUSES:
            status = ""
        return RequirementResult(rid, text, status, answers.notes.get(rid, ""))

    part_i = [result(rid, text) for rid, text in cra.PART_I]
    part_ii = [result(rid, text) for rid, text in cra.PART_II]
    by_id = {r.id: r for r in part_i + part_ii}
    warnings: list[str] = []

    if sbom_summary is not None:
        r = by_id["II.1"]
        n, direct, unknown = sbom_summary["components"], sbom_summary["direct"], sbom_summary["unknown"]
        evidence = (
            f"CycloneDX {sbom_summary.get('spec_version')} SBOM: {n} components "
            f"({direct} direct, {sbom_summary['transitive']} transitive, {unknown} relationship unknown)"
        )
        if n == 0:
            r.status, evidence = "partial", evidence + "; no components found, check the SBOM warnings"
        elif direct == 0 and unknown:
            r.status = "partial"
            evidence += "; top-level dependencies could not be identified from these files, so mark them manually or use a lockfile that records them"
        elif r.status in ("", "no"):
            r.status = "partial"
            evidence += "; also document how vulnerabilities in these components are tracked"
        r.evidence = "; ".join(x for x in (r.evidence, evidence) if x)

    if scan_summary is not None:
        r = by_id["I.2a"]
        vulnerable = scan_summary.get("vulnerable_components", 0)
        kev = scan_summary.get("known_exploited_count", 0)
        closed = scan_summary.get("closed_by_vex_count", 0)
        if closed:
            r.evidence = "; ".join(x for x in (r.evidence, (
                f"{closed} dependency advisories closed by recorded VEX decisions "
                f"({', '.join(scan_summary.get('vex_sources') or []) or 'VEX file'})"
            )) if x)
        if vulnerable:
            r.status = "at-risk"
            r.evidence = "; ".join(x for x in (r.evidence, (
                f"dependency scan found known vulnerabilities in {vulnerable} components"
                + (f", {kev} of them listed as exploited in the wild (CISA KEV)" if kev else "")
            )) if x)
            if kev:
                warnings.append(
                    "The scan found dependency vulnerabilities listed as actively exploited. Check whether they "
                    "are exploitable in your product: if so, Article 14 requires an early warning within 24 hours."
                )
        else:
            r.evidence = "; ".join(x for x in (r.evidence, "dependency scan found no known vulnerabilities (your own code is not covered)") if x)
            if r.status in ("", "no"):
                r.status = "partial"

    if product and product.security_contact and "example.com" not in product.security_contact:
        r = by_id["II.6"]
        r.evidence = "; ".join(x for x in (r.evidence, f"security contact: {product.security_contact}") if x)

    support_note = _support_note(product, today)
    return Assessment(scope, reasons, category, categories, conformity, part_i, part_ii, support_note, warnings)


def _scope(answers: Answers) -> tuple[str, list[str]]:
    s, reasons, unsure = answers.scope, [], []
    for key, question, basis in cra.EXCLUSIONS:
        value = answers.exclusions.get(key, "")
        if value == YES:
            return "out", [f"Excluded by {basis}."]
        if value in (UNSURE, ""):
            unsure.append(f"Exclusion not confirmed: {question}")
    if s.get("digital_elements") == NO:
        return "out", ["It is not a product with digital elements."]
    if s.get("data_connection") == NO:
        return "out", ["It has no direct or indirect data connection to a device or network (Article 2(1))."]
    if s.get("eu_market") == NO:
        return "out", ["It is not made available on the EU market."]
    if s.get("saas_only") == YES:
        return "likely-out", [
            "Pure cloud services are generally outside the CRA; it covers remote data processing only where "
            "it is part of a product with digital elements and the product cannot perform one of its functions without it (Article 3(1) and (2)). NIS2 may apply instead."
        ]
    if s.get("commercial") == NO:
        return "likely-out", [
            "Products not supplied in the course of a commercial activity are generally outside manufacturer "
            "obligations. If you are a legal person that systematically supports free and open-source software "
            "intended for commercial use, open-source steward obligations (Article 24) may apply."
        ]
    for key, question in SCOPE_QUESTIONS[:4]:
        if s.get(key) in (UNSURE, ""):
            unsure.append(f"Not confirmed: {question}")
    if unsure:
        return "unclear", unsure
    reasons.append("Software or hardware with a data connection, supplied commercially on the EU market, with no exclusion.")
    return "in", reasons


def _support_note(product: Product | None, today: date) -> str:
    if not product or not product.support_period_end:
        return ("No support period end date set. It must be at least five years, unless the product is expected "
                "to be in use for less time (Article 13(8)), and the end date, at least month and year, must be "
                "stated clearly at the time of purchase (Article 13(19)).")
    try:
        end = date.fromisoformat(product.support_period_end)
    except ValueError:
        return f"Support period end '{product.support_period_end}' is not a YYYY-MM-DD date."
    years = (end - today).days / 365.25
    if years < 5:
        return (f"Support period ends {end.isoformat()} ({years:.1f} years from today). Article 13(8) requires at "
                "least five years unless the product is expected to be in use for less time: record that justification.")
    return f"Support period ends {end.isoformat()} ({years:.1f} years from today)."


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

SCOPE_LABEL = {
    "in": "In scope",
    "out": "Out of scope",
    "likely-out": "Likely out of scope",
    "unclear": "Unclear: answer the open questions",
}


def to_markdown(a: Assessment, product: Product | None, today: date | None = None) -> str:
    today = today or date.today()
    name = f"{product.name} {product.version}" if product else "Unnamed product"
    counts = a.counts()
    total = len(a.all_requirements)
    lines = [
        f"# CRA readiness report: {name}",
        "",
        f"Generated {today.isoformat()} by cra-kit {__version__}. This is a structured self-check against "
        f"Regulation (EU) 2024/2847, not legal advice.",
        "",
        "## Summary",
        "",
        "| | |",
        "| --- | --- |",
        f"| Scope | **{SCOPE_LABEL[a.scope]}** |",
        f"| Product category | {CATEGORY_LABEL[a.category]} |",
        f"| Conformity assessment | {a.conformity} |",
        f"| Requirements done | {counts.get('done', 0)} of {total} |",
        f"| Partial | {counts.get('partial', 0)} |",
        f"| At risk | {counts.get('at-risk', 0)} |",
        f"| Not started | {counts.get('no', 0)} |",
        f"| Not answered | {counts.get('', 0)} |",
    ]
    if product and product.manufacturer:
        lines.append(f"| Manufacturer | {product.manufacturer} |")
    lines += ["", "**Key dates:** " + "; ".join(f"{d}: {t}" for d, t in cra.KEY_DATES) + ".", ""]
    if a.warnings:
        lines += ["> **Act now:** " + " ".join(a.warnings), ""]
    lines += ["## Scope", ""] + [f"- {r}" for r in a.scope_reasons]
    if a.categories:
        lines += ["", "Matched categories:"] + [f"- {c}" for c in a.categories]
    lines += ["", "## Essential requirements (Annex I, Part I)", ""] + _table(a.part_i)
    lines += ["", "## Vulnerability handling (Annex I, Part II)", ""] + _table(a.part_ii)
    gaps = [r for r in a.all_requirements if r.status in ("at-risk", "no", "")]
    lines += ["", "## Gaps to close first", ""]
    if gaps:
        order = {"at-risk": 0, "no": 1, "": 2}
        for r in sorted(gaps, key=lambda r: order[r.status]):
            lines.append(f"- **{r.id}** ({STATUS_LABEL[r.status]}): {r.text}")
    else:
        lines.append("- None: every requirement is done, partial or not applicable.")
    lines += [
        "",
        "## Support period",
        "",
        a.support_note,
        "",
        "## Reporting (applies from 11 September 2026)",
        "",
        "Actively exploited vulnerabilities and severe incidents must be reported through the CRA Single Reporting "
        "Platform: an early warning within 24 hours of becoming aware, a notification within 72 hours, and a final "
        "report (14 days after a fix is available for vulnerabilities; one month after the notification for "
        "incidents). Impacted users must also be informed (Article 14(8)). Prepare the pack in advance with "
        "`cra-kit report vulnerability` or `cra-kit report incident`.",
        "",
        f"Regulation text: {cra.REGULATION_URL}",
        "",
    ]
    return "\n".join(lines)


def _table(rows: list[RequirementResult]) -> list[str]:
    out = ["| ID | Requirement | Status | Evidence and notes |", "| --- | --- | --- | --- |"]
    for r in rows:
        out.append(f"| {r.id} | {r.text} | {STATUS_LABEL[r.status]} | {r.evidence.replace('|', '/')} |")
    return out
