"""Draft CRA documents: technical documentation (Annex VII), EU declaration of
conformity (Annex V), simplified declaration (Annex VI) and user information
(Annex II).

The drafts follow the structure the regulation sets out, point by point, and
fill in what cra-kit already knows from cra-kit.toml, the readiness answers,
the SBOM, the scan and any VEX decisions. Everything else is marked TODO.
They are working drafts for the manufacturer to complete and own; drawing up
the declaration makes the manufacturer responsible for the product's
compliance (Article 28(4)).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from pathlib import Path

from cra_kit import __version__, cra
from cra_kit.assess import CATEGORY_LABEL, STATUS_LABEL, Assessment
from cra_kit.config import Product

TODO = "**TODO:**"
HARDWARE_TYPES = {"device"}
FILES = {
    "README.md": "index",
    "01-technical-documentation.md": "annex_vii",
    "02-eu-declaration-of-conformity.md": "annex_v",
    "03-simplified-declaration.md": "annex_vi",
    "04-user-information.md": "annex_ii",
}


@dataclass
class Inputs:
    product: Product
    assessment: Assessment | None = None
    sbom_file: str = ""
    sbom_summary: dict | None = None
    scan_file: str = ""
    scan_summary: dict | None = None
    vex_file: str = ""
    security_policy: str = ""  # e.g. SECURITY.md, if the project has one
    today: date | None = None


def _v(value: str, todo: str) -> str:
    return value if value else f"{TODO} {todo}"


def _name(p: Product) -> str:
    return f"{p.name} {p.version}".strip()


def _header(title: str, basis: str, inp: Inputs) -> list[str]:
    today = (inp.today or date.today()).isoformat()
    return [
        f"# {title}",
        "",
        f"Product: **{_name(inp.product)}**. Legal basis: {basis}. Draft generated {today} by cra-kit {__version__}.",
        "",
        "> Working draft. Complete every TODO, check every prefilled value, and have the final text reviewed. "
        "This is not legal advice.",
        "",
    ]


# ---------------------------------------------------------------------------
# Annex VII: technical documentation
# ---------------------------------------------------------------------------


def annex_vii(inp: Inputs) -> str:
    p, a = inp.product, inp.assessment
    lines = _header("Technical documentation", "Regulation (EU) 2024/2847, Article 31 and Annex VII", inp)
    lines += [
        "Article 31(2): draw this up before the product is placed on the market and keep it updated, where "
        "appropriate, at least during the support period. Article 13(13): keep it, with the EU declaration of "
        "conformity, at the disposal of market surveillance authorities for at least 10 years after the product "
        "is placed on the market or for the support period, whichever is longer.",
        "",
        "## 1. General description of the product",
        "",
        "### (a) Intended purpose",
        "",
        _v(p.intended_purpose, "describe what the product is for (set intended_purpose in cra-kit.toml)."),
        "",
        "### (b) Versions of software affecting compliance with the essential cybersecurity requirements",
        "",
        f"- Product version: {_v(p.version, 'product version')}",
        f"- {TODO} list the firmware or software versions, and their components, that this documentation covers.",
        "",
        "### (c) Hardware: photographs or illustrations of external features, marking and internal layout",
        "",
        (f"{TODO} attach photographs or illustrations." if p.type in HARDWARE_TYPES
         else f"Not applicable if the product is software only (product type in cra-kit.toml: {p.type}). "
              f"{TODO} confirm."),
        "",
        "### (d) User information and instructions (Annex II)",
        "",
        "See [04-user-information.md](04-user-information.md).",
        "",
        "## 2. Design, development, production and vulnerability handling",
        "",
        "### (a) Design and development, including system architecture",
        "",
        f"{TODO} describe the system architecture: how software components build on or feed into each other and "
        "integrate into the overall processing. Add drawings and schemes where applicable.",
        "",
    ]
    if inp.sbom_summary:
        s = inp.sbom_summary
        lines += [
            f"Third-party components (from the SBOM): {s['components']} in total, {s['direct']} direct and "
            f"{s['transitive']} transitive" + (f", {s['unknown']} not stated" if s.get("unknown") else "") + ".",
            "",
        ]
    lines += [
        "### (b) Vulnerability handling processes",
        "",
        "| Element | Where it is documented |",
        "| --- | --- |",
        "| Software bill of materials | " + (
            f"`{inp.sbom_file}` (CycloneDX {inp.sbom_summary.get('spec_version')}, "
            f"{inp.sbom_summary['components']} components, generated {inp.sbom_summary.get('timestamp') or 'n/a'})"
            if inp.sbom_summary else f"{TODO} generate with `cra-kit sbom`") + " |",
        "| Coordinated vulnerability disclosure policy | " + (
            f"`{inp.security_policy}`" if inp.security_policy else f"{TODO} link your published policy") + " |",
        "| Contact address for reporting vulnerabilities | " + (
            p.security_contact if p.security_contact and "example.com" not in p.security_contact
            else f"{TODO} set security_contact in cra-kit.toml") + " |",
        f"| Secure distribution of updates | {TODO} describe the technical solution (e.g. signed updates over "
        "an authenticated channel) |",
        "| Dependency vulnerability monitoring | " + (
            f"`{inp.scan_file}`: OSV.dev and CISA KEV scan; " + _scan_sentence(inp.scan_summary)
            if inp.scan_summary else f"{TODO} run `cra-kit scan` in CI and keep the results") + " |",
        "| Exploitability decisions (VEX) | " + (
            f"`{inp.vex_file}`" if inp.vex_file else "None recorded (`cra-kit vex add`)") + " |",
        "",
        "Vulnerability handling requirements (Annex I, Part II):",
        "",
    ]
    lines += _requirements_table(a.part_ii if a else None, cra.PART_II)
    lines += [
        "",
        "### (c) Production and monitoring processes, and their validation",
        "",
        f"{TODO} describe how the product is built, released and monitored, and how those processes are validated "
        "(for example CI checks, code review, release signing).",
        "",
        "## 3. Cybersecurity risk assessment (Article 13)",
        "",
        f"{TODO} attach or summarise the risk assessment the product is designed, developed, produced, delivered "
        "and maintained against, and explain how each essential requirement in Part I of Annex I applies.",
        "",
        "How the essential cybersecurity requirements (Annex I, Part I) apply:",
        "",
    ]
    lines += _requirements_table(a.part_i if a else None, cra.PART_I)
    lines += [
        "",
        "A requirement marked not applicable needs a written justification in the risk assessment.",
        "",
        "## 4. Support period (Article 13(8))",
        "",
        f"- End of support period: {_v(p.support_period_end, 'set support_period_end in cra-kit.toml')}",
    ]
    if a:
        lines.append(f"- {a.support_note}")
    lines += [
        f"- {TODO} record the information taken into account to set the support period (for example the time "
        "users can reasonably expect to use the product, and the support periods of comparable products).",
        "",
        "## 5. Harmonised standards, common specifications or certification schemes applied",
        "",
        "| Standard, specification or scheme | Applied in full or in part | Parts applied |",
        "| --- | --- | --- |",
        f"| {TODO} | | |",
        "",
        "Where none was applied, describe the solutions adopted to meet each essential requirement in Parts I and "
        "II of Annex I, and list the other technical specifications applied.",
        "",
    ]
    if a:
        lines += [f"Conformity assessment route for this product ({CATEGORY_LABEL[a.category]}): {a.conformity}", ""]
    lines += [
        "## 6. Test reports",
        "",
        "| Report | Date | Covers |",
        "| --- | --- | --- |",
    ]
    if inp.scan_summary:
        lines.append(f"| Dependency vulnerability scan (`{inp.scan_file}`) | "
                     f"{(inp.today or date.today()).isoformat()} | Annex I, Part I(2)(a) and Part II(1), for "
                     "third-party components only |")
    lines += [
        f"| {TODO} security testing (e.g. penetration test, fuzzing, code review) | | Annex I, Part I and Part II(3) |",
        "",
        "## 7. EU declaration of conformity",
        "",
        "See [02-eu-declaration-of-conformity.md](02-eu-declaration-of-conformity.md).",
        "",
        "## 8. Software bill of materials (on reasoned request from a market surveillance authority)",
        "",
        (f"`{inp.sbom_file}`." if inp.sbom_file else f"{TODO} generate with `cra-kit sbom`."),
        "",
    ]
    return "\n".join(lines)


def _scan_sentence(summary: dict | None) -> str:
    if not summary:
        return ""
    n = summary.get("vulnerable_components", 0)
    text = (f"{n} component{'' if n == 1 else 's'} with open advisories, "
            f"{summary.get('known_exploited_count', 0)} known exploited")
    if summary.get("closed_by_vex_count"):
        text += f", {summary['closed_by_vex_count']} closed by VEX"
    return text


def _requirements_table(results, reference) -> list[str]:
    rows = ["| ID | Requirement | Status | Evidence and notes |", "| --- | --- | --- | --- |"]
    if results:
        for r in results:
            rows.append(f"| {r.id} | {r.text} | {STATUS_LABEL[r.status]} | "
                        f"{(r.evidence or TODO + ' evidence').replace('|', '/')} |")
    else:
        for rid, text in reference:
            rows.append(f"| {rid} | {text} | {TODO} | |")
    return rows


# ---------------------------------------------------------------------------
# Annex V: EU declaration of conformity
# ---------------------------------------------------------------------------


def annex_v(inp: Inputs) -> str:
    p, a = inp.product, inp.assessment
    manufacturer = _v(p.manufacturer, "manufacturer name")
    lines = _header("EU declaration of conformity", "Regulation (EU) 2024/2847, Article 28 and Annex V", inp)
    lines += [
        "Article 28(2): make this declaration available in the languages required by each Member State where the "
        "product is placed or made available on the market, and update it as appropriate. Article 28(3): if other "
        "Union legislation also requires a declaration, draw up a single declaration covering all of it.",
        "",
        "---",
        "",
        "**EU DECLARATION OF CONFORMITY**",
        "",
        "**1. Product** (name and type and any additional information enabling unique identification)",
        "",
        f"{_name(p)}" + (f", type: {p.type}" if p.type else "") + f". {TODO} add model or type number, "
        "and any other identifier.",
        "",
        "**2. Name and address of the manufacturer or its authorised representative**",
        "",
        manufacturer,
        "",
        _v(p.manufacturer_address, "postal address (set manufacturer_address in cra-kit.toml)"),
        "",
        "**3.** This EU declaration of conformity is issued under the sole responsibility of the provider.",
        "",
        "**4. Object of the declaration** (identification allowing traceability; may include a photograph)",
        "",
        f"{_name(p)}. {TODO} add serial or batch range, software version identification, and a photograph "
        "where appropriate.",
        "",
        "**5.** The object of the declaration described above is in conformity with Regulation (EU) 2024/2847 "
        "of the European Parliament and of the Council (Cyber Resilience Act), and the fulfilment of the applicable "
        "essential cybersecurity requirements set out in its Annex I has been demonstrated. "
        f"{TODO} list any other relevant Union harmonisation legislation, with publication references.",
        "",
        "**6. Harmonised standards, common specifications or cybersecurity certification used**",
        "",
        f"{TODO} references, or \"none\".",
        "",
        "**7. Notified body** (where applicable: name and number, conformity assessment procedure performed, "
        "certificate issued)",
        "",
    ]
    if a and a.category == "default":
        lines.append(f"Not applicable: internal control (module A). {TODO} confirm.")
    elif a and a.category == "class_i":
        lines.append("Not applicable if you used internal control (module A), which a Class I product may use only "
                     "when harmonised standards, common specifications or a European cybersecurity certification "
                     "scheme (at assurance level at least 'substantial') are applied in full (Article 32(2)). "
                     f"Otherwise: {TODO} name and number of the notified "
                     "body, the procedure performed and the certificate reference.")
    else:
        lines.append(f"{TODO} name and number of the notified body, the procedure performed and the certificate "
                     "reference" + (f" ({CATEGORY_LABEL[a.category]})." if a else "."))
    lines += [
        "",
        "**8. Additional information**",
        "",
        f"Signed for and on behalf of: {manufacturer}",
        "",
        f"(place and date of issue): {TODO}",
        "",
        f"(name, function) (signature): {TODO}",
        "",
    ]
    return "\n".join(lines)


def annex_vi(inp: Inputs) -> str:
    p = inp.product
    lines = _header("Simplified EU declaration of conformity", "Regulation (EU) 2024/2847, Article 13(20) and "
                    "Annex VI", inp)
    lines += [
        "Article 13(20): ship either a copy of the full declaration or this simplified one with the product. The "
        "simplified declaration must give the exact internet address of the full declaration.",
        "",
        "---",
        "",
        f"Hereby, {_v(p.manufacturer, 'name of manufacturer')} declares that the product with digital elements "
        f"type {_name(p)} is in compliance with Regulation (EU) 2024/2847.",
        "",
        "The full text of the EU declaration of conformity is available at the following internet address: "
        + _v(p.declaration_url, "URL (set declaration_url in cra-kit.toml)"),
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Annex II: information and instructions to the user
# ---------------------------------------------------------------------------


def annex_ii(inp: Inputs) -> str:
    p = inp.product
    contact = p.security_contact if p.security_contact and "example.com" not in p.security_contact else ""
    lines = _header("Information and instructions to the user", "Regulation (EU) 2024/2847, Annex II", inp)
    lines += [
        "At minimum, the product must be accompanied by the information below.",
        "",
        "**1. Manufacturer** (name, registered trade name or trademark; postal address; email or other digital "
        "contact; website where available)",
        "",
        f"- Name: {_v(p.manufacturer, 'manufacturer name')}",
        f"- Postal address: {_v(p.manufacturer_address, 'set manufacturer_address in cra-kit.toml')}",
        f"- Email or other digital contact: {TODO}",
        f"- Website: {_v(p.website, 'set website in cra-kit.toml, or remove if none')}",
        "",
        "**2. Single point of contact for vulnerabilities, and where the coordinated vulnerability disclosure "
        "policy can be found**",
        "",
        f"- Report vulnerabilities to: {_v(contact, 'set security_contact in cra-kit.toml')}",
        f"- Coordinated vulnerability disclosure policy: {_v(inp.security_policy, 'link to the published policy')}",
        "",
        "**3. Product identification** (name, type and any additional information enabling unique identification)",
        "",
        f"{_name(p)}" + (f", type: {p.type}" if p.type else "") + f". {TODO} model or type number.",
        "",
        "**4. Intended purpose**, including the security environment provided by the manufacturer, the product's "
        "essential functionalities and information about its security properties",
        "",
        _v(p.intended_purpose, "intended purpose (set intended_purpose in cra-kit.toml)"),
        "",
        f"{TODO} security environment, essential functionalities and security properties.",
        "",
        "**5. Known or foreseeable circumstances that may lead to significant cybersecurity risks** (in intended "
        "use or reasonably foreseeable misuse)",
        "",
        f"{TODO}",
        "",
        "**6. Internet address of the EU declaration of conformity** (where applicable)",
        "",
        _v(p.declaration_url, "URL, or remove if the full declaration ships with the product"),
        "",
        "**7. Technical security support and end of the support period** (during which users can expect "
        "vulnerabilities to be handled and to receive security updates)",
        "",
        f"- Type of support: {TODO}",
        f"- Support period ends: {_v(p.support_period_end, 'set support_period_end in cra-kit.toml')}",
        "",
        "**8. Detailed instructions** (or an internet address where they can be found) on:",
        "",
        f"- (a) the measures needed at initial commissioning and throughout the product's lifetime to ensure its "
        f"secure use: {TODO}",
        f"- (b) how changes to the product can affect the security of data: {TODO}",
        f"- (c) how security-relevant updates can be installed: {TODO}",
        f"- (d) secure decommissioning, including how user data can be securely removed: {TODO}",
        f"- (e) how the default setting enabling automatic installation of security updates (Annex I, Part I, "
        f"point (2)(c)) can be turned off: {TODO}",
        f"- (f) where the product is intended for integration into other products, the information the integrator "
        f"needs to comply with Annex I and Annex VII: {TODO} or \"not applicable\".",
        "",
        "**9. Software bill of materials** (only if you decide to make it available to users: where it can be "
        "accessed)",
        "",
        f"{TODO} URL, or remove if the SBOM is not shared with users.",
        "",
    ]
    return "\n".join(lines)


def index(inp: Inputs) -> str:
    lines = _header("CRA technical file", "Regulation (EU) 2024/2847", inp)
    lines += [
        "| File | Content | Legal basis |",
        "| --- | --- | --- |",
        "| [01-technical-documentation.md](01-technical-documentation.md) | Technical documentation | Article 31, "
        "Annex VII |",
        "| [02-eu-declaration-of-conformity.md](02-eu-declaration-of-conformity.md) | EU declaration of conformity "
        "| Article 28, Annex V |",
        "| [03-simplified-declaration.md](03-simplified-declaration.md) | Simplified declaration (optional) | "
        "Article 13(20), Annex VI |",
        "| [04-user-information.md](04-user-information.md) | Information and instructions to the user | Annex II |",
        "",
        "Re-running `cra-kit techfile` never overwrites these files unless you pass `--force`, so edit them freely. "
        "To refresh the prefilled facts, generate into a new folder and compare.",
        "",
        "Keep the technical documentation and the declaration for at least 10 years after the product is placed "
        "on the market or for the support period, whichever is longer (Article 13(13)).",
        "",
    ]
    return "\n".join(lines)


def build(inp: Inputs) -> dict[str, str]:
    builders = {"index": index, "annex_vii": annex_vii, "annex_v": annex_v, "annex_vi": annex_vi,
                "annex_ii": annex_ii}
    return {name: builders[kind](inp) for name, kind in FILES.items()}


def write(folder: Path, docs: dict[str, str], force: bool = False) -> tuple[list[Path], list[Path]]:
    """Write the drafts. Returns (written, kept) paths; existing files are kept unless force."""
    folder.mkdir(parents=True, exist_ok=True)
    written, kept = [], []
    for name, text in docs.items():
        target = folder / name
        if target.exists() and not force:
            kept.append(target)
            continue
        target.write_text(text, encoding="utf-8")
        written.append(target)
    return written, kept


def count_todos(docs: dict[str, str]) -> int:
    return sum(text.count(TODO) for text in docs.values())
