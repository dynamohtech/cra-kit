"""Rebuild the sample outputs in this folder from the test fixtures.

Run from the repository root:  python examples/generate.py
Uses the synthetic OSV/KEV data from tests/conftest.py, so it works offline.
"""

from __future__ import annotations

import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from conftest import FIXTURES, FakeTransport  # noqa: E402

from cra_kit import cra, reporting, techfile, vex  # noqa: E402
from cra_kit.assess import Answers, assess, to_markdown  # noqa: E402
from cra_kit.config import load  # noqa: E402
from cra_kit.sbom import collect  # noqa: E402
from cra_kit.sbom.cyclonedx import build_bom, summarize  # noqa: E402
from cra_kit.scan import scan  # noqa: E402
from cra_kit.scan import to_markdown as scan_md  # noqa: E402

HERE = Path(__file__).resolve().parent
TODAY = date(2026, 9, 30)
NOW = datetime(2026, 9, 30, 15, 0, tzinfo=timezone.utc)


def main() -> None:
    product = load(HERE / "cra-kit.toml")
    components = collect(FIXTURES / "npm-v3").deduplicated()
    bom = build_bom(components, product.name, product.version, product.manufacturer, product.type,
                    timestamp=NOW, serial="urn:uuid:00000000-0000-4000-8000-000000000000")
    result = scan([c.purl for c in components], transport=FakeTransport())

    # A VEX file with one decision of each common kind. Fixed IDs and times keep the output reproducible.
    own = vex.product_id(product.name, product.version)
    vex_doc = vex.new_document(product.manufacturer)
    vex_doc.update({"@id": "urn:uuid:00000000-0000-4000-8000-000000000001", "timestamp": "2026-09-30T13:00:00Z",
                    "last_updated": "2026-09-30T14:00:00Z", "version": 2, "tooling": "cra-kit"})
    vex_doc["statements"] = [
        vex.make_statement("CVE-2099-0003", "not_affected", "pkg:npm/%40babel/core@7.23.0", own,
                           justification="vulnerable_code_not_in_execute_path",
                           impact_statement="@babel/core is only used at build time; it is not shipped in the "
                                            "firmware image.", timestamp="2026-09-30T13:00:00Z"),
        vex.make_statement("CVE-2099-0001", "under_investigation", "pkg:npm/express@4.18.2", own,
                           timestamp="2026-09-30T14:00:00Z"),
    ]
    vex_path = HERE / "cra-kit.vex.json"
    vex_path.write_text(json.dumps(vex_doc, indent=2) + "\n", encoding="utf-8")
    vex.apply(result, vex.load(vex_path), {own})
    result.vex_sources = ["cra-kit.vex.json"]

    answers = Answers(
        scope={"digital_elements": "yes", "data_connection": "yes", "eu_market": "yes",
               "commercial": "yes", "saas_only": "no", "open_source": "no"},
        exclusions={key: "no" for key, _, _ in cra.EXCLUSIONS},
        class_i=[17],  # smart home products with security functionalities, e.g. smart door locks
        requirements={"I.1": "partial", "I.2b": "done", "I.2c": "done", "I.2d": "done", "I.2e": "done",
                      "I.2f": "partial", "I.2g": "done", "I.2h": "partial", "I.2i": "n/a", "I.2j": "partial",
                      "I.2k": "no", "I.2l": "no", "I.2m": "done", "II.2": "partial", "II.3": "partial",
                      "II.4": "no", "II.5": "no", "II.7": "done", "II.8": "done"},
        notes={"I.2c": "Signed OTA updates, automatic by default, opt-out in the app"},
    )
    (HERE / "cra-answers.toml").write_text(answers.dump(), encoding="utf-8")
    assessment = assess(answers, product, summarize(bom), result.to_dict(), today=TODAY)
    (HERE / "readiness-report.md").write_text(to_markdown(assessment, product, TODAY), encoding="utf-8")

    finding = result.to_dict()["findings"][0]
    aware, notes = reporting.parse_when("2026-09-30T11:20+02:00")
    pack = reporting.vulnerability_pack(product, aware, None, finding, notes)
    pack.generated = NOW
    (HERE / "vulnerability-pack.md").write_text(reporting.to_markdown(pack, NOW), encoding="utf-8")

    (HERE / "scan.md").write_text(scan_md(result), encoding="utf-8")
    docs = techfile.build(techfile.Inputs(
        product=product, assessment=assessment, sbom_file="sbom.cdx.json", sbom_summary=summarize(bom),
        scan_file="scan.json", scan_summary=result.to_dict(), vex_file="cra-kit.vex.json",
        security_policy="SECURITY.md", today=TODAY,
    ))
    techfile.write(HERE / "cra-technical-file", docs, force=True)
    print("examples regenerated")


if __name__ == "__main__":
    main()
