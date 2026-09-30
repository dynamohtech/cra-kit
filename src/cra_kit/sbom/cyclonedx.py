"""Write and read CycloneDX 1.6 JSON SBOMs."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from cra_kit import __version__
from cra_kit.model import Component

SPEC_VERSION = "1.6"
PRODUCT_REF = "product"


def build_bom(
    components: list[Component],
    product_name: str,
    product_version: str,
    manufacturer: str | None = None,
    product_type: str = "application",
    timestamp: datetime | None = None,
    serial: str | None = None,
) -> dict:
    """Build a CycloneDX 1.6 document for one product and its components."""
    ts = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
    product: dict = {
        "type": product_type,
        "bom-ref": PRODUCT_REF,
        "name": product_name,
        "version": product_version,
    }
    metadata: dict = {
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "tools": {
            "components": [
                {
                    "type": "application",
                    "name": "cra-kit",
                    "version": __version__,
                    "externalReferences": [
                        {"type": "vcs", "url": "https://github.com/dynamohtech/cra-kit"}
                    ],
                }
            ]
        },
        "component": product,
    }
    if manufacturer:
        metadata["manufacturer"] = {"name": manufacturer}
        product["manufacturer"] = {"name": manufacturer}

    bom_components = []
    for comp in components:
        bom_components.append(
            {
                "type": "library",
                "bom-ref": comp.purl,
                "name": comp.name,
                "version": comp.version,
                "purl": comp.purl,
                "scope": "required",
                "properties": [
                    {"name": "cra-kit:dependency-relationship", "value": comp.relationship},
                    {"name": "cra-kit:ecosystem", "value": comp.ecosystem},
                ],
            }
        )

    direct_refs = sorted({c.purl for c in components if c.direct})
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": metadata,
        "components": bom_components,
        "dependencies": [{"ref": PRODUCT_REF, "dependsOn": direct_refs}],
    }


def write_bom(bom: dict, path: Path) -> None:
    path.write_text(json.dumps(bom, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def read_purls(path: Path) -> list[str]:
    """Return every component purl in a CycloneDX JSON file (any tool's output)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{path} is not a CycloneDX JSON SBOM")
    purls: list[str] = []

    def walk(items: list[dict]) -> None:
        for item in items or []:
            if item.get("purl"):
                purls.append(item["purl"])
            walk(item.get("components", []))

    walk(data.get("components", []))
    return sorted(set(purls))


def summarize(bom: dict) -> dict:
    """Counts used by the readiness report.

    Uses cra-kit's own relationship property when present; for SBOMs made by
    other tools, falls back to the dependency graph of the main component.
    """
    root_ref = (bom.get("metadata", {}).get("component") or {}).get("bom-ref")
    root_deps = next(
        (set(d.get("dependsOn", [])) for d in bom.get("dependencies", []) or [] if root_ref and d.get("ref") == root_ref),
        set(),
    )

    def relationship(comp: dict) -> str:
        for prop in comp.get("properties", []) or []:
            if prop.get("name") == "cra-kit:dependency-relationship":
                return prop.get("value", "unknown")
        if root_deps:
            return "direct" if comp.get("bom-ref") in root_deps else "transitive"
        return "unknown"

    rels = [relationship(c) for c in bom.get("components", [])]
    return {
        "components": len(rels),
        "direct": rels.count("direct"),
        "transitive": rels.count("transitive"),
        "unknown": rels.count("unknown"),
        "spec_version": bom.get("specVersion"),
        "timestamp": bom.get("metadata", {}).get("timestamp"),
    }
