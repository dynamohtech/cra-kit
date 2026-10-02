"""VEX: record whether a known vulnerability actually affects your product.

A dependency scan lists every advisory for every component version, but many
do not affect the product: the vulnerable function is never called, the
feature is disabled, and so on. VEX (Vulnerability Exploitability eXchange)
records that decision in a machine-readable way, so scans stop flagging it
and auditors can see who decided what, when and why.

cra-kit writes OpenVEX (https://openvex.dev, v0.2.0) and reads both OpenVEX
and the VEX data in CycloneDX documents (``vulnerabilities[].analysis``).
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, unquote

from cra_kit import __version__
from cra_kit.scan import purl_key

OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
DEFAULT_FILE = "cra-kit.vex.json"
STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
JUSTIFICATIONS = (
    "component_not_present",
    "vulnerable_code_not_present",
    "vulnerable_code_not_in_execute_path",
    "vulnerable_code_cannot_be_controlled_by_adversary",
    "inline_mitigations_already_exist",
)
# Statuses that close a finding: it is no longer counted or failed on, but stays listed.
CLOSING = {"not_affected", "fixed"}
# CycloneDX analysis.state -> VEX status.
CYCLONEDX_STATE = {
    "not_affected": "not_affected",
    "false_positive": "not_affected",
    "resolved": "fixed",
    "resolved_with_pedigree": "fixed",
    "exploitable": "affected",
    "in_triage": "under_investigation",
}


@dataclass
class Statement:
    vulnerability: str
    status: str
    aliases: list[str] = field(default_factory=list)
    products: list[str] = field(default_factory=list)  # product @ids
    subcomponents: list[str] = field(default_factory=list)  # component @ids (usually purls)
    justification: str = ""
    impact_statement: str = ""
    action_statement: str = ""
    timestamp: str = ""
    source: str = ""
    order: int = 0

    @property
    def ids(self) -> set[str]:
        return {i.upper() for i in [self.vulnerability, *self.aliases] if i}

    def summary(self) -> dict:
        return {
            "status": self.status,
            "justification": self.justification,
            "impact_statement": self.impact_statement,
            "action_statement": self.action_statement,
            "timestamp": self.timestamp,
            "source": self.source,
        }


def product_id(name: str, version: str) -> str:
    """The identifier cra-kit uses for your own product in VEX documents."""
    return f"pkg:generic/{quote(name, safe='._-~')}@{quote(version, safe='._-~')}"


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------


def load(path: Path) -> list[Statement]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "statements" in data and "openvex" in str(data.get("@context", "")):
        return _from_openvex(data, str(path))
    if isinstance(data, dict) and data.get("bomFormat") == "CycloneDX":
        return _from_cyclonedx(data, str(path))
    raise ValueError(f"{path} is neither an OpenVEX document nor a CycloneDX document with VEX data")


def _ids(item: object) -> list[str]:
    if isinstance(item, str):
        return [item]
    if not isinstance(item, dict):
        return []
    out = [item["@id"]] if item.get("@id") else []
    identifiers = item.get("identifiers") or {}
    out += [v for k, v in identifiers.items() if k in ("purl", "cpe23", "cpe22") and v]
    return out


def _from_openvex(data: dict, source: str) -> list[Statement]:
    doc_time = str(data.get("timestamp") or "")
    out = []
    for order, st in enumerate(data.get("statements") or []):
        vuln = st.get("vulnerability") or {}
        if isinstance(vuln, str):  # OpenVEX v0.0.x
            name, aliases = vuln, []
        else:
            name, aliases = vuln.get("name") or vuln.get("@id") or "", list(vuln.get("aliases") or [])
        products, subs = [], []
        for product in st.get("products") or []:
            products += _ids(product)
            for sub in (product.get("subcomponents") or []) if isinstance(product, dict) else []:
                subs += _ids(sub)
        subs += [i for sub in st.get("subcomponents") or [] for i in _ids(sub)]  # v0.0.x top-level field
        out.append(Statement(
            vulnerability=name,
            status=str(st.get("status") or ""),
            aliases=aliases,
            products=products,
            subcomponents=subs,
            justification=str(st.get("justification") or ""),
            impact_statement=str(st.get("impact_statement") or ""),
            action_statement=str(st.get("action_statement") or ""),
            timestamp=str(st.get("timestamp") or st.get("last_updated") or doc_time),
            source=source,
            order=order,
        ))
    return out


def _from_cyclonedx(data: dict, source: str) -> list[Statement]:
    refs: dict[str, str] = {}

    def walk(items: list[dict]) -> None:
        for comp in items or []:
            if comp.get("bom-ref"):
                refs[comp["bom-ref"]] = comp.get("purl") or comp["bom-ref"]
            walk(comp.get("components", []))

    walk(data.get("components", []))
    meta = (data.get("metadata") or {}).get("component") or {}
    if meta.get("bom-ref"):
        refs[meta["bom-ref"]] = meta.get("purl") or meta["bom-ref"]
    doc_time = str((data.get("metadata") or {}).get("timestamp") or "")
    out = []
    for order, vuln in enumerate(data.get("vulnerabilities") or []):
        analysis = vuln.get("analysis") or {}
        status = CYCLONEDX_STATE.get(str(analysis.get("state") or ""))
        if not status:
            continue
        subjects = []
        for affect in vuln.get("affects") or []:
            ref = str(affect.get("ref") or "")
            if ref.startswith("urn:cdx:") and "#" in ref:
                ref = ref.split("#", 1)[1]
            subject = refs.get(ref, ref)
            versions = affect.get("versions") or []
            if not versions:
                subjects.append(subject)
                continue
            # Only exact versions not marked "affected" are covered; ranges are not evaluated.
            base = subject.split("?", 1)[0].split("#", 1)[0]
            if base.startswith("pkg:") and _purl_version(base) is not None:
                base = base.rsplit("@", 1)[0]
            for entry in versions:
                if entry.get("version") and entry.get("status") != "affected":
                    subjects.append(f"{base}@{entry['version']}")
        out.append(Statement(
            vulnerability=str(vuln.get("id") or ""),
            status=status,
            aliases=[r.get("id", "") for r in vuln.get("references") or [] if r.get("id")],
            subcomponents=subjects,
            justification=str(analysis.get("justification") or ""),
            impact_statement=str(analysis.get("detail") or ""),
            action_statement="; ".join(analysis.get("response") or []),
            timestamp=str(analysis.get("lastUpdated") or vuln.get("updated") or doc_time),
            source=source,
            order=order,
        ))
    return out


# ---------------------------------------------------------------------------
# Matching findings
# ---------------------------------------------------------------------------


def _purl_version(purl: str) -> str | None:
    body = purl.split("?", 1)[0].split("#", 1)[0]
    _, at, version = body.rpartition("@")
    return version if at and "/" not in version else None


def _normal_version(purl: str, version: str | None) -> str | None:
    if version is None:
        return None
    version = unquote(version)  # "1.0.0+build" and "1.0.0%2Bbuild" are the same version
    if purl[4:].lower().startswith("golang/"):
        version = version.removeprefix("v")  # Go modules are written with and without the "v"
    return version


def purl_matches(statement_id: str, purl: str) -> bool:
    """True when a VEX subject names this component (a versionless purl matches every version)."""
    if not statement_id[:4].lower() == "pkg:":
        return statement_id == purl
    statement_id = "pkg:" + statement_id[4:]
    if purl_key(statement_id) != purl_key(purl):
        return False
    wanted = _normal_version(statement_id, _purl_version(statement_id))
    return wanted is None or wanted == _normal_version(purl, _purl_version(purl))


def _when(timestamp: str) -> datetime:
    """Statement time for ordering; unparseable or missing times sort first."""
    try:
        value = datetime.fromisoformat(timestamp.strip())
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def find(statements: list[Statement], ids: set[str], purl: str, own_product_ids: set[str] = frozenset()) -> Statement | None:
    """The latest statement that covers this vulnerability in this component, if any."""
    wanted = {i.upper() for i in ids}
    matches = []
    for st in statements:
        if not (st.ids & wanted):
            continue
        if any(purl_matches(s, purl) for s in st.subcomponents + st.products):
            matches.append(st)
        elif not st.subcomponents and (not st.products or set(st.products) & set(own_product_ids)):
            matches.append(st)  # a statement about the whole product covers every component
    if not matches:
        return None
    return max(matches, key=lambda s: (_when(s.timestamp), s.order))


def apply(result, statements: list[Statement], own_product_ids: set[str] = frozenset()) -> int:
    """Annotate scan findings with their VEX decision. Returns how many were closed."""
    closed = 0
    for finding in result.findings:
        match = find(statements, {finding.id, *finding.aliases}, finding.purl, own_product_ids)
        if match:
            finding.vex = match.summary()
            closed += match.status in CLOSING
    result.vex_sources = sorted({s.source for s in statements})
    return closed


# ---------------------------------------------------------------------------
# Writing (OpenVEX)
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def new_document(author: str) -> dict:
    now = _now()
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": author or "Unknown author",
        "role": "Manufacturer",
        "timestamp": now,
        "last_updated": now,
        "version": 1,
        "tooling": f"cra-kit/{__version__}",
        "statements": [],
    }


def make_statement(
    vulnerability: str,
    status: str,
    component: str | None,
    product: str | None,
    justification: str = "",
    impact_statement: str = "",
    action_statement: str = "",
    timestamp: str | None = None,
) -> dict:
    if status not in STATUSES:
        raise ValueError(f"status must be one of: {', '.join(STATUSES)}")
    if justification and justification not in JUSTIFICATIONS:
        raise ValueError(f"justification must be one of: {', '.join(JUSTIFICATIONS)}")
    if status == "not_affected" and not (justification or impact_statement):
        raise ValueError("a not_affected statement needs --justification or --impact (OpenVEX requires one)")
    if status == "affected" and not action_statement:
        raise ValueError("an affected statement needs --action describing the remediation (OpenVEX requires it)")
    if component and not component.startswith("pkg:"):
        raise ValueError("--component must be a package URL (purl), e.g. pkg:npm/express@4.18.2")
    if not product and not component:
        raise ValueError("a statement needs a product (set name and version in cra-kit.toml) or a --component")
    entry: dict = {"@id": product or component}
    if product and component:
        entry["subcomponents"] = [{"@id": component}]
    statement: dict = {
        "vulnerability": {"name": vulnerability},
        "timestamp": timestamp or _now(),
        "products": [entry],
        "status": status,
    }
    for key, value in (("justification", justification), ("impact_statement", impact_statement),
                       ("action_statement", action_statement)):
        if value:
            statement[key] = value
    return statement


def add(path: Path, statement: dict, author: str) -> dict:
    """Append a statement to an OpenVEX file, creating it if needed."""
    if path.exists():
        doc = json.loads(path.read_text(encoding="utf-8"))
        if "openvex" not in str(doc.get("@context", "")):
            raise ValueError(f"{path} is not an OpenVEX document; cra-kit only appends to OpenVEX files")
        doc["version"] = int(doc.get("version", 1)) + 1
        doc["last_updated"] = statement["timestamp"]
    else:
        doc = new_document(author)
    doc.setdefault("statements", []).append(statement)
    path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return doc


def as_rows(statements: list[Statement]) -> list[dict]:
    return [asdict(s) for s in statements]
