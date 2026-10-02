"""Check components against OSV.dev and flag those in CISA's KEV catalogue.

OSV.dev (https://osv.dev) aggregates advisories from GitHub, PyPA, RustSec,
the Go vulnerability database and others. CISA's Known Exploited
Vulnerabilities (KEV) catalogue lists CVEs with evidence of exploitation in
the wild. A KEV match does not prove that *your* product is exploited, but
it is a strong signal to assess now: under Article 14 of the CRA an
actively exploited vulnerability in your product must be reported within
24 hours of becoming aware of it.
"""

from __future__ import annotations

import json
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable

from cra_kit import __version__

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BATCH_SIZE = 500
TIMEOUT = 30

# A transport takes (method, url, json_body_or_None) and returns parsed JSON.
Transport = Callable[[str, str, dict | None], dict]


def http_transport(method: str, url: str, body: dict | None = None) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", "User-Agent": f"cra-kit/{__version__}"},
    )
    with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 (fixed https URLs)
        return json.loads(resp.read().decode("utf-8"))


@dataclass
class Finding:
    purl: str
    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    severity: str = "UNKNOWN"
    cvss: str = ""
    fixed_versions: list[str] = field(default_factory=list)
    known_exploited: bool = False
    kev_date_added: str = ""
    url: str = ""
    vex: dict | None = None  # the VEX decision covering this finding, if any

    @property
    def closed(self) -> bool:
        """True when a VEX statement says the product is not affected or the issue is fixed."""
        return bool(self.vex) and self.vex.get("status") in ("not_affected", "fixed")

    @property
    def cves(self) -> list[str]:
        ids = [self.id] + self.aliases
        return sorted({i for i in ids if i.startswith("CVE-")})


@dataclass
class ScanResult:
    scanned: int
    findings: list[Finding]
    kev_checked: bool
    errors: list[str] = field(default_factory=list)
    vex_sources: list[str] = field(default_factory=list)

    @property
    def open_findings(self) -> list[Finding]:
        """Findings not closed by a VEX statement: these count, and --fail-on acts on them."""
        return [f for f in self.findings if not f.closed]

    @property
    def closed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.closed]

    @property
    def vulnerable_components(self) -> int:
        return len({f.purl for f in self.open_findings})

    @property
    def known_exploited(self) -> list[Finding]:
        return [f for f in self.open_findings if f.known_exploited]

    def to_dict(self) -> dict:
        return {
            "tool": {"name": "cra-kit", "version": __version__},
            "scanned_components": self.scanned,
            "vulnerable_components": self.vulnerable_components,
            "findings": [asdict(f) | {"cves": f.cves, "closed_by_vex": f.closed} for f in self.findings],
            "open_findings_count": len(self.open_findings),
            "known_exploited_count": len(self.known_exploited),
            "closed_by_vex_count": len(self.closed_findings),
            "vex_sources": self.vex_sources,
            "kev_checked": self.kev_checked,
            "errors": self.errors,
        }


def scan(purls: list[str], transport: Transport = http_transport, check_kev: bool = True) -> ScanResult:
    purls = sorted(set(p for p in purls if "@" in p))  # a version is required to match advisories
    hits: dict[str, list[str]] = {}
    errors: list[str] = []
    for start in range(0, len(purls), BATCH_SIZE):
        chunk = purls[start:start + BATCH_SIZE]
        payload = {"queries": [osv_query(p) for p in chunk]}
        response = transport("POST", OSV_BATCH_URL, payload)
        results = response.get("results", [])
        if len(results) != len(chunk):
            # Results are matched to queries by position, so a short answer cannot be trusted.
            raise ValueError(
                f"OSV.dev returned {len(results)} results for {len(chunk)} components; try the scan again"
            )
        for purl, res in zip(chunk, results, strict=True):
            ids = [v["id"] for v in (res or {}).get("vulns", []) or []]
            if res and res.get("next_page_token"):
                errors.append(f"{purl}: more advisories exist than one page returned; results may be incomplete")
            if ids:
                hits[purl] = ids

    details: dict[str, dict] = {}
    for vid in sorted({i for ids in hits.values() for i in ids}):
        try:
            details[vid] = transport("GET", OSV_VULN_URL.format(id=vid), None)
        except Exception as exc:  # keep going; one advisory failing should not hide the rest
            errors.append(f"{vid}: could not fetch details ({exc})")
            details[vid] = {"id": vid}

    findings = [
        _to_finding(purl, details[vid]) for purl, ids in sorted(hits.items()) for vid in ids
    ]

    kev_checked = False
    if check_kev and findings:
        try:
            kev = transport("GET", KEV_URL, None)
            by_cve = {v["cveID"]: v for v in kev.get("vulnerabilities", [])}
            for f in findings:
                match = next((by_cve[c] for c in f.cves if c in by_cve), None)
                if match:
                    f.known_exploited = True
                    f.kev_date_added = match.get("dateAdded", "")
            kev_checked = True
        except Exception as exc:
            errors.append(f"CISA KEV catalogue could not be fetched ({exc}); exploitation status unknown")

    order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda f: (not f.known_exploited, order.get(f.severity, 4), f.purl, f.id))
    return ScanResult(scanned=len(purls), findings=findings, kev_checked=kev_checked, errors=errors)


def osv_query(purl: str) -> dict:
    """OSV.dev query for one component.

    Go modules are queried by ecosystem, module path and version without the
    leading "v" (the form OSV's Go records use, and what osv-scanner sends).
    Everything else is queried by its versioned purl.
    """
    if purl.startswith("pkg:golang/") and "@" in purl:
        from urllib.parse import unquote

        path, _, version = purl[len("pkg:golang/"):].split("?", 1)[0].split("#", 1)[0].rpartition("@")
        return {"package": {"ecosystem": "Go", "name": unquote(path)}, "version": unquote(version).removeprefix("v")}
    return {"package": {"purl": purl}}


def _advisory_link(f: Finding) -> str:
    text = cell(f.id) + (f" ({cell(', '.join(f.cves))})" if f.cves and f.cves != [f.id] else "")
    if f.id and all(c.isalnum() or c in "-_.:" for c in f.id):
        return f"[{cell(f.id)}](https://osv.dev/vulnerability/{f.id})" + text[len(cell(f.id)):]
    return text


def purl_key(purl: str) -> tuple[str, str]:
    """('npm', '@scope/name') style identity of a purl, ignoring version and qualifiers."""
    from urllib.parse import unquote

    from cra_kit.model import normalize_pypi_name

    body = purl.split(":", 1)[1] if purl.startswith("pkg:") else purl
    body = body.split("?", 1)[0].split("#", 1)[0]
    head, _, tail = body.rpartition("/")
    tail = tail.split("@", 1)[0]
    ptype, _, namespace = head.partition("/")
    name = unquote(f"{namespace}/{tail}" if namespace else tail)
    if ptype == "pypi":
        name = normalize_pypi_name(name)
    return ptype.lower(), name.lower()


def _to_finding(purl: str, vuln: dict) -> Finding:
    vid = vuln.get("id", "")
    severity = str((vuln.get("database_specific") or {}).get("severity") or "").upper() or "UNKNOWN"
    cvss = next((s.get("score", "") for s in vuln.get("severity", []) or [] if s.get("type", "").startswith("CVSS")), "")
    ptype, pname = purl_key(purl)
    fixed: list[str] = []
    for aff in vuln.get("affected", []) or []:
        pkg = aff.get("package", {})
        aff_purl = pkg.get("purl", "")
        if aff_purl:
            same = purl_key(aff_purl) == (ptype, pname)
        else:
            same = purl_key(f"pkg:{ptype}/{pkg.get('name', '')}") == (ptype, pname)
        if not same:
            continue
        for rng in aff.get("ranges", []) or []:
            for event in rng.get("events", []) or []:
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return Finding(
        purl=purl,
        id=vid,
        aliases=sorted(vuln.get("aliases", []) or []),
        summary=(vuln.get("summary") or vuln.get("details", "")[:160]).strip(),
        severity=severity,
        cvss=cvss,
        fixed_versions=sorted(set(fixed)),
        url=f"https://osv.dev/vulnerability/{vid}" if vid else "",
    )


def cell(text: object) -> str:
    """Make outside data safe inside a Markdown table cell (advisory text and VEX statements
    come from third parties): one line, no table breaks, no raw HTML."""
    out = " ".join(str(text).split())
    out = out.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    out = out.replace("\\", "\\\\")  # backslashes first, so the escapes below stay intact
    for ch in "|[]":
        out = out.replace(ch, "\\" + ch)
    return out


def code(text: object) -> str:
    """Inline code span for identifiers such as purls."""
    return "`" + " ".join(str(text).split()).replace("`", "'") + "`"


def to_markdown(result: ScanResult) -> str:
    lines = ["# Vulnerability scan", ""]
    open_findings = result.open_findings
    lines.append(
        f"Scanned **{result.scanned}** components: **{result.vulnerable_components}** have known vulnerabilities "
        f"({len(open_findings)} open advisories)."
    )
    if result.closed_findings:
        lines.append(
            f"**{len(result.closed_findings)}** more advisories are closed by VEX statements "
            f"({cell(', '.join(result.vex_sources))}) and listed separately below."
        )
    if result.kev_checked:
        n = len(result.known_exploited)
        lines.append(
            f"**{n}** advisories are in CISA's Known Exploited Vulnerabilities catalogue."
            + (" Assess these first: if the vulnerability is actively exploited in your product, "
               "CRA Article 14 requires an early warning within 24 hours of becoming aware of it." if n else "")
        )
    lines += ["", "| Component | Advisory | Severity | Exploited (KEV) | Fixed in | Summary |",
              "| --- | --- | --- | --- | --- | --- |"]
    for f in open_findings:
        kev = f"Yes, since {cell(f.kev_date_added)}" if f.known_exploited else (
            "No" if result.kev_checked else "Not checked")
        summary = cell(f.summary)
        if f.vex:
            summary += f" (VEX: {cell(f.vex['status'].replace('_', ' '))})"
        lines.append(
            f"| {code(f.purl)} | {_advisory_link(f)} | {cell(f.severity)} | {kev} "
            f"| {cell(', '.join(f.fixed_versions)) or 'none listed'} | {summary} |"
        )
    if not open_findings:
        lines.append("| — | No open vulnerabilities | | | | |")
    if result.closed_findings:
        lines += ["", "## Closed by VEX", "",
                  "| Component | Advisory | Status | Justification or statement | Decided |",
                  "| --- | --- | --- | --- | --- |"]
        for f in result.closed_findings:
            why = f.vex.get("justification") or f.vex.get("impact_statement") or f.vex.get("action_statement") or ""
            lines.append(
                f"| {code(f.purl)} | {_advisory_link(f)} | {cell(f.vex['status'].replace('_', ' '))} "
                f"| {cell(why)} | {cell(f.vex.get('timestamp', '')[:10])} |"
            )
    if result.errors:
        lines += ["", "## Warnings", ""] + [f"- {cell(e)}" for e in result.errors]
    lines += ["", "_Sources: OSV.dev and CISA KEV. A listed advisory affects the component version; "
              "whether it is exploitable in your product needs your own assessment._", ""]
    return "\n".join(lines)
