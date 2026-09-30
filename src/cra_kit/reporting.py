"""Article 14 reporting packs: the deadlines and the content each report needs.

Under Article 14 of the CRA (applies from 11 September 2026) a manufacturer
reports actively exploited vulnerabilities and severe incidents in its
product through the single reporting platform, to the CSIRT designated as
coordinator and to ENISA at the same time:

* an early warning within 24 hours of becoming aware,
* a notification within 72 hours of becoming aware,
* a final report: for a vulnerability no later than 14 days after a
  corrective or mitigating measure is available; for an incident within one
  month after the incident notification.

It must also inform impacted users (Article 14(8)).

Deadlines are calculated conservatively (the earliest reading, no extension
for weekends or public holidays). Times without a time zone are taken as UTC.
"""

from __future__ import annotations

import calendar
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from cra_kit import __version__, cra
from cra_kit.config import Product

VULNERABILITY = "vulnerability"
INCIDENT = "incident"
# Label suffix for context that helps the CSIRT but that Article 14 does not require at that stage.
OPTIONAL = "(optional context)"


# ---------------------------------------------------------------------------
# Time handling
# ---------------------------------------------------------------------------


def parse_when(text: str, now: datetime | None = None) -> tuple[datetime, list[str]]:
    """Parse 'now' or an ISO 8601 date/time into a UTC datetime.

    Returns the datetime and any assumptions made, so the pack can state them.
    """
    raw = text.strip()
    if raw.lower() == "now":
        return (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(microsecond=0), []
    try:
        value = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"'{text}' is not an ISO 8601 date or time, e.g. 2026-09-30T14:05+02:00") from exc
    notes = []
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
        if len(raw) == 10:  # a date only
            notes.append(f"'{raw}' has no time or time zone: taken as 00:00 UTC, the earliest (most cautious) reading")
        else:
            notes.append(f"'{raw}' has no time zone: taken as UTC")
    return value.astimezone(timezone.utc), notes


def add_months(value: datetime, months: int = 1) -> datetime:
    """Same day number N months later; the month's last day if it has no such day."""
    index = value.month - 1 + months
    year, month = value.year + index // 12, index % 12 + 1
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def fmt(value: datetime | None) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if value else "Not yet known"


def time_left(due: datetime | None, now: datetime) -> str:
    if due is None:
        return ""
    seconds = int((due - now).total_seconds())
    span = abs(seconds)
    days, rem = divmod(span, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    text = (f"{days}d " if days else "") + f"{hours}h {minutes:02d}m"
    return f"{text} left" if seconds >= 0 else f"OVERDUE by {text}"


# ---------------------------------------------------------------------------
# Pack model
# ---------------------------------------------------------------------------


@dataclass
class Stage:
    key: str
    title: str
    basis: str
    due: datetime | None
    due_note: str
    fields: list[tuple[str, str]]  # (field label, prefilled value or ""); labels ending OPTIONAL are not required


@dataclass
class Pack:
    kind: str
    product: Product
    aware: datetime
    stages: list[Stage]
    notes: list[str] = field(default_factory=list)
    finding: dict | None = None
    generated: datetime = field(default_factory=lambda: datetime.now(timezone.utc).replace(microsecond=0))

    def to_dict(self, now: datetime | None = None) -> dict:
        now = now or self.generated
        return {
            "tool": {"name": "cra-kit", "version": __version__},
            "kind": self.kind,
            "regulation": cra.REGULATION_URL,
            "product": {
                "name": self.product.name,
                "version": self.product.version,
                "manufacturer": self.product.manufacturer,
                "member_states": self.product.member_states,
                "main_establishment": self.product.main_establishment,
            },
            "aware_at": _iso(self.aware),
            "generated_at": _iso(self.generated),
            "stages": [
                {
                    "key": s.key,
                    "title": s.title,
                    "legal_basis": s.basis,
                    "due": _iso(s.due) if s.due else None,
                    "due_note": s.due_note,
                    "time_left": time_left(s.due, now) or None,
                    "fields": [{"field": label, "value": value} for label, value in s.fields],
                }
                for s in self.stages
            ],
            "notes": self.notes,
            "finding": self.finding,
        }


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _common(product: Product, aware: datetime) -> list[tuple[str, str]]:
    states = ", ".join(product.member_states)
    return [
        ("Product concerned (name and version)", f"{product.name} {product.version}".strip()),
        ("Manufacturer", product.manufacturer),
        ("Time the manufacturer became aware", fmt(aware)),
        ("Member States where you know the product has been made available", states),
    ]


def _route(product: Product) -> str:
    coordinator = (
        f"the CSIRT designated as coordinator in {product.main_establishment} (your main establishment)"
        if product.main_establishment
        else "the CSIRT designated as coordinator in the Member State of your main establishment: where your "
             "cybersecurity decisions are predominantly taken (set main_establishment in cra-kit.toml)"
    )
    return (
        f"Submit each report through the single reporting platform (Article 16) to {coordinator} "
        "and, at the same time, to ENISA (Article 14(1) and 14(3)). With no main establishment in the EU, "
        "Article 14(7) uses, in order, the Member State of your authorised representative, importer or "
        "distributor, or the one with the most users."
    )


def _finding_fields(finding: dict | None) -> dict[str, str]:
    if not finding:
        return {}
    ids = [finding.get("id", "")] + [c for c in finding.get("cves", []) if c != finding.get("id")]
    severity = finding.get("severity", "")
    if finding.get("cvss"):
        severity = f"{severity} ({finding['cvss']})" if severity else finding["cvss"]
    fixed = ", ".join(finding.get("fixed_versions", []))
    return {
        "id": ", ".join(i for i in ids if i),
        "component": finding.get("purl", ""),
        "summary": finding.get("summary", ""),
        "severity": severity,
        "fixed": f"Upgrade {finding.get('purl', 'the component')} to {fixed}" if fixed else "",
        "kev": (f"Listed in CISA's Known Exploited Vulnerabilities catalogue since {finding.get('kev_date_added')} "
                "(exploited in the wild; confirm how it is exploited in your product)"
                if finding.get("known_exploited") else ""),
        "url": finding.get("url", ""),
    }


def vulnerability_pack(
    product: Product,
    aware: datetime,
    fix_available: datetime | None = None,
    finding: dict | None = None,
    notes: list[str] | None = None,
) -> Pack:
    f = _finding_fields(finding)
    early = aware + timedelta(hours=24)
    notification = aware + timedelta(hours=72)
    if fix_available:
        final, final_note = fix_available + timedelta(days=14), (
            f"14 days after the corrective or mitigating measure became available ({fmt(fix_available)})"
        )
    else:
        final, final_note = None, (
            "No later than 14 days after a corrective or mitigating measure is available. "
            "Re-run with --fix-available when it is."
        )
    stages = [
        Stage("early_warning", "Early warning", "Article 14(2)(a)", early, "24 hours after becoming aware",
              _common(product, aware) + [
                  (f"Vulnerability identifier (CVE or advisory ID) {OPTIONAL}", f.get("id", "")),
                  (f"Affected third-party component {OPTIONAL}", f.get("component", "")),
                  (f"Short description of the actively exploited vulnerability {OPTIONAL}", f.get("summary", "")),
                  (f"Evidence of active exploitation {OPTIONAL}", f.get("kev", "")),
              ]),
        Stage("notification", "Vulnerability notification", "Article 14(2)(b)", notification,
              "72 hours after becoming aware (unless already provided in the early warning)", [
                  ("General information about the product concerned", ""),
                  ("General nature of the exploit", ""),
                  ("General nature of the vulnerability", f.get("summary", "")),
                  ("Corrective or mitigating measures taken", ""),
                  ("Corrective or mitigating measures users can take", f.get("fixed", "")),
                  ("How sensitive you consider the notified information to be", ""),
              ]),
        Stage("final_report", "Final report", "Article 14(2)(c)", final, final_note, [
            ("Description of the vulnerability, including its severity and impact",
             "; ".join(x for x in (f.get("summary", ""), f"Severity: {f['severity']}" if f.get("severity") else "") if x)),
            ("Information about any malicious actor that has exploited or is exploiting it, where available", ""),
            ("Details about the security update or other corrective measures made available", f.get("fixed", "")),
        ]),
        _user_stage(VULNERABILITY, f),
    ]
    all_notes = list(notes or [])
    all_notes.append(_route(product))
    if f.get("component"):
        all_notes.append(
            "The vulnerability is in an integrated component: Article 13(6) also requires you to report it to "
            "the person or entity that manufactures or maintains that component."
        )
    return Pack(VULNERABILITY, product, aware, stages, all_notes, finding)


def incident_pack(
    product: Product,
    aware: datetime,
    notified: datetime | None = None,
    notes: list[str] | None = None,
) -> Pack:
    early = aware + timedelta(hours=24)
    notification = aware + timedelta(hours=72)
    if notified:
        final, final_note = add_months(notified), (
            f"One month after the incident notification was submitted ({fmt(notified)})"
        )
    else:
        final, final_note = add_months(notification), (
            "One month after the incident notification is submitted. Shown from the latest allowed notification "
            "time; re-run with --notified once you submit it, which brings this date forward if you notify early."
        )
    stages = [
        Stage("early_warning", "Early warning", "Article 14(4)(a)", early, "24 hours after becoming aware",
              _common(product, aware) + [
                  ("Is the incident suspected of being caused by unlawful or malicious acts?", ""),
                  (f"Short description of the incident {OPTIONAL}", ""),
              ]),
        Stage("notification", "Incident notification", "Article 14(4)(b)", notification,
              "72 hours after becoming aware (unless already provided in the early warning)", [
                  ("General information about the nature of the incident", ""),
                  ("Initial assessment of the incident", ""),
                  ("Corrective or mitigating measures taken", ""),
                  ("Corrective or mitigating measures users can take", ""),
                  ("How sensitive you consider the notified information to be", ""),
              ]),
        Stage("final_report", "Final report", "Article 14(4)(c)", final, final_note, [
            ("Detailed description of the incident, including its severity and impact", ""),
            ("Type of threat or root cause that is likely to have triggered the incident", ""),
            ("Applied and ongoing mitigation measures", ""),
        ]),
        _user_stage(INCIDENT, {}),
    ]
    all_notes = list(notes or [])
    all_notes.append(
        "An incident is severe, and so reportable, if it (a) negatively affects or is capable of negatively affecting "
        "the product's ability to protect the availability, authenticity, integrity or confidentiality of sensitive "
        "or important data or functions, or (b) has led or is capable of leading to the introduction or execution "
        "of malicious code in the product or in the network and information systems of a user (Article 14(5))."
    )
    all_notes.append(_route(product))
    return Pack(INCIDENT, product, aware, stages, all_notes, None)


def _user_stage(kind: str, f: dict[str, str]) -> Stage:
    what = "vulnerability" if kind == VULNERABILITY else "incident"
    return Stage(
        "user_information", "Inform impacted users", "Article 14(8)", None,
        "After becoming aware, in a timely manner. If you do not, the CSIRT may inform users itself.",
        [
            ("Impacted users to inform (and whether to inform all users)", ""),
            (f"Description of the {what}", f.get("summary", "")),
            ("Risk mitigation and corrective measures users can deploy", f.get("fixed", "")),
            ("Channel and format (structured and machine-readable where appropriate, e.g. a CSAF advisory)", ""),
        ],
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def to_markdown(pack: Pack, now: datetime | None = None) -> str:
    now = now or pack.generated
    subject = "actively exploited vulnerability" if pack.kind == VULNERABILITY else "severe incident"
    p = pack.product
    lines = [
        f"# CRA Article 14 reporting pack: {subject}",
        "",
        f"Product: **{p.name} {p.version}**" + (f", manufacturer **{p.manufacturer}**" if p.manufacturer else ""),
        f"Became aware: **{fmt(pack.aware)}**. Pack generated {fmt(pack.generated)} by cra-kit {__version__}.",
        "",
        "> Draft working document. Nothing has been submitted. Check every field before you report, and get legal "
        "advice where you are unsure. This is not legal advice.",
        "",
        "## Deadlines",
        "",
        "| Report | Due | Time left | Legal basis | Rule |",
        "| --- | --- | --- | --- | --- |",
    ]
    for s in pack.stages:
        lines.append(f"| {s.title} | {fmt(s.due) if s.due else '—'} | {time_left(s.due, now) or '—'} "
                     f"| {s.basis} | {s.due_note} |")
    lines += ["", "Deadlines are the earliest reading of the rule, with no extension for weekends or public holidays.", ""]
    if pack.notes:
        lines += ["## Before you submit", ""] + [f"- {n}" for n in pack.notes] + [""]
    for s in pack.stages:
        due = f"due {fmt(s.due)}" if s.due else s.due_note
        lines += [f"## {s.title} ({s.basis}, {due})", ""]
        for label, value in s.fields:
            lines += [f"**{label}**", "", value if value else "_To complete_", ""]
    if pack.finding and pack.finding.get("url"):
        lines += ["## Source advisory", "", pack.finding["url"], ""]
    lines += [f"Regulation text: {cra.REGULATION_URL}", ""]
    return "\n".join(lines)


def summary_lines(pack: Pack, now: datetime | None = None) -> list[str]:
    """Short deadline list for the terminal."""
    now = now or pack.generated
    out = []
    for s in pack.stages:
        if s.due:
            out.append(f"  {s.title:<28} {fmt(s.due)}   {time_left(s.due, now)}")
        else:
            out.append(f"  {s.title:<28} {s.due_note.split('.')[0]}")
    return out
