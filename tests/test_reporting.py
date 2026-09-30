from __future__ import annotations

from datetime import datetime, timezone

import pytest

from cra_kit.config import Product
from cra_kit.reporting import (
    add_months, incident_pack, parse_when, summary_lines, time_left, to_markdown, vulnerability_pack,
)

UTC = timezone.utc
PRODUCT = Product(name="Router X", version="3.1", manufacturer="Example BV",
                  member_states=["NL", "DE"], main_establishment="NL")


def dt(*args) -> datetime:
    return datetime(*args, tzinfo=UTC)


def stage(pack, key):
    return next(s for s in pack.stages if s.key == key)


@pytest.mark.parametrize(
    ("text", "expected", "note"),
    [
        ("2026-10-01T12:00+02:00", dt(2026, 10, 1, 10, 0), None),
        ("2026-10-01T12:00Z", dt(2026, 10, 1, 12, 0), None),
        ("2026-10-01T12:00", dt(2026, 10, 1, 12, 0), "no time zone"),
        ("2026-10-01", dt(2026, 10, 1, 0, 0), "00:00 UTC"),
    ],
)
def test_parse_when(text, expected, note):
    value, notes = parse_when(text)
    assert value == expected
    assert (note in notes[0]) if note else notes == []


def test_parse_when_now_and_bad_input():
    now = dt(2026, 9, 30, 8, 15, 30)
    assert parse_when("now", now) == (now, [])
    with pytest.raises(ValueError):
        parse_when("yesterday")


@pytest.mark.parametrize(
    ("start", "end"),
    [
        (dt(2026, 10, 4, 9), dt(2026, 11, 4, 9)),
        (dt(2027, 1, 31, 9), dt(2027, 2, 28, 9)),
        (dt(2028, 1, 31, 9), dt(2028, 2, 29, 9)),  # leap year
        (dt(2026, 12, 15, 9), dt(2027, 1, 15, 9)),
        (dt(2026, 8, 31, 9), dt(2026, 9, 30, 9)),
    ],
)
def test_add_months(start, end):
    assert add_months(start) == end


def test_vulnerability_deadlines():
    aware = dt(2026, 10, 1, 10, 0)
    pack = vulnerability_pack(PRODUCT, aware, fix_available=dt(2026, 10, 10, 16, 0))
    assert stage(pack, "early_warning").due == dt(2026, 10, 2, 10, 0)
    assert stage(pack, "notification").due == dt(2026, 10, 4, 10, 0)
    assert stage(pack, "final_report").due == dt(2026, 10, 24, 16, 0)
    assert stage(pack, "user_information").due is None


def test_vulnerability_final_unknown_without_fix():
    pack = vulnerability_pack(PRODUCT, dt(2026, 10, 1, 10, 0))
    final = stage(pack, "final_report")
    assert final.due is None
    assert "--fix-available" in final.due_note


def test_incident_deadlines():
    aware = dt(2027, 1, 28, 9, 0)
    pack = incident_pack(PRODUCT, aware, notified=dt(2027, 1, 31, 9, 0))
    assert stage(pack, "final_report").due == dt(2027, 2, 28, 9, 0)
    fallback = incident_pack(PRODUCT, aware)
    assert stage(fallback, "final_report").due == dt(2027, 2, 28, 9, 0)  # from the 72h deadline (31 Jan)
    assert "--notified" in stage(fallback, "final_report").due_note


def test_prefill_from_config_and_finding():
    finding = {
        "purl": "pkg:npm/express@4.18.2", "id": "GHSA-test-kev1-0001", "aliases": ["CVE-2099-0001"],
        "cves": ["CVE-2099-0001"], "summary": "Synthetic open redirect", "severity": "HIGH",
        "cvss": "CVSS:3.1/AV:N", "fixed_versions": ["4.19.2"], "known_exploited": True,
        "kev_date_added": "2026-09-15", "url": "https://osv.dev/vulnerability/GHSA-test-kev1-0001",
    }
    pack = vulnerability_pack(PRODUCT, dt(2026, 10, 1, 10, 0), finding=finding)
    early = dict(stage(pack, "early_warning").fields)
    assert early["Member States where you know the product has been made available"] == "NL, DE"
    assert early["Vulnerability identifier (CVE or advisory ID) (optional context)"] == "GHSA-test-kev1-0001, CVE-2099-0001"
    assert "2026-09-15" in early["Evidence of active exploitation (optional context)"]
    final = dict(stage(pack, "final_report").fields)
    assert "Severity: HIGH (CVSS:3.1/AV:N)" in final["Description of the vulnerability, including its severity and impact"]
    assert "4.19.2" in final["Details about the security update or other corrective measures made available"]
    notes = " ".join(pack.notes)
    assert "in NL" in notes and "ENISA" in notes and "Article 13(6)" in notes


def test_markdown_and_json():
    now = dt(2026, 10, 1, 20, 30)
    pack = incident_pack(PRODUCT, dt(2026, 10, 1, 10, 0), notes=["assumption noted"])
    pack.generated = now
    md = to_markdown(pack, now)
    assert md.startswith("# CRA Article 14 reporting pack: severe incident")
    assert "2026-10-02 10:00 UTC" in md
    assert "13h 30m left" in md
    assert "Article 14(5)" in md
    assert "assumption noted" in md
    assert "Nothing has been submitted" in md
    data = pack.to_dict(now)
    assert data["aware_at"] == "2026-10-01T10:00:00Z"
    assert data["stages"][0]["due"] == "2026-10-02T10:00:00Z"
    assert data["stages"][0]["time_left"] == "13h 30m left"
    assert data["product"]["member_states"] == ["NL", "DE"]
    assert any("Early warning" in line for line in summary_lines(pack, now))


def test_time_left():
    now = dt(2026, 10, 1, 12, 0)
    assert time_left(dt(2026, 10, 3, 14, 5), now) == "2d 2h 05m left"
    assert time_left(dt(2026, 10, 1, 11, 0), now) == "OVERDUE by 1h 00m"
    assert time_left(None, now) == ""


def test_missing_main_establishment_is_flagged():
    pack = vulnerability_pack(Product(name="x"), dt(2026, 10, 1))
    assert "set main_establishment" in " ".join(pack.notes)
