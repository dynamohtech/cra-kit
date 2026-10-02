"""Product settings stored in cra-kit.toml."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_NAME = "cra-kit.toml"

TEMPLATE = '''# cra-kit settings for one product. Every command reads this file when it
# is in the current folder (or pass --config PATH).

[product]
name = "{name}"
version = "{version}"
# The natural or legal person who develops or manufactures the product (or has
# it designed, developed or manufactured) and markets it under its own name or
# trademark (Article 3(13)).
manufacturer = "{manufacturer}"
# application | firmware | device | library | framework | operating-system
type = "application"
# Where users and researchers report vulnerabilities (Annex I, Part II(6)).
security_contact = "security@example.com"
# End of the support period (Article 13(8): at least five years unless the
# product is expected to be in use for less time). Format: YYYY-MM-DD.
support_period_end = ""
# EU Member States where the product is made available (ISO 3166 codes),
# needed in the 24-hour early warning (Article 14(2)(a) and 14(4)(a)).
member_states = []
# Used by `cra-kit techfile` (Annexes II, V and VII). Optional for other commands.
manufacturer_address = ""
website = ""
# What the product is for, in one or two sentences (Annex II(4), Annex VII(1)(a)).
intended_purpose = ""
# Public URL of the full EU declaration of conformity, if you publish it
# (Annex II(6); required in a simplified declaration, Article 13(20)).
declaration_url = ""
# EU Member State of your main establishment (ISO 3166 code): where your
# cybersecurity decisions are predominantly taken. Its CSIRT designated as
# coordinator receives your Article 14 reports (Article 14(7)). With no EU
# establishment, use the Member State of your authorised representative,
# importer or distributor (in that order), or the one with the most users.
main_establishment = ""
'''


@dataclass
class Product:
    name: str = "Unnamed product"
    version: str = "0.0.0"
    manufacturer: str = ""
    type: str = "application"
    security_contact: str = ""
    support_period_end: str = ""
    member_states: list[str] = field(default_factory=list)
    main_establishment: str = ""
    manufacturer_address: str = ""
    website: str = ""
    intended_purpose: str = ""
    declaration_url: str = ""


def load(path: Path | None = None) -> Product | None:
    target = path or Path.cwd() / CONFIG_NAME
    if not target.exists():
        if path is not None:
            raise FileNotFoundError(f"config file not found: {path}")
        return None
    data = tomllib.loads(target.read_text(encoding="utf-8")).get("product", {})
    known = {k: v for k, v in data.items() if k in Product.__dataclass_fields__}
    return Product(**known)


def write_template(path: Path, name: str, version: str, manufacturer: str) -> None:
    path.write_text(
        TEMPLATE.format(name=name, version=version, manufacturer=manufacturer), encoding="utf-8"
    )
