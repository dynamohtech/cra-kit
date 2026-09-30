"""Core data types shared by the SBOM, scan and assessment modules."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import quote

# Package ecosystems cra-kit can read, mapped to the names OSV.dev uses.
OSV_ECOSYSTEM = {
    "npm": "npm",
    "pypi": "PyPI",
    "cargo": "crates.io",
    "golang": "Go",
}


def _enc(segment: str) -> str:
    """Percent-encode one purl path segment (keeps characters purl allows)."""
    return quote(segment, safe="._-~")


def normalize_pypi_name(name: str) -> str:
    """PEP 503 normalisation, which the purl spec requires for PyPI names."""
    return re.sub(r"[-_.]+", "-", name).lower()


@dataclass(frozen=True, order=True)
class Component:
    """One third-party component found in a lockfile or manifest.

    ``direct`` is True for a top-level dependency, False for a transitive
    one and None when the source file does not say (for example a
    ``pip freeze`` style requirements file).
    """

    ecosystem: str
    name: str
    version: str
    direct: bool | None = field(default=None, compare=False)
    source: str = field(default="", compare=False)

    @property
    def purl(self) -> str:
        if self.ecosystem == "npm":
            if self.name.startswith("@") and "/" in self.name:
                scope, pkg = self.name.split("/", 1)
                return f"pkg:npm/{_enc(scope)}/{_enc(pkg)}@{_enc(self.version)}"
            return f"pkg:npm/{_enc(self.name)}@{_enc(self.version)}"
        if self.ecosystem == "pypi":
            return f"pkg:pypi/{_enc(normalize_pypi_name(self.name))}@{_enc(self.version)}"
        if self.ecosystem == "cargo":
            return f"pkg:cargo/{_enc(self.name)}@{_enc(self.version)}"
        if self.ecosystem == "golang":
            path = "/".join(_enc(part) for part in self.name.split("/"))
            return f"pkg:golang/{path}@{_enc(self.version)}"
        raise ValueError(f"unsupported ecosystem: {self.ecosystem}")

    @property
    def relationship(self) -> str:
        if self.direct is None:
            return "unknown"
        return "direct" if self.direct else "transitive"


@dataclass
class ParseResult:
    """Components found in one project, plus anything the user should know."""

    components: list[Component] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def merge(self, other: "ParseResult") -> None:
        self.components.extend(other.components)
        self.sources.extend(other.sources)
        self.warnings.extend(other.warnings)

    def deduplicated(self) -> list[Component]:
        """One entry per (ecosystem, name, version); 'direct' wins over the rest."""
        best: dict[tuple[str, str, str], Component] = {}
        for comp in self.components:
            key = (comp.ecosystem, comp.name if comp.ecosystem != "pypi" else normalize_pypi_name(comp.name), comp.version)
            current = best.get(key)
            if current is None or _rank(comp.direct) > _rank(current.direct):
                best[key] = comp
        return sorted(best.values(), key=lambda c: c.purl)


def _rank(direct: bool | None) -> int:
    return {True: 2, None: 1, False: 0}[direct]
