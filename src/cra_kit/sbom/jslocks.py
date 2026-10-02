"""pnpm-lock.yaml and yarn.lock (classic v1 and Berry v2+) parsers.

Neither format marks development dependencies on every package, so cra-kit
rebuilds the dependency graph from the lockfile and walks it from the
project's own dependencies (the "roots"). A package is included when it is
reachable from a production root, or from a development root with
``--include-dev``. Direct dependencies are the roots themselves.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from cra_kit.model import Component, ParseResult
from cra_kit.sbom import yaml_lite

PROD_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
DEV_SECTIONS = ("devDependencies",)


@dataclass
class _Node:
    name: str
    version: str
    deps: list[str] = field(default_factory=list)


def _components_from_graph(
    nodes: dict[str, _Node],
    roots: list[tuple[str, bool]],
    include_dev: bool,
    path: Path,
) -> list[Component]:
    """Walk from the roots; return one component per (name, version)."""
    start = [key for key, is_dev in roots if include_dev or not is_dev]
    seen: set[str] = set()
    stack = [k for k in start if k in nodes]
    while stack:
        key = stack.pop()
        if key in seen:
            continue
        seen.add(key)
        stack.extend(d for d in nodes[key].deps if d in nodes and d not in seen)
    direct_keys = set(start)
    by_identity: dict[tuple[str, str], bool] = {}
    for key in seen:
        node = nodes[key]
        ident = (node.name, node.version)
        by_identity[ident] = by_identity.get(ident, False) or key in direct_keys
    return [
        Component("npm", name, version, direct=direct, source=str(path))
        for (name, version), direct in sorted(by_identity.items())
    ]


def _manifest_roots(folder: Path) -> tuple[dict[str, str], dict[str, str]] | None:
    """(production deps, dev deps) as name -> range from package.json, or None."""
    manifest = folder / "package.json"
    if not manifest.is_file():
        return None
    data = json.loads(manifest.read_text(encoding="utf-8"))
    prod: dict[str, str] = {}
    for section in PROD_SECTIONS:
        prod.update({k: str(v) for k, v in (data.get(section) or {}).items()})
    dev = {k: str(v) for k, v in (data.get("devDependencies") or {}).items() if k not in prod}
    return prod, dev


def _usable_version(version: str) -> bool:
    return bool(version) and not any(x in version for x in ("://", "link:", "file:", "workspace:", "git+"))


# ---------------------------------------------------------------------------
# pnpm
# ---------------------------------------------------------------------------


def parse_pnpm_lock(path: Path, include_dev: bool = False) -> ParseResult:
    result = ParseResult(sources=[str(path)])
    docs = yaml_lite.load_all(path.read_text(encoding="utf-8"))
    data = next((d for d in reversed(docs) if isinstance(d, dict) and "lockfileVersion" in d), None)
    if data is None:
        result.warnings.append(f"{path}: not a pnpm lockfile (no lockfileVersion)")
        return result
    raw_version = str(data.get("lockfileVersion"))
    try:
        major = int(raw_version.split(".")[0])
    except ValueError:
        result.warnings.append(f"{path}: unknown lockfileVersion {raw_version!r}")
        return result
    if major < 5:
        result.warnings.append(f"{path}: lockfileVersion {raw_version} is too old to read; regenerate it with pnpm 7 or later")
        return result

    if major >= 9:
        graph_section, style = data.get("snapshots") or {}, "v9"
        if not graph_section:  # a lockfile without snapshots still lists packages
            graph_section = data.get("packages") or {}
    elif major >= 6:
        graph_section, style = data.get("packages") or {}, "v6"
    else:
        graph_section, style = data.get("packages") or {}, "v5"

    nodes: dict[str, _Node] = {}
    skipped: set[str] = set()
    for key, entry in graph_section.items():
        name, version = _pnpm_split_key(key, style)
        if not name or not _usable_version(version):
            skipped.add(key)
            continue
        entry = entry or {}
        deps = []
        for section in ("dependencies", "optionalDependencies"):
            for dep_name, ref in (entry.get(section) or {}).items():
                dep_key = _pnpm_ref_to_key(dep_name, str(ref), style)
                if dep_key:
                    deps.append(dep_key)
        nodes[key] = _Node(name, version, deps)

    importers = data.get("importers")
    if not isinstance(importers, dict):  # single-project lockfiles before v9 keep these at top level
        importers = {".": {s: data.get(s) for s in ("dependencies", "devDependencies", "optionalDependencies")}}
    roots: list[tuple[str, bool]] = []
    for importer in importers.values():
        importer = importer or {}
        for section in ("dependencies", "optionalDependencies", "devDependencies"):
            for dep_name, spec in (importer.get(section) or {}).items():
                ref = spec.get("version") if isinstance(spec, dict) else spec
                dep_key = _pnpm_ref_to_key(dep_name, str(ref or ""), style)
                if dep_key:
                    roots.append((dep_key, section == "devDependencies"))

    if skipped:
        result.warnings.append(
            f"{path}: skipped {len(skipped)} packages installed from git, a URL or a local path; check them by hand"
        )
    result.components.extend(_components_from_graph(nodes, roots, include_dev, path))
    return result


def _strip_peers(text: str) -> str:
    """'18.2.0(react@18.2.0)' -> '18.2.0'."""
    return text.split("(", 1)[0]


def _pnpm_split_key(key: str, style: str) -> tuple[str, str]:
    if style == "v5":
        body = key.lstrip("/")
        if "/" not in body:
            return "", ""
        name, version = body.rsplit("/", 1)
        return name, version.split("_", 1)[0]
    body = _strip_peers(key)
    if style == "v6":
        body = body.lstrip("/")
    at = body.find("@", 1)
    if at == -1:
        return "", ""
    return body[:at], body[at + 1:]


def _pnpm_ref_to_key(name: str, ref: str, style: str) -> str | None:
    if not ref or ref.startswith(("link:", "file:", "workspace:")):
        return None
    if style == "v5":
        return ref if ref.startswith("/") else f"/{name}/{ref}"
    if style == "v6":
        return ref if ref.startswith("/") else f"/{name}@{ref}"
    base = _strip_peers(ref)
    if "@" in base[1:]:  # alias: 'string-width@4.2.3' or '@scope/pkg@1.0.0'
        return ref
    return f"{name}@{ref}"


# ---------------------------------------------------------------------------
# yarn
# ---------------------------------------------------------------------------


def parse_yarn_lock(path: Path, include_dev: bool = False) -> ParseResult:
    text = path.read_text(encoding="utf-8")
    if re.search(r"^__metadata:", text, flags=re.MULTILINE):
        return _parse_yarn_berry(path, text, include_dev)
    return _parse_yarn_classic(path, text, include_dev)


def _split_descriptor(descriptor: str) -> tuple[str, str]:
    at = descriptor.find("@", 1)
    if at == -1:
        return descriptor, ""
    return descriptor[:at], descriptor[at + 1:]


def _unquote(token: str) -> str:
    token = token.strip()
    if len(token) >= 2 and token[0] == token[-1] == '"':
        return json.loads(token)
    return token


def _parse_yarn_classic(path: Path, text: str, include_dev: bool) -> ParseResult:
    result = ParseResult(sources=[str(path)])
    entries: list[dict] = []
    by_descriptor: dict[str, int] = {}
    current: dict | None = None
    section: str | None = None
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        line = raw.strip()
        if indent == 0:
            if not line.endswith(":"):
                raise ValueError(f"{path}:{number}: unexpected line in yarn.lock")
            current = {"descriptors": [], "version": "", "deps": {}}
            for part in _split_header(line[:-1]):
                current["descriptors"].append(part)
                by_descriptor[part] = len(entries)
            entries.append(current)
            section = None
        elif current is not None and indent == 2:
            if line.endswith(":"):
                section = line[:-1]
                continue
            section = None
            key, _, value = line.partition(" ")
            if key == "version":
                current["version"] = _unquote(value)
        elif current is not None and indent >= 4 and section in ("dependencies", "optionalDependencies"):
            key, _, value = _split_pair(line)
            current["deps"][key] = value

    nodes: dict[str, _Node] = {}
    for index, entry in enumerate(entries):
        first = entry["descriptors"][0]
        name, rng = _split_descriptor(first)
        if rng.startswith("npm:"):  # alias: install name differs from the real package
            name, _ = _split_descriptor(rng[4:])
        deps = [f"{d}@{r}" for d, r in entry["deps"].items()]
        if _usable_version(entry["version"]) and not any(
            _split_descriptor(d)[1].startswith(("file:", "link:")) for d in entry["descriptors"]
        ):
            nodes[str(index)] = _Node(name, entry["version"], [str(by_descriptor[d]) for d in deps if d in by_descriptor])

    manifest = _manifest_roots(path.parent)
    if manifest is None:
        result.warnings.append(
            f"{path}: no package.json next to the lockfile, so direct and development dependencies "
            "cannot be told apart; every package in the lockfile is listed"
        )
        result.components.extend(
            Component("npm", n.name, n.version, direct=None, source=str(path))
            for n in {(n.name, n.version): n for n in nodes.values()}.values()
        )
        return result
    prod, dev = manifest
    roots = [(str(by_descriptor[f"{n}@{r}"]), False) for n, r in prod.items() if f"{n}@{r}" in by_descriptor]
    roots += [(str(by_descriptor[f"{n}@{r}"]), True) for n, r in dev.items() if f"{n}@{r}" in by_descriptor]
    roots += _yarn_workspace_roots(path.parent, by_descriptor, result)
    result.components.extend(_components_from_graph(nodes, roots, include_dev, path))
    return result


def _split_header(header: str) -> list[str]:
    parts, buf, quoted = [], "", False
    for ch in header:
        if ch == '"':
            quoted = not quoted
            buf += ch
        elif ch == "," and not quoted:
            parts.append(_unquote(buf))
            buf = ""
        else:
            buf += ch
    if buf.strip():
        parts.append(_unquote(buf))
    return [p.strip() for p in parts]


def _split_pair(line: str) -> tuple[str, str, str]:
    if line.startswith('"'):
        end = line.index('"', 1)
        return line[1:end], " ", _unquote(line[end + 1:])
    key, sep, value = line.partition(" ")
    return key, sep, _unquote(value)


def _yarn_workspace_roots(folder: Path, by_descriptor: dict[str, int], result: ParseResult) -> list[tuple[str, bool]]:
    """Yarn classic does not list workspaces in the lockfile: read their package.json files."""
    manifest = folder / "package.json"
    data = json.loads(manifest.read_text(encoding="utf-8"))
    patterns = data.get("workspaces") or []
    if isinstance(patterns, dict):
        patterns = patterns.get("packages") or []
    roots: list[tuple[str, bool]] = []
    for pattern in patterns:
        for ws in sorted(folder.glob(pattern)):
            if not (ws / "package.json").is_file():
                continue
            ws_roots = _manifest_roots(ws)
            if ws_roots is None:
                continue
            for deps, is_dev in ((ws_roots[0], False), (ws_roots[1], True)):
                roots += [(str(by_descriptor[f"{n}@{r}"]), is_dev) for n, r in deps.items() if f"{n}@{r}" in by_descriptor]
    return roots


def _parse_yarn_berry(path: Path, text: str, include_dev: bool) -> ParseResult:
    result = ParseResult(sources=[str(path)])
    data = yaml_lite.load(text) or {}
    by_descriptor: dict[str, str] = {}
    for key in data:
        if key == "__metadata":
            continue
        for descriptor in key.split(", "):
            by_descriptor[descriptor.strip()] = key

    def lookup(name: str, rng: str) -> str | None:
        for candidate in (f"{name}@{rng}", f"{name}@npm:{rng}"):
            if candidate in by_descriptor:
                return by_descriptor[candidate]
        return None

    nodes: dict[str, _Node] = {}
    workspaces: list[tuple[str, dict]] = []
    other = 0
    for key, entry in data.items():
        if key == "__metadata" or not isinstance(entry, dict):
            continue
        resolution = str(entry.get("resolution") or "")
        if "@workspace:" in resolution:
            workspaces.append((resolution, entry))
            continue
        name, protocol_part = _split_descriptor(resolution)
        if entry.get("linkType") == "soft" or not protocol_part.startswith(("npm:", "patch:")):
            other += 1
            continue
        deps = []
        for section in ("dependencies", "optionalDependencies"):
            for dep_name, rng in (entry.get(section) or {}).items():
                target = lookup(dep_name, str(rng))
                if target:
                    deps.append(target)
        nodes[key] = _Node(name, str(entry.get("version") or ""), deps)

    roots: list[tuple[str, bool]] = []
    for resolution, entry in workspaces:
        ws_path = resolution.split("@workspace:", 1)[1]
        manifest = _manifest_roots(path.parent / ws_path)
        dev_names = set(manifest[1]) if manifest else set()
        if manifest is None:
            result.warnings.append(
                f"{path}: package.json for workspace '{ws_path}' not found; its development dependencies "
                "cannot be told apart and are treated as production dependencies"
            )
        for section in ("dependencies", "optionalDependencies"):
            for dep_name, rng in (entry.get(section) or {}).items():
                target = lookup(dep_name, str(rng))
                if target:
                    roots.append((target, dep_name in dev_names))
    if other:
        result.warnings.append(
            f"{path}: skipped {other} packages installed from git, a URL or a local path; check them by hand"
        )
    result.components.extend(_components_from_graph(nodes, roots, include_dev, path))
    return result
