"""Read dependency lockfiles and manifests into :class:`Component` lists.

Each parser takes the path of one file and returns a :class:`ParseResult`.
Parsers never execute project code or call a package manager: they only
read files, so running cra-kit on untrusted code is safe.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from cra_kit.model import Component, ParseResult, normalize_pypi_name

# ---------------------------------------------------------------------------
# npm: package-lock.json / npm-shrinkwrap.json
# ---------------------------------------------------------------------------


def parse_npm_lock(path: Path, include_dev: bool = False) -> ParseResult:
    data = json.loads(path.read_text(encoding="utf-8"))
    result = ParseResult(sources=[str(path)])
    packages = data.get("packages")
    if isinstance(packages, dict) and packages:
        _parse_npm_v2(packages, path, include_dev, result)
    elif isinstance(data.get("dependencies"), dict):
        # v1 lockfiles hoist transitive packages to the top level too, so only
        # package.json can tell which ones are direct.
        _parse_npm_v1(data["dependencies"], path, include_dev, result, _npm_manifest_direct(path.parent, include_dev))
    else:
        result.warnings.append(f"{path}: no packages found (empty or unknown lockfile format)")
    return result


def _npm_name_from_key(key: str) -> str:
    # "node_modules/a/node_modules/@s/b" -> "@s/b"
    return key.rsplit("node_modules/", 1)[-1]


def _parse_npm_v2(packages: dict, path: Path, include_dev: bool, result: ParseResult) -> None:
    root = packages.get("", {})
    direct_names = set()
    for section in ("dependencies", "optionalDependencies", "peerDependencies"):
        direct_names.update((root.get(section) or {}).keys())
    if include_dev:
        direct_names.update((root.get("devDependencies") or {}).keys())

    for key, entry in packages.items():
        if not key or not key.startswith("node_modules/") and "/node_modules/" not in key:
            # "" is the project itself; other keys without node_modules are
            # workspace folders, which belong to the product, not its deps.
            continue
        if entry.get("link"):
            continue
        if entry.get("dev") and not include_dev:
            continue
        if entry.get("devOptional") and not include_dev and not entry.get("optional"):
            continue
        version = entry.get("version")
        if not version:
            continue
        install_name = _npm_name_from_key(key)  # the folder name; differs from "name" for aliases
        name = entry.get("name") or install_name
        is_top_level = key == f"node_modules/{install_name}"
        result.components.append(
            Component("npm", name, version, direct=is_top_level and install_name in direct_names, source=str(path))
        )


def _npm_manifest_direct(folder: Path, include_dev: bool) -> set[str] | None:
    manifest = folder / "package.json"
    if not manifest.exists():
        return None
    data = json.loads(manifest.read_text(encoding="utf-8"))
    names: set[str] = set()
    sections = ["dependencies", "optionalDependencies", "peerDependencies"] + (["devDependencies"] if include_dev else [])
    for section in sections:
        names.update((data.get(section) or {}).keys())
    return names


def _parse_npm_v1(
    deps: dict, path: Path, include_dev: bool, result: ParseResult, direct_names: set[str] | None, top: bool = True
) -> None:
    for name, entry in deps.items():
        if entry.get("dev") and not include_dev:
            continue
        version = entry.get("version")
        if version and not version.startswith(("file:", "link:")):
            if not top:
                direct = False  # nested packages are never direct dependencies
            elif direct_names is None:
                direct = None
            else:
                direct = name in direct_names
            result.components.append(Component("npm", name, version, direct=direct, source=str(path)))
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _parse_npm_v1(nested, path, include_dev, result, direct_names, top=False)


# ---------------------------------------------------------------------------
# Python: requirements*.txt, poetry.lock, Pipfile.lock, uv.lock
# ---------------------------------------------------------------------------

_REQ_PIN = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*===?\s*(?P<version>[^\s;#,]+)"
)
_REQ_NAME = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)")


def parse_requirements(path: Path, _seen: set[Path] | None = None) -> ParseResult:
    seen = _seen if _seen is not None else set()
    path = path.resolve()
    result = ParseResult(sources=[str(path)])
    if path in seen:
        return result
    seen.add(path)

    lines = path.read_text(encoding="utf-8").splitlines()
    joined: list[str] = []
    buffer = ""
    for raw in lines:  # join backslash continuations (common with --hash)
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        joined.append(buffer + raw)
        buffer = ""
    if buffer:
        joined.append(buffer)

    for raw in joined:
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r ", "--requirement ")):
            target = (path.parent / line.split(None, 1)[1].strip()).resolve()
            if target.exists():
                result.merge(parse_requirements(target, seen))
            else:
                result.warnings.append(f"{path}: included file not found: {target.name}")
            continue
        if line.startswith("-"):
            if line.startswith(("-e ", "--editable")):
                result.warnings.append(f"{path}: skipped editable install: {line}")
            continue  # other pip options (--index-url, -c, ...) carry no packages
        if "://" in line or line.startswith((".", "/")):
            result.warnings.append(f"{path}: skipped direct URL or path requirement: {line}")
            continue
        requirement = line.split(";", 1)[0].strip()
        match = _REQ_PIN.match(requirement)
        if match:
            result.components.append(
                Component("pypi", match["name"], match["version"], direct=None, source=str(path))
            )
        else:
            name = _REQ_NAME.match(requirement)
            label = name["name"] if name else requirement
            result.warnings.append(
                f"{path}: '{label}' is not pinned with '=='; pin it (or use a lockfile) so the SBOM lists an exact version"
            )
    return result


def _pyproject_direct_names(project_dir: Path) -> set[str] | None:
    pyproject = project_dir / "pyproject.toml"
    if not pyproject.exists():
        return None
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    names: set[str] = set()
    for dep in data.get("project", {}).get("dependencies", []) or []:
        match = _REQ_NAME.match(dep.strip())
        if match:
            names.add(normalize_pypi_name(match["name"]))
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    names.update(normalize_pypi_name(n) for n in poetry_deps if n.lower() != "python")
    return names


def parse_poetry_lock(path: Path, include_dev: bool = False) -> ParseResult:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result = ParseResult(sources=[str(path)])
    direct = _pyproject_direct_names(path.parent)
    for pkg in data.get("package", []):
        groups = pkg.get("groups")
        category = pkg.get("category")
        is_dev = (groups is not None and "main" not in groups) or category == "dev"
        if is_dev and not include_dev:
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        is_direct = None if direct is None else normalize_pypi_name(name) in direct
        result.components.append(Component("pypi", name, version, direct=is_direct, source=str(path)))
    return result


def parse_pipfile_lock(path: Path, include_dev: bool = False) -> ParseResult:
    data = json.loads(path.read_text(encoding="utf-8"))
    result = ParseResult(sources=[str(path)])
    direct: set[str] | None = None
    pipfile = path.parent / "Pipfile"
    if pipfile.exists():
        manifest = tomllib.loads(pipfile.read_text(encoding="utf-8"))
        direct = {normalize_pypi_name(n) for n in (manifest.get("packages") or {})}
        if include_dev:
            direct.update(normalize_pypi_name(n) for n in (manifest.get("dev-packages") or {}))
    sections = ["default"] + (["develop"] if include_dev else [])
    for section in sections:
        for name, entry in (data.get(section) or {}).items():
            version = str(entry.get("version", "")).lstrip("=")
            if not version:
                result.warnings.append(f"{path}: '{name}' has no pinned version (VCS or path dependency?)")
                continue
            is_direct = None if direct is None else normalize_pypi_name(name) in direct
            result.components.append(Component("pypi", name, version, direct=is_direct, source=str(path)))
    return result


def parse_uv_lock(path: Path, include_dev: bool = False) -> ParseResult:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result = ParseResult(sources=[str(path)])
    packages = data.get("package", [])
    roots = [
        p for p in packages
        if isinstance(p.get("source"), dict) and ({"editable", "virtual"} & set(p["source"]))
    ]
    root_names = {normalize_pypi_name(p["name"]) for p in roots}
    direct: set[str] = set()
    dev_only: set[str] = set()
    for root in roots:
        direct.update(normalize_pypi_name(d["name"]) for d in root.get("dependencies", []))
        dev_groups = root.get("dev-dependencies", {}) or {}
        for group in dev_groups.values():
            dev_only.update(normalize_pypi_name(d["name"]) for d in group)
    dev_only -= direct
    if dev_only and not include_dev:
        result.warnings.append(
            f"{path}: skipped {len(dev_only)} direct dev dependencies; their own dependencies may still be listed"
        )
    for pkg in packages:
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        norm = normalize_pypi_name(name)
        if norm in root_names:
            continue  # the project itself
        if norm in dev_only and not include_dev:
            continue
        is_direct = norm in direct if roots else None
        result.components.append(Component("pypi", name, version, direct=is_direct, source=str(path)))
    return result


# ---------------------------------------------------------------------------
# Rust: Cargo.lock
# ---------------------------------------------------------------------------


def parse_cargo_lock(path: Path) -> ParseResult:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    result = ParseResult(sources=[str(path)])
    packages = data.get("package", [])
    # Packages without a "source" are the workspace's own crates.
    local = [p for p in packages if "source" not in p]
    local_names = {p["name"] for p in local}
    direct: set[str] = set()
    for crate in local:
        for dep in crate.get("dependencies", []):
            direct.add(dep.split(" ", 1)[0])
    for pkg in packages:
        if "source" not in pkg:
            continue
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version or name in local_names:
            continue
        result.components.append(
            Component("cargo", name, version, direct=name in direct if local else None, source=str(path))
        )
    return result


# ---------------------------------------------------------------------------
# Go: go.mod
# ---------------------------------------------------------------------------

_GO_REQ = re.compile(r"^(?P<module>\S+)\s+(?P<version>v\S+)(?P<rest>.*)$")


def parse_go_mod(path: Path) -> ParseResult:
    result = ParseResult(sources=[str(path)])
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("//"):
            continue
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require ") and not line.startswith("require ("):
            line = line[len("require "):].strip()
        elif not in_block:
            if line.startswith("replace "):
                result.warnings.append(f"{path}: 'replace' directives are not applied; check replaced modules by hand")
            continue
        match = _GO_REQ.match(line)
        if not match:
            continue
        indirect = "// indirect" in match["rest"]
        result.components.append(
            Component("golang", match["module"], match["version"], direct=not indirect, source=str(path))
        )
    return result
