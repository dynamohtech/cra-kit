"""Find dependency files in a project and turn them into a component list."""

from __future__ import annotations

import fnmatch
import os
from pathlib import Path

from cra_kit.model import ParseResult
from cra_kit.sbom import jslocks, parsers

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".tox", ".nox", ".mypy_cache", ".pytest_cache", "dist", "build", "target",
    "vendor", ".next", ".cache",
}

# File name patterns cra-kit reads, in the order they are tried per folder.
SUPPORTED = {
    "package-lock.json": "npm",
    "npm-shrinkwrap.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "poetry.lock": "poetry",
    "Pipfile.lock": "pipfile",
    "uv.lock": "uv",
    "requirements*.txt": "requirements",
    "Cargo.lock": "cargo",
    "go.mod": "gomod",
}

# Files we recognise but cannot read yet, so we can say so instead of
# silently producing an incomplete SBOM.
NOT_YET_SUPPORTED = ["bun.lockb", "bun.lock", "composer.lock",
                     "Gemfile.lock", "pom.xml", "build.gradle", "build.gradle.kts", "packages.lock.json"]


def find_dependency_files(root: Path) -> tuple[list[tuple[Path, str]], list[Path]]:
    """Return (supported files with their kind, recognised-but-unsupported files)."""
    found: list[tuple[Path, str]] = []
    unsupported: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".venv"))
        names = sorted(filenames)
        # A lockfile makes the matching requirements file redundant.
        has_py_lock = any(n in names for n in ("poetry.lock", "Pipfile.lock", "uv.lock"))
        for pattern, kind in SUPPORTED.items():
            for name in fnmatch.filter(names, pattern):
                if kind == "requirements" and has_py_lock:
                    continue
                found.append((Path(dirpath) / name, kind))
        for name in names:
            if name in NOT_YET_SUPPORTED:
                unsupported.append(Path(dirpath) / name)
    return found, unsupported


def collect(root: Path, include_dev: bool = False) -> ParseResult:
    """Parse every supported dependency file under ``root``."""
    root = root.resolve()
    if root.is_file():
        files, unsupported = [(root, _kind_for(root))], []
        if files[0][1] is None:
            raise ValueError(f"{root.name} is not a supported dependency file")
    else:
        files, unsupported = find_dependency_files(root)
    result = ParseResult()
    for path, kind in files:
        try:
            result.merge(_parse(path, kind, include_dev))
        except (ValueError, KeyError, TypeError) as exc:  # malformed file
            result.warnings.append(f"{path}: could not be read ({exc})")
    for path in unsupported:
        result.warnings.append(
            f"{path}: this file type is not supported yet, so its dependencies are NOT in the SBOM"
        )
    if not files:
        result.warnings.append(
            "no supported dependency files found (looked for package-lock.json, pnpm-lock.yaml, yarn.lock, "
            "poetry.lock, Pipfile.lock, uv.lock, requirements*.txt, Cargo.lock, go.mod)"
        )
    return result


def _kind_for(path: Path) -> str | None:
    for pattern, kind in SUPPORTED.items():
        if fnmatch.fnmatch(path.name, pattern):
            return kind
    return None


def _parse(path: Path, kind: str, include_dev: bool) -> ParseResult:
    if kind == "npm":
        return parsers.parse_npm_lock(path, include_dev)
    if kind == "pnpm":
        return jslocks.parse_pnpm_lock(path, include_dev)
    if kind == "yarn":
        return jslocks.parse_yarn_lock(path, include_dev)
    if kind == "poetry":
        return parsers.parse_poetry_lock(path, include_dev)
    if kind == "pipfile":
        return parsers.parse_pipfile_lock(path, include_dev)
    if kind == "uv":
        return parsers.parse_uv_lock(path, include_dev)
    if kind == "requirements":
        return parsers.parse_requirements(path)
    if kind == "cargo":
        return parsers.parse_cargo_lock(path)
    if kind == "gomod":
        return parsers.parse_go_mod(path)
    raise ValueError(f"unknown kind {kind}")
