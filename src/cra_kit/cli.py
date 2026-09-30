"""Command-line interface: cra-kit init | sbom | scan | assess | report."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
import urllib.error
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from cra_kit import __version__, assess as assess_mod, config, reporting
from cra_kit import scan as scan_mod
from cra_kit.config import Product
from cra_kit.sbom import collect
from cra_kit.sbom.cyclonedx import build_bom, read_purls, summarize, write_bom

ANSWERS_NAME = "cra-answers.toml"
DEFAULT_SBOM = "sbom.cdx.json"
COMPONENT_TYPES = {"application", "framework", "library", "container", "platform", "operating-system",
                   "device", "device-driver", "firmware", "file"}

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


class CliError(Exception):
    """A problem to report to the user without a traceback."""


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_ERROR
    try:
        return args.func(args)
    except (CliError, FileNotFoundError, ValueError, tomllib.TOMLDecodeError) as exc:
        print(f"cra-kit: error: {exc}", file=sys.stderr)
        return EXIT_ERROR
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        return 130


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cra-kit",
        description="Toolkit for EU Cyber Resilience Act compliance: SBOMs, vulnerability checks, "
                    "readiness reports and Article 14 reporting packs. Not legal advice.",
    )
    parser.add_argument("--version", action="version", version=f"cra-kit {__version__}")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", metavar="PATH", help=f"product settings file (default: ./{config.CONFIG_NAME})")
    sub = parser.add_subparsers(title="commands", metavar="COMMAND")

    p = sub.add_parser("init", parents=[common], help="create cra-kit.toml and a readiness answers file")
    p.add_argument("directory", nargs="?", default=".", help="project folder (default: current folder)")
    p.add_argument("--name", help="product name (default: read from package.json, pyproject.toml or Cargo.toml)")
    p.add_argument("--product-version", help="product version")
    p.add_argument("--manufacturer", default="", help="legal name of the manufacturer")
    p.add_argument("--force", action="store_true", help="overwrite existing files")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("sbom", parents=[common], help="generate a CycloneDX 1.6 SBOM from lockfiles")
    p.add_argument("path", nargs="?", default=".", help="project folder or a single lockfile (default: .)")
    p.add_argument("-o", "--output", default=DEFAULT_SBOM, help=f"output file (default: {DEFAULT_SBOM})")
    p.add_argument("--include-dev", action="store_true", help="include development-only dependencies")
    p.add_argument("--product-name", help="override the product name")
    p.add_argument("--product-version", help="override the product version")
    p.set_defaults(func=cmd_sbom)

    p = sub.add_parser("scan", parents=[common], help="check components against OSV.dev and CISA KEV")
    p.add_argument("target", nargs="?", default=".", help="CycloneDX JSON SBOM, lockfile or project folder (default: .)")
    p.add_argument("--format", choices=["table", "markdown", "json"], default="table")
    p.add_argument("-o", "--output", help="write the result to a file instead of the terminal")
    p.add_argument("--include-dev", action="store_true", help="include development-only dependencies")
    p.add_argument("--no-kev", action="store_true", help="skip the CISA Known Exploited Vulnerabilities check")
    p.add_argument("--fail-on", choices=["none", "any", "kev"], default="none",
                   help="exit with status 1 on any finding, or only on known-exploited ones (default: none)")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("assess", parents=[common], help="CRA scope, classification and readiness report")
    p.add_argument("--answers", metavar="FILE", help=f"answers file (default: ./{ANSWERS_NAME})")
    p.add_argument("--interactive", action="store_true", help="answer the questions in the terminal")
    p.add_argument("--save-answers", metavar="FILE", help="with --interactive, save your answers for next time")
    p.add_argument("--sbom", metavar="FILE", help=f"SBOM to use as evidence (default: ./{DEFAULT_SBOM} if present)")
    p.add_argument("--scan", metavar="FILE", help="JSON output of `cra-kit scan --format json` to use as evidence")
    p.add_argument("--format", choices=["markdown", "json"], default="markdown")
    p.add_argument("-o", "--output", help="write the report to a file instead of the terminal")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("report", help="Article 14 reporting pack with deadlines")
    kinds = p.add_subparsers(title="kind", metavar="KIND")
    for kind, text in (("vulnerability", "an actively exploited vulnerability"), ("incident", "a severe incident")):
        k = kinds.add_parser(kind, parents=[common], help=f"pack for {text}")
        k.add_argument("--aware", required=True, metavar="WHEN",
                       help="when you became aware: 'now' or ISO 8601, e.g. 2026-09-30T14:05+02:00")
        if kind == "vulnerability":
            k.add_argument("--fix-available", metavar="WHEN", help="when a corrective or mitigating measure became available")
            k.add_argument("--scan", metavar="FILE", help="JSON output of `cra-kit scan` to prefill details from")
            k.add_argument("--advisory", metavar="ID", help="advisory or CVE ID in the scan file to prefill from")
        else:
            k.add_argument("--notified", metavar="WHEN", help="when you submitted the 72-hour incident notification")
        k.add_argument("--format", choices=["markdown", "json"], default="markdown")
        k.add_argument("-o", "--output", help="write the pack to a file instead of the terminal")
        k.set_defaults(func=cmd_report, kind=kind)
    p.set_defaults(func=lambda _a, _p=p: (_p.print_help(), EXIT_ERROR)[1])
    return parser


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _product(args: argparse.Namespace) -> Product | None:
    path = Path(args.config) if getattr(args, "config", None) else None
    return config.load(path)


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text, encoding="utf-8")
        print(f"Wrote {output}", file=sys.stderr)
    else:
        sys.stdout.write(text if text.endswith("\n") else text + "\n")


def _warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)


def _detect_project(root: Path) -> tuple[str, str]:
    """Best-effort product name and version from the project's own manifest."""
    try:
        if (root / "package.json").is_file():
            data = json.loads((root / "package.json").read_text(encoding="utf-8"))
            if data.get("name"):
                return data["name"], data.get("version", "0.0.0")
        if (root / "pyproject.toml").is_file():
            data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
            proj = data.get("project") or data.get("tool", {}).get("poetry", {})
            if proj.get("name"):
                return proj["name"], str(proj.get("version", "0.0.0"))
        if (root / "Cargo.toml").is_file():
            data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
            pkg = data.get("package", {})
            if pkg.get("name") and isinstance(pkg.get("version"), str):
                return pkg["name"], pkg["version"]
    except (ValueError, tomllib.TOMLDecodeError, OSError):
        pass
    return root.resolve().name, "0.0.0"


def _relative(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path.cwd().resolve()))
    except ValueError:
        return path


def _is_cyclonedx(path: Path) -> bool:
    if not path.is_file() or path.suffix.lower() != ".json":
        return False
    try:
        return json.loads(path.read_text(encoding="utf-8")).get("bomFormat") == "CycloneDX"
    except (ValueError, OSError, AttributeError):
        return False


def _load_json(path: str, what: str) -> dict:
    p = Path(path)
    if not p.is_file():
        raise CliError(f"{what} not found: {path}")
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise CliError(f"{path} is not valid JSON ({exc})") from exc


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.directory)
    if not root.is_dir():
        raise CliError(f"not a folder: {args.directory}")
    name, version = _detect_project(root)
    name, version = args.name or name, args.product_version or version
    config_path = Path(args.config) if args.config else root / config.CONFIG_NAME
    answers_path = root / ANSWERS_NAME
    for path, write in (
        (config_path, lambda p: config.write_template(p, name, version, args.manufacturer)),
        (answers_path, lambda p: p.write_text(assess_mod.Answers().dump(), encoding="utf-8")),
    ):
        if path.exists() and not args.force:
            print(f"Kept existing {path} (use --force to overwrite)")
        else:
            write(path)
            print(f"Created {path}")
    print(
        "\nNext steps:\n"
        f"  1. Fill in {config_path.name} (manufacturer, security contact, support period, Member States)\n"
        f"  2. cra-kit sbom                 # writes {DEFAULT_SBOM}\n"
        "  3. cra-kit scan --format json -o scan.json\n"
        f"  4. Answer the questions in {ANSWERS_NAME}, then:\n"
        "     cra-kit assess --scan scan.json -o cra-readiness.md"
    )
    return EXIT_OK


def cmd_sbom(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        raise CliError(f"path not found: {args.path}")
    product = _product(args)
    result = collect(target, include_dev=args.include_dev)
    components = result.deduplicated()
    folder = target if target.is_dir() else target.parent
    detected_name, detected_version = _detect_project(folder)
    name = args.product_name or (product.name if product else detected_name)
    version = args.product_version or (product.version if product else detected_version)
    ptype = product.type if product else "application"
    if ptype not in COMPONENT_TYPES:
        _warn(f"product type '{ptype}' is not a CycloneDX component type; using 'application'")
        ptype = "application"
    bom = build_bom(components, name, version, manufacturer=(product.manufacturer if product else None) or None,
                    product_type=ptype)
    write_bom(bom, Path(args.output))
    s = summarize(bom)
    print(
        f"Wrote {args.output}: {s['components']} components "
        f"({s['direct']} direct, {s['transitive']} transitive, {s['unknown']} not stated) "
        f"from {len(result.sources)} dependency file(s)"
    )
    for src in result.sources:
        print(f"  read {_relative(src)}")
    for w in result.warnings:
        _warn(w)
    return EXIT_OK


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    if not target.exists():
        raise CliError(f"path not found: {args.target}")
    if _is_cyclonedx(target):
        purls = read_purls(target)
    else:
        result = collect(target, include_dev=args.include_dev)
        for w in result.warnings:
            _warn(w)
        purls = [c.purl for c in result.deduplicated()]
    if not purls:
        _warn("no components to scan")
    try:
        result = scan_mod.scan(purls, check_kev=not args.no_kev)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise CliError(f"could not reach OSV.dev ({exc}); check your network or proxy settings") from exc

    if args.format == "json":
        text = json.dumps(result.to_dict(), indent=2) + "\n"
    elif args.format == "markdown":
        text = scan_mod.to_markdown(result)
    else:
        text = _scan_table(result)
    _emit(text, args.output)
    if args.output or args.format != "table":
        print(_scan_headline(result), file=sys.stderr)
    for e in result.errors:
        _warn(e)

    if args.fail_on == "any" and result.findings:
        return EXIT_FINDINGS
    if args.fail_on == "kev":
        if result.findings and not result.kev_checked:
            print("cra-kit: error: --fail-on kev, but the CISA KEV catalogue could not be checked", file=sys.stderr)
            return EXIT_ERROR
        if result.known_exploited:
            return EXIT_FINDINGS
    return EXIT_OK


def _scan_headline(r: scan_mod.ScanResult) -> str:
    text = (f"Scanned {r.scanned} components: {r.vulnerable_components} with known vulnerabilities "
            f"({len(r.findings)} advisories)")
    if r.kev_checked:
        text += f", {len(r.known_exploited)} known exploited (CISA KEV)"
    return text + "."


def _scan_table(r: scan_mod.ScanResult) -> str:
    lines = [_scan_headline(r)]
    if r.known_exploited:
        lines.append("Known-exploited advisories are listed first. If one is exploitable in your product, "
                     "CRA Article 14 requires an early warning within 24 hours of becoming aware.")
    if r.findings:
        rows = [("KEV", "SEVERITY", "COMPONENT", "ADVISORY", "FIXED IN")]
        for f in r.findings:
            advisory = f.id + (f" ({', '.join(c for c in f.cves if c != f.id)})" if [c for c in f.cves if c != f.id] else "")
            kev = "YES" if f.known_exploited else ("no" if r.kev_checked else "?")
            rows.append((kev, f.severity, f.purl, advisory, ", ".join(f.fixed_versions) or "-"))
        widths = [max(len(row[i]) for row in rows) for i in range(4)]
        lines.append("")
        for row in rows:
            lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row[:4])) + "  " + row[4])
    return "\n".join(lines) + "\n"


def cmd_assess(args: argparse.Namespace) -> int:
    product = _product(args)
    if product is None:
        _warn(f"no {config.CONFIG_NAME} found: product details, support period and security contact are not "
              "checked (run `cra-kit init`)")
    if args.interactive:
        answers = assess_mod.ask_interactively()
        if args.save_answers:
            Path(args.save_answers).write_text(answers.dump(), encoding="utf-8")
            print(f"Saved answers to {args.save_answers}", file=sys.stderr)
    else:
        path = Path(args.answers or ANSWERS_NAME)
        if not path.is_file():
            raise CliError(f"answers file not found: {path}. Run `cra-kit init` to create one, or use --interactive")
        answers = assess_mod.Answers.load(path)

    sbom_path = args.sbom
    if sbom_path is None and Path(DEFAULT_SBOM).is_file():
        sbom_path = DEFAULT_SBOM
        print(f"Using {DEFAULT_SBOM} as SBOM evidence", file=sys.stderr)
    sbom_summary = summarize(_load_json(sbom_path, "SBOM")) if sbom_path else None
    scan_summary = _load_json(args.scan, "scan result") if args.scan else None
    if scan_summary is not None and "vulnerable_components" not in scan_summary:
        raise CliError(f"{args.scan} is not the JSON output of `cra-kit scan --format json`")

    result = assess_mod.assess(answers, product, sbom_summary, scan_summary)
    if args.format == "json":
        data = asdict(result) | {"counts": result.counts(), "tool": {"name": "cra-kit", "version": __version__}}
        text = json.dumps(data, indent=2) + "\n"
    else:
        text = assess_mod.to_markdown(result, product)
    _emit(text, args.output)
    counts = result.counts()
    print(
        f"Scope: {assess_mod.SCOPE_LABEL[result.scope]}. Category: {assess_mod.CATEGORY_LABEL[result.category]}. "
        f"Requirements done {counts.get('done', 0)}/{len(result.all_requirements)}, "
        f"at risk {counts.get('at-risk', 0)}, not started {counts.get('no', 0)}, "
        f"not answered {counts.get('', 0)}.",
        file=sys.stderr,
    )
    for w in result.warnings:
        _warn(w)
    return EXIT_OK


def cmd_report(args: argparse.Namespace) -> int:
    product = _product(args)
    if product is None:
        _warn(f"no {config.CONFIG_NAME} found: product fields are left blank (run `cra-kit init`)")
        product = Product(name="", version="")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    aware, notes = reporting.parse_when(args.aware, now)
    if args.kind == "vulnerability":
        fix, fix_notes = reporting.parse_when(args.fix_available, now) if args.fix_available else (None, [])
        finding = None
        if args.scan or args.advisory:
            if not (args.scan and args.advisory):
                raise CliError("--scan and --advisory are used together")
            finding = _find_finding(_load_json(args.scan, "scan result"), args.advisory)
        pack = reporting.vulnerability_pack(product, aware, fix, finding, notes + fix_notes)
    else:
        notified, n_notes = reporting.parse_when(args.notified, now) if args.notified else (None, [])
        if notified and notified < aware:
            raise CliError("--notified is earlier than --aware")
        pack = reporting.incident_pack(product, aware, notified, notes + n_notes)
    pack.generated = now

    if args.format == "json":
        text = json.dumps(pack.to_dict(now), indent=2) + "\n"
    else:
        text = reporting.to_markdown(pack, now)
    _emit(text, args.output)
    out = sys.stderr if not args.output else sys.stdout
    print("\nDeadlines:", file=out)
    for line in reporting.summary_lines(pack, now):
        print(line, file=out)
    return EXIT_OK


def _find_finding(scan_data: dict, advisory: str) -> dict:
    wanted = advisory.strip().upper()
    for f in scan_data.get("findings", []):
        ids = {f.get("id", "").upper(), *(a.upper() for a in f.get("aliases", [])), *(c.upper() for c in f.get("cves", []))}
        if wanted in ids:
            return f
    known = sorted({f.get("id", "") for f in scan_data.get("findings", [])})
    hint = f" Advisories in the file: {', '.join(known[:10])}" + (" ..." if len(known) > 10 else "") if known else ""
    raise CliError(f"advisory {advisory} not found in the scan file.{hint}")
