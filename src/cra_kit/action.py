"""Entry point for the cra-kit GitHub Action (action.yml at the repository root).

Inputs arrive as environment variables set by action.yml, never through a
shell command line, so a crafted input cannot inject shell commands. The
action writes the SBOM and the scan result, sets step outputs, adds the scan
report to the job summary and annotates open known-exploited findings.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from cra_kit import cli, config
from cra_kit import scan as scan_mod
from cra_kit.sbom.cyclonedx import summarize

TRUE = {"1", "true", "yes", "on"}


def _escape(text: str) -> str:
    """Escape data for a GitHub workflow command."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(text: str) -> str:
    return _escape(text).replace(":", "%3A").replace(",", "%2C")


def _append(path_var: str, text: str, env: dict) -> None:
    target = env.get(path_var)
    if target:
        with open(target, "a", encoding="utf-8") as fh:
            fh.write(text)


def run(env: dict | None = None) -> int:
    env = dict(os.environ if env is None else env)
    target = Path(env.get("CRA_PATH") or ".")
    fail_on = (env.get("CRA_FAIL_ON") or "kev").strip().lower()
    if fail_on not in ("none", "any", "kev"):
        print(f"::error::fail-on must be none, any or kev (got {_escape(fail_on)})")
        return cli.EXIT_ERROR
    include_dev = (env.get("CRA_INCLUDE_DEV") or "").strip().lower() in TRUE
    sbom_file = env.get("CRA_SBOM_FILE") or "sbom.cdx.json"
    scan_file = env.get("CRA_SCAN_FILE") or "cra-scan.json"
    vex_file = (env.get("CRA_VEX") or "").strip()
    config_file = (env.get("CRA_CONFIG") or "").strip()

    try:
        if not target.exists():
            raise cli.CliError(f"path not found: {target} (relative to {Path.cwd()})")
        product = config.load(Path(config_file) if config_file else None)
        if cli._is_cyclonedx(target):
            sbom_path = target  # scan an SBOM made elsewhere; do not overwrite it
        else:
            sbom_args = ["sbom", str(target), "-o", sbom_file] + (["--include-dev"] if include_dev else [])
            sbom_args += ["--config", config_file] if config_file else []
            code = cli.main(sbom_args)
            if code:
                print("::error title=cra-kit::SBOM generation failed; see the log above")
                return code
            sbom_path = Path(sbom_file)
        summary = summarize(json.loads(sbom_path.read_text(encoding="utf-8")))
        result = cli.run_scan(sbom_path, vex_paths=[vex_file] if vex_file else None, product=product)
    except (cli.CliError, ValueError, FileNotFoundError) as exc:
        print(f"::error title=cra-kit::{_escape(str(exc))}")
        return cli.EXIT_ERROR

    Path(scan_file).write_text(json.dumps(result.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(cli._scan_table(result))
    for err in result.errors:
        print(f"::warning title=cra-kit::{_escape(err)}")
    for f in result.known_exploited:
        title = _escape_property(f"Known exploited vulnerability in {f.purl}")
        message = (
            f"{f.id} ({', '.join(f.cves) or 'no CVE'}) is in the CISA KEV catalogue. CRA Article 14: if it is "
            "exploited in your product, an early warning is due within 24 hours of becoming aware."
        )
        print(f"::error title={title}::{_escape(message)}")

    outputs = {
        "sbom-file": str(sbom_path),
        "scan-file": scan_file,
        "components": summary["components"],
        "vulnerable-components": result.vulnerable_components,
        "open-advisories": len(result.open_findings),
        "known-exploited": len(result.known_exploited),
        "closed-by-vex": len(result.closed_findings),
    }
    _append("GITHUB_OUTPUT", "".join(f"{k}={v}\n" for k, v in outputs.items()), env)
    _append("GITHUB_STEP_SUMMARY", scan_mod.to_markdown(result) + "\n", env)
    return cli.fail_code(result, fail_on)


def main() -> int:
    return run()


if __name__ == "__main__":
    sys.exit(main())
