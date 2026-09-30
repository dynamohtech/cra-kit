# cra-kit

**Open-source toolkit for the EU Cyber Resilience Act (CRA).** Generate the SBOM, check your dependencies
for known and actively exploited vulnerabilities, see where your product stands against the essential
requirements, and have the Article 14 reporting pack ready before the 24-hour clock starts.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)
![Runtime dependencies: 0](https://img.shields.io/badge/runtime%20dependencies-0-brightgreen.svg)

> **Why now:** CRA reporting obligations apply from **11 September 2026**, including for products already on the
> market. If you become aware of an actively exploited vulnerability or a severe incident in a product you sell in
> the EU, you must send an early warning within **24 hours**. The rest of the Regulation, including the Annex I
> essential requirements, applies from **11 December 2027**.

```text
$ cra-kit sbom
Wrote sbom.cdx.json: 5 components (2 direct, 2 transitive, 1 not stated) from 2 dependency file(s)
  read package-lock.json
  read requirements.txt

$ cra-kit scan
Scanned 5 components: 3 with known vulnerabilities (3 advisories), 1 known exploited (CISA KEV).
Known-exploited advisories are listed first. If one is exploitable in your product, CRA Article 14
requires an early warning within 24 hours of becoming aware.

KEV  SEVERITY  COMPONENT                     ADVISORY                             FIXED IN
YES  HIGH      pkg:npm/express@4.18.2        GHSA-test-kev1-0001 (CVE-2099-0001)  4.19.2
no   CRITICAL  pkg:npm/%40babel/core@7.23.0  GHSA-test-scop-0003 (CVE-2099-0003)  7.23.2
no   UNKNOWN   pkg:pypi/django@4.2.7         PYSEC-TEST-0002 (CVE-2099-0002)      4.2.8
```

<sub>Sample run on the test fixtures, with synthetic advisory data.</sub>

## What it does

| Command | What you get | CRA obligation |
| --- | --- | --- |
| `cra-kit sbom` | CycloneDX 1.6 JSON SBOM from your lockfiles, with direct and transitive dependencies marked | Annex I, Part II(1): SBOM covering at least the top-level dependencies |
| `cra-kit scan` | Every component checked against [OSV.dev](https://osv.dev); matches flagged if listed in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Annex I, Part I(2)(a): no known exploitable vulnerabilities. Part II(2): remediate without delay |
| `cra-kit assess` | Scope check (Article 2 exclusions), product class (Annex III / IV), conformity route (Article 32), and a readiness report on all 22 Annex I requirements, using the SBOM and scan as evidence | Articles 2, 7, 8, 13(8), 32; Annex I |
| `cra-kit report` | Article 14 pack: exact 24h / 72h / final deadlines and every field each report needs, prefilled from your settings and the scan | Article 14(1)–(8) |

See [`examples/`](examples/) for a full readiness report and reporting pack for a fictional product.

## Install

Python 3.11 or newer. No runtime dependencies.

```bash
pipx install git+https://github.com/dynamohtech/cra-kit
# or
pip install git+https://github.com/dynamohtech/cra-kit
```

## Quickstart

Run these in your product's repository:

```bash
cra-kit init --manufacturer "Your Company Ltd"   # creates cra-kit.toml and cra-answers.toml
cra-kit sbom                                      # writes sbom.cdx.json
cra-kit scan --format json -o scan.json           # needs internet access to api.osv.dev and cisa.gov
# answer the questions in cra-answers.toml (or use: cra-kit assess --interactive)
cra-kit assess --scan scan.json -o cra-readiness.md
```

When something happens:

```bash
# Actively exploited vulnerability, prefilled from a scan finding
cra-kit report vulnerability --aware "2026-10-01T09:30+02:00" \
    --scan scan.json --advisory CVE-2024-12345 -o report-CVE-2024-12345.md

# Re-run once the fix ships to get the final-report deadline
cra-kit report vulnerability --aware "2026-10-01T09:30+02:00" --fix-available 2026-10-06 ...

# Severe incident
cra-kit report incident --aware now -o incident-pack.md
```

Times accept ISO 8601 or `now`. A time without a time zone is taken as UTC and the pack says so.

## Settings: `cra-kit.toml`

```toml
[product]
name = "Example Smart Lock Hub"
version = "2.4.0"
manufacturer = "Example Devices BV"      # who develops or manufactures it and markets it under their name (Article 3(13))
type = "device"                          # application | firmware | device | library | framework | operating-system
security_contact = "security@example.com"  # Annex I, Part II(6)
support_period_end = "2031-12-31"       # Article 13(8): at least five years in most cases
member_states = ["NL", "BE", "DE"]      # needed in the 24-hour early warning
main_establishment = "NL"               # where cybersecurity decisions are taken; decides which CSIRT gets your reports (Article 14(7))
```

## Supported dependency files

| Ecosystem | Files | Direct vs transitive |
| --- | --- | --- |
| JavaScript (npm) | `package-lock.json` (v1, v2, v3), `npm-shrinkwrap.json` | Yes |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` | Yes for lockfiles (read with `pyproject.toml` / `Pipfile`); not stated for requirements files |
| Rust | `Cargo.lock` | Yes |
| Go | `go.mod` | Yes (`// indirect`) |

Development-only dependencies are left out unless you pass `--include-dev`. Files cra-kit recognises but cannot
read yet (`yarn.lock`, `pnpm-lock.yaml`, `bun.lock`, `composer.lock`, `Gemfile.lock`, Maven, Gradle, NuGet) are
reported as warnings so an SBOM is never silently incomplete. `cra-kit scan` also accepts CycloneDX JSON SBOMs
produced by other tools.

## Use it in CI

Fail the build when a dependency has a vulnerability that is known to be exploited in the wild:

```yaml
# .github/workflows/cra.yml
name: CRA checks
on: [push, pull_request]
jobs:
  cra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install git+https://github.com/dynamohtech/cra-kit
      - run: cra-kit sbom
      - run: cra-kit scan --format markdown -o scan.md --fail-on kev
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cra-evidence
          path: |
            sbom.cdx.json
            scan.md
```

Exit codes: `0` success, `1` findings matched `--fail-on`, `2` error (including when `--fail-on kev` is set but the
KEV catalogue could not be checked).

## How it works, and what leaves your machine

- **Reads files only.** Parsers read lockfiles as data. cra-kit never runs your build, your package manager or
  your code, so it is safe to run on untrusted repositories.
- **No runtime dependencies.** Standard library only, so adding it does not grow your own supply chain.
- **Network use is limited to `scan`.** It sends package URLs (name and version, for example
  `pkg:npm/express@4.18.2`) to `api.osv.dev` and downloads the public KEV feed from `cisa.gov`. No source code,
  file names or product details are sent. `sbom`, `assess` and `report` work fully offline.
- **Cautious deadlines.** Report deadlines use the earliest reading of each rule, with no extension for weekends
  or public holidays.

## Limits

- cra-kit is a structured self-check and a set of working documents. **It is not legal advice** and does not
  replace a conformity assessment, a notified body, or your own judgement about exploitability.
- The scan covers third-party components with published advisories. It does not find vulnerabilities in your own
  code.
- A KEV match means the vulnerability is exploited somewhere, not necessarily in your product. It is a signal to
  assess now, because the 24-hour clock starts when you become aware.

## Roadmap

- More lockfiles: yarn, pnpm, bun, Maven, Gradle, NuGet, Composer
- VEX (CycloneDX VEX / OpenVEX) so you can record "not affected" decisions
- CSAF advisories for informing users (Article 14(8))
- Technical documentation (Annex VII) and EU declaration of conformity (Annex V) templates
- A ready-made GitHub Action

Issues and pull requests are welcome.

## Need help with CRA readiness?

cra-kit is built and maintained by [Emmanuel Adegbaju (Dynamoh Tech)](https://dynamotech.vercel.app/).
If you want help rolling it out across a product portfolio, wiring it into your release pipeline, or preparing your
vulnerability handling and reporting process, get in touch through the website or open an issue.

## License

[Apache License 2.0](LICENSE). Regulation text: [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj).
