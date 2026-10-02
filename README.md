# cra-kit

**Open-source toolkit for the EU Cyber Resilience Act (CRA).** Generate the SBOM, check your dependencies
for known and actively exploited vulnerabilities, record which ones actually affect you, see where your product
stands against the essential requirements, draft the technical file, and have the Article 14 reporting pack ready
before the 24-hour clock starts. Runs on your machine or as a GitHub Action.

[![CI](https://github.com/dynamohtech/cra-kit/actions/workflows/ci.yml/badge.svg)](https://github.com/dynamohtech/cra-kit/actions/workflows/ci.yml)
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

$ cra-kit scan
Scanned 5 components: 3 with known vulnerabilities (3 open advisories), 1 known exploited (CISA KEV).

KEV  SEVERITY  COMPONENT                     ADVISORY                             FIXED IN
YES  HIGH      pkg:npm/express@4.18.2        GHSA-test-kev1-0001 (CVE-2099-0001)  4.19.2
no   CRITICAL  pkg:npm/%40babel/core@7.23.0  GHSA-test-scop-0003 (CVE-2099-0003)  7.23.2
no   UNKNOWN   pkg:pypi/django@4.2.7         PYSEC-TEST-0002 (CVE-2099-0002)      4.2.8

$ cra-kit vex add --id CVE-2099-0001 --component pkg:npm/express@4.18.2 \
    --status not_affected --justification vulnerable_code_not_in_execute_path
Recorded CVE-2099-0001 as not_affected for pkg:npm/express@4.18.2 in cra-kit.vex.json

$ cra-kit scan --fail-on kev
Scanned 5 components: 2 with known vulnerabilities (2 open advisories), 0 known exploited (CISA KEV); 1 closed by VEX.
...
Closed by VEX:
STATUS        COMPONENT               ADVISORY                             REASON
not_affected  pkg:npm/express@4.18.2  GHSA-test-kev1-0001 (CVE-2099-0001)  vulnerable_code_not_in_execute_path
```

<sub>Sample run on the test fixtures, with synthetic advisory data.</sub>

## What it does

| Command | What you get | CRA obligation |
| --- | --- | --- |
| `cra-kit sbom` | CycloneDX 1.6 JSON SBOM from your lockfiles (npm, pnpm, yarn, Python, Rust, Go), with direct and transitive dependencies marked | Annex I, Part II(1): SBOM covering at least the top-level dependencies |
| `cra-kit scan` | Every component checked against [OSV.dev](https://osv.dev); matches flagged if listed in [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog); your VEX decisions applied | Annex I, Part I(2)(a): no known exploitable vulnerabilities. Part II(2): remediate without delay |
| `cra-kit vex` | Record and list "not affected", "affected", "fixed" or "under investigation" decisions as [OpenVEX](https://openvex.dev) | Annex I, Part II(1)–(2): document and handle vulnerabilities |
| `cra-kit assess` | Scope check (Article 2 exclusions), product class (Annex III / IV), conformity route (Article 32), and a readiness report on all 22 Annex I requirements, using the SBOM, scan and VEX as evidence | Articles 2, 7, 8, 13(8), 32; Annex I |
| `cra-kit techfile` | Drafts of the technical documentation, EU declaration of conformity, simplified declaration and user information, point by point, prefilled from everything above | Articles 13(13), 13(20), 28, 31; Annexes II, V, VI, VII |
| `cra-kit report` | Article 14 pack: exact 24h / 72h / final deadlines and every field each report needs, prefilled from your settings and the scan | Article 14(1)–(8) |
| GitHub Action | SBOM and scan on every push, with the report in the job summary and a failed check on known-exploited vulnerabilities | Continuous vulnerability handling |

See [`examples/`](examples/) for a full readiness report, reporting pack, VEX file and technical file for a
fictional product.

## Install

Python 3.11 or newer. No runtime dependencies.

```bash
pipx install git+https://github.com/dynamohtech/cra-kit@v0.2.0
# or
pip install git+https://github.com/dynamohtech/cra-kit@v0.2.0
```

## Quickstart

Run these in your product's repository:

```bash
cra-kit init --manufacturer "Your Company Ltd"   # creates cra-kit.toml and cra-answers.toml
cra-kit sbom                                      # writes sbom.cdx.json
cra-kit scan --format json -o scan.json           # needs internet access to api.osv.dev and cisa.gov
cra-kit vex add --id CVE-... --component pkg:... --status not_affected --justification ...   # for each one you've assessed
# answer the questions in cra-answers.toml (or use: cra-kit assess --interactive)
cra-kit assess --scan scan.json -o cra-readiness.md
cra-kit techfile --scan scan.json                 # drafts in ./cra-technical-file/
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

## Record decisions with VEX

A scan lists every advisory for every component version, but many do not affect your product: the vulnerable
function is never called, the feature is disabled, and so on. Record that decision once and cra-kit stops counting
it, while keeping an audit trail of who decided what, when and why.

```bash
cra-kit vex add --id CVE-2024-29041 --component pkg:npm/express@4.18.2 \
    --status not_affected --justification vulnerable_code_not_in_execute_path
cra-kit vex add --id CVE-2024-45590 --component pkg:npm/body-parser \
    --status affected --action "Upgrade to body-parser 1.20.3 in release 2.4.1"
cra-kit vex list
```

- Decisions go to `cra-kit.vex.json` (OpenVEX v0.2.0); `scan` picks that file up automatically. Pass other files
  with `--vex`, including CycloneDX documents with `vulnerabilities[].analysis`.
- `not_affected` and `fixed` close a finding: it moves to a "Closed by VEX" section and no longer counts towards
  totals or `--fail-on`. It is never hidden.
- A component without a version (`pkg:npm/body-parser`) covers every version. The latest decision wins.
- Statuses: `not_affected` (needs `--justification` or `--impact`), `affected` (needs `--action`), `fixed`,
  `under_investigation`.

## Draft the technical file

```bash
cra-kit techfile --scan scan.json
```

writes `cra-technical-file/` with drafts that follow the regulation point by point:

| File | Content | Legal basis |
| --- | --- | --- |
| `01-technical-documentation.md` | Technical documentation, with the Annex I requirement tables and evidence | Article 31, Annex VII |
| `02-eu-declaration-of-conformity.md` | EU declaration of conformity | Article 28, Annex V |
| `03-simplified-declaration.md` | Simplified declaration | Article 13(20), Annex VI |
| `04-user-information.md` | Information and instructions to the user | Annex II |

Facts cra-kit knows (product, manufacturer, SBOM, scan, VEX, support period, readiness answers, conformity route)
are filled in. Everything else is marked **TODO**. Running the command again never overwrites your edits unless you
pass `--force`.

## GitHub Action

```yaml
# .github/workflows/cra.yml
name: CRA checks
on: [push, pull_request]
permissions:
  contents: read
jobs:
  cra:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - id: cra
        uses: dynamohtech/cra-kit@v0.2.0
        with:
          fail-on: kev          # none | any | kev
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: cra-evidence
          path: |
            ${{ steps.cra.outputs.sbom-file }}
            ${{ steps.cra.outputs.scan-file }}
```

| Input | Default | Meaning |
| --- | --- | --- |
| `path` | `.` | Project folder, lockfile or CycloneDX SBOM |
| `fail-on` | `kev` | Fail on `none`, `any` open finding, or only `kev` (known exploited) |
| `include-dev` | `false` | Include development-only dependencies |
| `vex` | `cra-kit.vex.json` if present | OpenVEX or CycloneDX VEX file |
| `config` | `cra-kit.toml` if present | Product settings |
| `sbom-file` / `scan-file` | `sbom.cdx.json` / `cra-scan.json` | Where to write the SBOM and the scan result |
| `working-directory` | `.` | Folder to run in |
| `python-version` | `3.12` | Python to set up; empty to use the runner's own |

Outputs: `sbom-file`, `scan-file`, `components`, `vulnerable-components`, `open-advisories`, `known-exploited`,
`closed-by-vex`. The scan report is added to the job summary, and each open known-exploited finding becomes an error
annotation.

Inputs reach cra-kit as environment variables, never through a shell, and GitHub workflow commands are paused while
third-party text (advisory summaries, VEX statements, file names) is printed, so that text cannot inject commands
into your workflow.

Exit codes, for the action and the CLI: `0` success, `1` open findings matched `fail-on`, `2` error (including when
`fail-on: kev` is set but the KEV catalogue could not be checked).

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
manufacturer_address = "1 Example Street, Amsterdam"   # Annexes II and V
website = "https://example.com"
intended_purpose = "Controls smart door locks in homes."  # Annex II(4), Annex VII(1)(a)
declaration_url = "https://example.com/cra/declaration"  # Annex II(6), Article 13(20)
main_establishment = "NL"               # where cybersecurity decisions are taken; decides which CSIRT gets your reports (Article 14(7))
```

## Supported dependency files

| Ecosystem | Files | Direct vs transitive |
| --- | --- | --- |
| JavaScript | `package-lock.json` (v1–v3), `npm-shrinkwrap.json`, `pnpm-lock.yaml` (v5.x, v6, v9), `yarn.lock` (classic and Berry v2+) | Yes |
| Python | `poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt` | Yes for lockfiles (read with `pyproject.toml` / `Pipfile`); not stated for requirements files |
| Rust | `Cargo.lock` | Yes |
| Go | `go.mod` | Yes (`// indirect`) |

Development-only dependencies are left out unless you pass `--include-dev`. For pnpm and yarn, cra-kit rebuilds the
dependency graph from the lockfile and walks it from your `package.json`, so a package used only by dev tools is
excluded even when it is not marked as dev in the lockfile. Workspaces are supported. Packages installed from git, a
URL or a local path are reported as warnings to check by hand.

Files cra-kit recognises but cannot read yet (`bun.lock`, `composer.lock`, `Gemfile.lock`, Maven, Gradle, NuGet)
are reported as warnings so an SBOM is never silently incomplete. `cra-kit scan` also accepts CycloneDX JSON SBOMs
produced by other tools.

## How it works, and what leaves your machine

- **Reads files only.** Parsers read lockfiles as data. cra-kit never runs your build, your package manager or
  your code, so it is safe to run on untrusted repositories.
- **No runtime dependencies.** Standard library only, so adding it does not grow your own supply chain. pnpm and
  yarn Berry lockfiles are YAML; cra-kit reads them with a small built-in reader checked against PyYAML in tests.
- **Network use is limited to `scan`.** It sends package URLs (name and version, for example
  `pkg:npm/express@4.18.2`) to `api.osv.dev` and downloads the public KEV feed from `cisa.gov`. No source code,
  file names or product details are sent. Every other command works fully offline.
- **Tested against reality.** Lockfile fixtures are real files produced by pnpm 7/8/9, yarn 1 and yarn 4 and checked
  against npm's own resolution. A separate CI workflow checks the scanner against the live OSV.dev and CISA data
  every week.
- **Cautious deadlines.** Report deadlines use the earliest reading of each rule, with no extension for weekends
  or public holidays.

## Limits

- cra-kit is a structured self-check and a set of working documents. **It is not legal advice** and does not
  replace a conformity assessment, a notified body, or your own judgement about exploitability.
- The scan covers third-party components with published advisories. It does not find vulnerabilities in your own
  code.
- A KEV match means the vulnerability is exploited somewhere, not necessarily in your product. It is a signal to
  assess now, because the 24-hour clock starts when you become aware.
- VEX version ranges in CycloneDX documents are not evaluated; only exact versions are matched.

## Roadmap

- More lockfiles: bun, Maven, Gradle, NuGet, Composer
- CSAF advisories for informing users (Article 14(8))
- Signed releases with a published SBOM for cra-kit itself

Issues and pull requests are welcome.

## Need help with CRA readiness?

cra-kit is built and maintained by [Emmanuel Adegbaju (Dynamoh Tech)](https://dynamotech.vercel.app/).
If you want help rolling it out across a product portfolio, wiring it into your release pipeline, or preparing your
vulnerability handling, technical file and reporting process, get in touch through the website or open an issue.

## License

[Apache License 2.0](LICENSE). Regulation text: [Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj).
