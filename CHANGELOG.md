# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-10-02

### Added

- **pnpm and yarn lockfiles**: `pnpm-lock.yaml` (v5.x, v6, v9) and `yarn.lock` (classic v1 and Berry v2+),
  including workspaces, aliases, peer-dependency variants and yarn's `patch:` protocol. Development dependencies are
  excluded by walking the dependency graph from `package.json`. Fixtures are real lockfiles from pnpm 7/8/9, yarn 1
  and yarn 4, checked against npm's resolution of the same project.
- **VEX**: `cra-kit vex add` and `cra-kit vex list` record decisions as OpenVEX v0.2.0. `cra-kit scan --vex` (default
  `./cra-kit.vex.json`) reads OpenVEX and CycloneDX VEX. `not_affected` and `fixed` findings are closed: listed
  separately, excluded from counts and `--fail-on`, never hidden. The readiness report cites them as evidence.
- **GitHub Action** (`action.yml`): SBOM and scan in CI, report in the job summary, error annotations for open
  known-exploited findings, step outputs, `fail-on` gate.
- **`cra-kit techfile`**: drafts of the technical documentation (Annex VII), EU declaration of conformity (Annex V),
  simplified declaration (Annex VI) and user information (Annex II), prefilled from settings, readiness answers,
  SBOM, scan and VEX. Never overwrites existing files without `--force`.
- `cra-kit.toml`: optional `manufacturer_address`, `website`, `intended_purpose`, `declaration_url`.

### Fixed

- npm: an aliased direct dependency (`"x": "npm:real@1.0.0"`) is now marked direct.
- No Python traceback when output is piped into a command that stops reading early (for example `| head`).

### Security

- The GitHub Action pauses workflow commands while it prints third-party text, rejects inputs containing line
  breaks, and passes inputs as environment variables only.
- Scan reports in Markdown escape HTML, table and link syntax in advisory and VEX text.

## [0.1.0] - 2026-09-30

### Added

- `cra-kit init`: product settings (`cra-kit.toml`) and a readiness answers file, with name and version read from
  `package.json`, `pyproject.toml` or `Cargo.toml`.
- `cra-kit sbom`: CycloneDX 1.6 JSON SBOM from npm (`package-lock.json` v1–v3, `npm-shrinkwrap.json`), Python
  (`poetry.lock`, `uv.lock`, `Pipfile.lock`, `requirements*.txt`), Rust (`Cargo.lock`) and Go (`go.mod`), with
  direct and transitive dependencies marked. Warns about lockfile types it cannot read yet.
- `cra-kit scan`: checks components against OSV.dev and flags advisories in the CISA Known Exploited
  Vulnerabilities catalogue; table, Markdown and JSON output; `--fail-on any|kev` for CI.
- `cra-kit assess`: scope check (Article 2), product class (Annex III and IV), conformity route (Article 32),
  support period check (Article 13(8)) and a readiness report on the 22 Annex I requirements, using the SBOM and
  scan as evidence. Interactive mode or a TOML answers file.
- `cra-kit report vulnerability|incident`: Article 14 reporting pack with 24-hour, 72-hour and final-report
  deadlines, the content each report needs, prefill from settings and scan findings, and the Article 14(8) user
  notice. Markdown or JSON.
