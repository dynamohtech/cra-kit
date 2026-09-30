# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

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
