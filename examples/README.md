# Examples

Sample input and output for a fictional product, **Example Smart Lock Hub** by
**Example Devices BV**. The vulnerability data is synthetic (IDs such as
`CVE-2099-0001` do not exist), so the files show the format without pointing
at real advisories.

| File | What it is | Made with |
| --- | --- | --- |
| [`cra-kit.toml`](cra-kit.toml) | Product settings | `cra-kit init`, then edited |
| [`cra-answers.toml`](cra-answers.toml) | Scope, classification and requirement answers | `cra-kit init`, then filled in |
| [`cra-kit.vex.json`](cra-kit.vex.json) | Two VEX decisions (OpenVEX): one not affected, one under investigation | `cra-kit vex add` |
| [`scan.md`](scan.md) | Vulnerability scan with the VEX decisions applied | `cra-kit scan --format markdown` |
| [`readiness-report.md`](readiness-report.md) | CRA readiness report | `cra-kit assess --scan scan.json` |
| [`cra-technical-file/`](cra-technical-file/) | Drafts of the technical documentation, EU declaration of conformity, simplified declaration and user information | `cra-kit techfile --scan scan.json` |
| [`vulnerability-pack.md`](vulnerability-pack.md) | Article 14 reporting pack for an actively exploited vulnerability | `cra-kit report vulnerability --aware 2026-09-30T11:20+02:00 --scan scan.json --advisory CVE-2099-0001` |
| [`generate.py`](generate.py) | Rebuilds these samples offline | `python examples/generate.py` |
