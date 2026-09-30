# Security policy

cra-kit helps manufacturers handle vulnerabilities, so it follows the same practice itself.

## Reporting a vulnerability

Please report security issues privately through GitHub:
**Security → Report a vulnerability** on this repository
(<https://github.com/dynamohtech/cra-kit/security/advisories/new>).

Do not open a public issue for a security problem.

Please include the version (`cra-kit --version`), what you ran, and what an attacker could achieve.

## What to expect

- An acknowledgement within 5 working days.
- An assessment and a planned fix date as soon as the issue is confirmed.
- A GitHub security advisory and a CVE, where appropriate, when the fix is released. You are credited unless you
  ask not to be.

## Supported versions

Security fixes go into the latest release. cra-kit is pre-1.0, so please upgrade to the latest version.

## Scope notes

- cra-kit reads lockfiles as data and never executes project code. A way to make it execute code, write outside
  the paths you give it, or send data other than package URLs to OSV.dev is a vulnerability.
- Wrong or missing advisories come from the upstream databases: report those to
  [OSV.dev](https://github.com/google/osv.dev) or the originating database.
