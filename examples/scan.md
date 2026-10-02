# Vulnerability scan

Scanned **4 components**: **1** has known vulnerabilities (1 open advisory).
**1 more advisory** is closed by VEX statements (cra-kit.vex.json) and listed separately below.
**1 advisory** is in CISA's Known Exploited Vulnerabilities catalogue. Assess these first: if the vulnerability is actively exploited in your product, CRA Article 14 requires an early warning within 24 hours of becoming aware of it.

| Component | Advisory | Severity | Exploited (KEV) | Fixed in | Summary |
| --- | --- | --- | --- | --- | --- |
| `pkg:npm/express@4.18.2` | [GHSA-test-kev1-0001](https://osv.dev/vulnerability/GHSA-test-kev1-0001) (CVE-2099-0001) | HIGH | Yes, since 2026-09-15 | 4.19.2 | Synthetic open redirect in express (VEX: under investigation) |

## Closed by VEX

| Component | Advisory | Status | Justification or statement | Decided |
| --- | --- | --- | --- | --- |
| `pkg:npm/%40babel/core@7.23.0` | [GHSA-test-scop-0003](https://osv.dev/vulnerability/GHSA-test-scop-0003) (CVE-2099-0003) | not affected | vulnerable_code_not_in_execute_path | 2026-09-30 |

_Sources: OSV.dev and CISA KEV. A listed advisory affects the component version; whether it is exploitable in your product needs your own assessment._
