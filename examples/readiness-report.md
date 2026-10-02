# CRA readiness report: Example Smart Lock Hub 2.4.0

Generated 2026-09-30 by cra-kit 0.2.0. This is a structured self-check against Regulation (EU) 2024/2847, not legal advice.

## Summary

| | |
| --- | --- |
| Scope | **In scope** |
| Product category | Important product, Class I (Annex III) |
| Conformity assessment | Self-assessment (module A) only if you fully apply harmonised standards, common specifications or a European cybersecurity certification scheme at assurance level at least 'substantial'; otherwise a third-party assessment (EU-type examination, module B+C, or full quality assurance, module H) (Article 32(2)). |
| Requirements done | 8 of 22 |
| Partial | 7 |
| At risk | 1 |
| Not started | 4 |
| Not answered | 1 |
| Manufacturer | Example Devices BV |

**Key dates:** 2026-06-11: Rules on notified bodies apply (Chapter IV, Articles 35 to 51); 2026-09-11: Reporting of actively exploited vulnerabilities and severe incidents applies (Article 14), including for products already on the market (Article 69(3)); 2027-12-11: The rest of the Regulation applies, including the Annex I essential requirements (Article 71(2)).

> **Act now:** The scan found dependency vulnerabilities listed as actively exploited. Check whether they are exploitable in your product: if so, Article 14 requires an early warning within 24 hours.

## Scope

- Software or hardware with a data connection, supplied commercially on the EU market, with no exclusion.

Matched categories:
- Annex III Class I: Smart home products with security functionalities, including smart door locks, security cameras, baby monitoring systems and alarm systems

## Essential requirements (Annex I, Part I)

| ID | Requirement | Status | Evidence and notes |
| --- | --- | --- | --- |
| I.1 | Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks | Partial |  |
| I.2a | Made available on the market without known exploitable vulnerabilities | At risk | 1 dependency advisory closed by recorded VEX decisions (cra-kit.vex.json); dependency scan found known vulnerabilities in 1 component, 1 of them listed as exploited in the wild (CISA KEV) |
| I.2b | Made available with a secure by default configuration, including the possibility to reset to the original state | Done |  |
| I.2c | Vulnerabilities can be addressed through security updates (automatic updates by default where applicable, with an opt-out) | Done | Signed OTA updates, automatic by default, opt-out in the app |
| I.2d | Protection from unauthorised access by appropriate control mechanisms (authentication, identity or access management) | Done |  |
| I.2e | Confidentiality of stored, transmitted or otherwise processed data protected (e.g. encryption) | Done |  |
| I.2f | Integrity of stored, transmitted or otherwise processed data, commands, programs and configuration protected | Partial |  |
| I.2g | Only data that is adequate, relevant and limited to what is necessary is processed (data minimisation) | Done |  |
| I.2h | Availability of essential and basic functions protected, including resilience against denial-of-service attacks | Partial |  |
| I.2i | Negative impact on the availability of services provided by other devices or networks is minimised | Not applicable |  |
| I.2j | Designed, developed and produced to limit attack surfaces, including external interfaces | Partial |  |
| I.2k | Designed, developed and produced to reduce the impact of an incident using exploitation mitigation mechanisms | Not started |  |
| I.2l | Security-related information provided by recording and monitoring relevant internal activity, with a user opt-out | Not started |  |
| I.2m | Users can securely and easily remove all data and settings permanently; where data can be transferred to other products or systems, this is done securely | Done |  |

## Vulnerability handling (Annex I, Part II)

| ID | Requirement | Status | Evidence and notes |
| --- | --- | --- | --- |
| II.1 | Identify and document vulnerabilities and components, including a software bill of materials in a commonly used, machine-readable format covering at the very least the top-level dependencies | Partial | CycloneDX 1.6 SBOM: 4 components (2 direct, 2 transitive, 0 relationship unknown); also document how vulnerabilities in these components are tracked |
| II.2 | Address and remediate vulnerabilities without delay, including by providing security updates (separately from functionality updates where technically feasible) | Partial |  |
| II.3 | Apply effective and regular tests and reviews of the security of the product | Partial |  |
| II.4 | Once a security update is available, share and publicly disclose information about fixed vulnerabilities (description, affected products, impact, severity, remediation) | Not started |  |
| II.5 | Put in place and enforce a policy on coordinated vulnerability disclosure | Not started |  |
| II.6 | Facilitate the sharing of information about potential vulnerabilities, including a contact address for reporting them | Not answered | security contact: security@example-devices.test |
| II.7 | Provide mechanisms to securely distribute updates so vulnerabilities are fixed or mitigated in a timely and, where applicable, automatic manner | Done |  |
| II.8 | Disseminate security updates without delay and free of charge (unless otherwise agreed with a business user for a tailor-made product), with advisory messages | Done |  |

## Gaps to close first

- **I.2a** (At risk): Made available on the market without known exploitable vulnerabilities
- **I.2k** (Not started): Designed, developed and produced to reduce the impact of an incident using exploitation mitigation mechanisms
- **I.2l** (Not started): Security-related information provided by recording and monitoring relevant internal activity, with a user opt-out
- **II.4** (Not started): Once a security update is available, share and publicly disclose information about fixed vulnerabilities (description, affected products, impact, severity, remediation)
- **II.5** (Not started): Put in place and enforce a policy on coordinated vulnerability disclosure
- **II.6** (Not answered): Facilitate the sharing of information about potential vulnerabilities, including a contact address for reporting them

## Support period

Support period ends 2031-12-31 (5.3 years from today).

## Reporting (applies from 11 September 2026)

Actively exploited vulnerabilities and severe incidents must be reported through the CRA Single Reporting Platform: an early warning within 24 hours of becoming aware, a notification within 72 hours, and a final report (14 days after a fix is available for vulnerabilities; one month after the notification for incidents). Impacted users must also be informed (Article 14(8)). Prepare the pack in advance with `cra-kit report vulnerability` or `cra-kit report incident`.

Regulation text: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
