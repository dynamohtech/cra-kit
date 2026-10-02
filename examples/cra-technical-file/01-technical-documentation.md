# Technical documentation

Product: **Example Smart Lock Hub 2.4.0**. Legal basis: Regulation (EU) 2024/2847, Article 31 and Annex VII. Draft generated 2026-09-30 by cra-kit 0.2.0.

> Working draft. Complete every TODO, check every prefilled value, and have the final text reviewed. This is not legal advice.

Article 31(2): draw this up before the product is placed on the market and keep it updated, where appropriate, at least during the support period. Article 13(13): keep it, with the EU declaration of conformity, at the disposal of market surveillance authorities for at least 10 years after the product is placed on the market or for the support period, whichever is longer.

## 1. General description of the product

### (a) Intended purpose

A hub that connects smart door locks in homes to the owner's phone app over Wi-Fi.

### (b) Versions of software affecting compliance with the essential cybersecurity requirements

- Product version: 2.4.0
- **TODO:** list the firmware or software versions, and their components, that this documentation covers.

### (c) Hardware: photographs or illustrations of external features, marking and internal layout

**TODO:** attach photographs or illustrations.

### (d) User information and instructions (Annex II)

See [04-user-information.md](04-user-information.md).

## 2. Design, development, production and vulnerability handling

### (a) Design and development, including system architecture

**TODO:** describe the system architecture: how software components build on or feed into each other and integrate into the overall processing. Add drawings and schemes where applicable.

Third-party components (from the SBOM): 4 in total, 2 direct and 2 transitive.

### (b) Vulnerability handling processes

| Element | Where it is documented |
| --- | --- |
| Software bill of materials | `sbom.cdx.json` (CycloneDX 1.6, 4 components, generated 2026-09-30T15:00:00Z) |
| Coordinated vulnerability disclosure policy | `SECURITY.md` |
| Contact address for reporting vulnerabilities | security@example-devices.test |
| Secure distribution of updates | **TODO:** describe the technical solution (e.g. signed updates over an authenticated channel) |
| Dependency vulnerability monitoring | `scan.json`: OSV.dev and CISA KEV scan; 1 component with open advisories, 1 known exploited, 1 closed by VEX |
| Exploitability decisions (VEX) | `cra-kit.vex.json` |

Vulnerability handling requirements (Annex I, Part II):

| ID | Requirement | Status | Evidence and notes |
| --- | --- | --- | --- |
| II.1 | Identify and document vulnerabilities and components, including a software bill of materials in a commonly used, machine-readable format covering at the very least the top-level dependencies | Partial | CycloneDX 1.6 SBOM: 4 components (2 direct, 2 transitive, 0 relationship unknown); also document how vulnerabilities in these components are tracked |
| II.2 | Address and remediate vulnerabilities without delay, including by providing security updates (separately from functionality updates where technically feasible) | Partial | **TODO:** evidence |
| II.3 | Apply effective and regular tests and reviews of the security of the product | Partial | **TODO:** evidence |
| II.4 | Once a security update is available, share and publicly disclose information about fixed vulnerabilities (description, affected products, impact, severity, remediation) | Not started | **TODO:** evidence |
| II.5 | Put in place and enforce a policy on coordinated vulnerability disclosure | Not started | **TODO:** evidence |
| II.6 | Facilitate the sharing of information about potential vulnerabilities, including a contact address for reporting them | Not answered | security contact: security@example-devices.test |
| II.7 | Provide mechanisms to securely distribute updates so vulnerabilities are fixed or mitigated in a timely and, where applicable, automatic manner | Done | **TODO:** evidence |
| II.8 | Disseminate security updates without delay and free of charge (unless otherwise agreed with a business user for a tailor-made product), with advisory messages | Done | **TODO:** evidence |

### (c) Production and monitoring processes, and their validation

**TODO:** describe how the product is built, released and monitored, and how those processes are validated (for example CI checks, code review, release signing).

## 3. Cybersecurity risk assessment (Article 13)

**TODO:** attach or summarise the risk assessment the product is designed, developed, produced, delivered and maintained against, and explain how each essential requirement in Part I of Annex I applies.

How the essential cybersecurity requirements (Annex I, Part I) apply:

| ID | Requirement | Status | Evidence and notes |
| --- | --- | --- | --- |
| I.1 | Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks | Partial | **TODO:** evidence |
| I.2a | Made available on the market without known exploitable vulnerabilities | At risk | 1 dependency advisory closed by recorded VEX decisions (cra-kit.vex.json); dependency scan found known vulnerabilities in 1 component, 1 of them listed as exploited in the wild (CISA KEV) |
| I.2b | Made available with a secure by default configuration, including the possibility to reset to the original state | Done | **TODO:** evidence |
| I.2c | Vulnerabilities can be addressed through security updates (automatic updates by default where applicable, with an opt-out) | Done | Signed OTA updates, automatic by default, opt-out in the app |
| I.2d | Protection from unauthorised access by appropriate control mechanisms (authentication, identity or access management) | Done | **TODO:** evidence |
| I.2e | Confidentiality of stored, transmitted or otherwise processed data protected (e.g. encryption) | Done | **TODO:** evidence |
| I.2f | Integrity of stored, transmitted or otherwise processed data, commands, programs and configuration protected | Partial | **TODO:** evidence |
| I.2g | Only data that is adequate, relevant and limited to what is necessary is processed (data minimisation) | Done | **TODO:** evidence |
| I.2h | Availability of essential and basic functions protected, including resilience against denial-of-service attacks | Partial | **TODO:** evidence |
| I.2i | Negative impact on the availability of services provided by other devices or networks is minimised | Not applicable | **TODO:** evidence |
| I.2j | Designed, developed and produced to limit attack surfaces, including external interfaces | Partial | **TODO:** evidence |
| I.2k | Designed, developed and produced to reduce the impact of an incident using exploitation mitigation mechanisms | Not started | **TODO:** evidence |
| I.2l | Security-related information provided by recording and monitoring relevant internal activity, with a user opt-out | Not started | **TODO:** evidence |
| I.2m | Users can securely and easily remove all data and settings permanently; where data can be transferred to other products or systems, this is done securely | Done | **TODO:** evidence |

A requirement marked not applicable needs a written justification in the risk assessment.

## 4. Support period (Article 13(8))

- End of support period: 2031-12-31
- Support period ends 2031-12-31 (5.3 years from today).
- **TODO:** record the information taken into account to set the support period (for example the time users can reasonably expect to use the product, and the support periods of comparable products).

## 5. Harmonised standards, common specifications or certification schemes applied

| Standard, specification or scheme | Applied in full or in part | Parts applied |
| --- | --- | --- |
| **TODO:** | | |

Where none was applied, describe the solutions adopted to meet each essential requirement in Parts I and II of Annex I, and list the other technical specifications applied.

Conformity assessment route for this product (Important product, Class I (Annex III)): Self-assessment (module A) only if you fully apply harmonised standards, common specifications or a European cybersecurity certification scheme at assurance level at least 'substantial'; otherwise a third-party assessment (EU-type examination, module B+C, or full quality assurance, module H) (Article 32(2)).

## 6. Test reports

| Report | Date | Covers |
| --- | --- | --- |
| Dependency vulnerability scan (`scan.json`) | 2026-09-30 | Annex I, Part I(2)(a) and Part II(1), for third-party components only |
| **TODO:** security testing (e.g. penetration test, fuzzing, code review) | | Annex I, Part I and Part II(3) |

## 7. EU declaration of conformity

See [02-eu-declaration-of-conformity.md](02-eu-declaration-of-conformity.md).

## 8. Software bill of materials (on reasoned request from a market surveillance authority)

`sbom.cdx.json`.
