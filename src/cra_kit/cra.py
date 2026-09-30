"""Requirements of Regulation (EU) 2024/2847 (Cyber Resilience Act) used by cra-kit.

Texts are short summaries that stay close to the regulation's wording, with
the article or annex reference so users can check the source. They are not a
substitute for the regulation or for legal advice.
Source: https://eur-lex.europa.eu/eli/reg/2024/2847/oj
"""

from __future__ import annotations

REGULATION_URL = "https://eur-lex.europa.eu/eli/reg/2024/2847/oj"

KEY_DATES = [
    ("2026-06-11", "Rules on notified bodies apply (Chapter IV, Articles 35 to 51)"),
    ("2026-09-11", "Reporting of actively exploited vulnerabilities and severe incidents applies (Article 14), "
                   "including for products already on the market (Article 69(3))"),
    ("2027-12-11", "The rest of the Regulation applies, including the Annex I essential requirements (Article 71(2))"),
]

# Annex I, Part I: properties of the product. Point (1) plus the 13 items of point (2).
PART_I = [
    ("I.1", "Designed, developed and produced to ensure an appropriate level of cybersecurity based on the risks"),
    ("I.2a", "Made available on the market without known exploitable vulnerabilities"),
    ("I.2b", "Made available with a secure by default configuration, including the possibility to reset to the original state"),
    ("I.2c", "Vulnerabilities can be addressed through security updates (automatic updates by default where applicable, with an opt-out)"),
    ("I.2d", "Protection from unauthorised access by appropriate control mechanisms (authentication, identity or access management)"),
    ("I.2e", "Confidentiality of stored, transmitted or otherwise processed data protected (e.g. encryption)"),
    ("I.2f", "Integrity of stored, transmitted or otherwise processed data, commands, programs and configuration protected"),
    ("I.2g", "Only data that is adequate, relevant and limited to what is necessary is processed (data minimisation)"),
    ("I.2h", "Availability of essential and basic functions protected, including resilience against denial-of-service attacks"),
    ("I.2i", "Negative impact on the availability of services provided by other devices or networks is minimised"),
    ("I.2j", "Designed, developed and produced to limit attack surfaces, including external interfaces"),
    ("I.2k", "Designed, developed and produced to reduce the impact of an incident using exploitation mitigation mechanisms"),
    ("I.2l", "Security-related information provided by recording and monitoring relevant internal activity, with a user opt-out"),
    ("I.2m", "Users can securely and easily remove all data and settings permanently; where data can be transferred to other products or systems, this is done securely"),
]

# Annex I, Part II: vulnerability handling.
PART_II = [
    ("II.1", "Identify and document vulnerabilities and components, including a software bill of materials in a commonly used, machine-readable format covering at the very least the top-level dependencies"),
    ("II.2", "Address and remediate vulnerabilities without delay, including by providing security updates (separately from functionality updates where technically feasible)"),
    ("II.3", "Apply effective and regular tests and reviews of the security of the product"),
    ("II.4", "Once a security update is available, share and publicly disclose information about fixed vulnerabilities (description, affected products, impact, severity, remediation)"),
    ("II.5", "Put in place and enforce a policy on coordinated vulnerability disclosure"),
    ("II.6", "Facilitate the sharing of information about potential vulnerabilities, including a contact address for reporting them"),
    ("II.7", "Provide mechanisms to securely distribute updates so vulnerabilities are fixed or mitigated in a timely and, where applicable, automatic manner"),
    ("II.8", "Disseminate security updates without delay and free of charge (unless otherwise agreed with a business user for a tailor-made product), with advisory messages"),
]

# Annex III: important products. Class I (19 categories) and Class II (4).
ANNEX_III_CLASS_I = [
    "Identity management systems and privileged access management software and hardware, including authentication and access control readers, including biometric readers",
    "Standalone and embedded browsers",
    "Password managers",
    "Software that searches for, removes, or quarantines malicious software",
    "Products with digital elements with the function of virtual private network (VPN)",
    "Network management systems",
    "Security information and event management (SIEM) systems",
    "Boot managers",
    "Public key infrastructure and digital certificate issuance software",
    "Physical and virtual network interfaces",
    "Operating systems",
    "Routers, modems intended for the connection to the internet, and switches",
    "Microprocessors with security-related functionalities",
    "Microcontrollers with security-related functionalities",
    "Application specific integrated circuits (ASIC) and field-programmable gate arrays (FPGA) with security-related functionalities",
    "Smart home general purpose virtual assistants",
    "Smart home products with security functionalities, including smart door locks, security cameras, baby monitoring systems and alarm systems",
    "Internet connected toys covered by Directive 2009/48/EC that have social interactive features or location tracking features",
    "Personal wearable products with a health monitoring purpose not covered by Regulation (EU) 2017/745 or (EU) 2017/746, or personal wearable products intended for use by and for children",
]

ANNEX_III_CLASS_II = [
    "Hypervisors and container runtime systems that support virtualised execution of operating systems and similar environments",
    "Firewalls, intrusion detection and prevention systems",
    "Tamper-resistant microprocessors",
    "Tamper-resistant microcontrollers",
]

# Annex IV: critical products.
ANNEX_IV = [
    "Hardware devices with security boxes",
    "Smart meter gateways within smart metering systems and other devices for advanced security purposes, including for secure cryptoprocessing",
    "Smartcards or similar devices, including secure elements",
]

# Article 2 exclusions: (question id, question, legal basis).
EXCLUSIONS = [
    ("medical", "Is it a medical device or in vitro diagnostic medical device?", "Article 2(2): Regulations (EU) 2017/745 and 2017/746"),
    ("vehicle", "Is it covered by motor vehicle type-approval rules?", "Article 2(2): Regulation (EU) 2019/2144"),
    ("aviation", "Is it certified under the EU civil aviation safety rules?", "Article 2(3): Regulation (EU) 2018/1139"),
    ("marine", "Is it marine equipment?", "Article 2(4): Directive 2014/90/EU"),
    ("defence", "Was it developed or modified exclusively for national security or defence, or to process classified information?", "Article 2(7)"),
    ("spare_part", "Is it a spare part replacing an identical component, made to the same specifications?", "Article 2(6)"),
]

CONFORMITY = {
    "default": (
        "Any procedure in Article 32(1); usually internal control (module A): self-assessment by the "
        "manufacturer, followed by the EU declaration of conformity and CE marking."
    ),
    "class_i": (
        "Self-assessment (module A) only if you fully apply harmonised standards, common specifications or a "
        "European cybersecurity certification scheme at assurance level at least 'substantial'; otherwise a third-party assessment (EU-type examination, "
        "module B+C, or full quality assurance, module H) (Article 32(2))."
    ),
    "class_ii": (
        "Third-party assessment: EU-type examination (module B+C), full quality assurance (module H), or a "
        "European cybersecurity certification scheme at assurance level 'substantial' or higher (Article 32(3))."
    ),
    "critical": (
        "A European cybersecurity certification scheme where the Commission requires one by delegated act; "
        "until then, the Class II routes apply (Articles 8 and 32(4))."
    ),
}

FOSS_NOTE = (
    "Free and open-source products in Class I or II may use self-assessment (module A) if the technical "
    "documentation is made public (Article 32(5))."
)
