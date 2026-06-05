"""
Global regulatory framework catalogue.
Each entry maps a framework to its key requirements, timeline, and jurisdictions.
Used by the report renderer and the dashboard's compliance page.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass
class Framework:
    id: str
    name: str
    short: str
    jurisdiction: str
    jurisdiction_flag: str
    status: str                  # "implemented" | "stub" | "planned"
    deadline: str
    mandate_type: str            # "mandatory" | "advisory" | "emerging"
    body: str                    # issuing authority
    key_requirements: list[str]
    reference: str
    description: str


FRAMEWORKS: list[Framework] = [

    # ── India ─────────────────────────────────────────────────────────────────

    Framework(
        id="RBI", name="RBI Cybersecurity Framework + IT Master Direction",
        short="RBI", jurisdiction="India", jurisdiction_flag="🇮🇳",
        status="implemented", deadline="FY2026-27", mandate_type="mandatory",
        body="Reserve Bank of India",
        key_requirements=[
            "Cryptographic asset inventory (CBOM) for all regulated entities",
            "PQC migration roadmap submitted to RBI IT Risk Officer",
            "Board-level awareness of HNDL (harvest-now-decrypt-later) risk",
            "Hybrid PQC deployment on internet-facing systems by FY2026-27",
            "Third-party (HSM, CA, SaaS) PQC vendor assessment",
        ],
        reference="RBI/2024-25/37 · Master Direction DoS.CO.CGIT.SEC.01/2023-24",
        description="Governs all Scheduled Commercial Banks, NBFCs, Payment Banks, and RRBs.",
    ),

    Framework(
        id="SEBI", name="SEBI Cybersecurity & Cyber Resilience Framework",
        short="SEBI CSCRF", jurisdiction="India", jurisdiction_flag="🇮🇳",
        status="stub", deadline="FY2025-26", mandate_type="mandatory",
        body="Securities and Exchange Board of India",
        key_requirements=[
            "Annual cryptographic assessment for Market Infrastructure Institutions",
            "PQC readiness disclosure in CSCRF annual compliance report",
            "Penetration testing scope must include post-quantum threat modelling",
            "CERT-In coordination for quantum-related incident response plans",
        ],
        reference="SEBI/HO/ITD-1/ITD_CSC_EXT/P/CIR/2023/009 (CSCRF 2024)",
        description="Covers stock exchanges, depositories, clearing corporations, brokers, and RIAs.",
    ),

    Framework(
        id="CERT-In", name="CERT-In Directions on Cybersecurity",
        short="CERT-In", jurisdiction="India", jurisdiction_flag="🇮🇳",
        status="stub", deadline="Ongoing", mandate_type="mandatory",
        body="Indian Computer Emergency Response Team",
        key_requirements=[
            "6-hour incident reporting window for cryptographic breaches",
            "Audit logs of cryptographic operations retained for 180 days",
            "Threat modelling must include quantum adversary scenarios",
            "Coordinate with CERT-In on PQC transition advisories",
        ],
        reference="CERT-In Directions under Section 70B(6) IT Act · April 2022",
        description="Applies to all organisations operating IT infrastructure in India.",
    ),

    Framework(
        id="DPDP", name="Digital Personal Data Protection Act",
        short="DPDP 2023", jurisdiction="India", jurisdiction_flag="🇮🇳",
        status="stub", deadline="Rules expected 2025", mandate_type="emerging",
        body="Ministry of Electronics and IT (MeitY)",
        key_requirements=[
            "Data fiduciaries must implement 'reasonable security safeguards'",
            "Classical encryption of personal data may not meet safeguard standard post-2027",
            "DPO must assess cryptographic adequacy for long-lived personal data",
            "Significant data fiduciaries: mandatory security audits",
        ],
        reference="Digital Personal Data Protection Act, 2023 (No. 22 of 2023)",
        description="India's primary data protection law. Rules under finalisation as of 2025.",
    ),

    # ── United States ─────────────────────────────────────────────────────────

    Framework(
        id="NIST_CNSA2", name="NSA CNSA 2.0 / NIST Migration Guidelines",
        short="CNSA 2.0", jurisdiction="United States", jurisdiction_flag="🇺🇸",
        status="stub", deadline="2030 (national security systems)", mandate_type="mandatory",
        body="NSA / NIST",
        key_requirements=[
            "All NSS must use ML-KEM-768/1024 and ML-DSA-44/65/87 by 2030",
            "CNSA 2.0 deprecates classical public-key algorithms for NSS",
            "OMB M-23-02: federal agencies must inventory quantum-vulnerable crypto by FY2024",
            "CISA PQC initiative: critical infrastructure guidance for migration",
            "NIST SP 800-208: migrate to approved PQC algorithms; SP 800-131A sunset dates",
        ],
        reference="NSA CNSA 2.0 (Sep 2022) · OMB M-23-02 · NIST SP 800-208",
        description="Mandatory for US national security systems; advisory baseline for all US organisations.",
    ),

    # ── European Union ────────────────────────────────────────────────────────

    Framework(
        id="EU_DORA", name="EU DORA + ENISA PQC Recommendations",
        short="EU DORA", jurisdiction="European Union", jurisdiction_flag="🇪🇺",
        status="stub", deadline="Jan 2025 (DORA in force)", mandate_type="mandatory",
        body="European Banking Authority (EBA) / ENISA",
        key_requirements=[
            "DORA Article 9: financial entities must manage ICT risks including cryptographic obsolescence",
            "DORA RTS: cryptographic controls must be reviewed against state-of-the-art",
            "ENISA PQC guidelines: recommend hybrid deployment for TLS by 2026",
            "eIDAS 2.0: qualified trust services must adopt PQC-ready algorithms",
            "NIS2 Directive: critical entities must address emerging cryptographic threats",
        ],
        reference="DORA Regulation (EU) 2022/2554 · ENISA PQC Guidelines 2024 · NIS2 Directive",
        description="Covers EU financial entities, critical infrastructure, and digital service providers.",
    ),

    # ── United Kingdom ────────────────────────────────────────────────────────

    Framework(
        id="UK_NCSC", name="UK NCSC Post-Quantum Cryptography Guidance",
        short="NCSC UK", jurisdiction="United Kingdom", jurisdiction_flag="🇬🇧",
        status="stub", deadline="2028 guidance target", mandate_type="advisory",
        body="National Cyber Security Centre (NCSC)",
        key_requirements=[
            "NCSC recommends beginning PQC migration planning immediately",
            "Hybrid key exchange (X25519+ML-KEM) recommended for TLS from 2024",
            "FCA operational resilience: crypto agility required for systemically important firms",
            "NCSC: prioritise data with long confidentiality requirements (>10 years)",
        ],
        reference="NCSC Post-Quantum Cryptography (2023) · FCA PS21/3",
        description="Advisory for UK organisations; FCA operational resilience rules add teeth for financial services.",
    ),

    # ── Singapore ─────────────────────────────────────────────────────────────

    Framework(
        id="MAS_TRM", name="MAS Technology Risk Management Guidelines",
        short="MAS TRM", jurisdiction="Singapore", jurisdiction_flag="🇸🇬",
        status="stub", deadline="Advisory — 2025 review expected", mandate_type="advisory",
        body="Monetary Authority of Singapore (MAS)",
        key_requirements=[
            "MAS TRM 2021: cryptographic controls must be reviewed for quantum threats",
            "Financial institutions must maintain crypto-agility in system design",
            "MAS expects PQC roadmap in next technology risk assessment cycle",
            "CSA Singapore: include PQC in annual cybersecurity health check",
        ],
        reference="MAS TRM Guidelines 2021 (Sections 11.2, 14.1) · CSA SG Cyber Essentials",
        description="Applies to all MAS-regulated financial institutions operating in Singapore.",
    ),

    # ── Germany ───────────────────────────────────────────────────────────────

    Framework(
        id="BSI", name="BSI Technical Guidelines (TR-02102)",
        short="BSI TR-02102", jurisdiction="Germany", jurisdiction_flag="🇩🇪",
        status="stub", deadline="Updated 2024", mandate_type="advisory",
        body="Bundesamt für Sicherheit in der Informationstechnik (BSI)",
        key_requirements=[
            "BSI TR-02102-1: recommends ML-KEM and ML-DSA as of 2024 update",
            "Classical algorithms sunset dates: RSA/ECDH/ECDSA deprecated for new systems by 2026",
            "Hybrid key exchange required for German federal IT systems",
            "KRITIS operators: quantum threat must be addressed in IT security concepts",
        ],
        reference="BSI TR-02102-1 v2024.1 · IT-Grundschutz-Kompendium",
        description="Technical authority for Germany. BSI guidance is de facto mandatory for federal IT and KRITIS.",
    ),

    # ── Australia ─────────────────────────────────────────────────────────────

    Framework(
        id="ACSC", name="Australian Signals Directorate / ACSC PQC Guidance",
        short="ASD ACSC", jurisdiction="Australia", jurisdiction_flag="🇦🇺",
        status="stub", deadline="Advisory — 2025", mandate_type="advisory",
        body="Australian Signals Directorate (ASD) / ACSC",
        key_requirements=[
            "ASD recommends NIST FIPS 203/204/205 as replacement algorithms",
            "Essential Eight now includes cryptographic hygiene as a maturity indicator",
            "APRA CPS 234: cryptographic controls must be commensurate with threat",
            "Critical infrastructure entities must address quantum threat in risk assessment",
        ],
        reference="ASD PQC Advisory 2024 · APRA CPS 234 · Essential Eight Maturity Model",
        description="Applies to Australian government agencies, critical infrastructure, and APRA-regulated entities.",
    ),
]

FRAMEWORK_MAP = {f.id: f for f in FRAMEWORKS}
