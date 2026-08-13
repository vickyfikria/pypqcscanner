"""
targets/us_gov.py
50 US Federal Government portals for PQC readiness scanning.
Covers all major branches, agencies, and critical infrastructure.
"""

US_GOV_TARGETS = [
    # ─── National Security & Cyber ────────────────────────────────
    {
        "domain": "nist.gov",
        "name": "NIST – National Institute of Standards and Technology",
        "category": "Standards & Cybersecurity",
        "priority": "CRITICAL",
        "description": "Authors of FIPS 203/204/205 — the PQC standards themselves",
    },
    {
        "domain": "cisa.gov",
        "name": "CISA – Cybersecurity & Infrastructure Security Agency",
        "category": "Cybersecurity",
        "priority": "CRITICAL",
        "description": "US national cyber defense agency — leads federal PQC migration",
    },
    {
        "domain": "nsa.gov",
        "name": "NSA – National Security Agency",
        "category": "Intelligence & Cybersecurity",
        "priority": "CRITICAL",
        "description": "NSA — published Commercial National Security Algorithm Suite 2.0 (PQC)",
    },
    {
        "domain": "dhs.gov",
        "name": "DHS – Department of Homeland Security",
        "category": "National Security",
        "priority": "CRITICAL",
        "description": "Homeland Security — oversees US critical infrastructure protection",
    },
    {
        "domain": "fbi.gov",
        "name": "FBI – Federal Bureau of Investigation",
        "category": "Law Enforcement",
        "priority": "CRITICAL",
        "description": "Federal Bureau of Investigation — sensitive case and citizen data",
    },
    # ─── Finance & Economic ───────────────────────────────────────
    {
        "domain": "irs.gov",
        "name": "IRS – Internal Revenue Service",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "US tax authority — handles financial data for 150M+ Americans",
    },
    {
        "domain": "treasury.gov",
        "name": "US Department of the Treasury",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Treasury — manages national debt, sanctions, and financial policy",
    },
    {
        "domain": "federalreserve.gov",
        "name": "Federal Reserve",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "US central bank — monetary policy and financial system stability",
    },
    {
        "domain": "sec.gov",
        "name": "SEC – Securities and Exchange Commission",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Securities regulator — financial market data and investor records",
    },
    {
        "domain": "fdic.gov",
        "name": "FDIC – Federal Deposit Insurance Corporation",
        "category": "Finance",
        "priority": "HIGH",
        "description": "Insures US bank deposits — systemic financial risk data",
    },
    # ─── Defense ──────────────────────────────────────────────────
    {
        "domain": "defense.gov",
        "name": "US Department of Defense",
        "category": "Defense",
        "priority": "CRITICAL",
        "description": "DoD — largest US government agency, national security systems",
    },
    {
        "domain": "army.mil",
        "name": "US Army",
        "category": "Defense",
        "priority": "HIGH",
        "description": "United States Army public web presence",
    },
    {
        "domain": "navy.mil",
        "name": "US Navy",
        "category": "Defense",
        "priority": "HIGH",
        "description": "United States Navy public web presence",
    },
    {
        "domain": "af.mil",
        "name": "US Air Force",
        "category": "Defense",
        "priority": "HIGH",
        "description": "United States Air Force public web presence",
    },
    {
        "domain": "marines.mil",
        "name": "US Marine Corps",
        "category": "Defense",
        "priority": "HIGH",
        "description": "United States Marine Corps public web presence",
    },
    # ─── Health & Human Services ──────────────────────────────────
    {
        "domain": "hhs.gov",
        "name": "HHS – Dept. of Health & Human Services",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "US health policy — oversees Medicare, Medicaid, FDA, CDC, NIH",
    },
    {
        "domain": "cdc.gov",
        "name": "CDC – Centers for Disease Control",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Public health agency — disease surveillance and health data",
    },
    {
        "domain": "fda.gov",
        "name": "FDA – Food and Drug Administration",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Drug and medical device regulation — sensitive approval data",
    },
    {
        "domain": "nih.gov",
        "name": "NIH – National Institutes of Health",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Medical research — clinical trial and genomic data",
    },
    {
        "domain": "cms.gov",
        "name": "CMS – Centers for Medicare & Medicaid",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Manages $1T+ in healthcare payments annually",
    },
    # ─── Social Services ──────────────────────────────────────────
    {
        "domain": "ssa.gov",
        "name": "SSA – Social Security Administration",
        "category": "Social Services",
        "priority": "CRITICAL",
        "description": "Social Security — PII for 180M+ Americans including SSNs",
    },
    {
        "domain": "medicare.gov",
        "name": "Medicare.gov",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Medicare enrollment and benefits portal for seniors",
    },
    {
        "domain": "va.gov",
        "name": "VA – Department of Veterans Affairs",
        "category": "Social Services",
        "priority": "HIGH",
        "description": "Veterans health records and benefits — 9M+ veteran records",
    },
    {
        "domain": "healthcare.gov",
        "name": "HealthCare.gov – ACA Marketplace",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "ACA health insurance exchange — financial and health PII",
    },
    {
        "domain": "benefits.gov",
        "name": "Benefits.gov",
        "category": "Social Services",
        "priority": "MEDIUM",
        "description": "Federal benefits eligibility portal for citizens",
    },
    # ─── Executive & Legislative ──────────────────────────────────
    {
        "domain": "whitehouse.gov",
        "name": "The White House",
        "category": "Executive",
        "priority": "HIGH",
        "description": "Official website of the President of the United States",
    },
    {
        "domain": "congress.gov",
        "name": "Congress.gov",
        "category": "Legislative",
        "priority": "HIGH",
        "description": "US Congress portal — legislative records and public access",
    },
    {
        "domain": "supremecourt.gov",
        "name": "Supreme Court of the United States",
        "category": "Judicial",
        "priority": "HIGH",
        "description": "US Supreme Court — judicial opinions and filings",
    },
    {
        "domain": "doj.gov",
        "name": "DOJ – Department of Justice",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "US Attorney General — federal prosecution and law enforcement",
    },
    {
        "domain": "cia.gov",
        "name": "CIA – Central Intelligence Agency",
        "category": "Intelligence",
        "priority": "HIGH",
        "description": "Central Intelligence Agency — public web presence",
    },
    # ─── Infrastructure & Services ────────────────────────────────
    {
        "domain": "usps.com",
        "name": "USPS – United States Postal Service",
        "category": "Infrastructure",
        "priority": "HIGH",
        "description": "National postal service — package tracking and PII",
    },
    {
        "domain": "fema.gov",
        "name": "FEMA – Federal Emergency Management Agency",
        "category": "Emergency",
        "priority": "HIGH",
        "description": "Disaster relief — processes disaster assistance and PII",
    },
    {
        "domain": "gsa.gov",
        "name": "GSA – General Services Administration",
        "category": "Government",
        "priority": "MEDIUM",
        "description": "Federal procurement and real estate management",
    },
    {
        "domain": "opm.gov",
        "name": "OPM – Office of Personnel Management",
        "category": "Government",
        "priority": "CRITICAL",
        "description": "Federal HR agency — background check data on millions of clearances",
    },
    {
        "domain": "sba.gov",
        "name": "SBA – Small Business Administration",
        "category": "Commerce",
        "priority": "MEDIUM",
        "description": "Small business loans and support — financial data",
    },
    # ─── Science & Technology ─────────────────────────────────────
    {
        "domain": "nasa.gov",
        "name": "NASA – National Aeronautics & Space Administration",
        "category": "Science",
        "priority": "HIGH",
        "description": "Space agency — research data and mission-critical systems",
    },
    {
        "domain": "energy.gov",
        "name": "DOE – Department of Energy",
        "category": "Energy",
        "priority": "HIGH",
        "description": "Manages nuclear weapons complex and energy research",
    },
    {
        "domain": "nsf.gov",
        "name": "NSF – National Science Foundation",
        "category": "Science",
        "priority": "MEDIUM",
        "description": "Research funding — grant management data",
    },
    {
        "domain": "noaa.gov",
        "name": "NOAA – National Oceanic & Atmospheric Administration",
        "category": "Science",
        "priority": "MEDIUM",
        "description": "Weather and climate data — national forecasting infrastructure",
    },
    {
        "domain": "epa.gov",
        "name": "EPA – Environmental Protection Agency",
        "category": "Environment",
        "priority": "MEDIUM",
        "description": "Environmental regulation and compliance data",
    },
    # ─── Commerce & Data ──────────────────────────────────────────
    {
        "domain": "commerce.gov",
        "name": "US Department of Commerce",
        "category": "Commerce",
        "priority": "MEDIUM",
        "description": "Oversees NIST, Census, NOAA, and trade data",
    },
    {
        "domain": "census.gov",
        "name": "US Census Bureau",
        "category": "Data",
        "priority": "HIGH",
        "description": "National demographic data — PII for 330M+ Americans",
    },
    {
        "domain": "bls.gov",
        "name": "BLS – Bureau of Labor Statistics",
        "category": "Data",
        "priority": "MEDIUM",
        "description": "Employment and economic statistics",
    },
    {
        "domain": "data.gov",
        "name": "Data.gov – Open Government Data",
        "category": "Open Data",
        "priority": "MEDIUM",
        "description": "US open data portal — 250,000+ datasets",
    },
    {
        "domain": "usa.gov",
        "name": "USA.gov – Main Government Portal",
        "category": "National Portal",
        "priority": "HIGH",
        "description": "Primary US government citizen services portal",
    },
    # ─── Transport & Education ────────────────────────────────────
    {
        "domain": "transportation.gov",
        "name": "DOT – Department of Transportation",
        "category": "Transport",
        "priority": "MEDIUM",
        "description": "Aviation, highways, railroads — safety certification data",
    },
    {
        "domain": "faa.gov",
        "name": "FAA – Federal Aviation Administration",
        "category": "Transport",
        "priority": "HIGH",
        "description": "Air traffic control — aviation safety and pilot certification",
    },
    {
        "domain": "ed.gov",
        "name": "US Dept. of Education",
        "category": "Education",
        "priority": "MEDIUM",
        "description": "Student loan and grant data — FAFSA records for millions",
    },
    {
        "domain": "studentaid.gov",
        "name": "Federal Student Aid",
        "category": "Education",
        "priority": "HIGH",
        "description": "FAFSA & student loan portal — financial PII for 40M+ borrowers",
    },
    {
        "domain": "usda.gov",
        "name": "USDA – Dept. of Agriculture",
        "category": "Agriculture",
        "priority": "MEDIUM",
        "description": "Food safety, nutrition programs, rural development data",
    },
]

TARGET_MAP     = {t["domain"]: t for t in US_GOV_TARGETS}
ALL_DOMAINS    = [t["domain"] for t in US_GOV_TARGETS]
CRITICAL_TARGETS = [t for t in US_GOV_TARGETS if t["priority"] == "CRITICAL"]
HIGH_TARGETS     = [t for t in US_GOV_TARGETS if t["priority"] == "HIGH"]
MEDIUM_TARGETS   = [t for t in US_GOV_TARGETS if t["priority"] == "MEDIUM"]
