"""
targets/malaysia_gov.py
Curated list of Malaysian government (.gov.my) target websites
for PQC readiness scanning.
"""

MALAYSIA_GOV_TARGETS = [
    # ─── Priority 1: National Security & Critical Infrastructure ───
    {
        "domain": "nacsa.gov.my",
        "name": "NACSA – National Cyber Security Agency",
        "category": "Cybersecurity",
        "priority": "CRITICAL",
        "description": "National Cyber Security Agency — Malaysia's equivalent of BSSN",
    },
    {
        "domain": "bnm.gov.my",
        "name": "Bank Negara Malaysia",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Central Bank of Malaysia — monetary policy and banking regulation",
    },
    {
        "domain": "hasil.gov.my",
        "name": "Lembaga Hasil Dalam Negeri (LHDN)",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Inland Revenue Board — citizen tax data and e-filing portal",
    },
    {
        "domain": "eperolehan.com.my",
        "name": "ePerolehan – Gov Procurement",
        "category": "Procurement",
        "priority": "CRITICAL",
        "description": "Government e-procurement system — vendor and contract data",
    },
    {
        "domain": "immigration.gov.my",
        "name": "Jabatan Imigresen Malaysia",
        "category": "Identity",
        "priority": "CRITICAL",
        "description": "Immigration Department — passport, visa, travel documents",
    },
    # ─── Priority 2: High-impact public services ───
    {
        "domain": "malaysia.gov.my",
        "name": "MyGovHub – Portal Rasmi Malaysia",
        "category": "National Portal",
        "priority": "HIGH",
        "description": "Main Malaysian government services portal",
    },
    {
        "domain": "mampu.gov.my",
        "name": "MAMPU – Public Service Modernization",
        "category": "Government",
        "priority": "HIGH",
        "description": "Malaysian Administrative Modernisation and Management Planning Unit",
    },
    {
        "domain": "pdrm.gov.my",
        "name": "Polis Diraja Malaysia (PDRM)",
        "category": "Security",
        "priority": "HIGH",
        "description": "Royal Malaysia Police",
    },
    {
        "domain": "kwsp.gov.my",
        "name": "KWSP – Kumpulan Wang Simpanan Pekerja (EPF)",
        "category": "Social Security",
        "priority": "HIGH",
        "description": "Employees Provident Fund — retirement savings for millions",
    },
    {
        "domain": "perkeso.gov.my",
        "name": "PERKESO / SOCSO",
        "category": "Social Security",
        "priority": "HIGH",
        "description": "Social Security Organisation — worker insurance and benefits",
    },
    {
        "domain": "spr.gov.my",
        "name": "Suruhanjaya Pilihan Raya (SPR)",
        "category": "Democracy",
        "priority": "HIGH",
        "description": "Election Commission of Malaysia — electoral data integrity",
    },
    {
        "domain": "sprm.gov.my",
        "name": "SPRM – Malaysian Anti-Corruption Commission",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Malaysian Anti-Corruption Commission (MACC)",
    },
    {
        "domain": "kehakiman.gov.my",
        "name": "Jabatan Kehakiman Malaysia",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Department of Judiciary Malaysia — court records",
    },
    {
        "domain": "jpa.gov.my",
        "name": "Jabatan Perkhidmatan Awam (JPA)",
        "category": "Government",
        "priority": "HIGH",
        "description": "Public Service Department — civil servant HR data",
    },
    # ─── Priority 3: Public digital services ───
    {
        "domain": "moe.gov.my",
        "name": "Ministry of Education Malaysia",
        "category": "Education",
        "priority": "MEDIUM",
        "description": "Kementerian Pendidikan Malaysia",
    },
    {
        "domain": "moh.gov.my",
        "name": "Ministry of Health Malaysia (MOH)",
        "category": "Healthcare",
        "priority": "MEDIUM",
        "description": "Kementerian Kesihatan Malaysia — national health data",
    },
    {
        "domain": "dosm.gov.my",
        "name": "DOSM – Dept. of Statistics Malaysia",
        "category": "Data",
        "priority": "MEDIUM",
        "description": "Department of Statistics Malaysia",
    },
    {
        "domain": "sc.com.my",
        "name": "Securities Commission Malaysia",
        "category": "Finance",
        "priority": "MEDIUM",
        "description": "Securities Commission — capital markets regulation",
    },
    {
        "domain": "cybersecurity.my",
        "name": "CyberSecurity Malaysia",
        "category": "Cybersecurity",
        "priority": "MEDIUM",
        "description": "National cybersecurity specialist agency under MOSTI",
    },
    {
        "domain": "kpdn.gov.my",
        "name": "Kementerian Perdagangan Dalam Negeri",
        "category": "Trade",
        "priority": "MEDIUM",
        "description": "Ministry of Domestic Trade and Cost of Living",
    },
    {
        "domain": "mot.gov.my",
        "name": "Ministry of Transport Malaysia",
        "category": "Transport",
        "priority": "MEDIUM",
        "description": "Kementerian Pengangkutan Malaysia",
    },
    {
        "domain": "moha.gov.my",
        "name": "Ministry of Home Affairs",
        "category": "Government",
        "priority": "MEDIUM",
        "description": "Kementerian Dalam Negeri (KDN)",
    },
    {
        "domain": "data.gov.my",
        "name": "Open Data Malaysia",
        "category": "Open Data",
        "priority": "MEDIUM",
        "description": "Malaysia open government data portal",
    },
    {
        "domain": "mycert.org.my",
        "name": "MyCERT – Malaysia Computer Emergency Response Team",
        "category": "Cybersecurity",
        "priority": "MEDIUM",
        "description": "National CERT for Malaysia under CyberSecurity Malaysia",
    },
    {
        "domain": "kkmm.gov.my",
        "name": "Ministry of Communications – KKMM",
        "category": "Digital",
        "priority": "MEDIUM",
        "description": "Kementerian Komunikasi — digital and media policy",
    },
    # ─── Priority 4: National institutions & GLCs ───
    {
        "domain": "petronas.com.my",
        "name": "PETRONAS – Petroliam Nasional Berhad",
        "category": "National GLC",
        "priority": "HIGH",
        "description": "National oil company — critical national infrastructure",
    },
    {
        "domain": "bursamalaysia.com",
        "name": "Bursa Malaysia",
        "category": "Finance",
        "priority": "HIGH",
        "description": "Malaysian stock exchange — financial market infrastructure",
    },
    {
        "domain": "khazanah.com.my",
        "name": "Khazanah Nasional",
        "category": "National GLC",
        "priority": "MEDIUM",
        "description": "Malaysia's sovereign wealth fund",
    },
    {
        "domain": "felda.net.my",
        "name": "FELDA – Federal Land Development Authority",
        "category": "National GLC",
        "priority": "MEDIUM",
        "description": "Federal Land Development Authority",
    },
    {
        "domain": "dbkl.gov.my",
        "name": "DBKL – Kuala Lumpur City Hall",
        "category": "Local Government",
        "priority": "MEDIUM",
        "description": "Dewan Bandaraya Kuala Lumpur — capital city administration",
    },
]

TARGET_MAP = {t["domain"]: t for t in MALAYSIA_GOV_TARGETS}

CRITICAL_TARGETS = [t for t in MALAYSIA_GOV_TARGETS if t["priority"] == "CRITICAL"]
HIGH_TARGETS     = [t for t in MALAYSIA_GOV_TARGETS if t["priority"] == "HIGH"]
MEDIUM_TARGETS   = [t for t in MALAYSIA_GOV_TARGETS if t["priority"] == "MEDIUM"]

ALL_DOMAINS = [t["domain"] for t in MALAYSIA_GOV_TARGETS]
