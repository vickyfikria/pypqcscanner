"""
targets/indonesia_gov.py
Curated list of Indonesian government (.go.id) target websites
for PQC readiness scanning.
"""

# Each entry: (domain, description, category, priority)
INDONESIA_GOV_TARGETS = [
    # ─── Priority 1: Highest sensitivity / national security ───
    {
        "domain": "bssn.go.id",
        "name": "BSSN – Badan Siber dan Sandi Negara",
        "category": "Cybersecurity & Cryptography",
        "priority": "CRITICAL",
        "description": "National Cyber and Crypto Agency — directly responsible for national cybersecurity",
    },
    {
        "domain": "kemenkeu.go.id",
        "name": "Kementerian Keuangan",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Ministry of Finance — handles national budget, taxation, and fiscal policy",
    },
    {
        "domain": "bi.go.id",
        "name": "Bank Indonesia",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Central Bank of Indonesia — monetary policy and banking regulation",
    },
    {
        "domain": "pajak.go.id",
        "name": "Direktorat Jenderal Pajak",
        "category": "Finance",
        "priority": "CRITICAL",
        "description": "Directorate General of Taxes — citizen tax data portal",
    },
    {
        "domain": "imigrasi.go.id",
        "name": "Direktorat Jenderal Imigrasi",
        "category": "Identity",
        "priority": "CRITICAL",
        "description": "Immigration authority — passport and travel document services",
    },
    # ─── Priority 2: High-impact public services ───
    {
        "domain": "indonesia.go.id",
        "name": "Portal Informasi Indonesia",
        "category": "National Portal",
        "priority": "HIGH",
        "description": "Main national information portal",
    },
    {
        "domain": "setneg.go.id",
        "name": "Sekretariat Negara",
        "category": "Government",
        "priority": "HIGH",
        "description": "State Secretariat",
    },
    {
        "domain": "kemendagri.go.id",
        "name": "Kementerian Dalam Negeri",
        "category": "Government",
        "priority": "HIGH",
        "description": "Ministry of Home Affairs — civil registry, regional governance",
    },
    {
        "domain": "bpjs-kesehatan.go.id",
        "name": "BPJS Kesehatan",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "National health insurance — 250M+ citizen health data",
    },
    {
        "domain": "kemkes.go.id",
        "name": "Kementerian Kesehatan",
        "category": "Healthcare",
        "priority": "HIGH",
        "description": "Ministry of Health",
    },
    {
        "domain": "kpu.go.id",
        "name": "Komisi Pemilihan Umum",
        "category": "Democracy",
        "priority": "HIGH",
        "description": "General Elections Commission — electoral data integrity",
    },
    {
        "domain": "kpk.go.id",
        "name": "Komisi Pemberantasan Korupsi",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Corruption Eradication Commission",
    },
    {
        "domain": "mahkamahagung.go.id",
        "name": "Mahkamah Agung",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Supreme Court of Indonesia",
    },
    {
        "domain": "polri.go.id",
        "name": "Kepolisian Negara Republik Indonesia",
        "category": "Security",
        "priority": "HIGH",
        "description": "Indonesian National Police",
    },
    # ─── Priority 3: Public digital services ───
    {
        "domain": "kemdikbud.go.id",
        "name": "Kementerian Pendidikan",
        "category": "Education",
        "priority": "MEDIUM",
        "description": "Ministry of Education — student and academic data",
    },
    {
        "domain": "bps.go.id",
        "name": "Badan Pusat Statistik",
        "category": "Data",
        "priority": "MEDIUM",
        "description": "Central Statistics Agency",
    },
    {
        "domain": "bappenas.go.id",
        "name": "Bappenas",
        "category": "Planning",
        "priority": "MEDIUM",
        "description": "National Development Planning Agency",
    },
    {
        "domain": "oss.go.id",
        "name": "OSS – Online Single Submission",
        "category": "Business",
        "priority": "MEDIUM",
        "description": "Online business licensing portal",
    },
    {
        "domain": "lkpp.go.id",
        "name": "LKPP – Pengadaan Barang/Jasa",
        "category": "Procurement",
        "priority": "MEDIUM",
        "description": "Government procurement portal",
    },
    {
        "domain": "lapor.go.id",
        "name": "LAPOR! – Layanan Pengaduan",
        "category": "Public Service",
        "priority": "MEDIUM",
        "description": "National public complaints service",
    },
    {
        "domain": "data.go.id",
        "name": "Satu Data Indonesia",
        "category": "Open Data",
        "priority": "MEDIUM",
        "description": "Indonesia open data portal",
    },
    {
        "domain": "govtech.go.id",
        "name": "GovTech INA Digital",
        "category": "Digital Government",
        "priority": "MEDIUM",
        "description": "Integrated digital government ecosystem",
    },
    {
        "domain": "komdigi.go.id",
        "name": "Kementerian Komdigi",
        "category": "Digital",
        "priority": "MEDIUM",
        "description": "Ministry of Digital Affairs (formerly Kominfo)",
    },
    {
        "domain": "satusehat.kemkes.go.id",
        "name": "Satu Sehat",
        "category": "Healthcare",
        "priority": "MEDIUM",
        "description": "Integrated national health data platform",
    },
    {
        "domain": "tni.mil.id",
        "name": "Tentara Nasional Indonesia",
        "category": "Security",
        "priority": "MEDIUM",
        "description": "Indonesian Armed Forces",
    },
    # ─── Priority 3 (additional): Key institutions ───────────────
    {
        "domain": "kemenperin.go.id",
        "name": "Kementerian Perindustrian",
        "category": "Industry",
        "priority": "MEDIUM",
        "description": "Ministry of Industry — industrial policy and manufacturing data",
    },
    {
        "domain": "kemenpar.go.id",
        "name": "Kementerian Pariwisata",
        "category": "Tourism",
        "priority": "MEDIUM",
        "description": "Ministry of Tourism — national tourism promotion and data",
    },
    {
        "domain": "bpkp.go.id",
        "name": "BPKP – Badan Pengawasan Keuangan dan Pembangunan",
        "category": "Finance",
        "priority": "HIGH",
        "description": "Financial and Development Supervisory Agency — national audit body",
    },
    {
        "domain": "mahkamahkonstitusi.go.id",
        "name": "Mahkamah Konstitusi",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Constitutional Court of Indonesia — judicial review of laws",
    },
    {
        "domain": "kejaksaan.go.id",
        "name": "Kejaksaan Agung RI",
        "category": "Law & Justice",
        "priority": "HIGH",
        "description": "Attorney General's Office — prosecution of national crimes",
    },
]

# Quick lookup by domain
TARGET_MAP = {t["domain"]: t for t in INDONESIA_GOV_TARGETS}

# Priority groupings
CRITICAL_TARGETS = [t for t in INDONESIA_GOV_TARGETS if t["priority"] == "CRITICAL"]
HIGH_TARGETS = [t for t in INDONESIA_GOV_TARGETS if t["priority"] == "HIGH"]
MEDIUM_TARGETS = [t for t in INDONESIA_GOV_TARGETS if t["priority"] == "MEDIUM"]

ALL_DOMAINS = [t["domain"] for t in INDONESIA_GOV_TARGETS]
