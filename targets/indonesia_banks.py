"""
targets/indonesia_banks.py
Top 10 Indonesian bank internet banking portals for PQC readiness scanning.
Indonesian banking sector manages IDR 10,000+ trillion in assets.
"""

INDONESIA_BANK_TARGETS = [
    {
        "domain": "bankmandiri.co.id",
        "name": "Bank Mandiri",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "Indonesia's largest state-owned bank by assets — Livin' digital banking",
    },
    {
        "domain": "bca.co.id",
        "name": "Bank Central Asia (BCA)",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "Indonesia's largest private bank — KlikBCA & myBCA used by millions",
    },
    {
        "domain": "bri.co.id",
        "name": "Bank Rakyat Indonesia (BRI)",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "Largest microfinance bank in the world by loan portfolio — BRImo app",
    },
    {
        "domain": "bni.co.id",
        "name": "Bank Negara Indonesia (BNI)",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "State-owned national bank — BNI Mobile Banking & PortalKU",
    },
    {
        "domain": "btn.co.id",
        "name": "Bank Tabungan Negara (BTN)",
        "category": "Banking",
        "priority": "HIGH",
        "description": "State-owned bank specializing in housing loans — mortgage data",
    },
    {
        "domain": "cimbniaga.co.id",
        "name": "CIMB Niaga",
        "category": "Banking",
        "priority": "HIGH",
        "description": "7th largest bank in Indonesia — OCTO Mobile banking platform",
    },
    {
        "domain": "danamon.co.id",
        "name": "Bank Danamon Indonesia",
        "category": "Banking",
        "priority": "HIGH",
        "description": "Top-10 bank in Indonesia — D-Bank and retail banking",
    },
    {
        "domain": "permatabank.co.id",
        "name": "Bank Permata",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "Acquired by Bangkok Bank — PermataMobile X digital banking",
    },
    {
        "domain": "ocbcnisp.com",
        "name": "Bank OCBC Indonesia",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "OCBC Bank Indonesia (formerly OCBC NISP) — ONe Mobile banking",
    },
    {
        "domain": "paninbank.co.id",
        "name": "Bank Panin",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "Pan Indonesia Bank — retail and commercial banking",
    },
]

TARGET_MAP  = {t["domain"]: t for t in INDONESIA_BANK_TARGETS}
ALL_DOMAINS = [t["domain"] for t in INDONESIA_BANK_TARGETS]
