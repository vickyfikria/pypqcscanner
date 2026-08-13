"""
targets/malaysia_banks.py
Top 10 Malaysian bank portals for PQC readiness scanning.
"""

MALAYSIA_BANK_TARGETS = [
    {
        "domain": "maybank2u.com.my",
        "name": "Maybank2u – Maybank Internet Banking",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "Malaysia's largest bank by assets — millions of online banking users",
    },
    {
        "domain": "cimbclicks.com.my",
        "name": "CIMB Clicks – CIMB Bank",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "CIMB Group internet banking — second largest Malaysian bank",
    },
    {
        "domain": "pbebank.com",
        "name": "Public Bank Berhad",
        "category": "Banking",
        "priority": "CRITICAL",
        "description": "Public Bank — third largest bank, top mortgage lender in Malaysia",
    },
    {
        "domain": "hlonline.com.my",
        "name": "HLB Connect – Hong Leong Bank",
        "category": "Banking",
        "priority": "HIGH",
        "description": "Hong Leong Bank internet banking portal",
    },
    {
        "domain": "rhbgroup.com",
        "name": "RHB Bank",
        "category": "Banking",
        "priority": "HIGH",
        "description": "RHB Banking Group — one of Malaysia's largest financial groups",
    },
    {
        "domain": "ambankgroup.com",
        "name": "AmBank Group",
        "category": "Banking",
        "priority": "HIGH",
        "description": "AmBank Malaysia — retail and investment banking",
    },
    {
        "domain": "affinbank.com.my",
        "name": "Affin Bank",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "Affin Bank Berhad — retail banking",
    },
    {
        "domain": "alliancebank.com.my",
        "name": "Alliance Bank Malaysia",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "Alliance Bank — SME and retail banking focus",
    },
    {
        "domain": "ocbc.com.my",
        "name": "OCBC Bank Malaysia",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "OCBC Bank Malaysia — Singapore-headquartered bank with large MY presence",
    },
    {
        "domain": "hsbc.com.my",
        "name": "HSBC Malaysia",
        "category": "Banking",
        "priority": "MEDIUM",
        "description": "HSBC Bank Malaysia — global bank with major Malaysian operations",
    },
]

TARGET_MAP  = {t["domain"]: t for t in MALAYSIA_BANK_TARGETS}
ALL_DOMAINS = [t["domain"] for t in MALAYSIA_BANK_TARGETS]
