"""
targets/indonesia_ecommerce.py
Top 10 Indonesian e-commerce portals for PQC readiness scanning.
Indonesia is Southeast Asia's largest e-commerce market by GMV.
"""

INDONESIA_ECOMMERCE_TARGETS = [
    {
        "domain": "tokopedia.com",
        "name": "Tokopedia",
        "category": "E-Commerce",
        "priority": "CRITICAL",
        "description": "Indonesia's #1 homegrown marketplace — 100M+ monthly users, now merged into TikTok Shop",
    },
    {
        "domain": "shopee.co.id",
        "name": "Shopee Indonesia",
        "category": "E-Commerce",
        "priority": "CRITICAL",
        "description": "#1 most visited e-commerce site in Indonesia — Sea Group platform",
    },
    {
        "domain": "lazada.co.id",
        "name": "Lazada Indonesia",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Major Alibaba-backed e-commerce marketplace in Indonesia",
    },
    {
        "domain": "bukalapak.com",
        "name": "Bukalapak",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Indonesian unicorn marketplace — first Indonesian tech company to IPO",
    },
    {
        "domain": "blibli.com",
        "name": "Blibli",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Djarum Group-backed e-commerce and omnichannel retail platform",
    },
    {
        "domain": "traveloka.com",
        "name": "Traveloka",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Indonesia's #1 travel booking platform — flights, hotels, financial products",
    },
    {
        "domain": "tiket.com",
        "name": "Tiket.com",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Online travel agency for flights, trains, hotels — handles payment data",
    },
    {
        "domain": "bhinneka.com",
        "name": "Bhinneka",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Indonesia's oldest online electronics store — B2B and B2C",
    },
    {
        "domain": "zalora.co.id",
        "name": "ZALORA Indonesia",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Leading fashion e-commerce platform in Southeast Asia",
    },
    {
        "domain": "kaskus.co.id",
        "name": "Kaskus",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Indonesia's largest online community and marketplace (FJB)",
    },
]

TARGET_MAP  = {t["domain"]: t for t in INDONESIA_ECOMMERCE_TARGETS}
ALL_DOMAINS = [t["domain"] for t in INDONESIA_ECOMMERCE_TARGETS]
