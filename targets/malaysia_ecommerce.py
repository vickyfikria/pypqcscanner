"""
targets/malaysia_ecommerce.py
Top 10 Malaysian e-commerce & popular consumer portals for PQC scanning.
"""

MALAYSIA_ECOMMERCE_TARGETS = [
    {
        "domain": "shopee.com.my",
        "name": "Shopee Malaysia",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "#1 e-commerce platform in Malaysia — millions of daily transactions",
    },
    {
        "domain": "lazada.com.my",
        "name": "Lazada Malaysia",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Major e-commerce marketplace under Alibaba Group",
    },
    {
        "domain": "mudah.com.my",
        "name": "Mudah.my",
        "category": "E-Commerce",
        "priority": "HIGH",
        "description": "Malaysia's largest classifieds & second-hand marketplace",
    },
    {
        "domain": "lelong.com.my",
        "name": "Lelong.com.my",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Malaysian-owned online marketplace (auction and fixed price)",
    },
    {
        "domain": "zalora.com.my",
        "name": "ZALORA Malaysia",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Leading fashion e-commerce platform in Southeast Asia",
    },
    {
        "domain": "mydin.com.my",
        "name": "MYDIN Online",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Malaysian hypermarket chain with online shopping portal",
    },
    {
        "domain": "aeon.com.my",
        "name": "AEON Online Malaysia",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Japanese-Malaysian retail giant with online shopping",
    },
    {
        "domain": "senheng.com.my",
        "name": "Senheng Electric",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Malaysia's largest electronics retail chain",
    },
    {
        "domain": "parkson.com.my",
        "name": "Parkson Malaysia",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Malaysian department store with e-commerce presence",
    },
    {
        "domain": "carousell.com.my",
        "name": "Carousell Malaysia",
        "category": "E-Commerce",
        "priority": "MEDIUM",
        "description": "Popular C2C marketplace for new and secondhand goods",
    },
]

TARGET_MAP   = {t["domain"]: t for t in MALAYSIA_ECOMMERCE_TARGETS}
ALL_DOMAINS  = [t["domain"] for t in MALAYSIA_ECOMMERCE_TARGETS]
