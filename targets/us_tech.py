"""
targets/us_tech.py
25 top US tech company portals for PQC readiness scanning.
Includes Big Tech, cloud providers, cybersecurity, and SaaS leaders.
Note: Some of these companies (Cloudflare, Google) are known to deploy PQC.
"""

US_TECH_TARGETS = [
    {
        "domain": "google.com",
        "name": "Google",
        "category": "Big Tech",
        "priority": "CRITICAL",
        "description": "Alphabet subsidiary — pioneered PQC in Chrome (X25519Kyber768). Expect high score.",
    },
    {
        "domain": "cloudflare.com",
        "name": "Cloudflare",
        "category": "Network & Security",
        "priority": "CRITICAL",
        "description": "CDN/security leader — early PQC adopter, deployed X25519MLKEM768 in production",
    },
    {
        "domain": "microsoft.com",
        "name": "Microsoft",
        "category": "Big Tech",
        "priority": "CRITICAL",
        "description": "Microsoft Corp — Windows, Azure, Office 365. Active NIST PQC contributor.",
    },
    {
        "domain": "meta.com",
        "name": "Meta Platforms",
        "category": "Big Tech",
        "priority": "CRITICAL",
        "description": "Facebook/Instagram/WhatsApp parent — 3B+ user data",
    },
    {
        "domain": "netflix.com",
        "name": "Netflix",
        "category": "Streaming",
        "priority": "HIGH",
        "description": "Streaming leader — 270M+ subscribers, DRM and payment data",
    },
    {
        "domain": "salesforce.com",
        "name": "Salesforce",
        "category": "Enterprise SaaS",
        "priority": "HIGH",
        "description": "CRM platform — sensitive enterprise and customer data for Fortune 500",
    },
    {
        "domain": "oracle.com",
        "name": "Oracle",
        "category": "Enterprise Tech",
        "priority": "HIGH",
        "description": "Database and cloud services — enterprise financial and ERP data",
    },
    {
        "domain": "ibm.com",
        "name": "IBM",
        "category": "Enterprise Tech",
        "priority": "HIGH",
        "description": "IBM — major NIST PQC contributor, developed lattice-based Kyber/Dilithium",
    },
    {
        "domain": "intel.com",
        "name": "Intel Corporation",
        "category": "Semiconductor",
        "priority": "HIGH",
        "description": "CPU manufacturer — hardware PQC acceleration research",
    },
    {
        "domain": "nvidia.com",
        "name": "NVIDIA",
        "category": "Semiconductor",
        "priority": "HIGH",
        "description": "GPU/AI chip leader — most valuable semiconductor company",
    },
    {
        "domain": "cisco.com",
        "name": "Cisco Systems",
        "category": "Network & Security",
        "priority": "HIGH",
        "description": "Network infrastructure — routers, switches, security appliances",
    },
    {
        "domain": "adobe.com",
        "name": "Adobe Inc.",
        "category": "Enterprise SaaS",
        "priority": "MEDIUM",
        "description": "Creative and document cloud — PDF, digital signature infrastructure",
    },
    {
        "domain": "github.com",
        "name": "GitHub (Microsoft)",
        "category": "Developer Platform",
        "priority": "HIGH",
        "description": "100M+ developer accounts — SSH keys and code signing data",
    },
    {
        "domain": "stripe.com",
        "name": "Stripe",
        "category": "Fintech",
        "priority": "CRITICAL",
        "description": "Payment infrastructure for millions of businesses — PCI-DSS critical",
    },
    {
        "domain": "twilio.com",
        "name": "Twilio",
        "category": "Communications",
        "priority": "MEDIUM",
        "description": "Cloud communications API — SMS, voice, and authentication data",
    },
    {
        "domain": "zoom.us",
        "name": "Zoom Video Communications",
        "category": "Communications",
        "priority": "HIGH",
        "description": "Video conferencing — sensitive meeting content, 300M+ daily participants",
    },
    {
        "domain": "paloaltonetworks.com",
        "name": "Palo Alto Networks",
        "category": "Cybersecurity",
        "priority": "HIGH",
        "description": "Cybersecurity giant — firewalls, XDR, SASE platforms",
    },
    {
        "domain": "crowdstrike.com",
        "name": "CrowdStrike",
        "category": "Cybersecurity",
        "priority": "HIGH",
        "description": "EDR/XDR leader — endpoint security for critical infrastructure",
    },
    {
        "domain": "okta.com",
        "name": "Okta",
        "category": "Identity & Security",
        "priority": "HIGH",
        "description": "Identity management — SSO and MFA for 17,000+ enterprise customers",
    },
    {
        "domain": "qualcomm.com",
        "name": "Qualcomm",
        "category": "Semiconductor",
        "priority": "MEDIUM",
        "description": "Mobile chip leader — implementing PQC in Snapdragon platforms",
    },
    {
        "domain": "x.com",
        "name": "X (formerly Twitter)",
        "category": "Social Media",
        "priority": "MEDIUM",
        "description": "Social media platform — 500M+ users, DM and financial data",
    },
    {
        "domain": "linkedin.com",
        "name": "LinkedIn (Microsoft)",
        "category": "Social Media",
        "priority": "HIGH",
        "description": "Professional network — 1B+ member PII, sensitive career data",
    },
    {
        "domain": "dropbox.com",
        "name": "Dropbox",
        "category": "Cloud Storage",
        "priority": "MEDIUM",
        "description": "Cloud storage — encrypted files for 700M+ registered users",
    },
    {
        "domain": "splunk.com",
        "name": "Splunk (Cisco)",
        "category": "Cybersecurity",
        "priority": "MEDIUM",
        "description": "SIEM/security analytics — processes sensitive log data for enterprises",
    },
    {
        "domain": "akamai.com",
        "name": "Akamai Technologies",
        "category": "Network & Security",
        "priority": "HIGH",
        "description": "CDN and security platform — early PQC TLS research contributor",
    },
]

TARGET_MAP  = {t["domain"]: t for t in US_TECH_TARGETS}
ALL_DOMAINS = [t["domain"] for t in US_TECH_TARGETS]
