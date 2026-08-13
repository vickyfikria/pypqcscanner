# 🔐 PQC Readiness Scanner

A Python-based **Post-Quantum Cryptography (PQC) readiness scanner** for government websites (`.go.id` domains).

Measures TLS cryptographic posture against NIST-standardized PQC algorithms:
- **FIPS 203 (ML-KEM)** — Key Encapsulation, replaces RSA/ECDH
- **FIPS 204 (ML-DSA)** — Digital Signatures, replaces RSA/ECDSA
- **FIPS 205 (SLH-DSA)** — Hash-based Signatures
  
## ⚠️ Ethical Use

This scanner:
- Uses **passive TLS inspection** only (no exploitation)
- Makes standard **HTTPS GET/HEAD requests**
- Is intended for **educational and research** purposes
- Should only be used on targets you are authorized to scan

---

## 🚀 Quick Start

```bash
# 1. Clone / navigate into the project
cd pypqscanner

# 2. Install dependencies
pip install -r requirements.txt

# 3. (Optional) Install nmap for enhanced cipher analysis
brew install nmap     # macOS
# apt install nmap    # Linux

# 4. Run a quick scan on one domain
python main.py scan --target kemenkeu.go.id

# 5. Scan all 25 government portals
python main.py scan --all --workers 5

# 6. Scan only CRITICAL priority domains
python main.py scan --priority CRITICAL

# 7. View OQS/liboqs environment
python main.py oqs-info

# 8. Open the HTML report
open output/report.html
```

---

## 📂 Project Structure

```
pypqscanner/
├── main.py                    # CLI entrypoint (typer)
├── requirements.txt           # Dependencies
├── scanner/
│   ├── __init__.py
│   ├── core.py                # Scanner orchestrator (parallel)
│   ├── tls_analyzer.py        # TLS/SSL handshake + certificate analysis
│   ├── nmap_scanner.py        # Nmap ssl-enum-ciphers wrapper
│   ├── pqc_checker.py         # PQC scoring + OQS environment query
│   ├── http_analyzer.py       # HTTP security headers
│   └── report.py              # JSON + HTML report generator
├── targets/
│   ├── __init__.py
│   └── indonesia_gov.py       # 25 curated .go.id target domains
└── output/                    # Generated reports (JSON + HTML)
    ├── report.json
    └── report.html
```

---

## 🛠️ CLI Commands

### `scan` — Run a PQC readiness scan
```bash
python main.py scan [OPTIONS]

Options:
  --target DOMAIN       Scan a single domain
  --all                 Scan all 25 targets
  --priority LEVEL      Filter by priority: CRITICAL, HIGH, MEDIUM
  --workers INT         Parallel workers (default: 5)
  --timeout INT         Timeout per domain in seconds (default: 15)
  --no-nmap             Skip nmap (faster, less detail)
  --output FILE         JSON output path (default: output/report.json)
  --html/--no-html      Generate HTML report (default: yes)
```

### `report` — Regenerate HTML from JSON
```bash
python main.py report --input output/report.json --output output/report.html
```

### `list-targets` — Show all target domains
```bash
python main.py list-targets
python main.py list-targets --priority CRITICAL
```

### `oqs-info` — Show local OQS environment
```bash
python main.py oqs-info
```

---

## 📊 PQC Scoring Rubric (0–100)

| Component | Max Points | What It Measures |
|-----------|-----------|-----------------|
| TLS Version | 20 | TLS 1.3 required for PQC hybrid groups |
| Key Exchange | 15 | ECDHE / forward secrecy |
| Certificate Key | 20 | RSA-2048 (vulnerable) → ML-DSA (PQC) |
| **PQC Hybrid Group** | **30** | X25519MLKEM768 / FIPS 203 hybrid |
| HSTS | 10 | HTTP Strict Transport Security |
| Cipher Strength | 5 | Nmap grade A–F |

### Readiness Levels

| Score | Grade | Level | Color | HNDL Risk |
|-------|-------|-------|-------|-----------|
| 76–100 | A/A+ | 🟢 PQC-Ready | Green | LOW |
| 51–75 | B | 🔵 Classical-Safe | Blue | HIGH |
| 26–50 | C/D | 🟠 Vulnerable | Orange | HIGH |
| 0–25 | F | 🔴 Critical | Red | CRITICAL |

---

## ⚛️ OQS / liboqs Integration

The scanner uses [Open Quantum Safe liboqs-python](https://github.com/open-quantum-safe/liboqs-python) to:

1. **Inventory** which PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) are available in the environment
2. **Report** NIST-standardized algorithm availability (FIPS 203/204/205)
3. **Demonstrate** that PQC algorithms can be instantiated

```python
import oqs

# List supported KEMs
kems = oqs.get_enabled_KEM_mechanisms()   # ['ML-KEM-512', 'ML-KEM-768', ...]

# List supported signatures
sigs = oqs.get_enabled_sig_mechanisms()   # ['ML-DSA-44', 'ML-DSA-65', ...]

# Perform a PQC KEM operation
with oqs.KeyEncapsulation("ML-KEM-768") as client:
    public_key = client.generate_keypair()
    ciphertext, shared_secret_server = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
    shared_secret_client = client.decap_secret(ciphertext)
```

---

## 🎯 Target Domains (25 Indonesian Government Portals)

| Priority | Domain | Agency |
|----------|--------|--------|
| 🔴 CRITICAL | bssn.go.id | National Cyber & Crypto Agency |
| 🔴 CRITICAL | kemenkeu.go.id | Ministry of Finance |
| 🔴 CRITICAL | bi.go.id | Bank Indonesia (Central Bank) |
| 🔴 CRITICAL | pajak.go.id | Directorate General of Taxes |
| 🔴 CRITICAL | imigrasi.go.id | Immigration Authority |
| 🟠 HIGH | kpu.go.id | General Elections Commission |
| 🟠 HIGH | kpk.go.id | Corruption Eradication Commission |
| 🟠 HIGH | bpjs-kesehatan.go.id | National Health Insurance |
| 🟠 HIGH | polri.go.id | Indonesian National Police |
| 🟡 MEDIUM | data.go.id | Satu Data Indonesia |
| ... | ... | + 15 more |

---

## 🔒 What the Scanner Checks

### TLS/SSL Analysis (`scanner/tls_analyzer.py`)
- TLS version negotiation (1.0/1.1/1.2/1.3)
- Cipher suite and key exchange algorithm
- **PQC hybrid group detection** (`X25519MLKEM768`, `SecP256r1MLKEM768`, etc.)
- X.509 certificate: key type, size, signature algorithm, expiry, SANs
- HSTS header presence and configuration

### Nmap Cipher Enumeration (`scanner/nmap_scanner.py`)
- `ssl-enum-ciphers` NSE script for full cipher suite listing
- TLS version support matrix
- Nmap A–F grade per cipher suite
- Graceful fallback if nmap is not installed

### PQC Assessment (`scanner/pqc_checker.py`)
- Composite PQC score (0–100)
- HNDL (Harvest-Now-Decrypt-Later) risk classification
- Migration priority: Immediate / Near-term / Planned / Monitor
- Per-component score breakdown
- Actionable recommendations

### HTTP Security Headers (`scanner/http_analyzer.py`)
- HSTS (Strict-Transport-Security)
- Content-Security-Policy
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy, Permissions-Policy

---

## ⚠️ Ethical Use

This scanner:
- Uses **passive TLS inspection** only (no exploitation)
- Makes standard **HTTPS GET/HEAD requests**
- Is intended for **educational and research** purposes
- Should only be used on targets you are authorized to scan

---

## 📚 References

- [NIST FIPS 203 (ML-KEM)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 (ML-DSA)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 (SLH-DSA)](https://csrc.nist.gov/pubs/fips/205/final)
- [Open Quantum Safe Project](https://openquantumsafe.org)
- [IETF TLS Hybrid Key Exchange Draft](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/)
- [BSSN Indonesia Cybersecurity Guidelines](https://bssn.go.id)
