# 🔐 Global PQC Readiness Scanner

A Python-based **Post-Quantum Cryptography (PQC) readiness scanner** that measures the TLS cryptographic posture of government, e-commerce, and tech company websites across multiple countries against NIST-standardized PQC algorithms.

Currently supports **250 target portals** across 3 countries:

| Country | Gov | E-Commerce | Banking / Tech | Total |
|---------|-----|------------|----------------|-------|
| 🇮🇩 Indonesia | 30 | 10 | 10 (Banks) | **50** |
| 🇲🇾 Malaysia | 30 | 10 | 10 (Banks) | **50** |
| 🇺🇸 USA | 50 | 25 | 25 (Tech) | **100** |

### NIST Standards Assessed
- **FIPS 203 (ML-KEM)** — Key Encapsulation, replaces RSA/ECDH
- **FIPS 204 (ML-DSA)** — Digital Signatures, replaces RSA/ECDSA
- **FIPS 205 (SLH-DSA)** — Hash-based Signatures

## ⚠️ Ethical Use

This scanner:
- Uses **passive TLS inspection** only (no exploitation or fuzzing)
- Makes standard **HTTPS HEAD requests** and raw **TLS ClientHello probes**
- Is intended for **educational and research** purposes
- Reports publicly observable server behavior only
- Should only be used on targets you are **authorized to scan**

---

## 🚀 Quick Start

```bash
# 1. Navigate into the project
<<<<<<< HEAD
cd pqc-us-scanner

# 2. Activate the virtual environment
source .venv314/bin/activate
=======
cd pypqcscanner

# 2. Activate the virtual environment
source .yourvenv/bin/activate
>>>>>>> b674eb0e23cada0f524a733a3c209e5b2031e011

# 3. Scan all 100 US portals (gov + ecommerce + tech)
python main.py scan --country usa --all --no-nmap

# 4. Scan all 50 Indonesia portals
python main.py scan --country indonesia --all --no-nmap

# 5. Scan all 50 Malaysia portals
python main.py scan --country malaysia --all --no-nmap

# 6. Scan a single domain
python main.py scan --target cloudflare.com

# 7. Open the HTML report
open output/report.html
```

---

## 📂 Project Structure

```
pqc-us-scanner/
├── main.py                      # CLI entrypoint (typer)
├── requirements.txt             # Python dependencies
│
├── scanner/
│   ├── core.py                  # Parallel scan orchestrator
│   ├── tls_analyzer.py          # TLS/SSL handshake + certificate analysis
│   ├── pqc_probe.py             # ★ Raw-socket PQC ClientHello prober
│   ├── pqc_checker.py           # PQC scoring engine + OQS environment query
│   ├── nmap_scanner.py          # Nmap ssl-enum-ciphers wrapper (optional)
│   ├── http_analyzer.py         # HTTP security headers
│   └── report.py                # JSON + HTML report generator
│
├── targets/
│   ├── indonesia_gov.py         # 30 Indonesian government portals (.go.id)
│   ├── indonesia_ecommerce.py   # 10 Indonesian e-commerce portals
│   ├── indonesia_banks.py       # 10 Indonesian bank portals
│   ├── malaysia_gov.py          # 30 Malaysian government portals (.gov.my)
│   ├── malaysia_ecommerce.py    # 10 Malaysian e-commerce portals
│   ├── malaysia_banks.py        # 10 Malaysian bank portals
│   ├── us_gov.py                # 50 US federal government portals (.gov)
│   ├── us_ecommerce.py          # 25 US e-commerce portals
│   └── us_tech.py               # 25 US tech company portals
│
└── output/                      # Generated reports
    ├── indonesia_full_report.json
    ├── indonesia_full_report.html
    ├── usa_pqc_report_v2.json
    └── usa_pqc_report_v2.html
```

---

## 🛠️ CLI Reference

### `scan` — Run a PQC readiness scan

```bash
python main.py scan [OPTIONS]
```

| Option | Default | Description |
|--------|---------|-------------|
| `--country` | `indonesia` | Country to scan: `indonesia`, `malaysia`, `usa` |
| `--sector` | `all` | Sector filter: `gov`, `ecommerce`, `banking`, `tech`, `all` |
| `--all` | `False` | Scan all targets for the selected country + sector |
| `--target DOMAIN` | — | Scan a single specific domain |
| `--priority LEVEL` | — | Filter by priority: `CRITICAL`, `HIGH`, `MEDIUM` |
| `--workers INT` | `5` | Parallel workers |
| `--timeout INT` | `15` | Timeout per domain in seconds |
| `--no-nmap` | `False` | Skip nmap (faster, recommended) |
| `--output FILE` | `output/report.json` | JSON output path |
| `--html-output FILE` | `output/report.html` | HTML report path |
| `--no-html` | `False` | Disable HTML generation |

**Examples:**

```bash
# Scan all 100 US portals
python main.py scan --country usa --all --no-nmap --workers 10

# Scan only US government portals
python main.py scan --country usa --sector gov --all

# Scan only Indonesian banks
python main.py scan --country indonesia --sector banking --all

# Scan only US tech companies
python main.py scan --country usa --sector tech --all

# Scan CRITICAL priority Indonesian gov portals
python main.py scan --country indonesia --sector gov --priority CRITICAL

# Scan a single domain
python main.py scan --target cloudflare.com

# Full scan with custom output paths
python main.py scan --country usa --all --no-nmap \
  --output output/usa_report.json \
  --html-output output/usa_report.html
```

### `oqs-info` — Show local OQS/liboqs environment

```bash
python main.py oqs-info
```

Shows which PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) are available locally via `liboqs`.

### `list-targets` — Show all target domains

```bash
python main.py list-targets --country usa
python main.py list-targets --country indonesia --priority CRITICAL
```

### `report` — Regenerate HTML from existing JSON

```bash
python main.py report --input output/usa_report.json --output output/usa_report.html
```

---

## ⭐ Key Feature: Raw-Socket PQC ClientHello Detection (`scanner/pqc_probe.py`)

The most critical feature is the **raw-socket PQC prober** — the only correct method for detecting server-side PQC support.

### Why Python's `ssl` module is insufficient

Python's built-in `ssl` module never advertises PQC key exchange groups (`0x11ec`, `0x6399`) in its ClientHello. This means servers like **Cloudflare** and **Google** — which actively support `X25519MLKEM768` — silently fall back to classical X25519 without the scanner ever knowing they support PQC.

### How `pqc_probe.py` works

It crafts a **hand-built TLS 1.3 ClientHello** that:

1. Advertises PQC groups in the `supported_groups` extension:
   - `0x11ec` → `X25519MLKEM768` (FIPS 203, Chrome 131+, Cloudflare)
   - `0x11eb` → `SecP256r1MLKEM768` (FIPS 203 alternative)
   - `0x6399` → `X25519Kyber768Draft00` (Cloudflare legacy, Chrome 124–130)
2. Includes a valid **X25519 key share** only (no dummy ML-KEM bytes — those cause TLS fatal alerts)
3. Parses the raw **ServerHello** or **HelloRetryRequest** to detect the negotiated group

```
Your probe                              Server (e.g. Cloudflare)
    │── ClientHello ──────────────────►  │
    │   supported_groups:                │
    │     [X25519MLKEM768, X25519, ...]  │
    │                                    │
    │  ◄──────────── ServerHello ──────  │
    │   key_share: X25519MLKEM768 ✅     │
    │                                    │
    │  → pqc_detected = True             │
    │  → pqc_group_name = X25519MLKEM768 │
```

### Standalone test

```bash
python -m scanner.pqc_probe cloudflare.com google.com amazon.com nist.gov

# Output:
# Domain                    PQC?   Group                 Classical fallback   ms
# cloudflare.com            ✅ YES  X25519MLKEM768                             85ms
# google.com                ✅ YES  X25519MLKEM768                             44ms
# amazon.com                ✗  no                        X25519               534ms
# nist.gov                  ✅ YES  X25519MLKEM768                             440ms
```

---

## 📊 PQC Scoring Rubric (0–100)

| Component | Max Points | What It Measures |
|-----------|-----------|-----------------|
| TLS Version | 20 | TLS 1.3 required for PQC hybrid groups |
| Key Exchange | 15 | ECDHE / forward secrecy |
| Certificate Key | 20 | RSA-2048 (vulnerable) → EC → ML-DSA (PQC) |
| **PQC Hybrid Group** | **30** | `X25519MLKEM768` / FIPS 203 detected in handshake |
| HSTS | 10 | HTTP Strict Transport Security |
| Cipher Strength | 5 | Nmap grade A–F |

### Readiness Levels

| Score | Grade | Level | HNDL Risk | Meaning |
|-------|-------|-------|-----------|---------|
| 76–100 | A | 🟢 PQC-Ready | LOW | Hybrid PQC active + strong cert |
| 51–75 | B | 🔵 Classical-Safe | LOW | PQC hybrid active, cert upgrade needed |
| 26–50 | C/D | 🟠 Vulnerable | CRITICAL | No PQC, classical crypto only |
| 0–25 | F | 🔴 Unreachable | UNKNOWN | Could not connect |

### What is PQC Hybrid?

**PQC Hybrid = YES** means the server performed a dual-algorithm key exchange:

```
session_key = X25519_secret  ⊕  ML-KEM-768_secret
              (classical)        (quantum-safe)
```

Both algorithms must be broken simultaneously to compromise the session. A quantum computer can break X25519 — but **cannot** break ML-KEM-768 (FIPS 203). This protects against **Harvest-Now-Decrypt-Later (HNDL)** attacks, where adversaries capture encrypted traffic today to decrypt it once quantum computers exist.

---

## 📈 Scan Results Summary (August 2026)

### 🇺🇸 USA — 100 Portals

| Metric | Result |
|--------|--------|
| PQC-Ready (PQC Hybrid detected) | **18 / 100 (18%)** |
| Average PQC score | **40.4 / 100** |
| TLS 1.3 adoption | ~76% of reachable |
| HNDL Risk (CRITICAL) | 64 domains |

**Top PQC-Ready US sites:** `cloudflare.com`, `google.com`, `nist.gov`, `fbi.gov`, `apple.com`, `crowdstrike.com`, `shopify.com`, `federalreserve.gov`, `meta.com`, `zoom.us`

### 🇮🇩 Indonesia — 50 Portals

| Metric | Result |
|--------|--------|
| PQC-Ready | **0 / 50 (0%)** |
| Average PQC score | **32.0 / 100** |
| TLS 1.3 adoption | ~88% of reachable |
| HNDL Risk (CRITICAL) | 40 domains |

**Notable:** `BSSN` (national cyber agency) scores only 41/100 with RSA-2048 and no PQC.

### 🇲🇾 Malaysia — 50 Portals

| Metric | Result |
|--------|--------|
| PQC-Ready | **0 / 50 (0%)** |
| Average PQC score | **~32 / 100** |
| TLS 1.3 adoption | ~70% of reachable |
| HNDL Risk (CRITICAL) | ~35 domains |

---

## ⚛️ OQS / liboqs Integration

The scanner uses [Open Quantum Safe liboqs-python](https://github.com/open-quantum-safe/liboqs-python) v0.16.0 to inventory and demonstrate local PQC algorithm availability.

```python
import oqs

# List supported KEMs
kems = oqs.get_enabled_KEM_mechanisms()
# ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', ...]

# List supported signatures
sigs = oqs.get_enabled_sig_mechanisms()
# ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'SLH-DSA-SHA2-128f', ...]

# Perform a PQC KEM operation
with oqs.KeyEncapsulation("ML-KEM-768") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = oqs.KeyEncapsulation("ML-KEM-768").encap_secret(public_key)
    recovered = kem.decap_secret(ciphertext)
    assert shared_secret == recovered  # ✅
```

> **Note:** liboqs must be compiled from source. The project uses Python 3.14 venv (`.venv314`). See [Open Quantum Safe build instructions](https://github.com/open-quantum-safe/liboqs).

---

## 🔒 What the Scanner Checks

### 1. PQC-Capable TLS Handshake (`scanner/pqc_probe.py`)
- Crafts raw TLS 1.3 ClientHello advertising PQC key exchange groups
- Detects `X25519MLKEM768`, `SecP256r1MLKEM768`, `X25519Kyber768Draft00`
- Parses ServerHello and HelloRetryRequest for negotiated group
- **This is the key innovation** — standard TLS libraries cannot do this

### 2. TLS/SSL Analysis (`scanner/tls_analyzer.py`)
- TLS version negotiation (1.2 / 1.3)
- Cipher suite and key exchange algorithm
- X.509 certificate: key type, size, signature algorithm, expiry, SANs
- HSTS header presence and configuration

### 3. PQC Scoring Engine (`scanner/pqc_checker.py`)
- Composite PQC score (0–100) with per-component breakdown
- HNDL (Harvest-Now-Decrypt-Later) risk classification
- Migration priority: Immediate / Near-term / Planned / Monitor
- Actionable recommendations per domain

### 4. Nmap Cipher Enumeration (`scanner/nmap_scanner.py`) — optional
- `ssl-enum-ciphers` NSE script for full cipher suite listing
- TLS version support matrix
- Nmap A–F grade per cipher suite
- Gracefully skipped with `--no-nmap`

### 5. HTTP Security Headers (`scanner/http_analyzer.py`)
- HSTS, Content-Security-Policy, X-Frame-Options, X-Content-Type-Options

### 6. Report Generation (`scanner/report.py`)
- Rich terminal table output with color coding
- JSON report for programmatic use
- HTML report with full per-domain breakdown

---


<<<<<<< HEAD
This scanner:
- Uses **passive TLS inspection** only (no exploitation or fuzzing)
- Makes standard **HTTPS HEAD requests** and raw **TLS ClientHello probes**
- Is intended for **educational and research** purposes
- Reports publicly observable server behavior only
- Should only be used on targets you are **authorized to scan**
=======
>>>>>>> b674eb0e23cada0f524a733a3c209e5b2031e011

---

## 📚 References

| Resource | Link |
|----------|------|
| NIST FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST FIPS 204 (ML-DSA) | https://csrc.nist.gov/pubs/fips/204/final |
| NIST FIPS 205 (SLH-DSA) | https://csrc.nist.gov/pubs/fips/205/final |
| IETF TLS Hybrid Key Exchange | https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/ |
| IANA TLS Named Groups Registry | https://www.iana.org/assignments/tls-parameters/ |
| Open Quantum Safe Project | https://openquantumsafe.org |
| liboqs-python | https://github.com/open-quantum-safe/liboqs-python |
| NSA CNSA 2.0 (US PQC mandate) | https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF |
| BSSN Indonesia Cybersecurity | https://bssn.go.id |
