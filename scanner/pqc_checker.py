"""
scanner/pqc_checker.py
Post-Quantum Cryptography assessment module.
Uses the Open Quantum Safe (OQS) liboqs-python library to:
  - List supported PQC algorithms in the environment
  - Score each target's PQC readiness (0–100)
  - Flag Harvest-Now-Decrypt-Later (HNDL) risk
  - Provide migration recommendations
"""

from dataclasses import dataclass, field
from typing import Optional

# Try to import OQS library
try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    OQS_AVAILABLE = False
    oqs = None  # type: ignore


# ─── NIST PQC Standards (FIPS 203, 204, 205) ───
NIST_KEM_ALGORITHMS = {
    "ML-KEM-512":  {"fips": "FIPS 203", "security_level": 1, "type": "KEM"},
    "ML-KEM-768":  {"fips": "FIPS 203", "security_level": 3, "type": "KEM"},
    "ML-KEM-1024": {"fips": "FIPS 203", "security_level": 5, "type": "KEM"},
}

NIST_SIG_ALGORITHMS = {
    "ML-DSA-44":     {"fips": "FIPS 204", "security_level": 2, "type": "SIG"},
    "ML-DSA-65":     {"fips": "FIPS 204", "security_level": 3, "type": "SIG"},
    "ML-DSA-87":     {"fips": "FIPS 204", "security_level": 5, "type": "SIG"},
    "SLH-DSA-SHA2-128f": {"fips": "FIPS 205", "security_level": 1, "type": "SIG"},
    "SLH-DSA-SHAKE-128f": {"fips": "FIPS 205", "security_level": 1, "type": "SIG"},
    "SLH-DSA-SHA2-256f": {"fips": "FIPS 205", "security_level": 5, "type": "SIG"},
}

# Hybrid TLS groups that indicate PQC readiness
PQC_TLS_GROUPS = {
    "X25519MLKEM768":     {"score_bonus": 40, "description": "ML-KEM-768 hybrid (FIPS 203) — Gold standard"},
    "SecP256r1MLKEM768":  {"score_bonus": 35, "description": "ML-KEM-768 hybrid (FIPS 203)"},
    "X25519MLKEM512":     {"score_bonus": 30, "description": "ML-KEM-512 hybrid (FIPS 203)"},
    "SecP384r1MLKEM1024": {"score_bonus": 40, "description": "ML-KEM-1024 hybrid (FIPS 203)"},
    "X25519Kyber768":     {"score_bonus": 20, "description": "Pre-standard Kyber (experimental)"},
    "SecP256r1Kyber768":  {"score_bonus": 15, "description": "Pre-standard Kyber (experimental)"},
}

# Classical algorithm risk assessment
CLASSICAL_RISK = {
    "RSA-1024":  ("CRITICAL", "Factorizable with classical computers today"),
    "RSA-2048":  ("HIGH",     "Quantum computer with 4000 qubits would break in hours"),
    "RSA-4096":  ("MEDIUM",   "Safer but still quantum-vulnerable; plan migration"),
    "EC-P256":   ("HIGH",     "256-bit ECC broken by 2330-qubit quantum computer"),
    "EC-P384":   ("HIGH",     "384-bit ECC — all ECC is quantum-vulnerable"),
    "Ed25519":   ("HIGH",     "All elliptic curve schemes vulnerable to Shor's algorithm"),
    "Ed448":     ("HIGH",     "All elliptic curve schemes vulnerable to Shor's algorithm"),
}


@dataclass
class OQSEnvironmentInfo:
    """Information about OQS/liboqs availability in this environment."""
    oqs_available: bool = False
    oqs_version: str = ""
    enabled_kems: list = field(default_factory=list)
    enabled_sigs: list = field(default_factory=list)
    nist_kems_available: list = field(default_factory=list)    # Intersect with NIST standards
    nist_sigs_available: list = field(default_factory=list)
    total_kems: int = 0
    total_sigs: int = 0
    install_note: str = ""


@dataclass
class PQCReadinessResult:
    """Full PQC readiness assessment for a single domain."""
    domain: str = ""

    # Score (0–100)
    pqc_score: int = 0
    pqc_grade: str = ""         # A+, A, B, C, D, F
    readiness_level: str = ""   # "PQC-Ready", "Classical-Safe", "Vulnerable", "Critical"
    readiness_color: str = ""   # For UI rendering: "green", "yellow", "orange", "red"

    # HNDL (Harvest Now, Decrypt Later) risk
    hndl_risk: str = ""         # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    hndl_explanation: str = ""

    # Findings
    pqc_hybrid_detected: bool = False
    pqc_group_used: str = ""
    cert_key_type: str = ""
    cert_quantum_risk: str = ""
    tls_version: str = ""
    supports_tls13: bool = False

    # Scoring breakdown
    score_tls_version: int = 0
    score_key_exchange: int = 0
    score_cert_key: int = 0
    score_pqc_hybrid: int = 0
    score_hsts: int = 0
    score_cipher_strength: int = 0

    # Recommendations
    recommendations: list = field(default_factory=list)
    migration_priority: str = ""   # "Immediate", "Near-term", "Planned", "Monitor"

    # Issues found
    issues: list = field(default_factory=list)
    positives: list = field(default_factory=list)


def get_oqs_environment() -> OQSEnvironmentInfo:
    """Query the local OQS/liboqs environment for supported algorithms."""
    info = OQSEnvironmentInfo()

    if not OQS_AVAILABLE:
        info.install_note = (
            "liboqs-python not installed. Install with: pip install liboqs-python\n"
            "Note: Requires cmake and a C compiler to build liboqs.\n"
            "macOS: brew install cmake  |  Linux: apt install cmake build-essential"
        )
        return info

    try:
        info.oqs_available = True

        # Get version — v0.16.0 exposes OQS_VERSION constant and oqs_version()
        try:
            info.oqs_version = oqs.oqs_version()
        except Exception:
            try:
                info.oqs_version = str(oqs.OQS_VERSION)
            except Exception:
                info.oqs_version = "unknown"

        # List supported KEMs — v0.16.0 uses lowercase method names
        info.enabled_kems = oqs.get_enabled_kem_mechanisms()
        info.total_kems = len(info.enabled_kems)

        # List supported signatures
        info.enabled_sigs = oqs.get_enabled_sig_mechanisms()
        info.total_sigs = len(info.enabled_sigs)

        # Find NIST standard algorithms
        info.nist_kems_available = [
            alg for alg in NIST_KEM_ALGORITHMS.keys()
            if any(alg in enabled or enabled.replace("_", "-") == alg
                   for enabled in info.enabled_kems)
        ]
        info.nist_sigs_available = [
            alg for alg in NIST_SIG_ALGORITHMS.keys()
            if any(alg in enabled or enabled.replace("_", "-") == alg
                   for enabled in info.enabled_sigs)
        ]

    except Exception as e:
        info.oqs_available = False
        info.install_note = f"OQS import failed: {e}"

    return info


class PQCChecker:
    """
    Computes a PQC readiness score (0–100) for a domain based on:
      - TLS version
      - Key exchange algorithm
      - Certificate key type and size
      - Hybrid PQC group detection
      - HSTS configuration
      - Cipher suite strength
    """

    def assess(
        self,
        domain: str,
        tls_version: str,
        cipher_suite: str,
        key_exchange: str,
        negotiated_group: str,
        is_pqc_hybrid: bool,
        cert_key_type: str,
        cert_key_size: int,
        cert_quantum_risk: str,
        supports_tls13: bool,
        supports_tls12: bool,
        hsts_enabled: bool,
        hsts_max_age: int,
        nmap_least_strength: str = "",
        connection_error: str = "",
    ) -> PQCReadinessResult:
        """Compute a PQC readiness score and detailed recommendations."""

        result = PQCReadinessResult(domain=domain)
        result.pqc_hybrid_detected = is_pqc_hybrid
        result.pqc_group_used = negotiated_group
        result.cert_key_type = cert_key_type
        result.cert_quantum_risk = cert_quantum_risk
        result.tls_version = tls_version
        result.supports_tls13 = supports_tls13

        if connection_error:
            result.readiness_level = "Unreachable"
            result.readiness_color = "gray"
            result.pqc_score = 0
            result.pqc_grade = "N/A"
            result.hndl_risk = "UNKNOWN"
            result.issues.append(f"❌ Could not connect: {connection_error}")
            return result

        # ─── Scoring ───────────────────────────────────────────────────

        # 1. TLS Version (max 20 pts)
        if tls_version == "TLSv1.3":
            result.score_tls_version = 20
            result.positives.append("✅ TLS 1.3 (latest protocol) is active")
        elif tls_version == "TLSv1.2" or supports_tls12:
            result.score_tls_version = 10
            result.issues.append("⚠️  Only TLS 1.2 negotiated — TLS 1.3 not active on port 443")
        elif tls_version in ("TLSv1", "TLSv1.1", "SSLv3"):
            result.score_tls_version = 0
            result.issues.append(f"🚨 {tls_version} is deprecated and insecure!")

        if not supports_tls13 and tls_version != "TLSv1.3":
            result.issues.append("🚨 TLS 1.3 not supported — required for PQC hybrid groups")

        # 2. Key Exchange (max 15 pts)
        kex_upper = key_exchange.upper()
        if "ECDHE" in kex_upper or "X25519" in kex_upper:
            result.score_key_exchange = 15
            result.positives.append("✅ Forward-secret ECDHE key exchange")
        elif "DHE" in kex_upper:
            result.score_key_exchange = 10
            result.positives.append("✅ Forward-secret DHE key exchange (but not PQC-safe)")
        elif "RSA" in kex_upper and "ECDHE" not in kex_upper:
            result.score_key_exchange = 0
            result.issues.append("🚨 Static RSA key exchange — no forward secrecy!")

        # 3. Certificate key type (max 20 pts)
        cert_key_upper = cert_key_type.upper()
        if "RSA" in cert_key_upper:
            if cert_key_size >= 4096:
                result.score_cert_key = 15
                result.positives.append(f"✅ RSA-{cert_key_size} certificate (larger key)")
                result.issues.append(f"⚠️  RSA-{cert_key_size} is still quantum-vulnerable")
            elif cert_key_size >= 2048:
                result.score_cert_key = 8
                result.issues.append(f"⚠️  RSA-{cert_key_size} certificate — quantum-vulnerable")
            else:
                result.score_cert_key = 0
                result.issues.append(f"🚨 RSA-{cert_key_size} is critically weak!")
        elif "EC" in cert_key_upper or "ED25519" in cert_key_upper:
            result.score_cert_key = 12
            result.positives.append(f"✅ {cert_key_type} certificate — modern classical crypto")
            result.issues.append(f"⚠️  {cert_key_type} is quantum-vulnerable via Shor's algorithm")
        elif any(pqc in cert_key_upper for pqc in ["MLDSA", "DILITHIUM", "FALCON", "SPHINCS"]):
            result.score_cert_key = 20
            result.positives.append(f"🏆 PQC certificate detected: {cert_key_type}!")
        else:
            result.score_cert_key = 10
            result.issues.append(f"⚠️  Unknown cert key type: {cert_key_type}")

        # 4. PQC Hybrid Key Exchange (max 30 pts — the most important factor)
        if is_pqc_hybrid and negotiated_group:
            group_info = PQC_TLS_GROUPS.get(negotiated_group, {})
            bonus = group_info.get("score_bonus", 25)
            result.score_pqc_hybrid = min(30, bonus)
            result.positives.append(
                f"🏆 PQC Hybrid group active: {negotiated_group} "
                f"({group_info.get('description', '')})"
            )
        else:
            result.score_pqc_hybrid = 0
            result.issues.append(
                "🚨 No PQC hybrid key exchange detected — "
                "vulnerable to Harvest-Now-Decrypt-Later (HNDL) attacks"
            )

        # 5. HSTS (max 10 pts)
        if hsts_enabled:
            if hsts_max_age >= 31536000:  # 1 year
                result.score_hsts = 10
                result.positives.append(f"✅ HSTS enabled (max-age={hsts_max_age}s)")
            else:
                result.score_hsts = 5
                result.positives.append(f"⚠️  HSTS enabled but max-age={hsts_max_age}s is short")
        else:
            result.score_hsts = 0
            result.issues.append("⚠️  HSTS not detected — downgrade attacks possible")

        # 6. Cipher strength from nmap (max 5 pts)
        if nmap_least_strength:
            grade_scores = {"A": 5, "B": 3, "C": 1, "D": 0, "F": 0}
            result.score_cipher_strength = grade_scores.get(nmap_least_strength.upper(), 0)
            if nmap_least_strength.upper() == "A":
                result.positives.append("✅ All cipher suites rated A by nmap")
            elif nmap_least_strength.upper() in ("C", "D", "F"):
                result.issues.append(f"🚨 Weak cipher suites present (nmap grade: {nmap_least_strength})")
        else:
            result.score_cipher_strength = 3  # Assume moderate if nmap unavailable

        # ─── Total Score ────────────────────────────────────────────────
        result.pqc_score = (
            result.score_tls_version
            + result.score_key_exchange
            + result.score_cert_key
            + result.score_pqc_hybrid
            + result.score_hsts
            + result.score_cipher_strength
        )
        result.pqc_score = max(0, min(100, result.pqc_score))

        # ─── Grade ──────────────────────────────────────────────────────
        if result.pqc_score >= 90:
            result.pqc_grade = "A+"
            result.readiness_level = "PQC-Ready"
            result.readiness_color = "green"
            result.migration_priority = "Monitor"
        elif result.pqc_score >= 76:
            result.pqc_grade = "A"
            result.readiness_level = "PQC-Ready"
            result.readiness_color = "green"
            result.migration_priority = "Monitor"
        elif result.pqc_score >= 60:
            result.pqc_grade = "B"
            result.readiness_level = "Classical-Safe"
            result.readiness_color = "blue"
            result.migration_priority = "Planned"
        elif result.pqc_score >= 45:
            result.pqc_grade = "C"
            result.readiness_level = "Classical-Safe"
            result.readiness_color = "yellow"
            result.migration_priority = "Near-term"
        elif result.pqc_score >= 26:
            result.pqc_grade = "D"
            result.readiness_level = "Vulnerable"
            result.readiness_color = "orange"
            result.migration_priority = "Near-term"
        else:
            result.pqc_grade = "F"
            result.readiness_level = "Critical"
            result.readiness_color = "red"
            result.migration_priority = "Immediate"

        # ─── HNDL Risk ──────────────────────────────────────────────────
        if is_pqc_hybrid:
            result.hndl_risk = "LOW"
            result.hndl_explanation = (
                "Hybrid PQC key exchange active — current traffic protected against "
                "Harvest-Now-Decrypt-Later attacks."
            )
        elif supports_tls13 and "ECDHE" in (key_exchange or "").upper():
            result.hndl_risk = "HIGH"
            result.hndl_explanation = (
                "TLS 1.3 + ECDHE provides forward secrecy but is vulnerable to future "
                "quantum computers. Recorded traffic today CAN be decrypted when "
                "cryptographically-relevant quantum computers (CRQCs) emerge (~2030-2040)."
            )
        else:
            result.hndl_risk = "CRITICAL"
            result.hndl_explanation = (
                "No forward secrecy or TLS 1.3 — all recorded traffic is immediately "
                "at risk when quantum computers emerge. Priority: IMMEDIATE migration."
            )

        # ─── Recommendations ────────────────────────────────────────────
        recs = []
        if not supports_tls13:
            recs.append(
                "🔧 Enable TLS 1.3 on your web server. "
                "Nginx: ssl_protocols TLSv1.2 TLSv1.3; "
                "Apache: SSLProtocol TLSv1.2 TLSv1.3"
            )
        if not is_pqc_hybrid:
            recs.append(
                "🔧 Configure X25519MLKEM768 hybrid key exchange. "
                "Requires OpenSSL 3.5+ or nginx with oqs-provider. "
                "Nginx: ssl_ecdh_curve X25519MLKEM768:X25519;"
            )
        if "RSA" in cert_key_upper and cert_key_size < 4096:
            recs.append(
                f"🔧 Upgrade from RSA-{cert_key_size} to at minimum RSA-4096, "
                "or plan migration to ML-DSA certificate (FIPS 204)."
            )
        if not hsts_enabled:
            recs.append(
                "🔧 Enable HSTS: "
                "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            )
        if cert_key_type and not any(
            pqc in cert_key_upper for pqc in ["MLDSA", "DILITHIUM", "FALCON"]
        ):
            recs.append(
                "📋 Long-term: Migrate certificate to ML-DSA-65 (FIPS 204) "
                "when your CA supports PQC certificates."
            )
        recs.append(
            "📋 Refer to BSSN guidance and NIST SP 800-208 for PQC migration timeline."
        )
        result.recommendations = recs

        return result
