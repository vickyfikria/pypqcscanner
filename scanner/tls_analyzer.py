"""
scanner/tls_analyzer.py
TLS/SSL handshake analyzer — extracts cipher suites, key exchange groups,
certificate details, and tests for hybrid PQC group support.
"""

import ssl
import socket
import datetime
import ipaddress
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, ed448
from cryptography.x509.oid import ExtensionOID


# ─── PQC Group identifiers (IETF hybrid TLS 1.3 named groups) ───
# These are the group IDs used in the TLS 1.3 key_share extension
# for hybrid classical+PQC key exchange.
PQC_HYBRID_GROUPS = {
    "X25519MLKEM768":     "Hybrid X25519 + ML-KEM-768 (FIPS 203) — RECOMMENDED",
    "SecP256r1MLKEM768":  "Hybrid ECDH P-256 + ML-KEM-768 (FIPS 203)",
    "X25519MLKEM512":     "Hybrid X25519 + ML-KEM-512 (FIPS 203)",
    "SecP384r1MLKEM1024": "Hybrid ECDH P-384 + ML-KEM-1024 (FIPS 203)",
    "X25519Kyber768":     "Hybrid X25519 + Kyber-768 (pre-standard, experimental)",
    "SecP256r1Kyber768":  "Hybrid P-256 + Kyber-768 (pre-standard, experimental)",
}

# TLS groups to test in order of PQC priority
PQC_TEST_GROUPS = list(PQC_HYBRID_GROUPS.keys())

# Classical groups (not PQC)
CLASSICAL_GROUPS = {
    "X25519":   "X25519 ECDH — quantum-vulnerable",
    "X448":     "X448 ECDH — quantum-vulnerable",
    "P-256":    "NIST P-256 ECDH — quantum-vulnerable",
    "P-384":    "NIST P-384 ECDH — quantum-vulnerable",
    "P-521":    "NIST P-521 ECDH — quantum-vulnerable",
}

# Known-weak / deprecated algorithms
WEAK_KEY_EXCHANGES = {"RSA", "DH", "DHE"}
DEPRECATED_TLS_VERSIONS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


@dataclass
class CertificateInfo:
    subject_cn: str = ""
    issuer_cn: str = ""
    issuer_org: str = ""
    key_type: str = ""          # RSA, EC, Ed25519, etc.
    key_size: int = 0
    sig_algorithm: str = ""
    not_before: Optional[datetime.datetime] = None
    not_after: Optional[datetime.datetime] = None
    days_remaining: int = 0
    is_expired: bool = False
    san_domains: list = field(default_factory=list)
    is_ev: bool = False
    is_wildcard: bool = False
    serial_number: str = ""
    fingerprint_sha256: str = ""
    # PQC-specific
    is_pqc_cert: bool = False       # True if cert uses PQC key/sig
    pqc_algorithm: str = ""         # e.g. "ML-DSA-65"
    quantum_risk: str = ""          # "HIGH" / "MEDIUM" / "LOW"


@dataclass
class TLSConnectionInfo:
    domain: str = ""
    port: int = 443
    tls_version: str = ""
    cipher_suite: str = ""
    cipher_bits: int = 0
    key_exchange: str = ""
    negotiated_group: str = ""      # e.g. "X25519MLKEM768"
    is_pqc_hybrid: bool = False
    pqc_group_name: str = ""
    supports_tls13: bool = False
    supports_tls12: bool = False
    supports_tls11: bool = False    # Should be False (deprecated)
    supports_tls10: bool = False    # Should be False (deprecated)
    tls13_ciphers: list = field(default_factory=list)
    tls12_ciphers: list = field(default_factory=list)
    hsts_enabled: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    cert: Optional[CertificateInfo] = None
    error: str = ""
    connection_time_ms: float = 0.0


class TLSAnalyzer:
    """
    Analyzes TLS/SSL configuration of a target host.
    Checks for PQC readiness via:
      1. Certificate key type and signature algorithm
      2. Negotiated TLS version and cipher suite
      3. Key exchange group (hybrid PQC detection)
    """

    DEFAULT_TIMEOUT = 10  # seconds

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout

    def analyze(self, domain: str, port: int = 443) -> TLSConnectionInfo:
        """Full TLS analysis for a given domain."""
        info = TLSConnectionInfo(domain=domain, port=port)

        # 1. Primary connection — get cert + current TLS details
        self._connect_and_inspect(info)
        if info.error:
            return info

        # 2. Test TLS version support
        self._probe_tls_versions(info)

        # 3. Test for hybrid PQC group support
        self._probe_pqc_groups(info)

        return info

    def _connect_and_inspect(self, info: TLSConnectionInfo):
        """Open an SSL connection and extract certificate and handshake details."""
        import time
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            start = time.time()
            with socket.create_connection((info.domain, info.port), timeout=self.timeout) as raw_sock:
                with ctx.wrap_socket(raw_sock, server_hostname=info.domain) as ssl_sock:
                    info.connection_time_ms = (time.time() - start) * 1000

                    # TLS handshake details
                    info.tls_version = ssl_sock.version() or ""
                    cipher = ssl_sock.cipher()
                    if cipher:
                        info.cipher_suite = cipher[0]
                        info.cipher_bits = cipher[2] or 0
                        info.key_exchange = self._parse_key_exchange(cipher[0])

                    # Negotiated group (Python 3.10+)
                    if hasattr(ssl_sock, "get_channel_binding"):
                        pass
                    try:
                        # group() available on newer Python ssl
                        grp = ssl_sock.group() if hasattr(ssl_sock, "group") else None
                        if grp:
                            info.negotiated_group = grp
                            if grp in PQC_HYBRID_GROUPS:
                                info.is_pqc_hybrid = True
                                info.pqc_group_name = grp
                    except Exception:
                        pass

                    # HSTS check
                    try:
                        import http.client
                        conn = http.client.HTTPSConnection(
                            info.domain, port=info.port,
                            timeout=self.timeout,
                            context=ctx
                        )
                        conn.request("HEAD", "/")
                        resp = conn.getresponse()
                        hsts_header = resp.getheader("Strict-Transport-Security", "")
                        if hsts_header:
                            info.hsts_enabled = True
                            for part in hsts_header.split(";"):
                                part = part.strip()
                                if part.lower().startswith("max-age="):
                                    try:
                                        info.hsts_max_age = int(part.split("=")[1])
                                    except ValueError:
                                        pass
                                if part.lower() == "includesubdomains":
                                    info.hsts_include_subdomains = True
                        conn.close()
                    except Exception:
                        pass

                    # Certificate (PEM form)
                    der_cert = ssl_sock.getpeercert(binary_form=True)
                    if der_cert:
                        info.cert = self._parse_certificate(der_cert)

        except ssl.SSLCertVerificationError as e:
            info.error = f"SSL cert verification failed: {e}"
        except ssl.SSLError as e:
            info.error = f"SSL error: {e}"
        except socket.timeout:
            info.error = "Connection timed out"
        except ConnectionRefusedError:
            info.error = "Connection refused"
        except OSError as e:
            info.error = f"Network error: {e}"
        except Exception as e:
            info.error = f"Unexpected error: {e}"

    def _probe_tls_versions(self, info: TLSConnectionInfo):
        """Test which TLS protocol versions the server accepts."""
        version_map = {
            "TLSv1.3": (ssl.TLSVersion.TLSv1_3, "supports_tls13"),
            "TLSv1.2": (ssl.TLSVersion.TLSv1_2, "supports_tls12"),
        }
        # TLS 1.0 and 1.1 may not be available in modern Python ssl
        for label, (version, attr) in version_map.items():
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.minimum_version = version
                ctx.maximum_version = version
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((info.domain, info.port), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=info.domain):
                        setattr(info, attr, True)
            except Exception:
                setattr(info, attr, False)

        # Also mark current negotiated version
        if info.tls_version == "TLSv1.3":
            info.supports_tls13 = True
        elif info.tls_version == "TLSv1.2":
            info.supports_tls12 = True

    def _probe_pqc_groups(self, info: TLSConnectionInfo):
        """
        Test if the server accepts PQC hybrid key exchange by sending a real
        PQC-capable ClientHello (X25519MLKEM768 + X25519Kyber768Draft00 key
        shares). Uses raw sockets — the only method that actually works because
        Python's ssl module never advertises PQC groups in the ClientHello.
        """
        try:
            from scanner.pqc_probe import probe_pqc
            result = probe_pqc(info.domain, info.port, timeout=min(self.timeout, 8))

            if result.pqc_detected:
                info.is_pqc_hybrid   = True
                info.pqc_group_name  = result.pqc_group_name
                info.negotiated_group = result.pqc_group_name
            elif result.classical_group_name:
                info.negotiated_group = result.classical_group_name

            # Confirm TLS 1.3 from raw handshake if ssl module didn't catch it
            if result.tls13_confirmed and not info.supports_tls13:
                info.supports_tls13 = True

        except Exception:
            # Fall back gracefully — PQC just won't be detected
            pass

    def _parse_key_exchange(self, cipher_name: str) -> str:
        """Extract key exchange type from cipher suite name."""
        cipher_upper = cipher_name.upper()
        if "ECDHE" in cipher_upper:
            return "ECDHE"
        if "DHE" in cipher_upper or "EDH" in cipher_upper:
            return "DHE"
        if "RSA" in cipher_upper:
            return "RSA"
        if "MLKEM" in cipher_upper or "KYBER" in cipher_upper:
            return "PQC-Hybrid"
        return "Unknown"

    def _parse_certificate(self, der_bytes: bytes) -> CertificateInfo:
        """Parse a DER-encoded X.509 certificate into CertificateInfo."""
        cert_info = CertificateInfo()
        try:
            cert = x509.load_der_x509_certificate(der_bytes)

            # Subject CN
            try:
                cert_info.subject_cn = cert.subject.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
            except (IndexError, Exception):
                cert_info.subject_cn = "<no CN>"

            # Issuer
            try:
                cert_info.issuer_cn = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.COMMON_NAME
                )[0].value
            except (IndexError, Exception):
                cert_info.issuer_cn = "<unknown issuer>"
            try:
                cert_info.issuer_org = cert.issuer.get_attributes_for_oid(
                    x509.NameOID.ORGANIZATION_NAME
                )[0].value
            except (IndexError, Exception):
                cert_info.issuer_org = ""

            # Signature algorithm
            sig_algo = cert.signature_algorithm_oid.dotted_string
            try:
                sig_algo = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else sig_algo
                sig_algo_name = type(cert.signature_algorithm_parameters).__name__ if hasattr(cert, 'signature_algorithm_parameters') else ""
            except Exception:
                sig_algo_name = ""

            # Better sig algo name from hash
            try:
                algo_name = cert.signature_algorithm_oid._name
                cert_info.sig_algorithm = algo_name if algo_name else sig_algo
            except Exception:
                cert_info.sig_algorithm = sig_algo

            # Public key analysis
            pub_key = cert.public_key()
            if isinstance(pub_key, rsa.RSAPublicKey):
                cert_info.key_type = "RSA"
                cert_info.key_size = pub_key.key_size
                cert_info.quantum_risk = "HIGH" if pub_key.key_size < 4096 else "MEDIUM"
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                cert_info.key_type = f"EC ({pub_key.curve.name})"
                cert_info.key_size = pub_key.key_size
                cert_info.quantum_risk = "HIGH"  # All ECDSA is quantum-vulnerable
            elif isinstance(pub_key, ed25519.Ed25519PublicKey):
                cert_info.key_type = "Ed25519"
                cert_info.key_size = 256
                cert_info.quantum_risk = "HIGH"
            elif isinstance(pub_key, ed448.Ed448PublicKey):
                cert_info.key_type = "Ed448"
                cert_info.key_size = 448
                cert_info.quantum_risk = "HIGH"
            else:
                # Possibly a PQC key type
                key_class = type(pub_key).__name__
                cert_info.key_type = key_class
                cert_info.quantum_risk = "LOW"
                if any(algo in key_class.upper() for algo in ["MLDSA", "DILITHIUM", "FALCON", "SPHINCS"]):
                    cert_info.is_pqc_cert = True
                    cert_info.pqc_algorithm = key_class
                    cert_info.quantum_risk = "NONE"

            # Validity dates
            cert_info.not_before = cert.not_valid_before_utc
            cert_info.not_after = cert.not_valid_after_utc
            now = datetime.datetime.now(datetime.timezone.utc)
            cert_info.is_expired = now > cert_info.not_after
            cert_info.days_remaining = (cert_info.not_after - now).days

            # SANs
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                cert_info.san_domains = [
                    name.value for name in san_ext.value
                    if isinstance(name, x509.DNSName)
                ]
                cert_info.is_wildcard = any(d.startswith("*.") for d in cert_info.san_domains)
            except x509.ExtensionNotFound:
                cert_info.san_domains = []

            # Serial number
            cert_info.serial_number = hex(cert.serial_number)

            # SHA-256 fingerprint
            cert_info.fingerprint_sha256 = cert.fingerprint(hashes.SHA256()).hex()

            # EV cert check (has jurisdiction fields)
            try:
                ev_oids = [x509.NameOID.JURISDICTION_COUNTRY_NAME]
                for oid in ev_oids:
                    if cert.subject.get_attributes_for_oid(oid):
                        cert_info.is_ev = True
                        break
            except Exception:
                pass

        except Exception as e:
            cert_info.subject_cn = f"Parse error: {e}"

        return cert_info
