"""
scanner/nmap_scanner.py
Wrapper around nmap for port scanning and SSL cipher suite enumeration.
Uses the nmap ssl-enum-ciphers NSE script for detailed TLS analysis.
Gracefully falls back if nmap is unavailable.
"""

import subprocess
import shutil
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

try:
    import nmap as nmap_lib
    NMAP_LIB_AVAILABLE = True
except ImportError:
    NMAP_LIB_AVAILABLE = False


NMAP_BINARY = shutil.which("nmap")
NMAP_AVAILABLE = NMAP_BINARY is not None


@dataclass
class CipherSuiteEntry:
    name: str = ""
    protocol: str = ""
    key_bits: int = 0
    strength: str = ""          # A, B, C, D, F (nmap grade)
    is_pqc_related: bool = False


@dataclass
class NmapScanResult:
    domain: str = ""
    ip_address: str = ""
    port_open: bool = False
    port: int = 443
    service: str = ""
    product: str = ""
    version: str = ""
    nmap_available: bool = NMAP_AVAILABLE
    # TLS data from ssl-enum-ciphers
    tls_versions_supported: list = field(default_factory=list)
    ciphers_by_version: dict = field(default_factory=dict)   # {version: [CipherSuiteEntry]}
    least_strength: str = ""    # Weakest grade found across all cipher suites
    compressors: list = field(default_factory=list)
    # Error / raw
    error: str = ""
    raw_output: str = ""


# Known PQC-related cipher suite fragments
PQC_CIPHER_FRAGMENTS = [
    "MLKEM", "ML-KEM", "KYBER", "DILITHIUM", "MLDSA", "ML-DSA",
    "FALCON", "SPHINCS", "XMSS", "LMS", "NTRU", "SABER",
    "X25519MLKEM", "SECP256R1MLKEM",
]


def _cipher_is_pqc(name: str) -> bool:
    upper = name.upper().replace("-", "").replace("_", "")
    return any(frag.upper().replace("-", "") in upper for frag in PQC_CIPHER_FRAGMENTS)


class NmapScanner:
    """
    Uses nmap with the ssl-enum-ciphers script to enumerate TLS cipher suites.
    Falls back to a notice (no data) if nmap is not installed.
    """

    def __init__(self, timeout: int = 60):
        self.timeout = timeout

    def scan(self, domain: str, port: int = 443) -> NmapScanResult:
        result = NmapScanResult(domain=domain, port=port)

        if not NMAP_AVAILABLE:
            result.error = (
                "nmap binary not found in PATH. "
                "Install with: brew install nmap  (macOS) or  apt install nmap  (Linux). "
                "TLS cipher data will be unavailable — using Python ssl module only."
            )
            return result

        if NMAP_LIB_AVAILABLE:
            return self._scan_with_python_nmap(result)
        else:
            return self._scan_with_subprocess(result)

    def _scan_with_python_nmap(self, result: NmapScanResult) -> NmapScanResult:
        """Use python-nmap library for scanning."""
        try:
            nm = nmap_lib.PortScanner()
            # Run nmap with ssl-enum-ciphers script
            nm.scan(
                hosts=result.domain,
                ports=str(result.port),
                arguments=f"--script ssl-enum-ciphers -sV --open -T4",
                timeout=self.timeout,
            )

            # Process results
            for host in nm.all_hosts():
                result.ip_address = nm[host].get("addresses", {}).get("ipv4", "")
                tcp = nm[host].get("tcp", {})
                port_data = tcp.get(result.port, {})

                if port_data:
                    result.port_open = port_data.get("state") == "open"
                    result.service = port_data.get("name", "")
                    result.product = port_data.get("product", "")
                    result.version = port_data.get("version", "")

                # Parse ssl-enum-ciphers script output
                script_output = port_data.get("script", {}).get("ssl-enum-ciphers", "")
                if script_output:
                    result.raw_output = script_output
                    self._parse_ssl_enum_output(script_output, result)

        except Exception as e:
            result.error = f"nmap scan error: {e}"

        return result

    def _scan_with_subprocess(self, result: NmapScanResult) -> NmapScanResult:
        """Use subprocess to run nmap directly and parse XML output."""
        try:
            cmd = [
                NMAP_BINARY,
                "-p", str(result.port),
                "--script", "ssl-enum-ciphers",
                "-sV", "--open", "-T4",
                "-oX", "-",  # XML output to stdout
                result.domain,
            ]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            if proc.returncode not in (0, 1):
                result.error = f"nmap exited with code {proc.returncode}: {proc.stderr[:200]}"
                return result

            result.raw_output = proc.stdout
            self._parse_nmap_xml(proc.stdout, result)

        except subprocess.TimeoutExpired:
            result.error = f"nmap scan timed out after {self.timeout}s"
        except Exception as e:
            result.error = f"nmap subprocess error: {e}"

        return result

    def _parse_nmap_xml(self, xml_data: str, result: NmapScanResult):
        """Parse nmap XML output."""
        try:
            root = ET.fromstring(xml_data)
            for host in root.findall("host"):
                # IP address
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        result.ip_address = addr.get("addr", "")

                # Port state
                for port_elem in host.findall(".//port"):
                    portid = int(port_elem.get("portid", 0))
                    if portid != result.port:
                        continue
                    state_elem = port_elem.find("state")
                    if state_elem is not None:
                        result.port_open = state_elem.get("state") == "open"
                    svc = port_elem.find("service")
                    if svc is not None:
                        result.service = svc.get("name", "")
                        result.product = svc.get("product", "")
                        result.version = svc.get("version", "")

                    # Script output
                    for script in port_elem.findall("script"):
                        if script.get("id") == "ssl-enum-ciphers":
                            output = script.get("output", "")
                            result.raw_output = output
                            self._parse_ssl_enum_output(output, result)
        except ET.ParseError as e:
            result.error = f"XML parse error: {e}"

    def _parse_ssl_enum_output(self, output: str, result: NmapScanResult):
        """
        Parse ssl-enum-ciphers script text output.
        Format:
          TLSv1.2:
            ciphers:
              TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (secp256r1) - A
            ...
            least strength: A
        """
        current_version = None
        current_section = None

        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue

            # TLS version header
            tls_match = re.match(r"^(TLSv\d+(?:\.\d+)?|SSLv\d+(?:\.\d+)?):", stripped)
            if tls_match:
                current_version = tls_match.group(1)
                if current_version not in result.tls_versions_supported:
                    result.tls_versions_supported.append(current_version)
                result.ciphers_by_version.setdefault(current_version, [])
                continue

            # Section headers
            if stripped in ("ciphers:", "compressors:", "cipher preference:"):
                current_section = stripped.rstrip(":")
                continue

            # Compressor entry
            if current_section == "compressors" and current_version is None:
                result.compressors.append(stripped)
                continue

            # Least strength line
            if "least strength:" in stripped.lower():
                grade = stripped.split(":")[-1].strip()
                if not result.least_strength or grade < result.least_strength:
                    result.least_strength = grade
                continue

            # Cipher entry (under a TLS version + ciphers section)
            if current_version and current_section == "ciphers":
                cipher_match = re.match(
                    r"^(TLS_\S+)\s*(?:\(([^)]+)\))?\s*-\s*([A-F]?)$", stripped
                )
                if cipher_match:
                    cipher_name = cipher_match.group(1)
                    curve = cipher_match.group(2) or ""
                    grade = cipher_match.group(3) or "?"

                    # Try to extract key bits from cipher name
                    bits = 0
                    bits_match = re.search(r"_(\d+)_", cipher_name)
                    if bits_match:
                        bits = int(bits_match.group(1))

                    entry = CipherSuiteEntry(
                        name=cipher_name,
                        protocol=current_version,
                        key_bits=bits,
                        strength=grade,
                        is_pqc_related=_cipher_is_pqc(cipher_name),
                    )
                    result.ciphers_by_version[current_version].append(entry)


def check_nmap_available() -> dict:
    """Return nmap availability info."""
    return {
        "nmap_binary_found": NMAP_AVAILABLE,
        "nmap_path": NMAP_BINARY or "not found",
        "python_nmap_lib": NMAP_LIB_AVAILABLE,
        "note": (
            "nmap installed and ready."
            if NMAP_AVAILABLE
            else "Install nmap for enhanced cipher suite analysis."
        ),
    }
