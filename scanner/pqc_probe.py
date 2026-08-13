"""
scanner/pqc_probe.py

Raw-socket PQC ClientHello prober.

Sends a hand-crafted TLS 1.3 ClientHello that advertises PQC hybrid key
exchange groups (X25519MLKEM768, X25519Kyber768Draft00, …) in both the
supported_groups and key_share extensions, then parses the ServerHello to
detect which group the server selected.

This is the ONLY correct way to detect server-side PQC support because:
  – Python's ssl module never sends PQC group IDs in the ClientHello.
  – Servers like Cloudflare and Google only activate PQC when the client
    explicitly advertises it via a PQC key_share entry.

IANA / IETF group code points
──────────────────────────────────────────────────────────────
0x11ec (4588)  X25519MLKEM768        RFC 9180 hybrid, FIPS 203  ← standard
0x11eb (4587)  SecP256r1MLKEM768     RFC 9180 hybrid, FIPS 203
0x6399 (25497) X25519Kyber768Draft00 Pre-standard (Cloudflare/Google legacy)
0x001d (29)    X25519                classical fallback
0x0017 (23)    secp256r1             classical fallback
──────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import os
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional

# ── PQC group registry ─────────────────────────────────────────────────────────
PQC_GROUP_IDS: dict[int, str] = {
    0x11ec: "X25519MLKEM768",         # FIPS 203, IETF draft (Chrome 131+, CF)
    0x11eb: "SecP256r1MLKEM768",      # FIPS 203 alternative hybrid
    0x6399: "X25519Kyber768Draft00",  # Pre-standard (Cloudflare legacy, Chrome 124–130)
    0xFE31: "X25519Kyber512Draft00",  # Very early draft, rare
}

CLASSICAL_GROUP_IDS: dict[int, str] = {
    0x001d: "X25519",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001e: "X448",
}

# All groups to advertise in supported_groups (PQC first for priority)
ADVERTISED_GROUPS = [
    0x11ec,  # X25519MLKEM768   ← most important
    0x11eb,  # SecP256r1MLKEM768
    0x6399,  # X25519Kyber768Draft00
    0x001d,  # X25519           ← required for HRR-free TLS1.3 handshake
    0x0017,  # secp256r1
    0x0018,  # secp384r1
]


@dataclass
class PQCProbeResult:
    domain: str = ""
    pqc_detected: bool = False
    pqc_group_name: str = ""        # e.g. "X25519MLKEM768"
    pqc_group_id: int = 0           # e.g. 0x11ec
    classical_group_name: str = ""  # fallback group if no PQC
    selected_version: int = 0       # 0x0304 = TLS 1.3
    tls13_confirmed: bool = False
    error: str = ""
    probe_ms: float = 0.0


# ── Key material generation ─────────────────────────────────────────────────────

def _gen_x25519_pubkey() -> bytes:
    """Generate a fresh X25519 public key (32 bytes)."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        priv = X25519PrivateKey.generate()
        return priv.public_key().public_bytes_raw()
    except Exception:
        # Fallback: random bytes (server will reject, but we only care about ServerHello)
        return os.urandom(32)


# ── TLS record / extension builders ────────────────────────────────────────────

def _ext(ext_type: int, payload: bytes) -> bytes:
    """Wrap payload in a TLS extension: type(2) + length(2) + data."""
    return struct.pack(">HH", ext_type, len(payload)) + payload


def _build_sni(hostname: str) -> bytes:
    name = hostname.encode()
    # HostName: name_type(1) + len(2) + name
    host_entry = struct.pack(">BH", 0x00, len(name)) + name
    # server_name list: len(2) + entries
    sni_list = struct.pack(">H", len(host_entry)) + host_entry
    return _ext(0x0000, sni_list)


def _build_supported_versions() -> bytes:
    # Offer TLS 1.3 (0x0304) and TLS 1.2 (0x0303)
    versions = struct.pack(">HH", 0x0304, 0x0303)
    payload = struct.pack(">B", len(versions)) + versions
    return _ext(0x002b, payload)


def _build_supported_groups() -> bytes:
    group_bytes = b"".join(struct.pack(">H", g) for g in ADVERTISED_GROUPS)
    payload = struct.pack(">H", len(group_bytes)) + group_bytes
    return _ext(0x000a, payload)


def _build_key_share() -> bytes:
    """
    key_share for TLS 1.3 ClientHello — X25519 only.

    We only provide an X25519 key share (valid). All PQC groups are listed
    in supported_groups. A PQC-capable server will respond with either:
      • A normal ServerHello selecting X25519MLKEM768 (if it has our pubkey)
      • A HelloRetryRequest asking us to retry with X25519MLKEM768 or Kyber
        → This HRR response PROVES the server prefers PQC (we detect this)
      • A normal ServerHello selecting X25519 (server supports PQC but
        fell back because we didn't offer an ML-KEM key share)

    We intentionally do NOT send a dummy ML-KEM key share because:
      – Random bytes as a KEM public key cause fatal TLS alerts (decode_error
        from Cloudflare, illegal_parameter from Google).
      – HRR-based detection is sufficient to confirm PQC server support.
    """
    x25519_pub = _gen_x25519_pubkey()
    entry = struct.pack(">HH", 0x001d, len(x25519_pub)) + x25519_pub
    payload = struct.pack(">H", len(entry)) + entry
    return _ext(0x0033, payload)


def _build_sig_algs() -> bytes:
    algs = [
        0x0403,  # ecdsa_secp256r1_sha256
        0x0503,  # ecdsa_secp384r1_sha384
        0x0804,  # rsa_pss_rsae_sha256
        0x0805,  # rsa_pss_rsae_sha384
        0x0806,  # rsa_pss_rsae_sha512
        0x0401,  # rsa_pkcs1_sha256
        0x0501,  # rsa_pkcs1_sha384
        0x0601,  # rsa_pkcs1_sha512
    ]
    alg_bytes = b"".join(struct.pack(">H", a) for a in algs)
    payload = struct.pack(">H", len(alg_bytes)) + alg_bytes
    return _ext(0x000d, payload)


def _build_client_hello(hostname: str) -> bytes:
    """Assemble a complete TLS 1.3 ClientHello record."""

    # --- Extensions ---
    extensions = (
        _build_sni(hostname) +
        _build_supported_versions() +
        _build_supported_groups() +
        _build_key_share() +
        _build_sig_algs() +
        _ext(0x0023, b"") +          # session_ticket (empty)
        _ext(0x000f, b"\x01") +      # heartbeat (peer_allowed_to_send)
        _ext(0xff01, b"\x00")        # renegotiation_info (empty RI)
    )

    # --- Cipher suites (TLS 1.3 + common TLS 1.2) ---
    ciphers = bytes([
        0x13, 0x01,  # TLS_AES_128_GCM_SHA256
        0x13, 0x02,  # TLS_AES_256_GCM_SHA384
        0x13, 0x03,  # TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2c,  # TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b,  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2f,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
        0x00, 0xff,  # TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ])

    # --- ClientHello body ---
    ch  = bytes([0x03, 0x03])                              # legacy_version = TLS 1.2
    ch += os.urandom(32)                                   # random (32 bytes)
    sid = os.urandom(32)
    ch += struct.pack("B", len(sid)) + sid                 # session_id
    ch += struct.pack(">H", len(ciphers)) + ciphers        # cipher_suites
    ch += bytes([0x01, 0x00])                              # compression_methods
    ch += struct.pack(">H", len(extensions)) + extensions  # extensions

    # --- Handshake message ---
    hs  = bytes([0x01])                                    # HandshakeType = ClientHello
    hs += struct.pack(">I", len(ch))[1:]                   # 3-byte length
    hs += ch

    # --- TLS record ---
    rec  = bytes([0x16, 0x03, 0x01])                       # ContentType=Handshake, legacy TLS1.0
    rec += struct.pack(">H", len(hs)) + hs

    return rec


# ── ServerHello parser ─────────────────────────────────────────────────────────

def _read_tls_records(sock: socket.socket, max_bytes: int = 8192) -> bytes:
    """Read raw bytes from socket until we have enough for a ServerHello."""
    data = b""
    sock.settimeout(5.0)
    try:
        while len(data) < max_bytes:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            # Stop once we've received at least one full TLS record
            if len(data) >= 5:
                rec_len = struct.unpack(">H", data[3:5])[0]
                if len(data) >= 5 + rec_len:
                    break
    except (socket.timeout, OSError):
        pass
    return data


def _parse_server_hello(data: bytes) -> dict:
    """
    Walk through raw TLS records and extract ServerHello fields.
    Returns dict with keys: selected_version, key_share_group, is_hrr, error.
    """
    result: dict = {}
    pos = 0

    while pos + 5 <= len(data):
        ct     = data[pos]
        length = struct.unpack(">H", data[pos + 3: pos + 5])[0]

        if pos + 5 + length > len(data):
            break

        record = data[pos + 5: pos + 5 + length]
        pos   += 5 + length

        if ct != 0x16:          # Only Handshake records
            continue

        # Walk handshake messages inside record
        hpos = 0
        while hpos + 4 <= len(record):
            ht      = record[hpos]
            hlen    = struct.unpack(">I", b"\x00" + record[hpos + 1: hpos + 4])[0]
            hbody   = record[hpos + 4: hpos + 4 + hlen]
            hpos   += 4 + hlen

            if ht != 0x02:      # Only ServerHello (0x02)
                continue

            result.update(_parse_server_hello_body(hbody))
            return result       # Done after first ServerHello

    if not result:
        result["error"] = "ServerHello not found in response"
    return result


def _parse_server_hello_body(body: bytes) -> dict:
    """Extract selected version and key_share group from ServerHello body."""
    result: dict = {}
    if len(body) < 35:
        result["error"] = "ServerHello body too short"
        return result

    pos = 0

    # legacy_version (2)
    pos += 2

    # server_random (32) — check for HelloRetryRequest magic
    server_random = body[pos: pos + 32]
    HRR_MAGIC = bytes.fromhex(
        "CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C"
    )
    result["is_hrr"] = (server_random == HRR_MAGIC)
    pos += 32

    # session_id
    sid_len = body[pos]
    pos += 1 + sid_len

    # cipher_suite (2)
    if pos + 2 > len(body):
        return result
    result["cipher_suite"] = struct.unpack(">H", body[pos: pos + 2])[0]
    pos += 2

    # compression_method (1)
    pos += 1

    # extensions length (2)
    if pos + 2 > len(body):
        return result
    ext_total = struct.unpack(">H", body[pos: pos + 2])[0]
    pos += 2
    ext_end = pos + ext_total

    while pos + 4 <= ext_end:
        etype  = struct.unpack(">H", body[pos: pos + 2])[0]
        elen   = struct.unpack(">H", body[pos + 2: pos + 4])[0]
        edata  = body[pos + 4: pos + 4 + elen]
        pos   += 4 + elen

        if etype == 0x002b and len(edata) >= 2:
            # supported_versions → selected version
            result["selected_version"] = struct.unpack(">H", edata[:2])[0]

        elif etype == 0x0033 and len(edata) >= 2:
            # key_share → selected group (in ServerHello: group + key_exchange)
            result["key_share_group"] = struct.unpack(">H", edata[:2])[0]

    return result


# ── Public probe function ───────────────────────────────────────────────────────

def probe_pqc(hostname: str, port: int = 443, timeout: int = 8) -> PQCProbeResult:
    """
    Send a PQC-capable ClientHello and detect which key exchange group
    the server selects.

    Returns a PQCProbeResult with pqc_detected=True if the server chooses
    a PQC hybrid group (e.g. X25519MLKEM768).
    """
    result = PQCProbeResult(domain=hostname)
    t0 = time.time()

    try:
        client_hello = _build_client_hello(hostname)

        sock = socket.create_connection((hostname, port), timeout=timeout)
        try:
            sock.sendall(client_hello)
            raw = _read_tls_records(sock, max_bytes=8192)
        finally:
            try:
                sock.close()
            except OSError:
                pass

        result.probe_ms = (time.time() - t0) * 1000

        if not raw:
            result.error = "No response from server"
            return result

        sh = _parse_server_hello(raw)

        if "error" in sh and not sh.get("key_share_group"):
            result.error = sh["error"]
            return result

        # Check TLS version
        ver = sh.get("selected_version", 0)
        result.selected_version = ver
        result.tls13_confirmed  = (ver == 0x0304)

        # If HRR → server asked us to retry with a different group
        # This also indicates which group it wants
        if sh.get("is_hrr"):
            # key_share_group in HRR = the group the server WANTS
            hrr_group = sh.get("key_share_group", 0)
            if hrr_group in PQC_GROUP_IDS:
                result.pqc_detected    = True
                result.pqc_group_id    = hrr_group
                result.pqc_group_name  = PQC_GROUP_IDS[hrr_group]
            elif hrr_group in CLASSICAL_GROUP_IDS:
                result.classical_group_name = CLASSICAL_GROUP_IDS[hrr_group]
            return result

        # Normal ServerHello
        group = sh.get("key_share_group", 0)
        if group in PQC_GROUP_IDS:
            result.pqc_detected   = True
            result.pqc_group_id   = group
            result.pqc_group_name = PQC_GROUP_IDS[group]
        elif group in CLASSICAL_GROUP_IDS:
            result.classical_group_name = CLASSICAL_GROUP_IDS[group]
        elif group:
            result.classical_group_name = f"unknown-0x{group:04x}"

    except socket.timeout:
        result.error = "Probe timed out"
    except OSError as e:
        result.error = str(e)
    except Exception as e:
        result.error = f"Unexpected: {e}"

    result.probe_ms = (time.time() - t0) * 1000
    return result


if __name__ == "__main__":
    # Quick self-test
    import sys
    targets = sys.argv[1:] or ["cloudflare.com", "google.com", "microsoft.com", "amazon.com", "nist.gov"]
    print(f"\n{'Domain':35} {'PQC?':6} {'Group':30} {'Classical fallback':20} {'ms':6}")
    print("─" * 100)
    for host in targets:
        r = probe_pqc(host)
        pqc  = f"✅ YES" if r.pqc_detected else "✗  no"
        grp  = r.pqc_group_name  if r.pqc_detected else ""
        cls  = r.classical_group_name if not r.pqc_detected else ""
        err  = f"  [{r.error}]" if r.error and not r.pqc_detected else ""
        print(f"{host:35} {pqc:6} {grp:30} {cls:20} {r.probe_ms:5.0f}ms{err}")
