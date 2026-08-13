"""
scanner/http_analyzer.py
HTTP security header analyzer.
Checks HSTS, CSP, X-Frame-Options, and other security headers
that contribute to the overall security posture.
"""

import requests
import urllib3
from dataclasses import dataclass, field
from typing import Optional

# Suppress insecure request warnings for sites with cert issues
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HEADERS = {
    "User-Agent": (
        "PQC-Readiness-Scanner/1.0 "
        "(Indonesia Government Security Assessment; "
        "https://github.com/pqc-indonesia-scanner)"
    )
}

DEFAULT_TIMEOUT = 10


@dataclass
class SecurityHeaderResult:
    """Result of HTTP security header analysis."""
    domain: str = ""
    url: str = ""
    status_code: int = 0
    server_header: str = ""
    x_powered_by: str = ""

    # HSTS
    hsts: bool = False
    hsts_max_age: int = 0
    hsts_include_subdomains: bool = False
    hsts_preload: bool = False

    # Content Security
    csp: bool = False
    csp_value: str = ""

    # Framing protection
    x_frame_options: bool = False
    x_frame_options_value: str = ""

    # Content type
    x_content_type_options: bool = False   # Should be "nosniff"

    # XSS Protection
    x_xss_protection: bool = False

    # CORS
    access_control_allow_origin: str = ""
    cors_open: bool = False  # True if ACAO is "*"

    # Referrer policy
    referrer_policy: str = ""

    # Permissions policy
    permissions_policy: bool = False

    # Overall header score (0-100)
    header_score: int = 0
    header_grade: str = ""
    missing_headers: list = field(default_factory=list)
    present_headers: list = field(default_factory=list)

    error: str = ""
    redirect_chain: list = field(default_factory=list)


class HTTPAnalyzer:
    """Analyzes HTTP security headers for a given domain."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

    def analyze(self, domain: str, port: int = 443) -> SecurityHeaderResult:
        result = SecurityHeaderResult(domain=domain)
        url = f"https://{domain}" if port == 443 else f"https://{domain}:{port}"
        result.url = url

        try:
            resp = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=True,
            )
        except requests.exceptions.SSLError:
            # Try without verification if cert is invalid (still scan headers)
            try:
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    verify=False,
                )
            except requests.exceptions.RequestException as e:
                result.error = f"HTTP request failed: {e}"
                return result
        except requests.exceptions.Timeout:
            result.error = "HTTP request timed out"
            return result
        except requests.exceptions.RequestException as e:
            result.error = f"HTTP request failed: {e}"
            return result

        result.status_code = resp.status_code

        # Track redirects
        for r in resp.history:
            result.redirect_chain.append(f"{r.status_code} → {r.headers.get('Location', '?')}")

        headers = {k.lower(): v for k, v in resp.headers.items()}

        # Server fingerprinting (useful for assessing tech stack)
        result.server_header = headers.get("server", "")
        result.x_powered_by = headers.get("x-powered-by", "")

        # ─── HSTS ───────────────────────────────────────────────────────
        hsts_value = headers.get("strict-transport-security", "")
        if hsts_value:
            result.hsts = True
            result.present_headers.append("Strict-Transport-Security")
            for part in hsts_value.split(";"):
                part = part.strip().lower()
                if part.startswith("max-age="):
                    try:
                        result.hsts_max_age = int(part.split("=")[1])
                    except ValueError:
                        pass
                elif part == "includesubdomains":
                    result.hsts_include_subdomains = True
                elif part == "preload":
                    result.hsts_preload = True
        else:
            result.missing_headers.append("Strict-Transport-Security")

        # ─── Content Security Policy ─────────────────────────────────────
        csp_value = headers.get("content-security-policy", "")
        if csp_value:
            result.csp = True
            result.csp_value = csp_value[:200]  # truncate for storage
            result.present_headers.append("Content-Security-Policy")
        else:
            result.missing_headers.append("Content-Security-Policy")

        # ─── X-Frame-Options ─────────────────────────────────────────────
        xfo = headers.get("x-frame-options", "")
        if xfo:
            result.x_frame_options = True
            result.x_frame_options_value = xfo
            result.present_headers.append("X-Frame-Options")
        else:
            result.missing_headers.append("X-Frame-Options")

        # ─── X-Content-Type-Options ──────────────────────────────────────
        xcto = headers.get("x-content-type-options", "")
        if xcto.lower() == "nosniff":
            result.x_content_type_options = True
            result.present_headers.append("X-Content-Type-Options")
        else:
            result.missing_headers.append("X-Content-Type-Options")

        # ─── X-XSS-Protection ───────────────────────────────────────────
        xss = headers.get("x-xss-protection", "")
        if xss:
            result.x_xss_protection = True
            result.present_headers.append("X-XSS-Protection")

        # ─── CORS ────────────────────────────────────────────────────────
        acao = headers.get("access-control-allow-origin", "")
        result.access_control_allow_origin = acao
        if acao == "*":
            result.cors_open = True

        # ─── Referrer-Policy ─────────────────────────────────────────────
        result.referrer_policy = headers.get("referrer-policy", "")

        # ─── Permissions-Policy ──────────────────────────────────────────
        pp = headers.get("permissions-policy", headers.get("feature-policy", ""))
        if pp:
            result.permissions_policy = True
            result.present_headers.append("Permissions-Policy")
        else:
            result.missing_headers.append("Permissions-Policy")

        # ─── Header Score ────────────────────────────────────────────────
        score = 0
        if result.hsts:
            score += 30
            if result.hsts_max_age >= 31536000:
                score += 10
            if result.hsts_include_subdomains:
                score += 5
            if result.hsts_preload:
                score += 5
        if result.csp:
            score += 20
        if result.x_frame_options:
            score += 10
        if result.x_content_type_options:
            score += 10
        if result.permissions_policy:
            score += 5
        if result.referrer_policy:
            score += 5

        result.header_score = min(100, score)

        if result.header_score >= 80:
            result.header_grade = "A"
        elif result.header_score >= 60:
            result.header_grade = "B"
        elif result.header_score >= 40:
            result.header_grade = "C"
        elif result.header_score >= 20:
            result.header_grade = "D"
        else:
            result.header_grade = "F"

        return result
