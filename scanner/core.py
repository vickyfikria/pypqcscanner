"""
scanner/core.py
Main scanner orchestrator.
Coordinates TLS analysis, nmap scanning, HTTP header checks,
and PQC readiness scoring for all target domains.
"""

import json
import datetime
import concurrent.futures
from dataclasses import dataclass, field, asdict
from typing import Optional, Callable

from scanner.tls_analyzer import TLSAnalyzer, TLSConnectionInfo
from scanner.nmap_scanner import NmapScanner, NmapScanResult
from scanner.http_analyzer import HTTPAnalyzer, SecurityHeaderResult
from scanner.pqc_checker import PQCChecker, PQCReadinessResult, get_oqs_environment
from targets.indonesia_gov import TARGET_MAP as _ID_MAP, INDONESIA_GOV_TARGETS
from targets.malaysia_gov  import TARGET_MAP as _MY_MAP, MALAYSIA_GOV_TARGETS

# Module-level TARGET_MAP — can be patched at runtime by main.py
TARGET_MAP = {**_ID_MAP, **_MY_MAP}
ALL_KNOWN_TARGETS = INDONESIA_GOV_TARGETS + MALAYSIA_GOV_TARGETS


@dataclass
class DomainScanResult:
    """Full scan result for a single domain."""
    domain: str = ""
    name: str = ""
    category: str = ""
    priority: str = ""
    description: str = ""
    scan_timestamp: str = ""
    scan_duration_s: float = 0.0

    # Sub-results (as dicts for JSON serialization)
    tls: dict = field(default_factory=dict)
    nmap: dict = field(default_factory=dict)
    http: dict = field(default_factory=dict)
    pqc: dict = field(default_factory=dict)

    # Quick-access summary fields
    pqc_score: int = 0
    pqc_grade: str = ""
    readiness_level: str = ""
    hndl_risk: str = ""
    tls_version: str = ""
    is_pqc_hybrid: bool = False
    error: str = ""


def _dataclass_to_dict(obj) -> dict:
    """Recursively convert dataclass to dict, handling nested dataclasses and datetimes."""
    if hasattr(obj, "__dataclass_fields__"):
        return {k: _dataclass_to_dict(v) for k, v in asdict(obj).items()}
    elif isinstance(obj, datetime.datetime):
        return obj.isoformat()
    elif isinstance(obj, list):
        return [_dataclass_to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


def _safe_dict(obj) -> dict:
    """Convert an object to dict safely, handling datetime serialization."""
    try:
        d = asdict(obj)
        # Fix datetime fields
        for k, v in d.items():
            if isinstance(v, datetime.datetime):
                d[k] = v.isoformat()
            elif isinstance(v, dict):
                for kk, vv in v.items():
                    if isinstance(vv, datetime.datetime):
                        v[kk] = vv.isoformat()
        return d
    except Exception as e:
        return {"error": str(e)}


class Scanner:
    """
    Main PQC readiness scanner orchestrator.
    Runs TLS, nmap, HTTP, and PQC checks for each target domain.
    """

    def __init__(
        self,
        timeout: int = 15,
        max_workers: int = 5,
        use_nmap: bool = True,
        progress_callback: Optional[Callable] = None,
    ):
        self.timeout = timeout
        self.max_workers = max_workers
        self.use_nmap = use_nmap
        self.progress_callback = progress_callback

        self.tls_analyzer = TLSAnalyzer(timeout=timeout)
        self.nmap_scanner = NmapScanner(timeout=timeout * 4) if use_nmap else None
        self.http_analyzer = HTTPAnalyzer(timeout=timeout)
        self.pqc_checker = PQCChecker()

    def scan_domain(self, domain: str) -> DomainScanResult:
        """Perform a full PQC scan on a single domain."""
        import time

        meta = TARGET_MAP.get(domain, {
            "domain": domain,
            "name": domain,
            "category": "Custom",
            "priority": "MEDIUM",
            "description": "",
        })

        result = DomainScanResult(
            domain=domain,
            name=meta.get("name", domain),
            category=meta.get("category", ""),
            priority=meta.get("priority", ""),
            description=meta.get("description", ""),
            scan_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        )

        start = time.time()

        # ─── 1. TLS Analysis ─────────────────────────────────────────
        tls_info: TLSConnectionInfo = self.tls_analyzer.analyze(domain)
        result.tls = _safe_dict(tls_info)
        result.tls_version = tls_info.tls_version
        result.is_pqc_hybrid = tls_info.is_pqc_hybrid
        if tls_info.error:
            result.error = tls_info.error

        # ─── 2. Nmap Scan ─────────────────────────────────────────────
        if self.use_nmap and self.nmap_scanner:
            nmap_result: NmapScanResult = self.nmap_scanner.scan(domain)
            result.nmap = _safe_dict(nmap_result)
        else:
            result.nmap = {"note": "nmap scanning disabled"}

        # ─── 3. HTTP Security Headers ──────────────────────────────────
        http_result: SecurityHeaderResult = self.http_analyzer.analyze(domain)
        result.http = _safe_dict(http_result)

        # ─── 4. PQC Readiness Assessment ───────────────────────────────
        cert = tls_info.cert
        nmap_data = result.nmap or {}

        pqc_result: PQCReadinessResult = self.pqc_checker.assess(
            domain=domain,
            tls_version=tls_info.tls_version,
            cipher_suite=tls_info.cipher_suite,
            key_exchange=tls_info.key_exchange,
            negotiated_group=tls_info.negotiated_group,
            is_pqc_hybrid=tls_info.is_pqc_hybrid,
            cert_key_type=cert.key_type if cert else "",
            cert_key_size=cert.key_size if cert else 0,
            cert_quantum_risk=cert.quantum_risk if cert else "UNKNOWN",
            supports_tls13=tls_info.supports_tls13,
            supports_tls12=tls_info.supports_tls12,
            hsts_enabled=http_result.hsts or tls_info.hsts_enabled,
            hsts_max_age=http_result.hsts_max_age or tls_info.hsts_max_age,
            nmap_least_strength=nmap_data.get("least_strength", ""),
            connection_error=tls_info.error,
        )

        result.pqc = _safe_dict(pqc_result)
        result.pqc_score = pqc_result.pqc_score
        result.pqc_grade = pqc_result.pqc_grade
        result.readiness_level = pqc_result.readiness_level
        result.hndl_risk = pqc_result.hndl_risk

        result.scan_duration_s = round(time.time() - start, 2)

        if self.progress_callback:
            self.progress_callback(result)

        return result

    def scan_all(
        self,
        domains: Optional[list] = None,
        priority_filter: Optional[str] = None,
    ) -> list:
        """
        Scan multiple domains in parallel.
        Returns list of DomainScanResult dicts.
        """
        if domains is None:
            targets = INDONESIA_GOV_TARGETS
            if priority_filter:
                targets = [t for t in targets if t["priority"] == priority_filter.upper()]
            domains = [t["domain"] for t in targets]

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_domain = {
                executor.submit(self.scan_domain, domain): domain
                for domain in domains
            }
            for future in concurrent.futures.as_completed(future_to_domain):
                domain = future_to_domain[future]
                try:
                    result = future.result(timeout=self.timeout * 6)
                    results.append(_safe_dict(result))
                except concurrent.futures.TimeoutError:
                    results.append({
                        "domain": domain,
                        "error": "Scan timed out",
                        "pqc_score": 0,
                        "readiness_level": "Timeout",
                    })
                except Exception as e:
                    results.append({
                        "domain": domain,
                        "error": str(e),
                        "pqc_score": 0,
                        "readiness_level": "Error",
                    })

        # Sort by PQC score (lowest first = most critical first)
        results.sort(key=lambda x: x.get("pqc_score", 0))
        return results


def build_summary(results: list) -> dict:
    """Build a summary statistics dict from scan results."""
    total = len(results)
    if not total:
        return {}

    scores = [r.get("pqc_score", 0) for r in results]
    levels = [r.get("readiness_level", "Unknown") for r in results]
    hndl_risks = [r.get("hndl_risk", "UNKNOWN") for r in results]

    level_counts = {}
    for lvl in levels:
        level_counts[lvl] = level_counts.get(lvl, 0) + 1

    hndl_counts = {}
    for risk in hndl_risks:
        hndl_counts[risk] = hndl_counts.get(risk, 0) + 1

    pqc_ready = sum(1 for r in results if r.get("is_pqc_hybrid", False))

    return {
        "total_domains": total,
        "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "average_pqc_score": round(sum(scores) / total, 1),
        "min_pqc_score": min(scores),
        "max_pqc_score": max(scores),
        "pqc_ready_count": pqc_ready,
        "pqc_ready_percent": round(pqc_ready / total * 100, 1),
        "readiness_breakdown": level_counts,
        "hndl_risk_breakdown": hndl_counts,
        "critical_domains": [
            r["domain"] for r in results if r.get("readiness_level") == "Critical"
        ],
        "most_vulnerable": [
            {"domain": r["domain"], "score": r.get("pqc_score", 0)}
            for r in sorted(results, key=lambda x: x.get("pqc_score", 0))[:5]
        ],
    }
