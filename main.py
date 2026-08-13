#!/usr/bin/env python3
"""
main.py — Indonesia PQC Readiness Scanner CLI
Post-Quantum Cryptography readiness assessment for Indonesian government websites.

Usage:
    python main.py scan --all
    python main.py scan --target kemenkeu.go.id
    python main.py scan --priority CRITICAL
    python main.py report --input output/report.json
    python main.py list-targets
    python main.py oqs-info
"""

import json
import os
import sys
import time
import datetime
from pathlib import Path
from typing import Optional, List

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.live import Live
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule

from scanner.core import Scanner, build_summary
from scanner.pqc_checker import get_oqs_environment, OQSEnvironmentInfo
from scanner.report import ReportGenerator
from scanner.nmap_scanner import check_nmap_available
from targets.indonesia_gov       import INDONESIA_GOV_TARGETS,       ALL_DOMAINS as ID_GOV_DOMAINS,    TARGET_MAP as ID_GOV_MAP
from targets.indonesia_ecommerce  import INDONESIA_ECOMMERCE_TARGETS,  ALL_DOMAINS as ID_EC_DOMAINS,     TARGET_MAP as ID_EC_MAP
from targets.indonesia_banks      import INDONESIA_BANK_TARGETS,       ALL_DOMAINS as ID_BK_DOMAINS,     TARGET_MAP as ID_BK_MAP
from targets.malaysia_gov         import MALAYSIA_GOV_TARGETS,         ALL_DOMAINS as MY_GOV_DOMAINS,    TARGET_MAP as MY_GOV_MAP
from targets.malaysia_ecommerce   import MALAYSIA_ECOMMERCE_TARGETS,   ALL_DOMAINS as MY_EC_DOMAINS,     TARGET_MAP as MY_EC_MAP
from targets.malaysia_banks       import MALAYSIA_BANK_TARGETS,        ALL_DOMAINS as MY_BK_DOMAINS,     TARGET_MAP as MY_BK_MAP
from targets.us_gov               import US_GOV_TARGETS,               ALL_DOMAINS as US_GOV_DOMAINS,    TARGET_MAP as US_GOV_MAP
from targets.us_ecommerce         import US_ECOMMERCE_TARGETS,         ALL_DOMAINS as US_EC_DOMAINS,     TARGET_MAP as US_EC_MAP
from targets.us_tech              import US_TECH_TARGETS,              ALL_DOMAINS as US_TECH_DOMAINS,   TARGET_MAP as US_TECH_MAP

# ── Build combined per-country target sets ──────────────────────────────────
ID_ALL_TARGETS = INDONESIA_GOV_TARGETS + INDONESIA_ECOMMERCE_TARGETS + INDONESIA_BANK_TARGETS
ID_ALL_DOMAINS = ID_GOV_DOMAINS + ID_EC_DOMAINS + ID_BK_DOMAINS
ID_ALL_MAP     = {**ID_GOV_MAP, **ID_EC_MAP, **ID_BK_MAP}

MY_ALL_TARGETS = MALAYSIA_GOV_TARGETS + MALAYSIA_ECOMMERCE_TARGETS + MALAYSIA_BANK_TARGETS
MY_ALL_DOMAINS = MY_GOV_DOMAINS + MY_EC_DOMAINS + MY_BK_DOMAINS
MY_ALL_MAP     = {**MY_GOV_MAP, **MY_EC_MAP, **MY_BK_MAP}

US_ALL_TARGETS = US_GOV_TARGETS + US_ECOMMERCE_TARGETS + US_TECH_TARGETS
US_ALL_DOMAINS = US_GOV_DOMAINS + US_EC_DOMAINS + US_TECH_DOMAINS
US_ALL_MAP     = {**US_GOV_MAP, **US_EC_MAP, **US_TECH_MAP}

# Sector sub-groupings (for --sector filter)
COUNTRY_SECTORS = {
    "indonesia": {
        "gov":       {"targets": INDONESIA_GOV_TARGETS,      "domains": ID_GOV_DOMAINS,  "label": "Government"},
        "ecommerce": {"targets": INDONESIA_ECOMMERCE_TARGETS, "domains": ID_EC_DOMAINS,   "label": "E-Commerce"},
        "banking":   {"targets": INDONESIA_BANK_TARGETS,      "domains": ID_BK_DOMAINS,   "label": "Banking"},
        "all":       {"targets": ID_ALL_TARGETS,              "domains": ID_ALL_DOMAINS,  "label": "All Sectors"},
    },
    "malaysia": {
        "gov":       {"targets": MALAYSIA_GOV_TARGETS,        "domains": MY_GOV_DOMAINS,  "label": "Government"},
        "ecommerce": {"targets": MALAYSIA_ECOMMERCE_TARGETS,  "domains": MY_EC_DOMAINS,   "label": "E-Commerce"},
        "banking":   {"targets": MALAYSIA_BANK_TARGETS,       "domains": MY_BK_DOMAINS,   "label": "Banking"},
        "all":       {"targets": MY_ALL_TARGETS,              "domains": MY_ALL_DOMAINS,  "label": "All Sectors"},
    },
    "usa": {
        "gov":       {"targets": US_GOV_TARGETS,              "domains": US_GOV_DOMAINS,  "label": "Government (50)"},
        "ecommerce": {"targets": US_ECOMMERCE_TARGETS,        "domains": US_EC_DOMAINS,   "label": "E-Commerce (25)"},
        "tech":      {"targets": US_TECH_TARGETS,             "domains": US_TECH_DOMAINS, "label": "Tech Companies (25)"},
        "all":       {"targets": US_ALL_TARGETS,              "domains": US_ALL_DOMAINS,  "label": "All Sectors (100)"},
    },
}

# Top-level country registry
COUNTRY_TARGETS = {
    "indonesia": {"targets": ID_ALL_TARGETS, "domains": ID_ALL_DOMAINS, "map": ID_ALL_MAP, "flag": "🇮🇩", "tld": ".go.id / .co.id"},
    "malaysia":  {"targets": MY_ALL_TARGETS, "domains": MY_ALL_DOMAINS, "map": MY_ALL_MAP, "flag": "🇲🇾", "tld": ".gov.my / .com.my"},
    "usa":       {"targets": US_ALL_TARGETS, "domains": US_ALL_DOMAINS, "map": US_ALL_MAP, "flag": "🇺🇸", "tld": ".gov / .com"},
}

# Global lookup map (all countries)
ALL_DOMAINS = ID_ALL_DOMAINS + MY_ALL_DOMAINS + US_ALL_DOMAINS
TARGET_MAP  = {**ID_ALL_MAP, **MY_ALL_MAP, **US_ALL_MAP}

app = typer.Typer(
    name="pqc-global",
    help="🔐 Global PQC Readiness Scanner — ASEAN + USA",
    rich_markup_mode="rich",
    add_completion=False,
)
console = Console()

OUTPUT_DIR = Path("output")
OUTPUT_DIR.mkdir(exist_ok=True)

# ─── Color helpers ────────────────────────────────────────────────────────────

LEVEL_STYLE = {
    "PQC-Ready":      "bold green",
    "Classical-Safe": "bold blue",
    "Vulnerable":     "bold orange3",
    "Critical":       "bold red",
    "Unreachable":    "dim",
    "Timeout":        "dim",
    "Error":          "dim red",
}

HNDL_STYLE = {
    "LOW":      "green",
    "MEDIUM":   "yellow",
    "HIGH":     "orange3",
    "CRITICAL": "bold red",
    "UNKNOWN":  "dim",
}

SCORE_STYLE = {
    (76, 100): "bold green",
    (51, 75):  "blue",
    (26, 50):  "orange3",
    (0, 25):   "bold red",
}


def _score_style(score: int) -> str:
    for (lo, hi), style in SCORE_STYLE.items():
        if lo <= score <= hi:
            return style
    return "white"


def _score_icon(score: int) -> str:
    if score >= 76: return "🟢"
    if score >= 51: return "🔵"
    if score >= 26: return "🟠"
    return "🔴"


# ─── Banner ───────────────────────────────────────────────────────────────────

def _print_banner():
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║  🔐  PQC Readiness Scanner                                ║
║  Post-Quantum Cryptography Assessment for Government Websites        ║
║  Algorithms: ML-KEM (FIPS 203) · ML-DSA (FIPS 204) · SLH-DSA       ║
║  Targets: Government, E-commerce, Banking Portals                    ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    console.print(banner, style="bold cyan")


# ─── Scan Command ─────────────────────────────────────────────────────────────

@app.command("scan")
def cmd_scan(
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Single domain to scan"),
    all_targets: bool = typer.Option(False, "--all", "-a", help="Scan all targets for selected country+sector"),
    priority: Optional[str] = typer.Option(None, "--priority", "-p", help="Filter by priority: CRITICAL, HIGH, MEDIUM"),
    country: str = typer.Option("indonesia", "--country", "-c", help="Country to scan: indonesia, malaysia"),
    sector: Optional[str] = typer.Option(None, "--sector", "-s", help="Sector: gov, ecommerce, banking, all (default: all)"),
    workers: int = typer.Option(5, "--workers", "-w", help="Parallel workers (default: 5)"),
    timeout: int = typer.Option(15, "--timeout", help="Timeout per domain in seconds"),
    no_nmap: bool = typer.Option(False, "--no-nmap", help="Skip nmap scanning (faster)"),
    output: str = typer.Option("output/report.json", "--output", "-o", help="Output JSON file"),
    html: bool = typer.Option(True, "--html/--no-html", help="Generate HTML report"),
    html_output: str = typer.Option("output/report.html", "--html-output", help="HTML report file"),
):
    """
    🔍 Scan government, ecommerce, and banking websites for PQC readiness.

    Examples:
      python main.py scan --all
      python main.py scan --target kemenkeu.go.id
      python main.py scan --priority CRITICAL --workers 3
    """
    _print_banner()

    # ─── Determine targets ───────────────────────────────────────
    country_key = country.lower().strip()
    if country_key not in COUNTRY_TARGETS:
        console.print(f"[red]Unknown country '{country}'. Choose from: {', '.join(COUNTRY_TARGETS.keys())}[/]")
        raise typer.Exit(1)

    country_info = COUNTRY_TARGETS[country_key]
    sectors      = COUNTRY_SECTORS[country_key]
    flag         = country_info["flag"]
    tld          = country_info["tld"]
    sector_key   = (sector or "all").lower()

    if sector_key not in sectors:
        console.print(f"[red]Unknown sector '{sector}'. Choose from: gov, ecommerce, banking, all[/]")
        raise typer.Exit(1)

    sector_info = sectors[sector_key]
    gov_targets = sector_info["targets"]
    sector_label = sector_info["label"]

    if target:
        domains = [target.strip()]
        console.print(f"[cyan]Target:[/] {target}")
    elif all_targets or priority or sector:
        if priority:
            filtered = [t for t in gov_targets if t["priority"] == priority.upper()]
            domains  = [t["domain"] for t in filtered]
            console.print(f"{flag} [{sector_label}] [cyan]Priority filter:[/] {priority.upper()} → {len(domains)} domains")
        else:
            domains = sector_info["domains"]
            console.print(f"{flag} [cyan]Scanning {sector_label}:[/] {len(domains)} {country_key.capitalize()} domains ({tld})")
    else:
        console.print("[yellow]No target specified. Use --all or --target DOMAIN[/]")
        console.print("\nExamples:")
        console.print("  python main.py scan --country indonesia --all")
        console.print("  python main.py scan --country indonesia --sector banking")
        console.print("  python main.py scan --country indonesia --sector ecommerce")
        console.print("  python main.py scan --country indonesia --sector gov --priority CRITICAL")
        console.print("  python main.py scan --target tokopedia.com")
        raise typer.Exit(1)

    # Patch core TARGET_MAP so DomainScanResult gets proper metadata
    import scanner.core as _scanner_core
    _scanner_core.TARGET_MAP = TARGET_MAP   # Global combined map already built at import time

    # ─── Check environment ────────────────────────────────────────
    nmap_info = check_nmap_available()
    oqs_env = get_oqs_environment()

    console.print()
    _print_env_summary(nmap_info, oqs_env)
    console.print()

    # ─── Run scanner ─────────────────────────────────────────────
    use_nmap = not no_nmap and nmap_info["nmap_binary_found"]
    scanner = Scanner(
        timeout=timeout,
        max_workers=workers,
        use_nmap=use_nmap,
    )

    results = []
    completed = 0
    total = len(domains)
    start_time = time.time()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"[cyan]Scanning {total} domains...",
            total=total,
            status="",
        )

        def on_progress(result):
            nonlocal completed
            completed += 1
            score = result.pqc_score
            icon = _score_icon(score)
            status = f"{icon} {result.domain} → {result.readiness_level} ({score}/100)"
            progress.update(task, advance=1, status=status)

        scanner.progress_callback = on_progress

        results = scanner.scan_all(domains=domains)

    elapsed = time.time() - start_time

    # ─── Build summary ────────────────────────────────────────────
    summary = build_summary(results)

    # ─── Print results table ──────────────────────────────────────
    console.print()
    _print_results_table(results)

    # ─── Print summary panel ──────────────────────────────────────
    console.print()
    _print_summary_panel(summary, elapsed)

    # ─── Save JSON ────────────────────────────────────────────────
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    full_data = {
        "metadata": {
            "scanner": "ASEAN PQC Readiness Scanner",
            "version": "1.1.0",
            "country": country_key.capitalize(),
            "country_flag": flag,
            "tld": tld,
            "scan_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "scan_duration_s": round(elapsed, 2),
            "total_domains": total,
            "nmap_used": use_nmap,
            "oqs_available": oqs_env.oqs_available,
        },
        "summary": summary,
        "oqs_environment": {
            "oqs_available": oqs_env.oqs_available,
            "oqs_version": oqs_env.oqs_version,
            "enabled_kems": oqs_env.enabled_kems,
            "enabled_sigs": oqs_env.enabled_sigs,
            "nist_kems_available": oqs_env.nist_kems_available,
            "nist_sigs_available": oqs_env.nist_sigs_available,
            "total_kems": oqs_env.total_kems,
            "total_sigs": oqs_env.total_sigs,
            "install_note": oqs_env.install_note,
        },
        "results": results,
    }
    with open(output_path, "w") as f:
        json.dump(full_data, f, indent=2, default=str)
    console.print(f"\n[green]✅ JSON report saved:[/] {output_path}")

    # ─── Generate HTML ─────────────────────────────────────────────
    if html:
        reporter = ReportGenerator(output_dir=str(Path(html_output).parent))
        html_path = reporter.generate_html(
            results=results,
            summary=summary,
            oqs_env=full_data["oqs_environment"],
            filename=Path(html_output).name,
        )
        console.print(f"[green]✅ HTML report saved:[/] {html_path}")
        console.print(f"   Open in browser: [cyan]open {html_path}[/]")

    console.print()
    console.print(Rule("[dim]Scan Complete[/dim]"))


# ─── Report Command ───────────────────────────────────────────────────────────

@app.command("report")
def cmd_report(
    input_file: str = typer.Option("output/report.json", "--input", "-i", help="Input JSON file"),
    output: str = typer.Option("output/report.html", "--output", "-o", help="Output HTML file"),
):
    """📊 Generate HTML report from a saved JSON scan result."""
    _print_banner()

    input_path = Path(input_file)
    if not input_path.exists():
        console.print(f"[red]Error: Input file not found: {input_path}[/]")
        raise typer.Exit(1)

    with open(input_path) as f:
        data = json.load(f)

    results = data.get("results", [])
    summary = data.get("summary", build_summary(results))
    oqs_env = data.get("oqs_environment", {})

    reporter = ReportGenerator(output_dir=str(Path(output).parent))
    html_path = reporter.generate_html(
        results=results,
        summary=summary,
        oqs_env=oqs_env,
        filename=Path(output).name,
    )
    console.print(f"[green]✅ HTML report generated:[/] {html_path}")
    console.print(f"   Open with: [cyan]open {html_path}[/]")


# ─── List Targets Command ─────────────────────────────────────────────────────

@app.command("list-targets")
def cmd_list_targets(
    priority: Optional[str] = typer.Option(None, "--priority", "-p"),
    country: str = typer.Option("indonesia", "--country", "-c", help="Country: indonesia, malaysia"),
):
    """📋 List all target government domains for a given country."""
    _print_banner()

    country_key = country.lower()
    if country_key not in COUNTRY_TARGETS:
        console.print(f"[red]Unknown country: {country}[/]")
        raise typer.Exit(1)
    targets = COUNTRY_TARGETS[country_key]["targets"]
    flag    = COUNTRY_TARGETS[country_key]["flag"]
    if priority:
        targets = [t for t in targets if t["priority"] == priority.upper()]

    table = Table(
        title=f"{flag} {country_key.capitalize()} Government Targets",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("#", style="dim", width=3)
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("Agency Name", style="white")
    table.add_column("Category", style="yellow")
    table.add_column("Priority", style="bold")

    pri_style = {
        "CRITICAL": "bold red",
        "HIGH":     "bold orange3",
        "MEDIUM":   "yellow",
    }

    for i, t in enumerate(targets, 1):
        table.add_row(
            str(i),
            t["domain"],
            t["name"],
            t["category"],
            Text(t["priority"], style=pri_style.get(t["priority"], "white")),
        )

    console.print(table)
    console.print(f"\n[dim]Total: {len(targets)} domains[/]")


# ─── OQS Info Command ─────────────────────────────────────────────────────────

@app.command("oqs-info")
def cmd_oqs_info():
    """⚛️  Show OQS/liboqs environment and supported PQC algorithms."""
    _print_banner()

    console.print(Panel(
        "[bold]Querying local OQS (Open Quantum Safe) environment...[/]",
        border_style="cyan"
    ))

    oqs_env = get_oqs_environment()

    if not oqs_env.oqs_available:
        console.print(Panel(
            f"[yellow]⚠️  OQS not available[/]\n\n"
            f"{oqs_env.install_note}\n\n"
            f"[dim]Install: pip install liboqs-python[/]",
            title="OQS Status",
            border_style="yellow",
        ))
        return

    # NIST algorithms
    nist_table = Table(title="✅ NIST Standardized PQC Algorithms", box=box.ROUNDED, header_style="bold green")
    nist_table.add_column("Algorithm", style="green")
    nist_table.add_column("Standard", style="cyan")
    nist_table.add_column("Type", style="yellow")
    nist_table.add_column("Security Level")

    from scanner.pqc_checker import NIST_KEM_ALGORITHMS, NIST_SIG_ALGORITHMS
    all_nist = {**NIST_KEM_ALGORITHMS, **NIST_SIG_ALGORITHMS}
    for alg, info in all_nist.items():
        available = any(
            alg in enabled for enabled in (oqs_env.enabled_kems + oqs_env.enabled_sigs)
        )
        status = "✅ Available" if available else "❌ Not found"
        nist_table.add_row(
            alg,
            info["fips"],
            info["type"],
            f"Level {info['security_level']} — {status}",
        )
    console.print(nist_table)

    # KEM list
    kem_table = Table(
        title=f"Key Encapsulation Mechanisms ({oqs_env.total_kems} total)",
        box=box.SIMPLE, header_style="bold cyan"
    )
    kem_table.add_column("KEM Algorithm", style="cyan")
    for alg in oqs_env.enabled_kems:
        kem_table.add_row(alg)

    # Sig list
    sig_table = Table(
        title=f"Signature Algorithms ({oqs_env.total_sigs} total)",
        box=box.SIMPLE, header_style="bold purple"
    )
    sig_table.add_column("Signature Algorithm", style="magenta")
    for alg in oqs_env.enabled_sigs:
        sig_table.add_row(alg)

    console.print(Columns([kem_table, sig_table]))
    console.print(f"\n[green]OQS Library Version:[/] {oqs_env.oqs_version}")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _print_env_summary(nmap_info: dict, oqs_env: OQSEnvironmentInfo):
    items = []
    nmap_status = "[green]✅ nmap available[/]" if nmap_info["nmap_binary_found"] else "[yellow]⚠️  nmap not found (install: brew install nmap)[/]"
    oqs_status = f"[green]✅ liboqs v{oqs_env.oqs_version}[/]" if oqs_env.oqs_available else "[yellow]⚠️  liboqs not installed (pip install liboqs-python)[/]"

    console.print(Panel(
        f"[bold]Environment Check[/]\n\n"
        f"  {nmap_status}\n"
        f"  {oqs_status}\n"
        f"  [cyan]ℹ️  Python ssl module: always available[/]",
        border_style="cyan",
        padding=(0, 1),
    ))


def _print_results_table(results: list):
    table = Table(
        title="🔐 PQC Readiness Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
    )
    table.add_column("Score", width=6, justify="center")
    table.add_column("Grade", width=5, justify="center")
    table.add_column("Domain", style="cyan", no_wrap=True)
    table.add_column("TLS", width=8)
    table.add_column("Cert Key", width=12)
    table.add_column("PQC Hybrid", width=10, justify="center")
    table.add_column("HNDL Risk", width=10)
    table.add_column("Readiness", width=16)

    for r in results:
        score = r.get("pqc_score", 0)
        grade = r.get("pqc_grade", "?")
        domain = r.get("domain", "")
        tls_ver = r.get("tls_version", "—")
        level = r.get("readiness_level", "Unknown")
        hndl = r.get("hndl_risk", "UNKNOWN")
        is_pqc = r.get("is_pqc_hybrid", False)
        tls_data = r.get("tls", {})
        cert = tls_data.get("cert") or {}
        cert_key = cert.get("key_type", "—")
        if cert.get("key_size"):
            cert_key += f"-{cert['key_size']}"

        score_style = _score_style(score)
        level_style = LEVEL_STYLE.get(level, "white")
        hndl_style = HNDL_STYLE.get(hndl, "white")
        tls_style = "green" if tls_ver == "TLSv1.3" else "yellow" if tls_ver == "TLSv1.2" else "red"
        pqc_icon = "[green]🏆 YES[/]" if is_pqc else "[red]✗ NO[/]"

        table.add_row(
            Text(str(score), style=score_style),
            Text(grade, style=score_style),
            domain,
            Text(tls_ver or "—", style=tls_style),
            Text(cert_key, style="dim"),
            pqc_icon,
            Text(hndl, style=hndl_style),
            Text(f"{_score_icon(score)} {level}", style=level_style),
        )

    console.print(table)


def _print_summary_panel(summary: dict, elapsed: float):
    total = summary.get("total_domains", 0)
    avg = summary.get("average_pqc_score", 0)
    pqc_ready = summary.get("pqc_ready_count", 0)
    pqc_pct = summary.get("pqc_ready_percent", 0)
    hndl = summary.get("hndl_risk_breakdown", {})
    readiness = summary.get("readiness_breakdown", {})
    critical = summary.get("critical_domains", [])

    lines = [
        f"[bold]Scan Summary[/bold]",
        "",
        f"  📊 Domains scanned:   [cyan]{total}[/]",
        f"  ⏱️  Scan duration:     [dim]{elapsed:.1f}s[/]",
        f"  📈 Average PQC score: [{_score_style(int(avg))}]{avg}/100[/]",
        f"  🏆 PQC-Ready:         [green]{pqc_ready}[/] ({pqc_pct}%)",
        "",
        "  [bold]Readiness Breakdown:[/]",
    ]
    for level, count in readiness.items():
        icon = _score_icon(76 if "PQC" in level else 55 if "Classical" in level else 35 if "Vuln" in level else 0)
        lines.append(f"    {icon}  {level}: [bold]{count}[/]")

    lines.append("")
    lines.append("  [bold]HNDL Risk Breakdown:[/]")
    for risk, count in hndl.items():
        style = HNDL_STYLE.get(risk, "white")
        lines.append(f"    [{style}]{risk}[/]: [bold]{count}[/]")

    if critical:
        lines.append("")
        lines.append("  [bold red]⚠️  Critical Domains:[/]")
        for d in critical:
            lines.append(f"    [red]• {d}[/]")

    console.print(Panel("\n".join(lines), border_style="cyan", padding=(0, 1)))


# ─── Entry Point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
