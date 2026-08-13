"""
scanner/report.py
Report generator — produces JSON data files and a rich interactive HTML report.
"""

import json
import os
import datetime
from pathlib import Path
from typing import Optional


# ─── HTML Report Template ─────────────────────────────────────────────────────
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Indonesia PQC Readiness Report – {scan_date}</title>
  <meta name="description" content="Post-Quantum Cryptography readiness assessment of Indonesian government websites (.go.id)" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --bg-primary:    #0a0f1e;
      --bg-card:       #111827;
      --bg-card2:      #1a2236;
      --border:        #1e2d45;
      --accent-blue:   #3b82f6;
      --accent-cyan:   #06b6d4;
      --accent-green:  #10b981;
      --accent-yellow: #f59e0b;
      --accent-orange: #f97316;
      --accent-red:    #ef4444;
      --accent-purple: #8b5cf6;
      --text-primary:  #f1f5f9;
      --text-muted:    #94a3b8;
      --text-dim:      #475569;
      --shadow:        0 4px 24px rgba(0,0,0,0.4);
      --radius:        12px;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Inter', sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      line-height: 1.6;
    }}
    /* ─── Header ─────────────────────────────────────────────── */
    .site-header {{
      background: linear-gradient(135deg, #0d1b2a 0%, #1a2a4a 50%, #0d1b2a 100%);
      border-bottom: 1px solid var(--border);
      padding: 2rem 0;
      position: relative;
      overflow: hidden;
    }}
    .site-header::before {{
      content: '';
      position: absolute; inset: 0;
      background: radial-gradient(ellipse at 30% 50%, rgba(59,130,246,0.12) 0%, transparent 60%),
                  radial-gradient(ellipse at 80% 20%, rgba(139,92,246,0.1) 0%, transparent 50%);
      pointer-events: none;
    }}
    .header-inner {{
      max-width: 1300px; margin: 0 auto; padding: 0 2rem;
      display: flex; justify-content: space-between; align-items: center;
      flex-wrap: wrap; gap: 1rem; position: relative; z-index: 1;
    }}
    .logo-section h1 {{
      font-size: 1.8rem; font-weight: 800;
      background: linear-gradient(135deg, #60a5fa, #a78bfa, #34d399);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text;
    }}
    .logo-section p {{
      font-size: 0.85rem; color: var(--text-muted); margin-top: 0.25rem;
    }}
    .scan-meta {{
      text-align: right; font-size: 0.8rem; color: var(--text-muted);
    }}
    .scan-meta strong {{ color: var(--text-primary); font-size: 0.9rem; }}
    /* ─── Layout ─────────────────────────────────────────────── */
    .container {{ max-width: 1300px; margin: 0 auto; padding: 2rem; }}
    /* ─── Summary Stats ──────────────────────────────────────── */
    .stats-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem; margin-bottom: 2rem;
    }}
    .stat-card {{
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 1.5rem;
      text-align: center;
      position: relative; overflow: hidden;
      transition: transform 0.2s, border-color 0.2s;
    }}
    .stat-card:hover {{ transform: translateY(-2px); border-color: var(--accent-blue); }}
    .stat-card::after {{
      content: ''; position: absolute;
      bottom: 0; left: 0; right: 0; height: 3px;
      background: var(--accent-color, var(--accent-blue));
    }}
    .stat-card .stat-value {{
      font-size: 2.5rem; font-weight: 800; line-height: 1;
      background: linear-gradient(135deg, var(--accent-color, #60a5fa), white);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent;
      background-clip: text;
    }}
    .stat-card .stat-label {{
      font-size: 0.8rem; color: var(--text-muted); margin-top: 0.5rem; font-weight: 500;
      text-transform: uppercase; letter-spacing: 0.05em;
    }}
    /* ─── Score Gauge ────────────────────────────────────────── */
    .gauge-section {{
      display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; margin-bottom: 2rem;
    }}
    @media (max-width: 768px) {{ .gauge-section {{ grid-template-columns: 1fr; }} }}
    .gauge-card {{
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.5rem;
    }}
    .gauge-title {{
      font-size: 0.9rem; font-weight: 600; color: var(--text-muted);
      text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem;
    }}
    /* ─── Legend ─────────────────────────────────────────────── */
    .legend {{
      display: flex; flex-wrap: wrap; gap: 0.75rem;
      margin-bottom: 2rem;
    }}
    .legend-item {{
      display: flex; align-items: center; gap: 0.5rem;
      font-size: 0.8rem; color: var(--text-muted);
    }}
    .legend-dot {{
      width: 12px; height: 12px; border-radius: 50%;
    }}
    /* ─── Filters ────────────────────────────────────────────── */
    .filters {{
      display: flex; flex-wrap: wrap; gap: 0.75rem; margin-bottom: 1.5rem;
      align-items: center;
    }}
    .filter-label {{ font-size: 0.8rem; color: var(--text-muted); font-weight: 600; }}
    .filter-btn {{
      padding: 0.4rem 1rem; border-radius: 999px; font-size: 0.8rem; font-weight: 500;
      border: 1px solid var(--border); background: var(--bg-card2);
      color: var(--text-muted); cursor: pointer; transition: all 0.2s;
    }}
    .filter-btn:hover, .filter-btn.active {{
      background: var(--accent-blue); border-color: var(--accent-blue);
      color: white;
    }}
    /* ─── Domain Table ───────────────────────────────────────── */
    .table-wrap {{
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius); overflow: hidden; margin-bottom: 2rem;
    }}
    .table-header {{
      padding: 1.25rem 1.5rem;
      border-bottom: 1px solid var(--border);
      display: flex; justify-content: space-between; align-items: center;
    }}
    .table-header h2 {{ font-size: 1rem; font-weight: 700; }}
    .search-input {{
      padding: 0.4rem 0.8rem; border-radius: 8px;
      border: 1px solid var(--border); background: var(--bg-primary);
      color: var(--text-primary); font-size: 0.85rem; width: 200px;
      outline: none; transition: border-color 0.2s;
    }}
    .search-input:focus {{ border-color: var(--accent-blue); }}
    table {{
      width: 100%; border-collapse: collapse;
      font-size: 0.85rem;
    }}
    th {{
      background: var(--bg-card2); color: var(--text-muted);
      font-weight: 600; font-size: 0.75rem;
      text-transform: uppercase; letter-spacing: 0.05em;
      padding: 0.75rem 1rem; text-align: left; white-space: nowrap;
      border-bottom: 1px solid var(--border);
    }}
    td {{ padding: 0.85rem 1rem; border-bottom: 1px solid rgba(30,45,69,0.5); vertical-align: middle; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(59,130,246,0.04); }}
    .domain-cell {{ font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; }}
    .domain-link {{ color: var(--accent-cyan); text-decoration: none; }}
    .domain-link:hover {{ text-decoration: underline; }}
    .name-cell {{ font-weight: 500; font-size: 0.85rem; }}
    .name-cell small {{ display: block; color: var(--text-muted); font-weight: 400; font-size: 0.75rem; }}
    /* ─── Score Badge ────────────────────────────────────────── */
    .score-badge {{
      display: inline-flex; align-items: center; justify-content: center;
      width: 44px; height: 44px; border-radius: 50%;
      font-weight: 800; font-size: 1rem;
      border: 2px solid; flex-shrink: 0;
    }}
    .grade-badge {{
      display: inline-block; padding: 0.2rem 0.6rem;
      border-radius: 6px; font-size: 0.8rem; font-weight: 700;
      font-family: 'JetBrains Mono', monospace;
    }}
    /* ─── Status Pills ───────────────────────────────────────── */
    .pill {{
      display: inline-block; padding: 0.2rem 0.7rem;
      border-radius: 999px; font-size: 0.75rem; font-weight: 600;
      white-space: nowrap;
    }}
    .pill-green  {{ background: rgba(16,185,129,0.15); color: #34d399; border: 1px solid rgba(16,185,129,0.3); }}
    .pill-blue   {{ background: rgba(59,130,246,0.15); color: #60a5fa; border: 1px solid rgba(59,130,246,0.3); }}
    .pill-yellow {{ background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3); }}
    .pill-orange {{ background: rgba(249,115,22,0.15); color: #fb923c; border: 1px solid rgba(249,115,22,0.3); }}
    .pill-red    {{ background: rgba(239,68,68,0.15);  color: #f87171; border: 1px solid rgba(239,68,68,0.3); }}
    .pill-gray   {{ background: rgba(100,116,139,0.15); color: #94a3b8; border: 1px solid rgba(100,116,139,0.3); }}
    .pill-purple {{ background: rgba(139,92,246,0.15); color: #a78bfa; border: 1px solid rgba(139,92,246,0.3); }}
    /* ─── Priority badge ─────────────────────────────────────── */
    .pri-critical {{ color: #f87171; font-weight: 700; font-size: 0.7rem; }}
    .pri-high     {{ color: #fb923c; font-weight: 700; font-size: 0.7rem; }}
    .pri-medium   {{ color: #fbbf24; font-weight: 700; font-size: 0.7rem; }}
    /* ─── Score color helpers ────────────────────────────────── */
    .score-green  {{ border-color: #10b981; color: #34d399; }}
    .score-blue   {{ border-color: #3b82f6; color: #60a5fa; }}
    .score-yellow {{ border-color: #f59e0b; color: #fbbf24; }}
    .score-orange {{ border-color: #f97316; color: #fb923c; }}
    .score-red    {{ border-color: #ef4444; color: #f87171; }}
    .score-gray   {{ border-color: #64748b; color: #94a3b8; }}
    /* ─── Icons ──────────────────────────────────────────────── */
    .pqc-icon {{ font-size: 1.1rem; }}
    /* ─── Detail Panel ───────────────────────────────────────── */
    .detail-panel {{
      display: none;
      background: var(--bg-primary); border-top: 1px solid var(--border);
    }}
    .detail-panel.open {{ display: table-row; }}
    .detail-content {{
      padding: 1.5rem; display: grid;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
      gap: 1rem;
    }}
    .detail-group {{
      background: var(--bg-card2); border-radius: 8px; padding: 1rem;
    }}
    .detail-group h4 {{
      font-size: 0.75rem; font-weight: 700; color: var(--text-muted);
      text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.75rem;
    }}
    .detail-row {{
      display: flex; justify-content: space-between; align-items: flex-start;
      padding: 0.3rem 0; border-bottom: 1px solid rgba(30,45,69,0.5);
      font-size: 0.8rem; gap: 1rem;
    }}
    .detail-row:last-child {{ border-bottom: none; }}
    .detail-key {{ color: var(--text-muted); flex-shrink: 0; }}
    .detail-val {{ color: var(--text-primary); font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; text-align: right; word-break: break-all; }}
    .rec-item {{
      font-size: 0.8rem; padding: 0.4rem 0;
      border-bottom: 1px solid rgba(30,45,69,0.5);
      color: var(--text-muted); line-height: 1.5;
    }}
    .rec-item:last-child {{ border-bottom: none; }}
    /* ─── Bar chart ──────────────────────────────────────────── */
    .bar-chart {{ display: flex; flex-direction: column; gap: 0.5rem; }}
    .bar-row {{ display: flex; align-items: center; gap: 0.75rem; }}
    .bar-label {{ font-size: 0.75rem; color: var(--text-muted); width: 120px; flex-shrink: 0; }}
    .bar-track {{
      flex: 1; background: rgba(30,45,69,0.7);
      border-radius: 999px; height: 8px; overflow: hidden;
    }}
    .bar-fill {{
      height: 100%; border-radius: 999px;
      background: linear-gradient(90deg, var(--fill-start), var(--fill-end));
      transition: width 0.6s ease;
    }}
    .bar-count {{ font-size: 0.75rem; color: var(--text-muted); width: 30px; text-align: right; }}
    /* ─── OQS Section ────────────────────────────────────────── */
    .oqs-card {{
      background: var(--bg-card); border: 1px solid var(--border);
      border-radius: var(--radius); padding: 1.5rem; margin-bottom: 2rem;
    }}
    .oqs-algorithms {{
      display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1rem;
    }}
    .algo-tag {{
      padding: 0.3rem 0.7rem; border-radius: 6px;
      font-family: 'JetBrains Mono', monospace; font-size: 0.72rem;
      background: rgba(59,130,246,0.12); color: #93c5fd;
      border: 1px solid rgba(59,130,246,0.25);
    }}
    .algo-tag.nist {{ background: rgba(16,185,129,0.12); color: #6ee7b7; border-color: rgba(16,185,129,0.3); }}
    /* ─── Footer ─────────────────────────────────────────────── */
    .site-footer {{
      margin-top: 3rem; padding: 2rem;
      border-top: 1px solid var(--border); text-align: center;
      font-size: 0.8rem; color: var(--text-dim);
    }}
    .expand-btn {{
      background: none; border: none; color: var(--text-muted);
      cursor: pointer; font-size: 0.9rem; padding: 0.25rem;
      transition: color 0.2s; line-height: 1;
    }}
    .expand-btn:hover {{ color: var(--accent-blue); }}
    /* ─── Section titles ─────────────────────────────────────── */
    .section-title {{
      font-size: 1.1rem; font-weight: 700; margin-bottom: 1rem;
      display: flex; align-items: center; gap: 0.5rem;
    }}
    .section-title span {{ font-size: 1.3rem; }}
  </style>
</head>
<body>

<header class="site-header">
  <div class="header-inner">
    <div class="logo-section">
      <h1>🔐 Indonesia PQC Readiness Report</h1>
      <p>Post-Quantum Cryptography Assessment · Indonesian Government Websites (.go.id)</p>
    </div>
    <div class="scan-meta">
      <strong>Scan Date</strong><br/>
      {scan_date}<br/>
      <span style="margin-top:0.25rem; display:block;">
        {total_domains} domains scanned
      </span>
    </div>
  </div>
</header>

<div class="container">

  <!-- ─── Summary Stats ─────────────────────────────────────── -->
  <div class="stats-grid" style="margin-top: 2rem;">
    <div class="stat-card" style="--accent-color: #60a5fa;">
      <div class="stat-value">{total_domains}</div>
      <div class="stat-label">Domains Scanned</div>
    </div>
    <div class="stat-card" style="--accent-color: #f59e0b;">
      <div class="stat-value">{avg_score}</div>
      <div class="stat-label">Avg PQC Score</div>
    </div>
    <div class="stat-card" style="--accent-color: #10b981;">
      <div class="stat-value">{pqc_ready}</div>
      <div class="stat-label">PQC-Ready (Hybrid)</div>
    </div>
    <div class="stat-card" style="--accent-color: #ef4444;">
      <div class="stat-value">{critical_count}</div>
      <div class="stat-label">Critical Risk Domains</div>
    </div>
    <div class="stat-card" style="--accent-color: #f97316;">
      <div class="stat-value">{hndl_critical}</div>
      <div class="stat-label">HNDL Critical Risk</div>
    </div>
    <div class="stat-card" style="--accent-color: #8b5cf6;">
      <div class="stat-value">{hndl_high}</div>
      <div class="stat-label">HNDL High Risk</div>
    </div>
  </div>

  <!-- ─── Readiness Distribution ────────────────────────────── -->
  <div class="gauge-section">
    <div class="gauge-card">
      <div class="gauge-title">📊 PQC Readiness Distribution</div>
      <div class="bar-chart" id="readiness-bars">
        {readiness_bars}
      </div>
    </div>
    <div class="gauge-card">
      <div class="gauge-title">⚡ HNDL Risk Distribution</div>
      <div class="bar-chart" id="hndl-bars">
        {hndl_bars}
      </div>
    </div>
  </div>

  <!-- ─── OQS Environment ───────────────────────────────────── -->
  <div class="oqs-card">
    <div class="section-title"><span>⚛️</span> Local OQS/liboqs Environment</div>
    {oqs_section}
  </div>

  <!-- ─── Domain Results Table ──────────────────────────────── -->
  <div class="table-wrap">
    <div class="table-header">
      <h2>🌐 Domain Scan Results</h2>
      <input class="search-input" type="text" id="search"
             placeholder="Search domain..." oninput="filterTable(this.value)"/>
    </div>

    <div class="filters" style="padding: 0.75rem 1.5rem; background: var(--bg-card2);">
      <span class="filter-label">Filter:</span>
      <button class="filter-btn active" onclick="setFilter('all', this)">All</button>
      <button class="filter-btn" onclick="setFilter('Critical', this)">🔴 Critical</button>
      <button class="filter-btn" onclick="setFilter('Vulnerable', this)">🟠 Vulnerable</button>
      <button class="filter-btn" onclick="setFilter('Classical-Safe', this)">🟡 Classical-Safe</button>
      <button class="filter-btn" onclick="setFilter('PQC-Ready', this)">🟢 PQC-Ready</button>
      <button class="filter-btn" onclick="setFilter('CRITICAL_PRIORITY', this)">⚠️ Priority: Critical</button>
    </div>

    <table id="results-table">
      <thead>
        <tr>
          <th></th>
          <th>Score</th>
          <th>Grade</th>
          <th>Domain</th>
          <th>Agency</th>
          <th>Category</th>
          <th>Priority</th>
          <th>TLS</th>
          <th>Cert Key</th>
          <th>PQC Hybrid</th>
          <th>HNDL Risk</th>
          <th>Readiness</th>
        </tr>
      </thead>
      <tbody id="table-body">
        {table_rows}
      </tbody>
    </table>
  </div>

  <!-- ─── Disclaimer ────────────────────────────────────────── -->
  <div class="oqs-card" style="border-color: rgba(245,158,11,0.3);">
    <div class="section-title" style="color: #fbbf24;"><span>⚠️</span> Important Disclaimer</div>
    <p style="font-size: 0.85rem; color: var(--text-muted); line-height: 1.7;">
      This report is generated for <strong>educational and research purposes</strong> only.
      The scanner uses passive TLS inspection and standard HTTPS requests — no active exploitation.
      PQC readiness is assessed based on publicly observable TLS configuration; internal cryptographic
      implementations may differ. All findings should be verified by qualified security professionals
      before drawing operational conclusions. Results reflect the state at the time of scanning
      ({scan_date}).
    </p>
    <p style="font-size: 0.8rem; color: var(--text-dim); margin-top: 0.75rem;">
      Standards references: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |
      BSSN Indonesia Cybersecurity Guidelines | IETF draft-ietf-tls-hybrid-design
    </p>
  </div>

</div>

<footer class="site-footer">
  Indonesia PQC Readiness Scanner · Built with Python + liboqs + nmap ·
  Open Quantum Safe (OQS) Project ·
  <a href="https://openquantumsafe.org" style="color: var(--accent-cyan);">openquantumsafe.org</a>
</footer>

<script>
  // ─── Row data (embedded JSON) ─────────────────────────────────
  const rowData = {row_data_json};

  // ─── Filter ───────────────────────────────────────────────────
  let currentFilter = 'all';
  let currentSearch = '';

  function setFilter(filter, btn) {{
    currentFilter = filter;
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    applyFilters();
  }}

  function filterTable(query) {{
    currentSearch = query.toLowerCase();
    applyFilters();
  }}

  function applyFilters() {{
    const rows = document.querySelectorAll('#table-body tr.data-row');
    rows.forEach(row => {{
      const level = row.dataset.level || '';
      const priority = row.dataset.priority || '';
      const domain = row.dataset.domain || '';
      const name = row.dataset.name || '';
      const matchFilter = currentFilter === 'all'
        ? true
        : currentFilter === 'CRITICAL_PRIORITY'
          ? priority === 'CRITICAL'
          : level === currentFilter;
      const matchSearch = !currentSearch
        || domain.includes(currentSearch)
        || name.includes(currentSearch);
      row.style.display = (matchFilter && matchSearch) ? '' : 'none';
      // Also hide associated detail row
      const detailRow = document.getElementById('detail-' + row.dataset.idx);
      if (detailRow) {{
        detailRow.style.display = (matchFilter && matchSearch) ? '' : 'none';
      }}
    }});
  }}

  // ─── Expand detail panel ──────────────────────────────────────
  function toggleDetail(idx) {{
    const panel = document.getElementById('detail-' + idx);
    const btn = document.getElementById('expand-btn-' + idx);
    if (!panel) return;
    const isOpen = panel.classList.contains('open');
    // Close all others
    document.querySelectorAll('.detail-panel').forEach(p => p.classList.remove('open'));
    document.querySelectorAll('.expand-btn').forEach(b => b.textContent = '▶');
    if (!isOpen) {{
      panel.classList.add('open');
      btn.textContent = '▼';
    }}
  }}
</script>
</body>
</html>
"""

# Score to color mapping
LEVEL_COLORS = {
    "PQC-Ready":      ("score-green",  "pill-green",  "🟢"),
    "Classical-Safe": ("pill-blue",    "pill-blue",   "🔵"),
    "Vulnerable":     ("score-orange", "pill-orange", "🟠"),
    "Critical":       ("score-red",    "pill-red",    "🔴"),
    "Unreachable":    ("score-gray",   "pill-gray",   "⚫"),
    "Timeout":        ("score-gray",   "pill-gray",   "⏱️"),
    "Error":          ("score-gray",   "pill-gray",   "❌"),
}

HNDL_COLORS = {
    "LOW":      "pill-green",
    "MEDIUM":   "pill-yellow",
    "HIGH":     "pill-orange",
    "CRITICAL": "pill-red",
    "UNKNOWN":  "pill-gray",
}

GRADE_COLORS = {
    "A+": ("grade-badge", "background:rgba(16,185,129,0.2);color:#34d399;border:1px solid rgba(16,185,129,0.4)"),
    "A":  ("grade-badge", "background:rgba(16,185,129,0.15);color:#6ee7b7;border:1px solid rgba(16,185,129,0.3)"),
    "B":  ("grade-badge", "background:rgba(59,130,246,0.15);color:#93c5fd;border:1px solid rgba(59,130,246,0.3)"),
    "C":  ("grade-badge", "background:rgba(245,158,11,0.15);color:#fbbf24;border:1px solid rgba(245,158,11,0.3)"),
    "D":  ("grade-badge", "background:rgba(249,115,22,0.15);color:#fb923c;border:1px solid rgba(249,115,22,0.3)"),
    "F":  ("grade-badge", "background:rgba(239,68,68,0.15);color:#f87171;border:1px solid rgba(239,68,68,0.3)"),
    "N/A":("grade-badge", "background:rgba(100,116,139,0.15);color:#94a3b8;border:1px solid rgba(100,116,139,0.3)"),
}


def _score_class(level: str) -> str:
    return LEVEL_COLORS.get(level, ("score-gray",))[0]


def _pill_class(level: str) -> str:
    return LEVEL_COLORS.get(level, ("score-gray", "pill-gray"))[1]


def _level_icon(level: str) -> str:
    return LEVEL_COLORS.get(level, ("", "", "?"))[2]


def _bar_html(label: str, count: int, total: int, color_start: str, color_end: str) -> str:
    pct = round(count / total * 100) if total else 0
    return (
        f'<div class="bar-row">'
        f'<div class="bar-label">{label}</div>'
        f'<div class="bar-track">'
        f'<div class="bar-fill" style="width:{pct}%;--fill-start:{color_start};--fill-end:{color_end}"></div>'
        f'</div>'
        f'<div class="bar-count">{count}</div>'
        f'</div>'
    )


def _build_readiness_bars(summary: dict) -> str:
    total = summary.get("total_domains", 1)
    breakdown = summary.get("readiness_breakdown", {})
    html = ""
    configs = [
        ("PQC-Ready",      "#10b981", "#34d399"),
        ("Classical-Safe", "#3b82f6", "#60a5fa"),
        ("Vulnerable",     "#f97316", "#fb923c"),
        ("Critical",       "#ef4444", "#f87171"),
        ("Unreachable",    "#64748b", "#94a3b8"),
    ]
    for label, c1, c2 in configs:
        count = breakdown.get(label, 0)
        if count > 0:
            html += _bar_html(label, count, total, c1, c2)
    return html or "<p style='color:var(--text-dim);font-size:0.8rem;'>No data</p>"


def _build_hndl_bars(summary: dict) -> str:
    total = summary.get("total_domains", 1)
    breakdown = summary.get("hndl_risk_breakdown", {})
    html = ""
    configs = [
        ("LOW",      "#10b981", "#34d399"),
        ("MEDIUM",   "#f59e0b", "#fbbf24"),
        ("HIGH",     "#f97316", "#fb923c"),
        ("CRITICAL", "#ef4444", "#f87171"),
        ("UNKNOWN",  "#64748b", "#94a3b8"),
    ]
    for label, c1, c2 in configs:
        count = breakdown.get(label, 0)
        if count > 0:
            html += _bar_html(label, count, total, c1, c2)
    return html or "<p style='color:var(--text-dim);font-size:0.8rem;'>No data</p>"


def _build_oqs_section(oqs_env: dict) -> str:
    if not oqs_env.get("oqs_available"):
        note = oqs_env.get("install_note", "liboqs not available")
        return (
            f'<div class="pill pill-orange">OQS Not Available</div>'
            f'<p style="margin-top:0.75rem;font-size:0.85rem;color:var(--text-muted);">{note}</p>'
            f'<p style="margin-top:0.5rem;font-size:0.8rem;color:var(--text-dim);">'
            f'Install: <code style="font-family:JetBrains Mono,monospace;">pip install liboqs-python</code></p>'
        )

    version = oqs_env.get("oqs_version", "?")
    total_kems = oqs_env.get("total_kems", 0)
    total_sigs = oqs_env.get("total_sigs", 0)
    nist_kems = oqs_env.get("nist_kems_available", [])
    nist_sigs = oqs_env.get("nist_sigs_available", [])
    all_kems = oqs_env.get("enabled_kems", [])[:20]  # limit display
    all_sigs = oqs_env.get("enabled_sigs", [])[:20]

    nist_tags = "".join(
        f'<span class="algo-tag nist">{alg}</span>' for alg in (nist_kems + nist_sigs)
    )
    kem_tags = "".join(
        f'<span class="algo-tag">{alg}</span>' for alg in all_kems
    )
    sig_tags = "".join(
        f'<span class="algo-tag">{alg}</span>' for alg in all_sigs
    )

    return f"""
    <div style="display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:1rem;">
      <span class="pill pill-green">OQS v{version}</span>
      <span class="pill pill-blue">{total_kems} KEMs</span>
      <span class="pill pill-purple">{total_sigs} Signatures</span>
    </div>
    <div style="margin-bottom:0.75rem;">
      <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem;font-weight:600;">
        ✅ NIST Standardized Algorithms (FIPS 203/204/205):
      </p>
      <div class="oqs-algorithms">{nist_tags or '<span style="color:var(--text-dim);font-size:0.8rem;">None detected</span>'}</div>
    </div>
    <div style="margin-bottom:0.75rem;">
      <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem;font-weight:600;">
        Available KEMs (first 20):
      </p>
      <div class="oqs-algorithms">{kem_tags}</div>
    </div>
    <div>
      <p style="font-size:0.8rem;color:var(--text-muted);margin-bottom:0.5rem;font-weight:600;">
        Available Signatures (first 20):
      </p>
      <div class="oqs-algorithms">{sig_tags}</div>
    </div>
    """


def _build_detail_panel(r: dict, idx: int) -> str:
    """Build an expandable detail panel row for a domain result."""
    tls = r.get("tls", {})
    cert = tls.get("cert") or {}
    pqc = r.get("pqc", {})
    http = r.get("http", {})
    nmap = r.get("nmap", {})

    def row(key: str, val) -> str:
        val_str = str(val) if val is not None else "—"
        if val_str == "" or val_str == "False":
            val_str = "No"
        if val_str == "True":
            val_str = "Yes"
        return f'<div class="detail-row"><span class="detail-key">{key}</span><span class="detail-val">{val_str[:80]}</span></div>'

    def rec_item(text: str) -> str:
        return f'<div class="rec-item">{text}</div>'

    tls_html = (
        row("TLS Version", tls.get("tls_version"))
        + row("Cipher Suite", tls.get("cipher_suite"))
        + row("Key Exchange", tls.get("key_exchange"))
        + row("Negotiated Group", tls.get("negotiated_group") or "—")
        + row("PQC Hybrid", tls.get("is_pqc_hybrid"))
        + row("TLS 1.3 Support", tls.get("supports_tls13"))
        + row("TLS 1.2 Support", tls.get("supports_tls12"))
        + row("Connection Time", f"{tls.get('connection_time_ms', 0):.1f}ms")
        + row("HSTS", tls.get("hsts_enabled"))
        + row("HSTS max-age", tls.get("hsts_max_age"))
    )

    cert_html = (
        row("Subject CN", cert.get("subject_cn"))
        + row("Issuer", cert.get("issuer_cn"))
        + row("Issuer Org", cert.get("issuer_org"))
        + row("Key Type", cert.get("key_type"))
        + row("Key Size", f"{cert.get('key_size', 0)} bits")
        + row("Sig Algorithm", cert.get("sig_algorithm"))
        + row("Valid Until", str(cert.get("not_after", ""))[:10])
        + row("Days Remaining", cert.get("days_remaining"))
        + row("Is Expired", cert.get("is_expired"))
        + row("Quantum Risk", cert.get("quantum_risk"))
        + row("PQC Cert", cert.get("is_pqc_cert"))
        + row("EV Cert", cert.get("is_ev"))
    )

    pqc_html = (
        row("PQC Score", f"{pqc.get('pqc_score', 0)}/100")
        + row("Grade", pqc.get("pqc_grade"))
        + row("Readiness Level", pqc.get("readiness_level"))
        + row("HNDL Risk", pqc.get("hndl_risk"))
        + row("Migration Priority", pqc.get("migration_priority"))
        + row("TLS Score", f"{pqc.get('score_tls_version', 0)}/20")
        + row("Key Exchange Score", f"{pqc.get('score_key_exchange', 0)}/15")
        + row("Cert Key Score", f"{pqc.get('score_cert_key', 0)}/20")
        + row("PQC Hybrid Score", f"{pqc.get('score_pqc_hybrid', 0)}/30")
        + row("HSTS Score", f"{pqc.get('score_hsts', 0)}/10")
        + row("Cipher Score", f"{pqc.get('score_cipher_strength', 0)}/5")
    )

    http_html = (
        row("HTTP Status", http.get("status_code"))
        + row("Server", http.get("server_header") or "—")
        + row("HSTS", http.get("hsts"))
        + row("CSP", http.get("csp"))
        + row("X-Frame-Options", http.get("x_frame_options"))
        + row("X-Content-Type", http.get("x_content_type_options"))
        + row("Header Score", f"{http.get('header_score', 0)}/100")
        + row("Header Grade", http.get("header_grade") or "—")
    )

    issues = pqc.get("issues", [])
    positives = pqc.get("positives", [])
    recommendations = pqc.get("recommendations", [])

    findings_html = ""
    for p in positives:
        findings_html += f'<div class="rec-item" style="color:#34d399;">{p}</div>'
    for i in issues:
        findings_html += f'<div class="rec-item" style="color:#f87171;">{i}</div>'

    recs_html = "".join(rec_item(r) for r in recommendations)

    hndl_exp = pqc.get("hndl_explanation", "")

    nmap_note = nmap.get("error", "") or nmap.get("note", "")
    nmap_ciphers = nmap.get("tls_versions_supported", [])
    nmap_html = row("Port Open", nmap.get("port_open")) + row("IP Address", nmap.get("ip_address") or "—")
    if nmap_ciphers:
        nmap_html += row("TLS Versions (nmap)", ", ".join(nmap_ciphers))
    if nmap_note:
        nmap_html += f'<div class="rec-item" style="color:var(--text-muted);margin-top:0.5rem;">{nmap_note}</div>'

    return f"""
<tr id="detail-{idx}" class="detail-panel">
  <td colspan="12">
    <div class="detail-content">
      <div class="detail-group">
        <h4>🔒 TLS Handshake</h4>
        {tls_html}
      </div>
      <div class="detail-group">
        <h4>📜 Certificate</h4>
        {cert_html}
      </div>
      <div class="detail-group">
        <h4>⚛️ PQC Assessment</h4>
        {pqc_html}
      </div>
      <div class="detail-group">
        <h4>🌐 HTTP Headers</h4>
        {http_html}
      </div>
      <div class="detail-group">
        <h4>🔍 Nmap</h4>
        {nmap_html}
      </div>
      <div class="detail-group">
        <h4>⚠️ Findings</h4>
        {findings_html or '<div class="rec-item" style="color:var(--text-dim);">No findings</div>'}
        {f'<div style="margin-top:0.75rem;padding:0.5rem;background:rgba(239,68,68,0.08);border-radius:6px;font-size:0.78rem;color:#fca5a5;border:1px solid rgba(239,68,68,0.2);">{hndl_exp}</div>' if hndl_exp else ''}
      </div>
      <div class="detail-group">
        <h4>🔧 Recommendations</h4>
        {recs_html or '<div class="rec-item" style="color:var(--text-dim);">None</div>'}
      </div>
    </div>
  </td>
</tr>"""


def _build_table_row(r: dict, idx: int) -> str:
    domain = r.get("domain", "")
    name = r.get("name", domain)
    category = r.get("category", "")
    priority = r.get("priority", "")
    level = r.get("readiness_level", "Unknown")
    score = r.get("pqc_score", 0)
    grade = r.get("pqc_grade", "?")
    tls_ver = r.get("tls_version", "—")
    is_pqc = r.get("is_pqc_hybrid", False)
    hndl = r.get("hndl_risk", "UNKNOWN")

    # Cert info from nested tls.cert
    tls = r.get("tls", {})
    cert = tls.get("cert") or {}
    cert_key = cert.get("key_type", "—")
    if cert.get("key_size"):
        cert_key += f"-{cert['key_size']}"

    score_cls = _score_class(level)
    level_icon = _level_icon(level)
    level_pill = _pill_class(level)
    hndl_cls = HNDL_COLORS.get(hndl, "pill-gray")
    grade_style = GRADE_COLORS.get(grade, GRADE_COLORS["N/A"])[1]
    pri_cls = {
        "CRITICAL": "pri-critical",
        "HIGH": "pri-high",
        "MEDIUM": "pri-medium",
    }.get(priority, "pri-medium")

    pqc_icon = "🏆" if is_pqc else "🔓"

    detail_row = _build_detail_panel(r, idx)

    row_html = f"""<tr class="data-row" data-level="{level}" data-priority="{priority}"
         data-domain="{domain.lower()}" data-name="{name.lower()}" data-idx="{idx}">
  <td><button class="expand-btn" id="expand-btn-{idx}" onclick="toggleDetail({idx})">▶</button></td>
  <td><div class="score-badge {score_cls}">{score}</div></td>
  <td><span class="grade-badge" style="{grade_style}">{grade}</span></td>
  <td class="domain-cell"><a class="domain-link" href="https://{domain}" target="_blank">{domain}</a></td>
  <td class="name-cell">{name}<small>{category}</small></td>
  <td><span class="pill pill-gray" style="font-size:0.7rem;">{category}</span></td>
  <td><span class="{pri_cls}">{priority}</span></td>
  <td><code style="font-size:0.75rem;color:{'#6ee7b7' if tls_ver == 'TLSv1.3' else '#fbbf24'};">{tls_ver or '—'}</code></td>
  <td><code style="font-size:0.75rem;color:var(--text-muted);">{cert_key}</code></td>
  <td style="text-align:center;font-size:1.2rem;" title="{pqc_icon}">{pqc_icon}</td>
  <td><span class="pill {hndl_cls}">{hndl}</span></td>
  <td><span class="pill {level_pill}">{level_icon} {level}</span></td>
</tr>
{detail_row}"""
    return row_html


class ReportGenerator:
    """Generates JSON and HTML reports from scan results."""

    def __init__(self, output_dir: str = "output"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def save_json(self, data: dict, filename: str = "report.json") -> str:
        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return str(out_path)

    def generate_html(
        self,
        results: list,
        summary: dict,
        oqs_env: dict,
        filename: str = "report.html",
    ) -> str:
        """Generate a full interactive HTML report."""
        scan_date = datetime.datetime.now().strftime("%Y-%m-%d %H:%M UTC+7")
        total = summary.get("total_domains", len(results))
        avg_score = summary.get("average_pqc_score", 0)
        pqc_ready = summary.get("pqc_ready_count", 0)
        hndl_breakdown = summary.get("hndl_risk_breakdown", {})
        readiness_breakdown = summary.get("readiness_breakdown", {})
        critical_count = readiness_breakdown.get("Critical", 0)
        hndl_critical = hndl_breakdown.get("CRITICAL", 0)
        hndl_high = hndl_breakdown.get("HIGH", 0)

        table_rows = ""
        for idx, r in enumerate(results):
            table_rows += _build_table_row(r, idx)

        html = HTML_TEMPLATE.format(
            scan_date=scan_date,
            total_domains=total,
            avg_score=avg_score,
            pqc_ready=pqc_ready,
            critical_count=critical_count,
            hndl_critical=hndl_critical,
            hndl_high=hndl_high,
            readiness_bars=_build_readiness_bars(summary),
            hndl_bars=_build_hndl_bars(summary),
            oqs_section=_build_oqs_section(oqs_env),
            table_rows=table_rows,
            row_data_json=json.dumps(results, default=str),
        )

        out_path = self.output_dir / filename
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)

        return str(out_path)
