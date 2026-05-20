#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.
#
# This program is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Generates a fully self-contained interactive HTML report for Munin.
No external CDN or internet required to VIEW the report.
"""

import json
import html
from pathlib import Path
from datetime import datetime
from typing import Dict


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

RISK_COLOR_CSS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "MINIMAL":  "#6b7280",
    "UNKNOWN":  "#9ca3af",
}

SEVERITY_COLOR_CSS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "NONE":     "#6b7280",
    "UNKNOWN":  "#9ca3af",
}

RISK_LABEL_CSS = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "MINIMAL":  "#6b7280",
    "UNKNOWN":  "#9ca3af",
}


def _build_findings_html(findings: list, score: int, level: str) -> str:
    """Build the 'Detected Threats' + 'Risk Explanation' HTML block."""
    if not findings:
        return ""

    _sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_f = sorted(
        findings,
        key=lambda f: _sev_weight.get(f.get("severity", "LOW"), 0),
        reverse=True,
    )

    level_color = RISK_LABEL_CSS.get(level, "#9ca3af")

    # ── Threat rows ───────────────────────────────────────────────────────────
    threat_rows = ""
    for f in sorted_f:
        sev   = f.get("severity", "?")
        sev_c = SEVERITY_COLOR_CSS.get(sev, "#9ca3af")
        name  = html.escape(f.get("name", ""))
        detail = html.escape(f.get("detail", ""))
        desc   = html.escape(f.get("description", ""))
        threat_rows += f"""
        <tr>
          <td>{_badge(sev, sev_c)}</td>
          <td style="font-weight:600">{name}</td>
          <td style="color:#94a3b8;font-size:.82rem">{detail}</td>
        </tr>
        <tr>
          <td colspan="3" style="color:#64748b;font-size:.78rem;
              padding:2px 12px 10px;border-bottom:1px solid #1e293b">
            {desc}
          </td>
        </tr>"""

    # ── Remediation steps ─────────────────────────────────────────────────────
    from scanner.analysis.risk_engine import prioritised_remediation
    steps = prioritised_remediation(findings)
    rem_html = ""
    if steps:
        items = "".join(
            f'<li style="margin:3px 0;color:#94a3b8;font-size:.82rem">'
            f'{html.escape(s)}</li>'
            for s in steps[:10]
        )
        rem_html = f"""
        <div style="margin-top:12px">
          <div style="font-weight:600;color:#e2e8f0;margin-bottom:6px">
            Recommended Actions
          </div>
          <ol style="margin-left:20px">{items}</ol>
        </div>"""

    return f"""
    <div style="margin:12px 0;border:1px solid {level_color}33;
         border-radius:8px;overflow:hidden">

      <div style="background:{level_color}18;padding:10px 14px;
           border-bottom:1px solid {level_color}33;
           display:flex;align-items:center;gap:10px">
        <span style="font-weight:700;color:{level_color}">
          THREATS DETECTED
        </span>
        <span style="color:#94a3b8;font-size:.8rem">
          Risk score: <strong style="color:{level_color}">{score}/100 [{level}]</strong>
        </span>
      </div>

      <div style="padding:12px;background:#0d1117">
        <table style="width:100%;border-collapse:collapse">
          <thead>
            <tr style="color:#475569;font-size:.75rem;text-transform:uppercase">
              <th style="text-align:left;padding:4px 8px;width:100px">Severity</th>
              <th style="text-align:left;padding:4px 8px;width:200px">Threat</th>
              <th style="text-align:left;padding:4px 8px">Detail</th>
            </tr>
          </thead>
          <tbody>{threat_rows}</tbody>
        </table>
        {rem_html}
      </div>
    </div>"""


def _badge(text: str, color: str) -> str:
    return (
        f'<span style="background:{color};color:#fff;'
        f'padding:2px 8px;border-radius:9999px;font-size:.75rem;'
        f'font-weight:700;white-space:nowrap">{html.escape(str(text))}</span>'
    )


def _risk_badge(level: str) -> str:
    color = RISK_COLOR_CSS.get(level, "#9ca3af")
    return _badge(level, color)


def _severity_badge(sev: str, score) -> str:
    color = SEVERITY_COLOR_CSS.get(sev, "#9ca3af")
    label = f"{sev} ({score})" if score else sev
    return _badge(label, color)


# ─────────────────────────────────────────────────────────────────────────────
# HTML building blocks
# ─────────────────────────────────────────────────────────────────────────────

def _build_summary_cards(result: dict) -> str:
    meta  = result.get("meta", {})
    hosts = result.get("hosts", [])

    total_cves = sum(
        sum(len(p.get("cves", [])) for p in h.get("ports", []))
        for h in hosts
    )
    open_ports = sum(
        sum(1 for p in h.get("ports", []) if p.get("state") == "open")
        for h in hosts
    )

    risk_counts = {lvl: 0 for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL")}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        if lvl in risk_counts:
            risk_counts[lvl] += 1

    def card(title, value, color="#6366f1"):
        return f"""
        <div class="card">
            <div class="card-value" style="color:{color}">{value}</div>
            <div class="card-label">{title}</div>
        </div>"""

    cards = (
        card("Target",      html.escape(meta.get("target", "N/A")))
        + card("Hosts Found",  len(hosts),    "#6366f1")
        + card("Open Ports",   open_ports,    "#3b82f6")
        + card("CVEs Found",   total_cves,    "#ef4444")
    )
    for lvl, cnt in risk_counts.items():
        if cnt:
            cards += card(f"{lvl} Hosts", cnt, RISK_COLOR_CSS.get(lvl, "#999"))

    return f'<div class="cards">{cards}</div>'


def _build_host_rows(hosts: list) -> str:
    rows = ""
    for h in sorted(hosts, key=lambda x: x.get("risk_score", 0), reverse=True):
        ip         = html.escape(h.get("ip", ""))
        mac        = html.escape(h.get("mac", "N/A"))
        vendor     = html.escape(h.get("mac_vendor", "Unknown"))
        hostname   = html.escape(h.get("hostname", "N/A"))
        os_name    = html.escape(h.get("os", {}).get("name", "Unknown"))
        os_acc     = h.get("os", {}).get("accuracy", 0)
        risk_score = h.get("risk_score", 0)
        risk_level = h.get("risk_level", "UNKNOWN")

        ports      = h.get("ports", [])
        open_count = sum(1 for p in ports if p.get("state") == "open")
        cve_count  = sum(len(p.get("cves", [])) for p in ports)

        row_id = f"row-{ip.replace('.', '-')}"

        # Port sub-table
        port_rows = ""
        for p in ports:
            pv = " ".join(filter(None, [
                p.get("product", ""), p.get("version", ""), p.get("extrainfo", "")
            ]))
            state_color = "#22c55e" if p["state"] == "open" else "#eab308"
            cve_cells   = ""
            for cve in p.get("cves", []):
                sev    = cve.get("severity", "UNKNOWN")
                score  = cve.get("cvss_score", "")
                desc   = html.escape(cve.get("description", "")[:200])
                cve_id = html.escape(cve.get("id", ""))
                ref    = cve.get("references", [""])[0]
                link   = (
                    f'<a href="{html.escape(ref)}" target="_blank" '
                    f'style="color:#6366f1">{cve_id}</a>'
                ) if ref else cve_id
                cve_cells += (
                    f'<div style="margin:4px 0">'
                    f'{_severity_badge(sev, score)} {link}'
                    f'<br><small style="color:#9ca3af">{desc}</small></div>'
                )

            port_rows += f"""
            <tr>
                <td><code>{p['port']}/{p['protocol']}</code></td>
                <td style="color:{state_color};font-weight:600">{p['state']}</td>
                <td>{html.escape(p.get('service', ''))}</td>
                <td>{html.escape(pv)}</td>
                <td>{cve_cells or '<span style="color:#6b7280">--</span>'}</td>
            </tr>"""

        # NSE findings
        nse_html = ""
        for port_num, scripts in h.get("vulnerabilities", {}).items():
            for script_name, output in scripts.items():
                out_str = str(output)
                if "VULNERABLE" in out_str.upper():
                    lines = html.escape(out_str[:400])
                    nse_html += (
                        f'<div style="background:#450a0a;border-left:3px solid #ef4444;'
                        f'padding:8px;margin:4px 0;border-radius:4px">'
                        f'<strong style="color:#ef4444">VULNERABLE: '
                        f'{html.escape(script_name)} (port {port_num})</strong>'
                        f'<pre style="margin:4px 0;font-size:.8rem;color:#fca5a5;'
                        f'white-space:pre-wrap">{lines}</pre></div>'
                    )

        # Threat findings block (new analysis engine)
        findings_html = _build_findings_html(
            h.get("findings", []),
            risk_score,
            risk_level,
        )
        detail_html = ""
        if port_rows or nse_html or findings_html:
            detail_html = f"""
            <tr id="{row_id}-detail" class="detail-row" style="display:none">
                <td colspan="8" style="padding:0">
                    <div style="padding:16px;background:#111827">
                        {findings_html}
                        {'<table class="inner-table"><thead><tr>'
                         '<th>Port</th><th>State</th><th>Service</th>'
                         '<th>Product / Version</th><th>CVEs</th>'
                         '</tr></thead><tbody>' + port_rows + '</tbody></table>'
                         if port_rows else ''}
                        {nse_html}
                    </div>
                </td>
            </tr>"""

        has_detail = bool(port_rows or nse_html or findings_html)
        toggle_js  = f"toggleRow('{row_id}-detail')" if has_detail else ""
        cursor     = "pointer" if has_detail else "default"
        arrow      = "&#9654;" if has_detail else ""   # right-pointing triangle, no emoji

        threat_count = len(h.get("findings", []))
        one_liner    = ""
        if threat_count:
            from scanner.analysis.risk_engine import one_line_summary
            ol = one_line_summary(ip, h.get("findings", []), risk_score, risk_level)
            # strip the IP+score prefix, keep just the threat names
            parts = ol.split("]  ", 1)
            one_liner = parts[1] if len(parts) > 1 else ""

        rows += f"""
        <tr class="host-row" onclick="{toggle_js}"
            style="cursor:{cursor}"
            data-risk="{risk_level}">
            <td style="color:#9ca3af;font-size:.9rem">{arrow}</td>
            <td><code style="color:#60a5fa">{ip}</code>
                {'<br><small style="color:#f97316;font-size:.72rem">' + html.escape(one_liner[:60]) + '</small>' if one_liner else ''}
            </td>
            <td><code style="font-size:.8rem">{mac}</code></td>
            <td>{vendor}</td>
            <td>{hostname}</td>
            <td style="max-width:200px">{os_name}
                {'<br><small style="color:#6b7280">' + str(os_acc) + '% confidence</small>'
                 if os_acc else ''}</td>
            <td style="text-align:center">{open_count}</td>
            <td style="text-align:center">{
                ('<span style="color:#ef4444;font-weight:700">' + str(cve_count) + '</span>')
                if cve_count else '<span style="color:#6b7280">0</span>'
            }</td>
            <td style="text-align:center">{
                ('<span style="color:#f97316;font-weight:700">' + str(threat_count) + '</span>')
                if threat_count else '<span style="color:#6b7280">0</span>'
            }</td>
            <td>{_risk_badge(risk_level)}<br>
                <small style="color:#9ca3af">{risk_score}/100</small></td>
        </tr>
        {detail_html}"""

    return rows


# ─────────────────────────────────────────────────────────────────────────────
# Main generator
# ─────────────────────────────────────────────────────────────────────────────

def generate(result: dict, output_path: str = "munin_report.html") -> str:
    """
    Write the self-contained HTML report to `output_path`.
    Returns the absolute path string.
    """
    meta     = result.get("meta", {})
    hosts    = result.get("hosts", [])
    now_str  = meta.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    target   = html.escape(meta.get("target", "N/A"))
    duration = f"{meta.get('scan_duration', 0):.1f}"

    summary_cards = _build_summary_cards(result)
    host_rows     = _build_host_rows(hosts)

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Munin — Network Report</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f172a; color: #e2e8f0;
    min-height: 100vh; padding: 24px;
  }}
  a {{ color: #60a5fa; }}

  .header {{
    display: flex; align-items: center; gap: 16px;
    margin-bottom: 32px;
  }}
  .logo {{
    font-size: 2rem; font-weight: 900; letter-spacing: -.05em;
    background: linear-gradient(135deg, #6366f1, #06b6d4);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }}
  .meta {{ color: #64748b; font-size: .875rem; line-height: 1.8; }}

  .cards {{
    display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px;
  }}
  .card {{
    background: #1e293b; border: 1px solid #334155;
    border-radius: 12px; padding: 20px 28px; min-width: 140px;
    text-align: center;
  }}
  .card-value {{ font-size: 2rem; font-weight: 800; }}
  .card-label {{ color: #94a3b8; font-size: .8rem; margin-top: 4px; }}

  .filters {{
    display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 16px;
    align-items: center;
  }}
  .filters input {{
    background: #1e293b; border: 1px solid #334155;
    color: #e2e8f0; border-radius: 8px; padding: 8px 14px;
    font-size: .9rem; flex: 1; min-width: 200px; outline: none;
  }}
  .filters input:focus {{ border-color: #6366f1; }}
  .filter-btn {{
    background: #1e293b; border: 1px solid #334155;
    color: #e2e8f0; border-radius: 8px; padding: 8px 14px;
    font-size: .85rem; cursor: pointer; transition: .15s;
  }}
  .filter-btn:hover, .filter-btn.active {{
    background: #6366f1; border-color: #6366f1;
  }}

  .table-wrap {{
    overflow-x: auto; border-radius: 12px;
    border: 1px solid #1e293b;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead {{ background: #1e293b; }}
  th {{
    padding: 12px 14px; text-align: left;
    font-size: .8rem; color: #94a3b8; font-weight: 600;
    text-transform: uppercase; letter-spacing: .05em;
    cursor: pointer; user-select: none; white-space: nowrap;
  }}
  th:hover {{ color: #e2e8f0; }}
  .host-row {{ border-bottom: 1px solid #1e293b; transition: background .1s; }}
  .host-row:hover {{ background: #1e293b; }}
  td {{ padding: 12px 14px; font-size: .875rem; vertical-align: middle; }}
  .detail-row td {{ background: #0f172a; }}

  .inner-table {{
    width: 100%; border-collapse: collapse;
    background: #111827; border-radius: 8px;
    overflow: hidden; margin-bottom: 12px;
  }}
  .inner-table th {{
    background: #1f2937; padding: 8px 12px;
    font-size: .75rem; color: #6b7280;
  }}
  .inner-table td {{
    padding: 8px 12px; border-bottom: 1px solid #1f2937;
    font-size: .8rem; vertical-align: top;
  }}

  .footer {{
    margin-top: 40px; text-align: center;
    color: #475569; font-size: .8rem;
  }}

  code {{ font-family: 'Cascadia Code','Fira Mono',monospace; }}
</style>
</head>
<body>

<div class="header">
  <div>
    <div class="logo">Munin</div>
    <div style="color:#64748b;font-size:.8rem;margin-top:2px">
      Network Reconnaissance &amp; Vulnerability Assessment
    </div>
  </div>
  <div class="meta" style="margin-left:auto;text-align:right">
    <div>Target: <strong style="color:#e2e8f0">{target}</strong></div>
    <div>Scanned: {now_str}</div>
    <div>Duration: {duration} seconds</div>
  </div>
</div>

{summary_cards}

<div class="filters">
  <input type="text" id="search-input"
    placeholder="Search IP, hostname, vendor, OS, MAC..."
    oninput="filterTable()">
  <button class="filter-btn" onclick="filterRisk('ALL')">All</button>
  <button class="filter-btn" onclick="filterRisk('CRITICAL')">Critical</button>
  <button class="filter-btn" onclick="filterRisk('HIGH')">High</button>
  <button class="filter-btn" onclick="filterRisk('MEDIUM')">Medium</button>
  <button class="filter-btn" onclick="filterRisk('LOW')">Low</button>
</div>

<div class="table-wrap">
  <table id="hosts-table">
    <thead>
      <tr>
        <th style="width:24px"></th>
        <th onclick="sortTable(1)">IP</th>
        <th>MAC</th>
        <th>Vendor</th>
        <th>Hostname</th>
        <th>OS</th>
        <th onclick="sortTable(6)" style="text-align:center">Ports</th>
        <th onclick="sortTable(7)" style="text-align:center">CVEs</th>
        <th onclick="sortTable(8)" style="text-align:center">Threats</th>
        <th onclick="sortTable(9)">Risk</th>
      </tr>
    </thead>
    <tbody id="hosts-tbody">
      {host_rows}
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by <strong>Munin</strong> &middot;
  For authorized use only &middot;
  {now_str}
</div>

<script>
function toggleRow(id) {{
  const el = document.getElementById(id);
  if (!el) return;
  el.style.display = el.style.display === 'none' ? 'table-row' : 'none';
  const parent = el.previousElementSibling;
  if (parent) {{
    const arrow = parent.querySelector('td:first-child');
    if (arrow) arrow.innerHTML = el.style.display === 'table-row' ? '&#9660;' : '&#9654;';
  }}
}}

let activeRisk = 'ALL';
function filterTable() {{
  const q = document.getElementById('search-input').value.toLowerCase();
  document.querySelectorAll('#hosts-tbody .host-row').forEach(row => {{
    const text        = row.textContent.toLowerCase();
    const risk        = row.dataset.risk || '';
    const matchSearch = !q || text.includes(q);
    const matchRisk   = activeRisk === 'ALL' || risk === activeRisk;
    row.style.display = matchSearch && matchRisk ? '' : 'none';
    const next = row.nextElementSibling;
    if (next && next.classList.contains('detail-row')) {{
      if (!matchSearch || !matchRisk) next.style.display = 'none';
    }}
  }});
}}

function filterRisk(level) {{
  activeRisk = level;
  document.querySelectorAll('.filter-btn').forEach(b => {{
    b.classList.toggle(
      'active',
      b.textContent.trim() === level || (level === 'ALL' && b.textContent.trim() === 'All')
    );
  }});
  filterTable();
}}

let sortDir = 1;
function sortTable(col) {{
  const tbody = document.getElementById('hosts-tbody');
  const rows  = [...tbody.querySelectorAll('.host-row')];
  rows.sort((a, b) => {{
    const av = a.cells[col]?.textContent.trim() || '';
    const bv = b.cells[col]?.textContent.trim() || '';
    const an = parseFloat(av), bn = parseFloat(bv);
    if (!isNaN(an) && !isNaN(bn)) return (an - bn) * sortDir;
    return av.localeCompare(bv) * sortDir;
  }});
  sortDir *= -1;
  rows.forEach(row => {{
    tbody.appendChild(row);
    const detail = document.getElementById(
      row.onclick?.toString()?.match(/'([^']+)'/)?.[1]
    );
    if (detail) tbody.appendChild(detail);
  }});
}}

filterRisk('ALL');
</script>
</body>
</html>"""

    path = Path(output_path)
    path.write_text(html_doc, encoding="utf-8")
    return str(path.resolve())
