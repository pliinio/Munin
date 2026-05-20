#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
pdf_report.py — Executive PDF Report Generator for Munin.

Generates a professional PDF report suitable for:
  - Directors / C-Suite (board audience)
  - ISO 27001 auditors
  - IT managers

Uses WeasyPrint (HTML→PDF) for professional output.
Falls back to an HTML file if WeasyPrint is not available.

Public API:
  generate_pdf(scan_result, output_path, audience) -> Path
  generate_html_report(scan_result, audience) -> str   (raw HTML)
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# Color palette (mirrors dashboard)
# ─────────────────────────────────────────────────────────────────────────────

_RISK_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "MINIMAL":  "#6b7280",
    "UNKNOWN":  "#9ca3af",
}

_LGPD_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
}


# ─────────────────────────────────────────────────────────────────────────────
# CSS (dark professional theme, print-friendly)
# ─────────────────────────────────────────────────────────────────────────────

_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

@page {
  size: A4;
  margin: 1.8cm 1.5cm;
  @bottom-center {
    content: "Munin Cyber Risk Report — CONFIDENTIAL — Page " counter(page) " of " counter(pages);
    font-size: 9px; color: #64748b; font-family: Inter, sans-serif;
  }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: Inter, system-ui, sans-serif;
  font-size: 10pt;
  line-height: 1.5;
  color: #1e293b;
  background: #fff;
}

/* Cover page */
.cover {
  height: 100vh;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 3cm;
  background: #0a0d12;
  color: #e2e8f0;
  page-break-after: always;
}
.cover-logo { font-size: 48pt; font-weight: 700; color: #3b82f6; margin-bottom: .3rem; }
.cover-subtitle { font-size: 14pt; color: #64748b; margin-bottom: 3rem; }
.cover-title { font-size: 22pt; font-weight: 600; margin-bottom: .5rem; color: #f1f5f9; }
.cover-meta { font-size: 10pt; color: #64748b; margin-top: 2rem; line-height: 2; }
.cover-confidential {
  margin-top: 3rem;
  font-size: 9pt;
  color: #ef4444;
  border: 1px solid #ef4444;
  display: inline-block;
  padding: .3rem 1rem;
  letter-spacing: .1em;
  text-transform: uppercase;
}

/* Section headings */
h1 { font-size: 16pt; font-weight: 600; color: #0f172a;
     border-bottom: 2px solid #3b82f6; padding-bottom: .4rem;
     margin-top: 1.5rem; margin-bottom: 1rem; }
h2 { font-size: 13pt; font-weight: 600; color: #1e293b;
     margin-top: 1.2rem; margin-bottom: .7rem; }
h3 { font-size: 11pt; font-weight: 600; color: #334155;
     margin-top: .9rem; margin-bottom: .4rem; }
p  { margin-bottom: .6rem; }

/* Metric grid */
.metric-grid {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: .8rem;
  margin: 1rem 0;
}
.metric-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: .9rem 1rem;
  text-align: center;
}
.metric-label { font-size: 8pt; color: #64748b; text-transform: uppercase;
                letter-spacing: .08em; margin-bottom: .3rem; }
.metric-value { font-size: 22pt; font-weight: 700; }
.metric-sub   { font-size: 8pt; color: #94a3b8; margin-top: .2rem; }

/* Risk badge */
.badge {
  display: inline-block;
  font-size: 8pt; font-weight: 600;
  padding: 2px 8px;
  border-radius: 12px;
  text-transform: uppercase;
  letter-spacing: .05em;
  color: #fff;
}

/* Compliance grid */
.compliance-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: .8rem;
  margin: 1rem 0;
}
.compliance-card {
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: .9rem 1rem;
  text-align: center;
}
.compliance-score { font-size: 24pt; font-weight: 700; margin: .3rem 0; }
.compliance-label { font-size: 8pt; color: #64748b; text-transform: uppercase; letter-spacing: .06em; }

/* Progress bar */
.progress-wrap { background: #f1f5f9; border-radius: 4px;
                 height: 8px; overflow: hidden; margin: .3rem 0 .6rem; }
.progress-fill { height: 100%; border-radius: 4px; }

/* Host table */
table { width: 100%; border-collapse: collapse; margin: .8rem 0; font-size: 9.5pt; }
th { background: #f8fafc; font-weight: 600; text-align: left;
     padding: .5rem .7rem; border-bottom: 1.5px solid #e2e8f0;
     font-size: 8.5pt; text-transform: uppercase; letter-spacing: .06em; }
td { padding: .45rem .7rem; border-bottom: 1px solid #f1f5f9; }
tr:last-child td { border-bottom: none; }

/* Finding cards */
.finding-card {
  border-left: 3px solid #e2e8f0;
  padding: .6rem .9rem;
  margin-bottom: .6rem;
  background: #f8fafc;
  border-radius: 0 6px 6px 0;
}
.finding-name { font-weight: 600; font-size: 10pt; margin-bottom: .2rem; }
.finding-detail { font-size: 9pt; color: #64748b; }

/* Action list */
.action-list { list-style: none; padding: 0; }
.action-list li {
  display: flex; gap: .6rem; align-items: flex-start;
  padding: .4rem 0;
  border-bottom: 1px solid #f1f5f9;
  font-size: 9.5pt;
}
.action-list li:last-child { border-bottom: none; }
.action-num {
  min-width: 20px; height: 20px;
  background: #3b82f6; color: #fff;
  border-radius: 50%;
  font-size: 8pt; font-weight: 600;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0; margin-top: 1px;
}

/* Page break helpers */
.page-break { page-break-before: always; }
.no-break    { page-break-inside: avoid; }

/* Footer / note */
.note { font-size: 8.5pt; color: #94a3b8; font-style: italic; margin-top: .4rem; }
"""


# ─────────────────────────────────────────────────────────────────────────────
# HTML builder helpers
# ─────────────────────────────────────────────────────────────────────────────

def _badge(level: str, text: str | None = None) -> str:
    color = _RISK_COLOR.get(level, "#9ca3af")
    label = text or level
    return f'<span class="badge" style="background:{color}">{label}</span>'


def _progress(pct: float, color: str = "#3b82f6") -> str:
    w = max(0, min(100, pct))
    return (
        f'<div class="progress-wrap">'
        f'<div class="progress-fill" style="width:{w}%;background:{color}"></div>'
        f'</div>'
    )


def _score_color(score: float) -> str:
    if score >= 80: return "#22c55e"
    if score >= 60: return "#eab308"
    if score >= 35: return "#f97316"
    return "#ef4444"


# ─────────────────────────────────────────────────────────────────────────────
# Section builders
# ─────────────────────────────────────────────────────────────────────────────

def _cover(meta: Dict, hosts: List[Dict], audience: str) -> str:
    scan_time = meta.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M"))
    target    = meta.get("target", "Network")
    audience_label = {"manager": "IT Management", "auditor": "Audit & Compliance", "board": "Board of Directors"}.get(audience, "Management")
    n_critical = sum(1 for h in hosts if h.get("risk_level") == "CRITICAL")
    n_high     = sum(1 for h in hosts if h.get("risk_level") == "HIGH")

    return f"""
<div class="cover">
  <div class="cover-logo">Munin</div>
  <div class="cover-subtitle">Cyber Risk Intelligence Platform</div>
  <div class="cover-title">Network Security Assessment Report</div>
  <div class="cover-meta">
    Target Network: <strong>{target}</strong><br>
    Scan Date: <strong>{scan_time}</strong><br>
    Duration: <strong>{meta.get('scan_duration', 0):.0f} seconds</strong><br>
    Audience: <strong>{audience_label}</strong><br>
    Hosts Scanned: <strong>{len(hosts)}</strong><br>
    Critical/High Risk Hosts: <strong style="color:#ef4444">{n_critical + n_high}</strong>
  </div>
  <div class="cover-confidential">Confidential — Internal Use Only</div>
</div>"""


def _executive_summary(hosts: List[Dict], env_compliance: Optional[Dict]) -> str:
    total      = len(hosts)
    n_critical = sum(1 for h in hosts if h.get("risk_level") == "CRITICAL")
    n_high     = sum(1 for h in hosts if h.get("risk_level") == "HIGH")
    n_medium   = sum(1 for h in hosts if h.get("risk_level") == "MEDIUM")
    n_low      = sum(1 for h in hosts if h.get("risk_level") in ("LOW", "MINIMAL"))
    total_cves = sum(sum(len(p.get("cves", [])) for p in h.get("ports", [])) for h in hosts)
    total_findings = sum(len(h.get("findings", [])) for h in hosts)
    avg_score  = sum(h.get("risk_score", 0) for h in hosts) / max(total, 1)

    iso_s   = env_compliance.get("iso27001_avg", 100) if env_compliance else 100
    nist_s  = env_compliance.get("nist_avg", 100) if env_compliance else 100
    lgpd    = env_compliance.get("lgpd_exposure", "LOW") if env_compliance else "LOW"
    lgpd_c  = _LGPD_COLOR.get(lgpd, "#22c55e")

    metrics_html = f"""
<div class="metric-grid">
  <div class="metric-card">
    <div class="metric-label">Total Hosts</div>
    <div class="metric-value" style="color:#3b82f6">{total}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Critical / High</div>
    <div class="metric-value" style="color:#ef4444">{n_critical + n_high}</div>
    <div class="metric-sub">{n_critical} critical · {n_high} high</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">CVEs Found</div>
    <div class="metric-value" style="color:#f97316">{total_cves}</div>
  </div>
  <div class="metric-card">
    <div class="metric-label">Avg Risk Score</div>
    <div class="metric-value" style="color:{_score_color(100 - avg_score)}">{avg_score:.0f}/100</div>
  </div>
</div>"""

    compliance_html = f"""
<div class="compliance-grid">
  <div class="compliance-card">
    <div class="compliance-label">ISO 27001:2022</div>
    <div class="compliance-score" style="color:{_score_color(iso_s)}">{iso_s:.0f}%</div>
    {_progress(iso_s, _score_color(iso_s))}
    <div class="metric-sub">Compliance posture</div>
  </div>
  <div class="compliance-card">
    <div class="compliance-label">NIST CSF 2.0</div>
    <div class="compliance-score" style="color:{_score_color(nist_s)}">{nist_s:.0f}%</div>
    {_progress(nist_s, _score_color(nist_s))}
    <div class="metric-sub">Framework score</div>
  </div>
  <div class="compliance-card">
    <div class="compliance-label">LGPD Exposure</div>
    <div class="compliance-score" style="color:{lgpd_c}">{lgpd}</div>
    <div class="metric-sub">Data protection risk</div>
  </div>
</div>"""

    return f"""
<h1>Executive Summary</h1>
{metrics_html}

<h2>Compliance Posture</h2>
{compliance_html}

<h2>Risk Distribution</h2>
<table>
  <thead><tr><th>Risk Level</th><th>Hosts</th><th>% of Environment</th></tr></thead>
  <tbody>
    <tr><td>{_badge('CRITICAL')} Critical</td><td>{n_critical}</td><td>{n_critical/max(total,1)*100:.0f}%</td></tr>
    <tr><td>{_badge('HIGH')} High</td><td>{n_high}</td><td>{n_high/max(total,1)*100:.0f}%</td></tr>
    <tr><td>{_badge('MEDIUM')} Medium</td><td>{n_medium}</td><td>{n_medium/max(total,1)*100:.0f}%</td></tr>
    <tr><td>{_badge('LOW')} Low / Minimal</td><td>{n_low}</td><td>{n_low/max(total,1)*100:.0f}%</td></tr>
  </tbody>
</table>
<p class="note">Total unique threats detected: {total_findings} across {total} hosts.</p>"""


def _host_section(host: Dict) -> str:
    ip       = host.get("ip", "?")
    hostname = host.get("hostname", "N/A")
    level    = host.get("risk_level", "UNKNOWN")
    score    = host.get("risk_score", 0)
    ports    = host.get("ports", [])
    findings = host.get("findings", [])
    os_info  = host.get("os", {})
    br       = host.get("business_report")

    color = _RISK_COLOR.get(level, "#9ca3af")

    # Business report block
    report_html = ""
    if br and isinstance(br, dict):
        summary = br.get("executive_summary", "")
        impact  = br.get("business_impact", "")
        flags   = br.get("compliance_flags", [])
        actions = br.get("priority_actions", [])
        urgency = br.get("urgency_label", "")

        flags_html   = " · ".join(f'<span class="badge" style="background:#1e40af;font-size:7.5pt">{f}</span>' for f in flags[:4])
        actions_html = "".join(
            f'<li><div class="action-num">{i+1}</div><div>{a}</div></li>'
            for i, a in enumerate(actions[:5])
        )
        report_html = f"""
<h3>Business Impact</h3>
<p>{summary}</p>
<p>{impact}</p>
{"<p>" + flags_html + "</p>" if flags else ""}
<h3>Priority Actions</h3>
<ul class="action-list">{actions_html}</ul>"""

    # Findings
    sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_f   = sorted(findings, key=lambda f: sev_weight.get(f.get("severity","LOW"), 0), reverse=True)
    findings_html = ""
    for f in sorted_f[:6]:
        sev    = f.get("severity", "?")
        fc     = _RISK_COLOR.get(sev, "#9ca3af")
        findings_html += f"""
<div class="finding-card" style="border-left-color:{fc}">
  <div class="finding-name">{_badge(sev)} {f.get('name','')}</div>
  <div class="finding-detail">{f.get('detail','')}</div>
</div>"""

    # Ports summary
    open_ports = [p for p in ports if p.get("state") == "open"]
    ports_rows = ""
    for p in open_ports[:10]:
        cve_n   = len(p.get("cves", []))
        cve_str = f'<span style="color:#ef4444">{cve_n} CVE{"s" if cve_n>1 else ""}</span>' if cve_n else "—"
        pv = " ".join(filter(None, [p.get("product",""), p.get("version","")])) or "—"
        ports_rows += f"<tr><td>{p['port']}/{p.get('protocol','tcp')}</td><td>{p.get('service','')}</td><td>{pv}</td><td>{cve_str}</td></tr>"

    return f"""
<div class="no-break">
<h2 style="border-left:4px solid {color};padding-left:.6rem;margin-top:1.4rem">
  {ip} &nbsp; {_badge(level, f'{level} {score}/100')}
  <span style="font-size:9pt;font-weight:400;color:#64748b;margin-left:.5rem">
    {hostname} · OS: {os_info.get('name','Unknown')} · MAC: {host.get('mac','N/A')}
  </span>
</h2>

{report_html}

{"<h3>Detected Threats</h3>" + findings_html if findings_html else ""}

{f'''<h3>Open Ports ({len(open_ports)})</h3>
<table>
  <thead><tr><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th></tr></thead>
  <tbody>{ports_rows}</tbody>
</table>''' if ports_rows else ""}
</div>"""


def _remediation_section(hosts: List[Dict]) -> str:
    """Global prioritized remediation list across all hosts."""
    # Collect all findings, sorted by severity
    sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    all_steps: List[tuple] = []   # (weight, ip, step)

    for host in hosts:
        ip = host.get("ip", "?")
        for f in host.get("findings", []):
            w = sev_weight.get(f.get("severity","LOW"), 0)
            for step in f.get("remediation", [])[:2]:
                all_steps.append((w, ip, step))

    all_steps.sort(key=lambda x: -x[0])

    seen: set = set()
    unique: List[tuple] = []
    for w, ip, step in all_steps:
        key = step.lower().strip()
        if key not in seen:
            seen.add(key)
            unique.append((w, ip, step))

    items_html = ""
    for i, (w, ip, step) in enumerate(unique[:15], 1):
        sev_label = {4:"CRITICAL",3:"HIGH",2:"MEDIUM",1:"LOW"}.get(w,"LOW")
        items_html += f"""
<li>
  <div class="action-num">{i}</div>
  <div>
    {_badge(sev_label)} &nbsp; <strong>[{ip}]</strong> {step}
  </div>
</li>"""

    return f"""
<div class="page-break"></div>
<h1>Remediation Roadmap</h1>
<p>The following actions are ordered by severity and exploitability.
   Address Immediate and High priority items before moving to Medium and Planned.</p>
<ul class="action-list">{items_html}</ul>
<p class="note">Full remediation details are available in the technical scan output.</p>"""


# ─────────────────────────────────────────────────────────────────────────────
# Main HTML assembler
# ─────────────────────────────────────────────────────────────────────────────

def generate_html_report(
    scan_result: Dict,
    audience:    str = "manager",
    env_compliance: Optional[Dict] = None,
) -> str:
    """
    Build the full HTML string for the PDF report.

    Args:
        scan_result:     dict as saved by Munin CLI
        audience:        "manager" | "auditor" | "board"
        env_compliance:  result of environment_compliance_score() (optional)

    Returns:
        HTML string
    """
    meta  = scan_result.get("meta", {})
    hosts = sorted(
        scan_result.get("hosts", []),
        key=lambda h: h.get("risk_score", 0),
        reverse=True,
    )

    cover_html   = _cover(meta, hosts, audience)
    exec_html    = _executive_summary(hosts, env_compliance)
    hosts_html   = "".join(_host_section(h) for h in hosts if h.get("risk_level") in ("CRITICAL","HIGH","MEDIUM"))
    remed_html   = _remediation_section(hosts)

    # Low-risk hosts as compact table
    low_hosts = [h for h in hosts if h.get("risk_level") in ("LOW","MINIMAL","UNKNOWN")]
    low_rows  = ""
    for h in low_hosts:
        low_rows += f"<tr><td style='font-family:monospace'>{h.get('ip','?')}</td><td>{h.get('hostname','N/A')}</td><td>{_badge(h.get('risk_level','UNKNOWN'))}</td><td>{h.get('risk_score',0)}/100</td></tr>"
    low_section = f"""
<div class="page-break"></div>
<h1>Low-Risk Hosts</h1>
<p>The following hosts showed no significant findings in this scan cycle.</p>
<table>
  <thead><tr><th>IP Address</th><th>Hostname</th><th>Risk Level</th><th>Score</th></tr></thead>
  <tbody>{low_rows}</tbody>
</table>""" if low_rows else ""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Munin Security Report — {meta.get('target', 'Network')}</title>
  <style>{_CSS}</style>
</head>
<body>
  {cover_html}

  <div class="page-break"></div>
  {exec_html}

  <div class="page-break"></div>
  <h1>Host Risk Analysis</h1>
  <p>Detailed analysis for hosts rated Medium risk and above.</p>
  {hosts_html}

  {low_section}
  {remed_html}

  <div class="page-break"></div>
  <h1>Appendix — Scan Metadata</h1>
  <table>
    <tr><td><strong>Target</strong></td><td>{meta.get('target','N/A')}</td></tr>
    <tr><td><strong>Scan started</strong></td><td>{meta.get('scan_time','N/A')}</td></tr>
    <tr><td><strong>Duration</strong></td><td>{meta.get('scan_duration',0):.0f} seconds</td></tr>
    <tr><td><strong>Total hosts</strong></td><td>{len(hosts)}</td></tr>
    <tr><td><strong>Report audience</strong></td><td>{audience}</td></tr>
    <tr><td><strong>Report generated</strong></td><td>{generated_at}</td></tr>
  </table>
  <p class="note">
    This report was generated automatically by Munin v2.
    All findings should be verified by a qualified security professional before action is taken.
    Munin is licensed under AGPL-3.0. Use only on networks you own or have explicit permission to audit.
  </p>
</body>
</html>"""

    return html


# ─────────────────────────────────────────────────────────────────────────────
# PDF generation
# ─────────────────────────────────────────────────────────────────────────────

def generate_pdf(
    scan_result:    Dict,
    output_path:    Optional[str] = None,
    audience:       str           = "manager",
    env_compliance: Optional[Dict]= None,
) -> Path:
    """
    Generate a PDF report from a Munin scan result.

    Args:
        scan_result:    Munin scan dict (from JSON file or in-memory)
        output_path:    output file path (auto-generated if None)
        audience:       "manager" | "auditor" | "board"
        env_compliance: compliance posture from environment_compliance_score()

    Returns:
        Path to the generated file (PDF or HTML fallback)

    Raises:
        ImportError: if WeasyPrint is not installed AND html fallback is disabled
    """
    from pathlib import Path as P

    html = generate_html_report(scan_result, audience, env_compliance)

    if output_path is None:
        ts     = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"reports/munin_report_{ts}.pdf"

    out = P(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Try WeasyPrint first
    try:
        from weasyprint import HTML as WP_HTML
        WP_HTML(string=html, base_url=".").write_pdf(str(out))
        print(f"[Munin] PDF report saved: {out}")
        return out

    except ImportError:
        # Fallback: save as HTML
        html_path = out.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        print(
            f"[Munin] WeasyPrint not installed — HTML report saved: {html_path}\n"
            f"        Install WeasyPrint: pip install weasyprint"
        )
        return html_path

    except Exception as exc:
        # Fallback on any WeasyPrint error
        html_path = out.with_suffix(".html")
        html_path.write_text(html, encoding="utf-8")
        print(f"[Munin] PDF generation failed ({exc}) — HTML saved: {html_path}")
        return html_path
