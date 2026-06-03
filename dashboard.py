#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

"""
dashboard.py — Flask GRC Dashboard for Munin.

Usage:
    python3 dashboard.py                          # loads last scan JSON
    python3 dashboard.py scans/munin_*.json
    python3 dashboard.py --port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# ── Always run from project directory ────────────────────────────────────────
_PROJECT_DIR = Path(__file__).resolve().parent
os.chdir(_PROJECT_DIR)

# ── Auto-relaunch inside venv if Flask is not found ──────────────────────────
# Handles the case where user runs `python3 dashboard.py` without activating venv.
_VENV_PYTHON = _PROJECT_DIR / ".venv" / "bin" / "python"
try:
    import flask  # noqa: F401 — just checking availability
except ImportError:
    if _VENV_PYTHON.exists() and Path(sys.executable).resolve() != _VENV_PYTHON.resolve():
        print(f"[Munin] Flask not found in current Python. Re-launching with venv...")
        os.execv(str(_VENV_PYTHON), [str(_VENV_PYTHON)] + sys.argv)
    else:
        print("[ERROR] Flask not found. Run: pip install flask  (or: sudo bash setup.sh)")
        sys.exit(1)

import json
import glob
import argparse
from datetime import datetime
from typing import Dict, List, Optional
from flask import Flask, render_template_string, jsonify, abort

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────

_scan_result: Dict = {}
_json_path: str = ""

RISK_COLOR = {
    "CRITICAL": "#ef4444",
    "HIGH":     "#f97316",
    "MEDIUM":   "#eab308",
    "LOW":      "#22c55e",
    "MINIMAL":  "#6b7280",
    "UNKNOWN":  "#9ca3af",
}

RISK_BG = {
    "CRITICAL": "rgba(239,68,68,0.12)",
    "HIGH":     "rgba(249,115,22,0.12)",
    "MEDIUM":   "rgba(234,179,8,0.12)",
    "LOW":      "rgba(34,197,94,0.12)",
    "MINIMAL":  "rgba(107,114,128,0.10)",
    "UNKNOWN":  "rgba(156,163,175,0.10)",
}

# ─────────────────────────────────────────────────────────────────────────────
# SVG logo — Munin raven (inline, no external files needed)
# ─────────────────────────────────────────────────────────────────────────────

RAVEN_IMG = '<img src="assets/Logo.png"

# ─────────────────────────────────────────────────────────────────────────────
# Base HTML template (shared layout)
# ─────────────────────────────────────────────────────────────────────────────

BASE_STYLE = """
<style>
  :root {
    --bg:        #0a0d12;
    --surface:   #111620;
    --surface2:  #161c2a;
    --border:    #1e2a3a;
    --accent:    #3b82f6;
    --accent2:   #60a5fa;
    --text:      #e2e8f0;
    --muted:     #64748b;
    --crit:      #ef4444;
    --high:      #f97316;
    --med:       #eab308;
    --low:       #22c55e;
    --radius:    10px;
    --font:      'Inter', system-ui, sans-serif;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }

  /* ── Nav ── */
  nav {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    padding: 0 2rem;
    height: 60px;
    display: flex;
    align-items: center;
    gap: 1rem;
    position: sticky;
    top: 0;
    z-index: 100;
  }
  .nav-logo {
    display: flex;
    align-items: center;
    gap: .6rem;
    text-decoration: none;
    color: var(--text);
  }
  .nav-logo svg { width: 32px; height: 32px; color: var(--accent2); }
  .nav-title { font-size: 18px; font-weight: 600; letter-spacing: .02em; }
  .nav-sub { font-size: 11px; color: var(--muted); margin-left: .2rem; }
  .nav-right { margin-left: auto; display: flex; align-items: center; gap: 1rem; }
  .nav-badge {
    font-size: 11px;
    padding: 3px 10px;
    border-radius: 20px;
    border: 1px solid var(--border);
    color: var(--muted);
  }

  /* ── Layout ── */
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .page-title { font-size: 22px; font-weight: 600; margin-bottom: .3rem; }
  .page-sub { color: var(--muted); font-size: 13px; margin-bottom: 2rem; }

  /* ── Metric cards ── */
  .metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    gap: 1rem;
    margin-bottom: 2rem;
  }
  .metric-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1.2rem 1.4rem;
  }
  .metric-card .label { font-size: 11px; color: var(--muted); text-transform: uppercase;
                        letter-spacing: .06em; margin-bottom: .4rem; }
  .metric-card .value { font-size: 28px; font-weight: 600; }
  .metric-card .sub { font-size: 11px; color: var(--muted); margin-top: .2rem; }

  /* ── Cards ── */
  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    margin-bottom: 1.2rem;
    overflow: hidden;
  }
  .card-header {
    padding: .9rem 1.2rem;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: .7rem;
    font-weight: 500;
  }
  .card-body { padding: 1.2rem; }

  /* ── Risk badge ── */
  .risk-badge {
    display: inline-flex;
    align-items: center;
    gap: .4rem;
    font-size: 11px;
    font-weight: 600;
    padding: 3px 10px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: .05em;
  }
  .risk-dot { width: 7px; height: 7px; border-radius: 50%; }

  /* ── Host list ── */
  .host-row {
    display: grid;
    grid-template-columns: 160px 90px 60px 1fr auto;
    align-items: center;
    gap: 1rem;
    padding: .8rem 1.2rem;
    border-bottom: 1px solid var(--border);
    transition: background .15s;
    text-decoration: none;
    color: var(--text);
  }
  .host-row:last-child { border-bottom: none; }
  .host-row:hover { background: var(--surface2); }
  .host-ip { font-family: monospace; font-size: 13px; font-weight: 500; }
  .host-hostname { font-size: 12px; color: var(--muted); }
  .score-bar-wrap { flex: 1; }
  .score-bar-bg {
    height: 6px;
    background: var(--border);
    border-radius: 3px;
    overflow: hidden;
  }
  .score-bar-fill { height: 100%; border-radius: 3px; transition: width .4s; }
  .score-num { font-size: 12px; color: var(--muted); white-space: nowrap; }

  /* ── Findings list ── */
  .finding-row {
    display: flex;
    gap: 1rem;
    padding: .7rem 0;
    border-bottom: 1px solid var(--border);
    align-items: flex-start;
  }
  .finding-row:last-child { border-bottom: none; }
  .finding-name { font-weight: 500; font-size: 13px; }
  .finding-detail { font-size: 12px; color: var(--muted); margin-top: 2px; }
  .finding-desc { font-size: 12px; color: var(--muted); margin-top: 4px; line-height: 1.5; }

  /* ── Business report ── */
  .report-section { margin-bottom: 1.4rem; }
  .report-section h3 {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .06em;
    color: var(--accent2);
    margin-bottom: .6rem;
  }
  .report-section p, .report-section li {
    font-size: 13px;
    color: var(--text);
    line-height: 1.7;
  }
  .report-section ul { padding-left: 1.2rem; }
  .report-section ul li { margin-bottom: .3rem; }
  .flag-tag {
    display: inline-block;
    font-size: 11px;
    padding: 2px 9px;
    border-radius: 12px;
    background: rgba(29,78,216,.18);
    color: var(--accent2);
    border: 1px solid rgba(29,78,216,.30);
    margin: 2px 3px;
  }
  .urgency-badge {
    display: inline-block;
    font-size: 12px;
    font-weight: 600;
    padding: 4px 14px;
    border-radius: 20px;
    margin-bottom: 1rem;
  }

  /* ── Port table ── */
  .port-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .port-table th {
    text-align: left;
    padding: 6px 10px;
    color: var(--muted);
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .05em;
    border-bottom: 1px solid var(--border);
  }
  .port-table td {
    padding: 6px 10px;
    border-bottom: 1px solid rgba(30,42,58,.5);
    font-family: monospace;
  }
  .port-table tr:last-child td { border-bottom: none; }
  .port-open { color: #22c55e; }
  .port-closed { color: var(--muted); }

  /* ── Section divider ── */
  .section-divider {
    font-size: 12px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--muted);
    margin: 2rem 0 1rem;
    display: flex;
    align-items: center;
    gap: .8rem;
  }
  .section-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* ── Tabs ── */
  .tabs { display: flex; gap: 4px; margin-bottom: 1.2rem; }
  .tab-btn {
    padding: 6px 16px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: transparent;
    color: var(--muted);
    font-size: 12px;
    cursor: pointer;
    transition: all .15s;
  }
  .tab-btn.active {
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    font-weight: 500;
  }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* ── Back link ── */
  .back-link {
    display: inline-flex;
    align-items: center;
    gap: .4rem;
    color: var(--accent2);
    text-decoration: none;
    font-size: 13px;
    margin-bottom: 1.5rem;
  }
  .back-link:hover { text-decoration: underline; }

  /* ── Donut chart placeholder ── */
  .donut-wrap {
    display: flex;
    align-items: center;
    gap: 2rem;
    padding: 1rem 0;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: .5rem;
    font-size: 13px;
    margin-bottom: .4rem;
  }
  .legend-dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }

  /* ── Responsive ── */
  @media (max-width: 768px) {
    .host-row { grid-template-columns: 1fr 80px; }
    .host-row .score-bar-wrap, .host-row .host-hostname { display: none; }
    .metric-grid { grid-template-columns: repeat(2, 1fr); }
  }
</style>
"""

NAV_HTML = """
<nav>
  <a class="nav-logo" href="/">
    {raven}
    <span class="nav-title">MUNIN</span>
    <span class="nav-sub">GRC Dashboard</span>
  </a>
  <div class="nav-right">
    <span class="nav-badge">v2.0.3</span>
    <span class="nav-badge">{scan_time}</span>
    <span class="nav-badge">{target}</span>
  </div>
</nav>
""".replace("{raven}", RAVEN_IMG)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _risk_badge(level: str, score: int = None) -> str:
    color = RISK_COLOR.get(level, "#9ca3af")
    bg    = RISK_BG.get(level, "rgba(156,163,175,.1)")
    score_str = f" · {score}/100" if score is not None else ""
    return (
        f'<span class="risk-badge" style="background:{bg};color:{color};'
        f'border:1px solid {color}40">'
        f'<span class="risk-dot" style="background:{color}"></span>'
        f'{level}{score_str}</span>'
    )

def _score_bar(score: int, level: str) -> str:
    color = RISK_COLOR.get(level, "#9ca3af")
    return (
        f'<div class="score-bar-bg">'
        f'<div class="score-bar-fill" style="width:{score}%;background:{color}"></div>'
        f'</div>'
    )

def _urgency_badge(label: str) -> str:
    colors = {
        "Immediate":    ("#ef4444", "rgba(239,68,68,.15)"),
        "This week":    ("#f97316", "rgba(249,115,22,.15)"),
        "This quarter": ("#eab308", "rgba(234,179,8,.15)"),
        "Monitor":      ("#22c55e", "rgba(34,197,94,.15)"),
    }
    c, bg = colors.get(label, ("#9ca3af", "rgba(156,163,175,.15)"))
    return (
        f'<span class="urgency-badge" style="color:{c};background:{bg};'
        f'border:1px solid {c}40">{label}</span>'
    )

def _get_meta() -> dict:
    return _scan_result.get("meta", {})

def _get_hosts() -> List[dict]:
    return sorted(
        _scan_result.get("hosts", []),
        key=lambda h: h.get("risk_score", 0),
        reverse=True,
    )

def _find_host(ip: str) -> Optional[dict]:
    for h in _scan_result.get("hosts", []):
        if h.get("ip") == ip:
            return h
    return None

# ─────────────────────────────────────────────────────────────────────────────
# Routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    meta  = _get_meta()
    hosts = _get_hosts()

    total_hosts = len(hosts)
    total_cves  = sum(
        sum(len(p.get("cves", [])) for p in h.get("ports", []))
        for h in hosts
    )
    total_findings = sum(len(h.get("findings", [])) for h in hosts)
    open_ports = sum(
        sum(1 for p in h.get("ports", []) if p.get("state") == "open")
        for h in hosts
    )

    risk_counts: dict = {}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    # ── Metric cards ──────────────────────────────────────────────────────────
    metrics_html = ""
    metrics_data = [
        ("Hosts",         str(total_hosts),    "scanned"),
        ("Open Ports",    str(open_ports),      "total"),
        ("CVEs Found",    str(total_cves),      "across all hosts"),
        ("Threats",       str(total_findings),  "detected"),
    ]
    for label, value, sub in metrics_data:
        metrics_html += f"""
        <div class="metric-card">
          <div class="label">{label}</div>
          <div class="value">{value}</div>
          <div class="sub">{sub}</div>
        </div>"""

    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = risk_counts.get(level, 0)
        if count > 0:
            color = RISK_COLOR[level]
            metrics_html += f"""
            <div class="metric-card" style="border-color:{color}40">
              <div class="label" style="color:{color}">{level}</div>
              <div class="value" style="color:{color}">{count}</div>
              <div class="sub">host{"s" if count > 1 else ""}</div>
            </div>"""

    # ── Host rows ──────────────────────────────────────────────────────────────
    host_rows_html = ""
    for h in hosts:
        ip    = h.get("ip", "?")
        level = h.get("risk_level", "UNKNOWN")
        score = h.get("risk_score", 0)
        hn    = h.get("hostname", "N/A")
        ports_open = sum(1 for p in h.get("ports", []) if p.get("state") == "open")
        badge = _risk_badge(level)
        bar   = _score_bar(score, level)

        # Business report summary if available
        br = h.get("business_report") or {}
        summary_snippet = br.get("executive_summary", "")[:120]
        if summary_snippet:
            summary_snippet = f'<div style="font-size:11px;color:var(--muted);margin-top:3px">{summary_snippet}…</div>'

        host_rows_html += f"""
        <a class="host-row" href="/host/{ip}">
          <div>
            <div class="host-ip">{ip}</div>
            <div class="host-hostname">{hn}</div>
            {summary_snippet}
          </div>
          <div>{badge}</div>
          <div style="font-size:12px;color:var(--muted)">{ports_open} ports</div>
          <div class="score-bar-wrap">{bar}</div>
          <div class="score-num">{score}/100 →</div>
        </a>"""

    # ── Legend for risk distribution ──────────────────────────────────────────
    legend_html = ""
    for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"):
        count = risk_counts.get(level, 0)
        if count:
            color = RISK_COLOR[level]
            pct   = round(count / total_hosts * 100) if total_hosts else 0
            legend_html += f"""
            <div class="legend-item">
              <span class="legend-dot" style="background:{color}"></span>
              <span>{level}</span>
              <span style="color:var(--muted);margin-left:auto">{count} ({pct}%)</span>
            </div>"""

    nav = NAV_HTML.format(
        scan_time=meta.get("scan_time", "N/A"),
        target=meta.get("target", "N/A"),
    )

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Munin GRC Dashboard</title>
  {BASE_STYLE}
</head>
<body>
  {nav}
  <div class="container">
    <div class="page-title">Executive Security Dashboard</div>
    <div class="page-sub">
      Scan completed in {meta.get("scan_duration", 0):.1f}s &nbsp;·&nbsp;
      Profile: {meta.get("scan_profile", "N/A")} &nbsp;·&nbsp;
      {total_hosts} host{"s" if total_hosts != 1 else ""} analysed
    </div>

    <div class="metric-grid">{metrics_html}</div>

    <div style="display:grid;grid-template-columns:1fr 240px;gap:1.2rem;margin-bottom:2rem">
      <div class="card">
        <div class="card-header">
          {RAVEN_SVG.replace('viewBox="0 0 200 200"', 'viewBox="0 0 200 200" style="width:18px;height:18px"')}
          Host Risk Overview
        </div>
        {host_rows_html}
      </div>

      <div class="card">
        <div class="card-header">Risk Distribution</div>
        <div class="card-body">
          <canvas id="donutChart" width="160" height="160" style="display:block;margin:0 auto 1rem"></canvas>
          {legend_html}
        </div>
      </div>
    </div>

    <div style="font-size:11px;color:var(--muted);text-align:center;padding:2rem 0">
      Munin GRC Dashboard · Click any host for the full report · {meta.get("scan_time", "")}
    </div>
  </div>

  <script>
  // Simple donut chart — no external libs
  const data = {json.dumps([
    {"level": l, "count": risk_counts.get(l, 0), "color": RISK_COLOR.get(l, "#9ca3af")}
    for l in ["CRITICAL","HIGH","MEDIUM","LOW","MINIMAL"]
    if risk_counts.get(l, 0) > 0
  ])};
  const total = data.reduce((s,d)=>s+d.count, 0);
  const canvas = document.getElementById("donutChart");
  const ctx = canvas.getContext("2d");
  let angle = -Math.PI/2;
  const cx=80,cy=80,r=60,inner=36;
  data.forEach(d=>{{
    const slice = (d.count/total)*2*Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx,cy);
    ctx.arc(cx,cy,r,angle,angle+slice);
    ctx.closePath();
    ctx.fillStyle=d.color;
    ctx.fill();
    angle+=slice;
  }});
  ctx.beginPath();
  ctx.arc(cx,cy,inner,0,2*Math.PI);
  ctx.fillStyle="#111620";
  ctx.fill();
  ctx.fillStyle="#e2e8f0";
  ctx.font="bold 20px system-ui";
  ctx.textAlign="center";
  ctx.textBaseline="middle";
  ctx.fillText(total,cx,cy-6);
  ctx.font="11px system-ui";
  ctx.fillStyle="#64748b";
  ctx.fillText("hosts",cx,cy+10);
  </script>
</body>
</html>"""
    return html_content


@app.route("/host/<ip>")
def host_detail(ip: str):
    host = _find_host(ip)
    if not host:
        abort(404)

    meta     = _get_meta()
    level    = host.get("risk_level", "UNKNOWN")
    score    = host.get("risk_score", 0)
    findings = host.get("findings", [])
    br       = host.get("business_report") or {}

    nav = NAV_HTML.format(
        scan_time=meta.get("scan_time", "N/A"),
        target=meta.get("target", "N/A"),
    )

    # ── Business report section ───────────────────────────────────────────────
    report_html = ""
    if br:
        urgency    = br.get("urgency_label", "")
        summary    = br.get("executive_summary", "")
        impact     = br.get("business_impact", "")
        flags      = br.get("compliance_flags", [])
        actions    = br.get("priority_actions", [])
        gen_by     = br.get("generated_by", "template")
        model      = br.get("model", "")
        audience   = br.get("audience", "manager")

        flags_html   = "".join(f'<span class="flag-tag">{f}</span>' for f in flags)
        actions_html = "".join(f"<li>{a}</li>" for a in actions)
        model_str    = f" / {model}" if model and model != "none" else ""

        report_html = f"""
        <div class="card">
          <div class="card-header" style="justify-content:space-between">
            <span>📋 GRC Business Report</span>
            <span style="font-size:11px;color:var(--muted)">
              {gen_by}{model_str} · audience: {audience}
            </span>
          </div>
          <div class="card-body">
            {_urgency_badge(urgency)}
            <div class="report-section">
              <h3>Executive Summary</h3>
              <p>{summary}</p>
            </div>
            <div class="report-section">
              <h3>Business Impact</h3>
              <p>{impact}</p>
            </div>
            {"<div class='report-section'><h3>Compliance Flags</h3><div>" + flags_html + "</div></div>" if flags else ""}
            {"<div class='report-section'><h3>Priority Actions</h3><ul>" + actions_html + "</ul></div>" if actions else ""}
          </div>
        </div>"""
    else:
        report_html = """
        <div class="card">
          <div class="card-body" style="color:var(--muted);font-size:13px">
            No business report available for this host.
            Run a scan with Ollama enabled to generate GRC reports.
          </div>
        </div>"""

    # ── Findings ──────────────────────────────────────────────────────────────
    findings_html = ""
    if findings:
        sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_f = sorted(findings, key=lambda f: sev_weight.get(f.get("severity","LOW"), 0), reverse=True)
        for f in sorted_f:
            sev   = f.get("severity", "?")
            color = RISK_COLOR.get(sev, "#9ca3af")
            bg    = RISK_BG.get(sev, "rgba(156,163,175,.08)")
            name  = f.get("name", "")
            detail= f.get("detail", "")
            desc  = f.get("description", "")
            rem   = f.get("remediation", [])
            rem_html = "".join(f"<li>{r}</li>" for r in rem[:4])

            findings_html += f"""
            <div class="finding-row" style="background:{bg};padding:.8rem 1rem;border-radius:8px;margin-bottom:.6rem;border:none">
              <div style="flex:0 0 auto">{_risk_badge(sev)}</div>
              <div style="flex:1">
                <div class="finding-name">{name}</div>
                {"<div class='finding-detail'>" + detail + "</div>" if detail else ""}
                {"<div class='finding-desc'>" + desc + "</div>" if desc else ""}
                {"<ul style='font-size:12px;color:var(--muted);margin-top:.5rem;padding-left:1.2rem'>" + rem_html + "</ul>" if rem else ""}
              </div>
            </div>"""
    else:
        findings_html = "<p style='color:var(--muted);font-size:13px'>No threats detected.</p>"

    # ── Ports table ───────────────────────────────────────────────────────────
    ports_html = ""
    for p in host.get("ports", []):
        state = p.get("state", "")
        sc    = "port-open" if state == "open" else "port-closed"
        cves  = p.get("cves", [])
        cve_str = (
            f'<span style="color:var(--crit);font-size:11px">{len(cves)} CVE{"s" if len(cves)>1 else ""}</span>'
            if cves else '<span style="color:var(--muted)">—</span>'
        )
        pv = " ".join(filter(None, [p.get("product",""), p.get("version","")]))
        ports_html += f"""
        <tr>
          <td class="{sc}">{p["port"]}/{p.get("protocol","tcp")}</td>
          <td class="{sc}">{state}</td>
          <td>{p.get("service","")}</td>
          <td style="color:var(--muted)">{pv or "—"}</td>
          <td>{cve_str}</td>
        </tr>"""

    os_info = host.get("os", {})
    os_str  = os_info.get("name","Unknown")
    acc     = os_info.get("accuracy", 0)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Munin · {ip}</title>
  {BASE_STYLE}
</head>
<body>
  {nav}
  <div class="container">
    <a class="back-link" href="/">← Back to Dashboard</a>

    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:.4rem">
      <div class="page-title" style="font-family:monospace">{ip}</div>
      {_risk_badge(level, score)}
    </div>
    <div class="page-sub">
      {host.get("hostname","N/A")} &nbsp;·&nbsp;
      OS: {os_str} {"(" + str(acc) + "% confidence)" if acc else ""} &nbsp;·&nbsp;
      MAC: {host.get("mac","N/A")} ({host.get("mac_vendor","Unknown")})
    </div>

    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab('report')">GRC Report</button>
      <button class="tab-btn" onclick="switchTab('threats')">Threats ({len(findings)})</button>
      <button class="tab-btn" onclick="switchTab('ports')">Ports ({len(host.get("ports",[]))})</button>
    </div>

    <div id="tab-report" class="tab-panel active">
      {report_html}
    </div>

    <div id="tab-threats" class="tab-panel">
      <div class="card">
        <div class="card-header">Detected Threats &amp; Anomalies</div>
        <div class="card-body">{findings_html}</div>
      </div>
    </div>

    <div id="tab-ports" class="tab-panel">
      <div class="card">
        <div class="card-header">Open Ports &amp; Services</div>
        <div class="card-body">
          <table class="port-table">
            <thead>
              <tr>
                <th>Port</th><th>State</th><th>Service</th><th>Version</th><th>CVEs</th>
              </tr>
            </thead>
            <tbody>{ports_html}</tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
  function switchTab(name) {{
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
    document.getElementById("tab-" + name).classList.add("active");
    event.target.classList.add("active");
  }}
  </script>
</body>
</html>"""
    return html_content


# ─────────────────────────────────────────────────────────────────────────────
# JSON API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/summary")
def api_summary():
    hosts = _get_hosts()
    risk_counts = {}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1
    return jsonify({
        "meta":        _get_meta(),
        "total_hosts": len(hosts),
        "risk_counts": risk_counts,
        "total_cves":  sum(sum(len(p.get("cves",[])) for p in h.get("ports",[])) for h in hosts),
        "total_findings": sum(len(h.get("findings",[])) for h in hosts),
    })


@app.route("/api/hosts")
def api_hosts():
    hosts = _get_hosts()
    return jsonify([{
        "ip":         h.get("ip"),
        "hostname":   h.get("hostname"),
        "risk_level": h.get("risk_level"),
        "risk_score": h.get("risk_score"),
        "findings":   len(h.get("findings", [])),
        "ports":      sum(1 for p in h.get("ports",[]) if p.get("state")=="open"),
    } for h in hosts])


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

def _load_result(path: str) -> None:
    global _scan_result, _json_path
    _json_path = path
    _scan_result = json.loads(Path(path).read_text(encoding="utf-8"))
    print(f"[Munin] Loaded: {path}  ({len(_scan_result.get('hosts',[]))} hosts)")


def _find_latest_json() -> Optional[str]:
    """Search for the most recent scan JSON in scans/ and current directory."""
    candidates = sorted(
        glob.glob("scans/munin_*.json") + glob.glob("munin_*.json"),
        reverse=True,
    )
    return candidates[0] if candidates else None


def main():
    parser = argparse.ArgumentParser(description="Munin GRC Dashboard")
    parser.add_argument("json_file", nargs="?", help="Path to Munin JSON result")
    parser.add_argument("--port", type=int, default=5000, help="Port (default: 5000)")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host")
    parser.add_argument("--debug", action="store_true", help="Flask debug mode")
    args = parser.parse_args()

    json_path = args.json_file or _find_latest_json()
    if not json_path:
        print("[ERROR] No scan JSON found.")
        print("        Run a scan first:  sudo bash run_cli.sh")
        print("        Or pass the file:  python3 dashboard.py scans/munin_20260529_*.json")
        sys.exit(1)

    if not Path(json_path).exists():
        print(f"[ERROR] File not found: {json_path}")
        # Show available scans to help the user
        available = sorted(glob.glob("scans/munin_*.json"), reverse=True)[:5]
        if available:
            print("  Available scans:")
            for f in available:
                print(f"    {f}")
        sys.exit(1)

    _load_result(json_path)

    print(f"[Munin] Dashboard at http://{args.host}:{args.port}")
    print(f"[Munin] Open in browser: xdg-open http://localhost:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
