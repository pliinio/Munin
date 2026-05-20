#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
dashboard.py v2 — Flask GRC Dashboard for Munin.

New in v2:
  - Authentication (login/logout, session timeout, IP allowlist)
  - Compliance scores (ISO 27001, NIST CSF, LGPD) on every page
  - Trend analysis with historical charts
  - Audience switcher (manager / auditor / board) without re-scanning
  - PDF report download
  - RBAC-ready structure

Usage:
    python3 dashboard.py
    python3 dashboard.py munin_20260506_120000.json
    python3 dashboard.py --port 8080 --host 0.0.0.0
"""

from __future__ import annotations

import json
import sys
import glob
import argparse
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

from flask import (
    Flask, jsonify, redirect, url_for,
    request, session, abort, Response,
)
from flask import render_template_string

from auth import (
    init_auth, login_required, login_session, logout_session,
    verify_credentials, is_authenticated, LOGIN_HTML,
)

app = Flask(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────

_scan_result: Dict = {}
_json_path:   str  = ""
_lock = threading.Lock()

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

RAVEN_SVG = """<svg viewBox="0 0 200 200" xmlns="http://www.w3.org/2000/svg" fill="currentColor">
  <path d="M100 15 C75 15 55 30 50 55 C45 75 52 88 45 100 C38 112 20 115 18 130
           C16 145 28 158 42 162 C35 170 30 178 35 185 C40 192 55 190 65 183
           C72 178 80 172 90 170 C95 180 98 190 105 193 C112 196 118 188 115 178
           C122 182 130 185 136 180 C142 175 140 165 134 160
           C148 155 160 142 158 128 C156 114 142 108 140 95
           C138 82 145 70 142 55 C138 35 120 15 100 15Z
           M85 65 C88 62 93 63 95 67 C97 71 94 75 90 74 C86 73 83 68 85 65Z
           M60 130 C65 120 78 118 85 125 C80 128 72 130 65 135 C62 133 59 133 60 130Z
           M95 140 C100 132 112 130 118 138 C112 140 104 140 97 145 C94 143 93 142 95 140Z"/>
</svg>"""

# ─────────────────────────────────────────────────────────────────────────────
# Shared CSS
# ─────────────────────────────────────────────────────────────────────────────

BASE_STYLE = """<style>
:root{--bg:#0a0d12;--surface:#111620;--surface2:#161c2a;--border:#1e2a3a;
      --accent:#3b82f6;--accent2:#60a5fa;--text:#e2e8f0;--muted:#64748b;
      --crit:#ef4444;--high:#f97316;--med:#eab308;--low:#22c55e;
      --radius:10px;--font:'Inter',system-ui,sans-serif;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;min-height:100vh;}
nav{background:var(--surface);border-bottom:1px solid var(--border);padding:0 2rem;height:60px;
    display:flex;align-items:center;gap:1rem;position:sticky;top:0;z-index:100;}
.nav-logo{display:flex;align-items:center;gap:.6rem;text-decoration:none;color:var(--text);}
.nav-logo svg{width:32px;height:32px;color:var(--accent2);}
.nav-title{font-size:18px;font-weight:600;letter-spacing:.02em;}
.nav-sub{font-size:11px;color:var(--muted);}
.nav-right{margin-left:auto;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap;}
.nav-badge{font-size:11px;padding:3px 10px;border-radius:20px;border:1px solid var(--border);color:var(--muted);}
.nav-user{font-size:12px;color:var(--accent2);font-weight:500;}
.btn-logout{font-size:11px;padding:4px 12px;border-radius:6px;border:1px solid var(--border);
            background:transparent;color:var(--muted);cursor:pointer;text-decoration:none;}
.btn-logout:hover{border-color:var(--crit);color:var(--crit);}
.container{max-width:1280px;margin:0 auto;padding:2rem;}
.page-title{font-size:22px;font-weight:600;margin-bottom:.3rem;}
.page-sub{color:var(--muted);font-size:13px;margin-bottom:2rem;}
.metric-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:1rem;margin-bottom:1.5rem;}
.metric-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.2rem 1.4rem;}
.metric-card .label{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em;margin-bottom:.4rem;}
.metric-card .value{font-size:28px;font-weight:600;}
.metric-card .sub{font-size:11px;color:var(--muted);margin-top:.2rem;}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:1.2rem;overflow:hidden;}
.card-header{padding:.9rem 1.2rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.7rem;font-weight:500;}
.card-body{padding:1.2rem;}
.compliance-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:1rem;margin-bottom:1.5rem;}
.compliance-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:1.2rem;text-align:center;}
.compliance-score{font-size:32px;font-weight:700;margin:.4rem 0;}
.compliance-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.07em;}
.progress-wrap{background:var(--border);border-radius:3px;height:6px;overflow:hidden;margin:.5rem 0;}
.progress-fill{height:100%;border-radius:3px;}
.risk-badge{display:inline-flex;align-items:center;gap:.4rem;font-size:11px;font-weight:600;
            padding:3px 10px;border-radius:20px;text-transform:uppercase;letter-spacing:.05em;}
.risk-dot{width:7px;height:7px;border-radius:50%;}
.host-row{display:grid;grid-template-columns:160px 90px 60px 1fr auto;align-items:center;
          gap:1rem;padding:.8rem 1.2rem;border-bottom:1px solid var(--border);
          transition:background .15s;text-decoration:none;color:var(--text);}
.host-row:last-child{border-bottom:none;}
.host-row:hover{background:var(--surface2);}
.host-ip{font-family:monospace;font-size:13px;font-weight:500;}
.score-bar-bg{height:6px;background:var(--border);border-radius:3px;overflow:hidden;}
.score-bar-fill{height:100%;border-radius:3px;}
.finding-row{display:flex;gap:1rem;padding:.7rem 0;border-bottom:1px solid var(--border);align-items:flex-start;}
.finding-row:last-child{border-bottom:none;}
.finding-name{font-weight:500;font-size:13px;}
.finding-detail{font-size:12px;color:var(--muted);margin-top:2px;}
.finding-desc{font-size:12px;color:var(--muted);margin-top:4px;line-height:1.5;}
.report-section{margin-bottom:1.4rem;}
.report-section h3{font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--accent2);margin-bottom:.6rem;}
.report-section p,.report-section li{font-size:13px;color:var(--text);line-height:1.7;}
.report-section ul{padding-left:1.2rem;}
.flag-tag{display:inline-block;font-size:11px;padding:2px 9px;border-radius:12px;
          background:rgba(59,130,246,.15);color:var(--accent2);border:1px solid rgba(59,130,246,.25);margin:2px 3px;}
.urgency-badge{display:inline-block;font-size:12px;font-weight:600;padding:4px 14px;border-radius:20px;margin-bottom:1rem;}
.port-table{width:100%;border-collapse:collapse;font-size:12px;}
.port-table th{text-align:left;padding:6px 10px;color:var(--muted);font-size:11px;text-transform:uppercase;
               letter-spacing:.05em;border-bottom:1px solid var(--border);}
.port-table td{padding:6px 10px;border-bottom:1px solid rgba(30,42,58,.5);font-family:monospace;}
.port-open{color:#22c55e;}.port-closed{color:var(--muted);}
.tabs{display:flex;gap:4px;margin-bottom:1.2rem;flex-wrap:wrap;}
.tab-btn{padding:6px 16px;border-radius:6px;border:1px solid var(--border);background:transparent;
         color:var(--muted);font-size:12px;cursor:pointer;transition:all .15s;}
.tab-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:500;}
.tab-panel{display:none;}.tab-panel.active{display:block;}
.audience-bar{display:flex;align-items:center;gap:.6rem;background:var(--surface);
              border:1px solid var(--border);border-radius:var(--radius);padding:.7rem 1rem;margin-bottom:1rem;}
.audience-label{font-size:12px;color:var(--muted);margin-right:.4rem;}
.audience-btn{padding:4px 14px;border-radius:6px;border:1px solid var(--border);
              background:transparent;color:var(--muted);font-size:12px;cursor:pointer;transition:all .15s;}
.audience-btn.active{background:var(--accent);border-color:var(--accent);color:#fff;font-weight:500;}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem;}
.back-link{display:inline-flex;align-items:center;gap:.4rem;color:var(--accent2);
           text-decoration:none;font-size:13px;margin-bottom:1.5rem;}
.back-link:hover{text-decoration:underline;}
.btn-outline{display:inline-flex;align-items:center;gap:.5rem;padding:6px 14px;
             background:transparent;border:1px solid var(--border);border-radius:6px;
             color:var(--muted);font-size:12px;cursor:pointer;text-decoration:none;}
.btn-outline:hover{border-color:var(--accent2);color:var(--accent2);}
.mitre-tag{display:inline-block;font-size:10px;padding:1px 7px;border-radius:4px;
           background:rgba(249,115,22,.12);color:#f97316;border:1px solid rgba(249,115,22,.25);
           margin:2px;font-family:monospace;}
.iso-tag{display:inline-block;font-size:10px;padding:1px 7px;border-radius:4px;
         background:rgba(59,130,246,.12);color:var(--accent2);border:1px solid rgba(59,130,246,.25);margin:2px;}
@media(max-width:768px){
  .host-row{grid-template-columns:1fr 80px;}
  .two-col{grid-template-columns:1fr;}
  .compliance-grid{grid-template-columns:repeat(2,1fr);}
}
</style>"""


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _nav() -> str:
    meta = _get_meta()
    user = session.get("username", "admin")
    return f"""
<nav>
  <a class="nav-logo" href="/">{RAVEN_SVG}
    <span class="nav-title">MUNIN</span>
    <span class="nav-sub">&nbsp;GRC v2</span>
  </a>
  <div class="nav-right">
    <span class="nav-badge">{meta.get('target','—')}</span>
    <span class="nav-badge">{meta.get('scan_time','—')[:16]}</span>
    <a class="btn-outline" href="/trends">📈 Trends</a>
    <a class="btn-outline" href="/api/export/pdf" target="_blank">📄 PDF</a>
    <span class="nav-user">👤 {user}</span>
    <a class="btn-logout" href="/logout">Sign out</a>
  </div>
</nav>"""


def _risk_badge(level: str, score: int = None) -> str:
    color = RISK_COLOR.get(level, "#9ca3af")
    bg    = RISK_BG.get(level, "rgba(156,163,175,.1)")
    score_str = f" · {score}/100" if score is not None else ""
    return (
        f'<span class="risk-badge" style="background:{bg};color:{color};border:1px solid {color}40">'
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
        f'<span class="urgency-badge" style="color:{c};background:{bg};border:1px solid {c}40">'
        f'{label}</span>'
    )


def _score_color(score: float) -> str:
    if score >= 80: return "#22c55e"
    if score >= 60: return "#eab308"
    return "#ef4444"


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


def _get_compliance(host: dict) -> dict:
    try:
        from scanner.analysis.compliance_mapper import compliance_score
        cs = compliance_score(host.get("findings", []), host.get("risk_score", 0))
        return cs.to_dict()
    except Exception:
        return {
            "iso27001_score": 100, "nist_score": 100, "cis_score": 100,
            "lgpd_exposure": "LOW", "overall_label": "Good",
            "nist_by_function": {}, "failed_controls": [], "failed_families": [],
        }


def _get_env_compliance() -> dict:
    try:
        from scanner.analysis.compliance_mapper import environment_compliance_score
        return environment_compliance_score(_get_hosts())
    except Exception:
        return {
            "iso27001_avg": 100, "nist_avg": 100, "cis_avg": 100,
            "lgpd_exposure": "LOW", "overall_label": "Good",
        }


def _compliance_cards_html(cs: dict, score_keys=("iso27001_score", "nist_score", "cis_score")) -> str:
    labels = {
        "iso27001_score": "ISO 27001:2022",
        "nist_score":     "NIST CSF 2.0",
        "cis_score":      "CIS Controls v8",
        "iso27001_avg":   "ISO 27001:2022",
        "nist_avg":       "NIST CSF 2.0",
        "cis_avg":        "CIS Controls v8",
    }
    html = '<div class="compliance-grid">'
    for k in score_keys:
        score = cs.get(k, 100)
        label = labels.get(k, k)
        sc    = _score_color(score)
        html += f"""
<div class="compliance-card">
  <div class="compliance-label">{label}</div>
  <div class="compliance-score" style="color:{sc}">{score:.0f}%</div>
  <div class="progress-wrap">
    <div class="progress-fill" style="width:{score}%;background:{sc}"></div>
  </div>
</div>"""
    lgpd   = cs.get("lgpd_exposure", "LOW")
    lgpd_c = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(lgpd, "#22c55e")
    html += f"""
<div class="compliance-card">
  <div class="compliance-label">LGPD Exposure</div>
  <div class="compliance-score" style="color:{lgpd_c}">{lgpd}</div>
  <div style="font-size:11px;color:var(--muted);margin-top:.4rem">Data protection risk</div>
</div>"""
    html += '</div>'
    return html


# ─────────────────────────────────────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if is_authenticated(session):
        return redirect(url_for("index"))

    error    = None
    next_url = request.args.get("next", "/")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        next_url = request.form.get("next", "/")

        if verify_credentials(username, password):
            login_session(session, username)
            return redirect(next_url if next_url.startswith("/") else "/")
        error = "Invalid username or password."

    return render_template_string(LOGIN_HTML, error=error, next=next_url)


@app.route("/logout")
def logout():
    logout_session(session)
    return redirect(url_for("login"))


# ─────────────────────────────────────────────────────────────────────────────
# Main dashboard
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    hosts    = _get_hosts()
    meta     = _get_meta()
    env_cs   = _get_env_compliance()
    audience = session.get("audience", "manager")

    total_hosts    = len(hosts)
    total_cves     = sum(sum(len(p.get("cves", [])) for p in h.get("ports", [])) for h in hosts)
    total_findings = sum(len(h.get("findings", [])) for h in hosts)
    open_ports_cnt = sum(
        sum(1 for p in h.get("ports", []) if p.get("state") == "open") for h in hosts
    )

    risk_counts: dict = {}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    metrics_html = f"""
<div class="metric-grid">
  <div class="metric-card"><div class="label">Total Hosts</div>
    <div class="value" style="color:var(--accent)">{total_hosts}</div></div>
  <div class="metric-card"><div class="label">Critical Hosts</div>
    <div class="value" style="color:var(--crit)">{risk_counts.get('CRITICAL',0)}</div>
    <div class="sub">{risk_counts.get('HIGH',0)} high risk</div></div>
  <div class="metric-card"><div class="label">CVEs Found</div>
    <div class="value" style="color:var(--high)">{total_cves}</div></div>
  <div class="metric-card"><div class="label">Open Ports</div>
    <div class="value" style="color:var(--muted)">{open_ports_cnt}</div></div>
  <div class="metric-card"><div class="label">Threats Detected</div>
    <div class="value" style="color:var(--med)">{total_findings}</div>
    <div class="sub">across all hosts</div></div>
</div>"""

    overall_score = env_cs.get("overall_label", "Good")
    overall_color = {"Good": "#22c55e", "Fair": "#eab308", "Poor": "#f97316", "Critical": "#ef4444"}.get(overall_score, "#22c55e")

    compliance_html = f"""
<div class="card">
  <div class="card-header">🛡️ Environment Compliance Posture
    <span style="margin-left:auto;font-size:11px;color:var(--muted)">
      Overall: <strong style="color:{overall_color}">{overall_score}</strong>
    </span>
  </div>
  <div class="card-body">
    {_compliance_cards_html(env_cs, ("iso27001_avg", "nist_avg", "cis_avg"))}
  </div>
</div>"""

    host_rows = ""
    for h in hosts:
        ip         = h.get("ip", "?")
        level      = h.get("risk_level", "UNKNOWN")
        score      = h.get("risk_score", 0)
        color      = RISK_COLOR.get(level, "#9ca3af")
        hostname   = h.get("hostname", "N/A")
        findings_n = len(h.get("findings", []))
        host_rows += f"""
<a class="host-row" href="/host/{ip}">
  <div><div class="host-ip">{ip}</div>
    <div style="font-size:11px;color:var(--muted)">{hostname}</div></div>
  {_risk_badge(level)}
  <div style="font-size:12px;color:var(--muted)">{score}/100</div>
  <div>{_score_bar(score, level)}</div>
  <div style="font-size:12px;color:var(--muted)">{findings_n} threat{'s' if findings_n != 1 else ''}</div>
</a>"""

    aud_btns = "".join(
        f'<button class="audience-btn{" active" if audience == a else ""}" '
        f'onclick="switchAudience(this,\'{a}\')">{a.title()}</button>'
        for a in ("manager", "auditor", "board")
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Munin · Dashboard</title>{BASE_STYLE}
</head>
<body>
  {_nav()}
  <div class="container">
    <div class="audience-bar">
      <span class="audience-label">Report audience:</span>
      {aud_btns}
      <span id="aud-status" style="margin-left:auto;font-size:11px;color:var(--muted)"></span>
    </div>
    <div class="page-title">Cyber Risk Dashboard</div>
    <div class="page-sub">
      Scan: {meta.get('target','—')} &nbsp;·&nbsp; {meta.get('scan_time','—')[:16]}
      &nbsp;·&nbsp; Duration: {meta.get('scan_duration',0):.0f}s
    </div>
    {metrics_html}
    {compliance_html}
    <div class="card">
      <div class="card-header">📡 Hosts — sorted by risk</div>
      <div>{host_rows}</div>
    </div>
  </div>
  <script>
  function switchAudience(btn, aud) {{
    document.querySelectorAll('.audience-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('aud-status').textContent = 'Updating…';
    fetch('/api/audience', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{audience: aud}})
    }}).then(r => r.json()).then(() => {{
      document.getElementById('aud-status').textContent = '✓ Reports updated';
      setTimeout(() => document.getElementById('aud-status').textContent = '', 2500);
    }});
  }}
  </script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# Host detail
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/host/<ip>")
@login_required
def host_detail(ip: str):
    host = _find_host(ip)
    if not host:
        abort(404)

    audience = session.get("audience", "manager")
    level    = host.get("risk_level", "UNKNOWN")
    score    = host.get("risk_score", 0)
    findings = host.get("findings", [])
    ports    = host.get("ports", [])
    os_info  = host.get("os", {})
    host_cs  = _get_compliance(host)

    try:
        from scanner.analysis.compliance_mapper import map_findings
        refs = map_findings(findings)
    except Exception:
        refs = []

    br           = host.get("business_report") or host.get("nlp_report")
    report_html  = _build_report_html(br)
    findings_html= _build_findings_html(findings, refs)
    ports_html   = _build_ports_html(ports)
    compliance_detail = _build_compliance_detail_html(host_cs, refs)

    acc_str = f"({os_info.get('accuracy', '')}%)" if os_info.get("accuracy") else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>Munin · {ip}</title>{BASE_STYLE}
</head>
<body>
  {_nav()}
  <div class="container">
    <a class="back-link" href="/">← Dashboard</a>
    <div style="display:flex;align-items:center;gap:1rem;margin-bottom:.4rem;flex-wrap:wrap">
      <div class="page-title" style="font-family:monospace">{ip}</div>
      {_risk_badge(level, score)}
      <a class="btn-outline" href="/api/export/host/{ip}/pdf" target="_blank">📄 PDF</a>
    </div>
    <div class="page-sub">
      {host.get('hostname','N/A')} &nbsp;·&nbsp;
      OS: {os_info.get('name','Unknown')} {acc_str} &nbsp;·&nbsp;
      MAC: {host.get('mac','N/A')} ({host.get('mac_vendor','Unknown')})
    </div>

    {_compliance_cards_html(host_cs)}

    <div class="tabs">
      <button class="tab-btn active" onclick="switchTab(this,'tab-report')">📋 GRC Report</button>
      <button class="tab-btn" onclick="switchTab(this,'tab-threats')">🚨 Threats ({len(findings)})</button>
      <button class="tab-btn" onclick="switchTab(this,'tab-ports')">🔌 Ports ({len(ports)})</button>
      <button class="tab-btn" onclick="switchTab(this,'tab-compliance')">📜 Compliance</button>
    </div>

    <div id="tab-report"     class="tab-panel active">{report_html}</div>
    <div id="tab-threats"    class="tab-panel">
      <div class="card"><div class="card-header">Detected Threats &amp; Anomalies</div>
        <div class="card-body">{findings_html}</div></div>
    </div>
    <div id="tab-ports"      class="tab-panel">
      <div class="card"><div class="card-header">Open Ports &amp; Services</div>
        <div class="card-body">
          <table class="port-table">
            <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Version</th><th>CVEs</th></tr></thead>
            <tbody>{ports_html}</tbody>
          </table>
        </div></div>
    </div>
    <div id="tab-compliance" class="tab-panel">{compliance_detail}</div>
  </div>
  <script>
  function switchTab(btn, id) {{
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    btn.classList.add('active');
  }}
  </script>
</body>
</html>"""


def _build_report_html(br) -> str:
    if not br or not isinstance(br, dict):
        return """<div class="card"><div class="card-body" style="color:var(--muted);font-size:13px">
            No business report available. Run a scan with Ollama enabled to generate GRC reports.
            </div></div>"""

    summary  = br.get("executive_summary", "")
    impact   = br.get("business_impact", "")
    flags    = br.get("compliance_flags", [])
    actions  = br.get("priority_actions", [])
    urgency  = br.get("urgency_label", "")
    gen_by   = br.get("generated_by", "template")
    model    = br.get("model", "none")
    audience = br.get("audience", "manager")
    model_str = f" / {model}" if model and model != "none" else ""

    flags_html   = "".join(f'<span class="flag-tag">{f}</span>' for f in flags)
    actions_html = "".join(f"<li>{a}</li>" for a in actions)

    return f"""
<div class="card">
  <div class="card-header" style="justify-content:space-between">
    <span>📋 GRC Business Report</span>
    <span style="font-size:11px;color:var(--muted)">{gen_by}{model_str} · audience: {audience}</span>
  </div>
  <div class="card-body">
    {_urgency_badge(urgency)}
    <div class="report-section"><h3>Executive Summary</h3><p>{summary}</p></div>
    <div class="report-section"><h3>Business Impact</h3><p>{impact}</p></div>
    {"<div class='report-section'><h3>Compliance Flags</h3><div>" + flags_html + "</div></div>" if flags else ""}
    {"<div class='report-section'><h3>Priority Actions</h3><ul>" + actions_html + "</ul></div>" if actions else ""}
  </div>
</div>"""


def _build_findings_html(findings, refs) -> str:
    if not findings:
        return "<p style='color:var(--muted);font-size:13px'>No threats detected.</p>"

    ref_by_id = {r.pattern_id: r for r in refs}
    sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_f   = sorted(findings, key=lambda f: sev_weight.get(f.get("severity", "LOW"), 0), reverse=True)

    html = ""
    for f in sorted_f:
        sev   = f.get("severity", "?")
        color = RISK_COLOR.get(sev, "#9ca3af")
        bg    = RISK_BG.get(sev, "rgba(156,163,175,.08)")
        pid   = f.get("pattern_id", "")
        ref   = ref_by_id.get(pid)

        mitre_tags = ""
        iso_tags   = ""
        if ref:
            mitre_tags = "".join(f'<span class="mitre-tag">{t}</span>' for t in ref.mitre[:3])
            iso_tags   = "".join(f'<span class="iso-tag">{c}</span>'   for c in ref.iso27001[:3])

        rem_html = "".join(f"<li>{r}</li>" for r in f.get("remediation", [])[:3])

        html += f"""
<div style="background:{bg};padding:.8rem 1rem;border-radius:8px;margin-bottom:.6rem;border-left:3px solid {color}">
  <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem">
    {_risk_badge(sev)} <strong>{f.get('name','')}</strong>
  </div>
  <div class="finding-detail">{f.get('detail','')}</div>
  <div class="finding-desc">{f.get('description','')}</div>
  {('<div style="margin-top:.5rem">' + mitre_tags + iso_tags + '</div>') if (mitre_tags or iso_tags) else ''}
  {"<ul style='font-size:12px;color:var(--muted);margin-top:.5rem;padding-left:1.2rem'>" + rem_html + "</ul>" if rem_html else ""}
</div>"""
    return html


def _build_ports_html(ports) -> str:
    html = ""
    for p in ports:
        state  = p.get("state", "")
        sc     = "port-open" if state == "open" else "port-closed"
        cves   = p.get("cves", [])
        cve_str = (
            f'<span style="color:var(--crit);font-size:11px">{len(cves)} CVE{"s" if len(cves)>1 else ""}</span>'
            if cves else '<span style="color:var(--muted)">—</span>'
        )
        pv    = " ".join(filter(None, [p.get("product", ""), p.get("version", "")])) or "—"
        html += f"""<tr>
  <td class="{sc}">{p['port']}/{p.get('protocol','tcp')}</td>
  <td class="{sc}">{state}</td>
  <td>{p.get('service','')}</td>
  <td style="color:var(--muted)">{pv}</td>
  <td>{cve_str}</td>
</tr>"""
    return html


def _build_compliance_detail_html(cs: dict, refs) -> str:
    nist_funcs = {
        "GV": "Govern", "ID": "Identify", "PR": "Protect",
        "DE": "Detect",  "RS": "Respond",  "RC": "Recover",
    }
    nist_by_f = cs.get("nist_by_function", {})

    nist_bars = ""
    for func, name in nist_funcs.items():
        s = nist_by_f.get(func, 100)
        c = _score_color(s)
        nist_bars += f"""
<div style="margin-bottom:.7rem">
  <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:.2rem">
    <span><strong>{func}</strong> {name}</span>
    <span style="color:{c}">{s:.0f}%</span>
  </div>
  <div class="progress-wrap"><div class="progress-fill" style="width:{s}%;background:{c}"></div></div>
</div>"""

    failed_ctrls = "".join(
        f'<span class="iso-tag">{c}</span>' for c in cs.get("failed_controls", [])[:12]
    )
    failed_fams = ", ".join(cs.get("failed_families", [])) or "None"

    findings_map = ""
    for ref in refs:
        mitre = "".join(f'<span class="mitre-tag">{t}</span>' for t in ref.mitre)
        iso   = "".join(f'<span class="iso-tag">{c}</span>'   for c in ref.iso27001)
        lgpd  = " · ".join(ref.lgpd[:2])
        findings_map += f"""
<div style="padding:.7rem 0;border-bottom:1px solid var(--border)">
  <div style="display:flex;align-items:center;gap:.5rem;margin-bottom:.3rem">
    {_risk_badge(ref.severity)} <strong>{ref.finding_name}</strong>
    <span style="font-size:11px;color:var(--muted)">{ref.control_family}</span>
  </div>
  <div>{mitre}</div>
  <div style="margin-top:.3rem">{iso}</div>
  {f'<div style="font-size:11px;color:var(--muted);margin-top:.3rem">{lgpd}</div>' if lgpd else ''}
</div>"""

    return f"""
<div class="two-col">
  <div class="card">
    <div class="card-header">NIST CSF 2.0 — by Function</div>
    <div class="card-body">
      {nist_bars or '<p style="color:var(--muted)">No NIST violations.</p>'}
    </div>
  </div>
  <div class="card">
    <div class="card-header">Failed Controls</div>
    <div class="card-body">
      <p style="font-size:12px;color:var(--muted);margin-bottom:.7rem">
        Control families with failures: {failed_fams}
      </p>
      {failed_ctrls or '<p style="color:var(--muted);font-size:12px">No failed controls.</p>'}
    </div>
  </div>
</div>
<div class="card">
  <div class="card-header">📜 Finding → Framework Mapping (MITRE · ISO 27001 · LGPD)</div>
  <div class="card-body">
    {findings_map or '<p style="color:var(--muted)">No findings to map.</p>'}
  </div>
</div>"""


# ─────────────────────────────────────────────────────────────────────────────
# Trend page
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/trends")
@login_required
def trends():
    try:
        from report.history import load_snapshots, trend_data, latest_comparison
        snaps = load_snapshots(20)
        td    = trend_data(snaps) if snaps else None
        comp  = latest_comparison()
    except Exception:
        snaps, td, comp = [], None, None

    trend_json = json.dumps(td.to_dict() if td else {})

    comp_html = ""
    if comp:
        dc  = "#22c55e" if comp.avg_risk_delta < 0 else "#ef4444"
        ds  = "↓" if comp.avg_risk_delta < 0 else "↑"
        comp_html = f"""
<div class="card">
  <div class="card-header">📊 Latest Scan Comparison
    <span style="font-size:11px;color:var(--muted);margin-left:auto">
      {comp.old_time[:16]} → {comp.new_time[:16]}
    </span>
  </div>
  <div class="card-body">
    <div class="metric-grid" style="margin-bottom:1rem">
      <div class="metric-card"><div class="label">Avg Risk Delta</div>
        <div class="value" style="color:{dc}">{ds}{abs(comp.avg_risk_delta):.1f}</div></div>
      <div class="metric-card"><div class="label">Improved Hosts</div>
        <div class="value" style="color:#22c55e">{comp.improved_hosts}</div></div>
      <div class="metric-card"><div class="label">Worsened Hosts</div>
        <div class="value" style="color:#ef4444">{comp.worsened_hosts}</div></div>
      <div class="metric-card"><div class="label">CVE Delta</div>
        <div class="value" style="color:var(--muted)">{comp.total_cve_delta:+d}</div></div>
    </div>
    <p style="font-size:13px">{comp.summary}</p>
  </div>
</div>"""

    charts_html = ""
    if snaps:
        charts_html = """
<div class="card">
  <div class="card-header">📈 Average Risk Score Over Time</div>
  <div class="card-body"><canvas id="trendChart" height="80"></canvas></div>
</div>
<div class="two-col">
  <div class="card">
    <div class="card-header">🔴 Critical / High Hosts</div>
    <div class="card-body"><canvas id="critChart" height="120"></canvas></div>
  </div>
  <div class="card">
    <div class="card-header">🐛 Total CVEs</div>
    <div class="card-body"><canvas id="cveChart" height="120"></canvas></div>
  </div>
</div>"""

    no_data = ""
    if not snaps:
        no_data = """<div class="card"><div class="card-body" style="color:var(--muted);text-align:center;padding:2rem">
          No historical data yet. Run multiple scans to enable trend analysis.
        </div></div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"><title>Munin · Trends</title>{BASE_STYLE}
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
  {_nav()}
  <div class="container">
    <a class="back-link" href="/">← Dashboard</a>
    <div class="page-title">Trend Analysis</div>
    <div class="page-sub">Risk evolution across {len(snaps)} historical scan(s)</div>
    {comp_html}
    {no_data}
    {charts_html}
  </div>
  <script>
  const td = {trend_json};
  if (td && td.timestamps && td.timestamps.length > 0) {{
    Chart.defaults.color = '#64748b';
    Chart.defaults.borderColor = '#1e2a3a';

    new Chart(document.getElementById('trendChart'), {{
      type: 'line',
      data: {{
        labels: td.timestamps,
        datasets: [{{
          label: 'Avg Risk Score', data: td.avg_risk,
          borderColor: '#3b82f6', backgroundColor: 'rgba(59,130,246,.1)',
          tension: .3, fill: true, pointRadius: 4,
        }}]
      }},
      options: {{ scales: {{ y: {{ min: 0, max: 100 }} }},
                  plugins: {{ legend: {{ display: false }} }}, responsive: true }}
    }});

    new Chart(document.getElementById('critChart'), {{
      type: 'bar',
      data: {{
        labels: td.timestamps,
        datasets: [
          {{ label: 'Critical', data: td.critical_count, backgroundColor: '#ef4444' }},
          {{ label: 'High',     data: td.high_count,     backgroundColor: '#f97316' }},
        ]
      }},
      options: {{ plugins: {{ legend: {{ labels: {{ color: '#64748b' }} }} }}, responsive: true }}
    }});

    new Chart(document.getElementById('cveChart'), {{
      type: 'line',
      data: {{
        labels: td.timestamps,
        datasets: [{{
          label: 'CVEs', data: td.cve_totals,
          borderColor: '#f97316', backgroundColor: 'rgba(249,115,22,.1)',
          tension: .3, fill: true, pointRadius: 3,
        }}]
      }},
      options: {{ plugins: {{ legend: {{ display: false }} }}, responsive: true }}
    }});
  }}
  </script>
</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
# JSON API
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/summary")
@login_required
def api_summary():
    hosts  = _get_hosts()
    env_cs = _get_env_compliance()
    rc: dict = {}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        rc[lvl] = rc.get(lvl, 0) + 1
    return jsonify({
        "meta":           _get_meta(),
        "total_hosts":    len(hosts),
        "risk_counts":    rc,
        "total_cves":     sum(sum(len(p.get("cves",[])) for p in h.get("ports",[])) for h in hosts),
        "total_findings": sum(len(h.get("findings",[])) for h in hosts),
        "compliance":     env_cs,
    })


@app.route("/api/hosts")
@login_required
def api_hosts():
    return jsonify([{
        "ip":         h.get("ip"),
        "hostname":   h.get("hostname"),
        "risk_level": h.get("risk_level"),
        "risk_score": h.get("risk_score"),
        "findings":   len(h.get("findings", [])),
        "ports":      sum(1 for p in h.get("ports", []) if p.get("state") == "open"),
    } for h in _get_hosts()])


@app.route("/api/host/<ip>/compliance")
@login_required
def api_host_compliance(ip: str):
    host = _find_host(ip)
    if not host:
        abort(404)
    return jsonify(_get_compliance(host))


@app.route("/api/audience", methods=["POST"])
@login_required
def api_set_audience():
    """Switch NLP report audience without re-scanning."""
    data = request.get_json(force=True)
    aud  = data.get("audience", "manager")
    if aud not in ("manager", "auditor", "board"):
        return jsonify({"error": "invalid audience"}), 400
    session["audience"] = aud
    session["last_activity"] = __import__("time").time()
    return jsonify({"audience": aud, "status": "ok"})


@app.route("/api/trends")
@login_required
def api_trends():
    try:
        from report.history import load_snapshots, trend_data
        td = trend_data(load_snapshots(30))
        return jsonify(td.to_dict())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/pdf")
@login_required
def api_export_pdf():
    try:
        from report.pdf_report import generate_pdf
        from scanner.analysis.compliance_mapper import environment_compliance_score
        hosts  = _get_hosts()
        env_cs = environment_compliance_score(hosts)
        aud    = session.get("audience", "manager")
        out    = generate_pdf(_scan_result, audience=aud,
                               env_compliance=env_cs if isinstance(env_cs, dict) else env_cs)
        ext = "application/pdf" if str(out).endswith(".pdf") else "text/html"
        disp = f"attachment; filename={out.name}" if str(out).endswith(".pdf") else "inline"
        return Response(
            out.read_bytes() if str(out).endswith(".pdf") else out.read_text("utf-8"),
            mimetype=ext,
            headers={"Content-Disposition": disp},
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/host/<ip>/pdf")
@login_required
def api_export_host_pdf(ip: str):
    host = _find_host(ip)
    if not host:
        abort(404)
    try:
        from report.pdf_report import generate_pdf
        result = {"meta": _get_meta(), "hosts": [host]}
        out    = generate_pdf(result, audience=session.get("audience", "manager"))
        ext  = "application/pdf" if str(out).endswith(".pdf") else "text/html"
        return Response(
            out.read_bytes() if str(out).endswith(".pdf") else out.read_text("utf-8"),
            mimetype=ext,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ─────────────────────────────────────────────────────────────────────────────
# Startup
# ─────────────────────────────────────────────────────────────────────────────

def _load_result(path: str) -> None:
    global _scan_result, _json_path
    _json_path   = path
    _scan_result = json.loads(Path(path).read_text(encoding="utf-8"))
    print(f"[Munin] Loaded: {path}  ({len(_scan_result.get('hosts',[]))} hosts)")


def _find_latest_json() -> Optional[str]:
    files = sorted(
        glob.glob("munin_*.json") + glob.glob("scans/munin_*.json"),
        reverse=True,
    )
    return files[0] if files else None


def main():
    parser = argparse.ArgumentParser(description="Munin GRC Dashboard v2")
    parser.add_argument("json_file", nargs="?",    help="Path to Munin JSON result")
    parser.add_argument("--port",    type=int,     default=5000)
    parser.add_argument("--host",                  default="127.0.0.1")
    parser.add_argument("--debug",   action="store_true")
    args = parser.parse_args()

    json_path = args.json_file or _find_latest_json()
    if not json_path:
        print("[ERROR] No JSON file found. Run a scan first or pass the file as argument.")
        print("Usage:  python3 dashboard.py munin_20260506_120000.json")
        sys.exit(1)
    if not Path(json_path).exists():
        print(f"[ERROR] File not found: {json_path}")
        sys.exit(1)

    _load_result(json_path)

    # Save history snapshot on startup
    try:
        from report.history import save_snapshot
        snap_path = save_snapshot(_scan_result)
        print(f"[Munin] History snapshot saved: {snap_path}")
    except Exception:
        pass

    init_auth(app)

    import os
    user = os.environ.get("MUNIN_DASHBOARD_USER", "admin")
    print(f"[Munin] Dashboard v2 → http://{args.host}:{args.port}")
    print(f"[Munin] Login with user: {user}  (password in .env)")
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
