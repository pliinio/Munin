#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

"""
Munin risk engine — intelligent scoring, prioritisation and human-readable output.

Score breakdown (max 100):
  Base port risk      → up to 20 pts  (open count + risky ports)
  CVE severity        → up to 35 pts  (weighted by CVSS)
  NSE confirmed vulns → up to 25 pts
  Correlation bonus   → up to 20 pts  (from pattern risk_bonus, capped)

Score labels:
  0–20  → LOW
  21–50 → MEDIUM
  51–80 → HIGH
  81–100→ CRITICAL

v2 additions:
  - full_report()  → integrates NLP translation layer (nlp_translator.py)
  - audience param propagated to BusinessReport
"""

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("munin.risk_engine")

# Ports that inherently add to base risk
_RISKY_PORTS = {
    21, 22, 23, 25, 53, 69, 79, 80, 110, 111, 119,
    135, 137, 138, 139, 143, 161, 389, 443, 445,
    512, 513, 514, 873, 1099, 1433, 1521, 2049,
    2375, 2376, 3000, 3306, 3389, 4444, 5432,
    5900, 5985, 6379, 8080, 8443, 8888, 9200, 27017,
}

SCORE_BANDS = [
    (81, "CRITICAL"),
    (51, "HIGH"),
    (21, "MEDIUM"),
    (5,  "LOW"),
    (0,  "MINIMAL"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Core scoring  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────────────────

def calculate_risk(
    ports: List[Dict],
    nse_results: Dict,
    findings: List[Dict] | None = None,
) -> Tuple[int, str]:
    """
    Produce a 0–100 risk score and severity label.

    Args:
        ports       – list of port dicts (as returned by portscan.scan_ports)
        nse_results – {port_num: {script_name: output}} from vulnscan
        findings    – optional list of Finding dicts from correlator.correlate()

    Returns:
        (score: int, level: str)
    """
    score = 0
    open_ports = [p for p in ports if p.get("state") == "open"]

    # ── Base: open port count (capped at 12) ─────────────────────────────────
    score += min(len(open_ports) * 1.2, 12)

    # ── Base: risky port exposure (2 pts each, capped at 8 extra) ────────────
    risky_hits = sum(1 for p in open_ports if p.get("port") in _RISKY_PORTS)
    score += min(risky_hits * 2, 8)

    # ── CVE severity (weighted, capped at 35) ─────────────────────────────────
    cve_score = 0
    for p in ports:
        for cve in p.get("cves", []):
            cvss = float(cve.get("cvss_score") or 0.0)
            if cvss >= 9.0:
                cve_score += 18
            elif cvss >= 7.0:
                cve_score += 10
            elif cvss >= 4.0:
                cve_score += 5
            else:
                cve_score += 1
    score += min(cve_score, 35)

    # ── NSE confirmed vulnerabilities (10 pts each, capped at 25) ────────────
    nse_score = 0
    for scripts in nse_results.values():
        for output in scripts.values():
            out_upper = str(output).upper()
            if "VULNERABLE" in out_upper:
                nse_score += 10
            elif "LIKELY VULNERABLE" in out_upper:
                nse_score += 5
    score += min(nse_score, 25)

    # ── Correlation bonus (from findings, capped at 20) ───────────────────────
    if findings:
        bonus = sum(f.get("risk_bonus", 0) for f in findings)
        score += min(int(math.sqrt(bonus) * 3.5), 20)

    final = min(int(score), 100)

    for threshold, label in SCORE_BANDS:
        if final >= threshold:
            return final, label

    return final, "MINIMAL"


# ─────────────────────────────────────────────────────────────────────────────
# Human-readable output helpers  (unchanged from v1)
# ─────────────────────────────────────────────────────────────────────────────

def one_line_summary(ip: str, findings: List[Dict], score: int, level: str) -> str:
    if not findings:
        label = "Nenhuma ameaça detectada"
    else:
        _weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_f = sorted(
            findings,
            key=lambda f: _weight.get(f.get("severity", "LOW"), 0),
            reverse=True,
        )
        label = " · ".join(f["name"] for f in sorted_f[:3])
        if len(findings) > 3:
            label += f" (+{len(findings) - 3} a mais)"
    return f"{ip}  [{level} {score}/100]  {label}"


def prioritised_remediation(findings: List[Dict]) -> List[str]:
    _weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_f = sorted(
        findings,
        key=lambda f: _weight.get(f.get("severity", "LOW"), 0),
        reverse=True,
    )
    seen: set = set()
    steps: List[str] = []
    for finding in sorted_f:
        for step in finding.get("remediation", []):
            key = step.lower().strip()
            if key not in seen:
                seen.add(key)
                steps.append(step)
    return [f"{i + 1}. {step}" for i, step in enumerate(steps)]


def summarize(host_data: Dict, findings: List[Dict], score: int, level: str) -> str:
    ip = host_data.get("ip", "?")
    lines = [f"Host: {ip}", f"Risco: {score}/100  [{level}]", ""]
    if not findings:
        lines.append("  Nenhuma ameaça ou anomalia detectada.")
    else:
        lines.append(f"  {len(findings)} ameaça(s) detectada(s):")
        for f in findings:
            sev    = f.get("severity", "?")
            name   = f["name"]
            detail = f.get("detail", "")
            lines.append(f"  [{sev}] {name}")
            if detail:
                lines.append(f"         {detail}")
    return "\n".join(lines)


def explain(findings: List[Dict]) -> List[str]:
    return [f["description"] for f in findings if f.get("description")]


# ─────────────────────────────────────────────────────────────────────────────
# v2 — NLP integration
# ─────────────────────────────────────────────────────────────────────────────

def full_report(
    host_data: Dict,
    findings: List[Dict],
    score: int,
    level: str,
    audience: str = "manager",
    api_key: Optional[str] = None,
):
    """
    Generate a complete BusinessReport for a host combining:
      - Technical risk score (v1 engine)
      - Plain-language NLP translation (v2 nlp_translator)

    Args:
        host_data   – host dict from the Munin scanner
        findings    – Finding dicts from correlator.correlate()
        score       – int from calculate_risk()
        level       – str from calculate_risk()
        audience    – "manager" | "auditor" | "board"
        api_key     – optional Anthropic API key (overrides env var)

    Returns:
        BusinessReport (see nlp_translator.BusinessReport)

    Usage:
        from scanner.analysis.risk_engine import full_report

        score, level = calculate_risk(ports, nse_results, findings)
        report = full_report(host_data, findings, score, level, audience="manager")

        print(report.executive_summary)
        print(report.to_markdown())
    """
    try:
        from scanner.analysis.nlp_translator import (
            translate_findings,
            set_audience,
        )
    except ImportError as exc:
        logger.error(
            "nlp_translator not found in scanner/analysis/: %s", exc
        )
        return _minimal_report_fallback(host_data, findings, score, level, audience)

    set_audience(audience)

    return translate_findings(
        host_data=host_data,
        findings=findings,
        score=score,
        level=level,
        audience=audience,
    )


def batch_full_reports(
    hosts: List[Dict],
    audience: str = "manager",
    api_key: Optional[str] = None,
) -> List:
    """
    Generate BusinessReports for multiple hosts.

    Each item in `hosts` must have: host_data, findings, score, level.

    Usage:
        from scanner.analysis.risk_engine import batch_full_reports

        host_list = [
            {"host_data": hd, "findings": f, "score": s, "level": lv}
            for hd, f, s, lv in results
        ]
        reports = batch_full_reports(host_list, audience="auditor")
        for r in reports:
            print(r.to_markdown())
    """
    try:
        from scanner.analysis.nlp_translator import translate_batch
    except ImportError as exc:
        logger.error("nlp_translator not found: %s", exc)
        return []

    return translate_batch(hosts, audience=audience)


# ─────────────────────────────────────────────────────────────────────────────
# Minimal fallback if nlp_translator is missing
# ─────────────────────────────────────────────────────────────────────────────

def _minimal_report_fallback(
    host_data: Dict,
    findings: List[Dict],
    score: int,
    level: str,
    audience: str,
) -> Dict:
    from scanner.analysis.nlp_translator import BusinessReport
    import time
    return BusinessReport(
        ip=host_data.get("ip", "unknown"),
        hostname=host_data.get("hostname") or host_data.get("ip", "unknown"),
        risk_level=level,
        score=score,
        executive_summary=summarize(host_data, findings, score, level),
        business_impact="Não foi possível gerar o relatório completo — camada NLP indisponível.",
        compliance_flags=[],
        priority_actions=prioritised_remediation(findings),
        urgency_label="This quarter",
        generated_by="fallback",
        model="none",
        audience=audience,
        generated_at=time.time(),
    )
