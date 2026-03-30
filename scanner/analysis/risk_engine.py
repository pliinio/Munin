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
"""

from typing import Dict, List, Tuple

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
# Core scoring
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
        # Use diminishing returns: sqrt-ish curve so one critical finding
        # doesn't instantly max out the bonus bucket.
        import math
        score += min(int(math.sqrt(bonus) * 3.5), 20)

    final = min(int(score), 100)

    for threshold, label in SCORE_BANDS:
        if final >= threshold:
            return final, label

    return final, "MINIMAL"


# ─────────────────────────────────────────────────────────────────────────────
# Human-readable output helpers
# ─────────────────────────────────────────────────────────────────────────────

def one_line_summary(ip: str, findings: List[Dict], score: int, level: str) -> str:
    """
    Return a compact one-line threat summary for terminal or HTML headers.

    Example:
        "192.168.1.10  [CRITICAL 87/100]  SSH Brute Force · Vulnerable Service Exposed"
    """
    if not findings:
        label = "No threats detected"
    else:
        # Sort by severity weight so the most serious appears first
        _weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        sorted_f = sorted(
            findings,
            key=lambda f: _weight.get(f.get("severity", "LOW"), 0),
            reverse=True,
        )
        label = " · ".join(f["name"] for f in sorted_f[:3])
        if len(findings) > 3:
            label += f" (+{len(findings) - 3} more)"

    return f"{ip}  [{level} {score}/100]  {label}"


def prioritised_remediation(findings: List[Dict]) -> List[str]:
    """
    Merge and de-duplicate remediation steps across all findings,
    ordered from highest to lowest severity finding.

    Returns a flat, numbered list like:
        ["1. Disable password auth on SSH", "2. Patch OpenSSH", ...]
    """
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
    """
    Return a multi-line human-readable threat summary.
    """
    ip = host_data.get("ip", "?")
    lines = [
        f"Host: {ip}",
        f"Risk: {score}/100  [{level}]",
        "",
    ]

    if not findings:
        lines.append("  No threats or anomalies detected.")
    else:
        lines.append(f"  {len(findings)} threat(s) detected:")
        for f in findings:
            sev  = f.get("severity", "?")
            name = f["name"]
            detail = f.get("detail", "")
            lines.append(f"  [{sev}] {name}")
            if detail:
                lines.append(f"         {detail}")

    return "\n".join(lines)


def explain(findings: List[Dict]) -> List[str]:
    """
    Return a list of one-sentence plain-English explanations for each finding.
    """
    return [f["description"] for f in findings if f.get("description")]
