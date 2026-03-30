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
Munin correlation engine.
Analyses a normalised host_data dict and returns a list of Finding objects,
each referencing a pattern from patterns.py.
"""

from typing import List, Dict, Any

from .patterns import PATTERN_BY_ID

# ─────────────────────────────────────────────────────────────────────────────
# Threshold constants (tunable)
# ─────────────────────────────────────────────────────────────────────────────

SSH_BRUTEFORCE_THRESHOLD  = 5    # failed login lines to trigger
AUTH_FAILURE_THRESHOLD    = 10   # generic auth failures
WEB_ERROR_THRESHOLD       = 20   # 4xx/5xx lines to flag
LARGE_SURFACE_THRESHOLD   = 15   # open ports to flag
HIGH_CVE_CVSS             = 7.0  # minimum CVSS for "high" CVE match

# Ports considered "critical" (lateral movement / well-known attack targets)
CRITICAL_PORTS = {
    23,    # Telnet
    3389,  # RDP
    445,   # SMB
    5900,  # VNC
    5985,  # WinRM
    4444,  # Metasploit default
}

CLEARTEXT_PORTS = {21, 23}       # FTP, Telnet

DATABASE_PORTS = {
    1433,  # MSSQL
    1521,  # Oracle
    2049,  # NFS (data exposure)
    3306,  # MySQL
    5432,  # PostgreSQL
    6379,  # Redis
    9200,  # Elasticsearch
    27017, # MongoDB
}

DOCKER_PORTS = {2375, 2376}

WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888}


# ─────────────────────────────────────────────────────────────────────────────
# Finding dataclass (plain dict for JSON serialisability)
# ─────────────────────────────────────────────────────────────────────────────

def _finding(pattern_id: str, detail: str = "") -> Dict:
    """Build a Finding dict from a pattern id."""
    pattern = PATTERN_BY_ID.get(pattern_id, {})
    return {
        "pattern_id":  pattern_id,
        "name":        pattern.get("name", pattern_id),
        "description": pattern.get("description", ""),
        "severity":    pattern.get("severity", "MEDIUM"),
        "risk_bonus":  pattern.get("risk_bonus", 10),
        "remediation": pattern.get("remediation", []),
        "detail":      detail,   # extra context specific to this host
    }


# ─────────────────────────────────────────────────────────────────────────────
# Log-derived metrics helper
# ─────────────────────────────────────────────────────────────────────────────

def _extract_log_metrics(log_entries: List[Dict]) -> Dict[str, Any]:
    """
    Scan parsed log entries (as returned by logreader.read_log) and
    produce a metrics dict consumed by the correlation rules.
    """
    metrics: Dict[str, Any] = {
        "failed_ssh_logins":    0,
        "auth_failures":        0,
        "web_errors_4xx":       0,
        "web_errors_5xx":       0,
        "accepted_logins":      0,
        "sudo_events":          0,
        "kernel_errors":        0,
    }

    for entry in log_entries:
        msg    = (entry.get("message") or "").lower()
        level  = (entry.get("level")   or "").upper()
        status = entry.get("status", "")

        # SSH-specific failures
        if ("failed password" in msg or "authentication failure" in msg
                or "invalid user" in msg):
            if "ssh" in (entry.get("process") or "").lower() or "sshd" in msg:
                metrics["failed_ssh_logins"] += 1
            metrics["auth_failures"] += 1

        # Generic auth failures (non-SSH too)
        elif level == "ERROR" and (
            "fail" in msg or "invalid" in msg or "denied" in msg
        ):
            metrics["auth_failures"] += 1

        # Successful logins
        if "accepted password" in msg or "accepted publickey" in msg:
            metrics["accepted_logins"] += 1

        # Sudo
        if "sudo" in msg and "command" in msg:
            metrics["sudo_events"] += 1

        # Kernel errors
        if level in ("ERROR", "CRIT") and entry.get("timestamp", "").startswith("["):
            metrics["kernel_errors"] += 1

        # Web HTTP status codes (access log entries)
        try:
            code = int(status)
            if 400 <= code < 500:
                metrics["web_errors_4xx"] += 1
            elif 500 <= code < 600:
                metrics["web_errors_5xx"] += 1
        except (ValueError, TypeError):
            pass

    return metrics


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def correlate(host_data: Dict) -> List[Dict]:
    """
    Run all detection rules against a normalised host_data dict.

    Expected host_data keys (all optional — missing keys are handled gracefully):
        ip, os, ports, services, cves, logs, vulnerabilities, risk_score

    Returns a list of Finding dicts (see _finding()).
    """
    findings: List[Dict] = []

    ports       = host_data.get("ports", [])
    log_entries = host_data.get("logs", [])
    nse_results = host_data.get("vulnerabilities", {})

    # Build quick-access sets
    open_port_nums = {
        p["port"] for p in ports if p.get("state") == "open"
    }

    # Extract log-derived metrics
    metrics = _extract_log_metrics(log_entries)

    # ── Rule 1: SSH Brute Force ───────────────────────────────────────────────
    if 22 in open_port_nums and metrics["failed_ssh_logins"] >= SSH_BRUTEFORCE_THRESHOLD:
        findings.append(_finding(
            "ssh_brute_force",
            f"{metrics['failed_ssh_logins']} failed SSH login(s) detected in logs",
        ))

    # ── Rule 2: Vulnerable Service Exposed (CVE CVSS ≥ 7) ───────────────────
    high_cve_ports: List[str] = []
    for p in ports:
        if p.get("state") != "open":
            continue
        for cve in p.get("cves", []):
            cvss = cve.get("cvss_score") or 0.0
            if float(cvss) >= HIGH_CVE_CVSS:
                svc = p.get("service") or p.get("product") or str(p["port"])
                high_cve_ports.append(
                    f"port {p['port']} ({svc}) — {cve['id']} CVSS {cvss}"
                )
                break   # one high CVE per port is enough to flag

    if high_cve_ports:
        findings.append(_finding(
            "vulnerable_service_exposed",
            "; ".join(high_cve_ports[:5]),
        ))

    # ── Rule 3: Web Error + CVE (exploitation probe) ─────────────────────────
    web_errors = metrics["web_errors_4xx"] + metrics["web_errors_5xx"]
    web_with_cve = any(
        p["port"] in WEB_PORTS and p.get("cves")
        for p in ports if p.get("state") == "open"
    )
    if web_errors >= WEB_ERROR_THRESHOLD and web_with_cve:
        findings.append(_finding(
            "web_error_with_cve",
            f"{web_errors} HTTP error(s) in logs + CVE(s) on web service",
        ))

    # ── Rule 4: Critical Port Open (RDP, SMB, VNC, Telnet, etc.) ─────────────
    exposed_critical = open_port_nums & CRITICAL_PORTS
    if exposed_critical:
        port_list = ", ".join(str(p) for p in sorted(exposed_critical))
        findings.append(_finding(
            "critical_port_open",
            f"Critical port(s) open: {port_list}",
        ))

    # ── Rule 5: Large Attack Surface ──────────────────────────────────────────
    if len(open_port_nums) >= LARGE_SURFACE_THRESHOLD:
        findings.append(_finding(
            "large_attack_surface",
            f"{len(open_port_nums)} open ports detected",
        ))

    # ── Rule 6: NSE Confirmed Vulnerability ───────────────────────────────────
    confirmed_vuln_scripts: List[str] = []
    for port_num, scripts in nse_results.items():
        for script_name, output in scripts.items():
            if "VULNERABLE" in str(output).upper():
                confirmed_vuln_scripts.append(
                    f"{script_name} on port {port_num}"
                )

    if confirmed_vuln_scripts:
        findings.append(_finding(
            "nse_confirmed_vuln",
            "; ".join(confirmed_vuln_scripts[:5]),
        ))

    # ── Rule 7: Cleartext Protocols (FTP / Telnet) ────────────────────────────
    exposed_cleartext = open_port_nums & CLEARTEXT_PORTS
    if exposed_cleartext:
        port_list = ", ".join(str(p) for p in sorted(exposed_cleartext))
        findings.append(_finding(
            "cleartext_protocol",
            f"Cleartext protocol port(s) open: {port_list}",
        ))

    # ── Rule 8: Database Port Exposed ─────────────────────────────────────────
    exposed_db = open_port_nums & DATABASE_PORTS
    if exposed_db:
        port_list = ", ".join(str(p) for p in sorted(exposed_db))
        findings.append(_finding(
            "database_exposed",
            f"Database port(s) reachable: {port_list}",
        ))

    # ── Rule 9: Auth Failure Spike (generic) ──────────────────────────────────
    # Only trigger if NOT already covered by SSH brute force
    already_ssh = any(f["pattern_id"] == "ssh_brute_force" for f in findings)
    if (not already_ssh
            and metrics["auth_failures"] >= AUTH_FAILURE_THRESHOLD):
        findings.append(_finding(
            "auth_failure_spike",
            f"{metrics['auth_failures']} authentication failure(s) in logs",
        ))

    # ── Rule 10: Docker API Exposed ───────────────────────────────────────────
    exposed_docker = open_port_nums & DOCKER_PORTS
    if exposed_docker:
        port_list = ", ".join(str(p) for p in sorted(exposed_docker))
        findings.append(_finding(
            "docker_api_exposed",
            f"Docker daemon API reachable on port(s): {port_list}",
        ))

    return findings
