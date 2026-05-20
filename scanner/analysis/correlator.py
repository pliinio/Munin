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
Munin correlation engine — v2 with ML anomaly detection.

Detection pipeline:
  Layer 1 (rule-based)  — 10 hard-coded pattern rules (unchanged from v1)
  Layer 2 (ML-based)    — Isolation Forest anomaly detection (new in v2)

Both layers run independently. Their findings are merged and returned together.
The ML layer adds findings only when it detects anomalies not covered by rules.

ML behaviour:
  - Requires at least 3 hosts in the scan session to train (network scan)
  - For single-host scans, tries to load a saved baseline (.pkl file)
  - If neither is available, ML layer is silently skipped (no crash)
  - ML findings are tagged with "generated_by": "isolation_forest"
"""

from typing import List, Dict, Any, Optional

from .patterns import PATTERN_BY_ID

# ─────────────────────────────────────────────────────────────────────────────
# Threshold constants (tunable)
# ─────────────────────────────────────────────────────────────────────────────

SSH_BRUTEFORCE_THRESHOLD  = 5
AUTH_FAILURE_THRESHOLD    = 10
WEB_ERROR_THRESHOLD       = 20
LARGE_SURFACE_THRESHOLD   = 15
HIGH_CVE_CVSS             = 7.0

CRITICAL_PORTS   = {23, 3389, 445, 5900, 5985, 4444}
CLEARTEXT_PORTS  = {21, 23}
DATABASE_PORTS   = {1433, 1521, 2049, 3306, 5432, 6379, 9200, 27017}
DOCKER_PORTS     = {2375, 2376}
WEB_PORTS        = {80, 443, 8080, 8443, 8000, 8888}

# Path to a persisted baseline model (used for single-host scans)
DEFAULT_BASELINE_PATH = "munin_baseline.pkl"


# ─────────────────────────────────────────────────────────────────────────────
# Finding builder
# ─────────────────────────────────────────────────────────────────────────────

def _finding(pattern_id: str, detail: str = "") -> Dict:
    pattern = PATTERN_BY_ID.get(pattern_id, {})
    return {
        "pattern_id":  pattern_id,
        "name":        pattern.get("name", pattern_id),
        "description": pattern.get("description", ""),
        "severity":    pattern.get("severity", "MEDIUM"),
        "risk_bonus":  pattern.get("risk_bonus", 10),
        "remediation": pattern.get("remediation", []),
        "detail":      detail,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Log metrics extractor (unchanged from v1)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_log_metrics(log_entries: List[Dict]) -> Dict[str, Any]:
    metrics: Dict[str, Any] = {
        "failed_ssh_logins": 0,
        "auth_failures":     0,
        "web_errors_4xx":    0,
        "web_errors_5xx":    0,
        "accepted_logins":   0,
        "sudo_events":       0,
        "kernel_errors":     0,
    }

    for entry in log_entries:
        msg    = (entry.get("message") or "").lower()
        level  = (entry.get("level")   or "").upper()
        status = entry.get("status", "")

        if ("failed password" in msg or "authentication failure" in msg
                or "invalid user" in msg):
            if "ssh" in (entry.get("process") or "").lower() or "sshd" in msg:
                metrics["failed_ssh_logins"] += 1
            metrics["auth_failures"] += 1
        elif level == "ERROR" and (
            "fail" in msg or "invalid" in msg or "denied" in msg
        ):
            metrics["auth_failures"] += 1

        if "accepted password" in msg or "accepted publickey" in msg:
            metrics["accepted_logins"] += 1

        if "sudo" in msg and "command" in msg:
            metrics["sudo_events"] += 1

        if level in ("ERROR", "CRIT") and entry.get("timestamp", "").startswith("["):
            metrics["kernel_errors"] += 1

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
# ML anomaly layer helper
# ─────────────────────────────────────────────────────────────────────────────

def _run_ml_detection(
    host_data: Dict,
    all_hosts: Optional[List[Dict]] = None,
) -> Optional[Dict]:
    """
    Run Isolation Forest anomaly detection on a single host.

    Strategy:
      1. If all_hosts is provided and has >= 3 entries, train on session data
      2. Otherwise, try to load a saved baseline from DEFAULT_BASELINE_PATH
      3. If neither works, return None silently

    Returns a Finding dict if an anomaly is detected, None otherwise.
    """
    try:
        from .anomaly_detector import (
            AnomalyDetector,
            train as ml_train,
            detect as ml_detect,
            load_baseline,
        )
        from pathlib import Path
    except ImportError:
        # scikit-learn not installed — skip silently
        return None

    result = None

    if all_hosts and len(all_hosts) >= 3:
        # Train on the current session hosts
        ml_train(all_hosts)
        anomaly = ml_detect(host_data)
    else:
        # Try loading a saved baseline
        baseline_path = Path(DEFAULT_BASELINE_PATH)
        if baseline_path.exists():
            try:
                detector = load_baseline(baseline_path)
                anomaly = detector.detect(host_data)
            except Exception:
                return None
        else:
            return None

    if anomaly and anomaly.is_anomaly:
        result = anomaly.to_finding()

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def correlate(
    host_data: Dict,
    all_hosts: Optional[List[Dict]] = None,
) -> List[Dict]:
    """
    Run all detection layers against a normalised host_data dict.

    Args:
        host_data   – single host dict from Munin scanner
        all_hosts   – optional list of ALL hosts in the current scan session.
                      When provided with >= 3 hosts, the ML layer trains on
                      them and uses that model to score host_data.
                      Pass None for single-host scans (baseline will be used).

    Returns:
        List of Finding dicts — rule-based + ML findings combined.
    """
    findings: List[Dict] = []

    ports       = host_data.get("ports", [])
    log_entries = host_data.get("logs", [])
    nse_results = host_data.get("vulnerabilities", {})

    open_port_nums = {
        p["port"] for p in ports if p.get("state") == "open"
    }

    metrics = _extract_log_metrics(log_entries)

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 1 — Rule-based detection (unchanged from v1)
    # ══════════════════════════════════════════════════════════════════════════

    # ── Rule 1: SSH Brute Force ───────────────────────────────────────────────
    if 22 in open_port_nums and metrics["failed_ssh_logins"] >= SSH_BRUTEFORCE_THRESHOLD:
        findings.append(_finding(
            "ssh_brute_force",
            f"{metrics['failed_ssh_logins']} failed SSH login(s) detected in logs",
        ))

    # ── Rule 2: Vulnerable Service Exposed ───────────────────────────────────
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
                break

    if high_cve_ports:
        findings.append(_finding(
            "vulnerable_service_exposed",
            "; ".join(high_cve_ports[:5]),
        ))

    # ── Rule 3: Web Error + CVE ───────────────────────────────────────────────
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

    # ── Rule 4: Critical Port Open ────────────────────────────────────────────
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

    # ── Rule 7: Cleartext Protocols ───────────────────────────────────────────
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

    # ── Rule 9: Auth Failure Spike ────────────────────────────────────────────
    already_ssh = any(f["pattern_id"] == "ssh_brute_force" for f in findings)
    if not already_ssh and metrics["auth_failures"] >= AUTH_FAILURE_THRESHOLD:
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

    # ══════════════════════════════════════════════════════════════════════════
    # LAYER 2 — ML anomaly detection (new in v2)
    # Only appends a finding if the ML model flags an anomaly AND
    # the host is not already CRITICAL from rule-based detection alone.
    # This avoids noise on hosts that rules already cover completely.
    # ══════════════════════════════════════════════════════════════════════════

    ml_finding = _run_ml_detection(host_data, all_hosts)

    if ml_finding:
        # Avoid duplicate signal: only add if ML found something rules missed
        rule_ids = {f["pattern_id"] for f in findings}
        if "ml_anomaly_detected" not in rule_ids:
            # If rules already found CRITICAL findings, downgrade ML to advisory
            rule_severities = {f["severity"] for f in findings}
            if "CRITICAL" in rule_severities:
                ml_finding["severity"]   = "LOW"
                ml_finding["risk_bonus"] = 0
                ml_finding["name"]       = "ML Anomaly (advisory — rules already critical)"
            findings.append(ml_finding)

    return findings
