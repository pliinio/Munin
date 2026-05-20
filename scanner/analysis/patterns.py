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
Attack and threat patterns for Munin correlation engine.
Each pattern defines conditions (evaluated by the correlator) and
human-readable metadata used by the output layer.
"""

from typing import List, Dict

# ─────────────────────────────────────────────────────────────────────────────
# Pattern registry
# Each entry:
#   id          – unique snake_case identifier
#   name        – short display name
#   description – one sentence explanation shown in "Explain Mode"
#   severity    – CRITICAL | HIGH | MEDIUM | LOW
#   risk_bonus  – points added to base risk score when matched
#   remediation – ordered list of remediation steps
# ─────────────────────────────────────────────────────────────────────────────

PATTERNS: List[Dict] = [

    # ── 1. SSH Brute Force ───────────────────────────────────────────────────
    {
        "id":          "ssh_brute_force",
        "name":        "SSH Brute Force",
        "description": (
            "Multiple failed SSH login attempts detected on an exposed SSH service, "
            "indicating a likely dictionary or brute-force attack in progress."
        ),
        "severity":    "HIGH",
        "risk_bonus":  30,
        "remediation": [
            "Disable password authentication — use SSH keys only (PasswordAuthentication no)",
            "Move SSH to a non-standard port (e.g. 2222) to reduce noise",
            "Install fail2ban and set a low threshold (e.g. 5 attempts → 1h ban)",
            "Restrict SSH access to trusted IP ranges via firewall rules",
            "Enable two-factor authentication (e.g. Google Authenticator PAM module)",
        ],
    },

    # ── 2. Vulnerable Service Exposed ────────────────────────────────────────
    {
        "id":          "vulnerable_service_exposed",
        "name":        "Vulnerable Service Exposed",
        "description": (
            "One or more open ports are running services with known CVEs "
            "(CVSS ≥ 7.0), meaning a publicly documented exploit may already exist."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  35,
        "remediation": [
            "Immediately patch or upgrade the affected service to the latest stable version",
            "If patching is not possible, restrict the port to trusted IPs via firewall",
            "Check vendor advisories for temporary mitigations or workarounds",
            "Enable IDS/IPS rules targeting the specific CVE vector",
            "Schedule a follow-up scan after patching to confirm remediation",
        ],
    },

    # ── 3. Web Error + CVE (possible exploitation attempt) ───────────────────
    {
        "id":          "web_error_with_cve",
        "name":        "Web Exploitation Attempt",
        "description": (
            "Elevated HTTP 4xx/5xx error rate in access logs combined with a "
            "CVE on the web service suggests active scanning or exploitation probing."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Review access logs for patterns (repeated paths, scanner user-agents)",
            "Enable a Web Application Firewall (WAF) such as ModSecurity",
            "Update the web server and all installed frameworks/plugins",
            "Block offending IPs at the firewall level",
            "Enable rate-limiting and request-size limits on the web server",
        ],
    },

    # ── 4. Critical Port Open (RDP / SMB) ────────────────────────────────────
    {
        "id":          "critical_port_open",
        "name":        "Critical Port Exposed",
        "description": (
            "A high-risk service (RDP, SMB, Telnet, VNC, etc.) is reachable from "
            "the network, presenting a well-known lateral-movement or exploitation target."
        ),
        "severity":    "HIGH",
        "risk_bonus":  20,
        "remediation": [
            "Place the service behind a VPN — never expose RDP/SMB directly to the internet",
            "Apply the latest OS security patches (e.g. EternalBlue/BlueKeep fixes)",
            "Enable Network Level Authentication (NLA) for RDP",
            "Restrict access to the port by source IP using firewall rules",
            "Disable the service entirely if not required",
        ],
    },

    # ── 5. Large Attack Surface ───────────────────────────────────────────────
    {
        "id":          "large_attack_surface",
        "name":        "Large Attack Surface",
        "description": (
            "An unusually high number of open ports increases the likelihood "
            "that at least one service is misconfigured or unpatched."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  15,
        "remediation": [
            "Audit every open port and disable or firewall any non-essential service",
            "Apply the principle of least privilege — only expose what is required",
            "Run a monthly port scan baseline to detect unexpected new listeners",
            "Segment the host into an isolated VLAN if it must run many services",
        ],
    },

    # ── 6. NSE Confirmed Vulnerability ───────────────────────────────────────
    {
        "id":          "nse_confirmed_vuln",
        "name":        "NSE Confirmed Vulnerability",
        "description": (
            "Nmap NSE scripts returned a VULNERABLE result, meaning an active check "
            "confirmed that the host is susceptible to a specific known exploit."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  40,
        "remediation": [
            "Treat this as an emergency — patch or isolate the host immediately",
            "Check the NSE script output for the CVE ID and consult the vendor advisory",
            "Take a forensic snapshot of the system before making changes",
            "Rotate all credentials stored on or accessible from this host",
            "Conduct a full incident-response review to check for signs of compromise",
        ],
    },

    # ── 7. Telnet / FTP (cleartext protocols) ────────────────────────────────
    {
        "id":          "cleartext_protocol",
        "name":        "Cleartext Protocol in Use",
        "description": (
            "Telnet or FTP is open, transmitting credentials and data in plaintext "
            "which can be intercepted by any host on the same network segment."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  15,
        "remediation": [
            "Replace Telnet with SSH and FTP with SFTP or FTPS immediately",
            "If the service cannot be replaced, isolate it to a dedicated VLAN",
            "Audit who has credentials for these services and force a password reset",
            "Disable the service at the OS level (systemctl disable telnet/ftp)",
        ],
    },

    # ── 8. Database Port Exposed ──────────────────────────────────────────────
    {
        "id":          "database_exposed",
        "name":        "Database Port Exposed",
        "description": (
            "A database service (MySQL, PostgreSQL, MongoDB, Redis, MSSQL, Oracle) "
            "is reachable without a firewall, risking direct data exfiltration."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Bind the database to 127.0.0.1 (localhost only) in its configuration",
            "If remote access is required, restrict by IP and require TLS",
            "Audit database users — remove anonymous access and default credentials",
            "Enable database-level audit logging",
            "Place the database in a private VLAN behind the application tier",
        ],
    },

    # ── 9. Auth Failure Spike (generic — not SSH-specific) ───────────────────
    {
        "id":          "auth_failure_spike",
        "name":        "Authentication Failure Spike",
        "description": (
            "A high volume of authentication failures was detected in system logs, "
            "suggesting brute-force or credential-stuffing across one or more services."
        ),
        "severity":    "MEDIUM",
        "risk_bonus":  20,
        "remediation": [
            "Enable account lockout policies after N failed attempts",
            "Deploy fail2ban or equivalent to auto-block offending IPs",
            "Enable multi-factor authentication on all exposed services",
            "Investigate the source IPs and block entire ASNs if they are known threat actors",
        ],
    },

    # ── 10. Docker API Exposed ────────────────────────────────────────────────
    {
        "id":          "docker_api_exposed",
        "name":        "Docker API Exposed",
        "description": (
            "The Docker daemon API (port 2375/2376) is reachable, which allows "
            "full control over all containers and can be used for host escape."
        ),
        "severity":    "CRITICAL",
        "risk_bonus":  40,
        "remediation": [
            "Immediately close port 2375/2376 at the firewall",
            "Configure Docker to listen on a Unix socket only (remove -H tcp://:2375)",
            "If remote access is needed, enable TLS mutual authentication (--tlsverify)",
            "Audit running containers for unexpected images or processes",
        ],
    },

    # ── 11. ML Anomaly Detected ───────────────────────────────────────────────
    {
        "id":          "ml_anomaly_detected",
        "name":        "ML Anomaly Detected",
        "description": (
            "The Isolation Forest anomaly detector flagged this host as statistically "
            "unusual compared to the baseline of normal hosts in this scan session. "
            "This may indicate a zero-day attack, unexpected misconfiguration, or "
            "lateral movement not covered by rule-based detection."
        ),
        "severity":    "HIGH",
        "risk_bonus":  25,
        "remediation": [
            "Investigate the host manually — the anomaly may indicate a novel attack vector",
            "Compare current running services and open ports against a known-good baseline",
            "Check for unexpected processes, scheduled tasks, or recently installed software",
            "Review authentication logs for unusual login patterns or new user accounts",
            "Run a follow-up scan after investigation to confirm remediation",
        ],
    },
]

# Quick lookup by id
PATTERN_BY_ID: Dict[str, Dict] = {p["id"]: p for p in PATTERNS}
