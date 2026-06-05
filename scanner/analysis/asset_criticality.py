#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
asset_criticality.py — Asset Criticality Classification for Munin.

Classifies network hosts by business criticality and adjusts risk scores
accordingly. A database server rated CRITICAL gets heavier weight than a
development workstation rated LOW — same vulnerability, different impact.

Asset types recognized by heuristics (port fingerprinting + hostname):
  - domain_controller  (AD/LDAP: 88, 389, 636, 3268)
  - database           (MySQL/MSSQL/Postgres/MongoDB/Redis/Oracle)
  - web_server         (80/443 with Apache/Nginx/IIS)
  - mail_server        (25/587/993/995 + SMTP/IMAP banners)
  - file_server        (SMB 445, NFS 2049)
  - vpn_gateway        (500/1194/51820/1723)
  - backup_server      (Veeam, Backup Exec — hostname heuristics)
  - container_host     (Docker 2375/2376, Kubernetes 6443/10250)
  - iot_device         (Telnet 23, RTSP 554, UPNP 1900)
  - workstation        (RDP 3389, VNC 5900, no server indicators)
  - server             (catch-all: multiple open ports, no specific type)
  - unknown            (cannot determine)

Criticality levels:
  CRITICAL  — outage/breach directly impacts operations or data
  HIGH      — significant operational impact
  MEDIUM    — departmental impact
  LOW       — minimal operational impact (lab, dev, isolated)

Public API:
  classify_asset(host: dict) -> AssetProfile
  enrich_host_with_criticality(host: dict) -> dict   (mutates host in-place)
  apply_criticality_to_risk(score: int, level: str, criticality: str) -> tuple[int, str]
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

# ─────────────────────────────────────────────────────────────────────────────
# Port signatures per asset type
# ─────────────────────────────────────────────────────────────────────────────

_SIGNATURES: Dict[str, Dict] = {
    "domain_controller": {
        "ports":    {88, 389, 636, 3268, 3269, 464, 445},
        "required": {88},                 # Kerberos — definitive
        "services": {"kerberos", "ldap"},
        "default_criticality": "CRITICAL",
    },
    "database": {
        "ports":    {1433, 1521, 3306, 5432, 6379, 9200, 27017, 5984, 7474},
        "required": set(),
        "services": {"mysql", "mssql", "postgresql", "mongodb", "redis",
                     "elasticsearch", "oracle", "couchdb", "neo4j"},
        "default_criticality": "HIGH",
    },
    "web_server": {
        "ports":    {80, 443, 8080, 8443, 8000, 8888},
        "required": set(),
        "services": {"http", "https"},
        "products": {"apache", "nginx", "iis", "lighttpd", "caddy", "tomcat"},
        "default_criticality": "MEDIUM",
    },
    "mail_server": {
        "ports":    {25, 110, 143, 465, 587, 993, 995},
        "required": {25},
        "services": {"smtp", "imap", "pop3"},
        "default_criticality": "HIGH",
    },
    "file_server": {
        "ports":    {139, 445, 2049, 548},
        "required": set(),
        "services": {"smb", "netbios", "nfs", "afp"},
        "default_criticality": "HIGH",
    },
    "vpn_gateway": {
        "ports":    {500, 1194, 51820, 1723, 4500, 1701},
        "required": set(),
        "services": {"isakmp", "openvpn", "pptp", "l2tp"},
        "default_criticality": "CRITICAL",
    },
    "container_host": {
        "ports":    {2375, 2376, 4243, 6443, 10250, 10255, 2379, 2380},
        "required": set(),
        "services": {"docker", "kubernetes"},
        "default_criticality": "HIGH",
    },
    "backup_server": {
        "ports":    {9392, 9393, 9443, 10000},
        "required": set(),
        "services": set(),
        "hostname_patterns": [r"backup", r"veeam", r"bacula", r"netbackup", r"tsm"],
        "default_criticality": "HIGH",
    },
    "iot_device": {
        "ports":    {23, 554, 1900, 8883, 5683},
        "required": set(),
        "services": {"telnet", "rtsp", "ssdp", "mqtt"},
        "default_criticality": "MEDIUM",
    },
    "workstation": {
        "ports":    {3389, 5900, 5800},
        "required": set(),
        "services": {"rdp", "vnc"},
        "default_criticality": "LOW",
    },
}

# Hostname keyword → asset_type / criticality hint
_HOSTNAME_HINTS: List[Tuple[str, str, str]] = [
    # (regex, asset_type, criticality)
    (r"(dc|ad|ldap|kerberos)",      "domain_controller", "CRITICAL"),
    (r"(sql|db|mysql|postgres|ora)", "database",          "HIGH"),
    (r"(mail|smtp|mx|exchange)",     "mail_server",       "HIGH"),
    (r"(vpn|gateway|fw|firewall)",   "vpn_gateway",       "CRITICAL"),
    (r"(nas|fs|files|share|nfs)",    "file_server",       "HIGH"),
    (r"(docker|k8s|kube|container)", "container_host",    "HIGH"),
    (r"(backup|bkp|veeam|bacula)",   "backup_server",     "HIGH"),
    (r"(web|www|app|api|nginx)",     "web_server",        "MEDIUM"),
    (r"(cam|cctv|iot|sensor|plc)",   "iot_device",        "MEDIUM"),
    (r"(dev|test|lab|staging)",      None,                "LOW"),    # env hint only
    (r"(pc|ws|desktop|laptop)",      "workstation",       "LOW"),
]

_SCORE_MULTIPLIER: Dict[str, float] = {
    "CRITICAL": 1.35,
    "HIGH":     1.20,
    "MEDIUM":   1.00,
    "LOW":      0.80,
}

_SCORE_BANDS = [
    (81, "CRITICAL"),
    (51, "HIGH"),
    (21, "MEDIUM"),
    (5,  "LOW"),
    (0,  "MINIMAL"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Data class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AssetProfile:
    """Classification result for a single host."""
    ip:                 str
    hostname:           str
    asset_type:         str     # domain_controller | database | web_server | ...
    criticality:        str     # CRITICAL | HIGH | MEDIUM | LOW
    confidence:         str     # high | medium | low
    type_reason:        str     # human-readable reason for classification
    criticality_reason: str     # why this criticality level
    matched_ports:      List[int]
    matched_services:   List[str]

    def to_dict(self) -> dict:
        return {
            "asset_type":         self.asset_type,
            "criticality":        self.criticality,
            "confidence":         self.confidence,
            "type_reason":        self.type_reason,
            "criticality_reason": self.criticality_reason,
            "matched_ports":      self.matched_ports,
            "matched_services":   self.matched_services,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Classification logic
# ─────────────────────────────────────────────────────────────────────────────

def _open_port_set(host: dict) -> Set[int]:
    return {p["port"] for p in host.get("ports", []) if p.get("state") == "open"}


def _service_set(host: dict) -> Set[str]:
    return {
        (p.get("service") or "").lower()
        for p in host.get("ports", [])
        if p.get("state") == "open"
    }


def _product_set(host: dict) -> Set[str]:
    products = set()
    for p in host.get("ports", []):
        prod = (p.get("product") or "").lower()
        if prod:
            products.add(prod)
    return products


def _hostname_lower(host: dict) -> str:
    return (host.get("hostname") or host.get("ip", "")).lower()


def _match_signature(
    open_ports: Set[int],
    services:   Set[str],
    products:   Set[str],
    hostname:   str,
    sig_name:   str,
    sig:        Dict,
) -> Tuple[bool, int, List[int], List[str]]:
    """
    Score a host against one signature.
    Returns (matched, score, matched_ports, matched_services).
    """
    matched_ports    = list(open_ports & sig["ports"])
    matched_services = list(services   & sig.get("services", set()))

    score = len(matched_ports) * 2 + len(matched_services) * 3

    # Required ports must be present
    if sig["required"] and not (open_ports & sig["required"]):
        return False, 0, [], []

    # Product keyword match
    for prod_kw in sig.get("products", set()):
        if any(prod_kw in p for p in products):
            score += 4

    # Hostname pattern
    for pattern in sig.get("hostname_patterns", []):
        if re.search(pattern, hostname):
            score += 5

    matched = score > 0
    return matched, score, matched_ports, matched_services


def _classify_by_hostname(hostname: str) -> Tuple[Optional[str], Optional[str], str]:
    """
    Fast-path: guess type and criticality from hostname keywords.
    Returns (asset_type, criticality, reason) — type may be None.
    """
    for pattern, asset_type, crit in _HOSTNAME_HINTS:
        if re.search(pattern, hostname, re.IGNORECASE):
            reason = f"Hostname corresponde ao padrão '{pattern}'"
            return asset_type, crit, reason
    return None, None, ""


def classify_asset(host: dict) -> AssetProfile:
    """
    Classify a host and determine its business criticality.

    Classification priority:
      1. Signature matching (ports + services + products + hostname patterns)
      2. Hostname keyword hints
      3. Port count heuristic (many open ports → server)
      4. Default: unknown / LOW

    Args:
        host: Munin host dict (with 'ports', 'hostname' fields)

    Returns:
        AssetProfile
    """
    ip           = host.get("ip", "?")
    hostname     = _hostname_lower(host)
    open_ports   = _open_port_set(host)
    services     = _service_set(host)
    products     = _product_set(host)

    # ── 1. Signature matching ─────────────────────────────────────────────────
    best_name:  str  = "unknown"
    best_score: int  = 0
    best_ports: List[int] = []
    best_svcs:  List[str] = []

    for sig_name, sig in _SIGNATURES.items():
        matched, score, m_ports, m_svcs = _match_signature(
            open_ports, services, products, hostname, sig_name, sig
        )
        if matched and score > best_score:
            best_score = score
            best_name  = sig_name
            best_ports = m_ports
            best_svcs  = m_svcs

    # ── 2. Hostname hint fallback ─────────────────────────────────────────────
    hn_type, hn_crit, hn_reason = _classify_by_hostname(hostname)

    if best_name == "unknown" and hn_type:
        best_name = hn_type

    # ── 3. Port-count heuristic ───────────────────────────────────────────────
    if best_name == "unknown":
        if len(open_ports) >= 5:
            best_name = "server"
        elif open_ports:
            best_name = "workstation"

    # ── Determine criticality ─────────────────────────────────────────────────
    sig_crit    = _SIGNATURES.get(best_name, {}).get("default_criticality", "MEDIUM")
    final_crit  = sig_crit

    crit_reason = f"Tipo de ativo '{best_name}' classificado como {sig_crit} por padrão"

    # Hostname env hint (dev/test/lab → downgrade to LOW)
    if hn_crit == "LOW" and final_crit in ("MEDIUM", "LOW"):
        final_crit  = "LOW"
        crit_reason = f"Hostname indica ambiente não produtivo"
    elif hn_crit and hn_crit != "LOW":
        # Hostname hint can upgrade criticality
        crit_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if crit_order.get(hn_crit, 0) > crit_order.get(final_crit, 0):
            final_crit  = hn_crit
            crit_reason = f"{hn_reason} → elevado para {hn_crit}"

    # Confidence
    if best_score >= 6:    confidence = "high"
    elif best_score >= 2:  confidence = "medium"
    elif hn_type:          confidence = "medium"
    else:                  confidence = "low"

    type_reason = (
        f"Correspondência de {len(best_ports)} porta(s) e {len(best_svcs)} serviço(s) "
        f"para o tipo '{best_name}' (pontuação {best_score})"
        if best_score > 0
        else f"Classificado como '{best_name}' por heurística"
    )

    return AssetProfile(
        ip=ip,
        hostname=hostname or ip,
        asset_type=best_name,
        criticality=final_crit,
        confidence=confidence,
        type_reason=type_reason,
        criticality_reason=crit_reason,
        matched_ports=sorted(best_ports),
        matched_services=sorted(best_svcs),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Risk score adjustment
# ─────────────────────────────────────────────────────────────────────────────

def apply_criticality_to_risk(
    base_score:  int,
    base_level:  str,
    criticality: str,
) -> Tuple[int, str]:
    """
    Adjust a base risk score using asset criticality.

    CRITICAL assets get 35% boost; LOW assets get 20% reduction.
    The level label is recalculated after adjustment.

    Args:
        base_score:   0-100 risk score from risk_engine
        base_level:   "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "MINIMAL"
        criticality:  AssetProfile.criticality

    Returns:
        (adjusted_score, adjusted_level)
    """
    mult           = _SCORE_MULTIPLIER.get(criticality, 1.0)
    adjusted       = min(int(base_score * mult), 100)

    for threshold, label in _SCORE_BANDS:
        if adjusted >= threshold:
            return adjusted, label

    return adjusted, "MINIMAL"


# ─────────────────────────────────────────────────────────────────────────────
# Host enrichment (mutates host dict in-place)
# ─────────────────────────────────────────────────────────────────────────────

def enrich_host_with_criticality(host: dict) -> dict:
    """
    Classify the host, attach the AssetProfile, and adjust risk score.

    Adds to host dict:
      host["asset_type"]        – string
      host["asset_criticality"] – CRITICAL | HIGH | MEDIUM | LOW
      host["asset_profile"]     – full AssetProfile.to_dict()
      host["risk_score"]        – adjusted (may increase or decrease)
      host["risk_level"]        – recalculated after adjustment

    Args:
        host: Munin host dict (mutated in-place)

    Returns:
        The mutated host dict (same reference)
    """
    profile = classify_asset(host)

    host["asset_type"]        = profile.asset_type
    host["asset_criticality"] = profile.criticality
    host["asset_profile"]     = profile.to_dict()

    base_score = host.get("risk_score", 0)
    base_level = host.get("risk_level", "LOW")

    adj_score, adj_level = apply_criticality_to_risk(
        base_score, base_level, profile.criticality
    )

    host["risk_score_raw"]   = base_score
    host["risk_score"]       = adj_score
    host["risk_level"]       = adj_level

    return host


def enrich_all_hosts(hosts: List[dict]) -> List[dict]:
    """
    Classify and enrich all hosts in a scan result.

    Args:
        hosts: list of host dicts (mutated in-place)

    Returns:
        Same list (mutated)
    """
    for host in hosts:
        enrich_host_with_criticality(host)
    return hosts
