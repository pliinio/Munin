#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
remediation_engine.py — Intelligent Remediation Prioritization for Munin.

Answers: "O que corrigimos primeiro?"

Scoring model:
  exploitability_score  (0-40)  — is there a known exploit? how easy?
  cvss_score            (0-30)  — highest CVSS among host CVEs
  exposure_score        (0-20)  — internet-facing? critical port?
  compliance_score      (0-10)  — how many compliance controls fail?

Priority labels:
  80-100 → Immediate   (act now — hours, not days)
  60-79  → High        (this week)
  40-59  → Medium      (this quarter)
  0-39   → Planned     (schedule next cycle)

Public API:
  prioritize(host: dict, compliance_score: dict | None) -> RemediationPlan
  prioritize_environment(hosts: list) -> list[RemediationPlan]
  top_actions(plans: list, n: int) -> list[str]
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Port sets (locally defined to avoid circular imports)
_INTERNET_FACING_PORTS = {21, 22, 23, 25, 53, 80, 443, 8080, 8443, 3389, 5900}
_CRITICAL_PORTS        = {23, 3389, 445, 5900, 5985, 4444, 2375, 2376}
_DATABASE_PORTS        = {1433, 1521, 2049, 3306, 5432, 6379, 9200, 27017}

# Patterns with confirmed/easy exploitability
_EXPLOITABLE_PATTERNS = {
    "nse_confirmed_vuln":      40,
    "vulnerable_service_exposed": 30,
    "docker_api_exposed":      35,
    "database_exposed":        25,
    "cleartext_protocol":      20,
    "ssh_brute_force":         15,
    "critical_port_open":      15,
    "web_error_with_cve":      20,
    "auth_failure_spike":      10,
    "ml_anomaly_detected":     10,
    "large_attack_surface":    5,
}

_SEVERITY_WEIGHT = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class RemediationItem:
    """A single prioritized remediation action."""
    priority_score: int
    priority_label: str   # Immediate | High | Medium | Planned
    action:         str
    source_finding: str   # pattern_id or "CVE"
    severity:       str
    ip:             str
    port:           Optional[int] = None
    cve_id:         Optional[str] = None


@dataclass
class RemediationPlan:
    """Complete remediation plan for a single host."""
    ip:             str
    hostname:       str
    priority_score: int         # 0-100
    priority_label: str         # Immediate | High | Medium | Planned
    risk_score:     int
    risk_level:     str
    items:          List[RemediationItem] = field(default_factory=list)

    # Score breakdown
    exploitability: int = 0
    cvss_component: int = 0
    exposure:       int = 0
    compliance_pen: int = 0

    def top_actions(self, n: int = 5) -> List[str]:
        """Return the top N deduplicated action strings."""
        seen: set = set()
        result: List[str] = []
        for item in sorted(self.items, key=lambda x: -x.priority_score):
            key = item.action.lower().strip()
            if key not in seen:
                seen.add(key)
                result.append(item.action)
            if len(result) >= n:
                break
        return result

    def to_dict(self) -> dict:
        return {
            "ip":             self.ip,
            "hostname":       self.hostname,
            "priority_score": self.priority_score,
            "priority_label": self.priority_label,
            "risk_score":     self.risk_score,
            "risk_level":     self.risk_level,
            "top_actions":    self.top_actions(5),
            "item_count":     len(self.items),
            "score_breakdown": {
                "exploitability": self.exploitability,
                "cvss":           self.cvss_component,
                "exposure":       self.exposure,
                "compliance":     self.compliance_pen,
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Scoring helpers
# ─────────────────────────────────────────────────────────────────────────────

def _exploitability_score(findings: List[Dict]) -> int:
    """0-40: How exploitable are the detected findings?"""
    max_exp = 0
    for f in findings:
        pid = f.get("pattern_id", "")
        exp = _EXPLOITABLE_PATTERNS.get(pid, 0)
        # Boost by severity
        sev_mult = _SEVERITY_WEIGHT.get(f.get("severity", "LOW"), 1) / 4
        exp = int(exp * (0.5 + sev_mult))
        max_exp = max(max_exp, exp)
    return min(max_exp, 40)


def _cvss_score(ports: List[Dict]) -> int:
    """0-30: Weighted by highest CVSS among all port CVEs."""
    max_cvss = 0.0
    for p in ports:
        for cve in p.get("cves", []):
            cvss = float(cve.get("cvss_score") or 0.0)
            max_cvss = max(max_cvss, cvss)
    if max_cvss >= 9.0:   return 30
    if max_cvss >= 7.0:   return 20
    if max_cvss >= 4.0:   return 10
    if max_cvss > 0:      return 5
    return 0


def _exposure_score(ports: List[Dict]) -> int:
    """0-20: Is the host internet-facing or exposing critical ports?"""
    open_ports = {p["port"] for p in ports if p.get("state") == "open"}
    score = 0
    if open_ports & _CRITICAL_PORTS:
        score += 12
    if open_ports & _INTERNET_FACING_PORTS:
        score += 5
    if open_ports & _DATABASE_PORTS:
        score += 8
    return min(score, 20)


def _compliance_penalty(compliance: Optional[Dict]) -> int:
    """0-10: Points from compliance failures."""
    if not compliance:
        return 0
    iso   = compliance.get("iso27001_score", 100)
    nist  = compliance.get("nist_score", 100)
    lgpd  = compliance.get("lgpd_exposure", "LOW")
    lgpd_pts = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 0}.get(lgpd, 0)
    score = int((100 - (iso + nist) / 2) / 10) + lgpd_pts
    return min(score, 10)


def _label_from_score(score: int) -> str:
    if score >= 80:  return "Immediate"
    if score >= 60:  return "High"
    if score >= 40:  return "Medium"
    return "Planned"


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def prioritize(
    host: Dict,
    compliance: Optional[Dict] = None,
) -> RemediationPlan:
    """
    Build a RemediationPlan for a single host.

    Args:
        host:       host dict from Munin scanner (with 'ports', 'findings', etc.)
        compliance: optional ComplianceScore.to_dict() for this host

    Returns:
        RemediationPlan
    """
    ip       = host.get("ip", "?")
    hostname = host.get("hostname") or ip
    ports    = host.get("ports", [])
    findings = host.get("findings", [])
    risk_s   = host.get("risk_score", 0)
    risk_l   = host.get("risk_level", "LOW")

    exp_s  = _exploitability_score(findings)
    cvss_s = _cvss_score(ports)
    expo_s = _exposure_score(ports)
    comp_s = _compliance_penalty(compliance)

    total  = min(exp_s + cvss_s + expo_s + comp_s, 100)
    label  = _label_from_score(total)

    # ── Build action items ─────────────────────────────────────────────────
    items: List[RemediationItem] = []

    # From findings — use their remediation steps
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(
        findings,
        key=lambda f: (sev_order.get(f.get("severity", "LOW"), 3),
                       -_EXPLOITABLE_PATTERNS.get(f.get("pattern_id", ""), 0))
    )

    for f in sorted_findings:
        pid     = f.get("pattern_id", "")
        sev     = f.get("severity", "MEDIUM")
        exp_pts = _EXPLOITABLE_PATTERNS.get(pid, 5)
        f_score = min(exp_pts + comp_s, 100)
        f_label = _label_from_score(f_score)

        for step in f.get("remediation", [])[:3]:
            items.append(RemediationItem(
                priority_score=f_score,
                priority_label=f_label,
                action=step,
                source_finding=f.get("name", pid),
                severity=sev,
                ip=ip,
            ))

    # From high-severity CVEs — add patch action
    for p in ports:
        for cve in p.get("cves", []):
            cvss = float(cve.get("cvss_score") or 0.0)
            if cvss >= 7.0:
                cve_id  = cve.get("id", "")
                service = p.get("product") or p.get("service") or str(p.get("port", "?"))
                items.append(RemediationItem(
                    priority_score=_cvss_score([p]),
                    priority_label=_label_from_score(_cvss_score([p])),
                    action=f"Patch {service} — {cve_id} (CVSS {cvss})",
                    source_finding="CVE",
                    severity="CRITICAL" if cvss >= 9 else "HIGH",
                    ip=ip,
                    port=p.get("port"),
                    cve_id=cve_id,
                ))

    # Sort items by priority_score desc
    items.sort(key=lambda x: -x.priority_score)

    return RemediationPlan(
        ip=ip,
        hostname=hostname,
        priority_score=total,
        priority_label=label,
        risk_score=risk_s,
        risk_level=risk_l,
        items=items,
        exploitability=exp_s,
        cvss_component=cvss_s,
        exposure=expo_s,
        compliance_pen=comp_s,
    )


def prioritize_environment(
    hosts: List[Dict],
    compliance_scores: Optional[List[Dict]] = None,
) -> List[RemediationPlan]:
    """
    Build RemediationPlans for all hosts in a scan session, sorted by priority.

    Args:
        hosts:             list of host dicts
        compliance_scores: optional list of ComplianceScore.to_dict() (same order as hosts)

    Returns:
        List of RemediationPlan sorted by priority_score desc (highest first)
    """
    plans = []
    for i, host in enumerate(hosts):
        comp = compliance_scores[i] if compliance_scores and i < len(compliance_scores) else None
        plans.append(prioritize(host, comp))

    plans.sort(key=lambda p: -p.priority_score)
    return plans


def top_actions(plans: List[RemediationPlan], n: int = 10) -> List[str]:
    """
    Return the top N unique remediation actions across all plans.
    Deduplicated and sorted by priority.
    """
    seen: set = set()
    result: List[str] = []

    # Flatten all items sorted by priority_score desc
    all_items: List[RemediationItem] = []
    for plan in plans:
        all_items.extend(plan.items)
    all_items.sort(key=lambda x: -x.priority_score)

    for item in all_items:
        key = item.action.lower().strip()
        if key not in seen:
            seen.add(key)
            result.append(f"[{item.priority_label.upper()}] [{item.ip}] {item.action}")
        if len(result) >= n:
            break

    return result
