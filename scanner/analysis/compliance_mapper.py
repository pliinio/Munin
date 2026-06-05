#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
compliance_mapper.py — GRC Framework Mapping Engine for Munin.

Maps each detected finding/pattern to the relevant controls across:
  - NIST Cybersecurity Framework (CSF) 2.0
  - ISO 27001:2022 Annex A
  - CIS Controls v8
  - MITRE ATT&CK (technique IDs)
  - LGPD / GDPR (when applicable)

Public API:
  map_finding(finding: dict) -> ComplianceRef
  map_findings(findings: list) -> list[ComplianceRef]
  compliance_score(findings: list) -> ComplianceScore
  format_compliance_report(score: ComplianceScore) -> str
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Mapping database
# ─────────────────────────────────────────────────────────────────────────────

# Structure per pattern_id:
#   mitre      – ATT&CK technique IDs
#   nist_csf   – NIST CSF 2.0 function.category codes
#   iso27001   – ISO 27001:2022 Annex A controls
#   cis        – CIS Controls v8 safeguard IDs
#   lgpd       – LGPD article references (with Portuguese context)
#   gdpr       – GDPR article references
#   control_family – short label for grouping

_MAPPING_DB: Dict[str, Dict] = {

    "ssh_brute_force": {
        "mitre":        ["T1110", "T1110.001", "T1078"],
        "nist_csf":     ["PR.AC-7", "DE.CM-3", "RS.AN-1"],
        "iso27001":     ["A.5.15", "A.5.16", "A.8.16", "A.8.5"],
        "cis":          ["CIS-05", "CIS-06.02", "CIS-13.10"],
        "lgpd":         ["Art. 46 (Medidas de Segurança)", "Art. 47 (Agentes de Tratamento)"],
        "gdpr":         ["Art. 32 (Security of processing)"],
        "control_family": "Controle de Acesso",
        "severity_weight": 3,
    },

    "vulnerable_service_exposed": {
        "mitre":        ["T1190", "T1203", "T1068"],
        "nist_csf":     ["ID.RA-1", "ID.RA-2", "PR.IP-12", "RS.MI-3"],
        "iso27001":     ["A.8.8", "A.8.7", "A.12.6"],
        "cis":          ["CIS-07.01", "CIS-07.03", "CIS-07.07"],
        "lgpd":         ["Art. 46 (Medidas técnicas e administrativas)"],
        "gdpr":         ["Art. 32", "Art. 25 (Data protection by design)"],
        "control_family": "Gestão de Vulnerabilidades",
        "severity_weight": 4,
    },

    "web_error_with_cve": {
        "mitre":        ["T1190", "T1059.007", "T1505.003"],
        "nist_csf":     ["DE.CM-8", "ID.RA-1", "PR.DS-2"],
        "iso27001":     ["A.8.9", "A.14.2", "A.12.4"],
        "cis":          ["CIS-16.01", "CIS-16.02", "CIS-07.03"],
        "lgpd":         ["Art. 46", "Art. 48 (Comunicação de Incidentes)"],
        "gdpr":         ["Art. 32", "Art. 33 (Notification of breach)"],
        "control_family": "Segurança de Aplicações",
        "severity_weight": 3,
    },

    "critical_port_open": {
        "mitre":        ["T1021", "T1021.001", "T1021.002", "T1133"],
        "nist_csf":     ["PR.AC-5", "PR.PT-3", "DE.CM-1"],
        "iso27001":     ["A.8.20", "A.8.21", "A.5.14"],
        "cis":          ["CIS-12.01", "CIS-12.02", "CIS-04.05"],
        "lgpd":         ["Art. 46 §1 (Acesso Não Autorizado)"],
        "gdpr":         ["Art. 32.1(b) (Confidentiality and integrity)"],
        "control_family": "Segurança de Rede",
        "severity_weight": 3,
    },

    "large_attack_surface": {
        "mitre":        ["T1046", "T1595.001"],
        "nist_csf":     ["PR.IP-1", "ID.AM-2", "PR.AC-4"],
        "iso27001":     ["A.8.8", "A.8.20", "A.5.19"],
        "cis":          ["CIS-04.01", "CIS-12.01", "CIS-16.09"],
        "lgpd":         ["Art. 46 (Princípio da necessidade)"],
        "gdpr":         ["Art. 25 (Data minimisation)"],
        "control_family": "Gestão de Superfície de Ataque",
        "severity_weight": 2,
    },

    "nse_confirmed_vuln": {
        "mitre":        ["T1190", "T1068", "T1210"],
        "nist_csf":     ["RS.MI-3", "RS.AN-2", "DE.CM-8", "ID.RA-3"],
        "iso27001":     ["A.8.8", "A.5.29", "A.6.8"],
        "cis":          ["CIS-07.01", "CIS-07.02", "CIS-07.07"],
        "lgpd":         ["Art. 46", "Art. 48 (Incidente de Segurança)"],
        "gdpr":         ["Art. 32", "Art. 33", "Art. 34"],
        "control_family": "Resposta a Incidentes",
        "severity_weight": 4,
    },

    "cleartext_protocol": {
        "mitre":        ["T1040", "T1557", "T1110"],
        "nist_csf":     ["PR.DS-2", "PR.DS-5", "PR.AC-3"],
        "iso27001":     ["A.8.24", "A.8.20", "A.8.9"],
        "cis":          ["CIS-03.10", "CIS-12.06"],
        "lgpd":         ["Art. 46 (Criptografia em trânsito)", "Art. 46 §1"],
        "gdpr":         ["Art. 32.1(a) (Encryption)"],
        "control_family": "Criptografia e Proteção de Dados",
        "severity_weight": 2,
    },

    "database_exposed": {
        "mitre":        ["T1213", "T1078", "T1530"],
        "nist_csf":     ["PR.DS-1", "PR.DS-2", "PR.AC-4"],
        "iso27001":     ["A.8.2", "A.8.3", "A.8.11", "A.5.34"],
        "cis":          ["CIS-03.01", "CIS-03.03", "CIS-12.01"],
        "lgpd":         ["Art. 46", "Art. 48 (Vazamento de Dados)", "Art. 52 (Sanções)"],
        "gdpr":         ["Art. 32", "Art. 83 (Administrative fines)"],
        "control_family": "Proteção de Dados",
        "severity_weight": 4,
    },

    "auth_failure_spike": {
        "mitre":        ["T1110", "T1110.003", "T1110.004"],
        "nist_csf":     ["DE.CM-3", "PR.AC-7", "DE.AE-2"],
        "iso27001":     ["A.8.5", "A.8.16", "A.5.16"],
        "cis":          ["CIS-06.02", "CIS-13.10"],
        "lgpd":         ["Art. 46", "Art. 47"],
        "gdpr":         ["Art. 32"],
        "control_family": "Identidade e Autenticação",
        "severity_weight": 2,
    },

    "docker_api_exposed": {
        "mitre":        ["T1611", "T1610", "T1552.007"],
        "nist_csf":     ["PR.AC-4", "PR.IP-1", "DE.CM-7"],
        "iso27001":     ["A.8.20", "A.8.9", "A.8.25"],
        "cis":          ["CIS-04.06", "CIS-12.01"],
        "lgpd":         ["Art. 46 §1 (Acesso Privilegiado Não Autorizado)"],
        "gdpr":         ["Art. 32"],
        "control_family": "Segurança de Containers",
        "severity_weight": 4,
    },

    "ml_anomaly_detected": {
        "mitre":        ["T1071", "T1036", "T1027"],
        "nist_csf":     ["DE.AE-1", "DE.AE-3", "ID.RA-6"],
        "iso27001":     ["A.8.16", "A.12.4", "A.5.28"],
        "cis":          ["CIS-08.01", "CIS-08.02", "CIS-13.06"],
        "lgpd":         ["Art. 46 (Detecção de Anomalias)"],
        "gdpr":         ["Art. 32.1(d) (Ongoing testing)"],
        "control_family": "Detecção de Ameaças",
        "severity_weight": 3,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# NIST CSF category weights (for compliance score calculation)
# Lower score = better compliance
# ─────────────────────────────────────────────────────────────────────────────

_NIST_FUNCTIONS = {
    "GV": "Governar",
    "ID": "Identificar",
    "PR": "Proteger",
    "DE": "Detectar",
    "RS": "Responder",
    "RC": "Recuperar",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ComplianceRef:
    """Compliance references for a single finding."""
    pattern_id:     str
    finding_name:   str
    severity:       str
    mitre:          List[str]
    nist_csf:       List[str]
    iso27001:       List[str]
    cis:            List[str]
    lgpd:           List[str]
    gdpr:           List[str]
    control_family: str
    severity_weight: int = 1

    def to_dict(self) -> dict:
        return {
            "pattern_id":     self.pattern_id,
            "finding_name":   self.finding_name,
            "severity":       self.severity,
            "mitre":          self.mitre,
            "nist_csf":       self.nist_csf,
            "iso27001":       self.iso27001,
            "cis":            self.cis,
            "lgpd":           self.lgpd,
            "gdpr":           self.gdpr,
            "control_family": self.control_family,
        }


@dataclass
class ComplianceScore:
    """Aggregated compliance posture for a host or environment."""

    # Per-framework percentage scores (0–100, higher = better posture)
    iso27001_score: float = 100.0
    nist_score:     float = 100.0
    cis_score:      float = 100.0
    lgpd_exposure:  str   = "LOW"   # LOW | MEDIUM | HIGH | CRITICAL

    # Broken down by NIST function
    nist_by_function: Dict[str, float] = field(default_factory=dict)

    # Control families with failures
    failed_families: List[str]  = field(default_factory=list)
    failed_controls: List[str]  = field(default_factory=list)

    # Summary
    total_control_failures: int = 0
    overall_label: str = "Bom"   # Bom | Regular | Fraco | Crítico

    def to_dict(self) -> dict:
        return {
            "iso27001_score":        round(self.iso27001_score, 1),
            "nist_score":            round(self.nist_score, 1),
            "cis_score":             round(self.cis_score, 1),
            "lgpd_exposure":         self.lgpd_exposure,
            "nist_by_function":      {k: round(v, 1) for k, v in self.nist_by_function.items()},
            "failed_families":       self.failed_families,
            "failed_controls":       self.failed_controls[:10],
            "total_control_failures":self.total_control_failures,
            "overall_label":         self.overall_label,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def map_finding(finding: Dict) -> Optional[ComplianceRef]:
    """
    Map a single Finding dict to its compliance references.

    Args:
        finding: dict with at least 'pattern_id', 'name', 'severity'

    Returns:
        ComplianceRef or None if pattern is unknown
    """
    pid  = finding.get("pattern_id") or finding.get("id", "")
    data = _MAPPING_DB.get(pid)
    if not data:
        return None

    return ComplianceRef(
        pattern_id=pid,
        finding_name=finding.get("name", pid),
        severity=finding.get("severity", "MEDIUM"),
        mitre=data.get("mitre", []),
        nist_csf=data.get("nist_csf", []),
        iso27001=data.get("iso27001", []),
        cis=data.get("cis", []),
        lgpd=data.get("lgpd", []),
        gdpr=data.get("gdpr", []),
        control_family=data.get("control_family", "General"),
        severity_weight=data.get("severity_weight", 1),
    )


def map_findings(findings: List[Dict]) -> List[ComplianceRef]:
    """Map a list of findings to ComplianceRef objects. Skips unknown patterns."""
    result = []
    for f in findings:
        ref = map_finding(f)
        if ref:
            result.append(ref)
    return result


def enrich_finding_with_compliance(finding: Dict) -> Dict:
    """
    Add 'compliance' key to a finding dict in-place.

    Usage:
        for f in findings:
            enrich_finding_with_compliance(f)
    """
    ref = map_finding(finding)
    if ref:
        finding["compliance"] = ref.to_dict()
    return finding


def compliance_score(findings: List[Dict], host_risk_score: int = 0) -> ComplianceScore:
    """
    Calculate a compliance posture score for a host based on its findings.

    Scoring logic:
      - Each finding deducts points weighted by severity_weight and finding severity
      - ISO 27001 score: starts at 100, deducts per violated control
      - NIST score: starts at 100, deducts per violated function
      - CIS score: starts at 100, deducts per violated safeguard
      - LGPD exposure: derived from presence of data-related violations

    Args:
        findings:         list of Finding dicts
        host_risk_score:  0-100 base risk score from risk_engine

    Returns:
        ComplianceScore dataclass
    """
    refs = map_findings(findings)

    if not refs:
        return ComplianceScore(
            iso27001_score=100.0,
            nist_score=100.0,
            cis_score=100.0,
            lgpd_exposure="LOW",
            overall_label="Bom",
        )

    # ── ISO 27001 ─────────────────────────────────────────────────────────────
    violated_iso = set()
    for ref in refs:
        for ctrl in ref.iso27001:
            violated_iso.add(ctrl)

    # Each unique control violation costs points (weighted by severity)
    iso_deduction = 0
    for ref in refs:
        weight = ref.severity_weight
        sev_mult = {"CRITICAL": 2.5, "HIGH": 2.0, "MEDIUM": 1.5, "LOW": 1.0}.get(ref.severity, 1.0)
        iso_deduction += weight * sev_mult * 2   # base 2 pts per control per finding
    iso_score = max(0.0, 100.0 - min(iso_deduction, 100.0))

    # ── NIST CSF ──────────────────────────────────────────────────────────────
    violated_nist = {}   # function -> count of violations
    for ref in refs:
        for ctrl in ref.nist_csf:
            func = ctrl.split(".")[0]  # e.g. "PR" from "PR.AC-7"
            violated_nist[func] = violated_nist.get(func, 0) + ref.severity_weight

    nist_by_function: Dict[str, float] = {}
    for func in _NIST_FUNCTIONS:
        violations = violated_nist.get(func, 0)
        nist_by_function[func] = max(0.0, 100.0 - violations * 8)

    nist_score = sum(nist_by_function.values()) / len(_NIST_FUNCTIONS) if nist_by_function else 100.0

    # ── CIS Controls ─────────────────────────────────────────────────────────
    violated_cis = set()
    for ref in refs:
        for ctrl in ref.cis:
            violated_cis.add(ctrl)

    cis_deduction = len(violated_cis) * 6
    cis_score = max(0.0, 100.0 - cis_deduction)

    # ── LGPD exposure ─────────────────────────────────────────────────────────
    data_critical_patterns = {"database_exposed", "nse_confirmed_vuln", "vulnerable_service_exposed"}
    data_high_patterns     = {"cleartext_protocol", "ssh_brute_force", "docker_api_exposed"}
    data_medium_patterns   = {"auth_failure_spike", "web_error_with_cve", "critical_port_open"}

    active_pids = {ref.pattern_id for ref in refs}
    if active_pids & data_critical_patterns:
        lgpd_exposure = "CRITICAL"
    elif active_pids & data_high_patterns:
        lgpd_exposure = "HIGH"
    elif active_pids & data_medium_patterns:
        lgpd_exposure = "MEDIUM"
    else:
        lgpd_exposure = "LOW"

    # ── Failed controls summary ───────────────────────────────────────────────
    failed_families = list({ref.control_family for ref in refs})
    failed_controls = list(violated_iso | violated_cis)

    total_failures = len(violated_iso) + len(violated_cis) + sum(violated_nist.values())

    # ── Overall label ─────────────────────────────────────────────────────────
    avg = (iso_score + nist_score + cis_score) / 3
    if avg >= 80:
        overall_label = "Bom"
    elif avg >= 60:
        overall_label = "Regular"
    elif avg >= 35:
        overall_label = "Fraco"
    else:
        overall_label = "Crítico"

    return ComplianceScore(
        iso27001_score=round(iso_score, 1),
        nist_score=round(nist_score, 1),
        cis_score=round(cis_score, 1),
        lgpd_exposure=lgpd_exposure,
        nist_by_function=nist_by_function,
        failed_families=sorted(failed_families),
        failed_controls=sorted(failed_controls)[:15],
        total_control_failures=total_failures,
        overall_label=overall_label,
    )


def environment_compliance_score(all_hosts: List[Dict]) -> Dict:
    """
    Aggregate compliance scores across all hosts in a scan session.

    Args:
        all_hosts: list of host dicts (each with 'findings' key)

    Returns:
        dict with per-framework averages and environment-level LGPD exposure
    """
    if not all_hosts:
        return {
            "iso27001_avg": 100.0,
            "nist_avg":     100.0,
            "cis_avg":      100.0,
            "lgpd_exposure": "LOW",
            "overall_label": "Bom",
            "host_scores":  [],
        }

    scores = []
    for host in all_hosts:
        findings  = host.get("findings", [])
        risk      = host.get("risk_score", 0)
        cs        = compliance_score(findings, risk)
        scores.append({
            "ip":            host.get("ip", "?"),
            "iso27001_score": cs.iso27001_score,
            "nist_score":     cs.nist_score,
            "cis_score":      cs.cis_score,
            "lgpd_exposure":  cs.lgpd_exposure,
            "overall_label":  cs.overall_label,
        })

    iso_avg  = sum(s["iso27001_score"] for s in scores) / len(scores)
    nist_avg = sum(s["nist_score"]     for s in scores) / len(scores)
    cis_avg  = sum(s["cis_score"]      for s in scores) / len(scores)

    # Worst-case LGPD exposure across environment
    lgpd_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    worst_lgpd = max(scores, key=lambda s: lgpd_order.get(s["lgpd_exposure"], 0))["lgpd_exposure"]

    avg = (iso_avg + nist_avg + cis_avg) / 3
    if avg >= 80:   overall_label = "Bom"
    elif avg >= 60: overall_label = "Regular"
    elif avg >= 35: overall_label = "Fraco"
    else:           overall_label = "Crítico"

    return {
        "iso27001_avg":  round(iso_avg, 1),
        "nist_avg":      round(nist_avg, 1),
        "cis_avg":       round(cis_avg, 1),
        "lgpd_exposure": worst_lgpd,
        "overall_label": overall_label,
        "host_scores":   scores,
    }


def format_compliance_report(cs: ComplianceScore, host_ip: str = "") -> str:
    """
    Format a ComplianceScore as a plain-text compliance report.

    Args:
        cs:      ComplianceScore from compliance_score()
        host_ip: optional IP for the header

    Returns:
        Multi-line string report
    """
    lines = []
    header = f"Postura de Conformidade — {host_ip}" if host_ip else "Postura de Conformidade"
    lines.append("=" * 60)
    lines.append(header)
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"  Geral:            {cs.overall_label}")
    lines.append(f"  ISO 27001:2022    {cs.iso27001_score:.0f}%")
    lines.append(f"  NIST CSF 2.0:     {cs.nist_score:.0f}%")
    lines.append(f"  CIS Controls v8:  {cs.cis_score:.0f}%")
    lines.append(f"  Exposição LGPD:   {cs.lgpd_exposure}")
    lines.append("")

    if cs.nist_by_function:
        lines.append("  NIST CSF por Função:")
        for func, func_name in _NIST_FUNCTIONS.items():
            score = cs.nist_by_function.get(func, 100.0)
            bar   = "█" * int(score / 10) + "░" * (10 - int(score / 10))
            lines.append(f"    {func} {func_name:<12}  {bar}  {score:.0f}%")
        lines.append("")

    if cs.failed_families:
        lines.append(f"  Famílias de Controle com Falhas ({len(cs.failed_families)}):")
        for fam in cs.failed_families:
            lines.append(f"    - {fam}")
        lines.append("")

    if cs.failed_controls:
        lines.append(f"  Controles com Falha (amostra):")
        for ctrl in cs.failed_controls[:8]:
            lines.append(f"    - {ctrl}")
        if len(cs.failed_controls) > 8:
            lines.append(f"    ... e mais {len(cs.failed_controls) - 8}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)
