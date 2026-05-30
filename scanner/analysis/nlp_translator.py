#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

"""
nlp_translator.py — NLP layer for Munin.

Translates raw technical findings (CVEs, port data, correlation results)
into plain-language business reports targeted at non-technical audiences:
coordinators, managers, and auditors.

Architecture:
  - Primary  : Ollama (local LLM — free, no API key, runs on Kali)
  - Fallback : Rule-based templates (works offline, no dependencies)
  - Cache    : In-memory per session (avoids repeated model calls)

Supported Ollama models (in order of preference):
  mistral, llama3, llama3.2, gemma2, phi3, qwen2, deepseek-r1

Quick setup (Kali):
  curl -fsSL https://ollama.com/install.sh | sh
  ollama pull mistral          # ~4GB, best quality/speed balance
  ollama serve                 # starts on localhost:11434

Public API:
  translate_findings(host_data, findings, score, level) -> BusinessReport
  translate_batch(hosts: list[dict]) -> list[BusinessReport]
  set_model(model: str) -> None        # e.g. "mistral", "llama3"
  set_ollama_url(url: str) -> None     # default: http://localhost:11434
  set_audience(audience: str) -> None  # "manager" | "auditor" | "board"
  is_ollama_available() -> bool
  clear_cache() -> None
"""

from __future__ import annotations

import json
import time
import hashlib
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("munin.nlp")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

_OLLAMA_URL   = "http://localhost:11434"
_MODEL        = "llama3.2:latest"      # updated default
_TIMEOUT      = 300
_MAX_RETRIES  = 1
_MODEL_SYNCED = False                  # tracks if auto_select ran this session

# Preferred models — tried in order when auto-detecting
_PREFERRED_MODELS = [
    "mistral", "llama3", "llama3.2", "gemma2", "phi3", "qwen2", "deepseek-r1"
]

_current_audience = "manager"

# In-memory cache: sha256(input_repr) -> BusinessReport
_cache: Dict[str, "BusinessReport"] = {}


# ─────────────────────────────────────────────────────────────────────────────
# Audience personas
# ─────────────────────────────────────────────────────────────────────────────

_AUDIENCE_PROFILES = {
    "manager": (
        "You are writing for a non-technical IT manager or department coordinator. "
        "Use simple language. Avoid acronyms unless explained. Focus on business impact "
        "and financial/operational risk. Keep each finding to 2-3 sentences."
    ),
    "auditor": (
        "You are writing for an internal or external IT auditor familiar with ISO 27001 "
        "and LGPD/GDPR. Use compliance-oriented language. Reference control families "
        "where appropriate (e.g. A.12 Operations, A.13 Communications). "
        "Be precise and evidence-based."
    ),
    "board": (
        "You are writing for a board of directors or C-suite executive. "
        "Use business language only. No technical terms. Focus exclusively on "
        "financial exposure, regulatory risk, and reputational impact. "
        "Be concise — maximum 3 bullet points per host."
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BusinessReport:
    """Plain-language output for a single host."""

    ip:               str
    hostname:         str
    risk_level:       str        # CRITICAL / HIGH / MEDIUM / LOW
    score:            int

    # NLP-generated fields
    executive_summary: str       # 2-3 sentence plain summary
    business_impact:   str       # What could go wrong in business terms
    compliance_flags:  List[str] # e.g. ["LGPD Art. 46", "ISO 27001 A.12.6"]
    priority_actions:  List[str] # Plain English, no jargon
    urgency_label:     str       # "Immediate" | "This week" | "This quarter" | "Monitor"

    # Metadata
    generated_by: str   = "ollama"    # "ollama" | "template"
    model:        str   = _MODEL
    audience:     str   = "manager"
    generated_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "ip":                self.ip,
            "hostname":          self.hostname,
            "risk_level":        self.risk_level,
            "score":             self.score,
            "executive_summary": self.executive_summary,
            "business_impact":   self.business_impact,
            "compliance_flags":  self.compliance_flags,
            "priority_actions":  self.priority_actions,
            "urgency_label":     self.urgency_label,
            "generated_by":      self.generated_by,
            "model":             self.model,
            "audience":          self.audience,
        }

    def to_markdown(self) -> str:
        lines = [
            f"## {self.ip}  —  {self.risk_level} ({self.score}/100)",
            f"**Urgency:** {self.urgency_label}  "
            f"*[generated by {self.generated_by} / {self.model}]*",
            "",
            "### Summary",
            self.executive_summary,
            "",
            "### Business Impact",
            self.business_impact,
        ]
        if self.compliance_flags:
            lines += ["", "### Compliance Flags"]
            lines += [f"- {c}" for c in self.compliance_flags]
        lines += ["", "### Priority Actions"]
        lines += [f"{i+1}. {a}" for i, a in enumerate(self.priority_actions)]
        return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Public configuration helpers
# ─────────────────────────────────────────────────────────────────────────────

def set_model(model: str) -> None:
    """Set the Ollama model to use. E.g. 'mistral', 'llama3', 'gemma2'."""
    global _MODEL
    _MODEL = model.strip()
    logger.info(f"NLP: Ollama model set to '{_MODEL}'.")


def set_ollama_url(url: str) -> None:
    """Override the Ollama server URL (default: http://localhost:11434)."""
    global _OLLAMA_URL
    _OLLAMA_URL = url.rstrip("/")
    logger.info(f"NLP: Ollama URL set to '{_OLLAMA_URL}'.")


def set_audience(audience: str) -> None:
    """Set the target audience. Valid: 'manager', 'auditor', 'board'."""
    global _current_audience
    if audience not in _AUDIENCE_PROFILES:
        raise ValueError(
            f"Unknown audience '{audience}'. "
            f"Choose from: {list(_AUDIENCE_PROFILES)}"
        )
    _current_audience = audience
    logger.info(f"NLP: Audience set to '{audience}'.")


def clear_cache() -> None:
    """Clear the in-memory translation cache."""
    _cache.clear()
    logger.info("NLP: Cache cleared.")


def is_ollama_available() -> bool:
    """
    Check if Ollama is running and reachable.
    Returns True if the /api/tags endpoint responds.
    """
    try:
        req = urllib.request.Request(
            f"{_OLLAMA_URL}/api/tags",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def list_ollama_models() -> List[str]:
    """Return list of model names currently pulled in Ollama."""
    try:
        req = urllib.request.Request(f"{_OLLAMA_URL}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return [m["name"].split(":")[0] for m in data.get("models", [])]
    except Exception:
        return []


def auto_select_model() -> Optional[str]:
    """
    Auto-select the best available model from the preferred list.
    Sets _MODEL globally if a match is found.
    Returns the selected model name or None.
    """
    global _MODEL
    available = list_ollama_models()
    for preferred in _PREFERRED_MODELS:
        if preferred in available:
            _MODEL = preferred
            logger.info(f"NLP: Auto-selected model '{_MODEL}'.")
            return _MODEL
    if available:
        _MODEL = available[0]
        logger.info(f"NLP: Using first available model '{_MODEL}'.")
        return _MODEL
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Core translation
# ─────────────────────────────────────────────────────────────────────────────

def translate_findings(
    host_data: Dict,
    findings:  List[Dict],
    score:     int,
    level:     str,
    audience:  Optional[str] = None,
) -> BusinessReport:
    """
    Translate technical scan findings into a plain-language BusinessReport.

    Tries Ollama first. Falls back to rule-based templates if Ollama is
    unavailable, the model is not pulled, or generation fails.

    Args:
        host_data – host dict from Munin scanner (ip, hostname, os, ports…)
        findings  – list of Finding dicts from correlator.correlate()
        score     – 0-100 risk score from risk_engine.calculate_risk()
        level     – severity label (CRITICAL/HIGH/MEDIUM/LOW)
        audience  – override global audience for this call

    Returns:
        BusinessReport — always returns, never raises.
    """
    target_audience = audience or _current_audience
    cache_key = _make_cache_key(host_data, findings, score, target_audience)

    if cache_key in _cache:
        logger.debug(f"NLP: Cache hit for {host_data.get('ip', '?')}")
        return _cache[cache_key]

    if is_ollama_available():
        # Auto-select the best available model once per session
        global _MODEL_SYNCED
        if not _MODEL_SYNCED:
            auto_select_model()
            _MODEL_SYNCED = True

        report = _translate_via_ollama(
            host_data, findings, score, level, target_audience
        )
    else:
        logger.warning(
            "NLP: Ollama not reachable at %s — using templates. "
            "Start Ollama with: ollama serve", _OLLAMA_URL
        )
        report = _translate_via_templates(
            host_data, findings, score, level, target_audience
        )

    _cache[cache_key] = report
    return report


def translate_batch(
    hosts:    List[Dict],
    audience: Optional[str] = None,
) -> List[BusinessReport]:
    """
    Translate multiple hosts sequentially.
    Each item must have keys: host_data, findings, score, level.
    """
    results = []
    for h in hosts:
        report = translate_findings(
            host_data=h["host_data"],
            findings=h["findings"],
            score=h["score"],
            level=h["level"],
            audience=audience,
        )
        results.append(report)
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Ollama backend
# ─────────────────────────────────────────────────────────────────────────────

def _translate_via_ollama(
    host_data: Dict,
    findings:  List[Dict],
    score:     int,
    level:     str,
    audience:  str,
) -> BusinessReport:
    """Call local Ollama API and parse JSON response."""
    ip       = host_data.get("ip", "unknown")
    hostname = host_data.get("hostname") or ip
    model    = _MODEL

    prompt = _build_prompt(audience, host_data, findings, score, level)

    payload = json.dumps({
        "model":  model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,      # low temp = more deterministic JSON
            "num_predict": 1200,      # max tokens in response
        },
    }).encode("utf-8")

    for attempt in range(_MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(
                f"{_OLLAMA_URL}/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                raw_bytes = resp.read()

            data = json.loads(raw_bytes)
            raw_text = data.get("response", "").strip()

            return _parse_llm_response(
                raw_text, ip, hostname, score, level, audience, model
            )

        except urllib.error.URLError as e:
            logger.error(f"NLP: Ollama connection error (attempt {attempt+1}): {e}")
        except json.JSONDecodeError as e:
            logger.error(f"NLP: Failed to parse Ollama response (attempt {attempt+1}): {e}")
        except Exception as e:
            logger.error(f"NLP: Unexpected error (attempt {attempt+1}): {e}")

        if attempt < _MAX_RETRIES:
            time.sleep(2)

    logger.warning("NLP: Ollama failed after retries — falling back to templates.")
    return _translate_via_templates(host_data, findings, score, level, audience)


def _build_prompt(
    audience:  str,
    host_data: Dict,
    findings:  List[Dict],
    score:     int,
    level:     str,
) -> str:
    """
    Build a rich, context-specific prompt for Ollama.
    Sends all relevant scan data so the model can produce a report
    specific to THIS host — not a generic template.
    """
    persona = _AUDIENCE_PROFILES.get(audience, _AUDIENCE_PROFILES["manager"])

    ip       = host_data.get("ip", "unknown")
    hostname = host_data.get("hostname") or ip
    os_info  = host_data.get("os", {})
    os_name  = os_info.get("name", "unknown") if isinstance(os_info, dict) else str(os_info)

    # Open ports with full detail
    open_ports = []
    for p in host_data.get("ports", []):
        if p.get("state") != "open":
            continue
        port_entry = {
            "port":    p.get("port"),
            "service": p.get("service", ""),
            "product": p.get("product", ""),
            "version": p.get("version", ""),
        }
        cves = p.get("cves", [])
        if cves:
            top_cve = max(cves, key=lambda c: float(c.get("cvss_score") or 0))
            port_entry["worst_cve"] = {
                "id":          top_cve.get("id", ""),
                "cvss":        top_cve.get("cvss_score"),
                "severity":    top_cve.get("severity", ""),
                "description": top_cve.get("description", "")[:200],
            }
            port_entry["total_cves"] = len(cves)
        open_ports.append(port_entry)

    # Findings with full context
    findings_detail = []
    for f in findings:
        findings_detail.append({
            "threat":      f.get("name", ""),
            "severity":    f.get("severity", ""),
            "detail":      f.get("detail", ""),
            "description": f.get("description", ""),
        })

    # Asset context
    asset_type        = host_data.get("asset_type", "unknown")
    asset_criticality = host_data.get("asset_criticality", "MEDIUM")

    scan_data = {
        "host": {
            "ip":               ip,
            "hostname":         hostname,
            "operating_system": os_name,
            "asset_type":       asset_type,
            "asset_criticality":asset_criticality,
            "mac_vendor":       host_data.get("mac_vendor", ""),
        },
        "risk": {
            "score": score,
            "level": level,
        },
        "open_ports":       open_ports,
        "threats_detected": findings_detail,
        "nse_confirmed_vulnerabilities": list(host_data.get("vulnerabilities", {}).keys()),
    }

    urgency_guidance = {
        "CRITICAL": "Immediate",
        "HIGH":     "This week",
        "MEDIUM":   "This quarter",
        "LOW":      "Monitor",
    }.get(level, "This quarter")

    return f"""{persona}

You are analyzing a REAL network security scan of a specific host. Write a report that is SPECIFIC to this exact data — not generic advice.

STRICT RULES:
- Respond ONLY with a valid JSON object. No text before or after. No markdown.
- Be SPECIFIC: mention the actual hostname "{hostname}", actual services found, actual threats detected.
- Do NOT write generic security advice. Every sentence must reflect the actual scan data provided.
- Do NOT mention port numbers by number — describe them by service name.
- urgency_label MUST be exactly: "{urgency_guidance}" (based on risk level {level})
- compliance_flags: list 3-5 specific LGPD articles, ISO 27001 controls, or NIST CSF references.
- priority_actions: 3-5 CONCRETE actions specific to the threats found on THIS host. Not generic advice.
- If no threats were found, say so clearly and give a positive assessment.

Required JSON schema (fill ALL fields):
{{
  "executive_summary": "<2-3 sentences, specific to this host and its actual issues>",
  "business_impact": "<1-2 sentences about concrete business/financial risk from these specific findings>",
  "compliance_flags": ["<specific regulation + article>", ...],
  "priority_actions": ["<specific action for this host>", ...],
  "urgency_label": "{urgency_guidance}"
}}

Complete scan data for host {ip}:
{json.dumps(scan_data, indent=2, ensure_ascii=False)}

JSON response:"""


def _parse_llm_response(
    raw:      str,
    ip:       str,
    hostname: str,
    score:    int,
    level:    str,
    audience: str,
    model:    str,
) -> BusinessReport:
    """
    Parse JSON from LLM response into a BusinessReport.
    Handles common LLM formatting quirks (markdown fences, trailing text).
    """
    # Strip markdown fences if model added them anyway
    clean = raw
    for fence in ("```json", "```JSON", "```"):
        clean = clean.replace(fence, "")
    clean = clean.strip()

    # Extract just the JSON object if there's surrounding text
    start = clean.find("{")
    end   = clean.rfind("}") + 1
    if start != -1 and end > start:
        clean = clean[start:end]

    
    try:
        data = json.loads(clean)
    except json.JSONDecodeError:
        # JSON incompleto — tenta fechar automaticamente
        open_braces   = clean.count("{") - clean.count("}")
        open_brackets = clean.count("[") - clean.count("]")
        # Remove última entrada incompleta (sem aspas de fechamento)
        if open_brackets > 0:
            last_quote = clean.rfind('"')
            if last_quote > 0:
                clean = clean[:last_quote] + '"'
            clean += "]" * open_brackets
        if open_braces > 0:
            clean += "}" * open_braces
        try:
            data = json.loads(clean)
        except json.JSONDecodeError:
            # Se ainda falhar, levanta para o caller cair no template
            raise

    # Validate urgency_label
    valid_urgency = {"Immediate", "This week", "This quarter", "Monitor"}
    urgency = data.get("urgency_label", "This quarter")
    if urgency not in valid_urgency:
        urgency = "This quarter"

    return BusinessReport(
        ip=ip,
        hostname=hostname,
        risk_level=level,
        score=score,
        executive_summary=data.get("executive_summary", ""),
        business_impact=data.get("business_impact", ""),
        compliance_flags=data.get("compliance_flags", []),
        priority_actions=data.get("priority_actions", []),
        urgency_label=urgency,
        generated_by="ollama",
        model=model,
        audience=audience,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Rule-based fallback templates
# ─────────────────────────────────────────────────────────────────────────────

_LEVEL_META = {
    "CRITICAL": {
        "urgency":        "Immediate",
        "impact_prefix":  "This system poses an immediate threat to business continuity.",
        "summary_prefix": "A critical security vulnerability was identified that requires emergency action.",
    },
    "HIGH": {
        "urgency":        "This week",
        "impact_prefix":  "This system has serious vulnerabilities that increase the risk of a data breach.",
        "summary_prefix": "Significant security weaknesses were found that must be addressed urgently.",
    },
    "MEDIUM": {
        "urgency":        "This quarter",
        "impact_prefix":  "This system has moderate security gaps that could be exploited over time.",
        "summary_prefix": "Several security issues were identified that should be remediated in the near term.",
    },
    "LOW": {
        "urgency":        "Monitor",
        "impact_prefix":  "This system has minor security concerns worth tracking.",
        "summary_prefix": "Low-severity security observations were recorded for this system.",
    },
}

_COMPLIANCE_MAP = {
    "ssh_brute_force":            ["LGPD Art. 46 (Segurança)", "ISO 27001 A.9.4 (Access Control)", "NIST CSF PR.AC-7"],
    "vulnerable_service_exposed": ["ISO 27001 A.12.6 (Vulnerability Management)", "NIST CSF ID.RA-1", "LGPD Art. 46"],
    "web_error_with_cve":         ["ISO 27001 A.14.2 (Secure Development)", "NIST CSF DE.CM-8"],
    "critical_port_open":         ["ISO 27001 A.13.1 (Network Security)", "NIST CSF PR.AC-5"],
    "large_attack_surface":       ["ISO 27001 A.12.1 (Operations)", "NIST CSF PR.IP-1"],
    "nse_confirmed_vuln":         ["ISO 27001 A.12.6", "LGPD Art. 46 §1", "NIST CSF RS.MI-3"],
    "cleartext_protocol":         ["ISO 27001 A.10.1 (Cryptography)", "LGPD Art. 46", "NIST CSF PR.DS-2"],
    "database_exposed":           ["LGPD Art. 46 + Art. 48 (Breach Notification)", "ISO 27001 A.8.2", "NIST CSF PR.DS-1"],
    "auth_failure_spike":         ["ISO 27001 A.9.4", "NIST CSF DE.CM-3", "LGPD Art. 46"],
    "docker_api_exposed":         ["ISO 27001 A.12.1", "NIST CSF PR.AC-4", "LGPD Art. 46 §1"],
    "ml_anomaly_detected":        ["ISO 27001 A.12.4 (Logging)", "NIST CSF DE.AE-1", "LGPD Art. 46"],
}

_ACTION_TEMPLATES = {
    "ssh_brute_force": [
        "Disable password login on the remote access service — require cryptographic keys instead",
        "Configure automatic IP blocking after repeated failed login attempts",
        "Restrict remote access to known, trusted IP addresses only",
    ],
    "vulnerable_service_exposed": [
        "Apply available security patches to the affected software immediately",
        "If patches are unavailable, restrict network access to this service as a temporary measure",
        "Contact the software vendor for an interim security advisory",
    ],
    "web_error_with_cve": [
        "Review web server logs for signs of active probing or attack attempts",
        "Enable a Web Application Firewall to filter malicious requests automatically",
        "Update the web server and all installed modules or plugins",
    ],
    "critical_port_open": [
        "Place sensitive remote access services behind a VPN — never expose directly to the internet",
        "Block direct internet access to these services using firewall rules",
        "Require multi-factor authentication for all remote access sessions",
    ],
    "large_attack_surface": [
        "Audit all running services and disable or firewall anything not actively required",
        "Apply least-privilege exposure — only services needed for business should be reachable",
        "Schedule a quarterly review to detect unexpected new services",
    ],
    "nse_confirmed_vuln": [
        "Treat this as an emergency — isolate or shut down the affected system until patched",
        "Change all credentials associated with or accessible from this system immediately",
        "Conduct a forensic review to determine if the vulnerability was already exploited",
    ],
    "cleartext_protocol": [
        "Replace unencrypted file transfer and terminal services with encrypted alternatives immediately",
        "Enforce encrypted connections for all data in transit",
        "Audit all users of these services and migrate them to secure replacements",
    ],
    "database_exposed": [
        "Restrict the database to accept connections only from the application server — not the open network",
        "Review database user accounts and remove accounts with excessive or unused permissions",
        "Enable audit logging on the database to track all data access",
    ],
    "auth_failure_spike": [
        "Investigate the source of repeated login failures and block offending IP ranges",
        "Enable multi-factor authentication on all externally accessible services",
        "Set account lockout thresholds to automatically limit repeated login attempts",
    ],
    "docker_api_exposed": [
        "Close the container management interface from all external network access immediately",
        "Restrict container management to local socket connections only",
        "Audit all running containers for unexpected workloads or unauthorised images",
    ],
    "ml_anomaly_detected": [
        "Investigate this host manually — the anomaly may indicate a novel or unknown attack",
        "Compare current running services and processes against a known-good configuration baseline",
        "Review recently installed software and configuration changes on this host",
    ],
}


def _translate_via_templates(
    host_data: Dict,
    findings:  List[Dict],
    score:     int,
    level:     str,
    audience:  str,
) -> BusinessReport:
    """Rule-based fallback — contextualised with real scan data, works fully offline."""
    ip       = host_data.get("ip", "unknown")
    hostname = host_data.get("hostname") or ip
    os_info  = host_data.get("os", {})
    os_name  = os_info.get("name", "") if isinstance(os_info, dict) else ""
    asset_type = host_data.get("asset_type", "host")
    meta     = _LEVEL_META.get(level, _LEVEL_META["MEDIUM"])

    # Gather open ports
    open_ports = [p for p in host_data.get("ports", []) if p.get("state") == "open"]
    service_names = [
        p.get("product") or p.get("service") or f"port {p.get('port')}"
        for p in open_ports[:5]
    ]

    # Gather all CVEs across ports
    all_cves = []
    for p in open_ports:
        for cve in p.get("cves", []):
            all_cves.append((float(cve.get("cvss_score") or 0), cve, p))
    all_cves.sort(key=lambda x: -x[0])
    worst_cve_info = ""
    if all_cves:
        cvss, cve, port = all_cves[0]
        svc = port.get("product") or port.get("service") or "a running service"
        worst_cve_info = (
            f" The most critical vulnerability ({cve.get('id', 'unknown CVE')}, "
            f"CVSS {cvss}) affects {svc}."
        )

    # Executive summary — specific to this host
    host_ref = f"{hostname} ({ip})" if hostname != ip else ip
    os_ref   = f" running {os_name}" if os_name else ""
    services_ref = (
        f" The host exposes {len(open_ports)} service(s): {', '.join(service_names)}."
        if service_names else ""
    )

    if findings:
        sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top_findings = sorted(findings, key=lambda f: sev_weight.get(f.get("severity","LOW"), 0), reverse=True)
        threat_names = [f["name"] for f in top_findings[:3]]
        threat_str   = ", ".join(threat_names)
        if len(findings) > 3:
            threat_str += f" and {len(findings) - 3} additional issue(s)"

        summary = (
            f"{meta['summary_prefix']} "
            f"The system {host_ref}{os_ref} received a risk score of {score}/100 ({level}).{services_ref} "
            f"Key threats identified: {threat_str}.{worst_cve_info}"
        )
    else:
        summary = (
            f"No significant threats were detected on {host_ref}{os_ref}. "
            f"Risk score: {score}/100.{services_ref} "
            f"Continue monitoring and apply routine patches."
        )

    # Business impact — use asset type and worst findings
    top_finding_names = [f["name"] for f in findings[:2]] if findings else []
    if top_finding_names:
        finding_ref = " and ".join(top_finding_names)
        impact = (
            f"{meta['impact_prefix']} "
            f"The {asset_type} at {ip} is affected by {finding_ref}. "
            f"A successful attack could result in data exfiltration, service disruption, "
            f"or regulatory penalties under LGPD (fines up to 2% of annual revenue)."
        )
    elif open_ports:
        impact = (
            f"{meta['impact_prefix']} "
            f"With {len(open_ports)} accessible service(s) on {ip}, "
            f"the exposure window is open to opportunistic attackers. "
            f"Unauthorised access could compromise data integrity and business continuity."
        )
    else:
        impact = (
            f"The host {ip} shows minimal exposure at this time. "
            f"Maintain current security posture and monitor for changes."
        )

    # Compliance flags — deduplicated, specific to findings
    compliance: List[str] = []
    seen_c: set = set()
    for f in findings:
        pid = f.get("pattern_id") or f.get("id", "")
        for flag in _COMPLIANCE_MAP.get(pid, []):
            if flag not in seen_c:
                compliance.append(flag)
                seen_c.add(flag)

    # Priority actions — specific to actual findings on this host
    actions: List[str] = []
    seen_a: set = set()

    sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_findings = sorted(findings, key=lambda f: sev_weight.get(f.get("severity","LOW"), 0), reverse=True)

    for f in sorted_findings:
        pid = f.get("pattern_id") or f.get("id", "")
        # Use the remediation list from the finding itself if available
        finding_remediations = f.get("remediation", [])
        template_actions     = _ACTION_TEMPLATES.get(pid, [])
        source = finding_remediations[:2] or template_actions[:2]
        for action in source:
            if action not in seen_a:
                # Make action host-specific
                host_specific = action.replace("the system", f"{ip}").replace("this system", f"{ip}")
                actions.append(host_specific)
                seen_a.add(action)
        if len(actions) >= 5:
            break

    # Add CVE-specific action if worst CVE is severe
    if all_cves and all_cves[0][0] >= 7.0:
        cvss, cve, port = all_cves[0]
        svc = port.get("product") or port.get("service") or "affected service"
        cve_action = f"Patch {svc} immediately — {cve.get('id','unknown CVE')} (CVSS {cvss}) has a known exploit vector"
        if cve_action not in seen_a and len(actions) < 5:
            actions.append(cve_action)

    if not actions:
        actions = [
            f"Schedule a follow-up security assessment for {ip} to verify configuration.",
            "Keep all services patched to their latest stable versions.",
        ]

    return BusinessReport(
        ip=ip,
        hostname=hostname,
        risk_level=level,
        score=score,
        executive_summary=summary,
        business_impact=impact,
        compliance_flags=compliance[:6],
        priority_actions=actions[:5],
        urgency_label=meta["urgency"],
        generated_by="template",
        model="none",
        audience=audience,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────

def _make_cache_key(
    host_data: Dict,
    findings:  List[Dict],
    score:     int,
    audience:  str,
) -> str:
    finding_ids = sorted(
        f.get("pattern_id", f.get("id", f.get("name", ""))) for f in findings
    )
    raw = f"{host_data.get('ip')}|{finding_ids}|{score}|{audience}|{_MODEL}"
    return hashlib.sha256(raw.encode()).hexdigest()
