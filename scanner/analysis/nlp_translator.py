#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
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
        "Você está redigindo para um gestor de TI ou coordenador de área sem perfil técnico. "
        "Use linguagem simples e formal. Evite siglas sem explicação. Foque no impacto nos negócios "
        "e no risco financeiro/operacional. Limite cada constatação a 2-3 frases."
    ),
    "auditor": (
        "Você está redigindo para um auditor de TI interno ou externo, familiarizado com ISO 27001 "
        "e LGPD. Use linguagem orientada à conformidade. Referencie famílias de controle "
        "quando apropriado (ex.: A.12 Operações, A.13 Comunicações). "
        "Seja preciso e baseado em evidências."
    ),
    "board": (
        "Você está redigindo para o conselho de administração ou executivos C-level. "
        "Use exclusivamente linguagem de negócios. Sem termos técnicos. Foque em "
        "exposição financeira, risco regulatório e impacto reputacional. "
        "Seja conciso — máximo de 3 tópicos por host."
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
            f"**Urgência:** {self.urgency_label}  "
            f"*[gerado por {self.generated_by} / {self.model}]*",
            "",
            "### Resumo Executivo",
            self.executive_summary,
            "",
            "### Impacto nos Negócios",
            self.business_impact,
        ]
        if self.compliance_flags:
            lines += ["", "### Indicadores de Conformidade"]
            lines += [f"- {c}" for c in self.compliance_flags]
        lines += ["", "### Ações Prioritárias"]
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
        "CRITICAL": "Imediato",
        "HIGH":     "Esta semana",
        "MEDIUM":   "Este trimestre",
        "LOW":      "Monitorar",
    }.get(level, "Este trimestre")

    return f"""{persona}

Você está analisando um scan REAL de segurança de rede de um host específico. Redija um relatório ESPECÍFICO a estes dados — não orientações genéricas. Todo o texto do JSON deve estar em português brasileiro formal.

REGRAS OBRIGATÓRIAS:
- Responda APENAS com um objeto JSON válido. Sem texto antes ou depois. Sem markdown.
- Seja ESPECÍFICO: mencione o hostname real "{hostname}", os serviços encontrados e as ameaças detectadas.
- NÃO escreva orientações genéricas de segurança. Cada frase deve refletir os dados reais do scan.
- NÃO mencione números de porta — descreva pelos nomes dos serviços.
- urgency_label DEVE ser exatamente: "{urgency_guidance}" (com base no nível de risco {level})
- compliance_flags: liste 3-5 referências específicas a artigos da LGPD, controles ISO 27001 ou NIST CSF.
- priority_actions: 3-5 ações CONCRETAS específicas às ameaças deste host. Não orientações genéricas.
- Se nenhuma ameaça foi encontrada, declare isso claramente e apresente avaliação positiva.

Esquema JSON obrigatório (preencha TODOS os campos):
{{
  "executive_summary": "<2-3 frases, específicas a este host e suas questões reais>",
  "business_impact": "<1-2 frases sobre risco concreto de negócio/financeiro destas constatações>",
  "compliance_flags": ["<regulamentação + artigo específico>", ...],
  "priority_actions": ["<ação específica para este host>", ...],
  "urgency_label": "{urgency_guidance}"
}}

Dados completos do scan do host {ip}:
{json.dumps(scan_data, indent=2, ensure_ascii=False)}

Resposta JSON:"""


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
    valid_urgency = {"Imediato", "Esta semana", "Este trimestre", "Monitorar"}
    urgency = data.get("urgency_label", "Este trimestre")
    if urgency not in valid_urgency:
        urgency = "Este trimestre"

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
        "urgency":        "Imediato",
        "impact_prefix":  "Este sistema representa ameaça imediata à continuidade dos negócios.",
        "summary_prefix": "Foi identificada vulnerabilidade crítica de segurança que exige ação emergencial.",
    },
    "HIGH": {
        "urgency":        "Esta semana",
        "impact_prefix":  "Este sistema apresenta vulnerabilidades graves que elevam o risco de violação de dados.",
        "summary_prefix": "Foram encontradas fraquezas significativas de segurança que devem ser tratadas com urgência.",
    },
    "MEDIUM": {
        "urgency":        "Este trimestre",
        "impact_prefix":  "Este sistema apresenta lacunas moderadas de segurança que podem ser exploradas ao longo do tempo.",
        "summary_prefix": "Foram identificadas questões de segurança que devem ser remediadas no curto prazo.",
    },
    "LOW": {
        "urgency":        "Monitorar",
        "impact_prefix":  "Este sistema apresenta preocupações menores de segurança que merecem acompanhamento.",
        "summary_prefix": "Foram registradas observações de baixa severidade para este sistema.",
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
        "Desabilitar login por senha no serviço de acesso remoto — exigir chaves criptográficas",
        "Configurar bloqueio automático de IP após tentativas de login malsucedidas",
        "Restringir acesso remoto somente a endereços IP conhecidos e confiáveis",
    ],
    "vulnerable_service_exposed": [
        "Aplicar imediatamente os patches de segurança disponíveis ao software afetado",
        "Caso os patches não estejam disponíveis, restringir o acesso de rede ao serviço como medida temporária",
        "Contatar o fornecedor do software para obter advisory de segurança intermediário",
    ],
    "web_error_with_cve": [
        "Revisar logs do servidor web em busca de sinais de varredura ou tentativas de ataque",
        "Habilitar Web Application Firewall para filtrar requisições maliciosas automaticamente",
        "Atualizar o servidor web e todos os módulos ou plugins instalados",
    ],
    "critical_port_open": [
        "Posicionar serviços sensíveis de acesso remoto atrás de VPN — nunca expor diretamente à internet",
        "Bloquear acesso direto à internet a esses serviços via regras de firewall",
        "Exigir autenticação multifator em todas as sessões de acesso remoto",
    ],
    "large_attack_surface": [
        "Auditar todos os serviços em execução e desabilitar ou proteger via firewall o que não for necessário",
        "Aplicar exposição mínima — apenas serviços necessários ao negócio devem ser acessíveis",
        "Agendar revisão trimestral para detectar novos serviços inesperados",
    ],
    "nse_confirmed_vuln": [
        "Tratar como emergência — isolar ou desligar o sistema afetado até aplicação do patch",
        "Alterar imediatamente todas as credenciais associadas ou acessíveis a partir deste sistema",
        "Conduzir revisão forense para verificar se a vulnerabilidade já foi explorada",
    ],
    "cleartext_protocol": [
        "Substituir imediatamente serviços de transferência de arquivos e terminal por alternativas criptografadas",
        "Impor conexões criptografadas para todos os dados em trânsito",
        "Auditar usuários desses serviços e migrá-los para alternativas seguras",
    ],
    "database_exposed": [
        "Restringir o banco de dados para aceitar conexões somente do servidor de aplicação — não da rede aberta",
        "Revisar contas de usuário do banco e remover contas com permissões excessivas ou não utilizadas",
        "Habilitar auditoria no banco de dados para rastrear todo acesso a dados",
    ],
    "auth_failure_spike": [
        "Investigar a origem das falhas de login repetidas e bloquear as faixas de IP ofensores",
        "Habilitar autenticação multifator em todos os serviços acessíveis externamente",
        "Definir limiares de bloqueio de conta para limitar tentativas de login repetidas",
    ],
    "docker_api_exposed": [
        "Fechar imediatamente a interface de gerenciamento de containers de todo acesso externo",
        "Restringir gerenciamento de containers a conexões locais via socket",
        "Auditar containers em execução quanto a cargas de trabalho ou imagens não autorizadas",
    ],
    "ml_anomaly_detected": [
        "Investigar este host manualmente — a anomalia pode indicar ataque inédito ou desconhecido",
        "Comparar serviços e processos atuais com baseline de configuração conhecida",
        "Revisar software instalado e alterações de configuração recentes neste host",
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
            f" A vulnerabilidade mais crítica ({cve.get('id', 'CVE desconhecida')}, "
            f"CVSS {cvss}) afeta {svc}."
        )

    # Executive summary — specific to this host
    host_ref = f"{hostname} ({ip})" if hostname != ip else ip
    os_ref   = f" running {os_name}" if os_name else ""
    services_ref = (
        f" O host expõe {len(open_ports)} serviço(s): {', '.join(service_names)}."
        if service_names else ""
    )

    if findings:
        sev_weight = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        top_findings = sorted(findings, key=lambda f: sev_weight.get(f.get("severity","LOW"), 0), reverse=True)
        threat_names = [f["name"] for f in top_findings[:3]]
        threat_str   = ", ".join(threat_names)
        if len(findings) > 3:
            threat_str += f" e mais {len(findings) - 3} questão(ões)"

        summary = (
            f"{meta['summary_prefix']} "
            f"O sistema {host_ref}{os_ref} recebeu pontuação de risco {score}/100 ({level}).{services_ref} "
            f"Principais ameaças identificadas: {threat_str}.{worst_cve_info}"
        )
    else:
        summary = (
            f"Nenhuma ameaça significativa foi detectada em {host_ref}{os_ref}. "
            f"Pontuação de risco: {score}/100.{services_ref} "
            f"Manter monitoramento e aplicar patches de rotina."
        )

    # Business impact — use asset type and worst findings
    top_finding_names = [f["name"] for f in findings[:2]] if findings else []
    if top_finding_names:
        finding_ref = " and ".join(top_finding_names)
        impact = (
            f"{meta['impact_prefix']} "
            f"O ativo {asset_type} em {ip} é afetado por {finding_ref}. "
            f"Um ataque bem-sucedido pode resultar em exfiltração de dados, interrupção de serviços "
            f"ou sanções regulatórias sob a LGPD (multas de até 2% do faturamento anual)."
        )
    elif open_ports:
        impact = (
            f"{meta['impact_prefix']} "
            f"Com {len(open_ports)} serviço(s) acessível(is) em {ip}, "
            f"a janela de exposição está aberta a atacantes oportunistas. "
            f"Acesso não autorizado pode comprometer a integridade dos dados e a continuidade dos negócios."
        )
    else:
        impact = (
            f"O host {ip} apresenta exposição mínima no momento. "
            f"Manter a postura de segurança atual e monitorar alterações."
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
        cve_action = f"Aplicar patch em {svc} imediatamente — {cve.get('id','CVE desconhecida')} (CVSS {cvss}) possui vetor de exploração conhecido"
        if cve_action not in seen_a and len(actions) < 5:
            actions.append(cve_action)

    if not actions:
        actions = [
            f"Agendar avaliação de segurança de acompanhamento para {ip} a fim de verificar a configuração.",
            "Manter todos os serviços atualizados com patches estáveis mais recentes.",
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
