#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
siem_connector.py — SIEM Integration Layer for Munin.

Sends Munin findings to external SIEM/SOAR platforms as structured events.

Supported connectors:
  - Elastic (Elasticsearch REST API / ECS format)
  - Splunk  (HTTP Event Collector)
  - Graylog (GELF over HTTP)
  - Syslog  (RFC 5424 UDP/TCP — works with any syslog-compatible SIEM)
  - Webhook (generic JSON POST — works with Slack, Teams, n8n, Zapier, etc.)

Configuration via environment variables (or .env):
  MUNIN_SIEM_ELASTIC_URL     = http://elastic:9200
  MUNIN_SIEM_ELASTIC_INDEX   = munin-findings
  MUNIN_SIEM_ELASTIC_API_KEY = Base64==

  MUNIN_SIEM_SPLUNK_URL      = https://splunk:8088
  MUNIN_SIEM_SPLUNK_TOKEN    = abcdef-...

  MUNIN_SIEM_GRAYLOG_URL     = http://graylog:12201/gelf

  MUNIN_SIEM_SYSLOG_HOST     = 192.168.1.10
  MUNIN_SIEM_SYSLOG_PORT     = 514
  MUNIN_SIEM_SYSLOG_PROTO    = udp   # or tcp

  MUNIN_SIEM_WEBHOOK_URL     = https://hooks.example.com/munin

Public API:
  send_findings(scan_result: dict, connector: str = "auto") -> SIEMResult
  send_all(scan_result: dict) -> list[SIEMResult]
  list_configured() -> list[str]
"""

from __future__ import annotations

import json
import logging
import os
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("munin.siem")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration loader
# ─────────────────────────────────────────────────────────────────────────────

def _env(key: str, default: str = "") -> str:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass
    return os.environ.get(key, default)


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SIEMResult:
    """Result of a single SIEM send operation."""
    connector:    str
    success:      bool
    events_sent:  int
    error:        Optional[str] = None
    response_code: Optional[int] = None
    details:      Dict[str, Any] = field(default_factory=dict)


# ─────────────────────────────────────────────────────────────────────────────
# Event formatter — converts Munin findings to SIEM-agnostic dicts
# ─────────────────────────────────────────────────────────────────────────────

def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _severity_to_syslog_level(severity: str) -> int:
    """Map Munin severity to syslog severity number (RFC 5424)."""
    return {"CRITICAL": 2, "HIGH": 3, "MEDIUM": 4, "LOW": 6}.get(severity.upper(), 6)


def build_events(scan_result: dict) -> List[Dict]:
    """
    Flatten a Munin scan result into a list of SIEM event dicts.
    One event per finding per host.
    """
    meta   = scan_result.get("meta", {})
    target = meta.get("target", "unknown")
    events: List[Dict] = []

    for host in scan_result.get("hosts", []):
        ip        = host.get("ip", "unknown")
        hostname  = host.get("hostname", ip)
        risk_lvl  = host.get("risk_level", "UNKNOWN")
        risk_sc   = host.get("risk_score", 0)
        asset_t   = host.get("asset_type", "unknown")
        asset_c   = host.get("asset_criticality", "MEDIUM")

        for finding in host.get("findings", []):
            # Compliance refs (if enriched)
            compliance = finding.get("compliance", {})
            mitre   = compliance.get("mitre", [])
            iso     = compliance.get("iso27001", [])
            cis     = compliance.get("cis", [])

            events.append({
                # Event metadata
                "timestamp":      _iso_now(),
                "scan_target":    target,
                "scan_time":      meta.get("scan_time", ""),

                # Asset
                "host_ip":        ip,
                "host_hostname":  hostname,
                "host_risk_score": risk_sc,
                "host_risk_level": risk_lvl,
                "asset_type":     asset_t,
                "asset_criticality": asset_c,

                # Finding
                "finding_id":     finding.get("pattern_id", ""),
                "finding_name":   finding.get("name", ""),
                "finding_detail": finding.get("detail", ""),
                "severity":       finding.get("severity", "UNKNOWN"),
                "risk_bonus":     finding.get("risk_bonus", 0),

                # Compliance
                "mitre_techniques": mitre,
                "iso27001_controls": iso,
                "cis_controls":     cis,

                # Source
                "source":         "munin",
                "source_version": "2.0",
            })

        # Also send CVE events for high-severity CVEs
        for port in host.get("ports", []):
            for cve in port.get("cves", []):
                cvss = float(cve.get("cvss_score") or 0)
                if cvss < 7.0:
                    continue
                events.append({
                    "timestamp":       _iso_now(),
                    "scan_target":     target,
                    "scan_time":       meta.get("scan_time", ""),
                    "host_ip":         ip,
                    "host_hostname":   hostname,
                    "host_risk_score": risk_sc,
                    "host_risk_level": risk_lvl,
                    "asset_type":      asset_t,
                    "asset_criticality": asset_c,
                    "finding_id":      cve.get("id", ""),
                    "finding_name":    f"CVE: {cve.get('id','')}",
                    "finding_detail":  cve.get("description", "")[:200],
                    "severity":        cve.get("severity", "HIGH"),
                    "cvss_score":      cvss,
                    "cvss_vector":     cve.get("vector", ""),
                    "affected_port":   port.get("port"),
                    "affected_service": port.get("service", ""),
                    "source":          "munin_nvd",
                    "source_version":  "2.0",
                })

    return events


# ─────────────────────────────────────────────────────────────────────────────
# Elastic connector
# ─────────────────────────────────────────────────────────────────────────────

def _ecs_wrap(event: Dict) -> Dict:
    """Wrap a Munin event in Elastic Common Schema (ECS)."""
    return {
        "@timestamp":    event["timestamp"],
        "event": {
            "kind":     "alert",
            "category": ["vulnerability"],
            "type":     ["info"],
            "severity": _severity_to_syslog_level(event.get("severity", "LOW")),
            "dataset":  "munin.findings",
        },
        "host": {
            "ip":       [event["host_ip"]],
            "hostname": event["host_hostname"],
        },
        "vulnerability": {
            "id":           event.get("finding_id", ""),
            "description":  event.get("finding_detail", ""),
            "severity":     event.get("severity", ""),
            "score": {
                "base": event.get("cvss_score"),
            },
        },
        "labels": {
            "asset_type":        event.get("asset_type", ""),
            "asset_criticality": event.get("asset_criticality", ""),
            "risk_level":        event.get("host_risk_level", ""),
            "risk_score":        str(event.get("host_risk_score", 0)),
        },
        "tags":   ["munin", "security", "grc"],
        "munin":  event,
    }


def send_elastic(events: List[Dict]) -> SIEMResult:
    """Send events to Elasticsearch using bulk API."""
    import requests

    url       = _env("MUNIN_SIEM_ELASTIC_URL", "http://localhost:9200")
    index     = _env("MUNIN_SIEM_ELASTIC_INDEX", "munin-findings")
    api_key   = _env("MUNIN_SIEM_ELASTIC_API_KEY", "")
    username  = _env("MUNIN_SIEM_ELASTIC_USER", "")
    password  = _env("MUNIN_SIEM_ELASTIC_PASS", "")

    if not url:
        return SIEMResult("elastic", False, 0, "MUNIN_SIEM_ELASTIC_URL not configured")

    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"

    auth = (username, password) if username else None

    # Build NDJSON bulk body
    lines = []
    for ev in events:
        meta_line = json.dumps({"index": {"_index": index}})
        doc_line  = json.dumps(_ecs_wrap(ev))
        lines.append(meta_line)
        lines.append(doc_line)

    body = "\n".join(lines) + "\n"
    bulk_url = f"{url.rstrip('/')}/_bulk"

    try:
        r = requests.post(bulk_url, data=body, headers=headers, auth=auth, timeout=15)
        if r.status_code in (200, 201):
            errors = r.json().get("errors", False)
            if errors:
                return SIEMResult("elastic", False, len(events),
                                  "Bulk had errors", r.status_code, r.json())
            return SIEMResult("elastic", True, len(events), response_code=r.status_code)
        return SIEMResult("elastic", False, 0,
                          f"HTTP {r.status_code}: {r.text[:200]}", r.status_code)
    except Exception as e:
        return SIEMResult("elastic", False, 0, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Splunk HEC connector
# ─────────────────────────────────────────────────────────────────────────────

def send_splunk(events: List[Dict]) -> SIEMResult:
    """Send events to Splunk HTTP Event Collector."""
    import requests

    url   = _env("MUNIN_SIEM_SPLUNK_URL", "")
    token = _env("MUNIN_SIEM_SPLUNK_TOKEN", "")

    if not url or not token:
        return SIEMResult("splunk", False, 0,
                          "MUNIN_SIEM_SPLUNK_URL or MUNIN_SIEM_SPLUNK_TOKEN not configured")

    hec_url = f"{url.rstrip('/')}/services/collector/event"
    headers = {
        "Authorization": f"Splunk {token}",
        "Content-Type":  "application/json",
    }

    # Splunk HEC batch: concatenated JSON objects
    batch = ""
    for ev in events:
        batch += json.dumps({
            "time":       time.time(),
            "sourcetype": "munin:finding",
            "source":     "munin",
            "host":       ev.get("host_ip", "unknown"),
            "event":      ev,
        })

    try:
        r = requests.post(hec_url, data=batch, headers=headers, timeout=15, verify=False)
        if r.status_code == 200:
            return SIEMResult("splunk", True, len(events), response_code=200)
        return SIEMResult("splunk", False, 0,
                          f"HTTP {r.status_code}: {r.text[:200]}", r.status_code)
    except Exception as e:
        return SIEMResult("splunk", False, 0, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Graylog GELF connector
# ─────────────────────────────────────────────────────────────────────────────

def _to_gelf(event: Dict) -> Dict:
    """Convert a Munin event to GELF format."""
    return {
        "version":        "1.1",
        "host":           event.get("host_hostname", event.get("host_ip", "unknown")),
        "short_message":  f"[{event.get('severity','?')}] {event.get('finding_name','')}",
        "full_message":   event.get("finding_detail", ""),
        "timestamp":      time.time(),
        "level":          _severity_to_syslog_level(event.get("severity", "LOW")),
        "_host_ip":        event.get("host_ip", ""),
        "_risk_score":     event.get("host_risk_score", 0),
        "_risk_level":     event.get("host_risk_level", ""),
        "_asset_type":     event.get("asset_type", ""),
        "_finding_id":     event.get("finding_id", ""),
        "_severity":       event.get("severity", ""),
        "_source":         "munin",
        "_scan_target":    event.get("scan_target", ""),
    }


def send_graylog(events: List[Dict]) -> SIEMResult:
    """Send events to Graylog via GELF HTTP input."""
    import requests

    url = _env("MUNIN_SIEM_GRAYLOG_URL", "")
    if not url:
        return SIEMResult("graylog", False, 0,
                          "MUNIN_SIEM_GRAYLOG_URL not configured")

    sent = 0
    for ev in events:
        gelf = _to_gelf(ev)
        try:
            r = requests.post(url, json=gelf, timeout=10)
            if r.status_code in (200, 202):
                sent += 1
            else:
                logger.warning(f"Graylog HTTP {r.status_code} for event {ev.get('finding_id','?')}")
        except Exception as e:
            logger.error(f"Graylog send error: {e}")

    success = sent > 0
    return SIEMResult("graylog", success, sent,
                      None if success else "No events accepted")


# ─────────────────────────────────────────────────────────────────────────────
# Syslog connector (RFC 5424)
# ─────────────────────────────────────────────────────────────────────────────

def _rfc5424_msg(event: Dict, hostname: str) -> bytes:
    """Build an RFC 5424 syslog message."""
    pri      = (1 * 8) + _severity_to_syslog_level(event.get("severity", "LOW"))
    version  = 1
    ts       = event.get("timestamp", _iso_now())
    app_name = "munin"
    proc_id  = "-"
    msg_id   = (event.get("finding_id") or "-").replace(" ", "_")[:32]
    msg      = (
        f"[{event.get('severity','?')}] "
        f"host={event.get('host_ip','?')} "
        f"finding={event.get('finding_name','?')!r} "
        f"risk={event.get('host_risk_score',0)}"
    )
    line = f"<{pri}>{version} {ts} {hostname} {app_name} {proc_id} {msg_id} - {msg}"
    return line.encode("utf-8")


def send_syslog(events: List[Dict]) -> SIEMResult:
    """Send events via syslog (UDP or TCP)."""
    host  = _env("MUNIN_SIEM_SYSLOG_HOST", "")
    port  = int(_env("MUNIN_SIEM_SYSLOG_PORT", "514"))
    proto = _env("MUNIN_SIEM_SYSLOG_PROTO", "udp").lower()

    if not host:
        return SIEMResult("syslog", False, 0,
                          "MUNIN_SIEM_SYSLOG_HOST not configured")

    local_hostname = socket.gethostname()
    sent = 0

    try:
        if proto == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            for ev in events:
                msg = _rfc5424_msg(ev, local_hostname) + b"\n"
                sock.sendall(msg)
                sent += 1
            sock.close()
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            for ev in events:
                msg = _rfc5424_msg(ev, local_hostname)
                sock.sendto(msg, (host, port))
                sent += 1
            sock.close()

        return SIEMResult("syslog", True, sent)
    except Exception as e:
        return SIEMResult("syslog", False, sent, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Generic webhook connector
# ─────────────────────────────────────────────────────────────────────────────

def send_webhook(events: List[Dict], scan_result: dict) -> SIEMResult:
    """POST a summary JSON payload to a generic webhook URL."""
    import requests

    url = _env("MUNIN_SIEM_WEBHOOK_URL", "")
    if not url:
        return SIEMResult("webhook", False, 0,
                          "MUNIN_SIEM_WEBHOOK_URL not configured")

    meta      = scan_result.get("meta", {})
    hosts     = scan_result.get("hosts", [])
    critical  = sum(1 for h in hosts if h.get("risk_level") == "CRITICAL")
    high      = sum(1 for h in hosts if h.get("risk_level") == "HIGH")
    total_cve = sum(
        sum(len(p.get("cves", [])) for p in h.get("ports", []))
        for h in hosts
    )

    # Top-5 critical findings for the summary
    top_findings = sorted(
        events,
        key=lambda e: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            e.get("severity", "LOW"), 0
        ),
        reverse=True,
    )[:5]

    payload = {
        "timestamp":    _iso_now(),
        "source":       "munin",
        "scan_target":  meta.get("target", "unknown"),
        "scan_time":    meta.get("scan_time", ""),
        "summary": {
            "total_hosts":    len(hosts),
            "critical_hosts": critical,
            "high_hosts":     high,
            "total_cves":     total_cve,
            "total_events":   len(events),
        },
        "top_findings": top_findings,
    }

    try:
        r = requests.post(
            url, json=payload,
            headers={"Content-Type": "application/json", "User-Agent": "Munin/2.0"},
            timeout=15,
        )
        if r.status_code in (200, 201, 202, 204):
            return SIEMResult("webhook", True, len(events), response_code=r.status_code)
        return SIEMResult("webhook", False, 0,
                          f"HTTP {r.status_code}", r.status_code)
    except Exception as e:
        return SIEMResult("webhook", False, 0, str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def list_configured() -> List[str]:
    """Return list of connector names that have their env vars set."""
    configured = []
    if _env("MUNIN_SIEM_ELASTIC_URL"):
        configured.append("elastic")
    if _env("MUNIN_SIEM_SPLUNK_URL") and _env("MUNIN_SIEM_SPLUNK_TOKEN"):
        configured.append("splunk")
    if _env("MUNIN_SIEM_GRAYLOG_URL"):
        configured.append("graylog")
    if _env("MUNIN_SIEM_SYSLOG_HOST"):
        configured.append("syslog")
    if _env("MUNIN_SIEM_WEBHOOK_URL"):
        configured.append("webhook")
    return configured


def send_findings(
    scan_result: dict,
    connector:   str = "auto",
) -> List[SIEMResult]:
    """
    Send scan findings to one or all configured SIEM connectors.

    Args:
        scan_result: Munin scan result dict
        connector:   "auto" (all configured) | "elastic" | "splunk" |
                     "graylog" | "syslog" | "webhook"

    Returns:
        List of SIEMResult (one per connector attempted)
    """
    events  = build_events(scan_result)
    targets = list_configured() if connector == "auto" else [connector]

    if not events:
        logger.info("No findings to send to SIEM.")
        return []

    results: List[SIEMResult] = []
    for target in targets:
        logger.info(f"Sending {len(events)} events to {target}…")
        if target == "elastic":
            results.append(send_elastic(events))
        elif target == "splunk":
            results.append(send_splunk(events))
        elif target == "graylog":
            results.append(send_graylog(events))
        elif target == "syslog":
            results.append(send_syslog(events))
        elif target == "webhook":
            results.append(send_webhook(events, scan_result))
        else:
            results.append(SIEMResult(target, False, 0, f"Unknown connector: {target}"))

        r = results[-1]
        if r.success:
            logger.info(f"  ✔ {target}: {r.events_sent} events sent")
        else:
            logger.warning(f"  ✗ {target}: {r.error}")

    return results


# keep old name for compatibility
send_all = send_findings
