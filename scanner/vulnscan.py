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
Vulnerability assessment:
  1. nmap NSE --script vuln,auth,exploit  (local, no internet needed)
  2. NVD API CVE lookup per service/version (requires internet)
  3. Risk score calculation (0–100) per host
"""

import time
from typing import Dict, List, Tuple

import nmap      # type: ignore
import requests
from rich.console import Console

console = Console()

# NVD REST API v2
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# In-process CVE cache to avoid duplicate queries
_CVE_CACHE: Dict[str, List[Dict]] = {}

# Ports considered sensitive by default (used in risk scoring)
_RISKY_PORTS = {
    21, 22, 23, 25, 53, 69, 79, 80, 110, 111, 119,
    135, 137, 138, 139, 143, 161, 389, 443, 445,
    512, 513, 514, 873, 1099, 1433, 1521, 2049,
    2375, 2376, 3000, 3306, 3389, 4444, 5432,
    5900, 5985, 6379, 8080, 8443, 8888, 9200, 27017,
}


# ──────────────────────────────────────────────────────────────────────────────
# 1. NSE vulnerability scripts
# ──────────────────────────────────────────────────────────────────────────────

def run_nse_vuln_scripts(ip: str, open_ports: List[int]) -> Dict[int, Dict]:
    """
    Run `--script vuln,auth,exploit` against the known open ports.
    Returns  {port_number: {script_name: raw_output, ...}}
    """
    if not open_ports:
        return {}

    # Limit to 60 ports to keep scan time sane
    port_str = ",".join(str(p) for p in open_ports[:60])
    nm = nmap.PortScanner()

    try:
        nm.scan(
            hosts=ip,
            arguments=f"-p {port_str} --script vuln,auth,exploit -T4 --script-timeout 30",
            sudo=True,
        )
    except Exception as exc:
        console.print(f"[yellow]⚠  NSE scan error on {ip}: {exc}[/yellow]")
        return {}

    if ip not in nm.all_hosts():
        return {}

    results: Dict[int, Dict] = {}
    host_data = nm[ip]

    for proto in host_data.all_protocols():
        for port_num in host_data[proto]:
            scripts = host_data[proto][port_num].get("script", {})
            if scripts:
                results[port_num] = scripts

    return results


# ──────────────────────────────────────────────────────────────────────────────
# 2. NVD CVE lookup
# ──────────────────────────────────────────────────────────────────────────────

def search_cves(product: str, version: str, max_results: int = 5) -> List[Dict]:
    """
    Query the NVD API for CVEs matching `product version`.
    Returns a list of CVE dicts:
      {id, description, cvss_score, severity, vector, references, published}

    Rate-limit note: without an API key NVD allows 5 req/30 s.
    We sleep 0.65 s between calls to stay safe.
    """
    if not product:
        return []

    cache_key = f"{product.lower()}:{version.lower()}"
    if cache_key in _CVE_CACHE:
        return _CVE_CACHE[cache_key]

    query = product + (f" {version}" if version else "")

    try:
        r = requests.get(
            NVD_URL,
            params={"keywordSearch": query, "resultsPerPage": max_results},
            headers={"User-Agent": "NetAudit/1.0 (security research)"},
            timeout=12,
        )
        time.sleep(0.65)           # NVD rate-limit buffer

        if r.status_code != 200:
            _CVE_CACHE[cache_key] = []
            return []

        cves: List[Dict] = []
        for vuln in r.json().get("vulnerabilities", []):
            cve = vuln.get("cve", {})

            # English description
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
                "No description available.",
            )

            # CVSS score — prefer v3.1 > v3.0 > v2
            metrics    = cve.get("metrics", {})
            cvss_score = None
            severity   = "UNKNOWN"
            vector     = ""

            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics:
                    m = metrics[key][0]
                    cvss_score = m["cvssData"].get("baseScore")
                    severity   = (
                        m["cvssData"].get("baseSeverity")
                        or m.get("baseSeverity", "UNKNOWN")
                    )
                    vector = m["cvssData"].get("vectorString", "")
                    break

            references = [ref["url"] for ref in cve.get("references", [])[:3]]

            cves.append({
                "id":          cve.get("id", ""),
                "description": desc[:350],
                "cvss_score":  cvss_score,
                "severity":    severity.upper(),
                "vector":      vector,
                "references":  references,
                "published":   cve.get("published", "")[:10],
            })

        _CVE_CACHE[cache_key] = cves
        return cves

    except Exception as exc:
        console.print(f"[yellow]⚠  CVE lookup failed for '{product}': {exc}[/yellow]")
        _CVE_CACHE[cache_key] = []
        return []


def enrich_ports_with_cves(ports: List[Dict]) -> List[Dict]:
    """
    For every port that has a detected product/version, query NVD and
    attach the found CVEs to port['cves'].
    """
    seen: set = set()

    for port in ports:
        product = port.get("product", "").strip()
        version = port.get("version", "").strip()

        if not product:
            continue

        key = f"{product}:{version}"
        if key in seen:
            # Re-use results from a previous port with the same service/version
            cache_key = f"{product.lower()}:{version.lower()}"
            port["cves"] = _CVE_CACHE.get(cache_key, [])
            continue

        seen.add(key)
        port["cves"] = search_cves(product, version)

    return ports


# ──────────────────────────────────────────────────────────────────────────────
# 3. Risk scoring
# ──────────────────────────────────────────────────────────────────────────────

def calculate_risk(ports: List[Dict], nse_results: Dict[int, Dict], findings: list | None = None) -> Tuple[int, str]:
    """
    Produce a 0–100 risk score and a label for a single host.

    Scoring breakdown (approximate):
      • Open port count               → up to 15 pts
      • Sensitive / well-known ports  → up to 20 pts
      • CVE CVSS scores               → up to 40 pts
      • NSE confirmed vulnerabilities → up to 25 pts
    """
    score = 0

    open_ports = [p for p in ports if p["state"] == "open"]

    # Open port count (capped at 15)
    score += min(len(open_ports) * 1.5, 15)

    # Sensitive ports
    for p in open_ports:
        if p["port"] in _RISKY_PORTS:
            score += 2          # each risky open port adds 2

    score = min(score, 35)      # cap the port sub-score

    # CVEs
    cve_score = 0
    for p in ports:
        for cve in p.get("cves", []):
            cvss = cve.get("cvss_score") or 0.0
            if cvss >= 9.0:
                cve_score += 15
            elif cvss >= 7.0:
                cve_score += 8
            elif cvss >= 4.0:
                cve_score += 4
            else:
                cve_score += 1
    score += min(cve_score, 40)

    # NSE confirmed vulnerabilities
    nse_score = 0
    for scripts in nse_results.values():
        for output in scripts.values():
            out_upper = str(output).upper()
            if "VULNERABLE" in out_upper:
                nse_score += 10
            elif "LIKELY VULNERABLE" in out_upper:
                nse_score += 5
    score += min(nse_score, 25)

    score = min(int(score), 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    elif score >= 5:
        level = "LOW"
    else:
        level = "MINIMAL"

    return score, level
