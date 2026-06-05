#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
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
Port scanning with nmap service/version detection.
Four scan profiles from stealth to aggressive.
"""

from typing import Dict, List

import nmap  # type: ignore
from rich.console import Console

console = Console()

# ──────────────────────────────────────────────────────────────────────────────
# Scan profiles
# ──────────────────────────────────────────────────────────────────────────────

PROFILES: Dict[str, Dict] = {
    "quick": {
        "label":       "Quick — top 1 000 ports, T4",
        "args":        "-sS -sV --top-ports 1000 -T4",
    },
    "normal": {
        "label":       "Normal — top 10 000 ports + default scripts, T4",
        "args":        "-sS -sV -sC -p 1-10000 -T4",
    },
    "full": {
        "label":       "Full — all 65 535 ports + version + scripts, T4",
        "args":        "-sS -sV -sC -p- -T4",
    },
    "stealth": {
        "label":       "Stealth — all ports, low rate, T2 (slow but quiet)",
        "args":        "-sS -sV -p- --min-rate 200 -T2",
    },
}


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────

def scan_ports(ip: str, profile: str = "normal") -> List[Dict]:
    """
    Scan `ip` using the selected profile.
    Returns a list of port dicts (open + filtered only):

    {
        port, protocol, state, service,
        product, version, extrainfo, cpe,
        scripts,   # raw nmap script output dict
        cves,      # populated later by vulnscan
    }
    """
    args = PROFILES.get(profile, PROFILES["normal"])["args"]
    nm = nmap.PortScanner()

    try:
        nm.scan(hosts=ip, arguments=args, sudo=True)
    except Exception as exc:
        console.print(f"[red]✗ Port scan failed on {ip}: {exc}[/red]")
        return []

    if ip not in nm.all_hosts():
        return []

    host_data = nm[ip]
    ports: List[Dict] = []

    for proto in host_data.all_protocols():
        for port_num in sorted(host_data[proto].keys()):
            info = host_data[proto][port_num]

            # Skip closed ports — they add noise
            if info["state"] not in ("open", "filtered"):
                continue

            product = info.get("product", "")
            version = info.get("version", "")
            extra   = info.get("extrainfo", "")

            ports.append({
                "port":      port_num,
                "protocol":  proto,
                "state":     info["state"],
                "service":   info.get("name", ""),
                "product":   product,
                "version":   version,
                "extrainfo": extra,
                "cpe":       info.get("cpe", ""),
                "scripts":   info.get("script", {}),
                "cves":      [],          # filled by vulnscan later
            })

    return ports


def get_open_port_numbers(ports: List[Dict]) -> List[int]:
    """Convenience: return only the port numbers that are open."""
    return [p["port"] for p in ports if p["state"] == "open"]
