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
Host discovery via ARP scan (scapy) with nmap ping-scan fallback.
Returns a list of {ip, mac} dicts for every live host on the network.
"""

import socket
from typing import List, Dict

from rich.console import Console

console = Console()


# ──────────────────────────────────────────────────────────────────────────────
# Primary: ARP scan via scapy (fastest, most reliable on local networks)
# ──────────────────────────────────────────────────────────────────────────────

def arp_scan(target: str) -> List[Dict]:
    """
    Broadcast ARP requests to every IP in `target` (CIDR or single IP).
    Requires root. Falls back to nmap if scapy is unavailable.
    """
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore

        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answered, _ = srp(packet, timeout=3, verbose=0)

        hosts: List[Dict] = []
        for _, recv in answered:
            hosts.append({
                "ip":  recv.psrc,
                "mac": recv.hwsrc.upper(),
            })
        return hosts

    except ImportError:
        console.print(
            "[yellow]⚠  scapy não encontrado — usando nmap para descoberta[/yellow]"
        )
        return _nmap_ping_scan(target)

    except Exception as exc:
        console.print(
            f"[yellow]⚠  ARP scan falhou ({exc}) — usando nmap como fallback[/yellow]"
        )
        return _nmap_ping_scan(target)


# ──────────────────────────────────────────────────────────────────────────────
# Fallback: nmap -sn (ping scan)
# ──────────────────────────────────────────────────────────────────────────────

def _nmap_ping_scan(target: str) -> List[Dict]:
    """nmap ping scan — slower but works without scapy."""
    import nmap  # type: ignore

    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments="-sn -PR --send-eth", sudo=True)

    hosts: List[Dict] = []
    for host in nm.all_hosts():
        if nm[host].state() == "up":
            mac = nm[host]["addresses"].get("mac", "N/A")
            hosts.append({
                "ip":  host,
                "mac": mac.upper() if mac != "N/A" else "N/A",
            })
    return hosts


# ──────────────────────────────────────────────────────────────────────────────
# Hostname resolution
# ──────────────────────────────────────────────────────────────────────────────

def resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup. Returns 'N/A' on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/A"
