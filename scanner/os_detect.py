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
OS fingerprinting (nmap -O) and MAC-vendor lookup.
The vendor lookup uses mac-vendor-lookup (offline DB) with an API fallback.
"""

import time
import requests
from typing import Dict

from rich.console import Console

console = Console()

# Simple in-process cache so we don't hammer the API
_VENDOR_CACHE: Dict[str, str] = {}
_MAC_LOOKUP_INSTANCE = None


def _get_mac_lookup():
    """Lazy-init MacLookup and download DB once per process."""
    global _MAC_LOOKUP_INSTANCE
    if _MAC_LOOKUP_INSTANCE is None:
        try:
            from mac_vendor_lookup import MacLookup  # type: ignore
            _MAC_LOOKUP_INSTANCE = MacLookup()
            # Quietly try to update the vendor DB (fails silently offline)
            try:
                _MAC_LOOKUP_INSTANCE.update_vendors()
            except Exception:
                pass
        except ImportError:
            pass
    return _MAC_LOOKUP_INSTANCE


# ──────────────────────────────────────────────────────────────────────────────
# Public helpers
# ──────────────────────────────────────────────────────────────────────────────

def get_mac_vendor(mac: str) -> str:
    """
    Resolve a MAC address to its manufacturer.
    Priority: offline DB → macvendors.com API → 'Unknown'
    """
    if not mac or mac == "N/A":
        return "Unknown"

    # Normalise separators and upper-case
    mac_norm = mac.upper().replace("-", ":").strip()

    if mac_norm in _VENDOR_CACHE:
        return _VENDOR_CACHE[mac_norm]

    # 1) Offline library
    lookup = _get_mac_lookup()
    if lookup:
        try:
            vendor = lookup.lookup(mac_norm)
            _VENDOR_CACHE[mac_norm] = vendor
            return vendor
        except Exception:
            pass

    # 2) API fallback
    try:
        r = requests.get(
            f"https://api.macvendors.com/{mac_norm}",
            timeout=4,
            headers={"User-Agent": "NetAudit/1.0"},
        )
        if r.status_code == 200:
            vendor = r.text.strip()
            _VENDOR_CACHE[mac_norm] = vendor
            return vendor
    except Exception:
        pass

    _VENDOR_CACHE[mac_norm] = "Unknown"
    return "Unknown"


def detect_os(ip: str) -> Dict:
    """
    Run `nmap -O --osscan-guess` on a single host.

    Returns a dict with keys:
      name, accuracy, type, vendor, osfamily, cpe
    """
    import nmap  # type: ignore

    nm = nmap.PortScanner()
    default = {
        "name": "Unknown",
        "accuracy": 0,
        "type": "Unknown",
        "vendor": "Unknown",
        "osfamily": "Unknown",
        "cpe": "",
    }

    try:
        nm.scan(hosts=ip, arguments="-O --osscan-guess -T4", sudo=True)

        if ip not in nm.all_hosts():
            return default

        os_matches = nm[ip].get("osmatch", [])
        if not os_matches:
            return default

        best = os_matches[0]
        os_class = (best.get("osclass") or [{}])[0]

        return {
            "name":     best.get("name", "Unknown"),
            "accuracy": int(best.get("accuracy", 0)),
            "type":     os_class.get("type", "Unknown"),
            "vendor":   os_class.get("vendor", "Unknown"),
            "osfamily": os_class.get("osfamily", "Unknown"),
            "cpe":      (os_class.get("cpe") or [""])[0],
        }

    except Exception as exc:
        console.print(f"[yellow]⚠  OS detection error on {ip}: {exc}[/yellow]")
        return default
