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
Rich terminal output for Munin — pretty-prints every part of the scan result.
"""

from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.padding import Padding
from rich.rule    import Rule
from rich         import box

console = Console()

# ─────────────────────────────────────────────────────────────────────────────
# Color / label maps
# ─────────────────────────────────────────────────────────────────────────────

RISK_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "MINIMAL":  "dim green",
    "UNKNOWN":  "dim white",
}

RISK_LABEL = {
    "CRITICAL": "[CRITICAL]",
    "HIGH":     "[HIGH]",
    "MEDIUM":   "[MEDIUM]",
    "LOW":      "[LOW]",
    "MINIMAL":  "[MINIMAL]",
    "UNKNOWN":  "[UNKNOWN]",
}

SEVERITY_COLOR = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "NONE":     "dim",
    "UNKNOWN":  "dim",
}


# ─────────────────────────────────────────────────────────────────────────────
# Summary panel
# ─────────────────────────────────────────────────────────────────────────────

def print_summary(result: dict) -> None:
    meta  = result.get("meta", {})
    hosts = result.get("hosts", [])

    total_ports = sum(len(h.get("ports", [])) for h in hosts)
    total_cves  = sum(
        sum(len(p.get("cves", [])) for p in h.get("ports", []))
        for h in hosts
    )
    risk_counts: dict = {}
    for h in hosts:
        lvl = h.get("risk_level", "UNKNOWN")
        risk_counts[lvl] = risk_counts.get(lvl, 0) + 1

    t = Table(box=None, show_header=False, padding=(0, 2))
    t.add_column("key",   style="bold cyan", width=22, no_wrap=True)
    t.add_column("value", style="white")

    t.add_row("Target",       meta.get("target", "N/A"))
    t.add_row("Scan started", meta.get("scan_time", "N/A"))
    t.add_row("Duration",     f"{meta.get('scan_duration', 0):.1f} s")
    t.add_row("Hosts found",  str(len(hosts)))
    t.add_row("Open ports",   str(total_ports))
    t.add_row("CVEs found",   str(total_cves))

    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"):
        count = risk_counts.get(lvl, 0)
        if count:
            color = RISK_COLOR[lvl]
            label = RISK_LABEL[lvl]
            t.add_row(
                f"{label} hosts",
                f"[{color}]{count}[/{color}]",
            )

    console.print(
        Panel(t, title="[bold cyan]Scan Summary[/bold cyan]",
              border_style="cyan", padding=(1, 2))
    )


# ─────────────────────────────────────────────────────────────────────────────
# Per-host detail
# ─────────────────────────────────────────────────────────────────────────────

def print_host(host: dict) -> None:
    ip         = host.get("ip", "N/A")
    risk_level = host.get("risk_level", "UNKNOWN")
    risk_score = host.get("risk_score", 0)
    color      = RISK_COLOR.get(risk_level, "white")
    label      = RISK_LABEL.get(risk_level, "[?]")
    os_info    = host.get("os", {})

    info = Table(box=None, show_header=False, padding=(0, 1))
    info.add_column("k", style="dim", width=14, no_wrap=True)
    info.add_column("v", style="white")

    info.add_row("MAC",      host.get("mac", "N/A"))
    info.add_row("Vendor",   host.get("mac_vendor", "Unknown"))
    info.add_row("Hostname", host.get("hostname", "N/A"))

    os_name = os_info.get("name", "Unknown")
    acc     = os_info.get("accuracy", 0)
    os_str  = f"{os_name}  [dim]({acc}% confidence)[/dim]" if acc else os_name
    info.add_row("OS",       os_str)
    info.add_row("OS type",  os_info.get("type", "Unknown"))

    title = (
        f"[bold white]{ip}[/bold white]   "
        f"[{color}]{label}  (score {risk_score}/100)[/{color}]"
    )
    console.print(Panel(info, title=title, border_style=color, padding=(0, 2)))

    # ── Ports table ──────────────────────────────────────────────────────────
    ports = host.get("ports", [])
    if ports:
        pt = Table(
            box=box.SIMPLE_HEAD,
            border_style="dim",
            header_style="bold cyan",
            padding=(0, 1),
        )
        pt.add_column("Port",    width=7,  no_wrap=True)
        pt.add_column("Proto",   width=6,  no_wrap=True)
        pt.add_column("State",   width=9,  no_wrap=True)
        pt.add_column("Service", width=12, no_wrap=True)
        pt.add_column("Product / Version", width=36)
        pt.add_column("CVEs",    width=5,  no_wrap=True)

        for p in ports:
            state_color = "green" if p["state"] == "open" else "yellow"
            pv = " ".join(filter(None, [
                p.get("product"), p.get("version"), p.get("extrainfo")
            ]))
            cve_n   = len(p.get("cves", []))
            cve_str = f"[red]{cve_n}[/red]" if cve_n else "[dim]--[/dim]"

            pt.add_row(
                str(p["port"]),
                p["protocol"],
                f"[{state_color}]{p['state']}[/{state_color}]",
                p.get("service", ""),
                pv or "[dim]--[/dim]",
                cve_str,
            )

        console.print(Padding(pt, (0, 2)))

    # ── CVE details ──────────────────────────────────────────────────────────
    for p in ports:
        cves = p.get("cves", [])
        if not cves:
            continue
        console.print(
            f"  [bold yellow]CVEs for port "
            f"{p['port']}/{p.get('service', '?')}[/bold yellow]"
        )
        for cve in cves:
            score    = cve.get("cvss_score", "N/A")
            severity = cve.get("severity", "UNKNOWN")
            sc       = SEVERITY_COLOR.get(severity, "white")
            desc     = cve.get("description", "")[:130]
            console.print(
                f"    [{sc}]* {cve['id']}[/{sc}]  "
                f"CVSS [bold]{score}[/bold]  [{sc}]{severity}[/{sc}]"
            )
            console.print(f"      [dim]{desc}[/dim]")
        console.print()

    # ── NSE script findings ──────────────────────────────────────────────────
    for port_num, scripts in host.get("vulnerabilities", {}).items():
        for script_name, output in scripts.items():
            out_str = str(output)
            if "VULNERABLE" in out_str.upper() or "vuln" in script_name.lower():
                console.print(
                    f"  [bold red]VULNERABLE  {script_name}  (port {port_num})[/bold red]"
                )
                for line in out_str.splitlines()[:6]:
                    console.print(f"    [dim]{line}[/dim]")
                console.print()


# ─────────────────────────────────────────────────────────────────────────────
# Full dump
# ─────────────────────────────────────────────────────────────────────────────

def print_findings(findings: list, score: int, level: str) -> None:
    """
    Print the correlation findings (threat patterns) for a single host.
    Called from print_host when a host carries analysis data.
    """
    if not findings:
        return

    color = RISK_COLOR.get(level, "white")

    # ── Threat table ─────────────────────────────────────────────────────────
    t = Table(
        box=box.SIMPLE_HEAD,
        border_style="dim",
        header_style="bold yellow",
        padding=(0, 1),
    )
    t.add_column("Severity", width=10, no_wrap=True)
    t.add_column("Threat",   width=30, no_wrap=True)
    t.add_column("Detail",   width=60)

    SEV_COLOR = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "cyan",
    }

    for f in sorted(
        findings,
        key=lambda x: {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(
            x.get("severity", "LOW"), 0
        ),
        reverse=True,
    ):
        sev = f.get("severity", "?")
        sc  = SEV_COLOR.get(sev, "white")
        t.add_row(
            f"[{sc}]{sev}[/{sc}]",
            f["name"],
            f.get("detail", ""),
        )

    console.print(
        Rule(
            f"[bold yellow]Threat Analysis  [{color}]{level} {score}/100[/{color}][/bold yellow]",
            style="yellow",
        )
    )
    console.print(Padding(t, (0, 2)))

    # ── Remediation ───────────────────────────────────────────────────────────
    from scanner.analysis.risk_engine import prioritised_remediation, explain

    steps = prioritised_remediation(findings)
    if steps:
        console.print("  [bold cyan]Recommended Actions[/bold cyan]")
        for step in steps[:8]:   # cap at 8 to avoid wall of text
            console.print(f"    [dim]{step}[/dim]")
        console.print()

    # ── Explain mode ──────────────────────────────────────────────────────────
    explanations = explain(findings)
    if explanations:
        console.print("  [bold cyan]Why these threats were flagged[/bold cyan]")
        for exp in explanations:
            console.print(f"    [dim]* {exp}[/dim]")
        console.print()


def print_all(result: dict) -> None:
    """Render the complete scan result to the terminal."""
    print_summary(result)
    console.print()

    hosts = sorted(
        result.get("hosts", []),
        key=lambda h: h.get("risk_score", 0),
        reverse=True,
    )

    console.rule(f"[bold cyan]Host Details  ({len(hosts)} hosts found)[/bold cyan]")
    console.print()

    for host in hosts:
        print_host(host)

        # Print correlation findings if present
        findings = host.get("findings", [])
        if findings:
            print_findings(
                findings,
                host.get("risk_score", 0),
                host.get("risk_level", "UNKNOWN"),
            )

        console.print()

    # ── Network-wide one-line summaries ───────────────────────────────────────
    critical_hosts = [
        h for h in hosts
        if h.get("findings") and h.get("risk_level") in ("CRITICAL", "HIGH")
    ]
    if critical_hosts:
        from scanner.analysis.risk_engine import one_line_summary
        console.rule("[bold red]Priority Threats[/bold red]")
        console.print()
        for h in critical_hosts:
            summary = one_line_summary(
                h["ip"],
                h.get("findings", []),
                h.get("risk_score", 0),
                h.get("risk_level", "UNKNOWN"),
            )
            console.print(f"  [red]*[/red] {summary}")
        console.print()
