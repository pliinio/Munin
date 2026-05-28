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
Munin — Network Reconnaissance & Vulnerability Assessment Framework
"""

import os
import sys
import json
import time
import shlex
from datetime import datetime
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
REQUIRED = ["nmap", "rich", "requests"]
MISSING  = []
for pkg in REQUIRED:
    try:
        __import__(pkg)
    except ImportError:
        MISSING.append(pkg)

if MISSING:
    print(f"[ERROR] Missing packages: {', '.join(MISSING)}")
    print("Run:  pip install -r requirements.txt")
    sys.exit(1)

# ── Rich imports ──────────────────────────────────────────────────────────────
from rich.console  import Console
from rich.table    import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.rule     import Rule
from rich          import box

# ── Internal imports ──────────────────────────────────────────────────────────
from scanner.discovery import arp_scan, resolve_hostname
from scanner.os_detect  import get_mac_vendor, detect_os
from scanner.portscan   import scan_ports, get_open_port_numbers, PROFILES
from scanner.vulnscan   import (
    run_nse_vuln_scripts,
    enrich_ports_with_cves,
    calculate_risk,
)
from scanner.logreader  import read_log, LogReadError
from scanner.analysis.correlator  import correlate
from scanner.analysis.risk_engine import (
    calculate_risk as smart_calculate_risk,
    one_line_summary,
    summarize,
    prioritised_remediation,
    full_report,                  # ← v2: NLP business report
)
from report.terminal    import print_all
from report.html_report import generate as generate_html

from scanner.analysis.compliance_mapper   import (
    compliance_score,
    enrich_finding_with_compliance,
    environment_compliance_score,
)
from scanner.analysis.remediation_engine  import (
    prioritize_environment,
    top_actions,
)
from scanner.analysis.asset_criticality   import enrich_host_with_criticality


console = Console()

VERSION = "2.0.2"

BANNER = r"""
[bold cyan]
  ███╗   ███╗██╗   ██╗███╗   ██╗██╗███╗   ██╗
  ████╗ ████║██║   ██║████╗  ██║██║████╗  ██║
  ██╔████╔██║██║   ██║██╔██╗ ██║██║██╔██╗ ██║
  ██║╚██╔╝██║██║   ██║██║╚██╗██║██║██║╚██╗██║
  ██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║██║ ╚████║
  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝
[/bold cyan][dim]  Cyber Risk Intelligence Platform[/dim]
[dim]  v{version}  --  Use only on networks you own or have explicit permission to audit[/dim]
"""

HELP_TEXT = """\
[bold cyan]Core commands[/bold cyan]

  [cyan]scan net[/cyan] [white]<CIDR>[/white]             Full pipeline: discovery, OS, ports, CVEs
                              Example: scan net 192.168.1.0/24

  [cyan]scan host[/cyan] [white]<IP>[/white]              Port scan + CVE lookup on a single host
                              Example: scan host 192.168.1.105

  [cyan]discover[/cyan] [white]<CIDR>[/white]             ARP scan only — list live IPs and MACs
                              Example: discover 192.168.1.0/24

[bold cyan]Log analysis[/bold cyan]

  [cyan]readlog[/cyan] [white]<path>[/white]              Parse a system log file and display a table
                              Supports: syslog, auth.log, access.log, kern.log, custom
                              Example: readlog /var/log/syslog
                              Example: readlog /var/log/nginx/access.log

[bold cyan]Settings[/bold cyan]

  [cyan]set profile[/cyan] [white]<name>[/white]          Scan profile: quick | normal | full | stealth
  [cyan]set cve[/cyan] [white]<on|off>[/white]            Enable/disable NVD CVE lookup
  [cyan]set nse[/cyan] [white]<on|off>[/white]            Enable/disable NSE vulnerability scripts
  [cyan]set audience[/cyan] [white]<name>[/white]         NLP report audience: manager | auditor | board
  [cyan]show settings[/cyan]               Print current settings

[bold cyan]Reports[/bold cyan]

  [cyan]load[/cyan] [white]<json_path>[/white]            Load a saved JSON result and regenerate reports
  [cyan]export html[/cyan]                 Generate HTML report from the last scan result
  [cyan]export report[/cyan]               Generate plain-language business report from last scan

[bold cyan]General[/bold cyan]

  [cyan]help[/cyan]                        Show this help
  [cyan]version[/cyan]                     Show version info
  [cyan]clear[/cyan]                       Clear the terminal screen
  [cyan]exit[/cyan] / [cyan]quit[/cyan]                 Exit Munin

[bold cyan]v2 commands[/bold cyan]

  [cyan]compliance[/cyan]                  Show compliance posture (ISO 27001 / NIST / CIS / LGPD)
  [cyan]remediation[/cyan]                 Show prioritized remediation plan
  [cyan]history[/cyan]                     Show scan history and trend summary
  [cyan]export pdf[/cyan]                  Generate PDF executive report
  [cyan]export siem[/cyan] [white][connector][/white]  Push to SIEM (elastic|splunk|graylog|syslog|webhook|auto)
  [cyan]set criticality[/cyan] [white]<on|off>[/white]  Enable/disable asset criticality scoring


[bold cyan]Scan profiles[/bold cyan]

  quick    Top 1 000 ports, T4 (fast, ~1 min/host)
  normal   Top 10 000 ports + default scripts, T4 (recommended)
  full     All 65 535 ports + version detection, T4 (thorough)
  stealth  All ports, low rate T2 (slow, quiet)

[bold cyan]Threat analysis[/bold cyan]

  correlate [white]<IP> <logpath>[/white]  Attach a log file to a scanned host and re-run
                              full threat correlation
                              Example: correlate 192.168.1.10 /var/log/auth.log

[bold cyan]Risk levels[/bold cyan]

  0–20   LOW       Minimal exposure, low urgency
  21–50  MEDIUM    Notable risks, schedule remediation
  51–80  HIGH      Serious exposure, act soon
  81–100 CRITICAL  Immediate action required

[bold cyan]NLP report audiences[/bold cyan]

  manager  Plain language for IT coordinators and department heads (default)
  auditor  Compliance-oriented for ISO 27001 / LGPD auditors
  board    Executive summary for C-suite and board of directors
"""


# ─────────────────────────────────────────────────────────────────────────────
# Privilege check
# ─────────────────────────────────────────────────────────────────────────────

def check_root() -> bool:
    if os.geteuid() != 0:
        console.print(
            "[yellow]WARNING  Munin requires root / sudo for:\n"
            "         ARP scan, OS fingerprinting (-O), SYN scan (-sS)\n"
            "         Run:  sudo python main.py[/yellow]"
        )
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# Settings state
# ─────────────────────────────────────────────────────────────────────────────

class Settings:
    def __init__(self):
        self.profile  = "normal"
        self.do_cve   = True
        self.do_nse   = True
        self.audience = "manager"   # ← v2: NLP audience

    def show(self):
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("key",   style="dim",   width=18)
        t.add_column("value", style="white")
        t.add_row("scan profile", f"[cyan]{self.profile}[/cyan]")
        t.add_row("cve lookup",   "[green]on[/green]" if self.do_cve else "[red]off[/red]")
        t.add_row("nse scripts",  "[green]on[/green]" if self.do_nse else "[red]off[/red]")
        t.add_row("nlp audience", f"[cyan]{self.audience}[/cyan]")
        console.print()
        console.print(t)


# ─────────────────────────────────────────────────────────────────────────────
# Scan pipeline helpers
# ─────────────────────────────────────────────────────────────────────────────

def _scan_single_host(ip: str, profile: str, do_cve: bool, do_nse: bool,
                      log_entries: list | None = None,
                      audience: str = "manager") -> dict:
    host: dict = {
        "ip": ip, "mac": "N/A", "mac_vendor": "Unknown",
        "hostname": "N/A", "os": {}, "ports": [],
        "vulnerabilities": {}, "risk_score": 0, "risk_level": "UNKNOWN",
        "findings": [], "logs": [],
        "business_report": None,    # ← v2: populated after scoring
    }

    if log_entries:
        host["logs"] = log_entries

    host["hostname"] = resolve_hostname(ip)

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  console=console, transient=True) as prog:
        prog.add_task(f"OS fingerprinting {ip}...")
        host["os"] = detect_os(ip)

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        prog.add_task(f"Port scan ({profile}) {ip}...")
        host["ports"] = scan_ports(ip, profile)

    open_ports = get_open_port_numbers(host["ports"])

    if do_nse and open_ports:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            prog.add_task(f"NSE vuln scripts {ip}...")
            host["vulnerabilities"] = run_nse_vuln_scripts(ip, open_ports)

    if do_cve:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                      console=console, transient=True) as prog:
            prog.add_task(f"CVE lookup {ip}...")
            host["ports"] = enrich_ports_with_cves(host["ports"])

    # ── Correlation & smart risk scoring ────────────────────────────────────
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  console=console, transient=True) as prog:
        prog.add_task(f"Correlating threats {ip}...")
        host["findings"] = correlate(host, all_hosts=None)

    host["risk_score"], host["risk_level"] = smart_calculate_risk(
        host["ports"], host["vulnerabilities"], host["findings"]
    )

    host["threat_summary"] = one_line_summary(
        ip, host["findings"], host["risk_score"], host["risk_level"]
    )

    # ── v2: Enrich findings with compliance references ────────────────────────
    for f in host["findings"]:
        try:
            enrich_finding_with_compliance(f)
        except Exception:
            pass

    # ── v2: Asset criticality (adjusts risk score) ────────────────────────────
    try:
        enrich_host_with_criticality(host)
    except Exception:
        pass

    # ── v2: NLP business report ──────────────────────────────────────────────
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  console=console, transient=True) as prog:
        prog.add_task(f"Generating business report {ip}...")
        try:
            report = full_report(
                host_data=host,
                findings=host["findings"],
                score=host["risk_score"],
                level=host["risk_level"],
                audience=audience,
            )
            host["business_report"] = report.to_dict()
        except Exception as exc:
            console.print(f"[dim yellow]  NLP report skipped for {ip}: {exc}[/dim yellow]")
            host["business_report"] = None

    return host


def run_full_network_scan(target: str, profile: str, do_cve: bool, do_nse: bool,
                          audience: str = "manager") -> dict:
    start = time.time()
    result: dict = {
        "meta": {
            "target":        target,
            "scan_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_profile":  profile,
            "scan_duration": 0,
        },
        "hosts": [],
    }

    console.print()
    console.rule("[cyan]Phase 1 — Discovery[/cyan]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        prog.add_task(f"ARP scan {target}...")
        discovered = arp_scan(target)

    if not discovered:
        console.print("[yellow]No hosts found.[/yellow]")
        return result

    console.print(f"[green]  {len(discovered)} hosts found[/green]")
    console.print()
    console.rule("[cyan]Phase 2 — Host Analysis[/cyan]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("Scanning hosts...", total=len(discovered))
        for entry in discovered:
            ip  = entry["ip"]
            mac = entry.get("mac", "N/A")
            host = _scan_single_host(ip, profile, do_cve, do_nse, all_hosts=result["hosts"], audience=audience)
            host["mac"]        = mac
            host["mac_vendor"] = get_mac_vendor(mac)
            result["hosts"].append(host)
            prog.advance(task)

    result["meta"]["scan_duration"] = round(time.time() - start, 1)
    return result


def run_single_host_scan(ip: str, profile: str, do_cve: bool, do_nse: bool,
                         audience: str = "manager") -> dict:
    start = time.time()
    console.print()
    console.rule(f"[cyan]Scanning {ip}[/cyan]")

    host = _scan_single_host(ip, profile, do_cve, do_nse, audience=audience)

    result: dict = {
        "meta": {
            "target":        ip,
            "scan_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_profile":  profile,
            "scan_duration": round(time.time() - start, 1),
        },
        "hosts": [host],
    }
    return result


def run_discovery_only(target: str) -> dict:
    start = time.time()
    console.print()
    console.rule("[cyan]ARP Discovery[/cyan]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  TimeElapsedColumn(), console=console, transient=True) as prog:
        prog.add_task(f"Scanning {target}...")
        discovered = arp_scan(target)

    if not discovered:
        console.print("[yellow]No hosts found.[/yellow]")
        return {"meta": {}, "hosts": []}

    hosts = []
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  BarColumn(), TextColumn("{task.completed}/{task.total}"),
                  console=console) as prog:
        task = prog.add_task("Resolving hostnames & vendors...", total=len(discovered))
        for entry in discovered:
            ip  = entry["ip"]
            mac = entry.get("mac", "N/A")
            hosts.append({
                "ip":         ip,
                "mac":        mac,
                "mac_vendor": get_mac_vendor(mac),
                "hostname":   resolve_hostname(ip),
                "os":         {},
                "ports":      [],
                "vulnerabilities": {},
                "risk_score": 0,
                "risk_level": "UNKNOWN",
                "business_report": None,
            })
            prog.advance(task)

    result = {
        "meta": {
            "target":        target,
            "scan_time":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "scan_profile":  "discovery-only",
            "scan_duration": round(time.time() - start, 1),
        },
        "hosts": hosts,
    }

    t = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan")
    t.add_column("IP",       style="cyan")
    t.add_column("MAC",      style="dim")
    t.add_column("Vendor")
    t.add_column("Hostname")
    for h in hosts:
        t.add_row(h["ip"], h["mac"], h["mac_vendor"], h["hostname"])
    console.print(t)
    console.print(
        f"[green]  {len(hosts)} hosts found in "
        f"{result['meta']['scan_duration']}s[/green]"
    )
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Post-scan helpers
# ─────────────────────────────────────────────────────────────────────────────

def _save_json(result: dict) -> Path:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"munin_{ts}.json")
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False))
    return path


def _save_html(result: dict, suffix: str = "") -> str:
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    name = f"munin_{suffix + '_' if suffix else ''}{ts}.html"
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"),
                  console=console, transient=True) as prog:
        prog.add_task("Generating HTML report...")
        out = generate_html(result, name)
    return out


def _print_business_reports(result: dict, audience: str = "manager") -> None:
    """Print plain-language business reports for all hosts in a result."""
    hosts = result.get("hosts", [])
    if not hosts:
        console.print("[yellow]No hosts to report.[/yellow]")
        return

    console.print()
    console.rule(f"[cyan]Business Report — audience: {audience}[/cyan]")

    for host in hosts:
        # Use cached report if available and audience matches
        cached = host.get("business_report")
        if cached and cached.get("audience") == audience:
            _render_business_report_dict(cached)
            continue

        # Otherwise generate on demand
        try:
            report = full_report(
                host_data=host,
                findings=host.get("findings", []),
                score=host.get("risk_score", 0),
                level=host.get("risk_level", "LOW"),
                audience=audience,
            )
            _render_business_report_dict(report.to_dict())
        except Exception as exc:
            console.print(f"[red]  Could not generate report for {host.get('ip', '?')}: {exc}[/red]")


def _render_business_report_dict(report: dict) -> None:
    """Render a business report dict to the Rich console."""
    ip        = report.get("ip", "?")
    level     = report.get("risk_level", "?")
    score     = report.get("score", 0)
    urgency   = report.get("urgency_label", "")
    gen_by    = report.get("generated_by", "template")
    audience  = report.get("audience", "manager")

    # Colour the risk level
    level_colour = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "green",
    }.get(level, "white")

    console.print()
    console.print(
        f"[bold]{ip}[/bold]  "
        f"[{level_colour}]{level} {score}/100[/{level_colour}]  "
        f"[dim]urgency: {urgency}  ·  generated by: {gen_by}  ·  audience: {audience}[/dim]"
    )
    console.print()

    summary = report.get("executive_summary", "")
    if summary:
        console.print(f"  [bold]Summary[/bold]")
        console.print(f"  {summary}")
        console.print()

    impact = report.get("business_impact", "")
    if impact:
        console.print(f"  [bold]Business Impact[/bold]")
        console.print(f"  {impact}")
        console.print()

    flags = report.get("compliance_flags", [])
    if flags:
        console.print(f"  [bold]Compliance Flags[/bold]")
        for flag in flags:
            console.print(f"  [dim]•[/dim] {flag}")
        console.print()

    actions = report.get("priority_actions", [])
    if actions:
        console.print(f"  [bold]Priority Actions[/bold]")
        for i, action in enumerate(actions, 1):
            console.print(f"  [cyan]{i}.[/cyan] {action}")

    console.print()
    console.print("─" * 60)


def _save_business_report_md(result: dict, audience: str) -> Path:
    """Export all business reports to a Markdown file."""
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"munin_report_{audience}_{ts}.md")

    lines = [
        f"# Munin Business Report — {audience.capitalize()}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Target: {result.get('meta', {}).get('target', 'unknown')}",
        "",
    ]

    for host in result.get("hosts", []):
        cached = host.get("business_report")
        if cached and cached.get("audience") == audience:
            report_dict = cached
        else:
            try:
                report = full_report(
                    host_data=host,
                    findings=host.get("findings", []),
                    score=host.get("risk_score", 0),
                    level=host.get("risk_level", "LOW"),
                    audience=audience,
                )
                report_dict = report.to_dict()
            except Exception:
                continue

        ip      = report_dict.get("ip", "?")
        level   = report_dict.get("risk_level", "?")
        score   = report_dict.get("score", 0)
        urgency = report_dict.get("urgency_label", "")

        lines += [
            f"## {ip}  —  {level} ({score}/100)",
            f"**Urgency:** {urgency}",
            "",
            "### Summary",
            report_dict.get("executive_summary", ""),
            "",
            "### Business Impact",
            report_dict.get("business_impact", ""),
            "",
        ]

        flags = report_dict.get("compliance_flags", [])
        if flags:
            lines += ["### Compliance Flags"]
            lines += [f"- {f}" for f in flags]
            lines += [""]

        actions = report_dict.get("priority_actions", [])
        if actions:
            lines += ["### Priority Actions"]
            lines += [f"{i+1}. {a}" for i, a in enumerate(actions)]
            lines += [""]

        lines += ["---", ""]

    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def save_and_report(result: dict, s: "Settings") -> None:
    if not result.get("hosts"):
        return

    console.print()
    console.rule("[cyan]Results[/cyan]")
    print_all(result)

    # ── v2: NLP business report ──────────────────────────────────────────────
    ans_nlp = _ask("Generate plain-language business report? [y/N]: ").strip().lower()
    if ans_nlp in ("y", "yes"):
        audience_input = _ask(
            f"Audience [manager/auditor/board] (Enter = {s.audience}): "
        ).strip().lower()
        audience = (
            audience_input
            if audience_input in ("manager", "auditor", "board")
            else s.audience
        )
        _print_business_reports(result, audience)

        ans_md = _ask("Save business report as Markdown? [y/N]: ").strip().lower()
        if ans_md in ("y", "yes"):
            p = _save_business_report_md(result, audience)
            console.print(f"[green]  Markdown saved: {p.resolve()}[/green]")

    # ── Original post-scan options (unchanged) ───────────────────────────────
    ans = _ask("Save raw JSON result? [y/N]: ").strip().lower()
    if ans in ("y", "yes"):
        p = _save_json(result)
        console.print(f"[green]  JSON saved: {p.resolve()}[/green]")

    ans = _ask("Generate interactive HTML report? [y/N]: ").strip().lower()
    if ans in ("y", "yes"):
        out = _save_html(result)
        console.print(f"[green]  HTML saved: {out}[/green]")
        console.print(f"  Open in browser:  xdg-open {out}")


# ─────────────────────────────────────────────────────────────────────────────
# Log reader command
# ─────────────────────────────────────────────────────────────────────────────

def cmd_readlog(path_str: str) -> None:
    """Parse a log file, render a Rich table, run threat correlation, offer .md export."""
    console.print()
    console.rule(f"[cyan]Log Reader — {path_str}[/cyan]")

    try:
        log_type, entries = read_log(path_str)
    except LogReadError as exc:
        console.print(f"[red]ERROR  {exc}[/red]")
        return

    if not entries:
        console.print("[yellow]No entries found in the log file.[/yellow]")
        return

    console.print(
        f"[dim]  Detected format: [cyan]{log_type}[/cyan]  "
        f"({len(entries)} entries)[/dim]\n"
    )

    columns = list(entries[0].keys())

    t = Table(
        box=box.MINIMAL_DOUBLE_HEAD,
        border_style="dim",
        header_style="bold cyan",
        show_lines=False,
        padding=(0, 1),
    )
    col_widths = {
        "timestamp": 22, "level": 7, "host": 16, "process": 18,
        "pid": 7, "message": 60, "method": 7, "path": 40,
        "status": 7, "size": 8, "ip": 15, "user": 14,
        "facility": 10, "source": 20,
    }
    for col in columns:
        width = col_widths.get(col, 20)
        t.add_column(col.upper(), width=width, no_wrap=(col != "message"))

    def _style(col: str, val: str) -> str:
        if col == "level":
            return {
                "ERROR":   "[red]ERROR[/red]",
                "WARN":    "[yellow]WARN[/yellow]",
                "WARNING": "[yellow]WARNING[/yellow]",
                "INFO":    "[green]INFO[/green]",
                "DEBUG":   "[dim]DEBUG[/dim]",
                "CRIT":    "[bold red]CRIT[/bold red]",
                "NOTICE":  "[cyan]NOTICE[/cyan]",
            }.get(val.upper(), val)
        if col == "status":
            try:
                code = int(val)
                if code >= 500: return f"[red]{val}[/red]"
                if code >= 400: return f"[yellow]{val}[/yellow]"
                if code >= 300: return f"[cyan]{val}[/cyan]"
                return f"[green]{val}[/green]"
            except ValueError:
                return val
        return val

    for entry in entries:
        row = [_style(col, str(entry.get(col, ""))) for col in columns]
        t.add_row(*row)

    console.print(t)
    console.print(
        f"\n[dim]  Showing {len(entries)} log entries from "
        f"[cyan]{Path(path_str).name}[/cyan][/dim]"
    )

    _run_log_correlation(entries, log_type)

    ans = _ask("\nExport table to Markdown file? [y/N]: ").strip().lower()
    if ans in ("y", "yes"):
        _export_log_md(columns, entries, path_str)


def _run_log_correlation(entries: list, log_type: str) -> None:
    """Run the correlator against log entries only (no scan data) and print findings."""
    from scanner.analysis.correlator  import correlate
    from scanner.analysis.risk_engine import (
        calculate_risk as smart_risk,
        prioritised_remediation,
        explain,
    )
    from report.terminal import print_findings

    host_data = {
        "ip": "log-only",
        "ports": [],
        "vulnerabilities": {},
        "findings": [],
        "logs": entries,
    }

    findings = correlate(host_data, all_hosts=None)
    if not findings:
        console.print(
            "\n[dim green]  No threats detected in this log file.[/dim green]\n"
        )
        return

    score, level = smart_risk([], {}, findings)

    console.print()
    console.rule("[bold yellow]Log Threat Analysis[/bold yellow]")
    print_findings(findings, score, level)


def _export_log_md(columns: list, entries: list, source_path: str) -> None:
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    src_name = Path(source_path).name
    out_path = Path(f"munin_log_{src_name}_{ts}.md")

    lines = []
    lines.append(f"# Log Report — `{src_name}`\n")
    lines.append(
        f"Generated by Munin {VERSION} on "
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    lines.append("")
    lines.append("| " + " | ".join(c.upper() for c in columns) + " |")
    lines.append("| " + " | ".join("---" for _ in columns) + " |")

    import re
    _strip = lambda s: re.sub(r"\[/?[^\]]+\]", "", str(s))

    for entry in entries:
        cells = [_strip(entry.get(col, "")).replace("|", "\\|") for col in columns]
        lines.append("| " + " | ".join(cells) + " |")

    out_path.write_text("\n".join(lines), encoding="utf-8")
    console.print(f"[green]  Markdown saved: {out_path.resolve()}[/green]")


def cmd_correlate(ip: str, log_path: str, last_result: dict) -> None:
    """
    Attach a log file to an already-scanned host and re-run full threat
    correlation combining scan data + log events.
    """
    from scanner.analysis.correlator  import correlate
    from scanner.analysis.risk_engine import (
        calculate_risk as smart_risk,
        one_line_summary,
    )
    from report.terminal import print_findings

    host = next(
        (h for h in last_result.get("hosts", []) if h.get("ip") == ip),
        None,
    )

    if not host:
        console.print(
            f"[yellow]Host {ip} not found in last scan result. "
            f"Run 'scan host {ip}' first.[/yellow]"
        )
        return

    console.print()
    console.rule(f"[cyan]Correlating {ip} with {log_path}[/cyan]")

    try:
        log_type, entries = read_log(log_path)
    except LogReadError as exc:
        console.print(f"[red]ERROR  {exc}[/red]")
        return

    console.print(
        f"[dim]  Log format: [cyan]{log_type}[/cyan]  ({len(entries)} entries)[/dim]"
    )

    host["logs"]     = entries
    host["findings"] = correlate(host, all_hosts=None)
    host["risk_score"], host["risk_level"] = smart_risk(
        host["ports"], host.get("vulnerabilities", {}), host["findings"]
    )
    host["threat_summary"] = one_line_summary(
        ip, host["findings"], host["risk_score"], host["risk_level"]
    )

    print_findings(host["findings"], host["risk_score"], host["risk_level"])

    if not host["findings"]:
        console.print(
            "[dim green]  No additional threats detected after log correlation.[/dim green]\n"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Input helper
# ─────────────────────────────────────────────────────────────────────────────

def _ask(prompt: str) -> str:
    try:
        return input(prompt)
    except (EOFError, KeyboardInterrupt):
        return ""


# ─────────────────────────────────────────────────────────────────────────────
# Command dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def dispatch(line: str, s: Settings, last_result: dict) -> dict:
    """Parse and execute one command line. Returns (possibly updated) last_result."""
    try:
        parts = shlex.split(line)
    except ValueError:
        parts = line.split()

    if not parts:
        return last_result

    cmd = parts[0].lower()

    # ── help ─────────────────────────────────────────────────────────────────
    if cmd == "help":
        console.print(HELP_TEXT)

    # ── version ──────────────────────────────────────────────────────────────
    elif cmd == "version":
        console.print(f"[cyan]Munin[/cyan] v{VERSION}")
        try:
            from scanner.analysis.nlp_translator import is_ollama_available, list_ollama_models, _MODEL
            if is_ollama_available():
                models = list_ollama_models()
                console.print(f"[green]  Ollama  ✓ running[/green]  model: [cyan]{_MODEL}[/cyan]  available: {models}")
            else:
                console.print("[yellow]  Ollama  ✗ not running — run: ollama serve[/yellow]")
        except Exception:
            pass

    # ── clear ────────────────────────────────────────────────────────────────
    elif cmd == "clear":
        os.system("clear")

    # ── show settings ────────────────────────────────────────────────────────
    elif cmd == "show" and len(parts) > 1 and parts[1] == "settings":
        s.show()

    # ── set profile <name> ───────────────────────────────────────────────────
    elif cmd == "set" and len(parts) >= 3 and parts[1] == "profile":
        name = parts[2].lower()
        if name not in PROFILES:
            console.print(f"[red]Unknown profile '{name}'. "
                          f"Valid: {', '.join(PROFILES)}[/red]")
        else:
            s.profile = name
            console.print(f"[green]  profile => {name}[/green]")

    # ── set cve on|off ───────────────────────────────────────────────────────
    elif cmd == "set" and len(parts) >= 3 and parts[1] == "cve":
        val = parts[2].lower()
        if val in ("on", "true", "1"):
            s.do_cve = True
            console.print("[green]  cve lookup => on[/green]")
        elif val in ("off", "false", "0"):
            s.do_cve = False
            console.print("[yellow]  cve lookup => off[/yellow]")
        else:
            console.print("[red]Usage: set cve <on|off>[/red]")

    # ── set nse on|off ───────────────────────────────────────────────────────
    elif cmd == "set" and len(parts) >= 3 and parts[1] == "nse":
        val = parts[2].lower()
        if val in ("on", "true", "1"):
            s.do_nse = True
            console.print("[green]  nse scripts => on[/green]")
        elif val in ("off", "false", "0"):
            s.do_nse = False
            console.print("[yellow]  nse scripts => off[/yellow]")
        else:
            console.print("[red]Usage: set nse <on|off>[/red]")

    # ── set audience <name> ── v2 ─────────────────────────────────────────────
    elif cmd == "set" and len(parts) >= 3 and parts[1] == "audience":
        val = parts[2].lower()
        if val in ("manager", "auditor", "board"):
            s.audience = val
            console.print(f"[green]  nlp audience => {val}[/green]")
        else:
            console.print("[red]Usage: set audience <manager|auditor|board>[/red]")

    # ── scan net <CIDR> ──────────────────────────────────────────────────────
    elif cmd == "scan" and len(parts) >= 3 and parts[1] == "net":
        target = parts[2]
        s.show()
        ans = _ask(f"\nStart full scan on {target}? [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            last_result = run_full_network_scan(
                target, s.profile, s.do_cve, s.do_nse, audience=s.audience
            )
            save_and_report(last_result, s)
    elif cmd == "scan" and len(parts) == 2 and parts[1] == "net":
        console.print("[red]Usage: scan net <CIDR>  e.g. scan net 192.168.1.0/24[/red]")

    # ── scan host <IP> ───────────────────────────────────────────────────────
    elif cmd == "scan" and len(parts) >= 3 and parts[1] == "host":
        ip = parts[2]
        s.show()
        ans = _ask(f"\nStart scan on {ip}? [y/N]: ").strip().lower()
        if ans in ("y", "yes"):
            last_result = run_single_host_scan(
                ip, s.profile, s.do_cve, s.do_nse, audience=s.audience
            )
            save_and_report(last_result, s)
    elif cmd == "scan" and len(parts) == 2 and parts[1] == "host":
        console.print("[red]Usage: scan host <IP>  e.g. scan host 192.168.1.105[/red]")

    # ── discover <CIDR> ──────────────────────────────────────────────────────
    elif cmd == "discover":
        if len(parts) < 2:
            console.print("[red]Usage: discover <CIDR>  e.g. discover 192.168.1.0/24[/red]")
        else:
            last_result = run_discovery_only(parts[1])
            if last_result.get("hosts"):
                ans = _ask("\nGenerate HTML report for discovered hosts? [y/N]: ").strip().lower()
                if ans in ("y", "yes"):
                    out = _save_html(last_result, "discovery")
                    console.print(f"[green]  HTML saved: {out}[/green]")

    # ── readlog <path> ───────────────────────────────────────────────────────
    elif cmd == "readlog":
        if len(parts) < 2:
            console.print("[red]Usage: readlog <path>  e.g. readlog /var/log/syslog[/red]")
        else:
            cmd_readlog(parts[1])

    # ── correlate <IP> <logpath> ─────────────────────────────────────────────
    elif cmd == "correlate":
        if len(parts) < 3:
            console.print("[red]Usage: correlate <IP> <logpath>[/red]")
        else:
            cmd_correlate(parts[1], parts[2], last_result)

    # ── export html ──────────────────────────────────────────────────────────
    elif cmd == "export" and len(parts) >= 2 and parts[1] == "html":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result in memory. Run a scan first.[/yellow]")
        else:
            out = _save_html(last_result)
            console.print(f"[green]  HTML saved: {out}[/green]")

    # ── export report ── v2 ───────────────────────────────────────────────────
    elif cmd == "export" and len(parts) >= 2 and parts[1] == "report":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result in memory. Run a scan first.[/yellow]")
        else:
            audience_input = _ask(
                f"Audience [manager/auditor/board] (Enter = {s.audience}): "
            ).strip().lower()
            audience = (
                audience_input
                if audience_input in ("manager", "auditor", "board")
                else s.audience
            )
            _print_business_reports(last_result, audience)
            ans_md = _ask("Save as Markdown? [y/N]: ").strip().lower()
            if ans_md in ("y", "yes"):
                p = _save_business_report_md(last_result, audience)
                console.print(f"[green]  Markdown saved: {p.resolve()}[/green]")

    # ── load <json_path> ─────────────────────────────────────────────────────
    elif cmd == "load":
        if len(parts) < 2:
            console.print("[red]Usage: load <json_path>[/red]")
        else:
            p = Path(parts[1])
            if not p.exists():
                console.print(f"[red]File not found: {parts[1]}[/red]")
            else:
                try:
                    loaded = json.loads(p.read_text())
                    n = len(loaded.get("hosts", []))
                    console.print(f"[green]  {n} hosts loaded from {parts[1]}[/green]")
                    print_all(loaded)
                    last_result = loaded
                    ans = _ask("Generate HTML report? [y/N]: ").strip().lower()
                    if ans in ("y", "yes"):
                        out = _save_html(last_result, "loaded")
                        console.print(f"[green]  HTML saved: {out}[/green]")
                except Exception as exc:
                    console.print(f"[red]Error loading JSON: {exc}[/red]")


    # ── compliance ─────────────────────────────────────────────────────────────
    elif cmd == "compliance":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result. Run a scan first.[/yellow]")
        else:
            try:
                from scanner.analysis.compliance_mapper import environment_compliance_score
                hosts  = last_result.get("hosts", [])
                env_cs = environment_compliance_score(hosts)
                console.print()
                console.rule("[cyan]Compliance Posture[/cyan]")
                t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
                t.add_column("framework", style="cyan", width=22)
                t.add_column("score", style="white")
                def _bar(s):
                    blocks = int(s/10)
                    color = "green" if s>=80 else "yellow" if s>=60 else "red"
                    return f"[{color}]{'█'*blocks}{'░'*(10-blocks)}[/{color}]  {s:.0f}%"
                t.add_row("ISO 27001:2022",  _bar(env_cs.get("iso27001_avg",100)))
                t.add_row("NIST CSF 2.0",   _bar(env_cs.get("nist_avg",100)))
                t.add_row("CIS Controls v8", _bar(env_cs.get("cis_avg",100)))
                lgpd = env_cs.get("lgpd_exposure","LOW")
                lc   = {"CRITICAL":"red","HIGH":"red","MEDIUM":"yellow","LOW":"green"}.get(lgpd,"green")
                t.add_row("LGPD Exposure",  f"[{lc}]{lgpd}[/{lc}]")
                console.print(t)
            except Exception as exc:
                console.print(f"[red]  Compliance error: {exc}[/red]")

    # ── remediation ────────────────────────────────────────────────────────────
    elif cmd == "remediation":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result. Run a scan first.[/yellow]")
        else:
            try:
                plans = prioritize_environment(last_result.get("hosts",[]))
                console.print()
                console.rule("[cyan]Remediation Prioritization[/cyan]")
                t = Table(box=box.SIMPLE_HEAD, border_style="dim", header_style="bold cyan", padding=(0,1))
                t.add_column("IP",        style="cyan", width=16)
                t.add_column("Priority",  width=12)
                t.add_column("Score",     width=8)
                lc_map = {"Immediate":"bold red","High":"red","Medium":"yellow","Planned":"green"}
                for plan in plans:
                    lc  = lc_map.get(plan.priority_label,"white")
                    top = plan.top_actions(1)
                    t.add_row(plan.ip, f"[{lc}]{plan.priority_label}[/{lc}]", str(plan.priority_score))
                console.print(t)
                console.print()
                console.print("[bold cyan]  Top 10 environment actions:[/bold cyan]")
                for action in top_actions(plans, 10):
                    console.print(f"  [dim]•[/dim] {action}")
            except Exception as exc:
                console.print(f"[red]  Remediation error: {exc}[/red]")

    # ── history ────────────────────────────────────────────────────────────────
    elif cmd == "history":
        try:
            from report.history import load_snapshots, latest_comparison
            snaps = load_snapshots(10)
            if not snaps:
                console.print("[yellow]No history yet. Run more scans.[/yellow]")
            else:
                console.print()
                console.rule("[cyan]Scan History[/cyan]")
                t = Table(box=box.SIMPLE_HEAD, border_style="dim", header_style="bold cyan", padding=(0,1))
                t.add_column("Scan",    width=18)
                t.add_column("Target",  width=20)
                t.add_column("Hosts",   width=7)
                t.add_column("Avg Risk",width=10)
                t.add_column("CVEs",    width=7)
                for s2 in reversed(snaps[-8:]):
                    t.add_row(s2.scan_time[:16], s2.target, str(s2.host_count),
                              f"{s2.avg_risk:.0f}", str(s2.total_cves))
                console.print(t)
                comp = latest_comparison()
                if comp:
                    dc = "green" if comp.avg_risk_delta < 0 else "red"
                    ds = "↓" if comp.avg_risk_delta < 0 else "↑"
                    console.print(f"\n  Latest vs previous: avg risk [{dc}]{ds}{abs(comp.avg_risk_delta):.1f}[/{dc}]  {comp.summary}")
        except Exception as exc:
            console.print(f"[red]  History error: {exc}[/red]")

    # ── export pdf ─────────────────────────────────────────────────────────────
    elif cmd == "export" and len(parts) >= 2 and parts[1] == "pdf":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result. Run a scan first.[/yellow]")
        else:
            try:
                from report.pdf_report import generate_pdf
                from scanner.analysis.compliance_mapper import environment_compliance_score
                import datetime as _dt
                hosts  = last_result.get("hosts",[])
                env_cs = environment_compliance_score(hosts)
                ts     = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
                out_p  = f"reports/munin_report_{s.audience}_{ts}.pdf"
                import pathlib; pathlib.Path("reports").mkdir(exist_ok=True)
                out    = generate_pdf(last_result, output_path=out_p,
                                      audience=s.audience, env_compliance=env_cs)
                console.print(f"[green]  Report saved: {out}[/green]")
            except Exception as exc:
                console.print(f"[red]  PDF export failed: {exc}[/red]")

    # ── export siem ────────────────────────────────────────────────────────────
    elif cmd == "export" and len(parts) >= 2 and parts[1] == "siem":
        if not last_result.get("hosts"):
            console.print("[yellow]No scan result. Run a scan first.[/yellow]")
        else:
            try:
                from scanner.analysis.siem_connector import send_findings, list_configured
                connector = parts[2] if len(parts) >= 3 else "auto"
                configured = list_configured()
                if not configured:
                    console.print("[yellow]  No SIEM connectors configured. Set MUNIN_SIEM_* env vars.[/yellow]")
                else:
                    results = send_findings(last_result, connector)
                    for r in results:
                        if r.success:
                            console.print(f"[green]  ✔ {r.connector}: {r.events_sent} events[/green]")
                        else:
                            console.print(f"[red]  ✗ {r.connector}: {r.error}[/red]")
            except Exception as exc:
                console.print(f"[red]  SIEM push failed: {exc}[/red]")


    # ── exit / quit ──────────────────────────────────────────────────────────
    elif cmd in ("exit", "quit"):
        console.print("\n[dim]Goodbye.[/dim]\n")
        sys.exit(0)

    # ── unknown ──────────────────────────────────────────────────────────────
    else:
        console.print(
            f"[red]Unknown command: '{line}'[/red]  "
            f"Type [cyan]help[/cyan] for available commands."
        )

    return last_result


# ─────────────────────────────────────────────────────────────────────────────
# Main REPL
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    os.system("clear")
    console.print(BANNER.format(version=VERSION))
    console.print(
        f"[dim]  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  "
        f"Type [cyan]help[/cyan] to list all commands.[/dim]\n"
    )

    if not check_root():
        ans = _ask("Continue without root? (limited features) [y/N]: ").strip().lower()
        if ans not in ("y", "yes"):
            sys.exit(0)
        console.print()

    s           = Settings()
    last_result: dict = {}

    while True:
        try:
            line = input("munin > ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Goodbye.[/dim]\n")
            sys.exit(0)

        if not line:
            continue

        last_result = dispatch(line, s, last_result)


if __name__ == "__main__":
    main()
