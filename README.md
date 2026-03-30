<div align="center">
  <img src="assets/Logo.png" alt="Munin Logo" width="120" />

  <h1>Munin</h1>

  <p><strong>Network Reconnaissance &amp; Intelligent Threat Analysis Framework</strong></p>

  <p>
    <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+"/>
    <img src="https://img.shields.io/badge/license-AGPL--3.0-blue?style=flat-square" alt="License: AGPL-3.0"/>
    <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey?style=flat-square" alt="Platform"/>
    <img src="https://img.shields.io/badge/requires-root%20%2F%20sudo-critical?style=flat-square" alt="Requires root"/>
    <img src="https://img.shields.io/badge/version-1.0.0-brightgreen?style=flat-square" alt="Version"/>
  </p>


</div>

> [!WARNING]
> **Legal Warning** — Use Munin **exclusively** on networks you own or have explicit written permission to audit. Unauthorized use is illegal in most jurisdictions and may result in criminal charges. The authors assume no liability for misuse.

---

## What is Munin?

Munin is a modular, terminal-first network security auditing framework built for security professionals and system administrators. It combines active scanning, CVE intelligence, log analysis, and an automated threat correlation engine into a single interactive shell — giving you a complete picture of your network's exposure in minutes.

Unlike standalone tools that leave interpretation to the analyst, Munin's **analysis engine** automatically crosses scan results with log data, detects attack patterns (brute force, exposed databases, NSE-confirmed exploits, and more), calculates an intelligent risk score per host, and outputs prioritised, actionable remediation steps.

---

## Key Features

| Capability | Description |
|---|---|
| **Host Discovery** | ARP broadcast scan via Scapy with automatic nmap fallback |
| **OS Fingerprinting** | nmap `-O` detection + MAC vendor lookup (offline DB + API) |
| **Port Scanning** | 4 scan profiles from stealth to full with service/version detection |
| **CVE Intelligence** | Live NVD API v2 queries — real CVEs linked to each detected service |
| **NSE Vuln Scripts** | `vuln`, `auth`, `exploit` script categories run against open ports |
| **Log Analysis** | Auto-detects syslog, auth.log, access.log, kern.log, journald |
| **Threat Correlation** | Crosses scan + log data to detect 10 attack patterns automatically |
| **Smart Risk Scoring** | 0–100 score per host weighted by CVE CVSS, NSE results, and findings |
| **Explain Mode** | Human-readable explanation for every threat detected |
| **Remediation Engine** | Prioritised, de-duplicated action list ordered by severity |
| **Terminal Output** | Rich-formatted tables, threat panels, one-line summaries |
| **HTML Report** | Self-contained interactive report with filters, sorting, threat details |
| **JSON Export** | Full raw result for archiving or re-loading into Munin |
| **Markdown Export** | Log tables exported as `.md` for documentation |

---

## Architecture

```
munin/
│
├── main.py                        # Interactive REPL shell + scan orchestration
├── requirements.txt
├── README.md
│
├── scanner/                       # Active scanning modules
│   ├── discovery.py               # ARP scan + hostname resolution
│   ├── os_detect.py               # nmap -O + MAC vendor lookup
│   ├── portscan.py                # Port scan (4 profiles) + service detection
│   ├── vulnscan.py                # NSE scripts + NVD CVE API + base risk score
│   ├── logreader.py               # Log parser (syslog/auth/access/kern/generic)
│   │
│   └── analysis/                  # Intelligence engine
│       ├── patterns.py            # Attack pattern registry (10 patterns)
│       ├── correlator.py          # Cross-domain threat detection engine
│       └── risk_engine.py         # Smart scoring + human-readable output
│
└── report/                        # Output renderers
    ├── terminal.py                # Rich terminal output + threat panels
    └── html_report.py             # Self-contained interactive HTML report
```

### Data Flow

```
  [Discovery] ──► [OS Detect] ──► [Port Scan] ──► [NSE Scripts] ──► [CVE Lookup]
                                                                           │
                                                                    [host_data dict]
                                                                           │
                                                    [Log Reader] ──────────┤
                                                                           │
                                                                    [Correlator]
                                                                           │
                                                               ┌───────────┴───────────┐
                                                          [Findings]            [Risk Score]
                                                               │
                                                    ┌──────────┴──────────┐
                                               [Terminal]             [HTML Report]
```

---

## Installation

### System Requirements

- Linux (Kali, Ubuntu, Debian) — macOS works with limitations (no ARP scan)
- Python 3.10+
- nmap installed at system level
- Root / sudo for ARP scan, SYN scan (`-sS`), and OS detection (`-O`)

### Steps

```bash
# 1. Install system dependencies
sudo apt update && sudo apt install -y nmap python3-pip

# 2. Enter the project directory
cd munin/

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. (Optional) Pre-download offline MAC vendor database
python3 -c "from mac_vendor_lookup import MacLookup; MacLookup().update_vendors()"

# 5. Launch
sudo python3 main.py
```

---

## Usage

### Starting the Shell

```bash
sudo python3 main.py
```

Munin opens with an ASCII banner and an interactive prompt:

```
munin >
```

Type `help` at any time to see all available commands.

---

### Core Commands

#### Full Network Scan

```
munin > scan net 192.168.1.0/24
```

Runs the complete pipeline: ARP discovery → OS fingerprinting → port scan → NSE scripts → CVE lookup → threat correlation → risk scoring. Results are shown in the terminal and you are offered JSON + HTML export.

#### Single Host Scan

```
munin > scan host 192.168.1.105
```

Skips discovery and runs the full analysis pipeline directly on one IP.

#### ARP Discovery Only

```
munin > discover 192.168.1.0/24
```

Fast host enumeration — returns IP, MAC, vendor, and hostname without port scanning.

#### Log File Analysis

```
munin > readlog /var/log/auth.log
munin > readlog /var/log/syslog
munin > readlog /var/log/nginx/access.log
```

Parses the log file, auto-detects its format, renders a Rich table in the terminal, runs threat correlation on the log events, and offers Markdown export.

#### Cross-Correlation: Scan + Log

```
munin > correlate 192.168.1.10 /var/log/auth.log
```

Attaches a log file to an already-scanned host and re-runs the full correlation engine combining both scan data and log events. This is where the analysis truly shines — SSH brute force detection, for example, requires both port 22 to be open (from scan) and failed login events (from log).

---

### Settings

```
munin > set profile quick      # quick | normal | full | stealth
munin > set cve off            # disable NVD API queries (faster scans)
munin > set nse off            # disable NSE vulnerability scripts
munin > show settings          # print current configuration
```

### Reports

```
munin > export html            # generate HTML report from last scan
munin > load munin_20260329_143012.json   # reload a saved result
```

---

## Scan Profiles

| Profile | Ports Scanned | Approximate Speed | Best For |
|---|---|---|---|
| `quick` | Top 1,000 | ~1 min/host | Fast first look |
| `normal` | Top 10,000 + scripts | ~3 min/host | Recommended default |
| `full` | All 65,535 | ~10 min/host | Thorough audit |
| `stealth` | All 65,535, T2, low rate | ~30+ min/host | IDS evasion |

---

## Threat Correlation Engine

The analysis engine (`scanner/analysis/`) is what separates Munin from a raw nmap wrapper. It operates in three layers:

### 1. Pattern Registry (`patterns.py`)

Defines 10 named attack patterns, each with severity, a risk bonus score, a plain-English description, and ordered remediation steps:

| Pattern | Severity | Trigger Conditions |
|---|---|---|
| SSH Brute Force | HIGH | Port 22 open + ≥5 failed SSH logins in logs |
| Vulnerable Service Exposed | CRITICAL | Any open port with CVE CVSS ≥ 7.0 |
| Web Exploitation Attempt | HIGH | ≥20 HTTP 4xx/5xx errors + CVE on web port |
| Critical Port Exposed | HIGH | RDP (3389), SMB (445), VNC (5900), Telnet (23) open |
| Large Attack Surface | MEDIUM | ≥15 open ports |
| NSE Confirmed Vulnerability | CRITICAL | NSE script returned `VULNERABLE` |
| Cleartext Protocol | MEDIUM | FTP (21) or Telnet (23) open |
| Database Exposed | HIGH | MySQL, PostgreSQL, MongoDB, Redis, etc. reachable |
| Auth Failure Spike | MEDIUM | ≥10 auth failures in logs (non-SSH) |
| Docker API Exposed | CRITICAL | Port 2375 or 2376 reachable |

### 2. Correlator (`correlator.py`)

Extracts log metrics (failed SSH logins, HTTP error counts, auth failures, sudo events) and evaluates each pattern rule against the combined host data. Returns a list of `Finding` dicts with full metadata.

### 3. Risk Engine (`risk_engine.py`)

Calculates a final 0–100 score from four components:

```
Base (port count + risky ports)  → up to 20 pts
CVE severity (CVSS-weighted)     → up to 35 pts
NSE confirmed vulns              → up to 25 pts
Correlation bonus (findings)     → up to 20 pts  (diminishing returns curve)
                                 ─────────────────────────────────────────────
Total (capped at 100)
```

Score bands:

| Score | Level | Meaning |
|---|---|---|
| 0–20 | LOW | Minimal exposure |
| 21–50 | MEDIUM | Notable risks, schedule remediation |
| 51–80 | HIGH | Serious exposure, act soon |
| 81–100 | CRITICAL | Immediate action required |

The engine also produces:

- **One-line summary** — `192.168.1.10 [CRITICAL 87/100] SSH Brute Force · Vulnerable Service Exposed (+2 more)`
- **Explain mode** — one plain-English sentence per finding
- **Prioritised remediation** — de-duplicated steps ordered from most to least critical finding

---

## Output Examples

### Terminal — Threat Panel

```
────────────── Threat Analysis  [CRITICAL 87/100] ──────────────

 Severity   Threat                        Detail
 ─────────  ────────────────────────────  ──────────────────────────────────────
 CRITICAL   NSE Confirmed Vulnerability   ssh-vuln-cve-2018-10933 on port 22
 CRITICAL   Vulnerable Service Exposed    port 22 (ssh) — CVE-2023-38408 CVSS 9.8
 HIGH       SSH Brute Force               47 failed SSH login(s) detected in logs
 HIGH       Critical Port Exposed         Critical port(s) open: 3389, 445
 HIGH       Database Port Exposed         Database port(s) reachable: 3306, 5432
 MEDIUM     Cleartext Protocol in Use     Cleartext protocol port(s) open: 21

  Recommended Actions
    1. Treat this as an emergency — patch or isolate the host immediately
    2. Disable password authentication — use SSH keys only
    3. Install fail2ban and set a low threshold
    4. Place the service behind a VPN — never expose RDP/SMB directly
    ...

  Why these threats were flagged
    * Nmap NSE scripts returned a VULNERABLE result ...
    * One or more open ports are running services with known CVEs (CVSS >= 7.0) ...
    * Multiple failed SSH login attempts detected on an exposed SSH service ...
```

### Terminal — Priority Threats (end of full scan)

```
──────────────────────── Priority Threats ────────────────────────
  * 192.168.1.10  [CRITICAL 87/100]  NSE Confirmed Vulnerability · SSH Brute Force
  * 192.168.1.44  [HIGH 63/100]      Vulnerable Service Exposed · Database Port Exposed
```

### HTML Report

The interactive HTML report (`munin_TIMESTAMP.html`) is fully self-contained — no CDN, no internet needed to view it. It includes:

- **Summary cards** — total hosts, open ports, CVEs, risk distribution
- **Sortable, filterable host table** — search by IP, OS, vendor, hostname; filter by risk level
- **Expandable rows** — click any host to see:
  - Detected Threats panel with severity badges and descriptions
  - Prioritised remediation list
  - Port / CVE sub-table
  - NSE vulnerability output
- **One-liner threat summary** shown inline under each IP in the table

---

## Log Format Support

| Format | Auto-detected By | Fields Extracted |
|---|---|---|
| syslog / messages | Syslog regex | timestamp, host, process, pid, message |
| auth.log | Path name + syslog regex | + level (ERROR/INFO/NOTICE) |
| access.log (nginx/apache) | Combined log regex | ip, user, timestamp, method, path, status, size |
| kern.log / dmesg | `[timestamp]` prefix | timestamp, level, message |
| journald | ISO 8601 timestamp | timestamp, host, process, pid, message |
| Generic | ISO timestamp fallback | timestamp, level, message |

---

## Technical Notes

- **NVD rate limiting** — without an API key, NVD allows 5 requests per 30 seconds. Munin sleeps 0.65 s between queries automatically. For large scans, get a free API key at https://nvd.nist.gov/developers/request-an-api-key and set the `NVD_API_KEY` environment variable.
- **CVE cache** — results are cached in memory per session to avoid duplicate queries for the same product/version.
- **Scapy fallback** — if Scapy is unavailable or fails (e.g. on macOS without raw socket access), discovery falls back to `nmap -sn` automatically.
- **Log reader limit** — the last 500 entries of large log files are parsed for display. All entries are used for threat correlation regardless of this limit.
- **Python 3.10+ required** — the codebase uses `X | Y` union type hints introduced in 3.10.

---

## Dependencies

```
python-nmap>=0.7.1         # nmap Python bindings
scapy>=2.5.0               # ARP scanning (optional, falls back gracefully)
requests>=2.31.0           # NVD API + MAC vendor API
rich>=13.7.0               # Terminal formatting
mac-vendor-lookup>=0.1.12  # Offline MAC OUI database
```

---

## License

Copyright (C) 2026 Plinio Lima

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU Affero General Public License** as published by the Free Software Foundation, version 3.

This program is distributed in the hope that it will be useful, but **without any warranty**; without even the implied warranty of merchantability or fitness for a particular purpose. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
