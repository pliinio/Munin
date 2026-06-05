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
Log file reader for Munin.
Supports: syslog/messages, auth.log, nginx/apache access.log,
          kern.log, journald-style, and generic fallback.
Returns (log_type, [entry_dicts]) where each dict has consistent keys.
"""

import re
from pathlib import Path
from typing import List, Dict, Tuple

# Maximum entries returned (avoid overwhelming the terminal on huge logs)
MAX_ENTRIES = 500


class LogReadError(Exception):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Regex patterns
# ─────────────────────────────────────────────────────────────────────────────

# Standard syslog: "Mar 29 10:14:22 hostname process[pid]: message"
_RE_SYSLOG = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# Systemd/journald: "2024-03-29T10:14:22.123456+00:00 hostname process[pid]: msg"
_RE_JOURNALD = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[\.\d]*[+\-]\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)

# auth.log extended (same base as syslog but we label it separately for context)
_RE_AUTH = _RE_SYSLOG

# Apache/Nginx combined access log:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326
_RE_ACCESS = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
)

# kern.log / dmesg-style: "[123456.789012] message" or standard syslog prefix
_RE_KERN_DMESG = re.compile(
    r"^\[\s*(?P<timestamp>[\d.]+)\]\s+(?P<message>.+)$"
)

# Generic: lines with a recognisable ISO or syslog timestamp
_RE_GENERIC_ISO = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:[,.\d]*)?\s+"
    r"(?:(?P<level>DEBUG|INFO|NOTICE|WARN(?:ING)?|ERROR|CRIT(?:ICAL)?|FATAL)\s+)?"
    r"(?P<message>.+)$",
    re.IGNORECASE,
)


# ─────────────────────────────────────────────────────────────────────────────
# Detection helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sniff_type(path: Path, sample: List[str]) -> str:
    """Guess log type from path name and content sample."""
    name = path.name.lower()

    if "access" in name or "access" in str(path):
        if any(_RE_ACCESS.match(l) for l in sample):
            return "access"

    if "kern" in name:
        if any(_RE_KERN_DMESG.match(l) for l in sample):
            return "kern"

    if "auth" in name:
        return "auth"

    if any(_RE_JOURNALD.match(l) for l in sample):
        return "journald"

    if any(_RE_SYSLOG.match(l) for l in sample):
        return "syslog"

    if any(_RE_ACCESS.match(l) for l in sample):
        return "access"

    if any(_RE_KERN_DMESG.match(l) for l in sample):
        return "kern"

    if any(_RE_GENERIC_ISO.match(l) for l in sample):
        return "generic"

    return "generic"


# ─────────────────────────────────────────────────────────────────────────────
# Parsers per type
# ─────────────────────────────────────────────────────────────────────────────

def _parse_syslog(lines: List[str], auth_mode: bool = False) -> List[Dict]:
    entries = []
    for line in lines:
        m = _RE_SYSLOG.match(line) or _RE_JOURNALD.match(line)
        if not m:
            continue
        d = m.groupdict()
        entry: Dict = {
            "timestamp": d.get("timestamp", ""),
            "host":      d.get("host", ""),
            "process":   d.get("process", ""),
            "pid":       d.get("pid") or "",
            "message":   d.get("message", "")[:140],
        }
        if auth_mode:
            # Annotate auth events
            msg = entry["message"].lower()
            if "failed" in msg or "failure" in msg or "invalid" in msg:
                entry["level"] = "ERROR"
            elif "accepted" in msg or "opened" in msg:
                entry["level"] = "INFO"
            elif "disconnect" in msg or "closed" in msg:
                entry["level"] = "NOTICE"
            else:
                entry["level"] = "DEBUG"
            # Reorder to put level after timestamp
            entry = {
                "timestamp": entry["timestamp"],
                "level":     entry["level"],
                "host":      entry["host"],
                "process":   entry["process"],
                "pid":       entry["pid"],
                "message":   entry["message"],
            }
        entries.append(entry)
    return entries


def _parse_access(lines: List[str]) -> List[Dict]:
    entries = []
    for line in lines:
        m = _RE_ACCESS.match(line)
        if not m:
            continue
        d = m.groupdict()
        entries.append({
            "ip":        d.get("ip", ""),
            "user":      d.get("user", "-"),
            "timestamp": d.get("timestamp", ""),
            "method":    d.get("method", ""),
            "path":      d.get("path", "")[:60],
            "status":    d.get("status", ""),
            "size":      d.get("size", ""),
        })
    return entries


def _parse_kern(lines: List[str]) -> List[Dict]:
    entries = []
    for line in lines:
        # Try dmesg numeric timestamp first
        m = _RE_KERN_DMESG.match(line)
        if m:
            msg = m.group("message")
            # Best-effort severity from known kernel prefixes
            lvl = "INFO"
            lower = msg.lower()
            if any(k in lower for k in ("error", "fail", "bug", "oops", "panic", "call trace")):
                lvl = "ERROR"
            elif any(k in lower for k in ("warn",)):
                lvl = "WARN"
            elif any(k in lower for k in ("info",)):
                lvl = "INFO"
            entries.append({
                "timestamp": m.group("timestamp"),
                "level":     lvl,
                "message":   msg[:140],
            })
            continue
        # Fallback: standard syslog kern line
        m2 = _RE_SYSLOG.match(line)
        if m2:
            d = m2.groupdict()
            entries.append({
                "timestamp": d.get("timestamp", ""),
                "level":     "INFO",
                "message":   d.get("message", "")[:140],
            })
    return entries


def _parse_generic(lines: List[str]) -> List[Dict]:
    entries = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        m = _RE_GENERIC_ISO.match(line)
        if m:
            d = m.groupdict()
            entries.append({
                "timestamp": d.get("timestamp", ""),
                "level":     (d.get("level") or "INFO").upper(),
                "message":   d.get("message", "")[:160],
            })
        else:
            # Last resort: raw line, no timestamp parsed
            entries.append({
                "timestamp": "",
                "level":     "INFO",
                "message":   line[:160],
            })
    return entries


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def read_log(path_str: str) -> Tuple[str, List[Dict]]:
    """
    Read and parse a log file.

    Returns:
        (log_type, entries)  — log_type is a string label,
                               entries is a list of dicts with consistent keys.

    Raises:
        LogReadError on I/O or permission errors.
    """
    path = Path(path_str)

    if not path.exists():
        raise LogReadError(f"File not found: {path_str}")
    if not path.is_file():
        raise LogReadError(f"Not a file: {path_str}")

    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except PermissionError:
        raise LogReadError(
            f"Permission denied: {path_str}  (try running with sudo)"
        )
    except OSError as exc:
        raise LogReadError(f"Cannot read file: {exc}")

    lines = [l for l in raw.splitlines() if l.strip()]

    if not lines:
        return "empty", []

    # Use first 40 non-empty lines for type detection
    sample = lines[:40]
    log_type = _sniff_type(path, sample)

    # Take last MAX_ENTRIES lines (most recent)
    lines = lines[-MAX_ENTRIES:]

    if log_type == "access":
        entries = _parse_access(lines)
    elif log_type == "auth":
        entries = _parse_syslog(lines, auth_mode=True)
    elif log_type in ("syslog", "journald"):
        entries = _parse_syslog(lines)
    elif log_type == "kern":
        entries = _parse_kern(lines)
    else:
        entries = _parse_generic(lines)

    return log_type, entries
