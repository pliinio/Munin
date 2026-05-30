#!/usr/bin/env python3

# Munin — Network Reconnaissance & Threat Analysis Framework
# Copyright (C) 2026 Plinio Lima
# AGPL-3.0 License

"""
history.py — Scan History & Trend Analysis for Munin.

Persists each scan result as a compact snapshot and enables:
  - Risk score evolution over time (per host or environment)
  - Comparison between scans ("what changed?")
  - Risk reduction tracking after remediation
  - Dashboard trend charts (JSON API)

Storage:
  data/history/YYYYMMDD_HHMMSS.json   — one file per scan (compact snapshot)

Public API:
  save_snapshot(scan_result)              -> Path
  load_snapshots(n: int)                  -> list[Snapshot]
  compare_snapshots(old, new)             -> ComparisonReport
  trend_data(snapshots)                   -> TrendData   (for chart rendering)
  get_host_history(ip, snapshots)         -> list[dict]
"""

from __future__ import annotations

import json
import glob
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set

# Resolve relative to project root (parent of this file's package)
# This ensures history is always saved in <project>/data/history/
# regardless of from where Python is invoked.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
HISTORY_DIR   = _PROJECT_ROOT / "data" / "history"


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HostSnapshot:
    """Compact per-host data for a single scan."""
    ip:            str
    hostname:      str
    risk_score:    int
    risk_level:    str
    open_ports:    int
    cve_count:     int
    finding_count: int
    finding_ids:   List[str]    # pattern_ids

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Snapshot:
    """Compact representation of a complete scan, stored in history."""
    scan_id:      str        # timestamp-based ID
    target:       str
    scan_time:    str
    host_count:   int
    total_cves:   int
    total_findings: int
    avg_risk:     float
    risk_distribution: Dict[str, int]   # {"CRITICAL": 2, "HIGH": 5, ...}
    hosts:        List[HostSnapshot]

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d: dict) -> "Snapshot":
        hosts = [HostSnapshot(**h) for h in d.get("hosts", [])]
        return Snapshot(
            scan_id=d["scan_id"],
            target=d.get("target", "?"),
            scan_time=d.get("scan_time", ""),
            host_count=d.get("host_count", 0),
            total_cves=d.get("total_cves", 0),
            total_findings=d.get("total_findings", 0),
            avg_risk=d.get("avg_risk", 0.0),
            risk_distribution=d.get("risk_distribution", {}),
            hosts=hosts,
        )


@dataclass
class HostDiff:
    """Changes for a single host between two scans."""
    ip:             str
    hostname:       str
    risk_before:    int
    risk_after:     int
    risk_delta:     int         # negative = improved
    new_findings:   List[str]   # pattern_ids that appeared
    fixed_findings: List[str]   # pattern_ids that disappeared
    new_ports:      int
    closed_ports:   int
    status:         str         # "improved" | "worsened" | "unchanged" | "new" | "gone"


@dataclass
class ComparisonReport:
    """Result of comparing two scan snapshots."""
    old_scan_id:  str
    new_scan_id:  str
    old_time:     str
    new_time:     str

    hosts_added:    List[str]
    hosts_removed:  List[str]
    hosts_changed:  List[HostDiff]

    avg_risk_before: float
    avg_risk_after:  float
    avg_risk_delta:  float

    total_cve_before:  int
    total_cve_after:   int
    total_cve_delta:   int

    improved_hosts:  int
    worsened_hosts:  int
    unchanged_hosts: int

    summary: str

    def to_dict(self) -> dict:
        return {
            "old_scan_id":    self.old_scan_id,
            "new_scan_id":    self.new_scan_id,
            "old_time":       self.old_time,
            "new_time":       self.new_time,
            "hosts_added":    self.hosts_added,
            "hosts_removed":  self.hosts_removed,
            "avg_risk_before": self.avg_risk_before,
            "avg_risk_after":  self.avg_risk_after,
            "avg_risk_delta":  self.avg_risk_delta,
            "total_cve_before": self.total_cve_before,
            "total_cve_after":  self.total_cve_after,
            "total_cve_delta":  self.total_cve_delta,
            "improved_hosts":  self.improved_hosts,
            "worsened_hosts":  self.worsened_hosts,
            "unchanged_hosts": self.unchanged_hosts,
            "summary":        self.summary,
            "host_changes":   [
                {
                    "ip":          d.ip,
                    "hostname":    d.hostname,
                    "risk_before": d.risk_before,
                    "risk_after":  d.risk_after,
                    "risk_delta":  d.risk_delta,
                    "status":      d.status,
                    "new_findings":   d.new_findings,
                    "fixed_findings": d.fixed_findings,
                }
                for d in self.hosts_changed
            ],
        }


@dataclass
class TrendData:
    """Time-series data for dashboard charts."""
    scan_ids:       List[str]
    timestamps:     List[str]
    avg_risk:       List[float]
    critical_count: List[int]
    high_count:     List[int]
    cve_totals:     List[int]
    host_counts:    List[int]

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────────────────────

def _make_host_snapshot(host: Dict) -> HostSnapshot:
    ports    = host.get("ports", [])
    findings = host.get("findings", [])
    cve_cnt  = sum(len(p.get("cves", [])) for p in ports)
    open_cnt = sum(1 for p in ports if p.get("state") == "open")

    return HostSnapshot(
        ip=host.get("ip", "?"),
        hostname=host.get("hostname", "N/A"),
        risk_score=host.get("risk_score", 0),
        risk_level=host.get("risk_level", "UNKNOWN"),
        open_ports=open_cnt,
        cve_count=cve_cnt,
        finding_count=len(findings),
        finding_ids=[f.get("pattern_id", "") for f in findings],
    )


def _risk_distribution(hosts: List[Dict]) -> Dict[str, int]:
    dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "MINIMAL": 0}
    for h in hosts:
        lvl = h.get("risk_level", "MINIMAL")
        dist[lvl] = dist.get(lvl, 0) + 1
    return dist


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def save_snapshot(scan_result: Dict) -> Path:
    """
    Save a compact snapshot of a scan result to data/history/.

    Args:
        scan_result: full Munin scan result dict

    Returns:
        Path to saved snapshot file
    """
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

    meta  = scan_result.get("meta", {})
    hosts = scan_result.get("hosts", [])

    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_id  = ts
    target   = meta.get("target", "unknown")
    scan_time= meta.get("scan_time", datetime.now().isoformat())

    total_cves = sum(
        sum(len(p.get("cves", [])) for p in h.get("ports", []))
        for h in hosts
    )
    total_findings = sum(len(h.get("findings", [])) for h in hosts)
    avg_risk = sum(h.get("risk_score", 0) for h in hosts) / max(len(hosts), 1)

    snapshot = Snapshot(
        scan_id=scan_id,
        target=target,
        scan_time=scan_time,
        host_count=len(hosts),
        total_cves=total_cves,
        total_findings=total_findings,
        avg_risk=round(avg_risk, 1),
        risk_distribution=_risk_distribution(hosts),
        hosts=[_make_host_snapshot(h) for h in hosts],
    )

    path = HISTORY_DIR / f"{ts}.json"
    path.write_text(json.dumps(snapshot.to_dict(), indent=2), encoding="utf-8")
    return path


def load_snapshots(n: int = 30) -> List[Snapshot]:
    """
    Load the N most recent scan snapshots from data/history/.

    Args:
        n: max number of snapshots to load (default: 30)

    Returns:
        List of Snapshot objects sorted oldest-first
    """
    files = sorted(glob.glob(str(HISTORY_DIR / "*.json")), reverse=True)[:n]
    snapshots = []
    for f in files:
        try:
            data = json.loads(Path(f).read_text(encoding="utf-8"))
            snapshots.append(Snapshot.from_dict(data))
        except Exception:
            pass
    return list(reversed(snapshots))  # oldest first


def compare_snapshots(old: Snapshot, new: Snapshot) -> ComparisonReport:
    """
    Compare two snapshots and return a delta report.

    Args:
        old: earlier snapshot
        new: later snapshot

    Returns:
        ComparisonReport with all changes
    """
    old_by_ip: Dict[str, HostSnapshot] = {h.ip: h for h in old.hosts}
    new_by_ip: Dict[str, HostSnapshot] = {h.ip: h for h in new.hosts}

    added   = [ip for ip in new_by_ip if ip not in old_by_ip]
    removed = [ip for ip in old_by_ip if ip not in new_by_ip]

    diffs: List[HostDiff] = []
    for ip in set(old_by_ip) & set(new_by_ip):
        o = old_by_ip[ip]
        n = new_by_ip[ip]

        delta = n.risk_score - o.risk_score
        old_set: Set[str] = set(o.finding_ids)
        new_set: Set[str] = set(n.finding_ids)

        new_f   = list(new_set - old_set)
        fixed_f = list(old_set - new_set)

        if delta < -5:    status = "improved"
        elif delta > 5:   status = "worsened"
        else:             status = "unchanged"

        diffs.append(HostDiff(
            ip=ip,
            hostname=n.hostname,
            risk_before=o.risk_score,
            risk_after=n.risk_score,
            risk_delta=delta,
            new_findings=new_f,
            fixed_findings=fixed_f,
            new_ports=max(0, n.open_ports - o.open_ports),
            closed_ports=max(0, o.open_ports - n.open_ports),
            status=status,
        ))

    improved  = sum(1 for d in diffs if d.status == "improved")
    worsened  = sum(1 for d in diffs if d.status == "worsened")
    unchanged = sum(1 for d in diffs if d.status == "unchanged")

    avg_delta = new.avg_risk - old.avg_risk
    cve_delta = new.total_cves - old.total_cves

    if avg_delta < -5:    summary = f"Risk improved: average score dropped {abs(avg_delta):.1f} pts since last scan."
    elif avg_delta > 5:   summary = f"Risk increased: average score rose {avg_delta:.1f} pts since last scan."
    else:                 summary = "Risk posture is stable since the previous scan."

    if worsened > 0:
        summary += f" {worsened} host(s) deteriorated."
    if improved > 0:
        summary += f" {improved} host(s) improved."

    return ComparisonReport(
        old_scan_id=old.scan_id,
        new_scan_id=new.scan_id,
        old_time=old.scan_time,
        new_time=new.scan_time,
        hosts_added=added,
        hosts_removed=removed,
        hosts_changed=diffs,
        avg_risk_before=old.avg_risk,
        avg_risk_after=new.avg_risk,
        avg_risk_delta=round(avg_delta, 1),
        total_cve_before=old.total_cves,
        total_cve_after=new.total_cves,
        total_cve_delta=cve_delta,
        improved_hosts=improved,
        worsened_hosts=worsened,
        unchanged_hosts=unchanged,
        summary=summary,
    )


def trend_data(snapshots: List[Snapshot]) -> TrendData:
    """
    Convert a list of snapshots into time-series data for charts.

    Args:
        snapshots: list of Snapshot objects (oldest first)

    Returns:
        TrendData with parallel lists indexed by scan
    """
    return TrendData(
        scan_ids=       [s.scan_id   for s in snapshots],
        timestamps=     [s.scan_time[:16] for s in snapshots],
        avg_risk=       [s.avg_risk  for s in snapshots],
        critical_count= [s.risk_distribution.get("CRITICAL", 0) for s in snapshots],
        high_count=     [s.risk_distribution.get("HIGH", 0)     for s in snapshots],
        cve_totals=     [s.total_cves for s in snapshots],
        host_counts=    [s.host_count for s in snapshots],
    )


def get_host_history(ip: str, snapshots: List[Snapshot]) -> List[Dict]:
    """
    Extract the time-series history for a single host IP.

    Args:
        ip:        target IP address
        snapshots: list of Snapshot objects (oldest first)

    Returns:
        List of dicts with scan_time, risk_score, risk_level, cve_count, finding_count
    """
    result = []
    for snap in snapshots:
        for h in snap.hosts:
            if h.ip == ip:
                result.append({
                    "scan_id":     snap.scan_id,
                    "scan_time":   snap.scan_time[:16],
                    "risk_score":  h.risk_score,
                    "risk_level":  h.risk_level,
                    "cve_count":   h.cve_count,
                    "finding_count": h.finding_count,
                })
                break
    return result


def latest_comparison() -> Optional[ComparisonReport]:
    """
    Compare the two most recent snapshots, if available.

    Returns:
        ComparisonReport or None if fewer than 2 snapshots exist
    """
    snaps = load_snapshots(2)
    if len(snaps) < 2:
        return None
    return compare_snapshots(snaps[0], snaps[1])
