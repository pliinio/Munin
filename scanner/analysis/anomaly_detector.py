#!/usr/bin/env python3

# Munin — Cyber Risk Intelligence Platform
# Copyright (C) 2026 Plinio Lima
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, version 3.

"""
anomaly_detector.py — ML Layer 1 for Munin (Isolation Forest).

Detects anomalous network behaviour that rule-based patterns cannot catch —
including zero-day indicators, unusual port combinations, and atypical
log event ratios.

Architecture:
  - Unsupervised learning: no labelled data required
  - Trains on "normal" host feature vectors from the current scan session
    or from a persisted baseline saved from a previous clean scan
  - Flags hosts whose feature vector is statistically anomalous
  - Runs AFTER the rule-based correlator — findings are additive

Feature vector (per host):
  [0]  open_port_count
  [1]  risky_port_count        (ports in _RISKY_PORTS)
  [2]  critical_port_count     (RDP, SMB, VNC …)
  [3]  db_port_count
  [4]  cleartext_port_count
  [5]  max_cvss                (highest CVSS across all ports)
  [6]  cve_count               (total CVEs)
  [7]  high_cve_count          (CVSS >= 7.0)
  [8]  failed_ssh_logins
  [9]  auth_failures
  [10] web_errors              (4xx + 5xx)
  [11] accepted_logins
  [12] sudo_events
  [13] nse_vuln_confirmed      (0 or 1)
  [14] docker_exposed          (0 or 1)

Public API:
  extract_features(host_data)              -> np.ndarray (shape: 15,)
  train(host_list)                         -> AnomalyDetector (fitted)
  train_from_baseline(path)               -> AnomalyDetector (fitted)
  detect(host_data)                       -> AnomalyResult | None
  save_baseline(host_list, path)          -> None
  load_baseline(path)                     -> AnomalyDetector (fitted)
"""

from __future__ import annotations

import json
import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("munin.anomaly")

# ─────────────────────────────────────────────────────────────────────────────
# Port sets (mirrors correlator.py — kept local to avoid circular import)
# ─────────────────────────────────────────────────────────────────────────────

_RISKY_PORTS = {
    21, 22, 23, 25, 53, 69, 79, 80, 110, 111, 119,
    135, 137, 138, 139, 143, 161, 389, 443, 445,
    512, 513, 514, 873, 1099, 1433, 1521, 2049,
    2375, 2376, 3000, 3306, 3389, 4444, 5432,
    5900, 5985, 6379, 8080, 8443, 8888, 9200, 27017,
}
_CRITICAL_PORTS   = {23, 3389, 445, 5900, 5985, 4444}
_DB_PORTS         = {1433, 1521, 2049, 3306, 5432, 6379, 9200, 27017}
_CLEARTEXT_PORTS  = {21, 23}
_DOCKER_PORTS     = {2375, 2376}

FEATURE_NAMES = [
    "open_port_count",
    "risky_port_count",
    "critical_port_count",
    "db_port_count",
    "cleartext_port_count",
    "max_cvss",
    "cve_count",
    "high_cve_count",
    "failed_ssh_logins",
    "auth_failures",
    "web_errors",
    "accepted_logins",
    "sudo_events",
    "nse_vuln_confirmed",
    "docker_exposed",
]

N_FEATURES = len(FEATURE_NAMES)   # 15


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AnomalyResult:
    """Output of anomaly detection for a single host."""
    ip:               str
    is_anomaly:       bool
    anomaly_score:    float          # 0.0–1.0  (higher = more anomalous)
    anomaly_severity: str            # CRITICAL / HIGH / MEDIUM / LOW
    anomaly_bonus:    int            # risk points to add to base score
    top_features:     List[str]      # top contributing feature names
    detail:           str            # human-readable explanation

    def to_finding(self) -> Dict:
        """Convert to a Finding dict compatible with correlator output."""
        return {
            "pattern_id":  "ml_anomaly_detected",
            "name":        "Anomalia Detectada por ML",
            "description": (
                "O detector de anomalias por aprendizado de máquina identificou comportamento "
                "atípico neste host em relação à baseline dos demais hosts. "
                "Isso pode indicar ataque zero-day, misconfiguração ou movimentação lateral."
            ),
            "severity":    self.anomaly_severity,
            "risk_bonus":  self.anomaly_bonus,
            "remediation": [
                "Investigar o host manualmente — a anomalia pode indicar vetor de ataque inédito",
                "Comparar o estado atual com baseline de configuração conhecida",
                "Verificar processos, conexões e tarefas agendadas inesperadas",
                "Revisar software instalado e alterações de configuração recentes",
            ],
            "detail": self.detail,
            "ml_score": round(self.anomaly_score, 4),
            "top_features": self.top_features,
            "generated_by": "isolation_forest",
        }


# ─────────────────────────────────────────────────────────────────────────────
# Feature extraction
# ─────────────────────────────────────────────────────────────────────────────

def extract_features(host_data: Dict) -> np.ndarray:
    """
    Convert a Munin host_data dict into a fixed-length feature vector.

    Safe to call on incomplete dicts — missing keys default to 0.

    Args:
        host_data: host dict from Munin scanner / correlator

    Returns:
        np.ndarray of shape (N_FEATURES,) with dtype float32
    """
    ports       = host_data.get("ports", [])
    log_entries = host_data.get("logs", [])
    nse_results = host_data.get("vulnerabilities", {})

    open_ports = [p for p in ports if p.get("state") == "open"]
    open_nums  = {p["port"] for p in open_ports}

    # ── Port features ────────────────────────────────────────────────────────
    open_port_count    = len(open_nums)
    risky_port_count   = len(open_nums & _RISKY_PORTS)
    critical_port_count= len(open_nums & _CRITICAL_PORTS)
    db_port_count      = len(open_nums & _DB_PORTS)
    cleartext_count    = len(open_nums & _CLEARTEXT_PORTS)

    # ── CVE features ─────────────────────────────────────────────────────────
    all_cvss: List[float] = []
    cve_count     = 0
    high_cve_count= 0
    for p in open_ports:
        for cve in p.get("cves", []):
            score = float(cve.get("cvss_score") or 0.0)
            all_cvss.append(score)
            cve_count += 1
            if score >= 7.0:
                high_cve_count += 1
    max_cvss = max(all_cvss) if all_cvss else 0.0

    # ── Log features ─────────────────────────────────────────────────────────
    failed_ssh  = 0
    auth_fail   = 0
    web_errors  = 0
    accepted    = 0
    sudo_events = 0

    for entry in log_entries:
        msg    = (entry.get("message") or "").lower()
        level  = (entry.get("level")   or "").upper()
        status = entry.get("status", "")

        if ("failed password" in msg or "authentication failure" in msg
                or "invalid user" in msg):
            if "ssh" in (entry.get("process") or "").lower() or "sshd" in msg:
                failed_ssh += 1
            auth_fail += 1
        elif level == "ERROR" and (
            "fail" in msg or "invalid" in msg or "denied" in msg
        ):
            auth_fail += 1

        if "accepted password" in msg or "accepted publickey" in msg:
            accepted += 1

        if "sudo" in msg and "command" in msg:
            sudo_events += 1

        try:
            code = int(status)
            if 400 <= code < 600:
                web_errors += 1
        except (ValueError, TypeError):
            pass

    # ── NSE / Docker binary features ─────────────────────────────────────────
    nse_confirmed = 0
    for scripts in nse_results.values():
        for output in scripts.values():
            if "VULNERABLE" in str(output).upper():
                nse_confirmed = 1
                break
        if nse_confirmed:
            break

    docker_exposed = 1 if open_nums & _DOCKER_PORTS else 0

    vec = np.array([
        open_port_count,
        risky_port_count,
        critical_port_count,
        db_port_count,
        cleartext_count,
        max_cvss,
        cve_count,
        high_cve_count,
        failed_ssh,
        auth_fail,
        web_errors,
        accepted,
        sudo_events,
        nse_confirmed,
        docker_exposed,
    ], dtype=np.float32)

    return vec


# ─────────────────────────────────────────────────────────────────────────────
# Anomaly Detector class
# ─────────────────────────────────────────────────────────────────────────────

class AnomalyDetector:
    """
    Wrapper around sklearn's IsolationForest.

    Lifecycle:
        detector = AnomalyDetector()
        detector.train(host_list)       # fit on a list of host_data dicts
        result = detector.detect(host)  # score a single host
        detector.save(path)             # persist model to disk
        detector = AnomalyDetector.load(path)  # restore
    """

    # Contamination: expected fraction of anomalies in training data.
    # 0.05 = we assume up to 5% of hosts in training may already be compromised.
    _CONTAMINATION = 0.05
    _N_ESTIMATORS  = 200   # more trees = more stable scores
    _MIN_TRAIN     = 3     # minimum hosts needed to train

    def __init__(self) -> None:
        self._model    = None
        self._scaler   = None
        self._is_fitted = False
        self._n_trained = 0

    # ── Training ─────────────────────────────────────────────────────────────

    def train(self, host_list: List[Dict]) -> "AnomalyDetector":
        """
        Fit the Isolation Forest on a list of host_data dicts.

        Args:
            host_list: list of host dicts (from scanner or JSON baseline)

        Returns:
            self (for chaining)
        """
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import RobustScaler

        if len(host_list) < self._MIN_TRAIN:
            logger.warning(
                f"AnomalyDetector: only {len(host_list)} host(s) — need at least "
                f"{self._MIN_TRAIN} to train reliably. Skipping."
            )
            return self

        X = np.vstack([extract_features(h) for h in host_list])

        # RobustScaler handles outliers better than StandardScaler for security data
        self._scaler = RobustScaler()
        X_scaled = self._scaler.fit_transform(X)

        self._model = IsolationForest(
            n_estimators=self._N_ESTIMATORS,
            contamination=self._CONTAMINATION,
            random_state=42,
            n_jobs=-1,
        )
        self._model.fit(X_scaled)

        self._is_fitted = True
        self._n_trained = len(host_list)
        logger.info(f"AnomalyDetector: trained on {self._n_trained} host(s).")
        return self

    # ── Detection ─────────────────────────────────────────────────────────────

    def detect(self, host_data: Dict) -> Optional[AnomalyResult]:
        """
        Score a single host. Returns None if model is not fitted.

        The anomaly_score is normalised to [0, 1]:
          IsolationForest returns decision_function scores in roughly [-0.5, 0.5]
          We invert and normalise so that 1.0 = maximally anomalous.

        Args:
            host_data: single host dict

        Returns:
            AnomalyResult if fitted, None otherwise
        """
        if not self._is_fitted:
            logger.debug("AnomalyDetector: not fitted — skipping detection.")
            return None

        vec     = extract_features(host_data).reshape(1, -1)
        scaled  = self._scaler.transform(vec)

        # predict: -1 = anomaly, 1 = normal
        label   = self._model.predict(scaled)[0]
        # decision_function: lower = more anomalous (typically -0.5 to +0.5)
        raw_score = self._model.decision_function(scaled)[0]

        # Normalise to [0, 1] where 1 = most anomalous
        anomaly_score = float(np.clip(0.5 - raw_score, 0.0, 1.0))
        is_anomaly    = (label == -1)

        if not is_anomaly:
            return AnomalyResult(
                ip=host_data.get("ip", "?"),
                is_anomaly=False,
                anomaly_score=anomaly_score,
                anomaly_severity="LOW",
                anomaly_bonus=0,
                top_features=[],
                detail="Nenhuma anomalia detectada pelo modelo de ML.",
            )

        # ── Severity & bonus based on score ──────────────────────────────────
        if anomaly_score >= 0.80:
            severity, bonus = "CRITICAL", 35
        elif anomaly_score >= 0.65:
            severity, bonus = "HIGH",     25
        elif anomaly_score >= 0.50:
            severity, bonus = "MEDIUM",   15
        else:
            severity, bonus = "LOW",      5

        # ── Top contributing features (highest absolute values) ───────────────
        feat_vec   = extract_features(host_data)
        feat_pairs = sorted(
            zip(FEATURE_NAMES, feat_vec.tolist()),
            key=lambda x: abs(x[1]),
            reverse=True,
        )
        top_features = [
            f"{name}={int(val) if val == int(val) else round(val, 1)}"
            for name, val in feat_pairs[:4]
            if val != 0
        ]

        detail = (
            f"Pontuação de anomalia ML: {anomaly_score:.2f} [{severity}]. "
            f"Indicadores principais: {', '.join(top_features) if top_features else 'combinação atípica de características'}. "
            f"Modelo treinado com {self._n_trained} host(s)."
        )

        return AnomalyResult(
            ip=host_data.get("ip", "?"),
            is_anomaly=True,
            anomaly_score=anomaly_score,
            anomaly_severity=severity,
            anomaly_bonus=bonus,
            top_features=top_features,
            detail=detail,
        )

    # ── Persistence ───────────────────────────────────────────────────────────

    def save(self, path: str | Path) -> None:
        """Persist the fitted model and scaler to disk (pickle)."""
        if not self._is_fitted:
            raise RuntimeError("Cannot save: model has not been trained yet.")
        state = {
            "model":      self._model,
            "scaler":     self._scaler,
            "n_trained":  self._n_trained,
        }
        Path(path).write_bytes(pickle.dumps(state))
        logger.info(f"AnomalyDetector: model saved to {path}")

    @classmethod
    def load(cls, path: str | Path) -> "AnomalyDetector":
        """Restore a previously saved model from disk."""
        state = pickle.loads(Path(path).read_bytes())
        det = cls()
        det._model     = state["model"]
        det._scaler    = state["scaler"]
        det._n_trained = state["n_trained"]
        det._is_fitted = True
        logger.info(
            f"AnomalyDetector: model loaded from {path} "
            f"(trained on {det._n_trained} host(s))"
        )
        return det


# ─────────────────────────────────────────────────────────────────────────────
# Convenience functions (module-level API)
# ─────────────────────────────────────────────────────────────────────────────

# Module-level singleton — shared across a scan session
_session_detector: Optional[AnomalyDetector] = None


def train(host_list: List[Dict]) -> AnomalyDetector:
    """
    Train (or retrain) the session-level detector on the given host list.
    Call this after a full network scan to establish the session baseline.
    """
    global _session_detector
    _session_detector = AnomalyDetector()
    _session_detector.train(host_list)
    return _session_detector


def detect(host_data: Dict) -> Optional[AnomalyResult]:
    """
    Score a single host using the session-level detector.
    Returns None if no model has been trained yet.
    """
    if _session_detector is None:
        return None
    return _session_detector.detect(host_data)


def save_baseline(host_list: List[Dict], path: str | Path = "munin_baseline.pkl") -> None:
    """
    Train on host_list and save the model to disk as a persistent baseline.
    Use this on a known-good scan to create a reference model.

    Usage:
        from scanner.analysis.anomaly_detector import save_baseline
        save_baseline(clean_scan_result["hosts"], "baselines/office_baseline.pkl")
    """
    det = AnomalyDetector()
    det.train(host_list)
    if det._is_fitted:
        det.save(path)
        logger.info(f"Baseline saved: {path}")
    else:
        logger.warning("Baseline not saved: insufficient hosts for training.")


def load_baseline(path: str | Path = "munin_baseline.pkl") -> AnomalyDetector:
    """
    Load a pre-trained baseline from disk and set it as the session detector.

    Usage:
        from scanner.analysis.anomaly_detector import load_baseline
        load_baseline("baselines/office_baseline.pkl")
        # now detect() will use this baseline
    """
    global _session_detector
    _session_detector = AnomalyDetector.load(path)
    return _session_detector
