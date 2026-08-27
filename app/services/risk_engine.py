"""
PREVAIL - Risk Engine
Combines anomaly score, attack probability, temporal signals into unified risk score.
"""
from typing import Dict, Any, Optional, List
import json
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.json"


def _load_config() -> Dict[str, Any]:
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            return json.load(f)
    return {}


def compute_risk(
    anomaly_score: float = 0.0,
    attack_probability: float = 0.0,
    temporal_score: float = 0.0,
    behavioral_signals: Optional[Dict[str, Any]] = None,
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    cfg = (config or _load_config()).get("risk_engine", {})
    weights = cfg.get("weights", {
        "anomaly_score": 0.25, "attack_probability": 0.30,
        "temporal_score": 0.25, "behavioral_signals": 0.20
    })
    thresholds = cfg.get("thresholds", {"low": 24, "moderate": 49, "high": 74, "critical": 100})

    behavioral_contribution = 0.0
    key_signals: List[str] = []

    if behavioral_signals:
        if behavioral_signals.get("max_failed_logins", 0) > 3:
            behavioral_contribution += 15
            key_signals.append(f"High failed login count: {behavioral_signals['max_failed_logins']}")
        if behavioral_signals.get("external_ratio", 0) > 0.3:
            behavioral_contribution += 12
            key_signals.append(f"Elevated external connections: {behavioral_signals['external_ratio']:.0%}")
        if behavioral_signals.get("privilege_change", 0):
            behavioral_contribution += 18
            key_signals.append("Privilege level change detected")
        if behavioral_signals.get("high_data_volume", 0):
            behavioral_contribution += 10
            key_signals.append("Abnormal data transfer volume")
        if behavioral_signals.get("host_discovery_count_5m", 0) > 0 or behavioral_signals.get("port_scan_count_5m", 0) > 0:
            behavioral_contribution += 20
            key_signals.append("Network reconnaissance activity detected")
        if behavioral_signals.get("data_transfer_count_5m", 0) > 0:
            behavioral_contribution += 15
            key_signals.append("Suspicious data transfer activity")
        if behavioral_signals.get("command_execution_count_5m", 0) > 0:
            behavioral_contribution += 10
            key_signals.append("Suspicious command execution detected")
        if behavioral_signals.get("unusual_login_time", 0):
            behavioral_contribution += 8
            key_signals.append("Login at unusual time")

    behavioral_contribution = min(behavioral_contribution, 100)

    risk_score = (
        anomaly_score * weights.get("anomaly_score", 0.25) +
        attack_probability * weights.get("attack_probability", 0.30) +
        temporal_score * weights.get("temporal_score", 0.25) +
        behavioral_contribution * weights.get("behavioral_signals", 0.20)
    )
    risk_score = max(0.0, min(100.0, risk_score))

    if risk_score <= thresholds.get("low", 24):
        risk_level = "LOW"
    elif risk_score <= thresholds.get("moderate", 49):
        risk_level = "MODERATE"
    elif risk_score <= thresholds.get("high", 74):
        risk_level = "HIGH"
    else:
        risk_level = "CRITICAL"

    if not key_signals:
        if risk_level == "LOW":
            key_signals.append("No significant anomalies detected")
        elif risk_level == "MODERATE":
            key_signals.append("Minor behavioral deviations observed")
        else:
            key_signals.append("Multiple anomalous behavioral indicators")

    stage = "normal"
    if risk_score > 75:
        stage = "imminent_attack"
    elif risk_score > 50:
        stage = "active_preparation"
    elif risk_score > 25:
        stage = "early_reconnaissance"

    return {
        "risk_score": round(risk_score, 1),
        "risk_level": risk_level,
        "components": {
            "anomaly_score": round(anomaly_score, 1),
            "attack_probability": round(attack_probability, 1),
            "temporal_score": round(temporal_score, 1),
            "behavioral_contribution": round(behavioral_contribution, 1),
        },
        "predicted_stage": stage,
        "key_signals": key_signals,
        "weights_used": weights,
    }
