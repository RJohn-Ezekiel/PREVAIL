"""
PREVAIL - Explanation Engine
Generates human-readable explanations for risk predictions.
"""
from typing import Dict, Any, List


def explain_risk(risk_result: Dict[str, Any], anomaly_result: Dict[str, Any] = None, features: Dict[str, Any] = None) -> Dict[str, Any]:
    risk_score = risk_result.get("risk_score", 0)
    risk_level = risk_result.get("risk_level", "LOW")
    components = risk_result.get("components", {})
    key_signals = risk_result.get("key_signals", [])
    predicted_stage = risk_result.get("predicted_stage", "normal")

    explanation = {
        "summary": _generate_summary(risk_score, risk_level, predicted_stage),
        "risk_breakdown": _breakdown(components),
        "key_indicators": _format_signals(key_signals, features),
        "recommendation": _recommendation(risk_level, predicted_stage),
        "confidence_notes": _confidence_notes(anomaly_result, features),
    }
    return explanation


def _generate_summary(risk_score: float, risk_level: str, stage: str) -> str:
    stage_descriptions = {
        "normal": "The observed behavior appears consistent with normal operational patterns.",
        "early_reconnaissance": "Early indicators suggest potential reconnaissance activity. Behavioral anomalies have been detected that may precede an attack.",
        "active_preparation": "Multiple behavioral indicators suggest active attack preparation. The observed sequence of events is consistent with pre-attack staging.",
        "imminent_attack": "Critical risk level detected. The behavioral pattern strongly suggests an imminent or ongoing attack. Immediate investigation recommended.",
    }
    return stage_descriptions.get(stage, f"Risk level: {risk_level} ({risk_score}/100)")


def _breakdown(components: Dict[str, Any]) -> List[Dict[str, Any]]:
    breakdown = []
    label_map = {
        "anomaly_score": "Behavioral Anomaly",
        "attack_probability": "Attack Probability Model",
        "temporal_score": "Temporal Pattern Analysis",
        "behavioral_contribution": "Behavioral Signal Analysis",
    }
    for key, label in label_map.items():
        val = components.get(key, 0)
        breakdown.append({
            "component": label,
            "score": round(val, 1),
            "contribution": f"{val:.1f}%",
            "bar_width": min(val, 100),
        })
    return breakdown


def _format_signals(signals: List[str], features: Dict[str, Any] = None) -> List[Dict[str, Any]]:
    formatted = []
    priority_keywords = ["privilege", "reconnaissance", "exfiltration", "data transfer", "suspicious"]
    for sig in signals:
        priority = "high" if any(kw in sig.lower() for kw in priority_keywords) else "medium"
        formatted.append({"signal": sig, "priority": priority})

    if features:
        if features.get("max_failed_logins", 0) > 5:
            formatted.append({"signal": f"Maximum consecutive failed logins: {features['max_failed_logins']}", "priority": "high"})
        if features.get("external_connections", 0) > 3:
            formatted.append({"signal": f"Multiple external network connections: {features['external_connections']}", "priority": "medium"})

    formatted.sort(key=lambda x: 0 if x["priority"] == "high" else 1)
    return formatted


def _recommendation(level: str, stage: str) -> str:
    recs = {
        ("LOW", "normal"): "No immediate action required. Continue monitoring.",
        ("MODERATE", "early_reconnaissance"): "Investigate the source of behavioral anomalies. Review recent access patterns for affected users.",
        ("HIGH", "active_preparation"): "Urgent investigation recommended. Isolate affected endpoints and review authentication logs.",
        ("CRITICAL", "imminent_attack"): "IMMEDIATE ACTION REQUIRED. Isolate affected systems, preserve forensic evidence, and initiate incident response.",
    }
    return recs.get((level, stage), f"Review the detected signals and investigate as appropriate for {level} risk level.")


def _confidence_notes(anomaly_result, features) -> str:
    notes = []
    if anomaly_result and anomaly_result.get("confidence", 0) < 0.5:
        notes.append("Anomaly detection confidence is low - consider gathering more behavioral data.")
    if features and features.get("event_count", 0) < 5:
        notes.append("Limited event data available. Predictions may be less reliable with sparse telemetry.")
    if not notes:
        notes.append("Prediction based on available behavioral telemetry and trained models.")
    return " ".join(notes)
