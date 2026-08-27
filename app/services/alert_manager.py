"""
PREVAIL - Alert Manager
Threat alert system with configurable thresholds and history.
"""
import time
from typing import Dict, Any, List, Optional
from collections import deque
import json
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "prevail.db"


class AlertManager:
    def __init__(self, max_alerts: int = 500):
        self.max_alerts = max_alerts
        self.alerts: deque = deque(maxlen=max_alerts)
        self.thresholds = {
            "risk_critical": 75,
            "risk_high": 50,
            "anomaly_high": 70,
            "rapid_escalation": 30,
        }
        self.last_risk_score: float = 0
        self.alert_id_counter: int = 0

    def check_risk(self, risk_score: float, risk_level: str, components: Dict[str, Any] = None):
        if risk_score >= self.thresholds["risk_critical"]:
            self._add_alert("CRITICAL_RISK", f"Risk score reached {risk_score:.1f}/100 (CRITICAL)", "critical",
                            {"risk_score": risk_score, "risk_level": risk_level})
        elif risk_score >= self.thresholds["risk_high"]:
            self._add_alert("HIGH_RISK", f"Risk score reached {risk_score:.1f}/100 (HIGH)", "high",
                            {"risk_score": risk_score, "risk_level": risk_level})

        if components:
            anomaly = components.get("anomaly_score", 0)
            if anomaly >= self.thresholds["anomaly_high"]:
                self._add_alert("HIGH_ANOMALY", f"Anomaly score reached {anomaly:.1f}", "high",
                                {"anomaly_score": anomaly})

        if self.last_risk_score > 0:
            delta = risk_score - self.last_risk_score
            if delta >= self.thresholds["rapid_escalation"]:
                self._add_alert("RAPID_ESCALATION",
                                f"Risk escalated by {delta:.1f} points ({self.last_risk_score:.1f} -> {risk_score:.1f})",
                                "high", {"delta": delta, "from": self.last_risk_score, "to": risk_score})
        self.last_risk_score = risk_score

    def _add_alert(self, alert_type: str, message: str, severity: str, data: Dict[str, Any] = None):
        self.alert_id_counter += 1
        alert = {
            "id": self.alert_id_counter,
            "timestamp": time.time(),
            "type": alert_type,
            "message": message,
            "severity": severity,
            "data": data or {},
            "acknowledged": False,
        }
        self.alerts.append(alert)

    def acknowledge(self, alert_id: int) -> bool:
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["acknowledged"] = True
                return True
        return False

    def get_alerts(self, limit: int = 50, include_acknowledged: bool = True) -> List[Dict[str, Any]]:
        alerts = list(self.alerts)
        if not include_acknowledged:
            alerts = [a for a in alerts if not a["acknowledged"]]
        return alerts[-limit:]

    def get_unacknowledged_count(self) -> int:
        return sum(1 for a in self.alerts if not a["acknowledged"])

    def update_thresholds(self, thresholds: Dict[str, float]):
        self.thresholds.update(thresholds)

    def clear(self):
        self.alerts.clear()
        self.last_risk_score = 0


_alert_manager = AlertManager()


def get_alert_manager() -> AlertManager:
    return _alert_manager
