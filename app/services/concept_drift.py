"""
PREVAIL - Concept Drift Detector
Tracks model performance over time, detects degradation.
"""
import time
from typing import Dict, Any, List, Optional
from collections import deque


class DriftDetector:
    def __init__(self, window_size: int = 50, alert_threshold: float = 0.15):
        self.window_size = window_size
        self.alert_threshold = alert_threshold
        self.predictions: deque = deque(maxlen=window_size)
        self.ground_truth: deque = deque(maxlen=window_size)
        self.alerts: List[Dict[str, Any]] = []
        self.baseline_accuracy: Optional[float] = None
        self.start_time = time.time()

    def add_observation(self, predicted: int, actual: int):
        self.predictions.append(predicted)
        self.ground_truth.append(actual)
        if len(self.predictions) >= 10:
            self._check_drift()

    def set_baseline(self, accuracy: float):
        self.baseline_accuracy = accuracy

    def _check_drift(self):
        if self.baseline_accuracy is None or len(self.predictions) < 10:
            return
        correct = sum(1 for p, a in zip(self.predictions, self.ground_truth) if p == a)
        current_accuracy = correct / len(self.predictions)
        drop = self.baseline_accuracy - current_accuracy
        if drop > self.alert_threshold:
            alert = {
                "timestamp": time.time(),
                "type": "concept_drift",
                "message": f"Model accuracy dropped by {drop:.1%} (baseline: {self.baseline_accuracy:.1%}, current: {current_accuracy:.1%})",
                "severity": "high" if drop > 0.25 else "medium",
                "baseline": self.baseline_accuracy,
                "current": current_accuracy,
                "drop": round(drop, 4),
            }
            self.alerts.append(alert)

    def get_status(self) -> Dict[str, Any]:
        current_accuracy = None
        if len(self.predictions) >= 10:
            correct = sum(1 for p, a in zip(self.predictions, self.ground_truth) if p == a)
            current_accuracy = round(correct / len(self.predictions), 4)
        return {
            "baseline_accuracy": self.baseline_accuracy,
            "current_accuracy": current_accuracy,
            "window_size": len(self.predictions),
            "drift_detected": len(self.alerts) > 0,
            "alert_count": len(self.alerts),
            "recent_alerts": self.alerts[-5:],
            "uptime_seconds": round(time.time() - self.start_time),
        }

    def reset(self):
        self.predictions.clear()
        self.ground_truth.clear()
        self.alerts.clear()
        self.baseline_accuracy = None
        self.start_time = time.time()


_detector = DriftDetector()


def get_drift_detector() -> DriftDetector:
    return _detector
