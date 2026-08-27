"""
PREVAIL - Sequence / Temporal Correlation Engine
Detects multi-stage attack patterns via temporal signal correlation.
"""
from typing import Dict, Any, List, Optional
from collections import deque
from datetime import datetime
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.telemetry import TelemetryEvent, EventType

KNOWN_ATTACK_PATTERNS = [
    {"sequence": ["auth_failure", "host_discovery", "port_scan", "privilege_change"], "weight": 0.9},
    {"sequence": ["auth_failure", "privilege_change", "data_transfer"], "weight": 0.85},
    {"sequence": ["host_discovery", "port_scan", "command_execution"], "weight": 0.8},
    {"sequence": ["port_scan", "privilege_change", "data_transfer"], "weight": 0.85},
    {"sequence": ["login", "host_discovery", "port_scan"], "weight": 0.7},
    {"sequence": ["privilege_change", "command_execution", "data_transfer"], "weight": 0.9},
]


class SequenceEngine:
    def __init__(self, window_size: int = 10):
        self.window_size = window_size
        self.event_buffer: deque = deque(maxlen=window_size)
        self.detected_patterns: List[Dict[str, Any]] = []

    def _classify_event(self, event: TelemetryEvent) -> str:
        if event.event_type == EventType.AUTH_FAILURE or (event.event_type == EventType.LOGIN and event.login_success == False):
            return "auth_failure"
        if event.event_type == EventType.HOST_DISCOVERY:
            return "host_discovery"
        if event.event_type == EventType.PORT_SCAN:
            return "port_scan"
        if event.event_type == EventType.PRIVILEGE_CHANGE:
            return "privilege_change"
        if event.event_type == EventType.COMMAND_EXECUTION:
            return "command_execution"
        if event.event_type == EventType.DATA_TRANSFER:
            return "data_transfer"
        if event.event_type == EventType.FILE_ACCESS and event.resource and "/etc/" in str(event.resource):
            return "sensitive_file_access"
        if event.event_type == EventType.CONFIG_CHANGE:
            return "config_change"
        if event.event_type == EventType.LOGIN:
            return "login"
        return "other"

    def add_event(self, event: TelemetryEvent) -> Dict[str, Any]:
        classification = self._classify_event(event)
        entry = {"timestamp": event.timestamp.isoformat(), "type": classification, "event_type": str(event.event_type)}
        self.event_buffer.append(entry)
        return self._analyze()

    def _analyze(self) -> Dict[str, Any]:
        if len(self.event_buffer) < 2:
            return {"temporal_score": 0.0, "detected_patterns": [], "sequence_risk": "none"}

        sequence = [e["type"] for e in self.event_buffer]
        sequence_str = " → ".join(sequence)
        matched_patterns = []

        for pattern in KNOWN_ATTACK_PATTERNS:
            pat_seq = pattern["sequence"]
            if self._is_subsequence(pat_seq, sequence):
                matched_patterns.append({
                    "pattern": " → ".join(pat_seq),
                    "weight": pattern["weight"],
                    "match_length": len(pat_seq),
                })

        if matched_patterns:
            best_weight = max(p["weight"] for p in matched_patterns)
            temporal_score = best_weight * 100
            risk = "high" if best_weight > 0.8 else "moderate"
        else:
            consecutive_anomalous = 0
            for e in reversed(sequence):
                if e in ("auth_failure", "host_discovery", "port_scan", "privilege_change", "data_transfer"):
                    consecutive_anomalous += 1
                else:
                    break
            temporal_score = min(consecutive_anomalous * 15, 60)
            risk = "moderate" if consecutive_anomalous >= 2 else "low"

        self.detected_patterns = matched_patterns
        return {
            "temporal_score": round(temporal_score, 1),
            "detected_patterns": matched_patterns,
            "sequence_risk": risk,
            "current_sequence": sequence_str,
            "events_in_window": len(self.event_buffer),
        }

    def _is_subsequence(self, pattern: List[str], sequence: List[str]) -> bool:
        it = iter(sequence)
        return all(p in it for p in pattern)

    def get_state(self) -> Dict[str, Any]:
        return {
            "events_in_buffer": len(self.event_buffer),
            "buffer": list(self.event_buffer),
            "detected_patterns": self.detected_patterns,
        }

    def reset(self):
        self.event_buffer.clear()
        self.detected_patterns = []


_engine = SequenceEngine()


def get_engine() -> SequenceEngine:
    return _engine


def analyze_sequence(events: List[TelemetryEvent]) -> Dict[str, Any]:
    engine = SequenceEngine()
    result = None
    for ev in events:
        result = engine.add_event(ev)
    return result or {"temporal_score": 0.0, "detected_patterns": [], "sequence_risk": "none"}
