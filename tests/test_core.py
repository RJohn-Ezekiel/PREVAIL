"""
PREVAIL - Tests
Basic tests for core functionality.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from datetime import datetime
from app.services.telemetry import TelemetryEvent, EventType, PrivilegeLevel, Protocol
from app.services.feature_engine import extract_features
from app.services.risk_engine import compute_risk
from app.services.sequence_engine import SequenceEngine
from app.services.explanation_engine import explain_risk
from simulation.event_generator import load_scenario, generate_baseline_data, generate_normal_event


class TestTelemetryEvent:
    def test_create_event(self):
        ev = TelemetryEvent(
            timestamp=datetime.utcnow(),
            user_id="user_1",
            source_ip="10.0.0.1",
            event_type=EventType.LOGIN,
            login_success=True,
        )
        assert ev.user_id == "user_1"
        assert ev.event_type == EventType.LOGIN

    def test_to_dict(self):
        ev = TelemetryEvent(
            timestamp=datetime.utcnow(),
            event_type=EventType.LOGIN,
            login_success=True,
        )
        d = ev.to_dict()
        assert "timestamp" in d
        assert d["event_type"] == "login"

    def test_from_json(self):
        json_str = '{"timestamp": "2026-08-27T10:00:00", "event_type": "login", "login_success": true, "user_id": "test"}'
        ev = TelemetryEvent.from_json(json_str)
        assert ev.user_id == "test"


class TestFeatureEngine:
    def test_extract_features_empty(self):
        features = extract_features([])
        assert features == {}

    def test_extract_features(self):
        events = generate_baseline_data(50, seed=1)
        features = extract_features(events)
        assert isinstance(features, dict)
        assert "event_count" in features

    def test_extract_features_with_anomalous(self):
        events = load_scenario("brute_force", seed=1)
        if events:
            features = extract_features(events)
            assert features.get("failed_logins_5m", 0) > 0 or features.get("event_count", 0) > 0


class TestRiskEngine:
    def test_low_risk(self):
        result = compute_risk(anomaly_score=5, attack_probability=2, temporal_score=0)
        assert result["risk_score"] < 25
        assert result["risk_level"] == "LOW"

    def test_high_risk(self):
        result = compute_risk(anomaly_score=80, attack_probability=90, temporal_score=70)
        assert result["risk_score"] > 50
        assert result["risk_level"] in ("HIGH", "CRITICAL")

    def test_components_present(self):
        result = compute_risk()
        assert "components" in result
        assert "key_signals" in result


class TestSequenceEngine:
    def test_single_event(self):
        engine = SequenceEngine()
        ev = TelemetryEvent(timestamp=datetime.utcnow(), event_type=EventType.LOGIN, login_success=True)
        result = engine.add_event(ev)
        assert "temporal_score" in result

    def test_attack_sequence(self):
        engine = SequenceEngine()
        events = [
            TelemetryEvent(timestamp=datetime.utcnow(), event_type=EventType.AUTH_FAILURE, login_success=False),
            TelemetryEvent(timestamp=datetime.utcnow(), event_type=EventType.HOST_DISCOVERY),
            TelemetryEvent(timestamp=datetime.utcnow(), event_type=EventType.PORT_SCAN),
            TelemetryEvent(timestamp=datetime.utcnow(), event_type=EventType.PRIVILEGE_CHANGE),
        ]
        for ev in events:
            result = engine.add_event(ev)
        assert result["temporal_score"] > 0


class TestExplanationEngine:
    def test_explain_low_risk(self):
        risk = {"risk_score": 10, "risk_level": "LOW", "predicted_stage": "normal", "key_signals": ["No issues"], "components": {}}
        explanation = explain_risk(risk)
        assert "summary" in explanation
        assert "recommendation" in explanation

    def test_explain_high_risk(self):
        risk = {"risk_score": 85, "risk_level": "CRITICAL", "predicted_stage": "imminent_attack",
                "key_signals": ["Privilege escalation detected"], "components": {"anomaly_score": 80}}
        explanation = explain_risk(risk)
        assert "summary" in explanation


class TestScenarios:
    def test_load_scenario(self):
        events = load_scenario("normal", seed=1)
        assert len(events) > 0

    def test_load_multi_stage(self):
        events = load_scenario("multi_stage_attack", seed=1)
        assert len(events) > 3

    def test_baseline_data(self):
        events = generate_baseline_data(20, seed=1)
        assert len(events) == 20
