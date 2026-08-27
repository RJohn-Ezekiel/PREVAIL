"""
PREVAIL - Attack Scenario Definitions
Defines multi-stage attack progressions for simulation.
"""
from typing import List, Dict, Any

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "multi_stage_attack": {
        "name": "Multi-Stage Attack",
        "description": "Progressive attack: auth anomaly → recon → privilege escalation → exfiltration → C2",
        "stages": [
            {"label": "Normal Activity", "event_count": 2, "scenario": "normal", "risk_contribution": 0},
            {"label": "Unusual Login Pattern", "event_count": 1, "scenario": "brute_force", "risk_contribution": 10},
            {"label": "Repeated Auth Failures", "event_count": 3, "scenario": "brute_force", "risk_contribution": 20},
            {"label": "Successful Compromise", "event_count": 1, "scenario": "brute_force", "risk_contribution": 25},
            {"label": "Internal Reconnaissance", "event_count": 3, "scenario": "reconnaissance", "risk_contribution": 35},
            {"label": "Privilege Escalation", "event_count": 3, "scenario": "privilege_escalation", "risk_contribution": 50},
            {"label": "Data Staging", "event_count": 2, "scenario": "data_exfiltration", "risk_contribution": 65},
            {"label": "Data Exfiltration", "event_count": 2, "scenario": "data_exfiltration", "risk_contribution": 80},
            {"label": "C2 Communication", "event_count": 1, "scenario": "multi_stage_attack", "risk_contribution": 90},
        ],
    },
    "brute_force_only": {
        "name": "Brute Force Attack",
        "description": "Credential brute force leading to compromise",
        "stages": [
            {"label": "Normal Activity", "event_count": 2, "scenario": "normal", "risk_contribution": 0},
            {"label": "First Auth Failure", "event_count": 1, "scenario": "brute_force", "risk_contribution": 8},
            {"label": "Repeated Failures", "event_count": 4, "scenario": "brute_force", "risk_contribution": 20},
            {"label": "Credential Compromise", "event_count": 1, "scenario": "brute_force", "risk_contribution": 35},
        ],
    },
    "recon_then_privilege": {
        "name": "Reconnaissance → Privilege Escalation",
        "description": "Network discovery followed by privilege escalation",
        "stages": [
            {"label": "Normal Activity", "event_count": 2, "scenario": "normal", "risk_contribution": 0},
            {"label": "Host Discovery", "event_count": 1, "scenario": "reconnaissance", "risk_contribution": 15},
            {"label": "Port Scanning", "event_count": 3, "scenario": "reconnaissance", "risk_contribution": 30},
            {"label": "Privilege Escalation", "event_count": 2, "scenario": "privilege_escalation", "risk_contribution": 55},
        ],
    },
}

DEFAULT_SCENARIO = "multi_stage_attack"


def get_scenario(name: str = DEFAULT_SCENARIO) -> Dict[str, Any]:
    return SCENARIOS.get(name, SCENARIOS[DEFAULT_SCENARIO])


def list_scenarios() -> List[str]:
    return list(SCENARIOS.keys())
