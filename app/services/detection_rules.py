"""
PREVAIL - Detection Rules
Toggleable detection rules that gate sections of the risk pipeline.
"""
from typing import Dict, Any

DEFAULT_RULES = {
    "login_monitoring": True,
    "brute_force_detection": True,
    "recon_detection": True,
    "privilege_monitoring": True,
    "exfil_detection": True,
    "c2_detection": True,
    "temporal_correlation": True,
    "anomaly_detection": True,
}

_rules: Dict[str, bool] = dict(DEFAULT_RULES)


def get_detection_rules() -> Dict[str, bool]:
    return dict(_rules)


def set_detection_rules(rules: Dict[str, bool]):
    _rules.update(rules)


def is_enabled(rule: str) -> bool:
    return _rules.get(rule, True)


def apply_rules_to_features(features: Dict[str, Any]) -> Dict[str, Any]:
    filtered = dict(features)
    if not _rules.get("brute_force_detection", True):
        filtered["max_failed_logins"] = 0
        filtered["failed_logins_5m"] = 0
        filtered["failed_logins_15m"] = 0
        filtered["login_failures_5m"] = 0
    if not _rules.get("recon_detection", True):
        filtered["host_discovery_count_5m"] = 0
        filtered["port_scan_count_5m"] = 0
    if not _rules.get("privilege_monitoring", True):
        filtered["privilege_change"] = 0
        filtered["privilege_change_count_5m"] = 0
    if not _rules.get("exfil_detection", True):
        filtered["data_transfer_count_5m"] = 0
        filtered["high_data_volume"] = 0
        filtered["bytes_sent_5m"] = 0
    if not _rules.get("c2_detection", True):
        filtered["command_execution_count_5m"] = 0
    if not _rules.get("login_monitoring", True):
        filtered["unusual_login_time"] = 0
    return filtered
