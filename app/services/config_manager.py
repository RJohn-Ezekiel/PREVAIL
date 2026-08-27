"""
PREVAIL - Config Manager
Live configuration singleton. Reads/writes config.json, holds state in memory.
Risk engine and other components read from this instead of re-reading file each call.
"""
import json
import threading
from pathlib import Path
from typing import Dict, Any, Optional

CONFIG_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "config.json"

_lock = threading.Lock()


class ConfigManager:
    def __init__(self):
        self._config: Dict[str, Any] = {}
        self._load()

    def _load(self):
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                self._config = json.load(f)
        else:
            self._config = {}

    def get_config(self) -> Dict[str, Any]:
        with _lock:
            return json.loads(json.dumps(self._config))

    def get_risk_weights(self) -> Dict[str, float]:
        with _lock:
            return dict(self._config.get("risk_engine", {}).get("weights", {
                "anomaly_score": 0.25, "attack_probability": 0.30,
                "temporal_score": 0.25, "behavioral_signals": 0.20
            }))

    def get_thresholds(self) -> Dict[str, int]:
        with _lock:
            return dict(self._config.get("risk_engine", {}).get("thresholds", {
                "low": 24, "moderate": 49, "high": 74, "critical": 100
            }))

    def get_model_params(self) -> Dict[str, Any]:
        with _lock:
            return {
                "anomaly": dict(self._config.get("model", {}).get("anomaly", {})),
                "classifier": dict(self._config.get("model", {}).get("classifier", {})),
            }

    def get_detection_rules(self) -> Dict[str, bool]:
        with _lock:
            return dict(self._config.get("detection_rules", {
                "login_monitoring": True,
                "brute_force_detection": True,
                "recon_detection": True,
                "privilege_monitoring": True,
                "exfil_detection": True,
                "c2_detection": True,
                "temporal_correlation": True,
                "anomaly_detection": True,
            }))

    def update_risk_weights(self, weights: Dict[str, float]) -> bool:
        with _lock:
            total = sum(weights.values())
            if total <= 0:
                return False
            normalized = {k: round(v / total, 4) for k, v in weights.items()}
            self._config.setdefault("risk_engine", {})["weights"] = normalized
            return self._save()

    def update_thresholds(self, thresholds: Dict[str, int]) -> bool:
        with _lock:
            self._config.setdefault("risk_engine", {})["thresholds"] = thresholds
            return self._save()

    def update_model_params(self, params: Dict[str, Any]) -> bool:
        with _lock:
            for section, values in params.items():
                if section in self._config.get("model", {}):
                    self._config["model"][section].update(values)
            return self._save()

    def update_detection_rules(self, rules: Dict[str, bool]) -> bool:
        with _lock:
            self._config.setdefault("detection_rules", {}).update(rules)
            return self._save()

    def update_simulation_config(self, sim_config: Dict[str, Any]) -> bool:
        with _lock:
            self._config.setdefault("simulation", {}).update(sim_config)
            return self._save()

    def _save(self) -> bool:
        try:
            CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_PATH, "w") as f:
                json.dump(self._config, f, indent=2)
            return True
        except Exception:
            return False

    def reload(self):
        with _lock:
            self._load()


_manager = ConfigManager()


def get_config_manager() -> ConfigManager:
    return _manager
