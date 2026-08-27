"""
PREVAIL - Anomaly Detector
Isolation Forest based behavioral anomaly detection.
"""
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, Optional, Tuple
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "anomaly"


class AnomalyDetector:
    def __init__(self):
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        self.feature_names: list = []
        self.is_trained = False

    def train(self, feature_matrix: np.ndarray, feature_names: list = None, contamination: float = 0.1) -> Dict[str, Any]:
        self.feature_names = feature_names or [f"f{i}" for i in range(feature_matrix.shape[1])]
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(feature_matrix)
        self.model = IsolationForest(
            contamination=contamination, n_estimators=100,
            max_samples="auto", random_state=42, n_jobs=-1
        )
        self.model.fit(X_scaled)
        self.is_trained = True
        scores = self.model.decision_function(X_scaled)
        return {
            "samples_trained": len(feature_matrix),
            "features_used": len(self.feature_names),
            "mean_anomaly_score": float(np.mean(scores)),
            "std_anomaly_score": float(np.std(scores)),
        }

    def predict(self, features) -> Dict[str, Any]:
        if not self.is_trained or self.model is None:
            return {"anomaly_score": 0.0, "is_anomalous": False, "top_features": [], "confidence": 0.0}
        try:
            arr = np.array(features, dtype=float).reshape(1, -1)
            n_train = self.scaler.n_features_in_
            if arr.shape[1] < n_train:
                pad = np.zeros((1, n_train - arr.shape[1]))
                arr = np.hstack([arr, pad])
            elif arr.shape[1] > n_train:
                arr = arr[:, :n_train]
            X_scaled = self.scaler.transform(arr)
            raw_score = float(self.model.decision_function(X_scaled)[0])
            prediction = int(self.model.predict(X_scaled)[0])
            anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))
            is_anomalous = prediction == -1

            top_features = []
            if len(self.feature_names) == arr.shape[1]:
                importances = np.abs(X_scaled[0])
                top_idx = np.argsort(importances)[::-1][:5]
                for idx in top_idx:
                    if importances[idx] > 0:
                        top_features.append({
                            "feature": self.feature_names[idx],
                            "value": float(arr[0][idx]),
                            "scaled_importance": float(importances[idx]),
                        })

            return {
                "anomaly_score": round(anomaly_score * 100, 1),
                "is_anomalous": is_anomalous,
                "raw_score": round(raw_score, 4),
                "top_features": top_features,
                "confidence": round(min(abs(raw_score) * 10, 1.0), 2),
            }
        except Exception:
            return {"anomaly_score": 0.0, "is_anomalous": False, "top_features": [], "confidence": 0.0}

    def save(self, path: Optional[str] = None):
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        path = path or str(MODEL_DIR / "isolation_forest.joblib")
        joblib.dump({"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names}, path)

    def load(self, path: Optional[str] = None) -> bool:
        path = path or str(MODEL_DIR / "isolation_forest.joblib")
        if not Path(path).exists():
            return False
        try:
            data = joblib.load(path)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.feature_names = data.get("feature_names", [])
            self.is_trained = True
            return True
        except Exception:
            return False


_detector = AnomalyDetector()


def get_detector() -> AnomalyDetector:
    if not _detector.is_trained:
        _detector.load()
    return _detector


def train_anomaly_detector(feature_matrix: np.ndarray, feature_names: list = None) -> Dict[str, Any]:
    return _detector.train(feature_matrix, feature_names)


def detect_anomaly(features: np.ndarray) -> Dict[str, Any]:
    return _detector.predict(features)
