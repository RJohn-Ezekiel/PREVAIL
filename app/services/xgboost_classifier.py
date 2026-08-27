"""
PREVAIL - XGBoost Classifier
Gradient boosting classifier for attack probability prediction.
"""
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, Optional

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "classifier"


class XGBoostClassifier:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names: list = []
        self.is_trained = False
        self.metrics: Dict[str, Any] = {}

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: list = None,
              n_estimators: int = 200, max_depth: int = 6, learning_rate: float = 0.1,
              random_state: int = 42) -> Dict[str, Any]:
        try:
            from xgboost import XGBClassifier as _XGB
        except ImportError:
            return {"error": "xgboost not installed. Run: pip install xgboost"}

        self.feature_names = feature_names or [f"f{i}" for i in range(X.shape[1])]
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        pos_count = int(np.sum(y == 1))
        neg_count = int(np.sum(y == 0))
        scale_pos_weight = neg_count / max(pos_count, 1)

        self.model = _XGB(
            n_estimators=n_estimators, max_depth=max_depth,
            learning_rate=learning_rate, random_state=random_state,
            scale_pos_weight=scale_pos_weight, eval_metric="logloss",
            use_label_encoder=False, n_jobs=-1
        )
        self.model.fit(X_scaled, y)
        self.is_trained = True

        from sklearn.model_selection import cross_val_score
        cv_folds = min(3, len(y))
        scores = cross_val_score(self.model, X_scaled, y, cv=cv_folds, scoring="f1")

        self.metrics = {
            "accuracy": round(float(self.model.score(X_scaled, y)), 4),
            "f1_mean": round(float(scores.mean()), 4),
            "f1_std": round(float(scores.std()), 4),
            "n_estimators": n_estimators,
            "max_depth": max_depth,
            "learning_rate": learning_rate,
            "n_samples": len(X),
            "n_features": X.shape[1],
            "scale_pos_weight": round(scale_pos_weight, 2),
        }
        return self.metrics

    def predict(self, features) -> Dict[str, Any]:
        if not self.is_trained or self.model is None:
            return {"attack_probability": 0.0, "prediction": 0, "confidence": 0.0}
        try:
            arr = np.array(features, dtype=float).reshape(1, -1)
            n_train = self.scaler.n_features_in_
            if arr.shape[1] < n_train:
                arr = np.hstack([arr, np.zeros((1, n_train - arr.shape[1]))])
            elif arr.shape[1] > n_train:
                arr = arr[:, :n_train]
            X_scaled = self.scaler.transform(arr)
            proba = self.model.predict_proba(X_scaled)[0]
            attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
            prediction = int(self.model.predict(X_scaled)[0])
            return {
                "attack_probability": round(attack_prob * 100, 1),
                "prediction": prediction,
                "confidence": round(float(max(proba)), 3),
            }
        except Exception:
            return {"attack_probability": 0.0, "prediction": 0, "confidence": 0.0}

    def get_feature_importance(self) -> list:
        if not self.is_trained or self.model is None:
            return []
        try:
            importances = self.model.feature_importances_
            pairs = sorted(zip(self.feature_names, importances), key=lambda x: -x[1])
            return [{"feature": n, "importance": round(float(v), 4)} for n, v in pairs[:15]]
        except Exception:
            return []

    def save(self, path: Optional[str] = None):
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        path = path or str(MODEL_DIR / "xgboost.joblib")
        joblib.dump({
            "model": self.model, "scaler": self.scaler,
            "feature_names": self.feature_names, "metrics": self.metrics
        }, path)

    def load(self, path: Optional[str] = None) -> bool:
        path = path or str(MODEL_DIR / "xgboost.joblib")
        if not Path(path).exists():
            return False
        try:
            data = joblib.load(path)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.feature_names = data.get("feature_names", [])
            self.metrics = data.get("metrics", {})
            self.is_trained = True
            return True
        except Exception:
            return False


_xgb = XGBoostClassifier()


def get_xgboost() -> XGBoostClassifier:
    if not _xgb.is_trained:
        _xgb.load()
    return _xgb
