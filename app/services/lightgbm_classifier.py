"""
PREVAIL - LightGBM Classifier
Fast gradient boosting classifier for attack probability prediction.
"""
import numpy as np
import joblib
from pathlib import Path
from typing import Dict, Any, Optional

MODEL_DIR = Path(__file__).resolve().parent.parent.parent / "models" / "classifier"


class LightGBMClassifier:
    def __init__(self):
        self.model = None
        self.scaler = None
        self.feature_names: list = []
        self.is_trained = False
        self.metrics: Dict[str, Any] = {}

    def train(self, X: np.ndarray, y: np.ndarray, feature_names: list = None,
              n_estimators: int = 200, max_depth: int = -1, learning_rate: float = 0.1,
              num_leaves: int = 31, random_state: int = 42) -> Dict[str, Any]:
        try:
            import lightgbm as lgb
        except ImportError:
            return {"error": "lightgbm not installed. Run: pip install lightgbm"}

        self.feature_names = feature_names or [f"f{i}" for i in range(X.shape[1])]
        from sklearn.preprocessing import StandardScaler
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = lgb.LGBMClassifier(
            n_estimators=n_estimators, max_depth=max_depth,
            learning_rate=learning_rate, num_leaves=num_leaves,
            random_state=random_state, n_jobs=-1, verbose=-1
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
            "num_leaves": num_leaves,
            "learning_rate": learning_rate,
            "n_samples": len(X),
            "n_features": X.shape[1],
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
        path = path or str(MODEL_DIR / "lightgbm.joblib")
        joblib.dump({
            "model": self.model, "scaler": self.scaler,
            "feature_names": self.feature_names, "metrics": self.metrics
        }, path)

    def load(self, path: Optional[str] = None) -> bool:
        path = path or str(MODEL_DIR / "lightgbm.joblib")
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


_lgb = LightGBMClassifier()


def get_lightgbm() -> LightGBMClassifier:
    if not _lgb.is_trained:
        _lgb.load()
    return _lgb
