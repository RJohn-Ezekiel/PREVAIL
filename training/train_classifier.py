"""
PREVAIL - Train Classifier (Attack Probability)
Trains Random Forest for attack probability prediction.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from simulation.event_generator import generate_training_data
from app.services.feature_engine import extract_labeled_features, events_to_dataframe
from app.database.database import init_db, store_model_metadata

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "classifier" / "attack_classifier.joblib"


def train():
    print("Generating training data...")
    events = generate_training_data(n_scenarios=20, seed=42)
    print(f"Generated {len(events)} events")

    print("Building feature matrix with labels...")
    df = events_to_dataframe(events)
    feature_groups = []
    group = []
    for _, row in df.iterrows():
        ev_dict = row.to_dict()
        from app.services.telemetry import TelemetryEvent
        try:
            ev = TelemetryEvent(**{k: v for k, v in ev_dict.items() if v is not None})
            group.append(ev)
        except Exception:
            pass
        if len(group) >= 20:
            feature_groups.append(group)
            group = []
    if group:
        feature_groups.append(group)

    labeled_features = []
    for grp in feature_groups:
        feat = extract_labeled_features(grp, prediction_horizon_minutes=30)
        if feat:
            labeled_features.append(feat)

    if not labeled_features:
        print("No labeled features!")
        return

    feat_df = pd.DataFrame(labeled_features).fillna(0)
    if "label" not in feat_df.columns:
        print("No labels generated!")
        return

    X = feat_df.drop(columns=["label"]).values.astype(float)
    y = feat_df["label"].values.astype(int)
    feature_names = [c for c in feat_df.columns if c != "label"]

    print(f"Dataset: {len(X)} samples, {sum(y)} positive, {len(y)-sum(y)} negative")

    if len(np.unique(y)) < 2:
        print("Only one class in data — cannot train classifier")
        return

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1] if len(np.unique(y_test)) > 1 else y_pred.astype(float)

    metrics = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "precision": round(precision_score(y_test, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_test, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_test, y_pred, zero_division=0), 4),
    }
    try:
        metrics["roc_auc"] = round(roc_auc_score(y_test, y_prob), 4)
    except Exception:
        metrics["roc_auc"] = None

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "feature_names": feature_names, "metrics": metrics}, MODEL_PATH)

    init_db()
    store_model_metadata("classifier", "random_forest", metrics, str(MODEL_PATH))

    print("Training complete!")
    for k, v in metrics.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    train()
