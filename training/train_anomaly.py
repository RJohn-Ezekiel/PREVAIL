"""
PREVAIL - Train Anomaly Detector
Trains Isolation Forest on synthetic behavioral data.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd
from simulation.event_generator import generate_training_data
from app.services.feature_engine import extract_features, events_to_dataframe
from app.services.anomaly_detector import get_detector
from app.database.database import init_db, store_model_metadata


def train():
    print("Generating training data...")
    events = generate_training_data(n_scenarios=15, seed=42)
    print(f"Generated {len(events)} events")

    print("Extracting features...")
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

    all_features = []
    for grp in feature_groups:
        feat = extract_features(grp)
        if feat:
            all_features.append(feat)

    if not all_features:
        print("No features extracted!")
        return

    feat_df = pd.DataFrame(all_features).fillna(0)
    feature_names = list(feat_df.columns)
    X = feat_df.values.astype(float)

    print(f"Training on {len(X)} samples with {len(feature_names)} features...")
    detector = get_detector()
    metrics = detector.train(X, feature_names)
    detector.save()

    init_db()
    store_model_metadata("anomaly", "isolation_forest", metrics, "models/anomaly/isolation_forest.joblib")

    print("Training complete!")
    for k, v in metrics.items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    train()
