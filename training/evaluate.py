"""
PREVAIL - Evaluate Models
Runs evaluation on trained models and reports metrics.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd
import joblib
from simulation.event_generator import generate_training_data
from app.services.feature_engine import extract_features, extract_labeled_features, events_to_dataframe
from app.services.anomaly_detector import get_detector
from app.database.database import init_db, get_model_metadata


def evaluate():
    init_db()
    print("=== PREVAIL Model Evaluation ===\n")

    # Anomaly detector
    detector = get_detector()
    if detector.is_trained:
        print("[Anomaly Detector] Model loaded")
        meta = get_model_metadata()
        for m in meta:
            if m["model_type"] == "anomaly":
                metrics = eval(m["metrics_json"]) if isinstance(m["metrics_json"], str) else m["metrics_json"]
                for k, v in metrics.items():
                    print(f"  {k}: {v}")
    else:
        print("[Anomaly Detector] No trained model found")

    # Classifier
    clf_path = Path("models/classifier/attack_classifier.joblib")
    if clf_path.exists():
        print("\n[Classifier] Model loaded")
        data = joblib.load(clf_path)
        metrics = data.get("metrics", {})
        for k, v in metrics.items():
            print(f"  {k}: {v}")
    else:
        print("\n[Classifier] No trained model found")

    print("\n=== Evaluation Complete ===")


if __name__ == "__main__":
    evaluate()
