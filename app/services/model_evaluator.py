"""
PREVAIL - Model Evaluator
Enhanced model evaluation: confusion matrix, ROC, precision/recall/F1, feature importance.
"""
import numpy as np
from typing import Dict, Any, List
from sklearn.metrics import (
    confusion_matrix, classification_report, roc_curve, auc,
    precision_recall_fscore_support, accuracy_score
)


def evaluate_classifier(model, X: np.ndarray, y: np.ndarray,
                        feature_names: List[str] = None) -> Dict[str, Any]:
    try:
        y_pred = model.predict(X)
        if hasattr(model, 'predict_proba'):
            y_proba = model.predict_proba(X)[:, 1]
        else:
            y_proba = y_pred.astype(float)

        cm = confusion_matrix(y, y_pred).tolist()
        report = classification_report(y, y_pred, output_dict=True, zero_division=0)
        fpr, tpr, thresholds = roc_curve(y, y_proba)
        roc_auc = auc(fpr, tpr)

        precision, recall, f1, _ = precision_recall_fscore_support(y, y_pred, average='binary', zero_division=0)
        accuracy = accuracy_score(y, y_pred)

        feature_importance = []
        if feature_names and hasattr(model, 'feature_importances_'):
            importances = model.feature_importances_
            pairs = sorted(zip(feature_names, importances), key=lambda x: -x[1])
            feature_importance = [{"feature": n, "importance": round(float(v), 4)} for n, v in pairs[:15]]

        return {
            "accuracy": round(float(accuracy), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "roc_auc": round(float(roc_auc), 4),
            "confusion_matrix": cm,
            "classification_report": report,
            "roc_curve": {
                "fpr": [round(float(x), 4) for x in fpr[::max(1, len(fpr)//50)]],
                "tpr": [round(float(x), 4) for x in tpr[::max(1, len(tpr)//50)]],
                "thresholds": [round(float(x), 4) for x in thresholds[::max(1, len(thresholds)//50)]],
            },
            "feature_importance": feature_importance,
            "n_samples": len(X),
        }
    except Exception as e:
        return {"error": str(e)}


def evaluate_anomaly_detector(model, X: np.ndarray, y_true: np.ndarray = None) -> Dict[str, Any]:
    try:
        predictions = model.predict(X)
        scores = model.decision_function(X) if hasattr(model, 'decision_function') else None
        anomaly_labels = (predictions == -1).astype(int)
        n_anomalies = int(np.sum(anomaly_labels))
        n_total = len(anomaly_labels)
        result = {
            "n_anomalies": n_anomalies,
            "n_total": n_total,
            "anomaly_ratio": round(n_anomalies / max(n_total, 1), 4),
            "mean_score": round(float(np.mean(scores)), 4) if scores is not None else None,
            "std_score": round(float(np.std(scores)), 4) if scores is not None else None,
        }
        if y_true is not None:
            cm = confusion_matrix(y_true, anomaly_labels).tolist()
            report = classification_report(y_true, anomaly_labels, output_dict=True, zero_division=0)
            result["confusion_matrix"] = cm
            result["classification_report"] = report
        return result
    except Exception as e:
        return {"error": str(e)}
