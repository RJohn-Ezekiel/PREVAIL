"""
PREVAIL - Explainability Engine (SHAP)
Computes SHAP values for model interpretability.
"""
import numpy as np
from typing import Dict, Any, List, Optional


def compute_shap_values(model, X: np.ndarray, feature_names: List[str],
                        top_n: int = 10) -> Dict[str, Any]:
    try:
        import shap
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X)
        if isinstance(shap_values, list):
            shap_vals = shap_values[1] if len(shap_values) > 1 else shap_values[0]
        else:
            shap_vals = shap_values
        if shap_vals.ndim > 1:
            shap_vals = shap_vals[0]
        importance = sorted(
            zip(feature_names, shap_vals),
            key=lambda x: abs(x[1]), reverse=True
        )[:top_n]
        return {
            "shap_values": [{"feature": n, "shap_value": round(float(v), 4)} for n, v in importance],
            "base_value": round(float(explainer.expected_value[1] if isinstance(explainer.expected_value, list) else explainer.expected_value), 4) if hasattr(explainer, 'expected_value') else 0,
            "available": True,
        }
    except ImportError:
        return {"shap_values": [], "available": False, "note": "shap not installed"}
    except Exception as e:
        return {"shap_values": [], "available": False, "note": str(e)}


def get_model_shap(model, feature_matrix: np.ndarray, feature_names: List[str]) -> Dict[str, Any]:
    if model is None or not hasattr(model, 'predict'):
        return {"shap_values": [], "available": False}
    return compute_shap_values(model, feature_matrix[:1], feature_names)
