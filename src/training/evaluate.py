"""
Model Evaluation and Benchmark Generator for CyberSentinel.
Aggregates metrics, formats confusion matrices, and writes reports/model_comparison_metrics.json.
"""
import sys
import json
from pathlib import Path
from typing import Dict, Any, List

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
from config.settings import (
    RF_BUNDLE_PATH,
    XGB_BUNDLE_PATH,
    AUTOENCODER_BUNDLE_PATH,
    METRICS_SUMMARY_PATH,
    REPORTS_DIR
)
from src.utils.logging_config import logger


def sanitize_for_json(obj: Any) -> Any:
    """Recursively converts NumPy types into native Python types for clean JSON serialization."""
    if isinstance(obj, dict):
        return {str(k): sanitize_for_json(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return [sanitize_for_json(item) for item in obj]
    elif hasattr(obj, "item"):
        return obj.item()
    elif isinstance(obj, (float, int, str, bool)) or obj is None:
        return obj
    else:
        return str(obj)


def generate_benchmark_report() -> Dict[str, Any]:
    """
    Loads saved model bundles and generates a consolidated evaluation summary.
    """
    report: Dict[str, Any] = {
        "title": "CyberSentinel Model Benchmark & Performance Evaluation",
        "generated_at": str(Path(__file__).stat().st_mtime),
        "models": {}
    }
    
    # 1. Random Forest
    if RF_BUNDLE_PATH.exists():
        rf_bundle = joblib.load(RF_BUNDLE_PATH)
        report["models"]["random_forest"] = {
            "name": rf_bundle["model_name"],
            "mode": rf_bundle["mode"],
            "accuracy": float(rf_bundle["accuracy"]),
            "precision_macro": float(rf_bundle["precision_macro"]),
            "recall_macro": float(rf_bundle["recall_macro"]),
            "f1_macro": float(rf_bundle["f1_macro"]),
            "false_positive_rate": float(rf_bundle["false_positive_rate"]),
            "inference_latency_ms_per_1k": float(rf_bundle["inference_latency_ms_per_1k"]),
            "training_duration_seconds": float(rf_bundle["training_duration_seconds"]),
            "target_names": [str(x) for x in rf_bundle["target_names"]],
            "confusion_matrix": sanitize_for_json(rf_bundle["confusion_matrix"]),
            "classification_report": sanitize_for_json(rf_bundle["classification_report"]),
            "top_features": {str(k): float(v) for k, v in rf_bundle.get("top_feature_importances", {}).items()}
        }
        
    # 2. XGBoost
    if XGB_BUNDLE_PATH.exists():
        xgb_bundle = joblib.load(XGB_BUNDLE_PATH)
        report["models"]["xgboost"] = {
            "name": xgb_bundle["model_name"],
            "is_fallback": bool(xgb_bundle.get("is_fallback", False)),
            "mode": xgb_bundle["mode"],
            "accuracy": float(xgb_bundle["accuracy"]),
            "precision_macro": float(xgb_bundle["precision_macro"]),
            "recall_macro": float(xgb_bundle["recall_macro"]),
            "f1_macro": float(xgb_bundle["f1_macro"]),
            "false_positive_rate": float(xgb_bundle["false_positive_rate"]),
            "inference_latency_ms_per_1k": float(xgb_bundle["inference_latency_ms_per_1k"]),
            "training_duration_seconds": float(xgb_bundle["training_duration_seconds"]),
            "target_names": [str(x) for x in xgb_bundle["target_names"]],
            "confusion_matrix": sanitize_for_json(xgb_bundle["confusion_matrix"]),
            "classification_report": sanitize_for_json(xgb_bundle["classification_report"]),
            "top_features": {str(k): float(v) for k, v in xgb_bundle.get("top_feature_importances", {}).items()}
        }
        
    # 3. Autoencoder (Anomaly Detection)
    if AUTOENCODER_BUNDLE_PATH.exists():
        ae_bundle = joblib.load(AUTOENCODER_BUNDLE_PATH)
        report["models"]["autoencoder"] = {
            "name": ae_bundle["model_name"],
            "mode": "unsupervised_anomaly_detection",
            "accuracy": float(ae_bundle["accuracy"]),
            "precision": float(ae_bundle["precision"]),
            "recall": float(ae_bundle["recall"]),
            "f1_score": float(ae_bundle["f1_score"]),
            "false_positive_rate": float(ae_bundle["false_positive_rate"]),
            "anomaly_threshold": float(ae_bundle["anomaly_threshold"]),
            "threshold_percentile": float(ae_bundle["threshold_percentile"]),
            "inference_latency_ms_per_1k": float(ae_bundle["inference_latency_ms_per_1k"]),
            "training_duration_seconds": float(ae_bundle["training_duration_seconds"]),
            "target_names": ["BENIGN", "ANOMALY (ATTACK)"],
            "confusion_matrix": sanitize_for_json(ae_bundle["confusion_matrix"]),
            "classification_report": sanitize_for_json(ae_bundle["classification_report"])
        }

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    with open(METRICS_SUMMARY_PATH, "w") as f:
        json.dump(sanitize_for_json(report), f, indent=2)
        
    logger.info(f"Consolidated benchmark report saved to: {METRICS_SUMMARY_PATH}")
    return report


if __name__ == "__main__":
    generate_benchmark_report()
