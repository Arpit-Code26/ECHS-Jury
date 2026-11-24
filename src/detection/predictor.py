"""
Unified Prediction Engine for CyberSentinel.
Loads trained models, validates incoming CSVs, executes inference,
evaluates ground-truth if available, and structures results for the SOC Dashboard.
"""
from typing import Dict, Any, Optional, Tuple, List, Union
from pathlib import Path
import time
import io
import pandas as pd
import numpy as np
import joblib

from config.settings import RF_BUNDLE_PATH, XGB_BUNDLE_PATH, AUTOENCODER_BUNDLE_PATH, AUTOENCODER_WEIGHTS_PATH
from config.model_config import TARGET_COLUMN, CANONICAL_FEATURES
from src.data.validation import validate_dataset_schema
from src.data.preprocessing import CyberSentinelPreprocessor, prepare_labels
from src.detection.threat_explainer import get_threat_explanation
from src.utils.logging_config import logger

try:
    import torch
    from src.training.train_autoencoder import CyberSentinelAutoencoder
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class CyberSentinelPredictor:
    """
    Reusable Inference Engine for Windows and Jetson platforms.
    """
    def __init__(self):
        self.cached_models: Dict[str, Any] = {}
        self.current_model_name: Optional[str] = None

    def load_model(self, model_type: str = "xgboost") -> Dict[str, Any]:
        """
        Loads and caches the requested model bundle.
        model_type: 'xgboost', 'random_forest', or 'autoencoder'
        """
        model_type = model_type.lower()
        if model_type in self.cached_models:
            self.current_model_name = model_type
            return self.cached_models[model_type]

        if model_type in ["xgboost", "xgb"]:
            if not XGB_BUNDLE_PATH.exists():
                raise FileNotFoundError(f"XGBoost bundle not found at: {XGB_BUNDLE_PATH}. Please train models first.")
            bundle = joblib.load(XGB_BUNDLE_PATH)
            self.cached_models["xgboost"] = bundle
            self.current_model_name = "xgboost"
            logger.info("XGBoost model bundle loaded into predictor.")
            return bundle

        elif model_type in ["random_forest", "rf"]:
            if not RF_BUNDLE_PATH.exists():
                raise FileNotFoundError(f"Random Forest bundle not found at: {RF_BUNDLE_PATH}. Please train models first.")
            bundle = joblib.load(RF_BUNDLE_PATH)
            self.cached_models["random_forest"] = bundle
            self.current_model_name = "random_forest"
            logger.info("Random Forest model bundle loaded into predictor.")
            return bundle

        elif model_type in ["autoencoder", "ae"]:
            if not HAS_TORCH:
                raise RuntimeError("PyTorch is not installed in this environment.")
            if not AUTOENCODER_BUNDLE_PATH.exists():
                raise FileNotFoundError(f"Autoencoder bundle not found at: {AUTOENCODER_BUNDLE_PATH}.")
            bundle = joblib.load(AUTOENCODER_BUNDLE_PATH)
            
            # Reconstruct PyTorch model
            model = CyberSentinelAutoencoder(input_dim=bundle["input_dim"], latent_dim=bundle["latent_dim"])
            model.load_state_dict(torch.load(AUTOENCODER_WEIGHTS_PATH, weights_only=True, map_location="cpu"))
            model.eval()
            bundle["model_instance"] = model
            self.cached_models["autoencoder"] = bundle
            self.current_model_name = "autoencoder"
            logger.info("PyTorch Autoencoder loaded into predictor.")
            return bundle

        else:
            raise ValueError(f"Unknown model_type: {model_type}. Expected 'xgboost', 'random_forest', or 'autoencoder'.")

    def predict_dataframe(
        self,
        df: pd.DataFrame,
        model_type: str = "xgboost",
        filename: str = "network_traffic.csv"
    ) -> Dict[str, Any]:
        """
        Executes end-to-end inference over an incoming DataFrame.
        """
        start_time = time.time()
        bundle = self.load_model(model_type)
        
        # 1. Check for ground-truth Label column
        ground_truth_present = False
        y_true_raw = None
        for col in df.columns:
            if col.strip().lower() == TARGET_COLUMN.lower():
                ground_truth_present = True
                y_true_raw = df[col].astype(str).str.strip()
                break

        # 2. Schema Validation
        val_report = validate_dataset_schema(df)
        if not val_report["is_valid"]:
            # If some features are missing, explain them clearly
            logger.warning(f"Dataset schema warning: {val_report['issues']}")

        # 3. Preprocessing Transformation
        preprocessor: CyberSentinelPreprocessor = bundle["preprocessor"]
        X_scaled = preprocessor.transform(df)
        
        # 4. Model Prediction
        confidence_scores: Optional[np.ndarray] = None
        
        if model_type in ["xgboost", "random_forest"]:
            model = bundle["model"]
            le = bundle["label_encoder"]
            y_pred_encoded = model.predict(X_scaled)
            
            # Predict probabilities if supported
            if hasattr(model, "predict_proba"):
                try:
                    proba = model.predict_proba(X_scaled)
                    confidence_scores = np.max(proba, axis=1)
                except Exception:
                    confidence_scores = np.ones(len(X_scaled))
            else:
                confidence_scores = np.ones(len(X_scaled))
                
            predicted_labels = le.inverse_transform(y_pred_encoded)
            is_suspicious = np.array([label.upper() != "BENIGN" for label in predicted_labels])

        elif model_type == "autoencoder":
            model = bundle["model_instance"]
            threshold = bundle["anomaly_threshold"]
            
            with torch.no_grad():
                inputs = torch.tensor(X_scaled, dtype=torch.float32)
                outputs = model(inputs)
                mse_errors = torch.mean((inputs - outputs) ** 2, dim=1).numpy()
                
            is_suspicious = mse_errors > threshold
            predicted_labels = np.where(is_suspicious, "ANOMALY", "BENIGN")
            # Normalised anomaly score between 0 and 1
            confidence_scores = np.clip(mse_errors / (threshold * 2), 0.0, 1.0)

        inference_duration = time.time() - start_time
        records_per_sec = int(len(df) / max(inference_duration, 1e-4))
        
        # 5. Build Result DataFrame
        result_df = df.copy()
        result_df["Predicted_Threat"] = predicted_labels
        result_df["Confidence_Score"] = np.round(confidence_scores, 4)
        result_df["Is_Suspicious"] = is_suspicious

        # 6. Compute Aggregates
        total_records = len(df)
        suspicious_count = int(np.sum(is_suspicious))
        benign_count = total_records - suspicious_count
        
        threat_distribution = {}
        for threat, count in pd.Series(predicted_labels).value_counts().items():
            threat_distribution[str(threat)] = int(count)

        # 7. Generate Cybersecurity Explanations for Detected Threat Groups
        explanations = []
        for threat, count in threat_distribution.items():
            if threat.upper() != "BENIGN":
                avg_conf = float(result_df[result_df["Predicted_Threat"] == threat]["Confidence_Score"].mean())
                exp = get_threat_explanation(
                    threat_category=threat,
                    record_count=count,
                    confidence_score=avg_conf,
                    filename=filename
                )
                explanations.append(exp)

        # 8. Ground-truth evaluation if labels were supplied
        ground_truth_metrics = None
        if ground_truth_present and y_true_raw is not None:
            from sklearn.metrics import accuracy_score, precision_recall_fscore_support
            
            if model_type == "autoencoder":
                y_true_bin = np.where(y_true_raw.str.upper() == "BENIGN", "BENIGN", "ANOMALY")
                y_pred_str = predicted_labels
            else:
                y_true_bin = y_true_raw
                y_pred_str = predicted_labels

            acc = accuracy_score(y_true_bin, y_pred_str)
            p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(
                y_true_bin, y_pred_str, average="macro", zero_division=0
            )
            ground_truth_metrics = {
                "accuracy": round(float(acc), 4),
                "precision_macro": round(float(p_macro), 4),
                "recall_macro": round(float(r_macro), 4),
                "f1_macro": round(float(f1_macro), 4),
            }

        return {
            "model_name": bundle["model_name"],
            "model_type": model_type,
            "filename": filename,
            "total_records": total_records,
            "benign_records": benign_count,
            "suspicious_records": suspicious_count,
            "threat_distribution": threat_distribution,
            "inference_duration_seconds": round(inference_duration, 3),
            "records_per_second": records_per_sec,
            "has_ground_truth": ground_truth_present,
            "ground_truth_metrics": ground_truth_metrics,
            "explanations": explanations,
            "result_dataframe": result_df,
            "validation_report": val_report
        }
