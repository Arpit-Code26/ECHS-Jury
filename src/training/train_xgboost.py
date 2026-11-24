"""
XGBoost Advanced Tabular Training Pipeline.
Features native cross-platform JSON export, multiclass probability estimation,
and automatic Scikit-learn HistGradientBoosting fallback for constrained edge setups.
"""
import sys
import time
from pathlib import Path
from typing import Dict, Any, Tuple

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
import joblib

from config.settings import XGB_BUNDLE_PATH, XGB_MODEL_JSON_PATH, RANDOM_SEED
from config.model_config import XGBOOST_PARAMS, HIST_GB_PARAMS, TARGET_COLUMN
from src.data.loader import load_dataset
from src.data.preprocessing import CyberSentinelPreprocessor, prepare_labels
from src.utils.logging_config import logger


def train_xgboost(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame,
    mode: str = "multiclass"
) -> Dict[str, Any]:
    """
    Trains XGBoost or HistGradientBoosting fallback and evaluates on test set.
    """
    logger.info(f"Initiating XGBoost training (mode={mode})...")
    start_time = time.time()
    
    # 1. Fit Preprocessor strictly on training data
    preprocessor = CyberSentinelPreprocessor()
    X_train = preprocessor.fit_transform(train_df)
    X_test = preprocessor.transform(test_df)
    
    # 2. Prepare labels
    y_train_bin, y_train_multi, le = prepare_labels(train_df[TARGET_COLUMN])
    y_test_bin, y_test_multi, _ = prepare_labels(test_df[TARGET_COLUMN])
    
    y_train = y_train_multi if mode == "multiclass" else y_train_bin
    y_test = y_test_multi if mode == "multiclass" else y_test_bin
    
    is_fallback = False
    model = None
    
    try:
        import xgboost as xgb
        logger.info("Using native XGBoost engine.")
        xgb_params = XGBOOST_PARAMS.copy()
        if mode == "multiclass":
            xgb_params["objective"] = "multi:softprob"
            xgb_params["num_class"] = len(le.classes_)
            xgb_params["eval_metric"] = "mlogloss"
        else:
            xgb_params["objective"] = "binary:logistic"
            xgb_params["eval_metric"] = "logloss"
            
        model = xgb.XGBClassifier(**xgb_params)
        model.fit(X_train, y_train)
        
        # Save native cross-platform JSON model
        XGB_MODEL_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
        model.save_model(str(XGB_MODEL_JSON_PATH))
        logger.info(f"Native XGBoost JSON model saved to: {XGB_MODEL_JSON_PATH}")
        
    except (ImportError, Exception) as e:
        logger.warning(f"XGBoost unavailable or failed ({e}). Activating HistGradientBoosting fallback.")
        from sklearn.ensemble import HistGradientBoostingClassifier
        is_fallback = True
        model = HistGradientBoostingClassifier(**HIST_GB_PARAMS)
        model.fit(X_train, y_train)

    training_duration = time.time() - start_time
    
    # 3. Measure Inference Latency
    infer_start = time.time()
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    infer_duration = time.time() - infer_start
    latency_ms_per_1k = (infer_duration / max(len(X_test), 1)) * 1000 * 1000

    # 4. Evaluate Metrics
    acc = accuracy_score(y_test, y_pred)
    prec_macro, rec_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    prec_weighted, rec_weighted, f1_weighted, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
    
    target_names = list(le.classes_) if mode == "multiclass" else ["BENIGN", "ATTACK"]
    cls_report = classification_report(y_test, y_pred, target_names=target_names, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    # False Positive Rate
    if mode == "binary":
        tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
        fpr = round(fp / (fp + tn) if (fp + tn) > 0 else 0.0, 4)
    else:
        benign_idx = list(le.classes_).index("BENIGN") if "BENIGN" in le.classes_ else 0
        fp = sum(cm[i][benign_idx] for i in range(len(cm)) if i != benign_idx)
        tn = sum(cm[i][j] for i in range(len(cm)) for j in range(len(cm)) if i != benign_idx and j != benign_idx)
        fpr = round(fp / (fp + tn) if (fp + tn) > 0 else 0.0, 4)

    # Feature Importances
    sorted_importances = {}
    if hasattr(model, "feature_importances_"):
        feat_importances = dict(zip(preprocessor.fitted_feature_names_, model.feature_importances_))
        sorted_importances = dict(sorted(feat_importances.items(), key=lambda x: x[1], reverse=True)[:15])

    bundle = {
        "model_name": "XGBoost" if not is_fallback else "HistGradientBoosting (Fallback)",
        "is_fallback": is_fallback,
        "mode": mode,
        "model": model,
        "preprocessor": preprocessor,
        "label_encoder": le,
        "target_names": target_names,
        "training_duration_seconds": round(training_duration, 3),
        "inference_latency_ms_per_1k": round(latency_ms_per_1k, 3),
        "accuracy": round(acc, 4),
        "precision_macro": round(prec_macro, 4),
        "recall_macro": round(rec_macro, 4),
        "f1_macro": round(f1_macro, 4),
        "precision_weighted": round(prec_weighted, 4),
        "recall_weighted": round(rec_weighted, 4),
        "f1_weighted": round(f1_weighted, 4),
        "false_positive_rate": fpr,
        "confusion_matrix": cm,
        "classification_report": cls_report,
        "top_feature_importances": sorted_importances,
    }

    # Save Bundle
    XGB_BUNDLE_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, XGB_BUNDLE_PATH)
    logger.info(f"XGBoost bundle saved to {XGB_BUNDLE_PATH} (Accuracy={acc:.4f}, F1-Macro={f1_macro:.4f})")

    return bundle


if __name__ == "__main__":
    from config.settings import PROCESSED_DATA_DIR
    train_path = PROCESSED_DATA_DIR / "train_subset.csv"
    test_path = PROCESSED_DATA_DIR / "test_subset.csv"
    
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)
    res = train_xgboost(train_df, test_df, mode="multiclass")
    print(f"XGBoost Training Completed. Accuracy: {res['accuracy']}, F1: {res['f1_macro']}")
