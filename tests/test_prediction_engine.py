"""
Unit Tests for CyberSentinel Prediction Engine and Cybersecurity Analysis Layer.
"""
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import pandas as pd
from src.detection.predictor import CyberSentinelPredictor
from src.data.loader import load_dataset


def test_prediction_engine_benign():
    predictor = CyberSentinelPredictor()
    demo_benign = BASE_DIR / "dataset" / "raw" / "demo_benign_traffic.csv"
    df = load_dataset(demo_benign)
    
    # Run XGBoost inference
    res = predictor.predict_dataframe(df, model_type="xgboost", filename="demo_benign_traffic.csv")
    assert res["total_records"] == len(df)
    assert res["benign_records"] > res["suspicious_records"]
    assert "BENIGN" in res["threat_distribution"]
    print(f"test_prediction_engine_benign PASSED (Benign: {res['benign_records']}, Suspicious: {res['suspicious_records']})")


def test_prediction_engine_attacks():
    predictor = CyberSentinelPredictor()
    demo_attack = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(demo_attack)
    
    # Run Random Forest inference
    res = predictor.predict_dataframe(df, model_type="random_forest", filename="demo_attack_traffic.csv")
    assert res["total_records"] == len(df)
    assert res["suspicious_records"] > 0
    assert len(res["explanations"]) > 0
    
    # Check explanations have required grounded fields
    first_exp = res["explanations"][0]
    assert "threat_category" in first_exp
    assert "description" in first_exp
    assert "relevant_features" in first_exp
    assert "suggested_investigation_steps" in first_exp
    print(f"test_prediction_engine_attacks PASSED (Detected threats: {list(res['threat_distribution'].keys())})")


def test_autoencoder_anomaly_prediction():
    predictor = CyberSentinelPredictor()
    demo_attack = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(demo_attack)
    
    res = predictor.predict_dataframe(df, model_type="autoencoder", filename="demo_attack_traffic.csv")
    assert res["total_records"] == len(df)
    assert "ANOMALY" in res["threat_distribution"] or "BENIGN" in res["threat_distribution"]
    print("test_autoencoder_anomaly_prediction PASSED")


if __name__ == "__main__":
    test_prediction_engine_benign()
    test_prediction_engine_attacks()
    test_autoencoder_anomaly_prediction()
    print("\nALL PREDICTION ENGINE TESTS PASSED!")
