"""
Unit Tests for Model Loading and Portability.
Verifies that serialized bundles (Random Forest, XGBoost, Autoencoder) load and predict accurately.
"""
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import joblib
import numpy as np
import pandas as pd
import torch

from config.settings import RF_BUNDLE_PATH, XGB_BUNDLE_PATH, AUTOENCODER_BUNDLE_PATH, AUTOENCODER_WEIGHTS_PATH
from src.data.loader import load_dataset
from src.training.train_autoencoder import CyberSentinelAutoencoder


def test_random_forest_bundle():
    assert RF_BUNDLE_PATH.exists(), "Random Forest bundle not found"
    bundle = joblib.load(RF_BUNDLE_PATH)
    assert "model" in bundle
    assert "preprocessor" in bundle
    assert "label_encoder" in bundle
    
    # Test sample inference
    demo_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(demo_csv, nrows=20)
    X = bundle["preprocessor"].transform(df)
    preds = bundle["model"].predict(X)
    assert len(preds) == 20
    print("test_random_forest_bundle PASSED")


def test_xgboost_bundle():
    assert XGB_BUNDLE_PATH.exists(), "XGBoost bundle not found"
    bundle = joblib.load(XGB_BUNDLE_PATH)
    assert "model" in bundle
    assert "preprocessor" in bundle
    
    demo_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(demo_csv, nrows=20)
    X = bundle["preprocessor"].transform(df)
    preds = bundle["model"].predict(X)
    assert len(preds) == 20
    print("test_xgboost_bundle PASSED")


def test_autoencoder_bundle():
    assert AUTOENCODER_BUNDLE_PATH.exists(), "Autoencoder bundle not found"
    assert AUTOENCODER_WEIGHTS_PATH.exists(), "Autoencoder weights not found"
    bundle = joblib.load(AUTOENCODER_BUNDLE_PATH)
    
    model = CyberSentinelAutoencoder(input_dim=bundle["input_dim"], latent_dim=bundle["latent_dim"])
    model.load_state_dict(torch.load(AUTOENCODER_WEIGHTS_PATH, weights_only=True))
    model.eval()
    
    demo_csv = BASE_DIR / "dataset" / "raw" / "demo_benign_traffic.csv"
    df = load_dataset(demo_csv, nrows=20)
    X = bundle["preprocessor"].transform(df)
    with torch.no_grad():
        inputs = torch.tensor(X, dtype=torch.float32)
        outputs = model(inputs)
        mse = torch.mean((inputs - outputs) ** 2, dim=1).numpy()
    assert len(mse) == 20
    print("test_autoencoder_bundle PASSED")


if __name__ == "__main__":
    test_random_forest_bundle()
    test_xgboost_bundle()
    test_autoencoder_bundle()
    print("\nALL MODEL PIPELINE TESTS PASSED!")
