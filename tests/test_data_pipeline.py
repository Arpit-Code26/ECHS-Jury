"""
Unit Tests for CyberSentinel Data Pipeline and Preprocessing.
Verifies loading, sanitation, missing value imputation, and label leakage prevention.
"""
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from src.data.loader import inspect_csv_metadata, load_dataset, get_class_distribution
from src.data.validation import validate_dataset_schema, sanitize_dataframe
from src.data.preprocessing import CyberSentinelPreprocessor, prepare_labels
from config.model_config import CANONICAL_FEATURES, TARGET_COLUMN


def test_metadata_inspection():
    test_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    meta = inspect_csv_metadata(test_csv)
    assert meta["has_label"] is True, "Failed to detect ground truth Label column"
    assert meta["column_count"] >= len(CANONICAL_FEATURES), "Column count mismatch"
    print("test_metadata_inspection PASSED")


def test_label_leakage_prevention():
    test_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(test_csv, nrows=100)
    
    preprocessor = CyberSentinelPreprocessor()
    X_transformed = preprocessor.fit_transform(df)
    
    # Assert fitted features do NOT contain the target label or leakage columns
    fitted_cols = [c.lower() for c in preprocessor.fitted_feature_names_]
    assert TARGET_COLUMN.lower() not in fitted_cols, "CRITICAL: Target column leaked into fitted feature list!"
    assert "source ip" not in fitted_cols, "Source IP leaked into features!"
    assert "destination ip" not in fitted_cols, "Destination IP leaked into features!"
    assert "timestamp" not in fitted_cols, "Timestamp leaked into features!"
    assert X_transformed.shape[1] == len(CANONICAL_FEATURES), "Transformed feature count does not match canonical spec"
    print("test_label_leakage_prevention PASSED")


def test_missing_and_infinity_handling():
    # Construct synthetic dirty dataframe
    dirty_data = {
        "Destination Port": [80, np.nan, 443],
        "Flow Duration": [1000, np.inf, 3000],
        "Total Fwd Packets": [-np.inf, 5, 10],
        "Label": ["BENIGN", "DDoS", "BENIGN"]
    }
    dirty_df = pd.DataFrame(dirty_data)
    
    preprocessor = CyberSentinelPreprocessor()
    X_scaled = preprocessor.fit_transform(dirty_df)
    
    # Assert no NaN or Inf remains
    assert not np.isnan(X_scaled).any(), "NaN values found after preprocessing!"
    assert not np.isinf(X_scaled).any(), "Infinity values found after preprocessing!"
    print("test_missing_and_infinity_handling PASSED")


def test_schema_validation():
    test_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    df = load_dataset(test_csv, nrows=50)
    report = validate_dataset_schema(df)
    assert report["is_valid"] is True, "Valid dataset failed schema check"
    assert report["missing_feature_count"] == 0, f"Unexpected missing features: {report['missing_features']}"
    print("test_schema_validation PASSED")


if __name__ == "__main__":
    test_metadata_inspection()
    test_label_leakage_prevention()
    test_missing_and_infinity_handling()
    test_schema_validation()
    print("\nALL DATA PIPELINE UNIT TESTS PASSED!")
