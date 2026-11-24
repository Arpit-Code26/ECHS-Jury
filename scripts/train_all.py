"""
Master Training Runner for CyberSentinel.
Orchestrates end-to-end model training for Random Forest, XGBoost, and Autoencoder.
"""
import sys
import time
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config.settings import PROCESSED_DATA_DIR
from src.data.loader import load_dataset
from src.training.train_random_forest import train_random_forest
from src.training.train_xgboost import train_xgboost
from src.training.train_autoencoder import train_autoencoder
from src.training.evaluate import generate_benchmark_report
from src.utils.logging_config import logger


def run_training_pipeline():
    print("=" * 70)
    print("CYBERSENTINEL: INITIATING FULL MODEL TRAINING & BENCHMARKING")
    print("=" * 70)
    
    train_path = PROCESSED_DATA_DIR / "train_subset.csv"
    test_path = PROCESSED_DATA_DIR / "test_subset.csv"
    
    if not train_path.exists() or not test_path.exists():
        logger.error(f"Datasets not found in {PROCESSED_DATA_DIR}. Please run dataset_generator.py first.")
        sys.exit(1)
        
    logger.info(f"Loading training data from: {train_path}")
    train_df = load_dataset(train_path)
    logger.info(f"Loaded {len(train_df)} training records.")
    
    logger.info(f"Loading test data from: {test_path}")
    test_df = load_dataset(test_path)
    logger.info(f"Loaded {len(test_df)} test records.")
    
    # 1. Train Random Forest (Baseline Multiclass)
    print("\n--- Training Model 1: Random Forest ---")
    rf_res = train_random_forest(train_df, test_df, mode="multiclass")
    print(f"Random Forest finished in {rf_res['training_duration_seconds']}s. "
          f"Accuracy: {rf_res['accuracy']:.4f}, Macro-F1: {rf_res['f1_macro']:.4f}")
          
    # 2. Train XGBoost (Advanced Multiclass Tabular)
    print("\n--- Training Model 2: XGBoost ---")
    xgb_res = train_xgboost(train_df, test_df, mode="multiclass")
    print(f"XGBoost finished in {xgb_res['training_duration_seconds']}s. "
          f"Accuracy: {xgb_res['accuracy']:.4f}, Macro-F1: {xgb_res['f1_macro']:.4f}")
          
    # 3. Train PyTorch Autoencoder (Unsupervised Anomaly Detection)
    print("\n--- Training Model 3: PyTorch Autoencoder ---")
    ae_res = train_autoencoder(train_df, test_df)
    if "error" not in ae_res:
        print(f"Autoencoder finished in {ae_res['training_duration_seconds']}s. "
              f"Accuracy: {ae_res['accuracy']:.4f}, Anomaly Threshold: {ae_res['anomaly_threshold']:.6f}")
    else:
        print(f"Autoencoder skipped: {ae_res['error']}")
        
    # 4. Generate Consolidated Benchmark Report
    print("\n--- Generating Consolidated Performance Report ---")
    summary = generate_benchmark_report()
    print("Training pipeline completed successfully! Models ready for prediction.")


if __name__ == "__main__":
    run_training_pipeline()
