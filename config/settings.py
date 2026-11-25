"""
Global Settings and Path Configurations for CyberSentinel.
"""
import os
from pathlib import Path
from src.utils.paths import (
    BASE_DIR,
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    TRAINED_MODELS_DIR,
    REPORTS_DIR,
    DASHBOARD_DIR,
    ensure_directories_exist
)

# Ensure runtime directories are created
ensure_directories_exist()

# App Metadata
APP_NAME = "CyberSentinel"
APP_TITLE = "CYBERSENTINEL: Cross-Platform Edge AI Network Intrusion Detection"
APP_SUBTITLE = "AI-Powered Network Intrusion Detection & Intelligent Security Assistant"
VERSION = "1.0.0"

# Random Seed for Reproducibility
RANDOM_SEED = 42

# Data Processing Settings
CHUNK_SIZE = 10000
DEFAULT_TEST_SIZE = 0.20
DEFAULT_VAL_SIZE = 0.10

# Inference Settings
INFERENCE_BATCH_SIZE = int(os.getenv("INFERENCE_BATCH_SIZE", "5000"))
MAX_DISPLAY_RECORDS = int(os.getenv("MAX_DISPLAY_RECORDS", "500"))

# Ollama LLM Settings
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:0.5b")
OLLAMA_TIMEOUT_SECONDS = int(os.getenv("OLLAMA_TIMEOUT_SECONDS", "15"))

# Model Bundle File Paths
RF_BUNDLE_PATH = TRAINED_MODELS_DIR / "random_forest_bundle.joblib"
XGB_BUNDLE_PATH = TRAINED_MODELS_DIR / "xgboost_bundle.joblib"
XGB_MODEL_JSON_PATH = TRAINED_MODELS_DIR / "xgboost_model.json"
AUTOENCODER_BUNDLE_PATH = TRAINED_MODELS_DIR / "autoencoder_bundle.joblib"
AUTOENCODER_WEIGHTS_PATH = TRAINED_MODELS_DIR / "autoencoder_weights.pt"
METRICS_SUMMARY_PATH = REPORTS_DIR / "model_comparison_metrics.json"
DATASET_MANIFEST_PATH = PROCESSED_DATA_DIR / "dataset_manifest.json"
