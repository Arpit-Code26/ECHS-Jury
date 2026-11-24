"""
Cross-platform Path Management using pathlib.
Ensures identical directory handling across Windows 11 and Jetson Linux.
"""
from pathlib import Path
import os

# Root directory of the CyberSentinel project
BASE_DIR = Path(__file__).resolve().parent.parent.parent

# Core project directories
CONFIG_DIR = BASE_DIR / "config"
DATASET_DIR = BASE_DIR / "dataset"
RAW_DATA_DIR = DATASET_DIR / "raw"
PROCESSED_DATA_DIR = DATASET_DIR / "processed"

MODELS_DIR = BASE_DIR / "models"
TRAINED_MODELS_DIR = MODELS_DIR / "trained"
CHECKPOINTS_DIR = MODELS_DIR / "checkpoints"

REPORTS_DIR = BASE_DIR / "reports"
TESTS_DIR = BASE_DIR / "tests"
DASHBOARD_DIR = BASE_DIR / "dashboard"
COMPONENTS_DIR = DASHBOARD_DIR / "components"


def ensure_directories_exist() -> None:
    """Ensure all required runtime directories exist."""
    dirs_to_create = [
        CONFIG_DIR,
        DATASET_DIR,
        RAW_DATA_DIR,
        PROCESSED_DATA_DIR,
        MODELS_DIR,
        TRAINED_MODELS_DIR,
        CHECKPOINTS_DIR,
        REPORTS_DIR,
        TESTS_DIR,
        DASHBOARD_DIR,
        COMPONENTS_DIR,
    ]
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)


if __name__ == "__main__":
    ensure_directories_exist()
    print("Project directory structure verified at:", BASE_DIR)
