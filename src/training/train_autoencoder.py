"""
PyTorch Deep Learning Autoencoder for Anomaly Detection.
Trained strictly on normal (BENIGN) traffic records.
Derives reconstruction error threshold from a held-out benign validation set.
"""
import sys
import time
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
import joblib

from config.settings import AUTOENCODER_BUNDLE_PATH, AUTOENCODER_WEIGHTS_PATH, RANDOM_SEED
from config.model_config import AUTOENCODER_CONFIG, TARGET_COLUMN
from src.data.loader import load_dataset
from src.data.preprocessing import CyberSentinelPreprocessor, prepare_labels
from src.utils.logging_config import logger

try:
    import torch
    import torch.nn as nn
    from torch.utils.data import DataLoader, TensorDataset
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


if HAS_TORCH:
    class CyberSentinelAutoencoder(nn.Module):
        """
        Symmetric Autoencoder for network flow feature reconstruction.
        """
        def __init__(self, input_dim: int, latent_dim: int = 16):
            super().__init__()
            self.input_dim = input_dim
            self.latent_dim = latent_dim
            
            # Encoder
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 48),
                nn.BatchNorm1d(48),
                nn.ReLU(),
                nn.Linear(48, 24),
                nn.BatchNorm1d(24),
                nn.ReLU(),
                nn.Linear(24, latent_dim),
            )
            
            # Decoder
            self.decoder = nn.Sequential(
                nn.Linear(latent_dim, 24),
                nn.BatchNorm1d(24),
                nn.ReLU(),
                nn.Linear(24, 48),
                nn.BatchNorm1d(48),
                nn.ReLU(),
                nn.Linear(48, input_dim),
            )

        def forward(self, x):
            z = self.encoder(x)
            x_rec = self.decoder(z)
            return x_rec
else:
    class CyberSentinelAutoencoder:
        pass


def train_autoencoder(
    train_df: pd.DataFrame,
    test_df: pd.DataFrame
) -> Dict[str, Any]:
    """
    Trains Autoencoder on benign network traffic and computes threshold on benign validation split.
    """
    if not HAS_TORCH:
        logger.warning("PyTorch is not available. Autoencoder training skipped.")
        return {"error": "PyTorch not installed on this environment."}

    logger.info("Initiating PyTorch Deep Learning Autoencoder training on BENIGN flows...")
    start_time = time.time()
    
    # 1. Filter benign records for training
    benign_mask = train_df[TARGET_COLUMN].astype(str).str.strip().str.upper() == "BENIGN"
    train_benign_df = train_df[benign_mask].copy()
    
    # Split into train-benign and validation-benign for threshold calculation
    train_b, val_b = train_test_split(train_benign_df, test_size=0.15, random_state=RANDOM_SEED)
    
    # 2. Fit Preprocessor on benign training data
    preprocessor = CyberSentinelPreprocessor()
    X_train_b = preprocessor.fit_transform(train_b)
    X_val_b = preprocessor.transform(val_b)
    X_test = preprocessor.transform(test_df)
    
    # 3. PyTorch DataLoaders
    torch.manual_seed(RANDOM_SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Autoencoder running on device: {device}")
    
    input_dim = X_train_b.shape[1]
    model = CyberSentinelAutoencoder(input_dim=input_dim, latent_dim=AUTOENCODER_CONFIG["latent_dim"]).to(device)
    
    train_dataset = TensorDataset(torch.tensor(X_train_b, dtype=torch.float32))
    train_loader = DataLoader(train_dataset, batch_size=AUTOENCODER_CONFIG["batch_size"], shuffle=True)
    
    criterion = nn.MSELoss()
    optimizer = torch.optim.Adam(
        model.parameters(),
        lr=AUTOENCODER_CONFIG["learning_rate"],
        weight_decay=AUTOENCODER_CONFIG["weight_decay"]
    )
    
    # 4. Training Loop
    model.train()
    epochs = AUTOENCODER_CONFIG["epochs"]
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for batch in train_loader:
            inputs = batch[0].to(device)
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, inputs)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(inputs)
            
        epoch_loss = total_loss / len(train_dataset)
        if epoch % 5 == 0 or epoch == epochs:
            logger.info(f"Epoch [{epoch}/{epochs}] - Reconstruction MSE Loss: {epoch_loss:.6f}")

    training_duration = time.time() - start_time
    
    # 5. Derive Anomaly Threshold on Held-Out Benign Validation Set
    model.eval()
    with torch.no_grad():
        val_inputs = torch.tensor(X_val_b, dtype=torch.float32).to(device)
        val_recs = model(val_inputs)
        val_errors = torch.mean((val_inputs - val_recs) ** 2, dim=1).cpu().numpy()
        
    threshold_pct = AUTOENCODER_CONFIG["threshold_percentile"]
    anomaly_threshold = float(np.percentile(val_errors, threshold_pct))
    logger.info(f"Derived Anomaly Reconstruction Threshold ({threshold_pct}th percentile): {anomaly_threshold:.6f}")
    
    # 6. Evaluate on Test Set
    infer_start = time.time()
    with torch.no_grad():
        test_inputs = torch.tensor(X_test, dtype=torch.float32).to(device)
        test_recs = model(test_inputs)
        test_errors = torch.mean((test_inputs - test_recs) ** 2, dim=1).cpu().numpy()
    infer_duration = time.time() - infer_start
    latency_ms_per_1k = (infer_duration / max(len(X_test), 1)) * 1000 * 1000
    
    # Prediction: 0 = BENIGN, 1 = ATTACK / ANOMALY
    y_pred_bin = np.where(test_errors > anomaly_threshold, 1, 0)
    y_test_bin, _, _ = prepare_labels(test_df[TARGET_COLUMN])
    
    acc = accuracy_score(y_test_bin, y_pred_bin)
    prec, rec, f1, _ = precision_recall_fscore_support(y_test_bin, y_pred_bin, average="binary", zero_division=0)
    cm = confusion_matrix(y_test_bin, y_pred_bin).tolist()
    tn, fp, fn, tp = confusion_matrix(y_test_bin, y_pred_bin).ravel()
    fpr = round(fp / (fp + tn) if (fp + tn) > 0 else 0.0, 4)
    
    cls_report = classification_report(
        y_test_bin,
        y_pred_bin,
        target_names=["BENIGN", "ANOMALY (ATTACK)"],
        output_dict=True,
        zero_division=0
    )

    # 7. Save State Dict and Bundle
    AUTOENCODER_WEIGHTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), AUTOENCODER_WEIGHTS_PATH)
    
    bundle = {
        "model_name": "Deep Learning Autoencoder",
        "mode": "anomaly_detection",
        "input_dim": input_dim,
        "latent_dim": AUTOENCODER_CONFIG["latent_dim"],
        "anomaly_threshold": anomaly_threshold,
        "threshold_percentile": threshold_pct,
        "preprocessor": preprocessor,
        "weights_path": str(AUTOENCODER_WEIGHTS_PATH),
        "training_duration_seconds": round(training_duration, 3),
        "inference_latency_ms_per_1k": round(latency_ms_per_1k, 3),
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": fpr,
        "confusion_matrix": cm,
        "classification_report": cls_report,
    }
    
    joblib.dump(bundle, AUTOENCODER_BUNDLE_PATH)
    logger.info(f"Autoencoder bundle saved to {AUTOENCODER_BUNDLE_PATH} (Accuracy={acc:.4f}, Recall={rec:.4f})")
    
    return bundle


if __name__ == "__main__":
    from config.settings import PROCESSED_DATA_DIR
    train_path = PROCESSED_DATA_DIR / "train_subset.csv"
    test_path = PROCESSED_DATA_DIR / "test_subset.csv"
    
    train_df = load_dataset(train_path)
    test_df = load_dataset(test_path)
    res = train_autoencoder(train_df, test_df)
    print(f"Autoencoder Training Completed. Accuracy: {res.get('accuracy')}, Threshold: {res.get('anomaly_threshold')}")
