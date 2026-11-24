"""
Model Configurations, Feature Schemas, and Hyperparameters.
"""
from typing import List, Dict, Any

# Primary Target Column
TARGET_COLUMN = "Label"

# Non-predictive or data-leakage columns that MUST be dropped from features
COLUMNS_TO_DROP = [
    "Flow ID",
    "Source IP",
    "Src IP",
    "Destination IP",
    "Dst IP",
    "Timestamp",
    "Source Port",
    "Src Port",
    "Unnamed: 0",
    "Flow_ID",
]

# Standard Canonical 40-feature subset derived from CIC-IDS2017
# These represent network flow statistics rather than identity attributes
CANONICAL_FEATURES: List[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Core attack labels supported in CyberSentinel
LABEL_MAPPING: Dict[str, str] = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS Hulk",
    "PortScan": "PortScan",
    "FTP-Patator": "FTP-Patator",
    "SSH-Patator": "SSH-Patator",
    "DoS GoldenEye": "DoS GoldenEye",
    "DoS slowloris": "DoS slowloris",
    "Bot": "Bot",
}

# Binary classification label mapping
BINARY_LABEL_BENIGN = "BENIGN"
BINARY_LABEL_ATTACK = "ATTACK"

# Random Forest Hyperparameters
RANDOM_FOREST_PARAMS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 16,
    "min_samples_split": 5,
    "min_samples_leaf": 2,
    "n_jobs": -1,
    "random_state": 42,
    "class_weight": "balanced",
}

# XGBoost Hyperparameters
XGBOOST_PARAMS: Dict[str, Any] = {
    "n_estimators": 100,
    "max_depth": 6,
    "learning_rate": 0.1,
    "subsample": 0.8,
    "colsample_bytree": 0.8,
    "random_state": 42,
    "n_jobs": -1,
    "tree_method": "hist",
}

# Scikit-learn HistGradientBoosting Fallback (for Jetson if XGBoost is absent)
HIST_GB_PARAMS: Dict[str, Any] = {
    "max_iter": 100,
    "max_depth": 8,
    "learning_rate": 0.1,
    "random_state": 42,
}

# PyTorch Deep Learning Autoencoder Hyperparameters
AUTOENCODER_CONFIG: Dict[str, Any] = {
    "latent_dim": 16,
    "hidden_layers": [48, 24],
    "learning_rate": 0.001,
    "batch_size": 128,
    "epochs": 15,
    "weight_decay": 1e-5,
    "threshold_percentile": 98.0,  # 98th percentile of reconstruction error on benign val set
}
