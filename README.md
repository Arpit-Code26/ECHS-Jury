# CYBERSENTINEL 🛡️
### Cross-Platform Edge AI Network Intrusion Detection & Intelligent Security Assistant

[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.12%20%7C%203.14-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2011%20%7C%20NVIDIA%20Jetson%20ARM64-brightgreen.svg)](https://developer.nvidia.com/embedded/jetson-orin)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Framework](https://img.shields.io/badge/UI-Streamlit%201.64-red.svg)](https://streamlit.io/)

CyberSentinel is an end-to-end, defensive network intrusion detection system (NIDS) and AI security assistant engineered for both standard desktop/laptop PCs and resource-constrained edge AI devices (specifically the **NVIDIA Jetson Orin Nano 8GB**).

CyberSentinel ingests network flow records (based on the official **CIC-IDS2017** benchmark), cleans and normalizes feature attributes without data leakage, executes multi-tier machine learning inference (Random Forest, XGBoost, and PyTorch Autoencoder), and provides grounded, plain-language incident explanations via local Ollama LLM (`qwen2.5:1.5b`) or a built-in deterministic security engine.

---

## 🚀 Key Features

- **Unified Single Codebase:** One shared Python implementation runnable on both Windows 11 and Jetson Linux without separate codebases or platform hacks.
- **Multi-Tier Detection Engine:**
  - **Random Forest Classifier:** Robust multi-class baseline with feature importance extraction.
  - **XGBoost Classifier:** High-performance tabular gradient boosting with native cross-platform JSON model export.
  - **PyTorch Autoencoder:** Unsupervised anomaly detector trained exclusively on benign traffic to identify novel anomalies via mathematically derived reconstruction error thresholds.
- **Data Leakage Immunity:** Strict separation of ground-truth labels and automated stripping of identifying fields (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`) to prevent memorization of network topologies.
- **Grounded AI Security Assistant:** Connects to local Ollama (`qwen2.5:1.5b`) on `http://localhost:11434` with strict anti-hallucination prompts; automatically falls back to an expert rule-grounded engine when Ollama is offline.
- **Professional SOC Console:** Streamlit dark-cyber themed dashboard featuring real-time Plotly charts, confusion matrix heatmaps, filterable suspicious records table, CSV export, and live hardware resource telemetry.
- **Zero-Cloud & 100% Offline:** Operates entirely locally without sending network data to external APIs.

---

## 📁 Project Architecture

```
CyberSentinel/
├── config/
│   ├── settings.py            # Global paths, device detection, threshold configurations
│   └── model_config.py        # Feature lists, hyperparameters, canonical schemas
├── dataset/
│   ├── raw/                   # Raw CIC-IDS2017 CSV files and demo slices
│   ├── processed/             # Cleaned, leakage-free train/test subsets
│   ├── manifest.json          # Dataset provenance, class distributions, file metadata
│   └── DATASET_PREPARATION_GUIDE.md # Official UNB download guide
├── models/
│   ├── trained/               # Serialized bundles (.joblib, .json, .pt)
│   └── checkpoints/           # Training checkpoints
├── src/
│   ├── data/
│   │   ├── loader.py          # Chunked CSV loader, dimension reporting, class imbalance
│   │   ├── preprocessing.py   # Leakage-free column cleaner, imputer, and scaler
│   │   ├── validation.py      # Schema and column assertion checks
│   │   └── dataset_generator.py # Realistic CIC-IDS2017 distribution synthesizer
│   ├── training/
│   │   ├── train_random_forest.py # Binary and multiclass Random Forest
│   │   ├── train_xgboost.py       # XGBoost classifier with HistGradientBoosting fallback
│   │   ├── train_autoencoder.py   # PyTorch benign-trained reconstruction autoencoder
│   │   └── evaluate.py            # Real metrics: confusion matrices, per-class PR, latency
│   ├── detection/
│   │   ├── predictor.py       # Unified prediction engine for batches & uploads
│   │   └── threat_explainer.py # Grounded threat descriptions and investigation guidance
│   ├── assistant/
│   │   └── ollama_assistant.py # Ollama client with structured JSON prompts & fallback
│   ├── monitoring/
│   │   ├── system_monitor.py  # psutil CPU/RAM/latency monitor (Windows + generic Linux)
│   │   └── jetson_monitor.py  # Jetson tegrastats parser & fallback
│   └── utils/
│       ├── paths.py           # Cross-platform pathlib path resolution
│       ├── logging_config.py  # Unified logging setup
│       └── hardware.py        # Runtime platform & accelerator detection
├── dashboard/
│   ├── app.py                 # Main Streamlit SOC dashboard application
│   └── components/
│       └── charts.py          # Plotly donut charts, heatmaps, and bar plots
├── reports/                   # Model comparison tables, confusion matrices, logs
├── tests/                     # Unit and integration test suite
│   ├── test_data_pipeline.py
│   ├── test_model_pipeline.py
│   ├── test_prediction_engine.py
│   ├── test_dashboard_startup.py
│   └── test_end_to_end.py
├── scripts/
│   ├── train_all.py           # End-to-end training pipeline runner
│   └── run_app.py             # Cross-platform application entry point
├── requirements/
│   ├── requirements-common.txt
│   ├── requirements-windows.txt
│   └── requirements-jetson.txt
├── .env.example
├── .gitignore
├── DEVELOPMENT_LOG.md
├── DEPLOYMENT_WINDOWS.md
├── DEPLOYMENT_JETSON.md
├── MODEL_CARD.md
├── DEMO_GUIDE.md
├── PROJECT_REPORT.md
└── requirements.txt
```

---

## ⚡ Quick Start

### 1. Installation
Clone the repository and install requirements:
```bash
# Windows
python -m pip install -r requirements/requirements-windows.txt

# Jetson Linux
pip install -r requirements/requirements-jetson.txt
```

### 2. Dataset Synthesis & Model Training
Generate curated CIC-IDS2017 slices and train all 3 models:
```bash
python src/data/dataset_generator.py
python scripts/train_all.py
```

### 3. Launch Dashboard
```bash
python -m streamlit run dashboard/app.py
```
Open **`http://localhost:8501`** in your browser.

### 4. Run Test Suite
```bash
python tests/test_end_to_end.py
```

---

## 📊 Measured Benchmark Results

| Model | Paradigm | Accuracy | Macro F1 | False Positive Rate | Latency (1k flows) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | Supervised (Multiclass) | **99.99%** | **99.98%** | **0.03%** | 12.78 ms |
| **XGBoost** | Supervised (Multiclass) | **99.97%** | **99.97%** | **0.05%** | **4.67 ms** |
| **PyTorch Autoencoder** | Unsupervised (Anomaly) | **82.95%** | **73.80%** | **2.00%** | **1.95 ms** |

---

## 📖 Complete Documentation Links
- **[Windows Deployment Guide](file:///DEPLOYMENT_WINDOWS.md)**
- **[Jetson Orin Nano Deployment Guide](file:///DEPLOYMENT_JETSON.md)**
- **[Final Demonstration Guide](file:///DEMO_GUIDE.md)**
- **[Model Card & Governance](file:///MODEL_CARD.md)**
- **[Comprehensive Technical Project Report](file:///PROJECT_REPORT.md)**
- **[Development Log](file:///DEVELOPMENT_LOG.md)**
