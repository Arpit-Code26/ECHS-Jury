# CYBERSENTINEL: WINDOWS 11 DEPLOYMENT GUIDE

## 1. System Requirements
- **Operating System:** Windows 11 (64-bit AMD64)
- **Processor:** Intel Core i5 (13th Gen or equivalent, 4+ cores)
- **Memory (RAM):** 8 GB minimum (16 GB recommended)
- **Storage:** At least 5 GB free disk space
- **GPU:** Optional. The entire pipeline executes CPU-optimized multithreading out-of-the-box.
- **Python:** Python 3.10 – 3.14 (Verified on Python 3.14 and 3.12)

---

## 2. Installation Steps (PowerShell)

### Step 1: Open Terminal & Clone/Open Directory
Open PowerShell in the project root:
```powershell
cd "c:\Users\ARPIT NAINWAL\OneDrive\Desktop\ECHS"
```

### Step 2: Create and Activate Virtual Environment
```powershell
# Create virtual environment
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1
```
*(Note: If script execution is restricted, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

### Step 3: Install Required Dependencies
Install common dependencies, Windows CPU wheels, and Streamlit:
```powershell
python -m pip install --upgrade pip
python -m pip install -r requirements/requirements-windows.txt
```

Verify installed packages:
```powershell
python -c "import numpy, pandas, sklearn, xgboost, torch, streamlit, plotly; print('All core libraries verified!')"
```

---

## 3. Local Ollama LLM Setup (Optional but Recommended)

CyberSentinel works 100% offline. If Ollama is not installed or running, CyberSentinel automatically uses its built-in rule-grounded expert security engine without crashing.

To enable the local LLM:
1. Download Ollama for Windows from https://ollama.com/download.
2. Install and launch Ollama.
3. Open a separate PowerShell window and pull the lightweight model:
   ```powershell
   ollama pull qwen2.5:1.5b
   ```
4. Verify Ollama is serving requests:
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:11434/api/tags"
   ```

---

## 4. Model Training & Evaluation
To train all three models (Random Forest baseline, XGBoost advanced classifier, and PyTorch Autoencoder anomaly detector):
```powershell
# Ensure synthetic or real CIC-IDS2017 slices exist
python src/data/dataset_generator.py

# Run full training and benchmark pipeline
python scripts/train_all.py
```
This saves trained bundles into `models/trained/` and writes `reports/model_comparison_metrics.json`.

---

## 5. Launching the CyberSentinel SOC Dashboard
Run the application using Streamlit:
```powershell
python -m streamlit run dashboard/app.py
```
Or via the launcher script:
```powershell
python scripts/run_app.py
```

The SOC dashboard will automatically open in your default browser at:
**http://localhost:8501**

---

## 6. Running Unit & Integration Tests
To verify all components before demonstration:
```powershell
python tests/test_data_pipeline.py
python tests/test_model_pipeline.py
python tests/test_prediction_engine.py
python tests/test_end_to_end.py
```

---

## 7. Troubleshooting Windows Deployment
| Issue | Cause | Resolution |
| :--- | :--- | :--- |
| `Cannot find module 'config'` | Current directory is not in `PYTHONPATH` | Run commands from the project root directory. |
| `WinError 10013: socket access forbidden` | Sandbox or local port conflict | Ensure no other service occupies port 8501 or 11434. |
| Ollama shows Offline | `ollama serve` is not running | Run `ollama serve` in a background terminal. Core IDS continues operating regardless. |
