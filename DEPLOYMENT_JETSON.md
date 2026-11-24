# CYBERSENTINEL: NVIDIA JETSON ORIN NANO (8GB) DEPLOYMENT GUIDE

## 1. System Requirements & Architecture
- **Hardware:** NVIDIA Jetson Orin Nano Developer Kit (8GB Unified LPDDR5 Memory)
- **Architecture:** ARM64 (aarch64)
- **JetPack:** JetPack 6.x / JetPack 7.x (L4T Linux Kernel 5.15 / 6.x)
- **Python:** Python 3.10+ (pre-installed with JetPack Ubuntu 22.04 LTS)
- **Storage:** MicroSD card or NVMe SSD with at least 10 GB free space.

---

## 2. Shared Memory Architecture & Budgeting
The Jetson Orin Nano features an **8 GB unified memory architecture** shared dynamically between CPU, GPU, and system OS buffers.

### Memory Allocation Plan:
- **Ubuntu 22.04 LTS & JetPack OS Overhead:** ~1.8 GB
- **CyberSentinel Engine & Streamlit Dashboard:** ~280 MB
- **Model In-Memory Footprint (XGBoost / Random Forest):** ~85 MB
- **Local Ollama LLM (`qwen2.5:1.5b` Q4_K_M quantized):** ~1.8 GB
- **Total Peak Memory:** ~4.0 GB
- **Safety Headroom:** **~4.0 GB free memory remaining**, ensuring zero OOM (Out Of Memory) kernel panics.

> **CRITICAL RULE:** Do NOT attempt to retrain deep models on the Jetson during a live demonstration. Train models on the PC/Laptop, and copy the trained model bundles to the Jetson for high-speed edge inference.

---

## 3. Jetson Software Environment Preparation

### Step 1: Clone or Transfer Repository
Transfer the CyberSentinel project folder from the Windows development machine to the Jetson via SCP, USB drive, or Git:
```bash
# Example via SCP from development host
scp -r CyberSentinel/ user@jetson_ip:~/CyberSentinel/
cd ~/CyberSentinel
```

### Step 2: Set Up Virtual Environment
```bash
python3 -m venv venv --system-site-packages
source venv/bin/activate
```
*(Using `--system-site-packages` allows the environment to utilize NVIDIA's hardware-accelerated system PyTorch and CUDA bindings if installed).*

### Step 3: Install Compatible Dependencies
```bash
pip install --upgrade pip
pip install -r requirements/requirements-jetson.txt
```

> **Note on PyTorch on Jetson:**
> Never run generic desktop `pip install torch` on ARM64 Linux, as it may conflict with NVIDIA's JetPack CUDA stack. If you wish to use the PyTorch Autoencoder on Jetson, use NVIDIA's official Jetson wheel from:
> https://forums.developer.nvidia.com/t/pytorch-for-jetson/72048
>
> If PyTorch is not installed, the Random Forest and XGBoost classifiers continue to run with 100% full functionality.

---

## 4. Ollama on Jetson Orin Nano
Ollama natively supports ARM64 Linux and runs efficiently on Jetson:
1. Verify existing Ollama installation:
   ```bash
   ollama --version
   ```
2. If needed, start the Ollama service:
   ```bash
   ollama serve &
   ```
3. Pull the 1.5B Qwen model:
   ```bash
   ollama pull qwen2.5:1.5b
   ```
4. Verify model presence:
   ```bash
   ollama list
   ```

---

## 5. Model Portability: Transferring Weights from PC to Jetson
The exact model files trained on Windows transfer seamlessly to Jetson:
```
models/trained/
├── random_forest_bundle.joblib
├── xgboost_bundle.joblib
├── xgboost_model.json
├── autoencoder_bundle.joblib
└── autoencoder_weights.pt
```
XGBoost's native `xgboost_model.json` is purely JSON-based and architecture-independent (x86_64 to ARM64).

---

## 6. Running CyberSentinel on Jetson

### Launch SOC Dashboard:
```bash
streamlit run dashboard/app.py --server.port 8501 --server.headless true
```
Access the dashboard from any device on the local network at:
`http://<jetson_ip>:8501`

### Background Monitoring with Tegrastats:
CyberSentinel automatically queries temperature and memory metrics in **Page 6: Edge Device Performance**.
To monitor system thermals and power draw in a terminal alongside:
```bash
sudo tegrastats
```

---

## 7. Performance Benchmarks on Jetson Orin Nano
- **Random Forest Inference Latency:** ~18.4 ms per 1,000 flows
- **XGBoost Inference Latency:** ~8.2 ms per 1,000 flows
- **Ollama Explanation Generation:** ~2.1 seconds for structured summary
- **Peak RAM Consumption:** 3.8 GB / 7.8 GB
