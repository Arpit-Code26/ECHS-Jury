# CYBERSENTINEL: FINAL DEMONSTRATION GUIDE
## Step-by-Step Defense & Presentation Script for B.Tech Final-Year Evaluation

This document outlines the exact, foolproof procedure to demonstrate CyberSentinel to professors, external examiners, and technical evaluators.

---

## 1. Pre-Demonstration Checklist
Before beginning the presentation, ensure:
1. Terminal / PowerShell is open in the project root:
   ```powershell
   cd "c:\Users\ARPIT NAINWAL\OneDrive\Desktop\ECHS"
   ```
2. Virtual environment is active:
   ```powershell
   .\venv\Scripts\Activate.ps1
   ```
3. Demonstration CSVs exist in `dataset/raw/`:
   - `demo_benign_traffic.csv`
   - `demo_attack_traffic.csv`
4. Pre-trained models exist in `models/trained/`:
   - `random_forest_bundle.joblib`
   - `xgboost_bundle.joblib`
   - `autoencoder_bundle.joblib`

---

## 2. Launching the Application
Execute the launcher command:
```powershell
python -m streamlit run dashboard/app.py
```
Your browser will open at **`http://localhost:8501`**.

---

## 3. Demonstration Workflow for Examiners

### Step 1: System Overview (Page 1)
- **What to show:**
  - Point to the SOC Header: **CYBERSENTINEL: AI-Powered Network Intrusion Detection**.
  - Show the four top metrics (currently at 0 before inference).
  - Highlight the **Runtime Telemetry** in the sidebar: Host OS, processor, available RAM, and Ollama status.
- **What to say to the Professor:**
  > *"CyberSentinel is designed as a unified cross-platform intrusion detection system. The exact same Python codebase and trained model bundles run on both Windows 11 laptops and edge AI devices like the NVIDIA Jetson Orin Nano without maintaining separate codebases."*

---

### Step 2: Dataset Management & Schema Validation (Page 2)
- **What to show:**
  - Navigate to **"2. Dataset Analysis"**.
  - Under "Load Demonstration Datasets", choose `demo_attack_traffic.csv` and click **"Load Selected Dataset"**.
  - Show the inspection report: 1,500 records, 67 canonical features, 0 missing values, 100% schema match.
  - Show the ground-truth label distribution donut chart (DDoS, PortScan, FTP-Patator, BENIGN) and class imbalance ratio.
- **What to say to the Professor:**
  > *"Network flow datasets frequently suffer from data leakage. In CyberSentinel, our data pipeline explicitly strips identifying IP addresses, ports, and timestamps, and isolates the target ground-truth label so it never touches the model inputs."*

---

### Step 3: Threat Detection & Inference (Page 3)
- **What to show:**
  - Navigate to **"3. Threat Detection"**.
  - Select **"XGBoost (Primary Advanced Tabular Classifier - Recommended)"**.
  - Click **"🚀 Analyze Traffic Records"**.
  - Watch the inference execute in milliseconds:
    - ~1,200 suspicious flows flagged.
    - 300 benign flows recognized.
    - Ground-truth evaluation displayed: Accuracy ~99.9%, Macro-F1 ~99.9%.
  - Point to the **Threat Category Distribution Donut Chart** showing detected DDoS, PortScan, and FTP-Patator proportions.
  - Expand the **Threat Explanations & Investigation Guidance** cards:
    - Show the description for DDoS (high packet rate, small packet size).
    - Show the recommended administrator investigation steps.
  - Filter the **Suspicious Flow Records Inspection** table by threat category.
  - Click **"📥 Download Complete Prediction Results (CSV)"** to show that analysts can export actionable reports.
- **What to say to the Professor:**
  > *"Notice how the system doesn't just output a raw number. It provides grounded defensive context: explaining which specific network flow features (like SYN Flag Count or Flow Packets/sec) caused the model to classify the event as a potential DDoS or PortScan, and gives the administrator a triage checklist."*

---

### Step 4: Comparing Models (Page 3 & 4)
- **What to show:**
  - Switch model selector to **"PyTorch Autoencoder (Unsupervised Anomaly Detection)"** and click **"Analyze Traffic Records"**.
  - Show that the Autoencoder operates on reconstruction error rather than predefined attack labels, identifying non-benign anomalies.
  - Navigate to **"4. Model Performance"**:
    - Show the side-by-side comparison chart between Random Forest, XGBoost, and the Autoencoder.
    - Show the interactive **Confusion Matrices** and **Feature Importance** plots.
- **What to say to the Professor:**
  > *"We implemented a two-tier paradigm: supervised models (XGBoost and Random Forest) achieve over 99.9% accuracy on known attack signatures, while our PyTorch Autoencoder was trained purely on normal benign traffic to detect novel, zero-day anomalies based on a mathematically derived reconstruction error threshold."*

---

### Step 5: Conversational AI Assistant (Page 5)
- **What to show:**
  - Navigate to **"5. AI Security Assistant"**.
  - Point to the active analysis context pill.
  - Click the quick question button: **"Explain DDoS in simple terms"**.
  - Click **"What should the administrator investigate first?"**.
  - Type a custom question in the chat input: *"Why is Port Scanning dangerous?"*.
  - Show how the assistant answers with grounded, defensive terminology without making claims that attacks were blocked.
- **What to say to the Professor:**
  > *"The AI Assistant bridges the gap between raw statistical machine learning outputs and junior SOC analysts, providing plain-language explanations of flow telemetry."*

---

### Step 6: Edge Hardware Telemetry (Page 6)
- **What to show:**
  - Navigate to **"6. Edge Device Performance"**.
  - Show live CPU percentage, per-core utilization, and RAM consumption.
  - Highlight the Jetson Orin Nano 8GB memory budgeting section.
- **What to say to the Professor:**
  > *"On the NVIDIA Jetson Orin Nano, memory is shared between CPU and GPU. We engineered CyberSentinel to keep the total active memory footprint under 4.0 GB, leaving ample headroom to prevent out-of-memory kernel locks."*

---

## 4. Key Questions & Model Answers for Examiners

**Q1: How did you prevent data leakage during training?**
> **Answer:** *"We took three critical precautions: First, the ground-truth Label column is separated immediately and never enters the feature space. Second, identifying fields like Source IP, Destination IP, Flow ID, and timestamps are stripped so the model cannot overfit on specific hosts. Third, preprocessing scalers and imputers are fitted strictly on the training partition and frozen before transforming test or inference data."*

**Q2: What is the difference between your supervised models and the Autoencoder?**
> **Answer:** *"XGBoost and Random Forest are supervised multi-class classifiers that recognize specific, known attack signatures with high precision and low false-positive rates. The PyTorch Autoencoder is an unsupervised model trained strictly on normal benign traffic; it flags unseen anomalies when the reconstruction mean squared error exceeds the 98th percentile threshold established on a held-out validation set."*

**Q3: Why did you choose a 1.5B LLM rather than a 7B or 13B model?**
> **Answer:** *"The Jetson Orin Nano 8GB has a unified memory constraint. A 7B parameter model requires 4.5+ GB of RAM, which risks crashing the operating system when running alongside background inference. The Qwen 2.5 1.5B quantized model requires only ~1.8 GB of RAM, leaving over 4 GB of headroom for OS and inference buffers."*
