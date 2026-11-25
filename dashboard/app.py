"""
CYBERSENTINEL: Cross-Platform Edge AI Network Intrusion Detection & Intelligent Security Assistant
Main Streamlit SOC Dashboard Application.
"""
import streamlit as st
import sys
import json
import time
from pathlib import Path
import pandas as pd
import numpy as np

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from config.settings import (
    APP_NAME,
    APP_TITLE,
    APP_SUBTITLE,
    VERSION,
    METRICS_SUMMARY_PATH,
    RAW_DATA_DIR,
    PROCESSED_DATA_DIR,
    OLLAMA_BASE_URL,
    OLLAMA_MODEL
)
from src.utils.hardware import get_hardware_profile
from src.data.loader import inspect_csv_metadata, load_dataset, get_class_distribution
from src.data.validation import validate_dataset_schema
from src.detection.predictor import CyberSentinelPredictor
from src.assistant.ollama_assistant import check_ollama_status, ask_security_assistant, explain_threat_with_assistant
from src.monitoring.jetson_monitor import get_jetson_metrics
from dashboard.components.charts import (
    plot_threat_donut,
    plot_confusion_matrix,
    plot_feature_importances,
    plot_model_comparison_bar
)

# Page configuration
st.set_page_config(
    page_title="CyberSentinel SOC",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Dark SOC Cyber Theme CSS
st.markdown("""
<style>
    .main {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    .stMetric {
        background: #151d30;
        padding: 14px;
        border-radius: 8px;
        border: 1px solid #1e293b;
    }
    .soc-card {
        background: #151d30;
        border: 1px solid #1e293b;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 14px;
    }
    .soc-header {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        color: #38bdf8;
        font-weight: 700;
        margin-bottom: 6px;
    }
    .status-pill {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 9999px;
        font-weight: 600;
        font-size: 0.8rem;
    }
    .status-benign {
        background: rgba(16, 185, 129, 0.15);
        color: #34d399;
        border: 1px solid #059669;
    }
    .status-danger {
        background: rgba(239, 68, 68, 0.15);
        color: #f87171;
        border: 1px solid #dc2626;
    }
    .status-warning {
        background: rgba(245, 158, 11, 0.15);
        color: #fbbf24;
        border: 1px solid #d97706;
    }
</style>
""", unsafe_allow_html=True)


# Initialize Session State
if "analysis_results" not in st.session_state:
    st.session_state.analysis_results = None
if "current_df" not in st.session_state:
    st.session_state.current_df = None
if "current_filename" not in st.session_state:
    st.session_state.current_filename = None
if "chat_history" not in st.session_state:
    st.session_state.chat_history = []


# Cached Predictor instance to prevent reloading weights on every rerun
@st.cache_resource
def get_predictor_instance() -> CyberSentinelPredictor:
    return CyberSentinelPredictor()

predictor = get_predictor_instance()
hw = get_hardware_profile()
ollama_info = check_ollama_status()


# ==========================================
# SIDEBAR
# ==========================================
st.sidebar.markdown(f"### 🛡️ **{APP_NAME}**")
st.sidebar.caption(f"v{VERSION} | Cross-Platform Edge NIDS")

page = st.sidebar.radio(
    "Security Console Navigation",
    [
        "1. Overview",
        "2. Dataset Analysis",
        "3. Threat Detection",
        "4. Model Performance",
        "5. AI Security Assistant",
        "6. Edge Device Performance"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("#### **Runtime Telemetry**")
st.sidebar.markdown(f"**Target Host:** `{'NVIDIA Jetson' if hw['is_jetson'] else 'Windows 11 PC'}`")
st.sidebar.markdown(f"**Compute:** `{hw['processor'][:25]}...`")
st.sidebar.markdown(f"**RAM:** `{hw['available_ram_gb']} GB free / {hw['total_ram_gb']} GB`")

# Ollama Status indicator in sidebar
if ollama_info["is_online"]:
    st.sidebar.success(f"🟢 Ollama Online (`{ollama_info['preferred_model']}`)")
else:
    st.sidebar.warning("🟡 Ollama Offline (Fallback Engine Active)")

st.sidebar.caption("CyberSentinel operates 100% locally and offline.")


# ==========================================
# PAGE 1: OVERVIEW
# ==========================================
if page == "1. Overview":
    st.title("🛡️ " + APP_TITLE)
    st.caption(APP_SUBTITLE)
    
    results = st.session_state.analysis_results
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        total = results["total_records"] if results else 0
        st.metric("Total Records Analyzed", f"{total:,}")
    with col2:
        benign = results["benign_records"] if results else 0
        st.metric("Benign Records", f"{benign:,}", delta=f"{round((benign/max(total,1))*100, 1)}%" if total else None)
    with col3:
        suspicious = results["suspicious_records"] if results else 0
        st.metric("Suspicious Records", f"{suspicious:,}", delta=f"-{round((suspicious/max(total,1))*100, 1)}%" if total else None, delta_color="inverse")
    with col4:
        threat_cats = len([k for k in results["threat_distribution"].keys() if k.upper() != "BENIGN"]) if results else 0
        st.metric("Threat Categories Detected", str(threat_cats))

    st.markdown("---")
    
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.markdown("### 📡 **Active Operational Status**")
        if not results:
            st.info("No active inspection has been executed yet. Navigate to **'2. Dataset Analysis'** to load traffic records or proceed to **'3. Threat Detection'** to analyze sample traffic.")
            
            st.markdown("#### **Quick Start Demo Traffic:**")
            col_b1, col_b2 = st.columns(2)
            with col_b1:
                if st.button("📥 Load Demo Benign Traffic (1,500 flows)"):
                    demo_path = RAW_DATA_DIR / "demo_benign_traffic.csv"
                    if demo_path.exists():
                        st.session_state.current_df = load_dataset(demo_path)
                        st.session_state.current_filename = "demo_benign_traffic.csv"
                        st.success("Loaded 'demo_benign_traffic.csv' into memory! Head to '3. Threat Detection' to run inference.")
            with col_b2:
                if st.button("⚠️ Load Demo Multi-Attack Traffic (1,500 flows)"):
                    demo_path = RAW_DATA_DIR / "demo_attack_traffic.csv"
                    if demo_path.exists():
                        st.session_state.current_df = load_dataset(demo_path)
                        st.session_state.current_filename = "demo_attack_traffic.csv"
                        st.warning("Loaded 'demo_attack_traffic.csv' into memory! Head to '3. Threat Detection' to run inference.")
        else:
            if results["suspicious_records"] == 0:
                st.markdown('<span class="status-pill status-benign">STATUS: NORMAL TRAFFIC PROFILE</span>', unsafe_allow_html=True)
                st.write(f"Inference completed using **{results['model_name']}** across **{results['total_records']}** network flows. No malicious anomalies were identified.")
            else:
                st.markdown('<span class="status-pill status-danger">STATUS: THREAT PATTERNS DETECTED</span>', unsafe_allow_html=True)
                st.write(f"Inference using **{results['model_name']}** flagged **{results['suspicious_records']}** suspicious flow(s) in `{results['filename']}`.")

            st.plotly_chart(plot_threat_donut(results["threat_distribution"]), use_container_width=True)

    with col_right:
        st.markdown("### 🏢 **System Architecture**")
        st.markdown("""
        - **Deployment Mode:** Cross-Platform Unified Codebase
        - **Supported Edge Device:** NVIDIA Jetson Orin Nano (ARM64)
        - **Supported Laptop:** Windows 11 (Intel 13th Gen CPU)
        - **Tabular Classifier:** XGBoost / Random Forest
        - **Anomaly Detector:** PyTorch Reconstruction Autoencoder
        - **Local Explainer:** Ollama (`qwen2.5:1.5b`)
        - **Dataset Benchmark:** CIC-IDS2017 (UNB)
        """)
        
        st.markdown("### ⚙️ **Hardware Metrics**")
        st.progress(hw["ram_used_percent"] / 100.0, text=f"Host RAM: {hw['ram_used_percent']}% utilized")
        st.caption(f"Free Disk: {hw['disk_free_gb']} GB | Logical CPUs: {hw['logical_cpus']}")


# ==========================================
# PAGE 2: DATASET ANALYSIS
# ==========================================
elif page == "2. Dataset Analysis":
    st.title("📂 Dataset Management & Inspection")
    st.write("Inspect network traffic datasets, validate feature schemas, and analyze class distributions.")
    
    tab1, tab2 = st.tabs(["Upload Custom CSV", "Load Demonstration Datasets"])
    
    with tab1:
        uploaded_file = st.file_uploader("Upload Network Flow CSV (CIC-IDS2017 Format)", type=["csv"])
        if uploaded_file is not None:
            st.session_state.current_filename = uploaded_file.name
            st.session_state.current_df = load_dataset(uploaded_file)
            st.success(f"Uploaded and parsed `{uploaded_file.name}` ({len(st.session_state.current_df):,} records).")

    with tab2:
        st.markdown("Select a verified demonstration dataset slice:")
        demo_choice = st.selectbox(
            "Available Pre-configured Datasets",
            [
                "demo_attack_traffic.csv (Multi-Attack: DDoS, PortScan, Patator, BENIGN)",
                "demo_benign_traffic.csv (Pure Normal Background Traffic)",
                "test_subset.csv (Hold-out Test Benchmark - 7,800 records)"
            ]
        )
        if st.button("Load Selected Dataset"):
            if "attack" in demo_choice:
                chosen_path = RAW_DATA_DIR / "demo_attack_traffic.csv"
                fname = "demo_attack_traffic.csv"
            elif "benign" in demo_choice:
                chosen_path = RAW_DATA_DIR / "demo_benign_traffic.csv"
                fname = "demo_benign_traffic.csv"
            else:
                chosen_path = PROCESSED_DATA_DIR / "test_subset.csv"
                fname = "test_subset.csv"

            if chosen_path.exists():
                st.session_state.current_df = load_dataset(chosen_path)
                st.session_state.current_filename = fname
                st.success(f"Successfully loaded `{fname}` ({len(st.session_state.current_df):,} records) into session memory!")

    # Display dataset details if loaded
    if st.session_state.current_df is not None:
        df = st.session_state.current_df
        st.markdown("---")
        st.markdown(f"### 📊 Inspection Report: `{st.session_state.current_filename}`")
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Records", f"{len(df):,}")
        c2.metric("Total Features", str(len(df.columns)))
        missing_count = int(df.isnull().sum().sum())
        c3.metric("Missing Values", f"{missing_count:,}")
        
        # Schema validation
        val_report = validate_dataset_schema(df)
        c4.metric("Schema Match", f"{val_report['match_percentage']}%")
        
        if val_report["issues"]:
            with st.expander("⚠️ Schema Warnings & Notes", expanded=False):
                for issue in val_report["issues"]:
                    st.warning(issue)

        # Ground truth class distribution if present
        dist = get_class_distribution(df)
        if "classes" in dist:
            st.markdown("#### **Ground-Truth Label Distribution**")
            col_d1, col_d2 = st.columns([1, 1])
            with col_d1:
                class_counts = {k: v["count"] for k, v in dist["classes"].items()}
                st.plotly_chart(plot_threat_donut(class_counts), use_container_width=True)
            with col_d2:
                dist_df = pd.DataFrame([
                    {"Category": k, "Flow Count": v["count"], "Percentage": f"{v['percentage']}%"}
                    for k, v in dist["classes"].items()
                ])
                st.dataframe(dist_df, use_container_width=True, hide_index=True)
                st.caption(f"Class Imbalance Ratio (Majority : Minority): **{dist['imbalance_ratio']} : 1**")

        st.markdown("#### **Dataset Preview (First 20 Records)**")
        st.dataframe(df.head(20), use_container_width=True)
    else:
        st.info("Please upload a CSV or load a demo dataset above to begin analysis.")


# ==========================================
# PAGE 3: THREAT DETECTION
# ==========================================
elif page == "3. Threat Detection":
    st.title("⚡ Real-Time Threat Prediction Engine")
    st.write("Execute multi-tier machine learning inference over network flow records.")
    
    if st.session_state.current_df is None:
        st.warning("No dataset loaded in memory. Please select or upload a dataset below:")
        if st.button("Load 'demo_attack_traffic.csv' automatically"):
            demo_path = RAW_DATA_DIR / "demo_attack_traffic.csv"
            st.session_state.current_df = load_dataset(demo_path)
            st.session_state.current_filename = "demo_attack_traffic.csv"
            st.rerun()
    else:
        df = st.session_state.current_df
        st.markdown(f"**Loaded Dataset:** `{st.session_state.current_filename}` ({len(df):,} records)")
        
        col_m1, col_m2 = st.columns([2, 1])
        with col_m1:
            selected_model = st.selectbox(
                "Select Detection Model",
                [
                    "XGBoost (Primary Advanced Tabular Classifier - Recommended)",
                    "Random Forest (Baseline Multiclass Classifier)",
                    "PyTorch Autoencoder (Unsupervised Anomaly Detection)"
                ]
            )
        with col_m2:
            st.markdown("<br>", unsafe_allow_html=True)
            run_btn = st.button("🚀 Analyze Traffic Records", type="primary", use_container_width=True)

        if run_btn:
            if "XGBoost" in selected_model:
                m_type = "xgboost"
            elif "Random Forest" in selected_model:
                m_type = "random_forest"
            else:
                m_type = "autoencoder"

            with st.spinner(f"Executing {selected_model}..."):
                res = predictor.predict_dataframe(
                    df,
                    model_type=m_type,
                    filename=st.session_state.current_filename
                )
                st.session_state.analysis_results = res
                st.success(f"Inference completed in {res['inference_duration_seconds']}s ({res['records_per_second']:,} records/sec).")

        # Render Results if available
        if st.session_state.analysis_results:
            res = st.session_state.analysis_results
            st.markdown("---")
            st.markdown(f"### 🛡️ Detection Findings (`{res['model_name']}`)")
            
            # Metrics Row
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Flow Records", f"{res['total_records']:,}")
            m2.metric("Benign Flows", f"{res['benign_records']:,}")
            m3.metric("Suspicious Flows", f"{res['suspicious_records']:,}", delta_color="inverse")
            m4.metric("Throughput", f"{res['records_per_second']:,} /sec")

            # Ground truth metrics if available
            if res["has_ground_truth"] and res["ground_truth_metrics"]:
                gt = res["ground_truth_metrics"]
                st.info(f"🎯 **Ground-Truth Evaluation:** Accuracy: `{gt['accuracy']*100:.2f}%` | Macro-Precision: `{gt['precision_macro']*100:.2f}%` | Macro-Recall: `{gt['recall_macro']*100:.2f}%` | Macro-F1: `{gt['f1_macro']*100:.2f}%`")

            # Charts Row
            c_left, c_right = st.columns([1, 1])
            with c_left:
                st.markdown("#### **Threat Category Distribution**")
                st.plotly_chart(plot_threat_donut(res["threat_distribution"]), use_container_width=True)
            with c_right:
                st.markdown("#### **Benign vs. Malicious Ratio**")
                binary_counts = {"BENIGN": res["benign_records"], "SUSPICIOUS": res["suspicious_records"]}
                st.plotly_chart(plot_threat_donut(binary_counts), use_container_width=True)

            # Grounded Cybersecurity Explanations
            if res["explanations"]:
                st.markdown("### 📋 **Cybersecurity Threat Explanations & Investigation Guidance**")
                for exp in res["explanations"]:
                    with st.expander(f"⚠️ {exp['title']} ({exp['suspicious_records']} flows detected)", expanded=True):
                        st.markdown(f"**Severity:** `{exp['severity']}` | **Model Confidence Score:** `{exp['model_confidence_score']*100:.1f}%`")
                        st.markdown(f"**Threat Summary:** {exp['description']}")
                        st.markdown(f"**Correlated Network Features:** {', '.join([f'`{f}`' for f in exp['relevant_features']])}")
                        st.markdown("**Suggested Defensive Investigation Steps:**")
                        for step in exp["suggested_investigation_steps"]:
                            st.markdown(f"- {step}")
                        st.caption(f"*{exp['disclaimer']}*")

            # Suspicious Records Table
            st.markdown("### 🔍 **Suspicious Flow Records Inspection**")
            res_df = res["result_dataframe"]
            suspicious_df = res_df[res_df["Is_Suspicious"] == True]
            
            if len(suspicious_df) > 0:
                threat_filter = st.multiselect(
                    "Filter by Threat Category",
                    options=list(res["threat_distribution"].keys()),
                    default=[t for t in res["threat_distribution"].keys() if t.upper() != "BENIGN"]
                )
                if threat_filter:
                    filtered_view = suspicious_df[suspicious_df["Predicted_Threat"].isin(threat_filter)]
                else:
                    filtered_view = suspicious_df
                
                # Show key preview columns
                display_cols = ["Predicted_Threat", "Confidence_Score"] + [c for c in ["Destination Port", "Flow Duration", "Flow Packets/s", "Flow Bytes/s", "SYN Flag Count"] if c in filtered_view.columns]
                st.dataframe(filtered_view[display_cols].head(300), use_container_width=True)
            else:
                st.success("No suspicious records found. All flows match benign profile.")

            # CSV Download Button
            csv_data = res_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Download Complete Prediction Results (CSV)",
                data=csv_data,
                file_name=f"cybersentinel_results_{res['model_type']}.csv",
                mime="text/csv",
                use_container_width=True
            )


# ==========================================
# PAGE 4: MODEL PERFORMANCE
# ==========================================
elif page == "4. Model Performance":
    st.title("📊 Model Benchmarks & Comparison")
    st.write("Real measured evaluation metrics across Random Forest, XGBoost, and PyTorch Autoencoder.")
    
    if METRICS_SUMMARY_PATH.exists():
        with open(METRICS_SUMMARY_PATH, "r") as f:
            benchmarks = json.load(f)
            
        models_data = benchmarks.get("models", {})
        
        # Comparison Overview
        st.markdown("### 🏆 **Model Performance Overview**")
        st.plotly_chart(plot_model_comparison_bar(models_data), use_container_width=True)
        
        # Summary Table
        summary_rows = []
        for key, m in models_data.items():
            summary_rows.append({
                "Model": m.get("name", key),
                "Paradigm": m.get("mode", "Supervised"),
                "Accuracy": f"{m.get('accuracy', 0.0)*100:.2f}%",
                "F1-Score": f"{m.get('f1_macro', m.get('f1_score', 0.0))*100:.2f}%",
                "False Positive Rate": f"{m.get('false_positive_rate', 0.0)*100:.3f}%",
                "Inference Latency": f"{m.get('inference_latency_ms_per_1k', 0.0):.2f} ms / 1k flows",
                "Training Duration": f"{m.get('training_duration_seconds', 0.0):.2f} s"
            })
        st.dataframe(pd.DataFrame(summary_rows), use_container_width=True, hide_index=True)

        st.markdown("---")
        
        # Tabbed deep-dives
        tab_rf, tab_xgb, tab_ae = st.tabs(["1. Random Forest (Baseline)", "2. XGBoost (Advanced)", "3. PyTorch Autoencoder (Anomaly)"])
        
        with tab_rf:
            rf = models_data.get("random_forest", {})
            st.markdown(f"#### **{rf.get('name')} (Multiclass)**")
            if "confusion_matrix" in rf:
                st.plotly_chart(
                    plot_confusion_matrix(rf["confusion_matrix"], rf["target_names"], title="Random Forest Confusion Matrix"),
                    use_container_width=True
                )
            if "top_features" in rf:
                st.plotly_chart(
                    plot_feature_importances(rf["top_features"], title="Random Forest Top Feature Importances"),
                    use_container_width=True
                )

        with tab_xgb:
            xgb = models_data.get("xgboost", {})
            st.markdown(f"#### **{xgb.get('name')} (Multiclass)**")
            if "confusion_matrix" in xgb:
                st.plotly_chart(
                    plot_confusion_matrix(xgb["confusion_matrix"], xgb["target_names"], title="XGBoost Confusion Matrix"),
                    use_container_width=True
                )
            if "top_features" in xgb:
                st.plotly_chart(
                    plot_feature_importances(xgb["top_features"], title="XGBoost Top Feature Importances"),
                    use_container_width=True
                )

        with tab_ae:
            ae = models_data.get("autoencoder", {})
            st.markdown(f"#### **{ae.get('name')} (Unsupervised Anomaly Detection)**")
            st.markdown(f"""
            - **Anomaly Detection Strategy:** Trained purely on normal `BENIGN` traffic flows.
            - **Reconstruction Threshold:** `{ae.get('anomaly_threshold', 0.0):.6f}` (derived from {ae.get('threshold_percentile', 98)}th percentile of validation reconstruction error).
            - **Binary Accuracy:** `{ae.get('accuracy', 0.0)*100:.2f}%` | **Recall on Attacks:** `{ae.get('recall', 0.0)*100:.2f}%`
            """)
            if "confusion_matrix" in ae:
                st.plotly_chart(
                    plot_confusion_matrix(ae["confusion_matrix"], ae["target_names"], title="Autoencoder Anomaly Confusion Matrix"),
                    use_container_width=True
                )

        st.markdown("---")
        st.markdown("### 🛡️ **Methodology & Leakage Prevention Protocol**")
        st.markdown("""
        1. **Strict Feature Separation:** The ground truth `Label` is stripped immediately and never supplied to model inputs.
        2. **Identification Column Removal:** Non-predictive identity columns (`Flow ID`, `Source IP`, `Destination IP`, `Timestamp`) are explicitly dropped to prevent overfitting on static network addresses.
        3. **Stratified Split:** Data preprocessing (imputation medians, standard scalers) is fitted strictly on training data and frozen before test inference.
        """)
    else:
        st.warning("Benchmark metrics file not found. Please run `python scripts/train_all.py` to generate real benchmarks.")


# ==========================================
# PAGE 5: AI SECURITY ASSISTANT
# ==========================================
elif page == "5. AI Security Assistant":
    st.title("🤖 Intelligent Security Assistant")
    st.write("Context-aware cybersecurity incident analysis powered by local Ollama LLM.")
    
    # Ollama Status Banner
    if ollama_info["is_online"]:
        st.success(f"🟢 **Local Ollama Active** | Model: `{ollama_info['preferred_model']}` | Host: `{OLLAMA_BASE_URL}`")
    else:
        st.warning(f"🟡 **Offline Mode Active:** Ollama not detected on `{OLLAMA_BASE_URL}`. Using CyberSentinel Grounded Deterministic Security Engine. To enable LLM inference, launch `ollama serve` and pull `qwen2.5:0.5b`.")

    # Context Summary from current analysis if present
    analysis_ctx = None
    if st.session_state.analysis_results:
        res = st.session_state.analysis_results
        analysis_ctx = {
            "model_name": res["model_name"],
            "total_records": res["total_records"],
            "suspicious_records": res["suspicious_records"],
            "threat_distribution": res["threat_distribution"]
        }
        st.info(f"📌 **Active Analysis Context:** Inspecting `{res['filename']}` ({res['suspicious_records']} suspicious flows flagged by {res['model_name']}).")

    # Suggested Prompts Row
    st.markdown("#### **Suggested Questions:**")
    p1, p2, p3, p4 = st.columns(4)
    suggested_q = None
    with p1:
        if st.button("Explain DDoS in simple terms"):
            suggested_q = "Explain DDoS in simple language."
    with p2:
        if st.button("What is Port Scanning?"):
            suggested_q = "What is port scanning and why is it dangerous?"
    with p3:
        if st.button("Summarize Current Threats"):
            suggested_q = "Summarise the current analysis results."
    with p4:
        if st.button("Admin Investigation Steps"):
            suggested_q = "What should the administrator investigate first?"

    # Render Chat History
    for msg in st.session_state.chat_history:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    # Handle Input
    user_input = st.chat_input("Ask CyberSentinel AI about network threats, detected events, or mitigation steps...")
    query_to_process = user_input or suggested_q

    if query_to_process:
        # Display user message
        st.session_state.chat_history.append({"role": "user", "content": query_to_process})
        with st.chat_message("user"):
            st.markdown(query_to_process)

        # Generate response
        with st.chat_message("assistant"):
            with st.spinner("Analyzing cybersecurity telemetry..."):
                response_text = ask_security_assistant(query_to_process, context_summary=analysis_ctx)
                st.markdown(response_text)
                st.session_state.chat_history.append({"role": "assistant", "content": response_text})


# ==========================================
# PAGE 6: EDGE DEVICE PERFORMANCE
# ==========================================
elif page == "6. Edge Device Performance":
    st.title("💻 Edge & Host Hardware Metrics")
    st.write("Real-time system resource utilization and hardware constraints.")
    
    j_metrics = get_jetson_metrics()
    
    col_d1, col_d2, col_d3 = st.columns(3)
    col_d1.metric("Platform", "NVIDIA Jetson" if j_metrics["is_jetson"] else "Windows 11 Laptop")
    col_d2.metric("Total RAM", f"{j_metrics['total_ram_gb']} GB")
    col_d3.metric("Free RAM", f"{j_metrics['available_ram_gb']} GB", delta=f"{100 - j_metrics['ram_percent']}% free")

    st.markdown("---")
    
    c_g1, c_g2 = st.columns(2)
    with c_g1:
        st.markdown("#### **CPU Core Telemetry**")
        st.metric("Aggregate CPU Usage", f"{j_metrics['cpu_percent']}%")
        st.progress(j_metrics['cpu_percent'] / 100.0)
        
        with st.expander("Per-Core Utilization", expanded=False):
            for idx, usage in enumerate(j_metrics.get("per_cpu_percent", [])):
                st.write(f"Core {idx}: {usage}%")
                st.progress(usage / 100.0)

    with c_g2:
        st.markdown("#### **Memory & Storage Telemetry**")
        st.metric("RAM Utilization", f"{j_metrics['used_ram_gb']} GB / {j_metrics['total_ram_gb']} GB ({j_metrics['ram_percent']}%)")
        st.progress(j_metrics['ram_percent'] / 100.0)
        
        st.metric("Available Disk Space", f"{j_metrics['disk_free_gb']} GB Free")

    st.markdown("---")
    st.markdown("### ⚡ **Jetson Orin Nano (8GB) Edge Deployment Notes**")
    st.markdown("""
    - **Unified Memory Architecture:** Jetson Orin Nano shares its 8GB LPDDR5 RAM between the ARM Cortex CPU, Ampere GPU, and OS buffers.
    - **Memory Budgeting:**
      - OS & JetPack System Overhead: ~1.8 GB
      - CyberSentinel Python Runtime & Streamlit: ~250 MB
      - Scikit-learn / XGBoost Model Memory: ~80 MB
      - Ollama (`qwen2.5:1.5b` Q4_K_M quantized): ~1.8 GB (invoked on-demand)
      - Total peak footprint: ~4.0 GB (fits safely inside 8GB capacity with 4GB headroom).
    - **Optimization Measures:**
      - Model lazy loading: models are instantiated only upon selection.
      - Chunked inference: large CSVs are evaluated in 5,000-flow batches to cap RAM spikes.
    """)
