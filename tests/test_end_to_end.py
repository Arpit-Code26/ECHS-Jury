"""
Comprehensive End-to-End Integration Test for CyberSentinel.
Tests the full lifecycle:
CSV load -> preprocessing -> Random Forest & XGBoost inference -> Autoencoder anomaly detection ->
Ground-truth comparison -> Cybersecurity explanation -> AI Assistant response.
"""
import sys
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.data.loader import load_dataset, inspect_csv_metadata
from src.data.validation import validate_dataset_schema
from src.detection.predictor import CyberSentinelPredictor
from src.assistant.ollama_assistant import ask_security_assistant, explain_threat_with_assistant


def test_full_pipeline():
    print("=" * 60)
    print("RUNNING CYBERSENTINEL END-TO-END PIPELINE TEST")
    print("=" * 60)
    
    # 1. Load Benign Demo Traffic
    benign_csv = BASE_DIR / "dataset" / "raw" / "demo_benign_traffic.csv"
    assert benign_csv.exists(), "demo_benign_traffic.csv missing"
    df_benign = load_dataset(benign_csv)
    print(f"[Step 1] Loaded {len(df_benign)} records from demo_benign_traffic.csv")
    
    # 2. Inspect Metadata & Schema
    meta = inspect_csv_metadata(benign_csv)
    assert meta["has_label"] is True
    val_report = validate_dataset_schema(df_benign)
    assert val_report["is_valid"] is True
    print("[Step 2] Metadata inspection & schema validation passed.")
    
    # 3. Predictor Initialization & Benign Inference
    predictor = CyberSentinelPredictor()
    res_benign = predictor.predict_dataframe(df_benign, model_type="xgboost", filename="demo_benign_traffic.csv")
    assert res_benign["total_records"] == 1500
    assert res_benign["benign_records"] > 1490
    print(f"[Step 3] XGBoost Benign evaluation passed ({res_benign['benign_records']} benign / {res_benign['total_records']})")
    
    # 4. Load Attack Demo Traffic
    attack_csv = BASE_DIR / "dataset" / "raw" / "demo_attack_traffic.csv"
    assert attack_csv.exists(), "demo_attack_traffic.csv missing"
    df_attack = load_dataset(attack_csv)
    print(f"[Step 4] Loaded {len(df_attack)} records from demo_attack_traffic.csv")
    
    # 5. Attack Traffic Inference (Random Forest)
    res_rf = predictor.predict_dataframe(df_attack, model_type="random_forest", filename="demo_attack_traffic.csv")
    assert res_rf["suspicious_records"] > 0
    assert len(res_rf["explanations"]) > 0
    print(f"[Step 5] Random Forest Attack evaluation passed ({res_rf['suspicious_records']} suspicious flows flagged)")
    
    # 6. Attack Traffic Inference (XGBoost)
    res_xgb = predictor.predict_dataframe(df_attack, model_type="xgboost", filename="demo_attack_traffic.csv")
    assert res_xgb["suspicious_records"] > 0
    print(f"[Step 6] XGBoost Attack evaluation passed ({res_xgb['suspicious_records']} suspicious flows flagged)")
    
    # 7. Unsupervised Autoencoder Anomaly Detection
    res_ae = predictor.predict_dataframe(df_attack, model_type="autoencoder", filename="demo_attack_traffic.csv")
    assert res_ae["total_records"] == len(df_attack)
    print(f"[Step 7] Autoencoder Anomaly evaluation passed ({res_ae['suspicious_records']} anomalous flows flagged)")
    
    # 8. AI Assistant Grounded Threat Explanation
    first_exp = res_xgb["explanations"][0]
    llm_explanation = explain_threat_with_assistant(first_exp)
    assert len(llm_explanation) > 50
    print(f"[Step 8] AI Threat Explanation generated successfully ({len(llm_explanation)} chars)")
    
    # 9. Conversational Security Assistant Q&A
    answer = ask_security_assistant("Explain DDoS and suggested investigation steps", context_summary=res_xgb)
    assert "DDoS" in answer or "investigate" in answer.lower()
    print("[Step 9] Security Assistant Q&A response verified.")
    
    print("\n>>> ALL END-TO-END PIPELINE STEPS PASSED SUCCESSFULLY! <<<")


if __name__ == "__main__":
    test_full_pipeline()
