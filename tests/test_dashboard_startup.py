"""
Unit test to verify that the Streamlit dashboard starts and serves health checks.
"""
import subprocess
import time
import sys
import requests
from pathlib import Path

def test_streamlit_starts():
    base_dir = Path(__file__).resolve().parent.parent
    app_path = base_dir / "dashboard" / "app.py"
    
    cmd = [
        sys.executable,
        "-m", "streamlit", "run",
        str(app_path),
        "--server.headless=true",
        "--server.port=8503",
        "--browser.gatherUsageStats=false"
    ]
    
    print("Launching Streamlit on port 8503...")
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    success = False
    
    try:
        # Give Streamlit up to 10 seconds to bind port
        for attempt in range(10):
            time.sleep(1)
            try:
                resp = requests.get("http://localhost:8503/_stcore/health", timeout=2)
                if resp.status_code == 200:
                    print(f"Streamlit health probe succeeded! Response: {resp.text.strip()}")
                    success = True
                    break
            except Exception:
                pass
    finally:
        proc.terminate()
        try:
            out, err = proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        print("STDOUT:", out)
        print("STDERR:", err)
        print("Streamlit process terminated.")
        
    assert success, "Streamlit failed to respond with HTTP 200 on /_stcore/health"
    print("Dashboard startup test PASSED!")

if __name__ == "__main__":
    test_streamlit_starts()
