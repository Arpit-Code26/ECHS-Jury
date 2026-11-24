"""
CyberSentinel Application Launcher Script.
"""
import subprocess
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
APP_PATH = BASE_DIR / "dashboard" / "app.py"

def main():
    print("=" * 60)
    print("Starting CyberSentinel SOC Dashboard...")
    print(f"App target: {APP_PATH}")
    print("=" * 60)
    cmd = [
        sys.executable,
        "-m", "streamlit", "run",
        str(APP_PATH),
        "--server.headless=true",
        "--server.port=8501",
        "--browser.gatherUsageStats=false"
    ]
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\nCyberSentinel stopped by user.")

if __name__ == "__main__":
    main()
