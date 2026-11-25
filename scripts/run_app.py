"""
CyberSentinel Application Launcher Script.
Automatically ensures Ollama background service is running and launches the Streamlit SOC console.
"""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
import requests

BASE_DIR = Path(__file__).resolve().parent.parent
APP_PATH = BASE_DIR / "dashboard" / "app.py"


def find_ollama_binary():
    paths = [
        shutil.which("ollama"),
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Ollama\ollama.exe"),
        r"C:\Program Files\Ollama\ollama.exe",
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Programs\Ollama\ollama.exe")
    ]
    for p in paths:
        if p and os.path.exists(p):
            return p
    return None


def ensure_ollama_running():
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=1.5)
        if r.status_code == 200:
            print("[✓] Ollama background service is already active on http://127.0.0.1:11434.")
            return True
    except Exception:
        pass

    ollama_bin = find_ollama_binary()
    if ollama_bin:
        print(f"[*] Starting local Ollama service via: {ollama_bin} serve ...")
        creationflags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        subprocess.Popen(
            [ollama_bin, "serve"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags
        )
        for _ in range(6):
            time.sleep(1)
            try:
                r = requests.get("http://127.0.0.1:11434/api/tags", timeout=1)
                if r.status_code == 200:
                    print("[✓] Ollama background service connected successfully.")
                    return True
            except Exception:
                continue
    print("[!] Ollama service not detected; CyberSentinel will use its built-in Deterministic Security Engine.")
    return False


def main():
    print("=" * 60)
    print("🛡️  Starting CyberSentinel SOC Dashboard...")
    print(f"App target: {APP_PATH}")
    print("=" * 60)

    # Auto-start Ollama if installed
    ensure_ollama_running()

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

