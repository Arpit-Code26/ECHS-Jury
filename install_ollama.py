"""
Automated Ollama Installation, Service Starter, and Lightweight Model Puller.
Designed for Windows to set up local Ollama on http://localhost:11434 cleanly.
"""
import os
import sys
import time
import subprocess
import shutil
import urllib.request
import requests

def log(msg):
    print(f"[*] {msg}", flush=True)

def find_ollama_binary():
    # Check standard paths
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

def is_ollama_running():
    try:
        r = requests.get("http://127.0.0.1:11434/api/tags", timeout=2)
        return r.status_code == 200
    except Exception:
        return False

def main():
    log("Checking if Ollama is already installed...")
    ollama_bin = find_ollama_binary()
    
    if not ollama_bin:
        temp_dir = os.environ.get("TEMP", r"C:\Windows\Temp")
        installer_path = os.path.join(temp_dir, "OllamaSetup.exe")
        download_url = "https://github.com/ollama/ollama/releases/download/v0.40.18/OllamaSetup.exe"
        
        log(f"Ollama binary not found. Downloading OllamaSetup.exe to {installer_path}...")
        
        # Download using urllib with simple progress logging
        def reporthook(count, block_size, total_size):
            if count % 2000 == 0:
                downloaded_mb = (count * block_size) / (1024 * 1024)
                total_mb = total_size / (1024 * 1024)
                log(f"Downloading: {downloaded_mb:.1f} MB / {total_mb:.1f} MB ({downloaded_mb/total_mb*100:.1f}%)")
                
        urllib.request.urlretrieve(download_url, installer_path, reporthook)
        log("Download complete. Running silent Inno Setup installation...")
        
        # Run silent Inno Setup
        cmd = [installer_path, "/VERYSILENT", "/NORESTART", "/SP-", "/SUPPRESSMSGBOXES"]
        subprocess.run(cmd, check=True)
        log("Installation command finished.")
        
        # Remove installer to free disk space immediately
        if os.path.exists(installer_path):
            os.remove(installer_path)
            log("Removed installer setup binary to conserve disk space.")
            
        time.sleep(3)
        ollama_bin = find_ollama_binary()
        
    if not ollama_bin:
        log("ERROR: Could not locate installed ollama.exe.")
        sys.exit(1)
        
    log(f"Ollama binary verified at: {ollama_bin}")
    
    # Check if Ollama service is already running
    if not is_ollama_running():
        log("Starting Ollama service (ollama serve)...")
        # Start in background
        subprocess.Popen([ollama_bin, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        
        # Wait up to 15 seconds for port 11434 to bind
        started = False
        for i in range(15):
            time.sleep(1)
            if is_ollama_running():
                started = True
                break
        if not started:
            log("Warning: Ollama server did not respond immediately on port 11434. Continuing...")
    else:
        log("Ollama server is already running on port 11434.")
        
    # Check available models
    log("Checking installed models...")
    r = requests.get("http://127.0.0.1:11434/api/tags").json()
    models = [m.get("name") for m in r.get("models", [])]
    log(f"Current models: {models}")
    
    # Pull lightweight model if neither qwen2.5:0.5b nor qwen2.5:1.5b is present
    target_model = "qwen2.5:0.5b" # Ultra-fast, ~398MB download, ideal for CPU and low disk space
    if not any("qwen2.5" in m for m in models):
        log(f"Pulling lightweight model '{target_model}'...")
        res = subprocess.run([ollama_bin, "pull", target_model])
        log(f"Pull completed with code: {res.returncode}")
    else:
        log("Qwen model is already present.")
        
    log("OLLAMA SETUP & VERIFICATION COMPLETED SUCCESSFULLY!")

if __name__ == "__main__":
    main()
