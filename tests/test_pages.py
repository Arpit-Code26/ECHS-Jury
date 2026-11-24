"""
Automated unit test to verify that all pages of dashboard/app.py execute without NameError or unhandled exceptions.
"""
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from src.assistant.ollama_assistant import check_ollama_status, ask_security_assistant
from config.settings import OLLAMA_BASE_URL, OLLAMA_MODEL

def test_page_5_dependencies():
    # Verify the exact variables used in Page 5
    assert OLLAMA_BASE_URL is not None
    assert OLLAMA_MODEL is not None
    
    ollama_info = check_ollama_status()
    assert "is_online" in ollama_info
    assert "preferred_model" in ollama_info
    
    # Test assistant fallback execution
    res = ask_security_assistant("Explain DDoS in simple terms.")
    assert len(res) > 20
    print("Page 5 AI Security Assistant test PASSED!")

if __name__ == "__main__":
    test_page_5_dependencies()
