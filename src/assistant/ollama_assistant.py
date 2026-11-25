"""
Ollama Local LLM Integration Module for CyberSentinel.
Connects to local Ollama (qwen2.5:1.5b) on http://localhost:11434.
Includes resilient fallback when Ollama is offline.
"""
from typing import Dict, Any, List, Optional, Tuple
import requests
import json
from config.settings import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT_SECONDS
from src.detection.threat_explainer import THREAT_PROFILES
from src.utils.logging_config import logger


SYSTEM_GROUNDING_PROMPT = """You are CyberSentinel AI, an expert defensive cybersecurity analyst and network intrusion assistant.
Your role is to explain detected network flow anomalies in clear, precise, and professional technical language.

STRICT OPERATIONAL RULES:
1. Base your explanation strictly on the supplied detection summary and flow statistics.
2. Machine-learning classification is a statistical threat indicator, NOT definitive proof of an active attack.
3. NEVER invent source IP addresses, external hacker groups, or events not present in the input.
4. Clearly distinguish between model predictions and verified facts.
5. Provide actionable, defensive investigation steps for network administrators.
"""


def check_ollama_status(base_url: str = OLLAMA_BASE_URL) -> Dict[str, Any]:
    """
    Checks if local Ollama server is running and inspects available models.
    Dynamically falls back to any available lightweight model (e.g. qwen2.5:0.5b).
    """
    tags_url = f"{base_url.rstrip('/')}/api/tags"
    try:
        resp = requests.get(tags_url, timeout=3)
        if resp.status_code == 200:
            models_info = resp.json().get("models", [])
            model_names = [m.get("name") for m in models_info]
            
            # Select active model: preferred OLLAMA_MODEL or best match
            active_model = OLLAMA_MODEL
            if not any(OLLAMA_MODEL in name for name in model_names):
                qwen_models = [name for name in model_names if "qwen" in name.lower()]
                if qwen_models:
                    active_model = qwen_models[0]
                elif model_names:
                    active_model = model_names[0]

            preferred_available = len(model_names) > 0
            return {
                "is_online": True,
                "preferred_model": active_model,
                "preferred_available": preferred_available,
                "available_models": model_names,
                "error": None
            }
        else:
            return {
                "is_online": False,
                "preferred_model": OLLAMA_MODEL,
                "preferred_available": False,
                "available_models": [],
                "error": f"Ollama HTTP {resp.status_code}"
            }
    except Exception as e:
        return {
            "is_online": False,
            "preferred_model": OLLAMA_MODEL,
            "preferred_available": False,
            "available_models": [],
            "error": "Ollama server not reachable on " + base_url
        }


def generate_offline_fallback_explanation(summary: Dict[str, Any]) -> str:
    """
    Produces a high-quality, grounded explanation when Ollama is unavailable.
    """
    category = summary.get("detected_category", "Unknown Activity")
    suspicious_count = summary.get("suspicious_records", 0)
    total_count = summary.get("total_records", 0)
    features = summary.get("relevant_features", ["Flow Duration", "Flow Packets/s", "Destination Port"])
    confidence = summary.get("confidence_score", 0.0)

    profile = THREAT_PROFILES.get(category, {
        "title": f"Unusual Traffic Pattern ({category})",
        "description": "Observed flow records exhibit statistical deviations from typical baseline traffic.",
        "key_features": features,
        "investigation_steps": [
            "Check targeted destination ports and active processes on target hosts.",
            "Verify edge firewall packet counters and rate-limiting triggers.",
            "Correlate flow timestamps with server event logs."
        ]
    })

    explanation_lines = [
        f"### 🛡️ Incident Analysis: {profile['title']}",
        "",
        f"**Classification Status:** Potential threat pattern identified by machine learning ({confidence * 100:.1f}% model confidence score).",
        f"**Scope:** {suspicious_count} suspicious record(s) out of {total_count} total flows analyzed.",
        "",
        "#### 1. Threat Significance",
        profile["description"],
        "",
        "#### 2. Key Correlated Network Flow Features",
        f"The model's classification is influenced by abnormal distributions in: {', '.join(features)}.",
        "",
        "#### 3. Recommended Administrative Investigation",
    ]
    for step in profile.get("investigation_steps", []):
        explanation_lines.append(f"- {step}")

    explanation_lines.extend([
        "",
        "> **Notice:** Generated via CyberSentinel Offline Grounded Analysis Engine. "
        "Ollama service was not detected on localhost:11434."
    ])

    return "\n".join(explanation_lines)


def query_ollama_llm(
    prompt: str,
    system_prompt: str = SYSTEM_GROUNDING_PROMPT,
    base_url: str = OLLAMA_BASE_URL,
    model: str = OLLAMA_MODEL
) -> Dict[str, Any]:
    """
    Sends a query to local Ollama API.
    """
    generate_url = f"{base_url.rstrip('/')}/api/generate"
    payload = {
        "model": model,
        "prompt": prompt,
        "system": system_prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "top_p": 0.9,
            "num_predict": 512
        }
    }

    try:
        resp = requests.post(generate_url, json=payload, timeout=OLLAMA_TIMEOUT_SECONDS)
        if resp.status_code == 200:
            result = resp.json()
            return {
                "success": True,
                "response": result.get("response", ""),
                "total_duration_sec": result.get("total_duration", 0) / 1e9,
                "model_used": model
            }
        else:
            return {
                "success": False,
                "response": None,
                "error": f"Ollama HTTP {resp.status_code}"
            }
    except Exception as e:
        return {
            "success": False,
            "response": None,
            "error": str(e)
        }


def explain_threat_with_assistant(summary: Dict[str, Any]) -> str:
    """
    Explains a detected threat group using Ollama with automatic grounded fallback.
    """
    status = check_ollama_status()
    if not status["is_online"]:
        return generate_offline_fallback_explanation(summary)

    # Ollama is online, construct grounded prompt
    prompt = f"""Explain the following network intrusion detection finding:
{json.dumps(summary, indent=2)}

Please provide:
1. What the detected category means.
2. Why this observed traffic pattern may be suspicious.
3. Which observed features support the model's classification.
4. Suggested defensive investigation steps for the administrator.
5. Analytical limitations or uncertainties (e.g. possibility of false positives).
"""
    res = query_ollama_llm(prompt, model=status["preferred_model"])
    if res["success"] and res["response"]:
        return res["response"].strip()
    else:
        return generate_offline_fallback_explanation(summary)


def ask_security_assistant(
    question: str,
    context_summary: Optional[Dict[str, Any]] = None
) -> str:
    """
    Conversational security assistant interface.
    """
    status = check_ollama_status()
    if status["is_online"]:
        ctx_str = f"\nCurrent Detection Context:\n{json.dumps(context_summary, indent=2)}\n" if context_summary else ""
        prompt = f"{ctx_str}User Question: {question}\nProvide a clear, technically sound, and concise cybersecurity answer:"
        res = query_ollama_llm(prompt, model=status["preferred_model"])
        if res["success"] and res["response"]:
            return res["response"].strip()

    # Fallback knowledge base answers for common questions
    q_lower = question.lower()
    if "ddos" in q_lower:
        return (
            "**DDoS (Distributed Denial of Service)** is an attack aimed at disrupting the normal traffic of a targeted server, "
            "service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic. "
            "In network flows, DDoS is typically characterized by massive Flow Packets/s, high SYN flag frequencies, and short inter-arrival times (Flow IAT Mean)."
        )
    elif "portscan" in q_lower or "port scan" in q_lower:
        return (
            "**Port Scanning** is a reconnaissance method where an adversary probes a range of server ports to discover open services, "
            "running versions, and potential vulnerabilities. In flow records, it appears as short duration flows, low packet counts (1-2 packets), "
            "and rapid connection attempts across sequential or randomized destination ports."
        )
    elif "hulk" in q_lower or "dos" in q_lower:
        return (
            "**DoS Hulk (HTTP Unbearable Load King)** is an application-layer DoS attack that generates unique, high-volume HTTP GET requests "
            "with randomized URL query parameters to bypass intermediate caching servers and directly exhaust server CPU and web server worker threads."
        )
    elif "patator" in q_lower or "brute" in q_lower:
        return (
            "**Patator Attacks (FTP-Patator / SSH-Patator)** represent multi-threaded, modular brute-force credential stuffing. "
            "They repeatedly attempt authentication handshakes on port 21 (FTP) or port 22 (SSH) in rapid succession."
        )
    elif "investigate" in q_lower or "admin" in q_lower:
        return (
            "**Recommended Investigation Protocol:**\n"
            "1. Identify the targeted internal IP and destination service port.\n"
            "2. Correlate timestamps with system authorization logs (`/var/log/auth.log` or Windows Security Log event 4625).\n"
            "3. Verify whether rate-limiting or Web Application Firewall (WAF) challenge thresholds were breached.\n"
            "4. Inspect host CPU, memory, and active socket connections (`netstat -ano` / `ss -tulpn`)."
        )
    else:
        return (
            f"**CyberSentinel Security Analyst Response:**\n\n"
            f"You asked: *\"{question}\"*\n\n"
            "CyberSentinel monitors network flow statistics (packet lengths, inter-arrival times, flag distributions, and flow durations) "
            "to differentiate benign operations from volumetric attacks (DDoS/DoS), reconnaissance (PortScan), and credential attacks (Patator). "
            "For active Ollama LLM conversation, start Ollama locally (`ollama serve`) with model `qwen2.5:1.5b`."
        )
