"""
Threat Explainer and Cybersecurity Knowledge Base.
Provides grounded descriptions, feature correlations, and administrator investigation steps.
Uses cautious defensive terminology (potential indication vs. proof of attack).
"""
from typing import Dict, Any, List
from datetime import datetime


THREAT_PROFILES: Dict[str, Dict[str, Any]] = {
    "DDoS": {
        "title": "Potential Distributed Denial of Service (DDoS) Activity",
        "severity": "HIGH",
        "description": (
            "Traffic pattern indicates a potential volumetric or state-exhaustion flood. "
            "Characterized by rapid packet bursts, elevated packet rates, and anomalous SYN/ACK ratios."
        ),
        "key_features": ["Flow Packets/s", "Flow Bytes/s", "SYN Flag Count", "Flow Duration", "Average Packet Size"],
        "investigation_steps": [
            "Inspect target destination ports (typically HTTP/80 or HTTPS/443).",
            "Verify edge firewall and reverse-proxy rate-limiting configurations.",
            "Cross-reference source flow frequencies to identify distributed source patterns.",
            "Confirm server CPU and memory saturation levels on targeted endpoints."
        ]
    },
    "DoS Hulk": {
        "title": "Traffic Pattern Consistent with DoS Hulk Flood",
        "severity": "HIGH",
        "description": (
            "Observed flows demonstrate persistent, high-frequency HTTP requests with elongated durations "
            "designed to exhaust web server thread pools."
        ),
        "key_features": ["Flow Duration", "Fwd Packets/s", "Total Length of Fwd Packets", "SYN Flag Count"],
        "investigation_steps": [
            "Review web server access and error logs for repetitive User-Agent patterns or unique query strings.",
            "Inspect keep-alive and connection timeout thresholds in web server configurations.",
            "Check upstream CDN/WAF challenge filters (e.g., JavaScript challenge or CAPTCHA gating)."
        ]
    },
    "PortScan": {
        "title": "Possible Port Reconnaissance / Scanning Behavior",
        "severity": "MEDIUM",
        "description": (
            "Short-lived flow records across varying destination ports with minimal data transfer. "
            "Consistent with automated reconnaissance probing for open network services."
        ),
        "key_features": ["Destination Port", "Flow Duration", "SYN Flag Count", "RST Flag Count", "Total Fwd Packets"],
        "investigation_steps": [
            "Identify the internal or external IP address originating the probes.",
            "Verify whether targeted ports correspond to legitimate exposed services.",
            "Ensure unused ports are closed and filtered by host or network firewalls.",
            "Check IDS alerts for follow-up vulnerability exploitation attempts."
        ]
    },
    "FTP-Patator": {
        "title": "Possible Brute-Force Behavior on Port 21 (FTP)",
        "severity": "MEDIUM",
        "description": (
            "Repetitive connection attempts to FTP port 21 with uniform small packet transfers, "
            "indicative of automated dictionary or credential-guessing attempts."
        ),
        "key_features": ["Destination Port", "Total Fwd Packets", "Flow Duration", "Fwd Packet Length Mean"],
        "investigation_steps": [
            "Inspect FTP service authentication logs for repeated failed logins.",
            "Check if account lockout or Fail2ban policies have been triggered.",
            "Consider disabling plaintext FTP in favor of SFTP or FTPS with key-based authentication."
        ]
    },
    "SSH-Patator": {
        "title": "Possible Brute-Force Behavior on Port 22 (SSH)",
        "severity": "MEDIUM",
        "description": (
            "Repetitive encrypted handshake handoffs and connection resets on port 22, "
            "consistent with automated password stuffing or brute-force scanning."
        ),
        "key_features": ["Destination Port", "Total Fwd Packets", "Total Backward Packets", "Flow Duration"],
        "investigation_steps": [
            "Check `/var/log/auth.log` or Windows Event Logs for repeated SSH login failures.",
            "Verify that password authentication is disabled in favor of Ed25519 or RSA public keys.",
            "Implement connection rate limits or restrict SSH access to trusted management subnets/VPNs."
        ]
    },
    "ANOMALY": {
        "title": "Unusual / Unseen Network Activity (Autoencoder Flag)",
        "severity": "LOW to MEDIUM",
        "description": (
            "The unsupervised Deep Learning Autoencoder flagged this flow because its statistical reconstruction "
            "error exceeds the benign baseline threshold. This indicates non-standard flow parameters."
        ),
        "key_features": ["Reconstruction MSE Error", "Flow Bytes/s", "Packet Length Variance", "Flow Duration"],
        "investigation_steps": [
            "Inspect the flow's destination port and protocols for proprietary or unexpected applications.",
            "Determine if recent network topology changes, software updates, or backups occurred.",
            "Correlate with supervised model predictions to determine if this anomaly matches known threat signatures."
        ]
    }
}


def get_threat_explanation(
    threat_category: str,
    record_count: int,
    confidence_score: float = 0.0,
    filename: str = "network_flow.csv"
) -> Dict[str, Any]:
    """
    Builds a grounded cybersecurity analysis object for a detected threat group.
    """
    profile = THREAT_PROFILES.get(
        threat_category,
        {
            "title": f"Unusual Network Activity ({threat_category})",
            "severity": "MEDIUM",
            "description": f"Statistical traffic flow indicators classify this pattern under category '{threat_category}'.",
            "key_features": ["Destination Port", "Flow Duration", "Flow Packets/s"],
            "investigation_steps": [
                "Inspect source and destination endpoints.",
                "Review network boundary firewall logs.",
                "Verify whether the pattern corresponds to scheduled batch transfers."
            ]
        }
    )

    return {
        "threat_category": threat_category,
        "title": profile["title"],
        "severity": profile["severity"],
        "description": profile["description"],
        "suspicious_records": record_count,
        "model_confidence_score": round(confidence_score, 4),
        "relevant_features": profile["key_features"],
        "suggested_investigation_steps": profile["investigation_steps"],
        "dataset_filename": filename,
        "analysis_timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "disclaimer": (
            "Machine-learning classification represents a potential threat indicator based on flow statistics, "
            "not absolute proof of an active compromise. CyberSentinel is a defensive detection system."
        )
    }
