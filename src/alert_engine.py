"""
alert_engine.py - Converts model predictions into SOC alerts.
Assigns priority (HIGH/MEDIUM/LOW) and computes risk score.
Includes false positive reduction rules.
"""

import time
import numpy as np
from datetime import datetime, timezone


# -- Priority map -------------------------------------------------------------
HIGH_ATTACKS = {
    "DDoS", "DoS GoldenEye", "DoS Hulk", "DoS",
    "DoS Slowhttptest", "DoS slowloris",
    "Heartbleed", "Botnet", "Bot",
    "Infiltration", "Web Attack - Brute Force", 
    "Web Attack - XSS", "Web Attack - Sql Injection",
}

MEDIUM_ATTACKS = {
    "PortScan", "FTP-Patator", "SSH-Patator",
}

# Severity multipliers for risk score computation
SEVERITY_WEIGHTS = {
    "HIGH":   1.0,
    "MEDIUM": 0.6,
    "LOW":    0.1,
}

# Confidence threshold below which an alert is down-graded one level
FP_CONFIDENCE_THRESHOLD = 0.20


def get_priority(label: str, confidence: float) -> str:
    """
    Determine alert priority based on attack type and model confidence.
    Refined to reduce false positives in real-time traffic.
    """
    label_clean = label.strip().upper()
    if label_clean == "BENIGN":
        return "LOW"
    
    # Attack detected - use confidence thresholds for severity
    if confidence > 0.85:
        return "HIGH"
    elif confidence > 0.65:
        return "MEDIUM"
    else:
        # Low confidence attack is likely a noise/false positive
        return "LOW"


def compute_risk_score(confidence: float, priority: str) -> float:
    """Risk score in [0, 1]: confidence * severity_weight."""
    weight = SEVERITY_WEIGHTS.get(priority, 0.6)
    return round(float(confidence * weight), 4)




def build_alert(
    label: str,
    confidence: float,
    raw_priority: str | None = None,
    apply_fp_rules: bool = True,
    source: str = "UNKNOWN",
) -> dict:
    """
    Build a structured alert dict.
    """
    priority = raw_priority if raw_priority else get_priority(label, confidence)

    risk_score = compute_risk_score(confidence, priority)

    return {
        "id": int(time.time() * 1000),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attack_type": label,
        "priority": priority,
        "confidence": round(float(confidence), 4),
        "risk_score": risk_score,
        "action": _recommended_action(priority),
        "is_benign": label.strip() == "BENIGN",
        "source": source,
    }


def _recommended_action(priority: str) -> str:
    return {
        "HIGH":   "HIGH: Immediate response required",
        "MEDIUM": "MEDIUM: Investigate and monitor",
        "LOW":    "LOW: Log and ignore",
    }.get(priority, "Unknown")


# -- Batch helper -------------------------------------------------------------
def batch_build_alerts(labels: list[str], confidences: list[float]) -> list[dict]:
    return [build_alert(l, c) for l, c in zip(labels, confidences)]
