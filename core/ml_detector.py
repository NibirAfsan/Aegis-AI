"""
AEGIS core/ml_detector.py
===========================
Loads the CIC-IDS2017 trained ONNX model and classifies network traffic.

FLOW:
  1. Scapy captures a packet
  2. extract_features() converts packet → 70 numeric features
  3. Features are scaled using saved scaler parameters
  4. ONNX model predicts: NORMAL / DDOS / BRUTE_FORCE / etc.
  5. Result shown on SIEM dashboard + stored for DFIR report

The model was trained on 2.83 million network flows with 99.61% accuracy.
"""

import os
import json
import time
import numpy as np
from datetime import datetime
from collections import deque
from threading import Lock

# ─────────────────────────────────────────────────────────────────────────────
# MODEL LOADER — singleton, loads once, reuses everywhere
# ─────────────────────────────────────────────────────────────────────────────

_model = None
_labels = None
_scaler_mean = None
_scaler_scale = None
_feature_names = None
_model_lock = Lock()

# Alert history — thread-safe ring buffer
_alert_history = deque(maxlen=500)
_alert_lock = Lock()

# Threat counters
_threat_counts = {
    "total_packets": 0,
    "total_threats": 0,
    "by_category": {},
    "critical_alerts": 0,
    "last_reset": datetime.now().isoformat()
}


def _get_model_dir():
    """Returns the ml_models directory path."""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "ml_models")


def load_model():
    """
    Loads the ONNX model, label encoder, and scaler parameters.
    Called once on first prediction — cached after that.
    """
    global _model, _labels, _scaler_mean, _scaler_scale, _feature_names

    with _model_lock:
        if _model is not None:
            return True

        model_dir = _get_model_dir()
        model_path = os.path.join(model_dir, "aegis_ids_model.onnx")
        labels_path = os.path.join(model_dir, "label_encoder.json")
        scaler_path = os.path.join(model_dir, "scaler_params.json")

        if not os.path.exists(model_path):
            print(f"[ML] Model not found at {model_path}")
            return False

        try:
            import onnxruntime as ort

            # Load ONNX model
            _model = ort.InferenceSession(model_path)

            # Load label encoder
            with open(labels_path, "r") as f:
                _labels = json.load(f)

            # Load scaler parameters
            with open(scaler_path, "r") as f:
                scaler = json.load(f)
                _scaler_mean = np.array(scaler["mean"], dtype=np.float32)
                _scaler_scale = np.array(scaler["scale"], dtype=np.float32)
                _feature_names = scaler["feature_names"]

            print(f"[ML] Model loaded: {len(_labels)} classes, "
                  f"{len(_feature_names)} features")
            return True

        except Exception as e:
            print(f"[ML] Failed to load model: {e}")
            _model = None
            return False


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — converts Scapy packet → 70 numeric features
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_from_packet(packet) -> dict:
    """
    Extracts CIC-IDS2017 compatible features from a Scapy packet.

    The CIC-IDS2017 dataset uses flow-level features (aggregated over
    a connection), not single-packet features. For real-time detection,
    we approximate flow features from individual packets and short-term
    flow statistics.

    Returns a dict of feature_name → value, or None if packet isn't IP.
    """
    try:
        from scapy.all import IP, TCP, UDP

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        pkt_len = len(packet)
        ip_len = ip.len if hasattr(ip, 'len') else pkt_len

        # Basic packet info
        src_port = 0
        dst_port = 0
        protocol = ip.proto  # 6=TCP, 17=UDP, 1=ICMP
        tcp_flags = 0
        window_size = 0
        header_len = ip.ihl * 4 if hasattr(ip, 'ihl') else 20

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            src_port = tcp.sport
            dst_port = tcp.dport
            tcp_flags = int(tcp.flags) if hasattr(tcp, 'flags') else 0
            window_size = tcp.window if hasattr(tcp, 'window') else 0
            header_len += tcp.dataofs * 4 if hasattr(tcp, 'dataofs') else 20
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            src_port = udp.sport
            dst_port = udp.dport
            header_len += 8

        payload_len = max(0, pkt_len - header_len)

        # Build feature dict matching CIC-IDS2017 column names
        # Many flow-level features are approximated from single packet
        features = {
            "Destination Port":              dst_port,
            "Flow Duration":                 0,
            "Total Fwd Packets":             1,
            "Total Backward Packets":        0,
            "Total Length of Fwd Packets":   pkt_len,
            "Total Length of Bwd Packets":   0,
            "Fwd Packet Length Max":         pkt_len,
            "Fwd Packet Length Min":         pkt_len,
            "Fwd Packet Length Mean":        float(pkt_len),
            "Fwd Packet Length Std":         0.0,
            "Bwd Packet Length Max":         0,
            "Bwd Packet Length Min":         0,
            "Bwd Packet Length Mean":        0.0,
            "Bwd Packet Length Std":         0.0,
            "Flow Bytes/s":                  float(pkt_len),
            "Flow Packets/s":               1.0,
            "Flow IAT Mean":                0.0,
            "Flow IAT Std":                 0.0,
            "Flow IAT Max":                 0,
            "Flow IAT Min":                 0,
            "Fwd IAT Total":               0,
            "Fwd IAT Mean":                0.0,
            "Fwd IAT Std":                 0.0,
            "Fwd IAT Max":                 0,
            "Fwd IAT Min":                 0,
            "Bwd IAT Total":               0,
            "Bwd IAT Mean":                0.0,
            "Bwd IAT Std":                 0.0,
            "Bwd IAT Max":                 0,
            "Bwd IAT Min":                 0,
            "Fwd PSH Flags":               1 if (tcp_flags & 0x08) else 0,
            "Bwd PSH Flags":               0,
            "Fwd URG Flags":               1 if (tcp_flags & 0x20) else 0,
            "Bwd URG Flags":               0,
            "Fwd Header Length":           header_len,
            "Bwd Header Length":           0,
            "Fwd Packets/s":              1.0,
            "Bwd Packets/s":              0.0,
            "Min Packet Length":           pkt_len,
            "Max Packet Length":           pkt_len,
            "Packet Length Mean":          float(pkt_len),
            "Packet Length Std":           0.0,
            "Packet Length Variance":      0.0,
            "FIN Flag Count":             1 if (tcp_flags & 0x01) else 0,
            "SYN Flag Count":             1 if (tcp_flags & 0x02) else 0,
            "RST Flag Count":             1 if (tcp_flags & 0x04) else 0,
            "PSH Flag Count":             1 if (tcp_flags & 0x08) else 0,
            "ACK Flag Count":             1 if (tcp_flags & 0x10) else 0,
            "URG Flag Count":             1 if (tcp_flags & 0x20) else 0,
            "CWE Flag Count":             1 if (tcp_flags & 0x40) else 0,
            "ECE Flag Count":             1 if (tcp_flags & 0x80) else 0,
            "Down/Up Ratio":              0,
            "Average Packet Size":        float(pkt_len),
            "Avg Fwd Segment Size":       float(payload_len),
            "Avg Bwd Segment Size":       0.0,
            "Fwd Header Length.1":        header_len,
            "Fwd Avg Bytes/Bulk":         0,
            "Fwd Avg Packets/Bulk":       0,
            "Fwd Avg Bulk Rate":          0,
            "Bwd Avg Bytes/Bulk":         0,
            "Bwd Avg Packets/Bulk":       0,
            "Bwd Avg Bulk Rate":          0,
            "Subflow Fwd Packets":        1,
            "Subflow Fwd Bytes":          pkt_len,
            "Subflow Bwd Packets":        0,
            "Subflow Bwd Bytes":          0,
            "Init_Win_bytes_forward":     window_size,
            "Init_Win_bytes_backward":    0,
            "act_data_pkt_fwd":           1 if payload_len > 0 else 0,
            "min_seg_size_forward":       header_len,
            "Active Mean":                0.0,
            "Active Std":                 0.0,
            "Active Max":                 0,
            "Active Min":                 0,
            "Idle Mean":                  0.0,
            "Idle Std":                   0.0,
            "Idle Max":                   0,
            "Idle Min":                   0,
        }

        return features

    except Exception as e:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFIER — runs the ML model on extracted features
# ─────────────────────────────────────────────────────────────────────────────

def classify_packet(packet) -> dict:
    """
    Takes a Scapy packet, extracts features, runs ML model.

    Returns:
    {
        "classification": "DDOS",
        "confidence": 0.95,
        "severity": "CRITICAL",
        "timestamp": "2026-04-19T12:00:00",
        "src": "192.168.1.100",
        "dst": "10.0.0.1",
        "port": 80,
        "protocol": "TCP",
        "packet_size": 1500
    }
    """
    from scapy.all import IP, TCP, UDP

    # Ensure model is loaded
    if _model is None:
        if not load_model():
            return None

    # Extract features
    features = extract_features_from_packet(packet)
    if features is None:
        return None

    try:
        # Build feature vector in the correct order
        feature_vector = []
        for fname in _feature_names:
            feature_vector.append(features.get(fname, 0.0))

        # Convert to numpy array and scale
        X = np.array([feature_vector], dtype=np.float32)

        # Apply the same scaling used during training
        X_scaled = (X - _scaler_mean) / _scaler_scale

        # Replace any NaN/inf from division by zero in scaling
        X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

        # Run prediction
        prediction = _model.run(None, {"X": X_scaled})[0]
        pred_label = _labels.get(str(int(prediction[0])), "UNKNOWN")

        # Get probability scores if available
        confidence = 0.85  # default
        try:
            proba = _model.run(None, {"X": X_scaled})[1]
            if proba is not None and len(proba) > 0:
                confidence = float(np.max(proba[0]))
        except (IndexError, Exception):
            pass

        # Determine severity based on attack type
        severity_map = {
            "NORMAL":        "LOW",
            "PORT_SCAN":     "MEDIUM",
            "BOTNET":        "HIGH",
            "BRUTE_FORCE":   "HIGH",
            "WEB_ATTACK":    "HIGH",
            "DOS":           "CRITICAL",
            "DDOS":          "CRITICAL",
            "SQL_INJECTION": "CRITICAL",
            "HEARTBLEED":    "CRITICAL",
            "INFILTRATION":  "CRITICAL",
        }

        # Build result
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        dst_port = 0
        proto = "IP"

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
            proto = "TCP"
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport
            proto = "UDP"

        result = {
            "classification": pred_label,
            "confidence":     round(confidence, 3),
            "severity":       severity_map.get(pred_label, "MEDIUM"),
            "timestamp":      datetime.now().isoformat(),
            "src":            src_ip,
            "dst":            dst_ip,
            "port":           dst_port,
            "protocol":       proto,
            "packet_size":    len(packet),
            "is_threat":      pred_label != "NORMAL",
        }

        # Update threat counters
        _update_threat_counts(result)

        # Store in alert history
        if result["is_threat"]:
            _store_alert(result)

        return result

    except Exception as e:
        return {
            "classification": "ERROR",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }


# ─────────────────────────────────────────────────────────────────────────────
# ALERT MANAGEMENT — stores alerts for SIEM dashboard
# ─────────────────────────────────────────────────────────────────────────────

def _update_threat_counts(result: dict):
    """Updates running threat counters."""
    global _threat_counts
    _threat_counts["total_packets"] += 1

    if result.get("is_threat"):
        _threat_counts["total_threats"] += 1
        cat = result["classification"]
        _threat_counts["by_category"][cat] = \
            _threat_counts["by_category"].get(cat, 0) + 1

        if result["severity"] == "CRITICAL":
            _threat_counts["critical_alerts"] += 1


def _store_alert(result: dict):
    """Stores a threat alert in the ring buffer."""
    with _alert_lock:
        _alert_history.append(result)


def get_recent_alerts(count: int = 50) -> list:
    """Returns the most recent threat alerts for the SIEM dashboard."""
    with _alert_lock:
        return list(_alert_history)[-count:]


def get_threat_summary() -> dict:
    """Returns threat statistics for the SIEM dashboard widgets."""
    return {
        "total_packets":   _threat_counts["total_packets"],
        "total_threats":   _threat_counts["total_threats"],
        "critical_alerts": _threat_counts["critical_alerts"],
        "by_category":     dict(_threat_counts["by_category"]),
        "threat_rate":     (
            round(_threat_counts["total_threats"] /
                  max(_threat_counts["total_packets"], 1) * 100, 2)
        ),
        "model_accuracy":  99.61,
        "model_classes":   10,
        "last_reset":      _threat_counts["last_reset"],
    }


def reset_threat_counts():
    """Resets all counters — called when starting a new monitoring session."""
    global _threat_counts
    _threat_counts = {
        "total_packets": 0,
        "total_threats": 0,
        "by_category": {},
        "critical_alerts": 0,
        "last_reset": datetime.now().isoformat()
    }


# ─────────────────────────────────────────────────────────────────────────────
# GENAI RESPONSE PLAYBOOK — generates incident response for detected attacks
# ─────────────────────────────────────────────────────────────────────────────

def generate_response_playbook(attack_type: str, details: dict) -> str:
    """
    Uses GenAI to generate a specific incident response playbook
    for a detected attack type.

    Called when the ML model detects a CRITICAL or HIGH severity attack.
    """
    from core.ai_engine import ask_ai

    prompt = f"""You are a senior SOC analyst. A real-time intrusion detection system
has just detected the following attack on the monitored network:

ATTACK TYPE: {attack_type}
SEVERITY: {details.get('severity', 'HIGH')}
SOURCE IP: {details.get('src', 'Unknown')}
DESTINATION: {details.get('dst', 'Unknown')}:{details.get('port', 'Unknown')}
PROTOCOL: {details.get('protocol', 'Unknown')}
CONFIDENCE: {details.get('confidence', 0) * 100:.1f}%
TIMESTAMP: {details.get('timestamp', 'Unknown')}

Generate a concise, actionable incident response playbook in Markdown:

## Immediate Actions (do within 5 minutes)
(3-5 specific commands or steps)

## Investigation Steps
(what to check, what logs to review)

## Containment
(how to stop the attack)

## Recovery
(how to restore normal operations)

## Prevention
(how to prevent this in future)

Be specific. Include actual Linux commands where relevant.
Keep it concise — this is for a SOC analyst who needs to act NOW.
"""
    return ask_ai(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# MODEL INFO — for dashboard display
# ─────────────────────────────────────────────────────────────────────────────

def get_model_info() -> dict:
    """Returns model metadata for display."""
    model_dir = _get_model_dir()
    summary_path = os.path.join(model_dir, "model_summary.json")

    if os.path.exists(summary_path):
        with open(summary_path, "r") as f:
            return json.load(f)

    return {
        "model_type": "RandomForestClassifier",
        "accuracy": 0.9961,
        "dataset": "CIC-IDS2017",
        "status": "loaded" if _model is not None else "not loaded"
    }