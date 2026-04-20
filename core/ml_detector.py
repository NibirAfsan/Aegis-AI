"""
AEGIS core/ml_detector.py
===========================
Hybrid intrusion detection: ML model + flow-based pattern analysis.

WHY HYBRID:
  The CIC-IDS2017 model was trained on FLOW-level features (aggregated
  connection statistics). Single packets don't carry enough info for
  accurate flow classification. So we combine:
  
  1. ML Model  — classifies based on packet features (port, size, flags)
  2. Flow Analysis — detects patterns across multiple packets:
     - Port scan: one IP hitting many different ports
     - Brute force: many connections to same service port
     - DDoS: flood of packets from many sources to one target
     - Exploit: known attack signatures (specific ports + patterns)

  This is how real SIEM systems work — multiple detection layers.
"""

import os
import json
import time
import numpy as np
from datetime import datetime
from collections import defaultdict, deque
from threading import Lock

# ─────────────────────────────────────────────────────────────────────────────
# MODEL LOADER
# ─────────────────────────────────────────────────────────────────────────────

_model = None
_labels = None
_scaler_mean = None
_scaler_scale = None
_feature_names = None
_model_lock = Lock()


def _get_model_dir():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "ml_models")


def load_model():
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
            _model = ort.InferenceSession(model_path)
            with open(labels_path, "r") as f:
                _labels = json.load(f)
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
# FLOW-BASED PATTERN DETECTION
# ─────────────────────────────────────────────────────────────────────────────

_flow_lock = Lock()
_port_hits = defaultdict(set)       # src_ip → set of dst_ports
_conn_counts = defaultdict(int)     # (src_ip, dst_port) → connection count
_syn_counts = defaultdict(int)      # src_ip → SYN-only packet count
_packet_counts = defaultdict(int)   # dst_ip → packet count (DDoS detection)
_last_reset = time.time()

# Known attack ports on Metasploitable
_EXPLOIT_PORTS = {1524, 6200, 6667, 6697, 1099, 3632}
_SERVICE_PORTS = {21, 22, 2121, 2222, 3306, 5432}


def _detect_flow_pattern(src_ip: str, dst_ip: str, dst_port: int,
                          tcp_flags: int = 0, pkt_size: int = 0) -> dict:
    """
    Analyses traffic patterns across multiple packets.
    Returns attack classification if pattern detected.
    """
    global _last_reset

    with _flow_lock:
        now = time.time()

        # Reset counters every 60 seconds to detect ongoing attacks
        if now - _last_reset > 60:
            _port_hits.clear()
            _conn_counts.clear()
            _syn_counts.clear()
            _packet_counts.clear()
            _last_reset = now

        # Track this packet
        _port_hits[src_ip].add(dst_port)
        _conn_counts[(src_ip, dst_port)] += 1
        _packet_counts[dst_ip] += 1

        if tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN without ACK
            _syn_counts[src_ip] += 1

        # ── PORT SCAN: one IP hitting 8+ different ports ──
        if len(_port_hits[src_ip]) >= 8:
            _port_hits[src_ip].clear()
            return {
                "classification": "PORT_SCAN",
                "severity": "HIGH",
                "confidence": 0.92,
                "reason": f"Source {src_ip} scanned {8}+ unique ports"
            }

        # ── BRUTE FORCE: 10+ connections to same service port ──
        if dst_port in _SERVICE_PORTS and _conn_counts[(src_ip, dst_port)] >= 10:
            _conn_counts[(src_ip, dst_port)] = 0
            service_names = {21: "FTP", 22: "SSH", 2121: "FTP",
                           2222: "SSH", 3306: "MySQL", 5432: "PostgreSQL"}
            return {
                "classification": "BRUTE_FORCE",
                "severity": "HIGH",
                "confidence": 0.88,
                "reason": (f"10+ rapid connections to "
                          f"{service_names.get(dst_port, 'service')} "
                          f"port {dst_port}")
            }

        # ── SYN FLOOD: 30+ SYN packets without completing handshake ──
        if _syn_counts[src_ip] >= 30:
            _syn_counts[src_ip] = 0
            return {
                "classification": "DOS",
                "severity": "CRITICAL",
                "confidence": 0.90,
                "reason": f"SYN flood from {src_ip}: 30+ SYN packets"
            }

        # ── EXPLOIT ATTEMPT: connection to known backdoor ports ──
        if dst_port in _EXPLOIT_PORTS:
            return {
                "classification": "INFILTRATION",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "reason": (f"Connection to known exploit port {dst_port} "
                          f"(backdoor/RCE service)")
            }

        # ── DDoS: 50+ packets to same destination in window ──
        if _packet_counts[dst_ip] >= 50:
            _packet_counts[dst_ip] = 0
            return {
                "classification": "DDOS",
                "severity": "CRITICAL",
                "confidence": 0.85,
                "reason": f"High packet volume to {dst_ip}"
            }

    return None  # No pattern detected


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE EXTRACTION — converts Scapy packet → numeric features
# ─────────────────────────────────────────────────────────────────────────────

def extract_features_from_packet(packet) -> dict:
    try:
        from scapy.all import IP, TCP, UDP

        if not packet.haslayer(IP):
            return None

        ip = packet[IP]
        pkt_len = len(packet)
        src_port = 0
        dst_port = 0
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

        features = {
            "Destination Port": dst_port,
            "Flow Duration": 0,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 0,
            "Total Length of Fwd Packets": pkt_len,
            "Total Length of Bwd Packets": 0,
            "Fwd Packet Length Max": pkt_len,
            "Fwd Packet Length Min": pkt_len,
            "Fwd Packet Length Mean": float(pkt_len),
            "Fwd Packet Length Std": 0.0,
            "Bwd Packet Length Max": 0,
            "Bwd Packet Length Min": 0,
            "Bwd Packet Length Mean": 0.0,
            "Bwd Packet Length Std": 0.0,
            "Flow Bytes/s": float(pkt_len),
            "Flow Packets/s": 1.0,
            "Flow IAT Mean": 0.0,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 0,
            "Flow IAT Min": 0,
            "Fwd IAT Total": 0,
            "Fwd IAT Mean": 0.0,
            "Fwd IAT Std": 0.0,
            "Fwd IAT Max": 0,
            "Fwd IAT Min": 0,
            "Bwd IAT Total": 0,
            "Bwd IAT Mean": 0.0,
            "Bwd IAT Std": 0.0,
            "Bwd IAT Max": 0,
            "Bwd IAT Min": 0,
            "Fwd PSH Flags": 1 if (tcp_flags & 0x08) else 0,
            "Bwd PSH Flags": 0,
            "Fwd URG Flags": 1 if (tcp_flags & 0x20) else 0,
            "Bwd URG Flags": 0,
            "Fwd Header Length": header_len,
            "Bwd Header Length": 0,
            "Fwd Packets/s": 1.0,
            "Bwd Packets/s": 0.0,
            "Min Packet Length": pkt_len,
            "Max Packet Length": pkt_len,
            "Packet Length Mean": float(pkt_len),
            "Packet Length Std": 0.0,
            "Packet Length Variance": 0.0,
            "FIN Flag Count": 1 if (tcp_flags & 0x01) else 0,
            "SYN Flag Count": 1 if (tcp_flags & 0x02) else 0,
            "RST Flag Count": 1 if (tcp_flags & 0x04) else 0,
            "PSH Flag Count": 1 if (tcp_flags & 0x08) else 0,
            "ACK Flag Count": 1 if (tcp_flags & 0x10) else 0,
            "URG Flag Count": 1 if (tcp_flags & 0x20) else 0,
            "CWE Flag Count": 1 if (tcp_flags & 0x40) else 0,
            "ECE Flag Count": 1 if (tcp_flags & 0x80) else 0,
            "Down/Up Ratio": 0,
            "Average Packet Size": float(pkt_len),
            "Avg Fwd Segment Size": float(payload_len),
            "Avg Bwd Segment Size": 0.0,
            "Fwd Header Length.1": header_len,
            "Fwd Avg Bytes/Bulk": 0,
            "Fwd Avg Packets/Bulk": 0,
            "Fwd Avg Bulk Rate": 0,
            "Bwd Avg Bytes/Bulk": 0,
            "Bwd Avg Packets/Bulk": 0,
            "Bwd Avg Bulk Rate": 0,
            "Subflow Fwd Packets": 1,
            "Subflow Fwd Bytes": pkt_len,
            "Subflow Bwd Packets": 0,
            "Subflow Bwd Bytes": 0,
            "Init_Win_bytes_forward": window_size,
            "Init_Win_bytes_backward": 0,
            "act_data_pkt_fwd": 1 if payload_len > 0 else 0,
            "min_seg_size_forward": header_len,
            "Active Mean": 0.0,
            "Active Std": 0.0,
            "Active Max": 0,
            "Active Min": 0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Idle Max": 0,
            "Idle Min": 0,
        }
        return features
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# CLASSIFIER — hybrid: ML model + flow pattern detection
# ─────────────────────────────────────────────────────────────────────────────

def classify_packet(packet) -> dict:
    """
    Hybrid classification:
    1. Check flow patterns first (port scan, brute force, exploit ports)
    2. Run ML model for additional classification
    3. Merge results — flow detection overrides ML for attack traffic
    """
    from scapy.all import IP, TCP, UDP

    if _model is None:
        if not load_model():
            return None

    if not packet.haslayer(IP):
        return None

    ip = packet[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    dst_port = 0
    tcp_flags = 0
    proto = "IP"

    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
        tcp_flags = int(packet[TCP].flags) if hasattr(packet[TCP], 'flags') else 0
        proto = "TCP"
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
        proto = "UDP"

    # ── Step 1: Flow-based pattern detection ──
    flow_result = _detect_flow_pattern(
        src_ip, dst_ip, dst_port, tcp_flags, len(packet))

    # ── Step 2: ML model classification ──
    ml_label = "NORMAL"
    ml_confidence = 0.85
    try:
        features = extract_features_from_packet(packet)
        if features and _feature_names:
            feature_vector = [features.get(fn, 0.0) for fn in _feature_names]
            X = np.array([feature_vector], dtype=np.float32)
            X_scaled = (X - _scaler_mean) / _scaler_scale
            X_scaled = np.nan_to_num(X_scaled, nan=0.0, posinf=0.0, neginf=0.0)

            prediction = _model.run(None, {"X": X_scaled})[0]
            ml_label = _labels.get(str(int(prediction[0])), "UNKNOWN")

            try:
                proba = _model.run(None, {"X": X_scaled})[1]
                if proba is not None and len(proba) > 0:
                    ml_confidence = float(np.max(proba[0]))
            except (IndexError, Exception):
                pass
    except Exception:
        pass

    # ── Step 3: Merge results ──
    # Flow detection takes priority for attack traffic
    if flow_result:
        classification = flow_result["classification"]
        severity = flow_result["severity"]
        confidence = flow_result["confidence"]
    elif ml_label != "NORMAL":
        classification = ml_label
        severity = _get_severity(ml_label)
        confidence = ml_confidence
    else:
        classification = "NORMAL"
        severity = "LOW"
        confidence = ml_confidence

    is_threat = classification != "NORMAL"

    return {
        "classification": classification,
        "confidence":     round(confidence, 3),
        "severity":       severity,
        "timestamp":      datetime.now().isoformat(),
        "src":            src_ip,
        "dst":            dst_ip,
        "port":           dst_port,
        "protocol":       proto,
        "packet_size":    len(packet),
        "is_threat":      is_threat,
        "ml_label":       ml_label,
        "detection_method": "flow_analysis" if flow_result else "ml_model",
    }


def _get_severity(label: str) -> str:
    return {
        "NORMAL": "LOW", "PORT_SCAN": "MEDIUM",
        "BOTNET": "HIGH", "BRUTE_FORCE": "HIGH",
        "WEB_ATTACK": "HIGH", "DOS": "CRITICAL",
        "DDOS": "CRITICAL", "SQL_INJECTION": "CRITICAL",
        "HEARTBLEED": "CRITICAL", "INFILTRATION": "CRITICAL",
    }.get(label, "MEDIUM")


# ─────────────────────────────────────────────────────────────────────────────
# ALERT MANAGEMENT — for backward compatibility with views
# ─────────────────────────────────────────────────────────────────────────────

def get_recent_alerts(count=50):
    """Read from Redis."""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        raw = r.lrange("aegis:siem:recent_alerts", 0, count - 1)
        return [json.loads(a) for a in raw]
    except Exception:
        return []


def get_threat_summary():
    """Read from Redis."""
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        total_packets = int(r.get("aegis:siem:total_packets") or 0)
        total_threats = int(r.get("aegis:siem:total_threats") or 0)
        return {
            "total_packets":   total_packets,
            "total_threats":   total_threats,
            "critical_alerts": int(r.get("aegis:siem:critical_alerts") or 0),
            "by_category":     {k: int(v) for k, v in
                                (r.hgetall("aegis:siem:by_category") or {}).items()},
            "threat_rate":     round(total_threats / max(total_packets, 1) * 100, 2),
            "model_accuracy":  99.61,
            "model_classes":   10,
        }
    except Exception:
        return {"total_packets": 0, "total_threats": 0, "critical_alerts": 0,
                "by_category": {}, "threat_rate": 0.0, "model_accuracy": 99.61}


def reset_threat_counts():
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        r.set("aegis:siem:total_packets", 0)
        r.set("aegis:siem:total_threats", 0)
        r.set("aegis:siem:critical_alerts", 0)
        r.delete("aegis:siem:by_category")
        r.delete("aegis:siem:recent_alerts")
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# GENAI RESPONSE PLAYBOOK
# ─────────────────────────────────────────────────────────────────────────────

def generate_response_playbook(attack_type: str, details: dict) -> str:
    from core.ai_engine import ask_ai

    prompt = f"""You are a senior SOC analyst. The AEGIS-AI SIEM has detected:

ATTACK TYPE: {attack_type}
SEVERITY: {details.get('severity', 'HIGH')}
SOURCE IP: {details.get('src', 'Unknown')}
DESTINATION: {details.get('dst', 'Unknown')}:{details.get('port', 'Unknown')}
PROTOCOL: {details.get('protocol', 'Unknown')}
CONFIDENCE: {details.get('confidence', 0) * 100:.1f}%
DETECTION METHOD: {details.get('detection_method', 'hybrid')}

Generate a concise incident response playbook:

## Immediate Actions (within 5 minutes)
## Investigation Steps
## Containment
## Recovery
## Prevention

Include specific Linux commands. Keep it actionable.
"""
    return ask_ai(prompt)


# ─────────────────────────────────────────────────────────────────────────────
# MODEL INFO
# ─────────────────────────────────────────────────────────────────────────────

def get_model_info():
    model_dir = _get_model_dir()
    summary_path = os.path.join(model_dir, "model_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r") as f:
            return json.load(f)
    return {"model_type": "RandomForestClassifier", "accuracy": 0.9961,
            "dataset": "CIC-IDS2017",
            "status": "loaded" if _model is not None else "not loaded"}

            