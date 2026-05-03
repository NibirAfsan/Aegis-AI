"""
AEGIS core/feedback_engine.py
==============================
Dynamic Learning Pipeline with GenAI-in-the-loop.

THE INNOVATION:
  Traditional IDS: train once → deploy forever → becomes outdated
  AEGIS: detect → GenAI validates → feedback saved → model retrains → smarter

HOW IT WORKS:
  1. Listener detects a threat (ML model + flow analysis)
  2. Detection is logged to training_feedback.csv
  3. GenAI automatically reviews the classification:
     - "Is this really a BRUTE_FORCE attack?"
     - "Yes, 10 rapid SSH connections from same IP confirms this"
     - OR "No, this looks more like PORT_SCAN — different ports targeted"
  4. GenAI-confirmed label saved as verified training data
  5. When enough samples collected → retrain model → better detection

WHY GENAI INSTEAD OF HUMAN:
  - GenAI knows the latest CVEs, attack techniques, threat intelligence
  - Available 24/7, processes instantly, scales infinitely
  - More consistent than human analysts
  - Human override still available when needed
"""

import os
import csv
import json
import time
import hashlib
from datetime import datetime
from threading import Lock
from collections import Counter

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FEEDBACK_CSV = os.path.join(_BASE_DIR, "ml_models", "training_feedback.csv")
ANOMALY_LOG = os.path.join(_BASE_DIR, "ml_models", "anomaly_detections.json")
LEARNING_STATS = os.path.join(_BASE_DIR, "ml_models", "learning_stats.json")

_feedback_lock = Lock()
_anomaly_lock = Lock()

# CSV columns for training feedback
FEEDBACK_COLUMNS = [
    "timestamp", "detection_id", "src_ip", "dst_ip", "dst_port",
    "protocol", "packet_size", "ml_prediction", "flow_prediction",
    "final_classification", "confidence", "severity",
    "detection_method", "verified_label", "verified_by",
    "verification_timestamp", "verification_reasoning", "notes"
]

# Known attack types from CIC-IDS2017 training
KNOWN_PATTERNS = {
    "PORT_SCAN", "BRUTE_FORCE", "DOS", "DDOS", "INFILTRATION",
    "SQL_INJECTION", "WEB_ATTACK", "BOTNET", "HEARTBLEED", "NORMAL"
}


# ─────────────────────────────────────────────────────────────────────────────
# DETECTION LOGGING — called automatically by the listener
# ─────────────────────────────────────────────────────────────────────────────

def log_detection(detection: dict) -> str:
    """
    Logs every SIEM detection to training_feedback.csv.
    Called by the listener whenever a threat is detected.
    Returns the detection_id.
    """
    detection_id = _generate_detection_id(detection)

    row = {
        "timestamp":            detection.get("timestamp", datetime.now().isoformat()),
        "detection_id":         detection_id,
        "src_ip":               detection.get("src", ""),
        "dst_ip":               detection.get("dst", ""),
        "dst_port":             detection.get("port", 0),
        "protocol":             detection.get("protocol", ""),
        "packet_size":          detection.get("packet_size", 0),
        "ml_prediction":        detection.get("ml_label", "UNKNOWN"),
        "flow_prediction":      detection.get("classification", "UNKNOWN"),
        "final_classification": detection.get("classification", "UNKNOWN"),
        "confidence":           detection.get("confidence", 0.0),
        "severity":             detection.get("severity", "LOW"),
        "detection_method":     detection.get("detection_method", "unknown"),
        "verified_label":       "",
        "verified_by":          "",
        "verification_timestamp": "",
        "verification_reasoning": "",
        "notes":                "",
    }

    with _feedback_lock:
        file_exists = os.path.exists(FEEDBACK_CSV)
        with open(FEEDBACK_CSV, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_COLUMNS)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

    # Check for anomaly patterns
    _check_and_log_anomaly(detection, detection_id)
    _update_stats("detections_logged")

    return detection_id


def _generate_detection_id(detection: dict) -> str:
    content = f"{detection.get('src','')}{detection.get('dst','')}" \
              f"{detection.get('port',0)}{time.time()}"
    return hashlib.md5(content.encode()).hexdigest()[:12]


# ─────────────────────────────────────────────────────────────────────────────
# GENAI AUTO-VALIDATION — the key innovation
# ─────────────────────────────────────────────────────────────────────────────

def genai_validate_detections(count: int = 10) -> dict:
    """
    Uses GenAI to automatically validate recent unverified detections.
    This is the GenAI-in-the-loop that replaces manual human review.

    GenAI receives the detection details and decides:
    - Is the classification correct?
    - If not, what's the correct label?
    - Why? (reasoning for audit trail)

    Returns summary of validations performed.
    """
    from core.ai_engine import ask_ai

    # Get unverified detections
    pending = get_pending_reviews(count)
    if not pending:
        return {"status": "ok", "validated": 0,
                "message": "No pending detections to validate"}

    # Build a batch prompt for GenAI — more efficient than one-by-one
    detection_descriptions = []
    for i, det in enumerate(pending):
        detection_descriptions.append(
            f"Detection #{i+1} (ID: {det.get('detection_id','?')}):\n"
            f"  Source: {det.get('src_ip','?')} → Dest: {det.get('dst_ip','?')}:{det.get('dst_port','?')}\n"
            f"  Protocol: {det.get('protocol','?')}, Size: {det.get('packet_size','?')} bytes\n"
            f"  ML Prediction: {det.get('ml_prediction','?')}\n"
            f"  Flow Analysis: {det.get('flow_prediction','?')}\n"
            f"  Final Classification: {det.get('final_classification','?')}\n"
            f"  Confidence: {det.get('confidence','?')}\n"
            f"  Detection Method: {det.get('detection_method','?')}"
        )

    prompt = f"""You are a senior SOC analyst validating automated threat detections.
The AEGIS-AI SIEM has detected the following network threats. For each one,
determine if the classification is CORRECT or needs CORRECTION.

KNOWN ATTACK TYPES: {', '.join(sorted(KNOWN_PATTERNS))}
If the pattern doesn't match any known type, classify as ANOMALY.

DETECTIONS TO VALIDATE:
{chr(10).join(detection_descriptions)}

For EACH detection, respond with EXACTLY this JSON format:
{{
  "validations": [
    {{
      "detection_id": "the ID from above",
      "original_label": "what the system classified it as",
      "verified_label": "correct label (same if correct, different if wrong)",
      "is_correct": true/false,
      "reasoning": "brief explanation why this is correct or what it should be"
    }}
  ]
}}

VALIDATION GUIDELINES:
- PORT_SCAN: one IP hitting many different destination ports (8+ unique ports)
- BRUTE_FORCE: many connections to SAME service port (SSH:22, FTP:21, MySQL:3306)
- DDOS: massive packet volume from many sources to one destination (200+ packets)
- DOS: high volume from single source (SYN flood, 30+ SYN packets)
- INFILTRATION: connections to known exploit/backdoor ports (1524, 6200, 6667, 3632)
- SQL_INJECTION: HTTP traffic with SQL patterns in URL parameters
- WEB_ATTACK: malicious HTTP requests (XSS, path traversal, etc.)
- NORMAL: legitimate traffic that was incorrectly flagged

Return ONLY valid JSON. No markdown, no explanation outside the JSON.
"""

    try:
        raw_response = ask_ai(prompt, json_mode=True)

        # Parse GenAI response
        import re
        cleaned = raw_response.strip()
        cleaned = re.sub(r'^```json\s*', '', cleaned)
        cleaned = re.sub(r'^```\s*', '', cleaned)
        cleaned = re.sub(r'\s*```$', '', cleaned)
        result = json.loads(cleaned)

        validations = result.get("validations", [])
        applied = 0
        corrected = 0

        for v in validations:
            det_id = v.get("detection_id", "")
            verified_label = v.get("verified_label", "")
            reasoning = v.get("reasoning", "")
            is_correct = v.get("is_correct", True)

            if det_id and verified_label:
                submit_feedback(
                    detection_id=det_id,
                    verified_label=verified_label,
                    verified_by="genai",
                    reasoning=reasoning
                )
                applied += 1
                if not is_correct:
                    corrected += 1

        _update_stats("genai_validations")

        return {
            "status": "ok",
            "validated": applied,
            "corrected": corrected,
            "confirmed": applied - corrected,
            "message": (f"GenAI validated {applied} detections: "
                        f"{applied - corrected} confirmed, {corrected} corrected")
        }

    except Exception as e:
        return {"status": "error", "validated": 0,
                "message": f"GenAI validation failed: {str(e)[:200]}"}


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTION — flags unknown/suspicious patterns
# ─────────────────────────────────────────────────────────────────────────────

def _check_and_log_anomaly(detection: dict, detection_id: str):
    """
    Flags detections that don't match known patterns.
    These could be zero-day attacks or novel techniques.
    """
    classification = detection.get("classification", "UNKNOWN")
    ml_label = detection.get("ml_label", "UNKNOWN")
    confidence = detection.get("confidence", 0.0)

    is_anomaly = False
    reason = ""

    # ML model and flow analysis disagree — conflicting signals
    if (classification != ml_label and
            classification != "NORMAL" and ml_label != "NORMAL"):
        is_anomaly = True
        reason = (f"ML predicted {ml_label} but flow analysis detected "
                  f"{classification} — conflicting signals, possible novel pattern")

    # Low confidence on a threat — model is uncertain
    elif confidence < 0.5 and classification != "NORMAL":
        is_anomaly = True
        reason = (f"Low confidence ({confidence:.2f}) on {classification} — "
                  f"model uncertain, may be unknown attack variant")

    # Unknown classification type
    elif classification not in KNOWN_PATTERNS and classification != "NORMAL":
        is_anomaly = True
        reason = f"Unknown classification '{classification}' — not in training data"

    if is_anomaly:
        anomaly_entry = {
            "detection_id":   detection_id,
            "timestamp":      detection.get("timestamp", datetime.now().isoformat()),
            "classification": classification,
            "ml_label":       ml_label,
            "confidence":     confidence,
            "src_ip":         detection.get("src", ""),
            "dst_ip":         detection.get("dst", ""),
            "dst_port":       detection.get("port", 0),
            "reason":         reason,
            "status":         "PENDING_REVIEW",
        }

        with _anomaly_lock:
            anomalies = _load_anomalies()
            anomalies.append(anomaly_entry)
            anomalies = anomalies[-500:]  # keep last 500
            with open(ANOMALY_LOG, "w") as f:
                json.dump(anomalies, f, indent=2)

        _update_stats("anomalies_detected")


def _load_anomalies() -> list:
    if os.path.exists(ANOMALY_LOG):
        try:
            with open(ANOMALY_LOG, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return []
    return []


# ─────────────────────────────────────────────────────────────────────────────
# FEEDBACK SUBMISSION — works for both GenAI and human review
# ─────────────────────────────────────────────────────────────────────────────

def submit_feedback(detection_id: str, verified_label: str,
                    verified_by: str = "human", reasoning: str = "",
                    notes: str = "") -> dict:
    """
    Submits a verified label for a detection.
    Can be called by GenAI auto-validation or human analyst.

    verified_by: "genai" or "human"
    """
    if verified_label not in KNOWN_PATTERNS and verified_label != "ANOMALY":
        KNOWN_PATTERNS.add(verified_label)

    with _feedback_lock:
        if not os.path.exists(FEEDBACK_CSV):
            return {"status": "error", "message": "No feedback data exists yet"}

        rows = []
        updated = False
        original_label = ""

        with open(FEEDBACK_CSV, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("detection_id") == detection_id and not updated:
                    original_label = row.get("final_classification", "")
                    row["verified_label"] = verified_label
                    row["verified_by"] = verified_by
                    row["verification_timestamp"] = datetime.now().isoformat()
                    row["verification_reasoning"] = reasoning
                    row["notes"] = notes
                    updated = True
                rows.append(row)

        if not updated:
            return {"status": "error",
                    "message": f"Detection {detection_id} not found"}

        with open(FEEDBACK_CSV, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FEEDBACK_COLUMNS)
            writer.writeheader()
            writer.writerows(rows)

    correction_needed = (original_label != verified_label)

    if verified_by == "genai":
        _update_stats("genai_reviews")
    else:
        _update_stats("human_reviews")
    if correction_needed:
        _update_stats("corrections_made")

    return {
        "status": "ok",
        "detection_id": detection_id,
        "original_label": original_label,
        "verified_label": verified_label,
        "verified_by": verified_by,
        "correction_needed": correction_needed,
    }


# ─────────────────────────────────────────────────────────────────────────────
# QUERIES — for dashboard and API
# ─────────────────────────────────────────────────────────────────────────────

def get_pending_reviews(count: int = 20) -> list:
    """Returns detections not yet verified (by GenAI or human)."""
    if not os.path.exists(FEEDBACK_CSV):
        return []

    pending = []
    with open(FEEDBACK_CSV, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not row.get("verified_label"):
                pending.append(row)

    return list(reversed(pending[-count:]))


def get_feedback_stats() -> dict:
    """Returns learning pipeline statistics."""
    stats = _load_stats()

    total_logged = 0
    verified = 0
    genai_verified = 0
    human_verified = 0
    corrections = 0
    label_distribution = Counter()

    if os.path.exists(FEEDBACK_CSV):
        with open(FEEDBACK_CSV, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                total_logged += 1
                if row.get("verified_label"):
                    verified += 1
                    if row.get("verified_by") == "genai":
                        genai_verified += 1
                    else:
                        human_verified += 1
                    if row.get("verified_label") != row.get("final_classification"):
                        corrections += 1
                label_distribution[row.get("final_classification", "UNKNOWN")] += 1

    anomaly_count = len(_load_anomalies())

    return {
        "total_detections_logged": total_logged,
        "verified_total":          verified,
        "genai_verified":          genai_verified,
        "human_verified":          human_verified,
        "corrections_made":        corrections,
        "pending_review":          total_logged - verified,
        "anomalies_detected":      anomaly_count,
        "label_distribution":      dict(label_distribution),
        "model_accuracy":          99.61,
        "samples_for_retrain":     verified,
        "retrain_ready":           verified >= 50,
        "retrain_threshold":       50,
        "last_updated":            stats.get("last_updated", "never"),
    }


def get_anomalies(count: int = 20) -> list:
    """Returns recent anomaly detections."""
    anomalies = _load_anomalies()
    return list(reversed(anomalies[-count:]))


# ─────────────────────────────────────────────────────────────────────────────
# TRAINING DATA EXPORT — for model retraining
# ─────────────────────────────────────────────────────────────────────────────

def export_training_data() -> dict:
    """Exports verified feedback as training data for retraining."""
    if not os.path.exists(FEEDBACK_CSV):
        return {"status": "error", "message": "No feedback data available"}

    export_path = os.path.join(_BASE_DIR, "ml_models", "verified_feedback.csv")

    verified_rows = []
    with open(FEEDBACK_CSV, "r", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row.get("verified_label"):
                verified_rows.append({
                    "timestamp":      row["timestamp"],
                    "src_ip":         row["src_ip"],
                    "dst_ip":         row["dst_ip"],
                    "dst_port":       row["dst_port"],
                    "protocol":       row["protocol"],
                    "packet_size":    row["packet_size"],
                    "original_label": row["final_classification"],
                    "correct_label":  row["verified_label"],
                    "verified_by":    row["verified_by"],
                    "confidence":     row["confidence"],
                })

    if not verified_rows:
        return {"status": "error", "message": "No verified feedback to export"}

    export_cols = list(verified_rows[0].keys())
    with open(export_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=export_cols)
        writer.writeheader()
        writer.writerows(verified_rows)

    return {
        "status":        "ok",
        "export_path":   export_path,
        "total_samples": len(verified_rows),
        "label_distribution": dict(Counter(
            r["correct_label"] for r in verified_rows)),
        "message": f"Exported {len(verified_rows)} verified samples for retraining"
    }


# ─────────────────────────────────────────────────────────────────────────────
# STATISTICS TRACKING
# ─────────────────────────────────────────────────────────────────────────────

def _load_stats() -> dict:
    if os.path.exists(LEARNING_STATS):
        try:
            with open(LEARNING_STATS, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return {
        "detections_logged": 0, "anomalies_detected": 0,
        "genai_reviews": 0, "genai_validations": 0,
        "human_reviews": 0, "corrections_made": 0,
        "retrains_completed": 0, "last_updated": "never",
    }


def _update_stats(field: str):
    try:
        stats = _load_stats()
        stats[field] = stats.get(field, 0) + 1
        stats["last_updated"] = datetime.now().isoformat()
        with open(LEARNING_STATS, "w") as f:
            json.dump(stats, f, indent=2)
    except Exception:
        pass

def sync_from_redis() -> dict:
    """
    Reads recent threat alerts from Redis and logs them to feedback CSV.
    Maps Redis field names to feedback format.
    """
    try:
        import redis
        r = redis.Redis(host='localhost', port=6379, db=1, decode_responses=True)
        raw = r.lrange("aegis:siem:recent_alerts", 0, 99)

        if not raw:
            return {"status": "ok", "synced": 0, "message": "No alerts to sync"}

        synced = 0
        for item in raw:
            try:
                alert = json.loads(item)

                # Map Redis field names to feedback format
                detection = {
                    "timestamp":      alert.get("timestamp", ""),
                    "src":            alert.get("source", alert.get("src", "")),
                    "dst":            alert.get("destination", alert.get("dst", "")),
                    "port":           alert.get("dst_port", alert.get("port", 0)),
                    "protocol":       alert.get("protocol_name", alert.get("protocol", "")),
                    "packet_size":    alert.get("size", alert.get("packet_size", 0)),
                    "classification": alert.get("ml_class", alert.get("alert", "UNKNOWN")),
                    "ml_label":       alert.get("ml_class", "UNKNOWN"),
                    "confidence":     alert.get("confidence", 0.85),
                    "severity":       alert.get("severity", "LOW"),
                    "detection_method": alert.get("detection_method", "hybrid"),
                    "is_threat":      alert.get("is_threat", True),
                }

                if not _is_already_logged(detection):
                    log_detection(detection)
                    synced += 1
            except (json.JSONDecodeError, Exception):
                continue

        return {"status": "ok", "synced": synced,
                "message": f"Synced {synced} alerts from Redis to training data"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


def _is_already_logged(detection: dict) -> bool:
    """Checks if this detection is already in the feedback CSV."""
    if not os.path.exists(FEEDBACK_CSV):
        return False

    ts = detection.get("timestamp", "")
    port = str(detection.get("port", detection.get("dst_port", "")))

    try:
        with open(FEEDBACK_CSV, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("timestamp") == ts and str(row.get("dst_port")) == port:
                    return True
    except Exception:
        pass
    return False        