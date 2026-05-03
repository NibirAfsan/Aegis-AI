#!/usr/bin/env python3
"""
AEGIS retrain_model.py
=======================
Dynamic model retraining script.

USAGE:
  python retrain_model.py                 # show learning status
  python retrain_model.py --export        # export verified feedback for Colab
  python retrain_model.py --validate      # run GenAI auto-validation now

WORKFLOW:
  Daily:    Listener detects → GenAI validates → feedback saved (automatic)
  Monthly:  Upload verified_feedback.csv to Colab → retrain → deploy new model
"""

import os
import sys
import json
import csv
from collections import Counter

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(BASE_DIR, "ml_models")
FEEDBACK_CSV = os.path.join(ML_DIR, "training_feedback.csv")
STATS_FILE = os.path.join(ML_DIR, "learning_stats.json")


def show_status():
    """Displays current learning pipeline status."""
    print("=" * 60)
    print("  AEGIS-AI DYNAMIC LEARNING STATUS")
    print("=" * 60)

    if not os.path.exists(FEEDBACK_CSV):
        print("\n  No feedback data yet.")
        print("  Run listener + scan to generate detections.")
        return

    total = verified = genai = human = corrections = 0
    labels = Counter()

    with open(FEEDBACK_CSV, "r", newline="") as f:
        for row in csv.DictReader(f):
            total += 1
            if row.get("verified_label"):
                verified += 1
                if row.get("verified_by") == "genai":
                    genai += 1
                else:
                    human += 1
                if row.get("verified_label") != row.get("final_classification"):
                    corrections += 1
                labels[row["verified_label"]] += 1
            else:
                labels[row.get("final_classification", "?")] += 1

    anomaly_count = 0
    anomaly_path = os.path.join(ML_DIR, "anomaly_detections.json")
    if os.path.exists(anomaly_path):
        with open(anomaly_path) as f:
            anomaly_count = len(json.load(f))

    print(f"\n  Detections logged:     {total}")
    print(f"  Verified (total):      {verified}")
    print(f"    - by GenAI:          {genai}")
    print(f"    - by human:          {human}")
    print(f"  Corrections made:      {corrections}")
    print(f"  Pending review:        {total - verified}")
    print(f"  Anomalies flagged:     {anomaly_count}")

    print(f"\n  Label distribution:")
    for label, count in sorted(labels.items(), key=lambda x: -x[1]):
        print(f"    {label:20s}  {count}")

    summary_path = os.path.join(ML_DIR, "model_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path) as f:
            info = json.load(f)
        print(f"\n  Current model accuracy:  {info.get('accuracy', 0)*100:.2f}%")
        print(f"  Training samples:        {info.get('total_samples', 0):,}")
        print(f"  Retrains completed:      {info.get('retrain_count', 0)}")

    ready = verified >= 50
    print(f"\n  Retrain ready: {'YES' if ready else 'NO'}")
    if not ready:
        print(f"  Need {50 - verified} more verified samples")
    print("=" * 60)


def export_feedback():
    """Exports verified feedback for Colab retraining."""
    if not os.path.exists(FEEDBACK_CSV):
        print("[!] No feedback data.")
        return

    export_path = os.path.join(ML_DIR, "verified_feedback.csv")
    rows = []
    with open(FEEDBACK_CSV, "r", newline="") as f:
        for row in csv.DictReader(f):
            if row.get("verified_label"):
                rows.append(row)

    if not rows:
        print("[!] No verified feedback to export.")
        return

    with open(export_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)

    print(f"[+] Exported {len(rows)} verified samples to {export_path}")
    print(f"[+] Upload this file to Google Colab for full retraining.")


def run_genai_validation():
    """Triggers GenAI auto-validation of pending detections."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'aegis_web.settings')

    try:
        import django
        django.setup()
        from core.feedback_engine import genai_validate_detections

        print("[+] Running GenAI auto-validation...")
        result = genai_validate_detections(count=20)
        print(f"[+] Result: {result.get('message', 'Unknown')}")
        print(f"    Validated: {result.get('validated', 0)}")
        print(f"    Confirmed: {result.get('confirmed', 0)}")
        print(f"    Corrected: {result.get('corrected', 0)}")

    except Exception as e:
        print(f"[!] GenAI validation failed: {e}")
        print("    Make sure Django and Gemini API are configured.")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AEGIS-AI Dynamic Learning")
    parser.add_argument("--export", action="store_true",
                        help="Export verified feedback for Colab")
    parser.add_argument("--validate", action="store_true",
                        help="Run GenAI auto-validation now")
    args = parser.parse_args()

    if args.export:
        export_feedback()
    elif args.validate:
        run_genai_validation()
    else:
        show_status()