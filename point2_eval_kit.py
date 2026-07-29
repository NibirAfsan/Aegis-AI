#!/usr/bin/env python3
"""
=============================================================================
AEGIS-AI  —  Point 2 Evaluation Kit
GenAI Validation Accuracy vs Human-Verified Ground Truth
=============================================================================

WHAT THIS DOES (Point 2):
  Measures how accurately the GenAI validation layer judges detections,
  by comparing GenAI's verdicts against YOUR human-verified labels, and
  reports precise Precision, Recall, and F1-score.

THIS IS A REAL EXPERIMENT. The numbers it produces come from your actual
system and your own labelling. Nothing is invented.

=============================================================================
HOW TO USE  —  three simple stages
=============================================================================

  STAGE 1  — Collect detections (build up the sample)
  STAGE 2  — You hand-label a subset as ground truth
  STAGE 3  — Script compares GenAI vs your labels -> Precision/Recall/F1

Run each stage with:
    python3 point2_eval_kit.py 1      # stage 1: show status / collect
    python3 point2_eval_kit.py 2      # stage 2: create labelling sheet
    python3 point2_eval_kit.py 3      # stage 3: compute metrics

=============================================================================
"""

import os
import csv
import sys
import json
from collections import Counter, defaultdict

# ----------------------------------------------------------------------------
# Paths — adjust only if your layout differs
# ----------------------------------------------------------------------------
BASE = os.path.dirname(os.path.abspath(__file__))
ML_DIR = os.path.join(BASE, "ml_models")
FEEDBACK_CSV = os.path.join(ML_DIR, "training_feedback.csv")     # source detections
GROUND_TRUTH_CSV = os.path.join(ML_DIR, "ground_truth_labels.csv")  # you fill this
RESULTS_JSON = os.path.join(ML_DIR, "point2_results.json")

KNOWN = ["PORT_SCAN", "BRUTE_FORCE", "DOS", "DDOS", "INFILTRATION",
         "SQL_INJECTION", "WEB_ATTACK", "BOTNET", "HEARTBLEED", "NORMAL", "ANOMALY"]

# How many to hand-label as ground truth
GROUND_TRUTH_TARGET = 100


# ============================================================================
# STAGE 1 — status of collected detections
# ============================================================================
def stage1_status():
    print("\n" + "="*70)
    print("STAGE 1 — DETECTION COLLECTION STATUS")
    print("="*70)

    if not os.path.exists(FEEDBACK_CSV):
        print("\n[!] No training_feedback.csv found yet.")
        print("    Generate detections first: run your listener + launch attacks")
        print("    against your lab (Metasploitable2 / DVWA), then trigger")
        print("    GenAI validation from the dashboard as usual.")
        return

    total = 0
    genai_validated = 0
    with open(FEEDBACK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            total += 1
            if row.get("verified_by") == "genai" and row.get("verified_label"):
                genai_validated += 1

    print(f"\n  Total detections logged:        {total}")
    print(f"  GenAI-validated detections:     {genai_validated}")
    print(f"\n  Target for a strong result:     ~300 total")
    print(f"  Ground-truth labels to create:  ~{GROUND_TRUTH_TARGET}")

    if genai_validated < 100:
        need = 300 - total
        print(f"\n  -> Collect more: generate ~{max(need,0)} more detections by")
        print(f"     running additional attack rounds, then GenAI-validate them.")
    else:
        print(f"\n  -> You have enough. Proceed to STAGE 2:  python3 {os.path.basename(__file__)} 2")


# ============================================================================
# STAGE 2 — create a labelling sheet for YOU to fill in
# ============================================================================
def stage2_make_sheet():
    print("\n" + "="*70)
    print("STAGE 2 — CREATE GROUND-TRUTH LABELLING SHEET")
    print("="*70)

    if not os.path.exists(FEEDBACK_CSV):
        print("\n[!] No detections found. Do STAGE 1 first.")
        return

    # Load all GenAI-validated detections
    rows = []
    with open(FEEDBACK_CSV, newline="") as f:
        for row in csv.DictReader(f):
            if row.get("verified_by") == "genai" and row.get("verified_label"):
                rows.append(row)

    if len(rows) < 10:
        print(f"\n[!] Only {len(rows)} GenAI-validated detections found.")
        print("    Generate + validate more before labelling.")
        return

    # Take a representative sample spread across the data (up to target)
    import random
    random.seed(42)  # reproducible sample
    sample = rows if len(rows) <= GROUND_TRUTH_TARGET else random.sample(rows, GROUND_TRUTH_TARGET)

    # Write a sheet with everything EXCEPT hiding GenAI's verdict from your view.
    # You fill in 'human_label' by examining the detection details yourself.
    cols = ["detection_id", "src_ip", "dst_ip", "dst_port", "protocol",
            "packet_size", "ml_prediction", "flow_prediction",
            "final_classification", "genai_verified_label",
            "human_label_FILL_THIS_IN"]

    with open(GROUND_TRUTH_CSV, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        for r in sample:
            w.writerow({
                "detection_id":          r.get("detection_id",""),
                "src_ip":                r.get("src_ip",""),
                "dst_ip":                r.get("dst_ip",""),
                "dst_port":              r.get("dst_port",""),
                "protocol":              r.get("protocol",""),
                "packet_size":           r.get("packet_size",""),
                "ml_prediction":         r.get("ml_prediction",""),
                "flow_prediction":       r.get("flow_prediction",""),
                "final_classification":  r.get("final_classification",""),
                "genai_verified_label":  r.get("verified_label",""),
                "human_label_FILL_THIS_IN": "",
            })

    print(f"\n  Created labelling sheet: {GROUND_TRUTH_CSV}")
    print(f"  Rows to label: {len(sample)}")
    print(f"""
  NOW DO THIS:
  1. Open ground_truth_labels.csv (in Excel / LibreOffice / any editor)
  2. For EACH row, look at the detection details (ports, protocol, size,
     ML + flow predictions) and decide the CORRECT label yourself.
     Use the same categories: {', '.join(KNOWN)}
  3. Type your decision in the 'human_label_FILL_THIS_IN' column.
     - Judge independently. It's fine if you agree OR disagree with GenAI.
       (Disagreements are what make the metric meaningful.)
  4. Save the file.
  5. Then run:  python3 {os.path.basename(__file__)} 3
""")
    print("  LABELLING GUIDE (same rules the system uses):")
    print("    PORT_SCAN     one IP -> many ports (8+)")
    print("    BRUTE_FORCE   many hits -> ONE service port (22/21/3306)")
    print("    DOS           high volume from ONE source (30+ SYN)")
    print("    DDOS          huge volume, many sources -> one dst (200+)")
    print("    INFILTRATION  connection to backdoor port (1524/6200/6667/3632)")
    print("    SQL_INJECTION HTTP with SQL patterns in URL")
    print("    WEB_ATTACK    malicious HTTP (XSS, traversal)")
    print("    NORMAL        legitimate traffic wrongly flagged")
    print("    ANOMALY       doesn't match any known pattern")


# ============================================================================
# STAGE 3 — compute Precision / Recall / F1  (GenAI vs your ground truth)
# ============================================================================
def stage3_metrics():
    print("\n" + "="*70)
    print("STAGE 3 — GENAI VALIDATION ACCURACY vs HUMAN GROUND TRUTH")
    print("="*70)

    if not os.path.exists(GROUND_TRUTH_CSV):
        print("\n[!] No ground_truth_labels.csv found. Do STAGE 2 first.")
        return

    pairs = []  # (human_label, genai_label)
    unlabelled = 0
    with open(GROUND_TRUTH_CSV, newline="") as f:
        for row in csv.DictReader(f):
            human = (row.get("human_label_FILL_THIS_IN") or "").strip().upper()
            genai = (row.get("genai_verified_label") or "").strip().upper()
            if not human:
                unlabelled += 1
                continue
            pairs.append((human, genai))

    if unlabelled:
        print(f"\n[!] {unlabelled} rows still have no human label — skipped.")
        print("    Fill them in for a complete result (or proceed with what you have).")

    n = len(pairs)
    if n == 0:
        print("\n[!] No labelled rows found. Fill in the human_label column first.")
        return

    # -------- Overall agreement (this is GenAI's validation accuracy) --------
    agree = sum(1 for h, g in pairs if h == g)
    overall_acc = agree / n

    # -------- Per-class Precision / Recall / F1 --------
    # Treat HUMAN label as ground truth, GENAI label as the prediction.
    labels = sorted(set([h for h, _ in pairs] + [g for _, g in pairs]))
    tp = defaultdict(int); fp = defaultdict(int); fn = defaultdict(int)

    for h, g in pairs:
        for lbl in labels:
            if g == lbl and h == lbl: tp[lbl] += 1
            elif g == lbl and h != lbl: fp[lbl] += 1
            elif g != lbl and h == lbl: fn[lbl] += 1

    def prf(lbl):
        p = tp[lbl] / (tp[lbl] + fp[lbl]) if (tp[lbl] + fp[lbl]) else 0.0
        r = tp[lbl] / (tp[lbl] + fn[lbl]) if (tp[lbl] + fn[lbl]) else 0.0
        f = 2*p*r / (p + r) if (p + r) else 0.0
        support = sum(1 for h, _ in pairs if h == lbl)
        return p, r, f, support

    # -------- Macro + weighted averages --------
    per_class = {}
    macro_p = macro_r = macro_f = 0.0
    wsum_p = wsum_r = wsum_f = 0.0
    total_support = 0
    present = [l for l in labels if sum(1 for h,_ in pairs if h==l) > 0]

    for lbl in present:
        p, r, f, sup = prf(lbl)
        per_class[lbl] = {"precision": p, "recall": r, "f1": f, "support": sup}
        macro_p += p; macro_r += r; macro_f += f
        wsum_p += p*sup; wsum_r += r*sup; wsum_f += f*sup
        total_support += sup

    k = len(present)
    macro = {"precision": macro_p/k, "recall": macro_r/k, "f1": macro_f/k}
    weighted = {"precision": wsum_p/total_support,
                "recall": wsum_r/total_support,
                "f1": wsum_f/total_support}

    # -------- Print results --------
    print(f"\n  Sample size (human-labelled):   {n}")
    print(f"  GenAI–human agreement:          {agree}/{n}  =  {overall_acc*100:.1f}%")
    print(f"\n  {'Class':<15}{'Precision':>10}{'Recall':>10}{'F1':>10}{'Support':>9}")
    print("  " + "-"*54)
    for lbl in present:
        m = per_class[lbl]
        print(f"  {lbl:<15}{m['precision']:>10.3f}{m['recall']:>10.3f}"
              f"{m['f1']:>10.3f}{m['support']:>9}")
    print("  " + "-"*54)
    print(f"  {'Macro avg':<15}{macro['precision']:>10.3f}{macro['recall']:>10.3f}{macro['f1']:>10.3f}")
    print(f"  {'Weighted avg':<15}{weighted['precision']:>10.3f}{weighted['recall']:>10.3f}{weighted['f1']:>10.3f}")

    # -------- Save for the paper --------
    results = {
        "sample_size": n,
        "genai_human_agreement": overall_acc,
        "per_class": per_class,
        "macro_avg": macro,
        "weighted_avg": weighted,
    }
    with open(RESULTS_JSON, "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n  Saved: {RESULTS_JSON}")
    print(f"""
  ============================================================
  WHAT TO TELL CLAUDE:
  Paste the table above (or the contents of point2_results.json).
  Claude will turn it into a paper-ready paragraph + table for
  Section VII, replacing the '100 detections' text with real
  Precision/Recall/F1 numbers.
  ============================================================
""")


# ============================================================================
def main():
    stage = sys.argv[1] if len(sys.argv) > 1 else "1"
    if stage == "1":   stage1_status()
    elif stage == "2": stage2_make_sheet()
    elif stage == "3": stage3_metrics()
    else:
        print("Usage: python3 point2_eval_kit.py [1|2|3]")
        print("  1 = check collection status")
        print("  2 = create ground-truth labelling sheet")
        print("  3 = compute Precision/Recall/F1")

if __name__ == "__main__":
    main()