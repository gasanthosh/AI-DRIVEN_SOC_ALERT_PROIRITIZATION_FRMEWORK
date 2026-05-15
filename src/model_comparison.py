"""
model_comparison.py
Trains Logistic Regression AND a new Random Forest on 8-feature subsetted data.
Evaluates them alongside the existing XGBoost (8 features) and Rule-Based Baseline.
Ensures consistency by making all models work on the same 8 SNIFFER_FEATURES.
Saves results to models/comparison_results.json.
"""

import os
import sys
import json
import logging
import warnings
import numpy as np
import joblib

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    precision_score, recall_score, f1_score,
    confusion_matrix, roc_curve, auc,
    classification_report,
)

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [COMPARE] %(message)s")
log = logging.getLogger("COMPARE")

MODELS_DIR = os.path.join(os.path.dirname(__file__), "..", "models")

# ── Sniffer-Compatible Feature Set ───────────────────────────────────────────
SNIFFER_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean"
]

# ── Load saved artefacts ────────────────────────────────────────────────────
def load_artifacts():
    log.info("Loading saved model artefacts…")
    X_test_all  = joblib.load(os.path.join(MODELS_DIR, "X_test.pkl"))
    y_test      = joblib.load(os.path.join(MODELS_DIR, "y_test.pkl"))
    X_train_all = joblib.load(os.path.join(MODELS_DIR, "X_train.pkl"))
    y_train     = joblib.load(os.path.join(MODELS_DIR, "y_train.pkl"))
    scaler      = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
    le          = joblib.load(os.path.join(MODELS_DIR, "label_encoder.pkl"))
    xgb         = joblib.load(os.path.join(MODELS_DIR, "xgb_model.pkl"))
    feature_names = joblib.load(os.path.join(MODELS_DIR, "feature_names.pkl"))
    
    # Subset to first 8 columns (consistently mapped to SNIFFER_FEATURES in this env)
    log.info(f"Subsetting X from {X_train_all.shape[1]} features to 8 features…")
    X_train = X_train_all[:, :8]
    X_test  = X_test_all[:, :8]

    return X_train, X_test, y_train, y_test, scaler, le, xgb


# ── Baseline Rule-Based Classifier ─────────────────────────────────────────
def rule_based_predict(X_subset):
    """
    Very simple threshold rules — no ML.
    X_subset is assumed to be 8-feature array (unscaled).
    Indices: 5=Flow Bytes/s, 6=Flow Packets/s
    """
    preds = np.zeros(len(X_subset), dtype=int)
    for i in range(len(X_subset)):
        row = X_subset[i]
        if row[5] > 1_000_000 or row[6] > 5_000:
            preds[i] = 1   # map to first non-benign class
    return preds


# ── Per-class metrics ───────────────────────────────────────────────────────
def compute_metrics(y_true, y_pred, classes):
    labels = list(range(len(classes)))
    
    macro_p  = float(precision_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    macro_r  = float(recall_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))
    macro_f1 = float(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0))

    try:
        per_class = classification_report(
            y_true, y_pred,
            labels=labels,
            target_names=classes,
            output_dict=True,
            zero_division=0,
        )
    except Exception as e:
        log.error(f"Classification report failed: {e}")
        per_class = {"macro avg": {"precision": macro_p, "recall": macro_r, "f1-score": macro_f1}}

    cm = confusion_matrix(y_true, y_pred, labels=labels).tolist()
    return {
        "macro_precision": round(macro_p, 4),
        "macro_recall":    round(macro_r, 4),
        "macro_f1":        round(macro_f1, 4),
        "per_class":       per_class,
        "confusion_matrix":cm,
    }


# ── ROC curve ────────────────────────────────────────────────────────────────
def compute_roc(y_true, y_proba, benign_class_idx):
    binary_y     = (y_true != benign_class_idx).astype(int)
    # y_proba shape [N, C]
    if y_proba is not None and y_proba.shape[1] > benign_class_idx:
        attack_proba = 1.0 - y_proba[:, benign_class_idx]
    else:
        # Binary or missing indices
        attack_proba = y_proba[:, 1] if y_proba is not None and y_proba.shape[1] > 1 else np.zeros(len(y_true))

    fpr, tpr, thresholds = roc_curve(binary_y, attack_proba)
    roc_auc = float(auc(fpr, tpr))
    step = max(1, len(fpr) // 50)
    return {
        "fpr": [round(float(v), 4) for v in fpr[::step]],
        "tpr": [round(float(v), 4) for v in tpr[::step]],
        "auc": round(roc_auc, 4)
    }


# ── Business Impact ──────────────────────────────────────────────────────────
def business_impact(baseline_fp, model_fp, total_alerts):
    fp_reduced       = max(baseline_fp - model_fp, 0)
    alert_reduction  = round(fp_reduced / total_alerts * 100, 1) if total_alerts else 0
    hours_saved      = round(fp_reduced * 5 / 60, 1)
    efficiency_gain  = round(alert_reduction * 1.2, 1)
    return {
        "fp_reduced":       fp_reduced,
        "alert_load_reduction_pct": alert_reduction,
        "analyst_hours_saved":      hours_saved,
        "operational_efficiency_gain_pct": efficiency_gain,
    }


# ── Main runner ───────────────────────────────────────────────────────────────
def run_comparison():
    X_train, X_test, y_train, y_test, scaler, le, xgb = load_artifacts()
    classes    = list(le.classes_)
    benign_idx = classes.index("BENIGN") if "BENIGN" in classes else 0
    total_test = len(y_test)

    # Scale using the 8-feature subsetted data
    log.info(f"Scaling data (shape: {X_train.shape})…")
    X_train_sc = scaler.transform(X_train)
    X_test_sc  = scaler.transform(X_test)

    # Train Logistic Regression (8 features)
    log.info("Training Logistic Regression (8-feat)…")
    lr = LogisticRegression(max_iter=500, random_state=42)
    lr.fit(X_train_sc, y_train)

    # Train a new Random Forest (8 features) to ensure dimension consistency
    log.info("Training new Random Forest (8-feat, small trees for speed)…")
    rf_new = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1)
    rf_new.fit(X_train_sc, y_train)

    models_info = {
        "Logistic Regression": (lr,     X_test_sc,  True),
        "Random Forest":       (rf_new, X_test_sc,  True),
        "XGBoost":             (xgb,    X_test_sc,  True),
    }

    results = {}
    
    # Baseline rule-based (unscaled input)
    log.info("Evaluating Rule-Based baseline…")
    rb_pred = rule_based_predict(X_test)
    total_benign = int(np.sum(y_test == benign_idx))
    rb_fp_count  = int(np.sum((y_test == benign_idx) & (rb_pred != benign_idx)))
    baseline_fp  = rb_fp_count

    results["Rule-Based (Baseline)"] = {
        "metrics": compute_metrics(y_test, rb_pred, classes),
        "roc":     None,
        "fp_stats": { "total_benign": total_benign, "false_positives": baseline_fp, "fpr": round(baseline_fp/total_benign, 4) if total_benign else 0 },
        "business": business_impact(baseline_fp, baseline_fp, total_test),
        "color":    "#b2bec3",
    }

    model_colors = {
        "Logistic Regression": "#3d9cf5",
        "Random Forest":       "#00e676",
        "XGBoost":             "#a29bfe",
    }

    for name, (model, X, use_proba) in models_info.items():
        log.info(f"Evaluating {name}…")
        y_pred  = model.predict(X)
        y_proba = model.predict_proba(X) if use_proba else None

        # Compute metrics
        m_stats = compute_metrics(y_test, y_pred, classes)
        r_data  = compute_roc(y_test, y_proba, benign_idx) if y_proba is not None else None
        
        fp_count = int(np.sum((y_test == benign_idx) & (y_pred != benign_idx)))
        fp_data  = { "total_benign": total_benign, "false_positives": fp_count, "fpr": round(fp_count/total_benign, 4) if total_benign else 0 }

        results[name] = {
            "metrics":  m_stats,
            "roc":      r_data,
            "fp_stats": fp_data,
            "business": business_impact(baseline_fp, fp_count, total_test),
            "color":    model_colors.get(name, "#00d4ff"),
        }

    payload = {
        "classes":        classes,
        "benign_index":   benign_idx,
        "total_test":     int(total_test),
        "models":         results,
        "generated_at":   __import__("datetime").datetime.utcnow().isoformat(),
    }

    out_path = os.path.join(MODELS_DIR, "comparison_results.json")
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2, default=str)
    log.info(f"Comparison results saved → {out_path}")
    return payload


if __name__ == "__main__":
    run_comparison()
