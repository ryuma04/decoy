"""Metrics shared by train_input and evaluate (targets in 10 §IR)."""
import os

import numpy as np
import yaml
from sklearn.metrics import confusion_matrix, f1_score

from app.preprocess import is_plain

LABELS = ["normal", "cmd_injection", "sqli", "xss", "path_traversal"]
ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
HARD_SET = os.path.join(ROOT, "data", "hard_set.yaml")
CUSTOMER_SET = os.path.join(ROOT, "data", "customer_set.yaml")  # shop-customer text, test only (v2)

TARGETS = {
    "attack_recall_at_0.8": 0.95,      # family hold-out
    "attack_precision_at_0.8": 0.90,   # family hold-out
    "normal_fpr_at_0.5": 0.02,         # family hold-out, maximum
    "hard_macro_f1": 0.80,             # hard set
}


def load_hard_set(path=HARD_SET):
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    values, labels = [], []
    for label, items in data.items():
        values += [str(v) for v in items]
        labels += [label] * len(items)
    return values, labels


def summarise(pipe, values, labels, fast_path=True):
    """Metrics for the system as deployed: plain values (is_plain) get risk 0 without the model."""
    proba = pipe.predict_proba(values)
    classes = list(pipe.classes_)
    risk = 1.0 - proba[:, classes.index("normal")]
    pred = [classes[i] for i in proba.argmax(axis=1)]
    if fast_path:
        for i, v in enumerate(values):
            if is_plain(v):
                risk[i], pred[i] = 0.0, "normal"
    y = np.array(labels)
    attack = y != "normal"
    flagged = risk >= 0.8
    out = {
        "n": len(values),
        "fast_path": fast_path,
        "attack_recall_at_0.5": float((risk[attack] >= 0.5).mean()) if attack.any() else 0.0,
        "attack_recall_at_0.8": float(flagged[attack].mean()) if attack.any() else 0.0,
        "attack_precision_at_0.8": float(attack[flagged].mean()) if flagged.any() else 0.0,
        "normal_fpr_at_0.5": float((risk[~attack] >= 0.5).mean()) if (~attack).any() else 0.0,
        "macro_f1": float(f1_score(y, pred, labels=LABELS, average="macro", zero_division=0)),
        "per_class_f1": dict(zip(LABELS, map(float, f1_score(y, pred, labels=LABELS, average=None, zero_division=0)))),
        "confusion": {"labels": LABELS, "matrix": confusion_matrix(y, pred, labels=LABELS).tolist()},
        "calibration": calibration(risk, attack),
        "errors": [{"value": v, "label": l, "pred": p, "risk": round(float(s), 3)}
                   for v, l, p, s in zip(values, labels, pred, risk)
                   if (l == "normal") != (s < 0.5) or (l != "normal" and p != l)][:40],
    }
    return out


def calibration(risk, attack, bins=5):
    """Per risk bucket: mean predicted risk vs observed attack rate (reliability check)."""
    rows = []
    edges = np.linspace(0, 1, bins + 1)
    for lo, hi in zip(edges[:-1], edges[1:]):
        m = (risk >= lo) & (risk < hi if hi < 1 else risk <= hi)
        if m.any():
            rows.append({"bucket": f"{lo:.1f}-{hi:.1f}", "n": int(m.sum()),
                         "mean_risk": round(float(risk[m].mean()), 3), "attack_rate": round(float(attack[m].mean()), 3)})
    return rows
