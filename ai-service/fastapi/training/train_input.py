"""Train the input-risk model -> models/input.joblib (10 §IR).

    python -m training.train_input

1. Hold out 25 % of the template families of every class, fit, and measure on those unseen shapes and on the
   hand-written hard set. Metrics go to reports/input_metrics.json (read by training.evaluate --check).
2. Refit on all generated rows and save the pipeline. The hard set is never trained on.
"""
import json
import math
import os
import random
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from app.preprocess import normalise
from training.metrics import CUSTOMER_SET, LABELS, load_hard_set, summarise

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
DATA = os.path.join(ROOT, "data", "processed", "inputs.csv")
MODEL = os.path.join(ROOT, "models", "input.joblib")
METRICS = os.path.join(ROOT, "reports", "input_metrics.json")
VERSION = "v2"


def build() -> Pipeline:
    return Pipeline([
        ("feats", FeatureUnion([
            ("char", TfidfVectorizer(analyzer="char", ngram_range=(1, 5), min_df=2, sublinear_tf=True,
                                     max_features=60000, preprocessor=normalise, lowercase=False)),
            ("word", TfidfVectorizer(token_pattern=r"[^\s]+", ngram_range=(1, 2), min_df=2, sublinear_tf=True,
                                     preprocessor=normalise, lowercase=False)),
        ])),
        ("clf", LogisticRegression(max_iter=3000, C=4.0, class_weight="balanced")),
    ])


def family_split(df: pd.DataFrame, frac=0.25, seed=0):
    r = random.Random(seed)
    test_fams = set()
    for label in LABELS:
        fams = sorted(df.loc[df.label == label, "family"].unique())
        r.shuffle(fams)
        test_fams.update(fams[:max(1, math.ceil(len(fams) * frac))])
    mask = df.family.isin(test_fams)
    return df[~mask], df[mask], sorted(test_fams)


def main():
    df = pd.read_csv(DATA, keep_default_na=False)
    train, test, test_fams = family_split(df)
    print(f"train {len(train)} rows / test {len(test)} rows from {len(test_fams)} held-out families")

    pipe = build()
    t0 = time.time()
    pipe.fit(train.value.tolist(), train.label.tolist())
    print(f"fit in {time.time() - t0:.1f}s")
    held = summarise(pipe, test.value.tolist(), test.label.tolist())
    held_model_only = summarise(pipe, test.value.tolist(), test.label.tolist(), fast_path=False)
    hv, hl = load_hard_set()
    hard = summarise(pipe, hv, hl)
    hard_model_only = summarise(pipe, hv, hl, fast_path=False)

    final = build()
    final.fit(df.value.tolist(), df.label.tolist())
    os.makedirs(os.path.dirname(MODEL), exist_ok=True)
    joblib.dump({"pipeline": final, "version": VERSION, "labels": list(final.classes_),
                 "trained_rows": len(df), "sklearn": sklearn.__version__}, MODEL)
    final_hard = summarise(final, hv, hl)
    cv, cl = load_hard_set(CUSTOMER_SET)
    customer = summarise(pipe, cv, cl)          # hold-out model: customer text it never saw
    final_customer = summarise(final, cv, cl)

    metrics = {"version": VERSION, "trained_rows": len(df), "held_out_families": test_fams,
               "family_holdout": held, "family_holdout_model_only": held_model_only,
               "hard_set_holdout_model": hard, "hard_set_holdout_model_only": hard_model_only,
               "hard_set_final_model": final_hard, "customer_set_holdout_model": customer,
               "customer_set_final_model": final_customer}
    os.makedirs(os.path.dirname(METRICS), exist_ok=True)
    with open(METRICS, "w", encoding="utf-8") as fh:
        json.dump(metrics, fh, indent=2)
    for name, m in (("family hold-out", held), ("  (model only)", held_model_only),
                    ("hard set (hold-out model)", hard), ("  (model only)", hard_model_only),
                    ("hard set (final model)", final_hard), ("customer set (hold-out model)", customer),
                    ("customer set (final model)", final_customer)):
        print(f"{name:28s} recall@0.5={m['attack_recall_at_0.5']:.3f} recall@0.8={m['attack_recall_at_0.8']:.3f} "
              f"precision@0.8={m['attack_precision_at_0.8']:.3f} normal FPR@0.5={m['normal_fpr_at_0.5']:.3f} "
              f"macro F1={m['macro_f1']:.3f}")
    print(f"saved {os.path.relpath(MODEL, ROOT)} ({os.path.getsize(MODEL) // 1024} KB)")


if __name__ == "__main__":
    np.random.seed(0)
    main()
