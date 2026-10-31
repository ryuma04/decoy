"""Report and gate the input-risk model (10 §IR).

    python -m training.evaluate           # write reports/input.md
    python -m training.evaluate --check   # also exit 1 if a target is missed

Reads reports/input_metrics.json (written by train_input) and measures latency of the saved model.
"""
import argparse
import json
import os
import sys
import time

from app.input_model import InputModel
from training.metrics import load_hard_set

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
METRICS = os.path.join(ROOT, "reports", "input_metrics.json")
REPORT = os.path.join(ROOT, "reports", "input.md")

# (metric path, comparison, target). Measured for the system as deployed (model + fast path).
TARGETS = [
    (("family_holdout", "attack_precision_at_0.8"), ">=", 0.90),
    (("family_holdout", "normal_fpr_at_0.5"), "<=", 0.02),
    (("family_holdout", "attack_recall_at_0.5"), ">=", 0.80),
    (("hard_set_holdout_model", "attack_recall_at_0.5"), ">=", 0.95),
    (("hard_set_holdout_model", "macro_f1"), ">=", 0.80),
    (("latency", "p95_ms"), "<=", 30.0),
]


def latency(model: InputModel, n=300):
    values, _ = load_hard_set()
    samples = []
    for i in range(n):
        v = values[i % len(values)]
        t0 = time.perf_counter()
        model.classify(v)
        samples.append((time.perf_counter() - t0) * 1000)
    samples.sort()
    return {"p50_ms": round(samples[len(samples) // 2], 2), "p95_ms": round(samples[int(len(samples) * 0.95)], 2)}


def fmt_block(name, m):
    lines = [f"### {name} (n={m['n']}, fast path {'on' if m['fast_path'] else 'off'})", "",
             "| metric | value |", "| --- | --- |"]
    for k in ("attack_recall_at_0.5", "attack_recall_at_0.8", "attack_precision_at_0.8", "normal_fpr_at_0.5", "macro_f1"):
        lines.append(f"| {k} | {m[k]:.3f} |")
    lines += ["", "Per-class F1: " + ", ".join(f"{k} {v:.2f}" for k, v in m["per_class_f1"].items()), "",
              "Confusion (rows = true, cols = predicted, order " + ", ".join(m["confusion"]["labels"]) + "):", "", "```"]
    lines += [" ".join(f"{x:5d}" for x in row) for row in m["confusion"]["matrix"]]
    lines += ["```", "", "Calibration (risk bucket → observed attack rate):", ""]
    lines += [f"- {c['bucket']}: n={c['n']}, mean risk {c['mean_risk']}, attack rate {c['attack_rate']}" for c in m["calibration"]]
    lines.append("")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args()
    with open(METRICS, encoding="utf-8") as fh:
        m = json.load(fh)
    model = InputModel.load()
    m["latency"] = latency(model)

    failed = []
    rows = ["| target | value | required | ok |", "| --- | --- | --- | --- |"]
    for path, op, target in TARGETS:
        value = m[path[0]][path[1]]
        ok = value >= target if op == ">=" else value <= target
        rows.append(f"| {'.'.join(path)} | {value:.3f} | {op} {target} | {'yes' if ok else 'NO'} |")
        if not ok:
            failed.append(".".join(path))

    lines = [f"# Input-risk model report ({m['version']}, {m['trained_rows']} training rows)", "",
             "## Targets", ""] + rows + ["", f"Latency per call: p50 {m['latency']['p50_ms']} ms, p95 {m['latency']['p95_ms']} ms", "",
             "## Held-out template families", "", ", ".join(m["held_out_families"]), ""]
    lines += fmt_block("Family hold-out", m["family_holdout"])
    lines += fmt_block("Family hold-out, model only", m["family_holdout_model_only"])
    lines += fmt_block("Hard set, hold-out model", m["hard_set_holdout_model"])
    lines += fmt_block("Hard set, final model", m["hard_set_final_model"])
    with open(REPORT, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print("\n".join(rows))
    print(f"latency p50 {m['latency']['p50_ms']} ms, p95 {m['latency']['p95_ms']} ms; report: {os.path.relpath(REPORT, ROOT)}")
    if a.check and failed:
        print("FAILED: " + ", ".join(failed))
        sys.exit(1)


if __name__ == "__main__":
    main()
