# Model card — input-risk model v1

**What it does:** scores one attacker-typed value (form field, URL parameter, path, login username) from a decoy or the
real-target login log. Output: `risk` 0–1 (= 1 − P(normal)) and a label
(`normal, cmd_injection, sqli, xss, path_traversal`). Used by the Go engine to grade injection findings (07 §4.1).
It never blocks or alerts on its own.

**Algorithm:** char 1–5-gram + word 1–2-gram TF-IDF → Logistic Regression (`C=4`, balanced classes), scikit-learn.
Values are URL-decoded twice and HTML-decoded once first; IPs, long numbers and base64/hex runs are replaced by tokens
(`app/preprocess.py`, shared by training and serving). Plain values (fast path, `is_plain`) get risk 0 without the model.

## Data

| Source | Rows | License |
| --- | --- | --- |
| Our generator `data/generators/inputs.py` + slot lists `slots/inputs.yaml` (team-written) | 7,000 (2,800 normal, 1,050 per attack class), 97 template families | ours |
| Hand-written hard set `data/hard_set.yaml` (test only, never trained on) | 125 | ours |
| Third-party payload lists | none yet | see `data/raw/LICENSES.md` |

## Evaluation

- **Split:** 25 % of the template families of every class held out (shapes never seen in training), then the
  hard set. Final model refit on all generated rows.
- **Results (system = model + fast path):** see `reports/input.md` (regenerate with `python -m training.evaluate`).

| Test | recall @0.5 | recall @0.8 | precision @0.8 | normal FPR @0.5 | macro F1 |
| --- | --- | --- | --- | --- | --- |
| Family hold-out | 0.84 | 0.75 | 1.00 | 0.0 % | 0.86 |
| Hard set (hold-out model) | 0.97 | 0.86 | 1.00 | 5 % | 0.95 |
| Hard set (final model) | 1.00 | 0.87 | 0.99 | 7.5 % | 0.95 |

Latency p95 ≈ 1.5 ms per value on a laptop CPU.

## Known limits

- **Generated data.** Training data comes from our own templates; the hard set was written by the same team, so real
  attacker traffic may differ. A whole technique missing from the generator scores low (0.3–0.7), see the hold-out
  recall at 0.8.
- **English-centric** normal text; other languages are untested.
- **No field context:** the model does not know what a field expects (an email box vs a search box).
- Normal values with SQL-like wording (`Order #4521 -- urgent`, `or maybe tomorrow?`) can score 0.6–0.9.
- Labels describe the *shape* of the input, not the attacker's intent or identity.
