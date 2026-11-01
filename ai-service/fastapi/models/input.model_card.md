# Model card — input-risk model v2.1

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
| Our generator `data/generators/inputs.py` + slot lists `slots/inputs.yaml` (team-written) | 9,000 (3,600 normal, 1,350 per attack class), 102 template families — v2 adds 5 shop-customer text families (messages, order notes, delivery notes, reviews, enquiries) | ours |
| Hand-written hard set `data/hard_set.yaml` (test only, never trained on) | 125 | ours |
| Hand-written customer set `data/customer_set.yaml` (test only): 40 real-style shop messages incl. the two live false positives, 22 payloads inside the same fields | 62 | ours |
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

**v1 → v2** (v2 adds shop-customer text as normal data; same algorithm):

| Test | v1 | v2 |
| --- | --- | --- |
| Customer set: harmless messages wrongly flagged (risk ≥ 0.5) | **7 / 40 (17.5 %)** | **0 / 40** |
| Customer set: harmless messages risk ≥ 0.8 (hard divert) | 1 | 0 |
| Customer set: attacks caught @0.5 / @0.8 | 100 % / 100 % | 100 % / 100 % |
| Hard set (final): normal FPR @0.5 | 7.5 % | 2.5 % |
| Hard set (final): errors | 6 | 3 |
| Family hold-out: attack recall @0.5 / @0.8 | 0.84 / 0.75 | 0.90 / 0.82 |
| Family hold-out: macro F1 | 0.86 | 0.90 |

Remaining v2 errors on the hard set: `SELECT * menu specials` (normal, risk 0.60), `z; history | tail -5` (cmd injection,
risk 0.42), `../../../home/deploy/.bash_history` (labelled cmd injection instead of path traversal). The v1 model is
kept at `models/input.v1.joblib` for comparison.

**v2 → v2.1** (SQL injection was the weakest class on unseen shapes): SQLi templates went from 3–12 to 9–21 per
family, plus a new `sqli:in_text` family (payload after normal shop text, as it arrives in a form field), plus a few
normal customer phrases starting with "or…". Measured with leave-one-family-out (`python -m training.lofo`: train
without one SQLi family, test on it, for every family), which does not depend on the random hold-out:

| Unseen SQLi family caught | v2 | v2.1 |
| --- | --- | --- |
| risk ≥ 0.5 (all families, weighted) | 78.1 % | **94.4 %** |
| risk ≥ 0.8 (hard divert) | 58.9 % | **84.7 %** |
| scored "normal" (missed) | 21.9 % | **5.6 %** |
| worst family (union) | 50.9 % | 100 % |

| Other tests | v2 | v2.1 |
| --- | --- | --- |
| Hard set, hold-out model: attacks @0.5 / normal FPR | 96.5 % / 2.5 % | 97.6 % / 0 % |
| Hard set, final model: errors / macro F1 | 3 / 0.977 | 2 / 0.985 |
| Customer set, final model: normal FPR / attacks @0.5 | 0 % / 100 % | 0 % / 100 % |

Remaining hard-set errors: `SELECT * menu specials` (normal, 0.62 = soft at most), `..\..ppsettings.json`
(path traversal, 0.49). Unseen XSS shapes (e.g. `<base href=…>`, `@import`) are the next weakest; the same recipe
(more variety per family + lofo check with `--label xss`) applies. v2 is kept at `models/input.v2.joblib`.

Latency p95 ≈ 1.5 ms per value on a laptop CPU.

## Known limits

- **Generated data.** Training data comes from our own templates; the hard set was written by the same team, so real
  attacker traffic may differ. A whole technique missing from the generator scores low (0.3–0.7), see the hold-out
  recall at 0.8.
- **English-centric** normal text; other languages are untested.
- **No field context:** the model does not know what a field expects (an email box vs a search box).
- v1 scored normal text with SQL-like punctuation (`Order #4521 -- urgent`, `Mom's cake; less sugar -- urgent`) at 0.6–0.9;
  v2 fixes the shop-customer cases measured above, but other domains' free text (support tickets, code snippets) is untested.
- Labels describe the *shape* of the input, not the attacker's intent or identity.
