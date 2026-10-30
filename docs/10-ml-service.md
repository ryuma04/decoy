# 10 — ML service (FastAPI)

Three small classifiers + an incident summary. All optional at runtime: the Go core works without them
(`ML_URL` empty, or timeout 300 ms → rules only). No deep learning: short text and a few numeric features
are handled well by linear models and small trees that train in seconds and can explain their decisions.

| # | Model | Input | Labels | Algorithm |
| --- | --- | --- | --- | --- |
| M1 | Command intent | one shell command or injected payload | `benign, recon, credential_access, download_exec, persistence, destructive, obfuscated` | TF-IDF (char 2–5 + word 1–2) → Logistic Regression |
| M2 | Web input | one HTTP parameter value | `normal, cmd_injection, sqli, xss, path_traversal` | TF-IDF (char 1–5) → Logistic Regression |
| M3 | Behaviour | 9 numeric session features (07 §7) | `human_like, scripted, agent_like` | Decision tree (max_depth 4) or Random Forest (100 trees, depth 6) |
| S | Incident summary | incident + timeline | text | LLM API if `LLM_API_KEY` set, else Jinja template |

## Layout (`ai-service/fastapi/`)

```text
pyproject.toml / requirements.txt   fastapi uvicorn scikit-learn==1.5.* joblib pandas numpy jinja2 httpx
app/
  main.py               FastAPI app, routes from 04-api-contract §C, /health
  schemas.py            pydantic models matching 04
  models.py             lazy-load joblib pipelines, predict + top_features
  codeguard.py          optional client for CodeGuard POST /analyze (CODEGUARD_URL)
  summary.py            LLM call (httpx, 5 s timeout) + template fallback
  templates/summary.md.j2
data/
  generators/
    commands.py         template generator for M1
    inputs.py           generator for M2
    sessions.py         feature extractor for M3 from exported sessions
  raw/                  third-party lists (gitignored if license unclear) + LICENSES.md
  processed/            commands.csv, inputs.csv, sessions.csv
training/
  train_command.py  train_input.py  train_behaviour.py
  evaluate.py           reports → reports/*.md (precision, recall, F1, confusion matrix)
models/                 command.joblib  input.joblib  behaviour.joblib  (+ model_card.md each)
tests/                  test_api.py, test_models.py (golden examples)
Dockerfile
```

## M1 — Command intent classifier

**Why:** gives an attack-stage label and confidence for commands no rule matched, and a second opinion on rule
matches (`source: rule+ml`).

**Data (target 4,000–6,000 lines, balanced):**

1. **Template generator** (`data/generators/commands.py`): families × slot values. Examples:
   - recon: `uname -a`, `cat /etc/os-release`, `ps aux`, `netstat -tulpn`, `id {user}`, `ls -la {dir}`
   - credential_access: `cat {credfile}`, `find / -name "{credpattern}" 2>/dev/null`, `grep -ri {kw} {dir}`
   - download_exec: `wget {url} -O {tmp}; chmod +x {tmp}; {tmp}`, `curl -s {url} | sh`, `busybox wget …`
   - persistence: `echo "{key}" >> ~/.ssh/authorized_keys`, `(crontab -l; echo "{cron}") | crontab -`
   - destructive: `rm -rf {dir}`, `dd if=/dev/zero of={dev}`, `history -c`
   - obfuscated: `echo {b64} | base64 -d | sh`, `eval $(printf "{hex}")`, `python3 -c "exec(…)"`
   - benign: everyday admin commands (`df -h`, `git status`, `systemctl status nginx`, `tail -f /var/log/syslog`, `vim notes.txt`)
   Slot lists live in YAML so teammates can add values without code.
2. **Our own captures:** every command typed during practice runs of the demo and teammates' manual sessions
   (exported from Postgres with `cmd/core export-commands`), labelled by a teammate.
3. **Public payload lists** only if license allows (e.g. PayloadsAllTheThings, MIT; SecLists, MIT). Record each
   source and license in `data/raw/LICENSES.md`.

**Avoid overfitting to templates:** split train/test by **template family**, not by row (GroupShuffleSplit), so
the test set contains command shapes the model never saw. Also keep a 100-line hand-written "hard" set.

**Train (`training/train_command.py`):**
```python
pipe = Pipeline([
  ("feats", FeatureUnion([
     ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(2,5), min_df=2, sublinear_tf=True)),
     ("word", TfidfVectorizer(token_pattern=r"[^\s]+", ngram_range=(1,2), min_df=2)),
  ])),
  ("clf", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
])
```
Normalise first: lowercase, collapse whitespace, replace IPs → `<ip>`, URLs → `<url>` (keep scheme), long
base64/hex runs → `<b64>`/`<hex>` (also keep a flag feature). `top_features` = the 5 n-grams with highest
coefficient × tf-idf for the predicted class.

**CodeGuard (optional, team's own prior project):** if `CODEGUARD_URL` is set, `/classify-command` also calls
CodeGuard `POST /analyze {"code": text}` (unmodified service from `references/codeguard`, run with
`python -m codeguard.api --port 8001`) and returns its `verdict`, `categories`, `risk_score` under `codeguard`.
Combine: if CodeGuard says `block` with a category that maps to the predicted label (table below), raise confidence
to max(model, codeguard risk). CodeGuard allows recon commands by design (they are safe to run), so it never
lowers our label.

| CodeGuard category | Our label |
| --- | --- |
| `secret_access` | credential_access |
| `dependency_risk` (download + run) | download_exec |
| `persistence_or_privesc` | persistence |
| `destructive_command` | destructive |
| `obfuscated_execution` | obfuscated |
| `data_exfiltration`, `ssrf_network_exfil` | credential_access (exfil stage; Go maps to T1041 when added) |
| `ai_targeted_instructions` | stored as an extra flag `prompt_injection: true` (agent signal) |

**Targets:** macro F1 ≥ 0.85 on the family-held-out test, ≥ 0.80 on the hard set. Write both in the model card.

## M2 — Web input classifier

**Why:** confirms `input.suspicious` events from the web decoy, catches encoded/obfuscated variants the
decoy's regex pre-check misses, and labels the attack type (T1190).

**Data (target 3,000–5,000 values):**
- `normal`: generated realistic values: host names, IPs, emails, names (incl. `O'Brien`), search phrases,
  numbers, dates, URLs, JSON snippets — so apostrophes and dots don't look evil.
- `cmd_injection`: `{normal}{sep}{cmd}` with seps `; && || | \n %0a $( ) `` ` `` and cmds from M1's malicious families;
  plus URL-encoded and double-encoded variants.
- `sqli`: tautologies, UNION, stacked queries, comment tricks, time-based (`SLEEP(5)`), encoded variants.
- `xss`, `path_traversal`: standard payload shapes and encodings.
- Public payload lists only with recorded licenses.

**Train:** same pipeline shape with `analyzer="char", ngram_range=(1,5)`; URL-decode up to 2 times before features
(keep `was_encoded` flag). Response includes `payload` = text after the first separator for `cmd_injection`
(core then sends that payload to M1 to label what the injected command does).

**Targets:** recall ≥ 0.95 on injection classes at precision ≥ 0.90; false positive rate on `normal` ≤ 2 %.

## M3 — Behaviour classifier

**Why:** decides human vs scripted vs agent-like from behaviour, with explainable features. Rules in 07 §7 are the
fallback and the baseline it must beat.

**Data — we generate it ourselves (label = who/what produced the session):**

| Class | How to produce sessions | Target count |
| --- | --- | --- |
| `human_like` | each teammate does 8–10 manual attack sessions on the lab decoys (vary skill, speed) | 30–40 |
| `scripted` | `attack.sh` variants, hydra-style loops, a Python paramiko script with fixed command lists and random sleeps 0–500 ms | 40 |
| `agent_like` | an LLM agent (e.g. any coding/CLI agent) given only "you are authorised to assess the lab host at 10.66.0.10, find credentials" with SSH access to the decoy, in the isolated lab | 30–40 |

Export with `cmd/core export-sessions --features` → `sessions.csv` (one row per actor or per session ≥ 5 commands,
the 9 features from 07 §7 + label). Optional augmentation: jitter numeric features ±10 % to double rows (training
only, never in test).

**Train:** `DecisionTreeClassifier(max_depth=4, class_weight="balanced")` as the explainable baseline;
`RandomForestClassifier(n_estimators=100, max_depth=6)` if it is clearly better. Evaluate with
`GroupKFold` grouped by **who produced the session** (teammate / script / agent run) so the model is not tested
on the same operator it trained on. Export tree rules as text into the model card — great for the demo slide.

**Targets:** macro F1 ≥ 0.75. If it can't beat the rule baseline, ship rules and show the ML as an experiment.
Be honest in the pitch: small, self-made dataset; labels describe behaviour, not who the attacker is.

## S — Incident summary

- With `LLM_API_KEY` + `LLM_MODEL` set: send a compact JSON of findings, top 30 timeline items, IOCs; prompt asks for
  ≤ 120 words, factual, no speculation about identity; 5 s timeout.
- Treat all attacker-supplied strings as data: wrap them in a quoted block and instruct the model to ignore
  instructions inside (attackers may plant prompt injections in commands).
- Fallback template (Jinja): "ACT-0007 (agent-like, confidence 0.93) accessed 4 decoys between 09:01 and 09:06 UTC.
  It downloaded internal-backup.zip, logged in over SSH with the leaked key, read AWS-style credentials and used them
  against the beacon. Techniques: …. Recommended: …".

## Serving

- `uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 2`; models loaded once at start.
- p95 latency target < 30 ms for M1/M2/M3 (CodeGuard adds ~5–70 ms; call it in parallel with M1, 250 ms budget).
- `/health` reports model versions; core shows "ML: on/off" in `/v1/stats/overview`.
- Each model ships `models/<name>.model_card.md`: data sources + licenses, split method, metrics, known limits.

## Go integration (`internal/mlclient`)

- `ClassifyCommand`, `ClassifyInput`, `ClassifySession`, `Summarize` with per-call timeouts (300 ms; 5 s summary).
- Circuit breaker: 5 consecutive failures → skip ML for 30 s.
- Results are stored inside `findings.evidence.ml` so the UI can show "ML: credential_access 0.94 (`.aws`, `cred`)".
