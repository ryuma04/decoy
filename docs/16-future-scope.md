# 16 — Future scope

Work we deliberately did not ship in the hackathon build, with a plan for each. Nothing here may block the main
demo; experiments live on separate branches behind feature flags.

## 1. Neural network risk model (branch `exp/mlp-risk`)

**Idea (team proposal):** risk is scored per stage (pre-access, access, post-access, lateral) from Go rules, ML
signals and MITRE findings; all stage scores feed a neural network with learned weights that outputs the final risk
and improves from false-positive feedback.

**What ships now instead:** the same structure with a single neuron (logistic regression) over the stage scores,
hard overrides on top, and weights nudged only by analyst feedback (07 §6). It is the one-layer version of this idea.

### Why it is future scope

- A network only learns what is wrong from **labels**. The labels come from analysts ("Confirmed attacker" /
  "False positive"), stored in `risk_feedback`. In a 24-hour build we will have too few for a hidden layer to beat
  one neuron.
- Learning from analyst corrections is **supervised learning**, not reinforcement learning.
- With a few hundred synthetic sessions a hidden-layer model mostly memorises the data generator.

### Plan

| Step | Detail |
| --- | --- |
| Branch | `exp/mlp-risk`; main stays on `SCORER=neuron` |
| Inputs | the 4 stage scores + raw features from `risk_feedback.features`: failed logins, hidden paths, honeytokens used, commands/min, tool tag present, injection score, edit rate, services visited (8–12 numbers, scaled 0–1) |
| Model | inputs → 8 hidden (ReLU) → 1 output (sigmoid) = probability of malicious actor |
| Data | attack-script sessions (y = 1), simulated normal users with typos and pauses (y = 0), every analyst feedback row (strongest labels); export with one SQL query to CSV |
| Training | offline in Python: `sklearn.neural_network.MLPClassifier(hidden_layer_sizes=(8,), max_iter=1000)`; trains in < 1 s |
| Serving | export weight matrices to JSON; Go forward pass (~40 lines: matmul → ReLU → matmul → sigmoid) in `intel/risk/mlp.go`; no Python at runtime |
| Self-improvement | no live weight changes: a "Retrain" job rebuilds from `risk_feedback`, and the new model loads only if its test score did not drop |
| Guardrails | hard overrides (07 §6.3) stay above the network; `SCORER=mlp` flag; instant fallback to the neuron |
| Evaluation | same test set as the neuron, split by who produced each session; compare F1, false-positive rate on normal users, and same output for the same attack on two runs |
| Merge rule | merge only if it beats the neuron on the held-out set and is deterministic; otherwise keep the result as evidence ("we tested an MLP; with our data size the simpler model was as accurate and explainable") |
| Time box | 3–4 h, only after the main demo is frozen |

## 2. Cognitive layer and LLM lures — beyond the hackathon

- Measure tactic effect statistically across many actors (A/B: tactic vs no tactic) before claiming impact.
- More bias patterns, learned from data instead of hand-written thresholds.
- Multi-turn LLM shell responses for unknown commands (cached, persona-consistent), with the same guard pipeline.

## 3. False-positive recovery — beyond the hackathon

- Integration with real SSO (OIDC) so recovery re-auth is seamless.
- More recoverable action types per application, defined in a per-app recovery manifest.
- Optional automatic replay for very low-risk actions (search, navigation) after a long clean history; never for writes.

## 4. Other future work

| Item | Why later |
| --- | --- |
| Per-user behaviour baselines (UEBA style) from identity and auth logs | needs weeks of real user history |
| Trained behaviour classifier (human / script / AI agent) | needs labelled human and agent sessions; rules ship now |
| Command-intent classifier for SSH commands (TF-IDF/LR, 7 labels) | removed 2026-10-31: template data mostly echoed the rules; revisit with real captured commands |
| CodeGuard as a second opinion on commands / payloads | removed 2026-10-31 with the command model; built for code snippets, not single commands |
| LLM narration per event in the live stream | too many calls; ships per alert / actor / on-demand Explain |
| Gradient-boosted risk model over raw features | next step after the MLP if real data grows |
| More decoys: Jenkins, real DB wire protocol, MCP/LLM decoy | effort vs 24 h |
| HASSH / JA4 client fingerprints | raw protocol parsing |
| Multi-level adaptive maze with bounded loops | static maze + one adaptive lure ships now |
| Integration with real firewalls (push block rules) | safety; we only recommend actions on production |
| SIEM export (syslog / Sentinel / Splunk) | not needed for the demo |
