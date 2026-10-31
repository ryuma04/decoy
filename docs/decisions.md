# Decisions log

Newest first. Format: date · decision · why · alternatives rejected.

| Date | Decision | Why | Rejected |
| --- | --- | --- | --- |
| 2026-10-31 | Database decoy = own Go Postgres wire-protocol server (`decoy-db`) with fake tables; accepts only the planted `tok_db` credential (+ persona weak postgres password); writes and file/command functions always denied | Completes the maze path lure_db → svc_db; proves credential theft → use → data access in one actor; nothing is ever executed | Real Postgres with fake data (a real server can be abused); MySQL protocol |
| 2026-10-31 | One trained model only: input-risk (TF-IDF/LR) scoring each attacker-typed value 0–1 plus attack label; risk scales finding points | Best data story (generated + licensed payload lists), beats regex on encoded input; type is needed for MITRE and titles | Command model (echoed rules), behaviour model (no data in time), CodeGuard (built for code snippets) |
| 2026-10-31 | LLM narration turns facts into plain English for Discord/Slack, actor card, incident and on-demand Explain; Go templates in core as fallback; 3 s budget for alerts | Analysts and judges read stories, not event types; alerts never depend on the LLM | LLM per stream event (cost/latency); templates in the ML service (ML off would lose readable alerts) |
| 2026-10-31 | Narration is guarded: attacker strings quoted as data, mentions stripped, every IP/token/label in output must exist in facts | Attackers control part of the input; Discord mentions are an abuse path | Trusting model output as is |
| 2026-10-31 | LLM provider-neutral: `LLM_PROVIDER=openai_compat` (Groq, Gemini, OpenRouter, Ollama) by default, `anthropic` optional | Team has no paid Anthropic key; one HTTP shape covers most providers | Locking to one vendor SDK |
| 2026-10-31 | Cognitive adaptive deception layer inside the honeypot: rule-based bias patterns → presentation tactics, max 1 per 5 min, effect measured as "lure taken / engagement continued" | Adds behaviour-aware deception honestly (patterns, not mind-reading) | Psychological profiling claims; ML bias detection |
| 2026-10-31 | LLM dynamic lures: one generator + deterministic Go guards + optional critic, background generation, Go inserts honeytokens, template fallback | Dynamic honeypot without hallucination or demo risk | 3–4 voting agents (shared failure modes, latency) |
| 2026-10-31 | False-positive recovery: analyst-approved, user re-authenticates and confirms, only allowlisted actions replayed via real app API as the user | Restores a real user's work without letting an attacker replay into production | Automatic replay of honeypot actions |
| 2026-10-31 | Final risk = single neuron (logistic regression) over per-stage scores (recon, access, post-access, lateral) + hard overrides; weights updated only from analyst feedback | Explainable, ~30 lines of Go, no training data needed upfront, demo-safe | Multi-layer NN now (no labelled data, 6–10 h, black box) → future scope (16) |
| 2026-10-31 | External telemetry (firewall, host SSH auth, real app login) enters through the same ingest pipeline via `cmd/log-collector`, `origin: production` | PS requires linking honeypot activity to other telemetry; reuses envelope, storage and timeline | Separate SIEM pipeline |
| 2026-10-31 | External events link to decoy actors (same IP ±60 min, decoy credential reused on real system, real brute force, real success) but never create actors | Keeps production noise out; decoy = high-confidence anchor | Actors from firewall logs alone |
| 2026-10-31 | Attacker profile has four parts: source, tools, behaviour, timeline; tool detection from UA, SSH banner, commands, rates | Matches PS wording; judges can check each part | — |
| 2026-10-31 | For real systems the SOC only recommends actions; lab decoys are the only things it blocks | Safety | Automated production response |
| 2026-10-30 | Own Go SSH decoy with emulated shell | Wisp SSH is credentials-only; Cowrie is Python and reference-only | Cowrie as base; Wisp as base |
| 2026-10-30 | Core is one Go process with an in-process bus | Fewer moving parts for a hackathon; splittable later | Microservices, Kafka/NATS |
| 2026-10-30 | SSE for live UI | One-way traffic, auto-reconnect, stdlib only | WebSockets |
| 2026-10-30 | Noisy-OR correlation, attach ≥ 0.60, credential lineage weight 0.90 | Explainable; IP alone (0.40) never attaches | IP-only grouping; clustering ML |
| 2026-10-30 | Risk × (0.5 + 0.5 × confidence); one finding per rule per actor | Loose clusters can't go critical; brute force can't dominate | Raw sum of events |
| 2026-10-30 | Response enforced by our decoys via policy polling | Safe, demo-able, no host firewall access from containers | nftables from core |
| 2026-10-30 | ~~3 ML models (command, web input, behaviour) + summary; all optional~~ superseded 2026-10-31 (one input-risk model + narration) | Rules carry correctness; ML adds labels and explanations | Deep learning |
| 2026-10-30 | LABYRINTH L3/L4 out of scope | TLS interception and prompt rewriting add legal/safety risk | — |
| 2026-10-30 | ~~CodeGuard (team's prior project) optional, run unmodified as a service~~ superseded 2026-10-31 (removed) | Saves effort on command risk; declared as prior work | Copying its code in |
