# Decisions log

Newest first. Format: date · decision · why · alternatives rejected.

| Date | Decision | Why | Rejected |
| --- | --- | --- | --- |
| 2026-10-30 | Own Go SSH decoy with emulated shell | Wisp SSH is credentials-only; Cowrie is Python and reference-only | Cowrie as base; Wisp as base |
| 2026-10-30 | Core is one Go process with an in-process bus | Fewer moving parts for a hackathon; splittable later | Microservices, Kafka/NATS |
| 2026-10-30 | SSE for live UI | One-way traffic, auto-reconnect, stdlib only | WebSockets |
| 2026-10-30 | Noisy-OR correlation, attach ≥ 0.60, credential lineage weight 0.90 | Explainable; IP alone (0.40) never attaches | IP-only grouping; clustering ML |
| 2026-10-30 | Risk × (0.5 + 0.5 × confidence); one finding per rule per actor | Loose clusters can't go critical; brute force can't dominate | Raw sum of events |
| 2026-10-30 | Response enforced by our decoys via policy polling | Safe, demo-able, no host firewall access from containers | nftables from core |
| 2026-10-30 | 3 ML models (command, web input, behaviour) + summary; all optional | Rules carry correctness; ML adds labels and explanations | Deep learning |
| 2026-10-30 | LABYRINTH L3/L4 out of scope | TLS interception and prompt rewriting add legal/safety risk | — |
| 2026-10-30 | CodeGuard (team's prior project) optional, run unmodified as a service | Saves effort on command risk; declared as prior work | Copying its code in |
