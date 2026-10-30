# 00 — Overview (plain words)

## The idea

We set up **fake** servers, files and passwords that look real. No legitimate user has a reason to touch them,
so anyone who does is suspicious. We record everything they do, work out what they want, link their activity
together, warn the security team and let an analyst respond.

## The flow of one attack

1. **Trap** — attacker finds a decoy: fake SSH server, fake admin website, fake Kubernetes API.
2. **Record** — the decoy sends every login, command, file read and API call to the Go core as an event.
3. **Analyse** — the core asks:
   - Is this the same attacker as before? (correlation → *actor*)
   - What are they doing? (rules + ML → MITRE ATT&CK technique)
   - How dangerous? (risk score 0–100)
   - Human, script or AI agent? (behaviour class)
4. **Adapt** — the maze shows new fake lures that match the attacker's interest (Kubernetes, database …),
   within strict limits.
5. **Alert** — high and critical activity posts to Discord (and Slack).
6. **Respond** — the analyst sees the full timeline in the dashboard and blocks the attacker (lab only).

## What is in scope for the hackathon

| In | Out |
| --- | --- |
| 4 decoys: SSH, admin web, Kubernetes API, token beacon | Real production integration |
| 5 honeytokens (AWS key, kubeconfig, backup zip, db.env, URL) | Real cloud credentials |
| Correlation, rules, MITRE, risk, timelines | Traffic interception / TLS MITM |
| Discord + Slack alerts, incidents, lab-only response | Blocking on real networks |
| Adaptive maze with bounded loops | Unbounded or infinite deception |
| 3 ML models + incident summary (all optional at runtime) | Deep learning |

## Team (4 people)

| Role | Tool | Owns |
| --- | --- | --- |
| P1 Backend lead | Claude Code | Go core: ingest, store, intel engine, maze, alerting, analyst API |
| P2 Frontend | Antigravity | Next.js SOC dashboard |
| P3 Decoys + infra | any | Go decoys, honeytokens, Docker, network isolation, attack script |
| P4 ML + demo | any | FastAPI service, 3 models, CodeGuard integration, datasets, demo rehearsal |

If P3 and P4 are combined or split differently, keep the ownership table in `14-milestones-and-team.md` current.
