# 14 — Milestones and team board

Hackathon length is not fixed in this doc; milestones are ordered, not dated. Put dates in once known.
Day-zero rule: **freeze 02 (event schema), 03 (database) and 04 (API contract) before anyone writes feature code.**

| Person | Tool | M1 Pipeline | M2 Decoys | M3 Intelligence | M4 Respond | M5 Signature |
| --- | --- | --- | --- | --- | --- | --- |
| P1 Backend lead | Claude Code | config, event, store, migrations, ingest, bus, SSE, auth, events API | maze-view (static), policy API, sensor heartbeat/status | fingerprint, honeytoken, correlate, features, rules, MITRE, risk, scan, actor APIs | alert, Discord/Slack, incidents, response, report, mlclient | adaptive maze, behaviour engine, summary hook |
| P2 Frontend | Antigravity | types, mocks, api layer, layout, login, overview, live events | actors list | actor profile (sessions graph, timeline, ATT&CK, behaviour) | incidents, actions, report download, honeytokens, sensors | maze graph live, polish, demo mode |
| P3 Decoys + infra | any | compose, Dockerfiles, networks, sensorkit, minimal SSH decoy | persona, fakefs, seed, full SSH, web, k8s, beacon | attacker container, attack.sh, webhook mock | e2e.sh, hardening, VM setup | maze-aware decoy views, bounded loops in decoys |
| P4 ML + demo | any | FastAPI skeleton + `/health`, data generators M1/M2 | train M1, M2; model cards | CodeGuard integration, `/classify-input` payload extraction; collect M3 sessions (with team) | train M3, summary + template, pitch deck | rehearsal, video fallback |

## Interfaces between people

| From → To | Contract | Mock until ready |
| --- | --- | --- |
| P3 decoys → P1 core | 02 envelope, 04 §A | P1 posts sample batches with `scripts/send-sample.sh` |
| P1 core → P2 UI | 04 §B | `frontend/nextjs/src/mocks/` |
| P1 core → P4 ML | 04 §C | core runs with `ML_URL` empty |
| P4 → everyone | model cards | — |

## Cadence

- Stand-up every ~4 h awake time: done / next / blocked (5 min).
- Integration checkpoint at each gate: everybody on `main`, `docker compose up` from clean, run `attack.sh`.
- Freeze features 6 h before judging; only bug fixes and rehearsal after that.

## Cut list (drop in this order if late)

1. Jenkins and DB decoys (already stretch).
2. HASSH / JA4 fingerprints.
3. Slack (keep Discord).
4. M3 ML model (keep behaviour rules).
5. LLM summary (keep template).
6. Adaptive unlocks (keep static maze with default lures) — last resort, it is the signature feature.
