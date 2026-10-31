# 14 — Milestones and team board

Hackathon length is not fixed in this doc; milestones are ordered, not dated. Put dates in once known.
Day-zero rule: **freeze 02 (event schema), 03 (database) and 04 (API contract) before anyone writes feature code.**

| Person | Tool | M1 Pipeline | M2 Decoys | M3 Intelligence | M4 Respond | M5 Signature |
| --- | --- | --- | --- | --- | --- | --- |
| P1 Backend lead | Claude Code | config, event, store, migrations, ingest, bus, SSE, auth, events API | maze-view (static), policy API, sensor heartbeat/status | fingerprint, honeytoken, correlate, features, rules, MITRE, risk, scan, actor APIs | alert, Discord/Slack, incidents, response, report, mlclient | adaptive maze, behaviour engine, `narrate` (alerts, actor card, Explain) |
| P2 Frontend | Antigravity | types, mocks, api layer, layout, login, overview, live events | actors list | actor profile (sessions graph, timeline, ATT&CK, behaviour) | incidents, actions, report download, honeytokens, sensors | maze graph live, polish, demo mode |
| P3 Decoys + infra | any | compose, Dockerfiles, networks, sensorkit, minimal SSH decoy | persona, fakefs, seed, full SSH, web, k8s, beacon | attacker container, attack.sh, webhook mock | e2e.sh, hardening, VM setup | maze-aware decoy views, bounded loops in decoys |
| P4 ML + demo | any | FastAPI skeleton + `/health`, input value generator | train input-risk model, evaluate, model card | `/classify-input` payload extraction + calibration; `/narrate` with output guard | narration prompt tuning on demo runs, pitch deck | rehearsal, video fallback |

### Added 2026-10-31

| Person | Task | Milestone |
| --- | --- | --- |
| P1 | per-stage scores, single-neuron combiner, overrides, feedback endpoint + weight versions (07 §6) | M3–M4 |
| P1 | `logparse`, `cmd/log-collector`, `intel/extlink`, `intel/tools`, profile fields (07 §8–9) | M3 |
| P2 | profile four-part cards, risk breakdown bar, production-styled timeline rows, feedback buttons, `/scorer` page | M3–M4 |
| P3 | `real-target` container (nftables logging, sshd, real login page writing JSON), sample log files, attack.sh real-login step | M3 |
| P4 | normal-user session simulator (for false-positive testing and future NN data) | M4 |
| Any | `exp/mlp-risk` branch (16), only after feature freeze | after G3 |

### Phase 5 stretch (after Gate 3 only)

| Person | Task |
| --- | --- |
| P1 | `internal/cognitive` (2 patterns: confirmation, sunk cost), `deception.tactic` events |
| P1/P4 | `internal/lurgen` with guards, cache, template fallback, one theme (database) |
| P3 | partial-success responses in decoys; serve generated lures via maze-view |
| P2 | timeline items for tactics, "Generated lures" panel on actor profile, "recover user session" checkbox |
| P3/P4 | recovery demo: real-target `/api/tickets`, recovery-runner, confirm page |

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
4. Event **Explain** button (keep alert + actor narration).
5. LLM narration entirely (keep Go templates; set `LLM_API_KEY` empty).
6. Adaptive unlocks (keep static maze with default lures) — last resort, it is the signature feature.
