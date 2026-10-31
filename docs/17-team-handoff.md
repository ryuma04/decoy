# 17 — Team handoff: parts to build by hand

The AI assistant used for this build (Claude Code) stopped while writing the parts below; its safety system
interrupted the output. They are fully specified in the docs and the surrounding code is ready, so a teammate
can write them directly. Keep this list current: tick items when done, add new ones if more are handed over.

| # | Part | Spec | Plugs into (already built and tested) | Owner |
| --- | --- | --- | --- | --- |
| 1 | SSH decoy network server (`internal/decoy/ssh/server.go`, `cmd/decoy-ssh`): `x/crypto/ssh` server, password + public-key callbacks emitting `auth.attempt`, PTY/shell/exec channels, idle 10 min / cap 30 min / 500 commands, policy checks | 06 §1, 08 limits | `sensorkit` (sessions, events, policy), `decoy/ssh` `LineEditor`, `Shell`, `BaseTree`, `persona` | done (Antigravity) |
| 2 | Web decoy (`internal/decoy/web`, `cmd/decoy-web`) | 06 §2 | `sensorkit`, persona | done (Antigravity) |
| 3 | Kubernetes API decoy (`internal/decoy/k8s`, `cmd/decoy-k8s`) | 06 §3 | `sensorkit`, persona | |
| 4 | Beacon (`internal/decoy/beacon`, `cmd/decoy-beacon`) | 06 §4 | `sensorkit` | done (Antigravity) |
| 5 | Per-session / per-actor features and behaviour class (`internal/intel/features`, `internal/intel/behaviour`) | 07 §3, §7 | rule engine reads `Features map[string]float64` (`internal/intel/rules`); `BehaviourDetail` type in 04 | done (Antigravity) |
| 6 | Dashboard mock fixtures (`frontend/nextjs/src/mocks/`). Pages still to build: overview, actors, actor profile, incidents, maze, honeytokens, sensors, scorer | 11, examples in 04, demo story in 13 | Built and working against the real core: login, live events page with SSE + event drawer, `lib/api.ts`, `lib/stream.tsx`, `lib/format.ts`, `/api/stream` pass-through, DESIGN.md tokens in `globals.css` | |
| 7 | `attack.sh` demo script and attacker container | 13 | decoys from rows 1–4 | |
| 8 | Discord / Slack notifiers + send queue with retries (`internal/alert/notify.go`) | 09 §Notification policy, §Discord payload | `internal/alert/policy.go` (severity → channel, cooldown, colours; built), narration in the ML service | done (Antigravity) |

Built since (verified end to end on Neon, 2026-10-31): intel engine (`internal/intel/engine`: fingerprints,
symmetric credential lineage, correlation + merges, honeytoken hits, port sweep, rules, findings, risk), input risk
from core (`intel/inputrisk`, `mlclient` with breaker), incidents (`internal/incident`), Go narration + LLM call
(`internal/narrate`), response actions → `policy`, incident report, feedback + scorer versions, all analyst
endpoints in 04 §B except `/tactics`, `/generated-lures`, `/recovery`, `cmd/seed`, adaptive maze (`internal/maze`,
real maze-view), log parsers + `cmd/log-collector`.

Still open (not attempted yet; specified in the docs):

| # | Part | Spec | Plugs into |
| --- | --- | --- | --- |
| 9 | External-telemetry linking (`intel/extlink`): link `origin: production` events to actors, findings `decoy_cred_on_real`, `real_bruteforce`, `real_success`, `fw_repeat`, set `touched_production` | 07 §8.2 | `cmd/log-collector` and `logparse` (built); engine skips production events today |
| 10 | Tool detection (`intel/tools`, `rules/tools.yaml`) → `actors.tools` | 07 §9.1 | `dto.ToolTag`, `actors.tools` column |
| 11 | Stretch: cognitive tactics, LLM lures, false-positive recovery | 08 §Cognitive / §LLM lures, 09 §Recovery | — |

Known limits found while testing:
- Each event costs the engine several Postgres round trips; against Neon in eu-west-2 from India that is ~2–4 s
  per event (events still stream to the UI in < 1 s). Use Postgres next to core (`--profile localdb`) for the demo.
- One feedback click moves risk by < 1 point at η = 0.05 (07 §6.5); raise η if the demo should show it.
- IP + SSH banner scores 0.49, not 0.61 as 07 says; 0.61 needs HASSH (stretch).

Notes for whoever picks these up:
- Decoys must never import `os/exec` or write outside `/data` and `/tmp` (`scripts/check-no-exec.sh`).
- `cmd/send-sample` shows how a decoy emits events through `sensorkit`; core already ingests, stores and streams them.
- Feature names the rules expect: `failed_auths_5m`, `distinct_pairs`, `successful_logins`, `commands`,
  `services_visited` (see `rules/rules.yaml`).
