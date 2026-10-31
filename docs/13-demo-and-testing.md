# 13 — Demo script and testing

## Demo story (≈ 4 minutes, rehearse at least 3 times)

| t | Presenter does | Judges see |
| --- | --- | --- |
| 0:00 | Open dashboard Overview | Quiet: 0 actors, sensors 4/4 ok |
| 0:20 | `docker compose --profile demo run --rm attacker /scripts/attack.sh` | Events start streaming |
| 0:30 | (script) nmap decoy subnet | `port_sweep`, new actor ACT-0001, low |
| 0:45 | (script) web: robots.txt → /admin/backup → download zip; `/api/diagnostics?host=8.8.8.8;cat /etc/passwd` | honeyfile download, `cmd_injection` T1190 (rule+ml) |
| 1:05 | (script) 6 wrong SSH passwords, then key from the zip | `password_guessing`, login linked by **credential lineage** |
| 1:25 | (script/agent) `id; uname -a; find / -name "*.kube*"; cat ~/.aws/credentials` | discovery + cred search; risk climbs; kubeconfig lure **appears** (maze unlock) |
| 1:50 | (script) `cat /opt/deploy/kubeconfig`; curl K8s API with token: list pods, secrets | T1613, T1552.007, high → Discord |
| 2:10 | (script) SigV4 request with the lure AWS key to beacon | `token.used`, **critical**, Discord `@here` |
| 2:20 | (script) tries the stolen decoy credential on the **real** login page of `real-target`; firewall logs its scan | Timeline shows "App login (production)" + firewall rows; finding "decoy credential used on real system"; badge **Touched production** |
| 2:30 | Open actor profile | 3+ linked sessions graph, timeline, ATT&CK, behaviour = scripted |
| 3:00 | Second terminal: teammate SSHs **from another IP** with the same key and types slowly | Joins ACT-0001 via `ssh_key` signal; behaviour shifts to human-like for that session |
| 3:20 | Incident page → AI/template summary → `block_ip` | Next SSH attempt refused within 5 s |
| 3:30 | On a separate test actor (teammate browsing normally), click **False positive** | Risk drops, toast shows new weights version |
| 3:40 | Download report | Markdown report with IOCs and ATT&CK |

Optional wow moment (only if M5 done and rehearsed): run an LLM agent against the decoys; show `agent_like`
classification and maze unlocks following its interest. Have a recorded video fallback.

## `attack.sh` (infrastructure/docker/attacker/scripts/)

Deterministic, idempotent, prints each step with a header, waits 2–4 s between steps so the dashboard reads well.
Uses only lab hosts (`decoy-ssh`, `decoy-web`, `decoy-k8s`, `decoy-beacon`). Reads persona values from
`/seed/persona.json` mounted read-only (so it knows the planted password/key paths for the scripted part).
Variants: `attack.sh --fast` (scripted timing), `attack.sh --slow` (human-like sleeps).

## Tests

| Layer | What | Tool |
| --- | --- | --- |
| Go unit | event validation, HMAC, every correlation signal, merge, each rule (positive + negative), risk math, maze limits, policy enforcement | `go test ./...` |
| Go integration | ingest → Postgres → findings, using a real Postgres (compose or testcontainers) | `go test -tags=integration` |
| Decoy safety | fuzz SSH line editor and command parser (`go test -fuzz`); assert no `os/exec` import in `internal/decoy` (lint check script) | Go fuzz + `scripts/check-no-exec.sh` |
| Contract | JSON of every analyst endpoint validates against TS types (generate JSON Schema from types with `ts-json-schema-generator`, validate in Go tests) | CI script |
| ML | golden examples per class; metrics thresholds in 10 enforced by `training/evaluate.py --check` | pytest |
| Frontend | type-check, lint, Playwright smoke: login → overview → actor page renders with mocks | `npm run test:e2e` |
| End to end | `scripts/e2e.sh`: compose up, run attack, poll API until an actor with risk ≥ 75 and ≥ 3 sessions exists, assert Discord mock received a message | bash + curl + jq |

Use a local Discord mock (`infrastructure/docker/webhook-mock`, 20-line Go server that logs payloads) in tests
so CI never hits real webhooks.

## Acceptance gates

| Gate | Pass criteria |
| --- | --- |
| G1 Pipeline | SSH command visible in UI < 2 s; event survives core restart (spool replay); duplicate batch is idempotent |
| G2b Telemetry | log-collector parses all three sample log files; external events link to the attack actor; profile shows source, tools, behaviour, timeline |
| G2 Intelligence | attack.sh produces 1 actor, ≥ 3 sessions, ≥ 1 non-IP link, ≥ 8 distinct techniques, risk ≥ 75 |
| G3 Demo-ready | full table above works 3 times in a row from a clean `docker compose down -v`; Discord alerts; block works; report downloads; ML off still passes G2 |
| G4 Signature | maze unlock visible live; behaviour class shown with features; ML models meet targets in 10 or are labelled experimental |
