# 05 — Backend implementation (Go)

One Go module, several binaries. Core runs ingest + intel + maze + alerter + analyst API in one process,
connected by an in-process bus, so it can be split later without code changes.

## Module layout (`backend/go/`)

```text
go.mod                       module github.com/<team>/deception-soc/backend
cmd/
  core/main.go               flags: serve | migrate | replay | seed-admin
  decoy-ssh/main.go
  decoy-web/main.go
  decoy-k8s/main.go
  decoy-beacon/main.go
  log-collector/main.go      tails firewall / sshd auth / app-login logs → dsoc.event/v1 (origin: production), 07 §8
  seed/main.go               generates persona + honeytokens + lure files → seed/out/*.json, inserts honeytokens
internal/
  config/                    env parsing (one struct, defaults, validation)
  event/                     Envelope types, validation, type registry, ULID helper
  sensorkit/                 shared decoy client: batching, HMAC signing, JSONL spool, heartbeat, policy poll, maze-view
  persona/                   fake company/user/host generator, deterministic from PERSONA_SEED
  fakefs/                    in-memory fake filesystem (tree, file contents, maze-gated entries)
  decoy/ssh/                 SSH server, PTY line editor with timing, command emulators
  decoy/web/                 admin portal, honeyfiles, diagnostics (injection bait)
  decoy/k8s/                 fake kube-apiserver
  decoy/beacon/              AWS-style endpoint + URL token endpoint
  ingest/                    sensor HTTP handlers, HMAC middleware, normalization, session mapping
  store/                     pgx pool, queries per table, tx helper, migrations (embed)
  bus/                       typed in-process pub/sub (buffered channels, fan-out)
  intel/
    fingerprint/             extract fingerprint rows from events
    correlate/               candidate search, scoring, attach/merge
    rules/                   YAML rule loader + evaluator over session/actor features
    features/                rolling per-session and per-actor feature state
    mitre/                   technique id → name/tactic table (static Go map)
    risk/                    per-stage scores, single-neuron combiner, overrides, feedback weight updates (07 §6)
    extlink/                 link external (production) events to decoy actors (07 §8)
    tools/                   tool detection rules (07 §9.1)
    behaviour/               rule classifier + ML hand-off
    honeytoken/              token match + token_hits
    scan/                    port-sweep detector (derived scan.detected)
  maze/                      graph loader, interest scorer, unlock logic, maze-view builder
  alert/                     incidents, notifier interface, discord, slack, templates
  response/                  actions → policy table, audit
  logparse/                  parsers for nftables/iptables, sshd auth.log, app JSON login logs (+ testdata)
  report/                    incident report (markdown/json)
  api/                       analyst REST, auth (JWT cookie), SSE hub, DTO mapping
  mlclient/                  HTTP client with timeouts + circuit breaker
migrations/                  0001_init.up.sql / .down.sql
rules/rules.yaml             detection rules (07)
maze/maze.yaml               maze graph (08)
mitre/techniques.csv         id,name,tactic (only techniques we use)
seed/                        persona templates
```

## Libraries (only these without asking)

`github.com/jackc/pgx/v5`, `github.com/golang-migrate/migrate/v4`, `golang.org/x/crypto/ssh`,
`golang.org/x/crypto/bcrypt`, `github.com/oklog/ulid/v2`, `gopkg.in/yaml.v3`, `github.com/golang-jwt/jwt/v5`,
`github.com/google/uuid`. Router: stdlib `http.ServeMux` with Go 1.22 patterns (`GET /v1/actors/{id}`).
Logging: `log/slog` JSON. Tests: stdlib `testing` + `testcontainers-go` optional for Postgres.

## Bus

```go
type Topic string
const (TopicEvent Topic = "event"; TopicFinding = "finding"; TopicActor = "actor";
       TopicIncident = "incident"; TopicMaze = "maze"; TopicSensor = "sensor")
type Bus interface { Publish(t Topic, v any); Subscribe(t Topic, buf int) <-chan any }
```

Intel engine processes events **sequentially per actor** (shard by `session_id` hash → N workers, N=4) so
correlation and scoring have no races. SSE hub subscribes to every topic.

## Build order (each step ends with a test)

### M1 — Pipeline
1. `config`, `event` (validation table tests for every type in 02), `store` + migrations, `cmd/core migrate`.
2. `ingest`: HMAC middleware (test with fixed key/time), `POST /v1/ingest/events`, dedup on `event_id`,
   session mapping (insert on first `sensor_session_id`), heartbeat → `sensors`.
3. `bus` + SSE hub + `GET /v1/stream`, `GET /v1/events`, auth (`seed-admin` from `SOC_ADMIN_EMAIL/PASSWORD`).
4. `sensorkit` (batch, sign, spool, heartbeat, policy poll).
5. `decoy/ssh` minimal: password auth, PTY shell, `whoami ls pwd cat uname id exit`, events + timing.
   **Gate 1:** a command typed into the SSH decoy appears on `/v1/stream` in < 2 s.

### M2 — Decoys
6. `persona`, `fakefs`, `cmd/seed` (honeytokens, lure files, backup zip with SSH key, kubeconfig).
7. Full SSH command set, `decoy/web`, `decoy/k8s`, `decoy/beacon` (see 06).
8. `GET /v1/sensor/maze-view` with static default view; `GET /v1/sensor/policy`.

### M3 — Intelligence
9. `intel/fingerprint`, `intel/honeytoken`, `intel/correlate` (07) with unit tests for each signal and the merge.
10. `intel/features`, `intel/rules` + `rules/rules.yaml`, `intel/mitre`, `intel/risk`, `intel/scan`.
11. Actor endpoints, timeline, techniques stats.
    **Gate 2:** demo script yields one actor with ≥ 3 linked sessions, ≥ 1 linked by a non-IP signal.

### M4 — Respond
11b. `intel/tools`, `logparse` + `cmd/log-collector`, `intel/extlink`; actor profile fields (source, tools, behaviour, timeline).
12. `alert` (incidents, severity rules, Discord + Slack, cooldown), `response` (actions → policy), `report`.
13. `mlclient` wired into rules (command + input classifiers) behind `ML_URL`.
    **Gate 3:** full chain end to end on the demo script; Discord message arrives; `block_ip` makes the next
    SSH connection from that IP fail.

12b. Feedback endpoint, `scorer_weights` versions, reset; online update behind `SCORER_LEARN`.

### M5 — Signature
14. `maze` adaptive unlocks + bounded loops; `GET /v1/actors/{id}/maze`.
15. `intel/behaviour` rules + ML session classifier; incident summary via ML.

## Error handling and safety

- Ingest never blocks on intel: insert → publish → return. Bus buffer 10k; if full, log + drop *publish* (row is stored; `replay` can recover).
- All handlers have `http.MaxBytesReader` (sensor: 13 MB batch; analyst: 64 KB).
- Analyst API: CORS off (same-origin via Next.js proxy); `SameSite=Lax` cookie; admin role for actions.
- Panics in workers are recovered and logged with the event id.

## Configuration (env)

| Var | Default | Used by |
| --- | --- | --- |
| `DATABASE_URL` | — | core |
| `SENSOR_KEYS` | — | core |
| `SENSOR_ID`, `SENSOR_KEY`, `CORE_URL` | — | each decoy |
| `JWT_SECRET`, `SOC_ADMIN_EMAIL`, `SOC_ADMIN_PASSWORD` | — | core |
| `ML_URL` | empty = ML off | core |
| `DISCORD_WEBHOOK_URL`, `SLACK_WEBHOOK_URL` | empty = off | core |
| `DASHBOARD_URL` | `http://localhost:3000` | core (links in alerts) |
| `PERSONA_SEED` | random at seed time | seed, decoys |
| `MAZE_ADAPTIVE` | `true` | core |
| `SCORER_LEARN` | `false` | core (enable single-neuron updates from feedback) |
| `SCORER` | `neuron` | core (`mlp` only on the future-scope branch, 16) |
| `LOG_SOURCES` | `fw:/logs/fw.log,hostauth:/logs/auth.log,appauth:/logs/app-login.jsonl` | log-collector |
| `LOG_LEVEL` | `info` | all |
