# 01 — Architecture

## Components

```text
                    ATTACKER (lab container / test VM)
                               │
   ════════════════ decoy_net (internal, no internet) ════════════════
     decoy-ssh :2222   decoy-web :8080   decoy-k8s :6443   decoy-beacon :8088
                               │  events (HTTP + HMAC)  ▲ maze view / policy
                               ▼                        │
   ┌──────────────────────── core (Go, one process) ───────────────────────┐
   │ sensor API :8443 ─► ingest ─► bus ─► intel engine ─► alerter          │
   │                                   │      │   ▲          │             │
   │                                   │      ▼   │          ▼             │
   │                              maze controller  mlclient  Discord/Slack │
   │ analyst API :8090 (REST + SSE)                                        │
   └───────────────────────────────────────────────────────────────────────┘
   ════════════════ mgmt_net ════════════════
     postgres :5432    ml (FastAPI) :8000    codeguard :8001    frontend :3000
```

`core` is the only container on both networks. Decoys reach only `core:8443`.

## Responsibilities

| Component | Owns | Never does |
| --- | --- | --- |
| Decoys (`cmd/decoy-*`) | Emulate a service, emit events, ask maze for view, obey policy | Execute input, score, store, reach internet |
| Ingest | HMAC auth, validation, normalization, dedup, session mapping, persist, publish to bus | Detection logic |
| Intel engine | Fingerprints, correlation, rules, MITRE, risk, behaviour class, ML calls | Network calls other than ML |
| Maze controller | Per-actor interest, unlock decisions, limits | Expose real systems |
| Alerter | Incidents, severity, Discord/Slack, dedup/cooldown | Block outside lab |
| Response | Policy (blocked IPs, killed sessions, burned tokens) served to decoys | Touch host firewall |
| Analyst API | REST + SSE for the dashboard, auth | Serve decoys |
| ML service | 3 classifiers + summary | Make final decisions |
| Frontend | All analyst UI | Talk to decoys or Postgres |

## Tech stack (fixed)

| Layer | Choice |
| --- | --- |
| Backend | Go 1.23+, stdlib `net/http` (1.22 routing patterns), `pgx/v5`, `golang-migrate`, `golang.org/x/crypto/ssh`, `oklog/ulid/v2`, `gopkg.in/yaml.v3`, `golang-jwt/jwt/v5`, `bcrypt` |
| Frontend | Next.js 15 (App Router) + TypeScript, Tailwind, shadcn/ui, Recharts, React Flow (`@xyflow/react`), native `EventSource` |
| ML | Python 3.11, FastAPI, scikit-learn, joblib, pandas |
| DB | PostgreSQL 16 |
| Infra | Docker Compose v2 |
| Alerts | Discord webhook, Slack incoming webhook |

## Ports

| Service | Port | Network | Exposed to host |
| --- | --- | --- | --- |
| decoy-ssh | 2222 | decoy_net | yes (demo) |
| decoy-web | 8080 | decoy_net | yes (demo) |
| decoy-k8s | 6443 (TLS, self-signed) | decoy_net | yes (demo) |
| decoy-beacon | 8088 | decoy_net | yes (demo) |
| core sensor API | 8443 | decoy_net | no |
| core analyst API | 8090 | mgmt_net | no (frontend proxies) |
| postgres | 5432 | mgmt_net | no |
| ml | 8000 | mgmt_net | no |
| codeguard | 8001 | mgmt_net | no |
| frontend | 3000 | mgmt_net | yes |

## Data flow per event

1. Decoy builds envelope → batches (1 s or 50 events) → `POST /v1/ingest/events` with HMAC.
2. Ingest validates → dedups by `event_id` → maps `sensor_session_id` → `session_id` (creates session on first event)
   → inserts into `events` → publishes on bus.
3. Intel engine (subscriber) updates fingerprints → correlation → rules (+ ML) → findings → risk → behaviour.
4. Maze controller (subscriber to findings) updates interest → may emit `maze.unlock`.
5. Alerter (subscriber to findings/risk) opens/updates incident → notifies.
6. SSE hub (subscriber) pushes `event`, `finding`, `incident`, `actor`, `maze` messages to browsers.
