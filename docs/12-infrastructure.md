# 12 — Infrastructure and isolation

## Networks

| Network | Members | Internet |
| --- | --- | --- |
| `decoy_net` | decoys, core, attacker (demo) | **none** (`internal: true`) |
| `mgmt_net` | core, postgres, ml, codeguard, frontend | outbound only for Discord/Slack/LLM (core, ml) |

Decoys therefore cannot reach Postgres, the dashboard, ML, the Docker socket or the internet. Core is the only
bridge. Core needs outbound internet for webhooks: attach it also to the default bridge network (`egress`), or run
the webhook sender only from core (it is).

## docker-compose.yml (skeleton)

```yaml
name: deception-soc
networks:
  decoy_net: { internal: true }
  mgmt_net: {}
  egress: {}
volumes: { pgdata: {}, sshdata: {}, quarantine: {}, seed: {}, prodlogs: {} }

services:
  postgres:
    image: postgres:16-alpine
    environment: { POSTGRES_DB: dsoc, POSTGRES_USER: dsoc, POSTGRES_PASSWORD: ${PG_PASSWORD} }
    volumes: [pgdata:/var/lib/postgresql/data]
    networks: [mgmt_net]
    healthcheck: { test: ["CMD-SHELL","pg_isready -U dsoc"], interval: 5s, retries: 10 }

  seed:
    build: { context: ./backend/go, target: seed }
    environment: { DATABASE_URL: postgres://dsoc:${PG_PASSWORD}@postgres:5432/dsoc?sslmode=disable, PERSONA_SEED: ${PERSONA_SEED} }
    volumes: [seed:/seed/out]
    networks: [mgmt_net]
    depends_on: { postgres: { condition: service_healthy } }

  core:
    build: { context: ./backend/go, target: core }
    env_file: .env
    environment: { DATABASE_URL: postgres://dsoc:${PG_PASSWORD}@postgres:5432/dsoc?sslmode=disable, ML_URL: http://ml:8000 }
    networks: [decoy_net, mgmt_net, egress]
    depends_on: { postgres: { condition: service_healthy }, seed: { condition: service_completed_successfully } }

  decoy-ssh:
    build: { context: ./backend/go, target: decoy-ssh }
    environment: { SENSOR_ID: ssh-01, SENSOR_KEY: ${KEY_SSH}, CORE_URL: http://core:8443 }
    volumes: [sshdata:/data, quarantine:/data/quarantine, seed:/seed:ro]
    ports: ["2222:2222"]
    networks: [decoy_net]
    read_only: true
    tmpfs: [/tmp]
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 256m
    pids_limit: 128
  # decoy-web (8080), decoy-k8s (6443), decoy-beacon (8088): same hardening block

  ml:
    build: ./ai-service/fastapi
    environment: { CODEGUARD_URL: http://codeguard:8001, LLM_API_KEY: ${LLM_API_KEY:-} }
    networks: [mgmt_net, egress]

  codeguard:            # optional; team's own prior project, run unmodified
    profiles: [codeguard]
    build: { context: ../references/codeguard, dockerfile: ../../deception-soc/infrastructure/docker/codeguard.Dockerfile }
    networks: [mgmt_net]

  frontend:
    build: ./frontend/nextjs
    environment: { CORE_API_URL: http://core:8090 }
    ports: ["3000:3000"]
    networks: [mgmt_net]

  log-collector:        # external telemetry (07 §8)
    build: { context: ./backend/go, target: log-collector }
    environment: { SENSOR_ID: logs-01, SENSOR_KEY: ${KEY_LOGS}, CORE_URL: http://core:8443 }
    volumes: [prodlogs:/logs:ro]
    networks: [decoy_net]

  real-target:          # small "production" host for the demo: nftables firewall logging + sshd + a real login page
    build: ./infrastructure/docker/real-target
    volumes: [prodlogs:/logs]   # writes fw.log, auth.log, app-login.jsonl
    cap_add: [NET_ADMIN]        # nftables inside its own container only
    networks: [decoy_net]

  attacker:             # demo only
    profiles: [demo]
    build: ./infrastructure/docker/attacker
    volumes: [./infrastructure/docker/attacker/scripts:/scripts:ro]
    networks: [decoy_net]
```

Note on decoy ports: publishing decoy ports to the host is for the live demo from a laptop. On a shared or
public network, unpublish them and attack only from the `attacker` container.

`infrastructure/docker/codeguard.Dockerfile`: `FROM python:3.11-slim`, copy the repo, `CMD python -m codeguard.api --host 0.0.0.0 --port 8001`.
It builds from `references/` without modifying it. Enable with `docker compose --profile codeguard up`.

## Dockerfiles

- `backend/go/Dockerfile`: multi-stage; builder `golang:1.23`; one final stage per binary, each `FROM gcr.io/distroless/static:nonroot`, `USER nonroot`.
- `frontend/nextjs/Dockerfile`: `node:20-alpine`, `output: "standalone"`.
- `ai-service/fastapi/Dockerfile`: `python:3.11-slim`, non-root user, models baked in.
- `infrastructure/docker/attacker/Dockerfile`: `debian:bookworm-slim` + `openssh-client nmap curl jq sshpass python3`.

## .env.example

```dotenv
PG_PASSWORD=change-me
JWT_SECRET=change-me-32-bytes-min
SOC_ADMIN_EMAIL=admin@soc.local
SOC_ADMIN_PASSWORD=change-me
KEY_SSH=… KEY_WEB=… KEY_K8S=… KEY_BEACON=… KEY_LOGS=…
SENSOR_KEYS=ssh-01:${KEY_SSH},web-01:${KEY_WEB},k8s-01:${KEY_K8S},beacon-01:${KEY_BEACON},logs-01:${KEY_LOGS}
SCORER_LEARN=false
DISCORD_WEBHOOK_URL=
SLACK_WEBHOOK_URL=
PERSONA_SEED=
LLM_API_KEY=
MAZE_ADAPTIVE=true
```

`.env` is gitignored. Generate keys with `openssl rand -hex 32`.

## Final demo deployment (optional VM)

One Linux VM (4 vCPU, 8 GB). Same compose. Host firewall: allow 22 (real admin SSH moved to a non-standard port if
the SSH decoy should own 22), 3000 only from the team IPs, decoy ports only from the attacker network. Never run on a
network you don't control; never point decoys at the public internet without the organisers' permission.
