# Deception SOC

Deception-driven threat detection and response. We plant fake servers, fake files and fake credentials that no real
user ever touches, so anyone who touches them is an attacker. Every move is linked into one attacker profile, mapped
to MITRE ATT&CK, scored with an explainable risk formula, explained in plain English and shown live on a SOC
dashboard, with alerts to Discord / Slack and lab-only response actions.

## What is in it

| Part | What it does |
| --- | --- |
| **Decoys** | SSH server with an emulated shell (:2222), admin web app (:8080), AWS-style beacon (:8088), Kubernetes API (:6443), **Postgres database (:5433)**. None of them ever executes anything. |
| **Honeytokens** | Fake AWS key, kubeconfig, DB password, SSH key, canary URLs, Aetees admin password and invoice link. Using one = critical. |
| **Intel engine** (Go core) | Fingerprints, noisy-OR correlation with credential lineage (stolen here, used there = same operator), YAML rules → ATT&CK, risk neuron with overrides, adaptive maze, incidents. |
| **ML service** (FastAPI) | Input-risk model (TF-IDF + logistic regression: cmd injection, SQLi, XSS, path traversal); LLM narration of alerts and actors; **LLM fallback** that maps commands / queries no rule knows to an ATT&CK technique from an allow-list (low weight, never critical on its own). Provider-neutral (Gemini, Groq, OpenRouter, Anthropic, Ollama). |
| **Dashboard** (Next.js) | Overview, live events, actors (story, correlation graph, ATT&CK panel, maze, tactics, shop diversion), incidents with actions and reports, maze, honeytokens, sensors, scorer, **diversions**. |
| **Product website** | Aetees Bakehouse lab copy: real shop (:3100) and a honeypot clone with synthetic data (:3101). The divert proxy that serves flagged visitors the clone on the same URL is being built by the team (docs/18 Tasks 9–12). |

## Quick start (local, no Docker)

Needs Go 1.23+, Python 3.11+, Node 20 and a `.env` (copy `.env.example`: `DATABASE_URL`, `JWT_SECRET`,
`SOC_ADMIN_*`, the `KEY_*` sensor keys and `SENSOR_KEYS`, optional `LLM_*` and webhook URLs).

```bash
scripts/dev-up.sh          # ML :8000, core :8443/:8090, all decoys, dashboard :3000 (logs in .logs/)
scripts/aetees-lab.sh      # optional: Aetees real shop :3100 + honeypot clone :3101 (needs ../references/aetee)
scripts/attack.sh          # optional: scripted demo attack against the lab decoys
scripts/dev-down.sh        # stop everything
```

Dashboard: http://localhost:3000 — `SOC_ADMIN_EMAIL` / `SOC_ADMIN_PASSWORD` from `.env`.
Step-by-step manual tests for every feature: [docs/19-run-and-test.md](docs/19-run-and-test.md).

With Docker: `docker compose --profile decoys --profile demo up` (see [12-infrastructure](docs/12-infrastructure.md)).

## Lab only

Decoys and the clone hold only generated data. Response actions (block, kill session, divert) apply to the lab
decoys; for real systems the SOC only recommends. Do not put the divert proxy in front of a real site without the
owner's explicit approval.

## Specification

| Doc | Contents |
| --- | --- |
| [00-overview](docs/00-overview.md) | What and why, in plain words |
| [01-architecture](docs/01-architecture.md) | Components, ports, networks, tech stack |
| [02-event-schema](docs/02-event-schema.md) | `dsoc.event/v1` envelope (frozen contract) |
| [03-database](docs/03-database.md) | PostgreSQL schema and migrations |
| [04-api-contract](docs/04-api-contract.md) | Sensor, analyst and ML APIs with JSON examples |
| [05-backend-implementation](docs/05-backend-implementation.md) | Go module layout and build steps |
| [06-decoys](docs/06-decoys.md) | SSH, web, Kubernetes, beacon decoys and honeytokens |
| [07-intelligence-engine](docs/07-intelligence-engine.md) | Fingerprints, correlation, rules, MITRE, risk, behaviour |
| [08-deception-maze](docs/08-deception-maze.md) | Adaptive maze graph, algorithm, limits |
| [09-alerting-response](docs/09-alerting-response.md) | Incidents, Discord/Slack, response actions, reports |
| [10-ml-service](docs/10-ml-service.md) | Input-risk model and LLM narration: data, training, serving |
| [11-frontend-spec](docs/11-frontend-spec.md) | Dashboard pages, components, data flows |
| [12-infrastructure](docs/12-infrastructure.md) | Docker Compose, isolation, env vars |
| [13-demo-and-testing](docs/13-demo-and-testing.md) | Attack script, tests, acceptance gates |
| [14-milestones-and-team](docs/14-milestones-and-team.md) | Plan and task board |
| [15-references-guide](docs/15-references-guide.md) | What to study in each reference repo |
| [16-future-scope](docs/16-future-scope.md) | Deliberately not built yet, with plans |
| [17-team-handoff](docs/17-team-handoff.md) | What is built, what is left, who builds it |
| [18-antigravity-prompts](docs/18-antigravity-prompts.md) | Copy-paste prompts for the remaining tasks |
| [19-run-and-test](docs/19-run-and-test.md) | Run locally and test every feature by hand |
| [20-live-bait-deployment](docs/20-live-bait-deployment.md) | Prompt: audit + put the divert proxy in front of aeteesbakehouse.com (Cloudflare Tunnel, shadow mode first) |
| [decisions](docs/decisions.md) | Running log of design decisions |
