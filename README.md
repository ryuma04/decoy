# Deception SOC

Deception-driven threat detection and response: decoys, honeytokens, attacker correlation, MITRE ATT&CK mapping,
an adaptive deception maze and a live SOC dashboard.

## Quick start (after M1)

```bash
cp .env.example .env            # set DISCORD_WEBHOOK_URL, SOC_ADMIN_PASSWORD, SENSOR_KEYS
docker compose up --build       # core, decoys, postgres, ml, frontend
open http://localhost:3000      # SOC dashboard
docker compose run --rm attacker /scripts/attack.sh   # authorised demo attack, lab only
```

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
| [14-milestones-and-team](docs/14-milestones-and-team.md) | Plan and task board for 4 people |
| [15-references-guide](docs/15-references-guide.md) | What to study in each reference repo |
| [decisions](docs/decisions.md) | Running log of design decisions |
