# Deception SOC

**Catch attackers by giving them fake targets only an intruder would touch, then turn everything they do into one
clear, explainable story the security team can act on in seconds.**

Firewalls and SIEMs drown analysts in alerts, and attackers (more and more often automated tools and AI agents)
move through networks unnoticed for weeks. Deception SOC flips that: it plants fake servers, fake files and fake
credentials that no real user ever needs, so anyone who touches them is an attacker, with almost no false alarms.
Every move is linked into one attacker profile, mapped to MITRE ATT&CK, scored with a transparent risk formula,
explained in plain English, and shown live on a SOC dashboard with alerts and one-click response.

It protects a real product website, **Aetees Bakehouse** (`aeteesbakehouse.com`): suspicious visitors are silently
served a honeypot copy of the shop on the same URL, while real customers are never monitored or affected.

---

## What it does

| Capability | How |
| --- | --- |
| **Decoys** | SSH server with an emulated Ubuntu 22.04 shell (:2222, 160+ commands, variables, `$( )`, loops), admin web app (:8080), AWS-style beacon (:8088), Kubernetes API (:6443), PostgreSQL server (:5433). Nothing is ever executed and nothing leaves the decoy. |
| **Honeytokens** | Fake AWS key, kubeconfig, DB password, SSH key, canary URLs, the shop clone's admin password and an invoice canary. Using one makes the actor critical. |
| **Same-URL honeypot for the website** | `divert-proxy` sits in front of the shop. A request with an exploit payload, a lure path, a scanner or a honeytoken is served by the honeypot clone (same code, synthetic data) with no redirect and no visible change. Main shop: **shadow mode** first (detect and report "would divert"), then live for hard signals only. **Admin subdomain** (`aeteesadmin.`): live honeypot; staff are recognised by a correct real login and get the real admin on the same URL. |
| **Keeping attackers busy** | Adaptive maze (reveals hidden lures that match what the attacker hunts for), AI-written internal pages for unknown paths, fake login success after failed tries, a customer export that stalls at 97 %, breadcrumbs, a tarpit for fast scanners. |
| **One attacker, one story** | Fingerprints plus noisy-OR correlation with credential lineage: a secret stolen on one decoy and used on another links the sessions into one actor, with the reason shown. |
| **ATT&CK and risk** | YAML rules map to MITRE techniques. Risk is a single explainable neuron over kill-chain stages with hard floors: honeytoken used → 90, honeyfile read → 40, confirmed exploit → 35. An LLM fallback maps commands and queries that no rule knows to a technique from an allow-list (low weight, never critical on its own). |
| **ML** | Input-risk model v2 (TF-IDF + logistic regression: command injection, SQLi, XSS, path traversal), trained with real shop-customer text so messages like `Mom's cake; less sugar -- urgent` stay normal. 0 / 40 false alarms on customer text, all attacks caught. |
| **Plain English** | LLM narration of alerts, actors and incidents with an output guard, and a Go template fallback. Provider-neutral: Gemini, Groq, OpenRouter, Anthropic or Ollama. |
| **Respond** | Incidents with recommended actions (block, kill session, divert or release a visitor), a downloadable report, Discord / Slack alerts, false-positive recovery. Actions apply to our decoys and proxy only; for real systems the SOC recommends. |
| **Dashboard** | Live overview (numbers straight from the database), live events, actors (story, correlation graph, ATT&CK panel, maze, tactics, shop diversion), incidents, deception maze, diversions, honeytokens, sensors, scorer. |

## Architecture

```
                       aeteesbakehouse.com / aeteesadmin.…   (Cloudflare Tunnel)
                                      │
                               divert-proxy :8200 ── real shop (unchanged)
                                      │ suspicious
                                      └──────────────── honeypot clone :3101 (synthetic data, lures, tactics)
 decoys: ssh :2222  web :8080  beacon :8088  k8s :6443  postgres :5433  │
            │  signed, batched dsoc.event/v1 envelopes (HMAC)          │
            ▼                                                          ▼
   core (Go) :8443 sensor API ─ ingest ─ bus ─ intel engine (correlate, rules, risk, maze, incidents)
             :8090 analyst API ─ SSE ──────────────► dashboard (Next.js) :3000
                     │                                     
             ML service (FastAPI) :8000 — input risk · narration · ATT&CK fallback · lure pages
             PostgreSQL (Neon or local)
```

## Quick start

Needs Go 1.26+, Python 3.11+, Node 20 and Git Bash (Windows) or bash (Linux).

1. Copy `.env.example` to `.env` and fill in: `DATABASE_URL`, `JWT_SECRET`, `SOC_ADMIN_EMAIL` / `SOC_ADMIN_PASSWORD`,
   one `KEY_*` per sensor and the matching `SENSOR_KEYS`. Optional: `LLM_*` (narration, ATT&CK fallback, lure pages),
   `DISCORD_WEBHOOK_URL` / `SLACK_WEBHOOK_URL`.
2. Start:

```bash
scripts/dev-up.sh          # ML, core, all decoys, divert proxy (if the lab exists), dashboard; logs in .logs/
scripts/aetees-lab.sh      # Aetees lab: real shop :3100 + honeypot clone :3101 (source in ../references/aetee)
scripts/dev-down.sh        # stop everything
```

Dashboard: http://localhost:3000, logging in with `SOC_ADMIN_EMAIL` / `SOC_ADMIN_PASSWORD`.

| Port | Service |
| --- | --- |
| 3000 | SOC dashboard (`DASHBOARD_PORT`; use another port when a real shop already owns 3000) |
| 8090 / 8443 | core analyst API / sensor API (local only) |
| 8000 | ML service (local only) |
| 8200 | divert proxy: the shop's public entry |
| 3100 / 3101 | Aetees lab shop / honeypot clone |
| 2222 · 8080 · 8088 · 6443 · 5433 | SSH · web · beacon · Kubernetes · PostgreSQL decoys |

With Docker: `docker compose --profile decoys --profile demo up` (see [12-infrastructure](docs/12-infrastructure.md)).

## Live website (aeteesbakehouse.com)

The shop runs on a Linux host behind a Cloudflare Tunnel. Point both hostnames at the proxy (`:8200`), not at the
shop, and set in `.env`:

| Variable | Meaning |
| --- | --- |
| `TRUST_CLOUDFLARE=1` | take the visitor's real IP from `CF-Connecting-IP`, only from the local tunnel |
| `DIVERT_MODE=shadow` | main shop: detect and report "would divert", everyone still gets the real shop; `live` diverts hard signals |
| `ADMIN_HONEYPOT_HOSTS=aeteesadmin.aeteesbakehouse.com` | admin subdomain is a live honeypot; staff get the real admin after a correct login |
| `AETEES_REAL_URL`, `PROXY_LISTEN`, `DASHBOARD_PORT` | where the real shop listens, the proxy address, and the dashboard port (keep it off the shop's) |

Step-by-step rollout with checkpoints: [20-live-bait-deployment](docs/20-live-bait-deployment.md).
Audit of the live host: [21-bait-audit](docs/21-bait-audit.md).
Keep the dashboard, core and ML local, or behind Cloudflare Access.

## Testing

```bash
cd backend/go && go vet ./... && go test ./... && bash scripts/check-no-exec.sh
cd ai-service/fastapi && python -m pytest -q && python -m training.evaluate --check
cd frontend/nextjs && npx tsc --noEmit && npm run lint
IP=<this machine's LAN IP> scripts/divert-check.sh    # 20 live cases: 12 harmless stay on the shop, 8 attacks diverted
scripts/attack.sh                                     # scripted attack story against the lab decoys
scripts/reset-demo.sh                                 # dry run; -yes wipes recorded activity for a clean demo
```

Manual tests for every feature, with expected results: [19-run-and-test](docs/19-run-and-test.md).

## Safety

- Decoys, the clone and the honeytokens hold only generated data; the real shop's database, customers and payment
  keys are never copied. `check-no-exec.sh` guarantees no decoy or proxy code can start a program.
- Real customers are never monitored: only diverted visitors produce SOC events. Real passwords that the proxy
  checks for staff are forwarded, never stored or logged.
- Response actions apply to our own decoys and proxy. Going live on a real domain needs the owner's written approval:
  shadow mode first, then hard signals only.

## Known limits

- With Neon (remote Postgres), analysis such as correlation, risk and maze unlocks lags 30–60 s behind the live
  event feed. Postgres next to core makes it near-instant.
- The SSH shell emulates the common bash subset (pipes, `&&` / `||`, redirects, variables, `$( )`, `for` and
  `while read` loops, about 160 commands), not every bash construct.
- The input-risk model and the behaviour rules are trained or tuned on lab data; real traffic will need retraining
  (the analyst feedback loop is in place).

## Documentation

| Doc | Contents |
| --- | --- |
| [00-overview](docs/00-overview.md) | What and why, in plain words |
| [01-architecture](docs/01-architecture.md) | Components, ports, networks, tech stack |
| [02-event-schema](docs/02-event-schema.md) | `dsoc.event/v1` envelope (frozen contract) |
| [03-database](docs/03-database.md) | PostgreSQL schema and migrations |
| [04-api-contract](docs/04-api-contract.md) | Sensor, analyst and ML APIs with JSON examples |
| [05-backend-implementation](docs/05-backend-implementation.md) | Go module layout and build steps |
| [06-decoys](docs/06-decoys.md) | Decoys and honeytokens |
| [07-intelligence-engine](docs/07-intelligence-engine.md) | Fingerprints, correlation, rules, MITRE, risk, behaviour |
| [08-deception-maze](docs/08-deception-maze.md) | Adaptive maze graph, algorithm, limits |
| [09-alerting-response](docs/09-alerting-response.md) | Incidents, Discord / Slack, response actions, reports |
| [10-ml-service](docs/10-ml-service.md) | Input-risk model, narration, ATT&CK fallback |
| [11-frontend-spec](docs/11-frontend-spec.md) | Dashboard pages, components, data flows |
| [12-infrastructure](docs/12-infrastructure.md) | Docker Compose, isolation, environment variables |
| [13-demo-and-testing](docs/13-demo-and-testing.md) | Attack script, tests, acceptance gates |
| [14-milestones-and-team](docs/14-milestones-and-team.md) | Plan and task board |
| [15-references-guide](docs/15-references-guide.md) | What we studied in each reference project |
| [16-future-scope](docs/16-future-scope.md) | Deliberately not built yet, with plans |
| [17-team-handoff](docs/17-team-handoff.md) | What is built and by whom |
| [18-antigravity-prompts](docs/18-antigravity-prompts.md) | Task prompts used to build the remaining parts |
| [19-run-and-test](docs/19-run-and-test.md) | Run locally and test every feature by hand |
| [20-live-bait-deployment](docs/20-live-bait-deployment.md) | Putting the proxy in front of aeteesbakehouse.com |
| [21-bait-audit](docs/21-bait-audit.md) | Audit of the live Linux host |
| [decisions](docs/decisions.md) | Running log of design decisions |
