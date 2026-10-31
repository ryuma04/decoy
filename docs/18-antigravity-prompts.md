# 18 — Prompts for the blocked parts (paste into Antigravity)

One prompt per part from `17-team-handoff.md`. Paste the **shared context** first, then one task prompt. Do the
tasks in this order: 1 → 5 → 8 → 2 → 3 → 4 → 6 → 7 (the SSH decoy and features give the demo the most value).
After each task, run the checks it lists and tick the row in `17-team-handoff.md`.

---

## Shared context (paste before every task)

```text
You are working in the repo "Decoy-" (Deception SOC, hackathon, lab use only). Read these first:
- README.md, docs/00-overview.md, docs/01-architecture.md
- docs/02-event-schema.md (event envelope, frozen), docs/04-api-contract.md (APIs, frozen)
- docs/17-team-handoff.md (what is built, what is left)
- backend/CLAUDE.md (backend rules)

Rules:
- Go 1.23+ module at backend/go (module path github.com/ryuma04/decoy/backend). Only the libraries listed in
  docs/05-backend-implementation.md. Next.js 15 + TypeScript strict in frontend/nextjs.
- Do not change docs/02, docs/03 or docs/04 (contracts). If something must change, stop and say so.
- Reuse what exists; do not rewrite tested packages. Write tests with every feature.
- Decoy code (internal/decoy/..., cmd/decoy-*) must never execute, fetch or resolve anything real, never import
  os/exec, and never write outside /data and /tmp. scripts/check-no-exec.sh enforces this.
- No real secrets. Honeytoken values come only from cmd/seed (seed/out/tokens.json).
- Before finishing: cd backend/go && go vet ./... && go test ./... && ./scripts/check-no-exec.sh

Local run (core + ML already work against the database in .env):
  cd backend/go && go run ./cmd/seed
  cd backend/go && set -a && . ../../.env && set +a && go run ./cmd/core serve
  (dashboard) cd frontend/nextjs && npm run dev   -> http://localhost:3000
```

---

## Task 1 — SSH decoy network server

```text
Build the SSH decoy server: internal/decoy/ssh/server.go and cmd/decoy-ssh/main.go. Spec: docs/06-decoys.md §1,
limits in docs/08-deception-maze.md, event types in docs/02.

Already built — use, don't rewrite:
- internal/decoy/ssh/lineedit.go (LineEditor: echo, edits, paste, timing fields)
- internal/decoy/ssh/commands.go (Shell.Run: emulated commands over the fake filesystem; returns output,
  argv0/args, file reads with honeyfile ids, stdout tokens)
- internal/decoy/ssh/tree.go (BaseTree from persona + lures), internal/fakefs, internal/persona
- internal/sensorkit (NewSession, Session.Event, Blocked/Killed policy, MazeView, Start/Close)
- cmd/send-sample/main.go shows how to emit events through sensorkit

Build:
- golang.org/x/crypto/ssh server, ServerVersion "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", persistent ed25519
  host key in DATA_DIR/ssh_host_ed25519.
- Emit conn.open / conn.close, an auth.attempt for every try (password and public key; record key_fp).
  Accept only the persona passwords (seed/out/persona.json) and the planted deploy key; on that key emit token.used.
- PTY shell and exec through LineEditor + Shell; one shell.command event per line with the timing object;
  file.read for each read (with honeyfile_id).
- Load lures from seed/out/tokens.json (path, content, hidden, maze_node) into BaseTree; call sensorkit MazeView
  (cached 2 s) on ls/find/cat and pass visible nodes to FS.SetVisible.
- Limits enforced inside the decoy: 10 min idle, 30 min cap, 500 commands. Refuse blocked IPs, close killed
  sessions (policy polled by sensorkit).
- Env: SENSOR_ID, SENSOR_KEY, CORE_URL, LISTEN_ADDR (:2222), DATA_DIR, SEED_DIR.

Done means: `ssh -p 2222 deploy@localhost` with the persona password gives a prompt; typed commands appear on the
dashboard live events page in < 2 s; a blocked IP is refused within 5 s; tests for auth callbacks and limits;
check-no-exec passes.
```

## Task 5 — Session features and behaviour class

```text
Build internal/intel/features (per-session and per-actor rolling features) and internal/intel/behaviour (rule
classifier). Spec: docs/07-intelligence-engine.md §3 and §7, BehaviourDetail type in docs/04.

Plug in through the existing interface in internal/intel/engine/engine.go:
  type Features interface { Observe(ev store.StoredEvent); Session(id string) map[string]float64; Actor(id string) map[string]float64 }
Set Engine.Features in cmd/core/main.go.

Features the rules already use (rules/rules.yaml): failed_auths_5m, distinct_pairs, successful_logins, commands,
services_visited. Behaviour features (07 §7): median_gap_ms, gap_cv, edit_rate, paste_rate, output_dependence,
services_visited, breadcrumbs_followed, param_mutation_retries, commands.

Then: write behaviour_class + behaviour_score on the actor at 5/10/20/40 commands (store method needed) and return
them from GET /v1/actors/{id} (internal/api/actors.go currently returns zeros and "unknown").
Wording: behaviour classes describe behaviour, never identity.

Done means: unit tests per feature and per class rule; the password_guessing, interactive_shell and multi_decoy
rules fire in a live run; the actor detail shows real features.
```

## Task 8 — Discord / Slack notifiers

```text
Build internal/alert/notify.go: Discord and Slack webhook notifiers plus a small queue with 3 retries and backoff
that never blocks the engine. Spec: docs/09-alerting-response.md (Notification policy, Discord payload, Slack Block
Kit, readable message text).

Already built: internal/alert/policy.go (Decide → channel, Cooldown, Colour), internal/incident/incident.go
(Manager with a NotifyFunc hook — implement that function and set it in cmd/core/main.go), internal/narrate
(Narrator.Narrate gives headline/text/bullets; use a 3 s budget for alerts, template on timeout),
cmd/webhook-mock (local receiver for tests).

Rules: strip any @mentions from narration text; add @here yourself only for critical; Slack only for critical;
medium goes into a 15-minute digest. Env: DISCORD_WEBHOOK_URL, SLACK_WEBHOOK_URL, DASHBOARD_URL.

Done means: tests against httptest servers (payload shape, retries, no mention injection); with webhook-mock, a
critical incident produces one Discord and one Slack message.
```

## Task 2 — Web decoy

```text
Build internal/decoy/web and cmd/decoy-web (port 8080). Spec: docs/06-decoys.md §2. Use sensorkit and persona.
Server-rendered admin login (html/template), robots.txt, /admin/backup listing, the backup zip download (from seed),
/.env, /api/diagnostics ping tool that never runs anything, /api/login JSON, nginx-style 404. Session = cookie sid
else ip+ua for 30 min. Emit http.request, auth.attempt (method form), file.read / file.download (with honeyfile_id),
and input.suspicious using the cheap pre-check in 06 §2 (core re-grades with the input-risk model).
Done means: handler tests for every path; events show on the dashboard; check-no-exec passes.
```

## Task 3 — Kubernetes API decoy

```text
Build internal/decoy/k8s and cmd/decoy-k8s (port 6443, self-signed TLS). Spec: docs/06-decoys.md §3 table
(401 without token, discovery/namespaces/pods/secrets/nodes with the lure token tok_kube from seed/out/tokens.json,
403 on writes). Secrets ci-jenkins-token / db-credentials only when the maze view lists them (sensorkit MazeView,
field k8s_secrets). Emit http.request, k8s.api_call, auth.attempt (bearer), token.used for the lure token.
Done means: handler tests per row of the table; kubectl with the planted kubeconfig lists pods.
```

## Task 4 — Beacon

```text
Build internal/decoy/beacon and cmd/decoy-beacon (port 8088). Spec: docs/06-decoys.md §4. AWS-style endpoint:
any SigV4 Authorization header carrying the lure access key id (seed/out/tokens.json, tok_aws_k7) → token.used
(via aws_api) and an AWS-style AccessDenied XML reply. URL tokens: GET /t/{token_id} → token.used (via url_fetch),
1×1 GIF. Never call real AWS.
Done means: tests for both paths; a signed request with the lure key turns the actor critical on the dashboard.
```

## Task 6 — Dashboard pages

```text
In frontend/nextjs, build the pages from docs/11-frontend-spec.md using the design in DESIGN.md (tokens already
in src/app/globals.css). Already working: login, live events with SSE and event drawer (src/app/page.tsx),
src/lib/api.ts, src/lib/stream.tsx, src/lib/format.ts, src/lib/types.ts (copied from docs/04 — do not edit by hand),
/api/stream pass-through route.

Every backend endpoint exists (docs/04 §B): /stats/overview, /stats/timeseries, /stats/techniques, /actors,
/actors/{id}, /actors/{id}/timeline, /actors/{id}/maze, /incidents, /incidents/{id} (+ PATCH, /actions, /report,
/feedback), /events/{id}/explain, /honeytokens, /sensors, /scorer, /maze.

Build in this order: sidebar layout → overview → actors list → actor profile (header, What happened card, sessions
graph with @xyflow/react, timeline, ATT&CK panel, behaviour, maze, risk breakdown) → incidents list + detail
(actions behind a "Lab environment only" confirm dialog, feedback buttons, report download) → maze → honeytokens →
sensors → scorer. Add mock fixtures in src/mocks/ only if you need them for NEXT_PUBLIC_USE_MOCKS=1.
Severity always has a text label, not colour alone. No `any`.
Done means: npm run build, npm run lint and tsc pass; every page renders against the real backend.
```

## Task 7 — Attack script and attacker container

```text
Build infrastructure/docker/attacker (Dockerfile: debian slim + openssh-client, nmap, curl, jq, sshpass, python3)
and scripts/attack.sh following the demo table in docs/13-demo-and-testing.md. It may only target the lab decoy
hosts (decoy-ssh, decoy-web, decoy-k8s, decoy-beacon) on the isolated decoy_net, reads planted values from
/seed/persona.json and /seed/tokens.json, prints a header per step and waits 2–4 s between steps.
Flags --fast and --slow. Add it to docker-compose.yml under the "demo" profile.
Done means: from a clean `docker compose --profile decoys --profile demo up`, one run yields one actor with ≥ 3
linked sessions, risk ≥ 75 and an open incident (Gate 2 in docs/13).
```
