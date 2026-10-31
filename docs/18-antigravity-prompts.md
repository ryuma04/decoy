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

Local run: scripts/dev-up.sh (ML :8000, core :8443/:8090, decoys, dashboard :3000; logs in .logs/),
scripts/dev-down.sh to stop. Aetees lab shop: scripts/aetees-lab.sh (real :3100, honeypot clone :3101).
How to test by hand: docs/19-run-and-test.md.
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

## Divert proxy — Tasks 9 to 12 (do them in order; each builds on the previous)

Already built for these tasks (do not rebuild): sensorkit `Kit.Diverted(ip)` / `Kit.Released(ip)` from policy
`diverted_ip` / `released_ip`; analyst API `GET/POST /v1/diversions` and the dashboard Diversions page; event types
`session.diverted`, `session.released`, `deception.tactic` (core stores tactics and shows them on the actor page);
honeytokens `tok_aetees_admin` (the clone's admin password) and `tok_aetees_invoice` (canary link in a clone order
note) in backend/go/seed/out/tokens.json; ML endpoint `/ml/v1/classify-input` (input risk) and the LLM helper
`app/narrate.call_llm` in ai-service/fastapi.

## Task 9 — Divert proxy: same-URL routing and monitoring

```text
Build internal/divert (proxy.go) and cmd/divert-proxy (Go stdlib net/http + net/http/httputil + internal/sensorkit;
no os/exec, writes only under DATA_DIR). It listens on LISTEN_ADDR (default :8200) in front of the Aetees lab:
REAL_URL=http://127.0.0.1:3100 (real shop) and CLONE_URL=http://127.0.0.1:3101 (honeypot clone, same Next.js build
with synthetic data). SENSOR_ID=aetees-01, service "web"; add aetees-01 with a new 32-char key to SENSOR_KEYS in
.env.example and to scripts/dev-up.sh (start it after the lab is up; skip it if .lab/aetees is missing).

Routing — the URL never changes and nothing visible differs:
- Never send an HTTP redirect to switch upstream. Forward with httputil.ReverseProxy, keep the public Host header,
  set X-Forwarded-For to the client IP (the shop rate-limits admin logins by it).
- Set one visitor cookie (e.g. "_aet_v", random id, HttpOnly, SameSite=Lax) on the first response for EVERY visitor,
  so its presence reveals nothing. Visitor key = cookie, falling back to IP + User-Agent.
- Per visitor keep: diverted bool, severity (soft|hard), reason, divertedAt, lastTrip, clean request count.
- Kit.Blocked(ip) -> 403. Kit.Diverted(ip) and not Kit.Released(ip) -> divert (hard, reason "core policy").
  Kit.Released(ip) on a diverted visitor -> release (reason "analyst").
- Honeytoken values from tokens.json (tok_aetees_admin password in a request body, tok_aetees_invoice path in the
  URL) -> divert (hard) + a token.used event {token_id, token_kind, via}.
- Define the interface the next task implements and call it on every request of a not-yet-diverted visitor:
    type Classifier interface { Classify(r *http.Request, body []byte, v VisitorView) Trip }
  (Trip{Sev None|Soft|Hard, Reason, Label, Param, Value}; VisitorView{NotFound5m, FailedLogins10m, RequestsPerMin});
  a nil Classifier means only policy and honeytokens divert. Count 404s and failed admin logins per visitor from
  upstream responses (ModifyResponse) to fill VisitorView.

Monitoring — only diverted visitors; real customers' traffic never goes to core:
- On divert: one sensorkit session per divert ("aetees-01:<visitor id>:<n>"), first event session.diverted
  {reason, severity, label}, then http.request {method, path, query, status, ua, body_sample (<= 512 bytes)} for
  every page/API request (skip /_next/ and image/font files), auth.attempt {method: form, username, success} for
  POST /api/admin/login, token.used as above. On release: session.released {reason} and stop emitting.

Done means: go test ./internal/divert/... with httptest upstreams covering: undiverted visitor reaches the real
upstream and emits nothing; policy-diverted IP reaches the clone with the same URL and status; released IP goes back;
honeytoken in body diverts; cookie is set for everyone; no redirect is ever sent. scripts/check-no-exec.sh passes.
```

## Task 10 — Tripwire classifier

```text
Implement internal/divert/tripwire.go: a type satisfying divert.Classifier from Task 9.
Trip.Sev decides what happens:
- Hard: something only an attacker does on this site (e.g. requesting files a Next.js shop never serves,
  exploitation payloads in query/body/path, known offensive tool user agents, repeated failed admin logins).
  The visitor is moved to the clone and stays there until an analyst releases them.
- Soft: something a curious or clumsy customer might also do (odd characters in a search, a burst of 404s,
  a scripted HTTP client). The visitor is diverted but auto-released after clean behaviour (Task 11).
- None: normal browsing, cart, checkout, menu, static assets.
Reuse what exists: decoy/web.CheckInput (separator pre-check) and the ML input-risk service via mlclient
(label + risk 0..1) for values that pass the cheap check; if ML is down, decide from the pre-check alone.
Label must be one of cmd_injection, sqli, xss, path_traversal, sensitive_path, scanner, bruteforce, probe, so the
core rules can map it. Keep false positives low: the real shop's normal traffic (routes in
../references/aetee/src/app) must classify as None. When a diverted visitor trips with an injection label, the
proxy also emits input.suspicious {param, value, path} so core's input-risk rules fire.
Done means: table tests in tripwire_test.go covering each label plus at least 20 normal shop requests that return
None; go test ./internal/divert/... passes.
```

## Task 11 — False-positive recovery in the proxy

```text
In internal/divert add recovery.go:
- Auto-release: a visitor diverted with severity soft is released after RELEASE_CLEAN_REQS (default 12) page/API
  requests and RELEASE_CLEAN_SECS (default 120) with no new trip -> session.released {reason: "auto: clean
  behaviour", clean_requests, seconds}. A new hard trip while soft-diverted upgrades to hard (no auto-release).
- Hold writes: while soft-diverted, POST /api/checkout and POST /api/contact are not forwarded; return the shop's
  own error shape {"success": false, "error": "We're receiving a lot of orders right now. Please try again in a
  minute."} with 503, and emit http.request with "held": true. A released customer simply retries and it works.
  Never return a fake successful order to a soft-diverted visitor.
- Verified admin: a soft-diverted visitor who POSTs /api/admin/login is checked against the REAL upstream; if the
  real shop accepts, release (reason "verified real admin login") and return the real response with its cookie.
  For a hard-diverted visitor never do this check.
- Analyst release from the dashboard (Kit.Released) wins over everything; afterwards only a hard trip re-diverts
  that IP for 24 h.
Done means: tests for auto-release timing, upgrade soft->hard, checkout hold, verified admin release, analyst release.
```

## Task 12 — Lures, cognitive tactics and LLM pages inside the clone

```text
In internal/divert add lures.go and tactics.go. Everything here applies only to diverted visitors; undiverted
visitors never see any of it. Values come from backend/go/seed/out/tokens.json, never hard-coded.
Lures (each read emits file.read or file.download with honeyfile_id = the token id):
- /.env.bak: a fake env file whose admin password is the tok_aetees_admin value and DB password the tok_db value.
- /backup/ directory listing and /backup/aetees_db_FINAL.sql.gz (small gzip of a fake SQL dump that contains the
  canary invoice link).
- the canary path (tok_aetees_invoice) serves a simple invoice page and emits token.used.
Cognitive tactics (each emits one deception.tactic {tactic, bias_pattern, lure_id, effect} per visitor):
- false_success (bias confirmation): after 3 failed admin logins, rewrite the body to the clone's credentials so
  the clone logs them in; the clone's admin panel shows only synthetic data.
- sunk_cost_export (bias sunk_cost): /api/admin/export returns a job whose progress climbs then stalls near 97 %
  for several polls before offering a CSV of the clone's synthetic customers; effect {polls, seconds_spent}.
- breadcrumb (bias anchoring): add one HTML comment to clone HTML pages pointing at /.env.bak and /backup/
  (request the clone with Accept-Encoding: identity so the body can be edited; fix Content-Length).
- tarpit (bias sunk_cost): when a diverted visitor exceeds 60 requests/min, add a growing delay up to 2 s.
LLM pages (optional): when the clone returns 404 for a path that looks interesting (admin, internal, staff,
report, export, config), call a new ML endpoint POST /ml/v1/lure-page {path, site: "Aetees Bakehouse"} that uses
app/narrate.call_llm to return {title, body_html} with an output guard (no scripts, no external links, no real
personal data), wrap it in a page using the shop's colours (#5a3424, #f8ecc2) and fonts (Oswald, Inter), cache per
path on disk under DATA_DIR, timeout 4 s, fall back to the clone's 404. Emit deception.tactic {tactic: llm_page}.
Add maze nodes lure_aetees_env and lure_aetees_orders to backend/go/maze/maze.yaml under an aetees_entry node.
Done means: tests for each lure, each tactic firing once per visitor, the guard rejecting <script> and external
links, cache hit on the second request; and the manual steps you add to docs/19 §9 work against
scripts/aetees-lab.sh.
```
