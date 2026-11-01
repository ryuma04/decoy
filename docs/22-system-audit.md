# 22 — System audit (2026-11-01, main @ 0e6d816, Windows dev machine)

Everything was run, not read: all test suites, every service, every decoy, the 20-case live proxy check, every
dashboard page, incidents and reports.

## Automated checks

| Check | Result |
| --- | --- |
| `go build ./...`, `go vet ./...` | pass |
| `go test ./...` (all 23 packages) | pass |
| `scripts/check-no-exec.sh` (no decoy / proxy code can start a program) | pass |
| ML `pytest` | 61 passed |
| ML `training.evaluate --check` (targets) | pass (model v2.1) |
| Dashboard `tsc --noEmit` | **failed** (missing `@phosphor-icons/react`), **fixed** by installing it |
| Dashboard lint | pass |
| `scripts/divert-check.sh` (12 harmless + 8 attacks through the proxy) | 20 / 20 |

## Live checks

| Component | Result |
| --- | --- |
| 12 services (ML, core ×2, 5 decoys, proxy, real shop, clone, dashboard) | all listening |
| Sensors (6) | all `ok`, heartbeats current |
| Web decoy: `.env` lure, diagnostics injection | 200, events recorded |
| Beacon canary URL | 200, event recorded |
| K8s decoy: `/version` open, no token → 401, stolen token → 200 | correct |
| DB decoy (Postgres wire): version, catalog, fake tables | correct |
| SSH decoy: login, honeyfile read, text tools | correct |
| Engine: events → actors / findings | works; **backlog of 15 events took ~2.5 min to clear** (Neon) |
| Incidents: LLM narration, recommended actions, report download | works (narration source `llm`) |
| Dashboard pages (9) with a session | all 200, no errors (after the fix above) |
| Logs (core, proxy, 5 decoys, ML) | no errors or panics |

## Broken — found and fixed in this audit

| # | Problem | Impact | Fix |
| --- | --- | --- | --- |
| B1 | Dashboard returned **HTTP 500 on every page**: commit 6c1ce58 added `@phosphor-icons/react` to package.json but `node_modules` predated it, and `dev-up.sh` only ran `npm install` when `node_modules` was missing | whole SOC UI down | installed it; `dev-up.sh` now reinstalls whenever `package-lock.json` is newer than the last install (teammates who pull get it automatically) |

## Not working / not configured (open)

| # | Item | Impact | What to do |
| --- | --- | --- | --- |
| N1 | **Discord / Slack alerts**: `DISCORD_WEBHOOK_URL` and `SLACK_WEBHOOK_URL` are empty | incidents open on the dashboard, but **no alert is sent** | add a webhook URL to `.env`, restart core |
| N2 | **Docker setup incomplete**: `docker-compose.yml` has no DB decoy, divert proxy or Aetees lab | `docker compose up` gives a partial system; the scripts (`dev-up.sh`) are the complete path | add `decoy-db` and `divert-proxy` services (lab stays script-based: client source is not in git) |
| N3 | **Live website not yet behind the proxy**: per docs/21 the Linux host's tunnel still sends aeteesbakehouse.com straight to the shop, and that host runs an old copy of the repo | the bait is not live on the real domain | pull latest on the Linux host, follow docs/20 (shadow mode first) |
| N4 | **Analysis lag on Neon** — **improved**: correlation loaded every candidate session and its fingerprints one query at a time (up to 218 round trips × ~200 ms per event); now bulk-loaded (2 queries), engine workers 4 → 12, DB pool 16 → 32. Same workload: 194 s → 41 s, mean 63.8 → 8.9 queries per event, worst event 43.7 s → 10.3 s. `ENGINE_TRACE=1` logs per-event time and round trips | remaining cost is Neon's ~200 ms per round trip; local Postgres would make it near-instant |
| N5 | **Human / script / AI behaviour: rules only**, no trained model | AI-agent detection is heuristic; on the website only "scripted" is visible | record human + agent SSH sessions, train (docs/16) |
| N6 | **Lab shop contact form returns 500** (no mail / Telegram keys in the lab) | held-message replay shows `failed` in the lab (works against a configured shop) | add test mail keys to the lab, or accept for demos |
| N7 | **Unseen XSS variants** are the model's weakest spot (F1 0.65 on held-out families) | some novel XSS shapes score < 0.5 | same recipe as SQLi: more variety + `python -m training.lofo --label xss` |
| N8 | Web decoy login `.star` CSS (merged from `master`) has **no element using it** | nothing visible changes | add the element or drop the CSS (ask the author) |
| N9 | Two AI lure pages cached from before the token-budget fix still show the plain fallback | `/internal/staff-report`, `/reports/export-config` look generic | delete the files in `.data/aetees/lure_pages/` |

## Not broken (explanations for things that look wrong)

- **Many actors (100+)**: each fresh visitor is its own session; a shared IP alone never merges actors (by design). Most
  are leftovers from automated tests — `scripts/reset-demo.sh -yes` before a demo.
- **`gofmt -l` lists ~70 files**: Windows checkout with `core.autocrlf=true` gives CRLF line endings; the committed
  files are LF and formatted. Not an issue on Linux or in git.
- **docs/21 says the proxy, recovery and lures are "missing"**: it audited an old copy on the Linux host; they exist on
  main.
- **Plain `curl` gets diverted (soft)**: intended, a scripted client is a soft signal; use a browser user-agent for
  customer tests.
