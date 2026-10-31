# 20 — Live bait deployment: aeteesbakehouse.com on the Linux laptop

The Aetees shop runs on a second (Linux) laptop and is published on `aeteesbakehouse.com` through a Cloudflare Tunnel.
This doc is the prompt for the coding agent on that laptop (Antigravity / Claude Code): first audit what is built
and whether it works there, then put the divert proxy in front of the shop so the website itself becomes bait.

Paste the "Shared context" block from docs/18 first, then the prompt below.

```text
GOAL
Turn the Aetees shop published at aeteesbakehouse.com (Cloudflare Tunnel -> this Linux laptop) into bait:
every visitor reaches the site through our divert proxy; suspicious visitors are silently served the honeypot
clone on the same URL and recorded in the SOC; real customers are never monitored and never harmed.
Work in two phases. Do not start phase 2 before phase 1's report is written.

SAFETY RULES (non-negotiable)
- If the site behind the tunnel is the REAL shop (real customers, real orders, live payment keys), the proxy must
  start in SHADOW mode (detect + report, divert nobody) and may switch to LIVE diverting only after the human
  confirms in chat that the business owner approved it in writing. Ask; do not assume.
- The clone holds only synthetic data (scripts/aetees-lab.sh clone instance, SQLite). Never copy the real
  database, real customer data or real payment keys into the clone, the SOC, logs or git.
- Response actions (block / divert) apply only to our proxy and decoys, never to Cloudflare firewall rules or the
  real server, unless the human asks.
- The SOC dashboard (:3000), core analyst API (:8090) and ML (:8000) must NOT be reachable from the internet.
  Expose them only through a separate tunnel hostname protected by Cloudflare Access (email OTP), or not at all.
- Never commit .env, tokens, tunnel credentials (~/.cloudflared/*.json) or the client's source (.lab/ is ignored).

PHASE 1 — AUDIT (report only, change nothing)
1. Repo state: `git log --oneline -5` and `git status`. The latest work must be present: check that
   internal/divert/wiring_test.go contains TestLureReadsReachCore, TestFalseSuccessKeepsJSON,
   TestAnalystReleaseAppliesOnce; ai-service/fastapi/data/customer_set.yaml exists; models card says v2;
   internal/sensorkit/sensorkit.go has mazeViewTimeout. If any is missing: STOP and tell the human to push
   from the main machine (they are uncommitted there) and pull here.
2. Tooling: go version (>= 1.23), node -v (20), python3 --version (>= 3.11), cloudflared --version.
3. Configuration: .env present with DATABASE_URL, JWT_SECRET, SOC_ADMIN_*, KEY_SSH/WEB/K8S/BEACON/LOGS/DB/AETEES
   and SENSOR_KEYS containing aetees-01 and db-01, LLM_* (optional). Print key NAMES only, never values.
4. Tunnel: read the cloudflared config (~/.cloudflared/config.yml or the dashboard-managed tunnel) and report
   which hostname points to which local port. Report whether aeteesbakehouse.com currently points to the shop
   directly (e.g. :3000/:3100) or to the proxy (:8200).
5. Which shop is behind the tunnel: real production build with its real database, or the lab copy
   (scripts/aetees-lab.sh)? Ask the human if unclear. Record the answer in the report.
6. Run every automated check and paste the summary lines:
     cd backend/go && go vet ./... && go test ./... && bash scripts/check-no-exec.sh
     cd ai-service/fastapi && python -m pytest -q && python -m training.evaluate --check
     cd frontend/nextjs && npx tsc --noEmit && npm run lint
7. Start the stack locally (scripts/dev-up.sh, scripts/aetees-lab.sh) and run, from THIS laptop, with IP = one of
   this machine's non-loopback addresses:   IP=<lan-ip> scripts/divert-check.sh   (expect 20 passed, 0 failed)
8. Walk docs/19 sections 1-8 and the divert-proxy section; for each feature record PASS / FAIL / NOT RUN with one
   line of evidence (event type seen, HTTP status, actor label). Features to cover:
   SSH decoy, web decoy, beacon, K8s decoy, DB decoy (psql on 5433), honeytokens (token.used -> critical),
   correlation (credential lineage merges actors), MITRE findings, risk overrides (confirmed_exploit_attempt,
   honeyfile_read, token_used), LLM fallback mapping (llm findings), narration, incidents + actions + report,
   Discord/Slack alert (if webhook set), adaptive maze (hidden lure unlocks; may lag ~1 min on Neon),
   divert proxy (same URL, no redirect, lures, false success, sunk-cost export, breadcrumb, LLM page,
   soft-divert checkout hold, auto-release, analyst release from Dashboard -> Diversions), Overview live updates.
9. Write the report to docs/21-bait-audit.md: a table Feature | Status | Evidence | Fix needed, then a list of
   gaps found. Show it to the human before phase 2.

PHASE 2 — IMPLEMENT (each step with tests; go test ./... must stay green)
A. Real client IP behind Cloudflare (BLOCKER). Behind the tunnel every request reaches the proxy from cloudflared
   on 127.0.0.1, so today every visitor shares one IP (and 127.0.0.1 may be "released" in policy).
   In internal/divert/proxy.go: when TRUST_CLOUDFLARE=1 and the TCP peer is loopback, take the client IP from the
   CF-Connecting-IP header (fall back to the first X-Forwarded-For entry); otherwise ignore those headers (they
   can be forged). Use that IP everywhere the proxy uses the client IP (visitor key, policy checks, sensorkit
   session src IP, X-Forwarded-For sent upstream). Tests: trusted loopback + header -> header IP; non-loopback
   peer + header -> peer IP; header absent -> peer IP.
B. HTTPS awareness. Cloudflare terminates TLS, so the proxy sees plain HTTP. When TRUST_CLOUDFLARE=1, treat
   X-Forwarded-Proto: https (from loopback) as TLS: do NOT strip the Secure cookie flag
   (insecureCookiesOnHTTP) and keep cookies identical to the real site. Test both cases.
C. SHADOW mode. Add DIVERT_MODE=shadow|live (default shadow). In shadow mode the tripwire, honeytoken and policy
   checks run exactly as in live mode, but every request is forwarded to the REAL shop; instead of diverting,
   send one event per visitor+reason: session.diverted with data {"shadow": true, reason, severity, label}
   (events from shadow visitors are the only ones sent; normal visitors still send nothing). Lures, tactics and
   checkout holds are never applied in shadow mode. The Diversions page and Live Events must show "would divert"
   for shadow events (frontend: badge when data.shadow is true). Tests for both modes.
D. ADMIN SUBDOMAIN HONEYPOT (aeteesadmin.aeteesbakehouse.com; no new subdomain). Legitimate visitors there are only
   the owner and staff, so this host runs in LIVE mode from the start, independent of DIVERT_MODE for the main site.
   - Config: ADMIN_HONEYPOT_HOSTS=aeteesadmin.aeteesbakehouse.com (comma list; matched on the request Host, port
     ignored). The shop's own middleware already rewrites that host to /admin pages; both copies receive the same
     public Host, so the clone renders the identical admin panel.
   - Every new visitor on an admin-honeypot host is served the CLONE (session.diverted, severity hard,
     label admin_subdomain, reason "admin subdomain") - except staff, below.
   - Staff keep using the same URL and their normal password: on POST /api/admin/login from a visitor on an
     admin-honeypot host who is not yet staff, first send a copy of the request to the REAL shop (reuse the
     verified-admin check in recovery.go, but allow it for this hard divert). If the real shop answers 200: mark
     the visitor as STAFF (visitor cookie bound, plus the real admin_token cookie it sets), emit
     session.released {reason: "verified staff login"}, return the real response; all later requests of that
     visitor go to the real shop and send no events. Otherwise forward to the clone as usual (failed tries count
     toward false_success; the tok_aetees_admin password gives token.used).
   - A staff visitor who logs out (POST /api/admin/logout) or whose real admin_token cookie disappears goes back to
     "unverified" (next visit starts in the clone again until they log in).
   - Never log, store or emit real passwords: auth.attempt events carry the username and success only; the copy sent
     to the real shop is not kept. Staff logins must not appear in the SOC at all (only session.released).
   - Real-shop brute-force protection still applies: the copy to the real shop carries the visitor's real IP in
     X-Forwarded-For, so an attacker cannot use the proxy to bypass the 5-tries lockout.
   - Tests: unknown visitor on the admin host -> clone; correct real password -> staff -> real for the next 5
     requests, no events after release; wrong passwords -> clone, false_success after 3; honeytoken password ->
     clone + token.used; logout -> clone again; a request to the MAIN host never takes this path; no password
     string appears in any emitted event.
   - Before enabling it on the real domain, tell the human to inform the owner/staff: "same link, same password;
     the first page after opening the admin may ask you to log in again."
   - Also record what Host the tunnel sends for the main domain and confirm /admin on aeteesbakehouse.com behaves
     the same for the real shop and the clone (the shop redirects it to / outside localhost/LAN).
E. Wiring: scripts/dev-up.sh starts the proxy with TRUST_CLOUDFLARE and DIVERT_MODE from .env; .env.example
   documents both plus ADMIN_HONEYPOT_HOSTS; dev-down stops it. Tunnel config: aeteesbakehouse.com AND
   aeteesadmin.aeteesbakehouse.com -> http://127.0.0.1:8200 (the proxy), NOT directly to the shop. The dashboard
   stays local (or its own hostname behind Cloudflare Access).
F. Clone parity check through the tunnel: fetch the same 10 public pages via the domain while (a) not diverted and
   (b) diverted from Dashboard -> Diversions; compare status codes, header names, cookie names and HTML <title>;
   report any difference (it would reveal the honeypot).
G. Admin subdomain goes live once D passes its tests and the human confirms the owner/staff were told.
   The MAIN site goes live only after the human confirms owner approval in chat AND reviewed a day of shadow
   results: then DIVERT_MODE=live, but divert only HARD trips on the main site (lure paths, honeytokens, offensive
   scanners, exploit payloads); soft trips stay shadow. Rerun step F and scripts/divert-check.sh from an outside
   network (phone hotspot) using the public domain.

DONE MEANS
- docs/21-bait-audit.md written and shown; every FAIL either fixed in phase 2 or listed as a known gap.
- go test ./... , pytest, tsc and lint green; check-no-exec ok.
- Through https://aeteesbakehouse.com from an outside network: normal browsing creates no SOC events; a probe of
  /.env.bak creates session.diverted with the VISITOR'S public IP (not 127.0.0.1) — in shadow mode marked
  "would divert" and the visitor still sees the real shop; in live mode the visitor gets the clone, same URL.
- https://aeteesadmin.aeteesbakehouse.com from an outside network: an unknown visitor gets the clone admin login;
  3+ wrong passwords then "logged in" to synthetic orders (false_success), all visible in the SOC with the visitor's
  public IP; the owner's real password gets the real admin on the same URL and produces no SOC events.
- Dashboard not reachable without Cloudflare Access.
- docs/19 gains a "Live domain" section with the exact test steps and expected results.
```

## Notes for the human
- Push the main machine's uncommitted work before running this; phase 1 step 1 stops otherwise.
- Admin subdomain: live honeypot from day one (no customers go there); staff keep the same link and password.
- Main shop: shadow mode first (detect + "would divert", everyone gets the real shop); then live for hard trips only,
  with the owner's written approval.
- The engine on Neon analyses events with a 30-60 s lag (maze unlocks, risk); Live Events itself is near-instant.
