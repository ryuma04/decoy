# 19 — Run it and test it by hand

## Start / stop

```bash
scripts/dev-up.sh      # ~10 s: ML :8000, core :8443/:8090, decoys, dashboard :3000. Logs in .logs/
scripts/dev-down.sh    # stops everything
RESEED=1 scripts/dev-up.sh   # new persona + honeytoken values (otherwise the existing seed is reused)
```

Needs `.env` (copy `.env.example`): `DATABASE_URL`, `JWT_SECRET`, `SOC_ADMIN_*`, the five `KEY_*`, `SENSOR_KEYS`,
`LLM_*`. Requires Go, Python 3.11+, Node 20. The Kubernetes decoy starts automatically once `cmd/decoy-k8s` exists.

| What | Where |
| --- | --- |
| Dashboard | http://localhost:3000 — `admin@soc.local`, password = `SOC_ADMIN_PASSWORD` in `.env` |
| SSH decoy | `ssh -p 2222 deploy@localhost` — password = `deploy_password` in `backend/go/seed/out/persona.json` |
| Web decoy | http://localhost:8080 |
| Beacon | http://localhost:8088 |
| Kubernetes decoy | https://localhost:6443 |
| Database decoy | `psql -h localhost -p 5433 -U app orders` — password = `tok_db` in `backend/go/seed/out/tokens.json` (5433 because a local Postgres usually owns 5432; `DB_DECOY_PORT` changes it) |
| Aetees lab shop | http://localhost:3100 (real), http://localhost:3101 (honeypot clone) — `scripts/aetees-lab.sh` |

Keep the dashboard **Live Events** page open on one screen while you do the steps below.

## Manual tests

Events reach the dashboard in about 1–2 s. Analysis (actors, findings, risk) takes a few seconds more because the
database is remote (Neon); with local Postgres it is near instant.

### 1. Web decoy — recon and injection
1. Open http://localhost:8080/robots.txt → it lists `/admin/backup` and `/api/diagnostics`.
2. Open http://localhost:8080/admin/backup and http://localhost:8080/.env.
3. Open `http://localhost:8080/api/diagnostics?host=8.8.8.8;cat%20/etc/passwd` → fake ping output with a fake
   passwd file (nothing real runs).

Expect on the dashboard: `http.request`, `file.read`, `input.suspicious` rows; a new actor with **T1190**
(command injection, source `rule+ml`), **T1087.001** (from the injected `cat /etc/passwd`) and **T1552.001**
(`.env` read).

### 2. SSH decoy — login and credential theft
```bash
ssh -o StrictHostKeyChecking=no -p 2222 deploy@localhost
uname -a
ls -la
cat ~/.aws/credentials
find / -name "*.kube*"
cat /opt/deploy/kubeconfig      # appears only after the maze unlocks it (step above raises k8s interest)
exit
```
Expect: `auth.attempt`, `shell.command` and `file.read` rows; findings system discovery (T1082), credential search
(T1552.001), honeyfile read; the actor's **Deception Maze** shows `lure_kubeconfig` change from hidden to visible.
Try a wrong password first to see failed `auth.attempt` rows.

### 3. Beacon — honeytoken use (goes critical)
- Open http://localhost:8088/t/tok_url → 1×1 image, `token.used` event.
- The strongest signal: use the AWS key from step 2 against the beacon (the planted `~/.aws/config` points there).
  A SigV4 request carrying that key → `token.used` (sensitivity 5) → the actor jumps to **critical (≥ 90)**,
  an incident opens, and if the same IP / key links the sessions, the SSH and beacon sessions merge into one actor
  through **credential lineage**.

### 3b. Kubernetes decoy — stolen kubeconfig
After step 2 unlocked it, copy the bearer token from `/opt/deploy/kubeconfig` (or from `tok_kube` in
`backend/go/seed/out/tokens.json`), then:
```bash
curl -k https://localhost:6443/version                                   # open, like a real API server
curl -k https://localhost:6443/api/v1/namespaces                         # 401 without a token
curl -k -H "Authorization: Bearer <token>" https://localhost:6443/api/v1/namespaces          # default, kube-system, ci, payments
curl -k -H "Authorization: Bearer <token>" https://localhost:6443/api/v1/namespaces/default/pods
curl -k -X DELETE -H "Authorization: Bearer <token>" https://localhost:6443/api/v1/namespaces/default/pods/x   # 403
```
Expect: `token.used` (k8s_bearer), `k8s.api_call` rows; findings **T1613** (container discovery), **T1078**
(honeytoken used); the actor goes **critical**.

### 3c. Full scripted attack
`scripts/attack.sh` (also in `infrastructure/docker/attacker`) runs the whole demo story from doc 13 against the lab
decoys; with Docker: `docker compose --profile decoys --profile demo up`.

### 4. Dashboard walkthrough
1. **Overview** — KPIs, events per minute, top techniques, highest-risk actor.
2. **Actors → actor** — risk gauge, *What happened* story, source / tools / kill chain / risk formula cards,
   correlation graph (why sessions are linked), timeline, ATT&CK panel, maze.
3. **Incidents → incident** — AI or template summary, recommended actions. Click **block_ip** (confirm "lab only"),
   then try SSH again from that IP: refused within ~5 s.
4. **Download report** — markdown incident report with IOCs, ATT&CK table, linked sessions and fixes.
5. **False positive / Confirmed** buttons — records analyst feedback (weights change only if `SCORER_LEARN=true`).
6. Live events → click a row → **Explain** — plain-English explanation of one event.

### 4b. Database decoy — stolen DB password used
The DB password is planted in `/etc/app/db.env` (SSH decoy, after the maze unlocks it) and in the web decoy's `/.env`.
```bash
psql -h localhost -p 5433 -U app orders          # password: the tok_db value
select version();
\dt
select * from customers limit 5;
select username, role, password_hash from staff_users;
copy customers to program 'id';                  # denied (42501), logged
drop table orders;                               # denied (42501), logged
```
Expect: `auth.attempt` + `token.used` (db_login) → the actor goes **critical** and merges with the actor that stole the
password (credential lineage); `db.query` rows; findings **T1082** (db_recon), **T1213** (business data read),
**T1555** (password hashes), **T1059** (COPY … PROGRAM), **T1485** (DROP); the maze shows `svc_db` visited.
No psql installed? Any Postgres client works (DBeaver, pgAdmin, Python psycopg).

### 5. LLM fallback for commands no rule maps
In the SSH decoy run commands our rules do not know, e.g. `iptables -F`, `chattr +i /tmp/.x`,
`nohup ./miner -o pool:3333 &`. Within ~30 s the actor gets findings such as **T1562.001**, **T1222.002**,
**T1496**, each marked `llm` in the ATT&CK panel with the model's one-line reason. They are worth 5 points each and
never make an actor critical on their own. Navigation (`cd`, `ls`, `pwd`, `history`, `exit`) is never sent to the LLM.
Without `LLM_*` in `.env` nothing happens (rules still run).

### 6. Diversions (product website, analyst side)
1. Dashboard → **Diversions** → enter an IP → **Divert to clone** → the row shows *In honeypot clone*.
2. **Release** → the row shows *Released*. Same buttons on every actor page (*Aetees shop diversion* card) and as
   recommended actions on incidents (`divert_ip`, `release_ip`).
3. The divert proxy that acts on this is not built yet (docs/18 Task 9); the policy it will read is live now.

### 7. Aetees lab shop
`scripts/aetees-lab.sh` (first run ~3 min: copies `../references/aetee` into `.lab/aetees`, SQLite, one build).
- http://localhost:3100 — the "real" shop (catalogue only)
- http://localhost:3101 — the honeypot clone: same site, synthetic customers and orders; admin login
  `admin` / the `tok_aetees_admin` value in `backend/go/seed/out/tokens.json`
`REBUILD=1 scripts/aetees-lab.sh` rebuilds from the source.

### 8. Deception tactics panel
`SENSOR_ID=ssh-01 SENSOR_KEY=$KEY_SSH CORE_URL=http://127.0.0.1:8443 go run ./cmd/send-sample -ip 10.66.0.77 -tactic`
(from `backend/go`, with `.env` loaded) → the new actor's page shows *Tactics applied (1)*: `sunk_cost_export`.

### 9. Divert proxy, planted lures and cognitive tactics
Run the lab and proxy:
1. `scripts/aetees-lab.sh` starts the real shop on `:3100` and honeypot clone on `:3101`.
2. Start the divert proxy on `:8200`:
   ```bash
   (cd backend/go && SENSOR_ID=aetees-01 SENSOR_KEY=$KEY_AETEES LISTEN_ADDR=:8200 \
     REAL_URL=http://127.0.0.1:3100 CLONE_URL=http://127.0.0.1:3101 go run ./cmd/divert-proxy)
   ```
3. **Clean visitor**: `curl -c cookies.txt -i http://localhost:8200/` reaches the real shop (`:3100`). Real customer traffic is never sent to the clone or logged to core.
4. **Soft diversion & checkout hold**:
   - `curl -b cookies.txt -c cookies.txt -i "http://localhost:8200/?search='"` triggers soft diversion.
   - `curl -b cookies.txt -c cookies.txt -X POST -i http://localhost:8200/api/checkout` returns `503 Service Unavailable` with `{"success":false,"error":"We're receiving a lot of orders right now. Please try again in a minute."}` (writes held; real shop protected).
5. **Hard diversion & planted lures**:
   - `curl -b cookies.txt -c cookies.txt -i http://localhost:8200/.env` triggers hard diversion.
   - Read lure `/.env.bak`: `curl -b cookies.txt -c cookies.txt http://localhost:8200/.env.bak` returns fake env with `tok_aetees_admin` password and `tok_db`, emitting `file.read`.
   - Read lure `/backup/`: `curl -b cookies.txt -c cookies.txt http://localhost:8200/backup/` lists `aetees_db_FINAL.sql.gz`.
   - Download lure `/backup/aetees_db_FINAL.sql.gz`: `curl -b cookies.txt -c cookies.txt http://localhost:8200/backup/aetees_db_FINAL.sql.gz -o dump.sql.gz` emits `file.download`. Gunzipping reveals canary invoice link `tok_aetees_invoice`.
   - Trigger canary token: `curl -b cookies.txt -c cookies.txt "http://localhost:8200$(python -c "import json;print(json.load(open('backend/go/seed/out/tokens.json'))['tok_aetees_invoice']['match_value'])")"` serves invoice and emits `token.used`.
6. **Cognitive deception tactics**:
   - `false_success`: Send 3 wrong passwords to `/api/admin/login`; on the 4th attempt, the proxy rewrites the credentials to the clone's admin password, granting access to synthetic data and emitting `deception.tactic` (`false_success`).
   - `sunk_cost_export`: Repeatedly poll `/api/admin/export`; progress climbs (30%, 65%, 88%) then stalls at 97% for several polls before reaching 100% and offering `/api/admin/export/download` (CSV of synthetic customers), emitting `deception.tactic` (`sunk_cost_export`).
   - `breadcrumb`: `curl -b cookies.txt -c cookies.txt http://localhost:8200/` returns clone HTML with injected comment `<!-- DEBUG: Migration in progress. Remove /.env.bak and /backup/ before production release. -->`.
   - `llm_page`: `curl -b cookies.txt -c cookies.txt http://localhost:8200/admin/staff-report` intercepts clone 404, generating an Aetees-themed decoy portal page (#5a3424, #f8ecc2, Oswald/Inter) and caching it to disk under `.data/lure_pages/`.

## If something looks wrong
- Nothing on the dashboard: check `.logs/core.log` and the decoy log in `.logs/`; `scripts/dev-down.sh` then
  `scripts/dev-up.sh`.
- "port already in use": an old process is still running → `scripts/dev-down.sh` (it reports any port still busy).
- Narration shows "template": the LLM answered too slowly or the key ran out — expected fallback.
- Test data from earlier runs stays in the database; actors from earlier tests can merge with new ones when the
  same honeytoken is reused (that is correct behaviour: same stolen credential = same operator).
