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
| Kubernetes decoy | https://localhost:6443 (once built) |

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

## If something looks wrong
- Nothing on the dashboard: check `.logs/core.log` and the decoy log in `.logs/`; `scripts/dev-down.sh` then
  `scripts/dev-up.sh`.
- "port already in use": an old process is still running → `scripts/dev-down.sh` (it reports any port still busy).
- Narration shows "template": the LLM answered too slowly or the key ran out — expected fallback.
- Test data from earlier runs stays in the database; actors from earlier tests can merge with new ones when the
  same honeytoken is reused (that is correct behaviour: same stolen credential = same operator).
