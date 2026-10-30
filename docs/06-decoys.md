# 06 — Decoys and honeytokens

All decoys are Go binaries using `internal/sensorkit`. Common rules:

- Never execute, fetch, resolve or write anything real. Simulate.
- Obey `/v1/sensor/policy` (blocked IPs, killed sessions, burned tokens) — poll every 5 s.
- Enforce limits locally: 500 requests per session, 10 min idle, 30 min absolute, 5 MB upload cap.
- Add 30–150 ms random latency to responses so timing looks like a real host.
- Use the persona (`internal/persona`, seeded by `PERSONA_SEED`): company `<Name> Logistics`, host names
  `<prefix>-app-01`, users `deploy`, `jenkins`, `<firstname>.<lastname>`. Never hard-code names in code.

## 1. SSH decoy (`cmd/decoy-ssh`, port 2222)

**Study first:** Cowrie (`src/cowrie/shell/`, `src/cowrie/commands/`, its event ids), Wisp `internal/service/sshsvc`
(credential capture only). Write our own.

Server:
- `golang.org/x/crypto/ssh` server; persistent host key in `/data/ssh_host_ed25519`.
- `ServerVersion` = `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10`.
- Password callback: emit `auth.attempt` for every try. Accept only:
  `root` / persona weak password (from seed) and `deploy` / persona password; plus public-key auth for the
  **deploy key planted in `backup.zip`** (emit `token.used` with `via: ssh_key` — credential lineage).
- Public-key callback: always record `key_fp` (SHA256) even when rejected.
- Capture `ClientVersion()` → `client.ssh_banner`. HASSH needs the raw client KEXINIT; implement only as stretch
  by wrapping `net.Conn` and parsing the first packets.

Shell:
- Handle `pty-req`, `shell`, `exec` (exec = one command, same emulator), `window-change`.
- Own line editor: echo, backspace, ←/→, ↑ history, Ctrl-C, Ctrl-D, Tab (no completion; bell).
  Record per line: `keystrokes`, `edits`, `paste` (≥ 8 chars in one read), `since_prev_ms`.
- Prompt `deploy@<host>:~$ ` / `root@<host>:~# `.
- Command emulators (each a Go func `func(ctx *ShellCtx, args []string) (stdout string, exit int)`):

| Commands | Behaviour |
| --- | --- |
| `whoami id hostname uname uptime w date pwd` | persona-based static output |
| `ls cd cat head tail find grep stat file` | over `fakefs` incl. maze-visible lures; emit `file.read` for reads (with `honeyfile_id` when a lure) |
| `ps top netstat ss ip ifconfig df free env history` | plausible static output; `history` contains a URL token |
| `wget curl` | record URL in `shell.command`; print a believable progress line; create an empty quarantined file; never fetch |
| `scp sftp` uploads | `file.upload` with sha256, stored in `/data/quarantine/` (never executable) |
| `chmod chown mv cp rm mkdir touch echo > file` | mutate the per-session overlay of fakefs only |
| `sudo su` | ask password, fail with `Sorry, try again.` x3 |
| `kubectl` | if kubeconfig visible: fake `get pods/secrets` output matching k8s decoy; else connection refused |
| `mysql psql` | `Access denied` unless db lure visible, then fake prompt that errors on any query |
| `python3 perl bash sh nc` | `-c` / scripts: print nothing, exit 0 (record raw) |
| `exit logout` | close |
| unknown | `bash: <x>: command not found` |

- Pipes `|`, `;`, `&&`: split and run each emulator in order (no real shell).
- Every line → `shell.command` event with `timing`.
- On every `ls`, `find`, `cat` call `maze-view` (cached 2 s) so newly unlocked lures appear.

## 2. Web decoy (`cmd/decoy-web`, port 8080)

**Study first:** HoneyWire WebRouterDecoy (design only), Wisp `httpdecoy`, Echidra HTTP persona.

| Path | Behaviour | Events |
| --- | --- | --- |
| `/` → `/login` | "<Company> Internal Admin" login form, server-rendered HTML (Go `html/template`) | `http.request`, `auth.attempt` (method `form`, always fails) |
| `/robots.txt` | `Disallow: /admin/backup` `Disallow: /api/diagnostics` | `http.request` |
| `/admin/backup` | directory listing with `internal-backup.zip` (honeyfile) and two dull files | `http.request` |
| `/admin/backup/internal-backup.zip` | zip with `deploy_id_ed25519` (decoy-accepted key), `notes.txt` mentioning SSH host | `file.download`, token seen |
| `/.env` `/config.php.bak` | fake env with db creds (`tok_db`) | `file.read` |
| `/api/diagnostics?host=` | **injection bait**: "ping tool". Returns fake ping output. If the value fails the strict host regex `^[a-zA-Z0-9.-]{1,253}$`, emit `input.suspicious` with separator + payload and answer with a fake shell-ish output for common payloads (`id`, `whoami`, `cat /etc/passwd` from fakefs) | `http.request`, `input.suspicious` |
| `/api/login` (JSON) | same as form, for scripts | `auth.attempt` |
| anything else | nginx-style 404 | `http.request` |

Cheap pre-check in the decoy (engine re-checks with rules + ML):
separators `;`, `&&`, `||`, `|`, `` ` ``, `$(`, `%0a`, `\n`; SQL `' OR`, `UNION SELECT`, `--`; `../`; `<script`.

Session = cookie `sid` (set on first request) else `ip+ua` for 30 min.

## 3. Kubernetes API decoy (`cmd/decoy-k8s`, port 6443, TLS self-signed)

**Study first:** Wisp `internal/service/k8ssvc` and `kubeletsvc`.

| Request | No / bad token | Valid lure token (`tok_kube`) |
| --- | --- | --- |
| `GET /version`, `/healthz` | 200 (as real API servers do) | 200 |
| `GET /api`, `/apis` | 401 `{"kind":"Status","status":"Failure","reason":"Unauthorized","code":401}` | discovery JSON |
| `GET /api/v1/namespaces` | 401 | `default`, `kube-system`, `ci`, `payments` |
| `GET /api/v1/namespaces/{ns}/pods` | 401 | 3–6 persona pods |
| `GET /api/v1/namespaces/{ns}/secrets` | 401 | list; `ci-jenkins-token` and `db-credentials` only when maze-visible |
| `GET /api/v1/nodes` | 401 | 3 nodes |
| `POST/DELETE/PATCH` anything | 401 | 403 Forbidden (`deploy-reader` RBAC) |

Events: `http.request`, `k8s.api_call` (verb/resource/ns/name/authenticated), `auth.attempt` (bearer),
`token.used` when the lure token appears.

## 4. Beacon (`cmd/decoy-beacon`, port 8088)

- **AWS-style endpoint.** The planted `~/.aws/config` sets `endpoint_url = http://s3.<persona-domain>:8088` and the
  decoy's fake `/etc/hosts` maps that name to the beacon. Any SigV4 request carrying the lure access key id
  (`Authorization: AWS4-HMAC-SHA256 Credential=AKIA…/…`) → `token.used` (`via: aws_api`); reply with an AWS-style
  `AccessDenied` XML. Honest limit: a real `aws` CLI with default endpoints would go to real AWS, which we don't
  watch. Say this in the demo if asked.
- **URL tokens.** `GET /t/{token_id}` → `token.used` (`via: url_fetch`), returns a 1×1 GIF or `404`.

## 5. Honeytokens (`cmd/seed`)

| token_id | kind | Planted at | match_value | Sensitivity |
| --- | --- | --- | --- | --- |
| `tok_backup_key` | ssh_key | web `/admin/backup/internal-backup.zip` | ed25519 public key fp | 4 |
| `tok_aws_k7` | aws_key | ssh `/home/deploy/.aws/credentials` | access key id `AKIA` + 16 random | 5 |
| `tok_kube` | kubeconfig | ssh `/opt/deploy/kubeconfig` (maze lure) | bearer token | 5 |
| `tok_db` | db_cred | ssh `/etc/app/db.env` (maze lure), web `/.env` | password | 4 |
| `tok_url` | url | ssh `~/.bash_history` | `/t/tok_url` | 2 |

Seed writes `seed/out/persona.json`, `seed/out/tokens.json` (mounted read-only into decoys) and inserts rows
into `honeytokens`. Re-running seed with a new `PERSONA_SEED` gives a different company and new token values.
AWS key ids must be random and invalid; never use real-looking patterns of known keys.
