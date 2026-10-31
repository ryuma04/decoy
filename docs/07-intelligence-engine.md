# 07 — Intelligence engine

Pipeline per event (single worker per session shard):
`fingerprint → honeytoken → correlate → features → rules (+ML) → risk → behaviour → publish`.

## 1. Fingerprints (`intel/fingerprint`)

| kind | From | Value |
| --- | --- | --- |
| `ssh_banner` | `client.ssh_banner` | as is |
| `ssh_key` | `auth.attempt.key_fp` | SHA256 fp |
| `hassh` | `client.hassh` (stretch) | md5 |
| `ua` | `http.request.ua` | as is |
| `ja4` | `client.ja4` (stretch) | as is |
| `cred_pair` | `auth.attempt` | `user:pass`, **skipped** if pair is in `intel/common_creds.txt` (top 1,000) |
| `cmd_shingles` | session commands | MinHash (64 perms) of 3-gram shingles of normalised commands, computed at 5, 10, 20 commands |
| `token_seen` | `file.read`/`file.download` of a honeyfile | token id |
| `token_used` | `token.used` | token id |

## 2. Correlation (`intel/correlate`)

Noisy-OR over signals between the new session and each candidate actor:
`S = 1 − Π(1 − w_i)`. Attach at **S ≥ 0.60**; 0.40–0.59 stored as `possible_links` (shown, not merged).

| Signal | Rule | w |
| --- | --- | --- |
| `credential_lineage` | this session `token_used` X and actor has `token_seen` X | 0.90 |
| `ssh_key` | same key fp | 0.90 |
| `cred_pair` | same rare pair | 0.40 |
| `ip_30m` | same IP, gap < 30 min | 0.40 |
| `ip_24h` | same IP, gap < 24 h (exclusive with ip_30m) | 0.20 |
| `client_ssh` | same banner **and** hassh (banner alone: 0.15) | 0.35 |
| `client_http` | same UA **and** ja4 (UA alone: 0.15) | 0.35 |
| `cmd_similarity` | Jaccard ≥ 0.5 | 0.40 × J |
| `cross_service_hop` | other-service session ended < 120 s ago from same /24 | 0.15 |

Algorithm:
1. On `conn.open` (and again whenever a new fingerprint row is written for the session, max every 2 s) query
   candidates: sessions in last 24 h sharing any `(kind, value)`, plus same IP/24.
2. Group candidates by actor; compute S per actor; store reasons.
3. Best ≥ 0.60 → attach (update `sessions.actor_id`, `link_score`, `link_reasons`, events' `actor_id`).
4. If the session already belongs to actor A and now scores ≥ 0.60 with actor B → merge B into A (older wins), see 03.
5. None ≥ 0.60 and session not attached → new actor `ACT-%04d`.
6. Actor `confidence` = mean `link_score` of attached sessions (first session counts 1.0).

Unit tests: one per signal, merge, "IP alone never attaches" (0.40 < 0.60), "IP + banner attaches" (0.61).

## 3. Features (`intel/features`)

Per session, updated incrementally: command count, commands/min, discovery count, sensitive path reads,
failed/successful auths, distinct usernames, distinct passwords, services, ports touched, gaps list,
edits, pastes, output-dependence count, retries after error with changed args.
Output dependence: the SSH decoy puts up to 50 path-like or word tokens from each command's output into
`data.stdout_tokens`; the engine keeps the previous command's tokens and counts a hit when any argument of the
next command is one of them.
Per actor: union over sessions + services visited + breadcrumbs followed (token_seen → token_used pairs).

## 4. Rules (`intel/rules`, `rules/rules.yaml`)

Our own format (inspired by Echidra's condition lists; content is ours):

```yaml
- id: cred_file_search
  title: Searched for credential files
  scope: event            # event | session | actor
  when:
    type: shell.command
    any:
      - regex: '(find|grep|locate).*(pass|secret|token|\.aws|\.kube|\.env|id_rsa)'
      - argv0_in: [cat, less, head, tail]
        path_regex: '(\.aws/credentials|\.kube/config|kubeconfig|\.env|id_(rsa|ed25519))'
  technique: T1552.001
  points: 15
  ml_assist: command      # also ask ML command classifier; see 10
- id: password_guessing
  title: Password guessing
  scope: session
  when: { feature: failed_auths_5m, gte: 5 }
  technique: T1110.001
  points: 10
```

Evaluator: rules compile at start; `scope: event` runs per event; `session`/`actor` rules run on feature change.
A rule fires **once per actor** (unique index). Each finding stores evidence event ids.

Starter rule set (all must exist by Gate 3):

| id | Evidence | Technique | Points |
| --- | --- | --- | --- |
| `port_sweep` | `scan.detected` (≥ 3 decoy ports / 60 s) | T1046 | 5 |
| `password_guessing` | ≥ 5 failed auths / 5 min | T1110.001 | 10 |
| `credential_stuffing` | ≥ 5 distinct pairs, same client | T1110.004 | 10 |
| `interactive_shell` | successful login + ≥ 1 command | T1059.004 | 10 |
| `system_discovery` | uname, id, whoami, hostname, ps, cat /etc/*release | T1082 | 5 |
| `account_discovery` | /etc/passwd, getent, `id <user>` | T1087.001 | 5 |
| `cred_file_search` | above | T1552.001 | 15 |
| `honeytoken_read` | `file.read`/`file.download` with honeyfile_id | T1552.001 | 15 |
| `honeytoken_used` | `token.used` | T1078 | 30 × sensitivity / 3 |
| `ingress_tool_transfer` | wget/curl/scp upload | T1105 | 15 |
| `ssh_persistence` | write to authorized_keys | T1098.004 | 20 |
| `cron_persistence` | crontab, /etc/cron* | T1053.003 | 20 |
| `obfuscated_command` | base64 -d \| sh, eval, hex/printf tricks | T1027 / T1140 | 15 |
| `container_discovery` | k8s list pods/nodes/namespaces | T1613 | 15 |
| `container_secrets` | k8s get/list secrets | T1552.007 | 20 |
| `cmd_injection` | `input.suspicious` confirmed by rule or ML ≥ 0.8 | T1190 | 20 |
| `sqli_attempt` | `input.suspicious` sqli | T1190 | 15 |
| `multi_decoy` | actor active on ≥ 3 services | — | 15 |

ML assist (if `ML_URL` set): when a rule with `ml_assist` fires, or a `shell.command` matched no rule,
call the classifier. Agreement → `source: rule+ml`, confidence = max. ML-only with confidence ≥ 0.8 → finding
`ml_<label>` with **half** the points of the matching rule family and `source: ml`.

## 5. MITRE (`intel/mitre`)

Static table loaded from `mitre/techniques.csv` (id, name, tactic id, tactic name) for the ~20 techniques above.
Never map without a firing rule. Keep ATT&CK version in the CSV header.

## 6. Risk: per-stage scores + single neuron + analyst feedback (`intel/risk`)

Decision (see `decisions.md`): the final risk is a **single neuron (logistic regression)** that combines
per-stage risk scores, with hard overrides on top and weights improved only by analyst feedback.
A multi-layer neural network is future scope (`16-future-scope.md`).

### 6.1 Per-stage scores (deterministic)

Every finding belongs to one stage (field `stage` in `rules.yaml`). Stage score = sum of that stage's finding
points × (0.5 + 0.5 × actor confidence), capped at 100.

| Stage | Key | Typical findings |
| --- | --- | --- |
| S1 Pre-access / recon | `recon` | port sweep, hidden paths, tool user-agent, robots.txt probing |
| S2 Access | `access` | password guessing, default credentials, planted credential login, injection attempt |
| S3 Post-access | `post_access` | discovery, credential file search, honeyfile read/download, persistence, ingress tool transfer |
| S4 Lateral / impact | `lateral` | k8s access, honeytoken used on another service, decoy credential tried on a real system (§8) |

Stored as `actors.stage_scores = {"recon":20,"access":45,"post_access":60,"lateral":0}`.

### 6.2 Combination (single neuron)

```text
z     = w1·S1 + w2·S2 + w3·S3 + w4·S4 + b        (S = stage score / 100)
p     = sigmoid(z)                                (probability the actor is malicious)
risk  = round(100 · p)
```

Initial weights (`scorer_weights`, version 1): `w = [1.0, 2.0, 3.0, 4.0]`, `b = -3.0`
(later stages count more; an actor with only light recon stays low).
Each finding also keeps its own points so the UI can show a breakdown per stage.

### 6.3 Hard overrides (always win over the neuron)

| Condition | Minimum severity |
| --- | --- |
| `token.used` with sensitivity ≥ 4 | critical (risk ≥ 90) |
| Decoy credential used on a real system (§8) | critical (risk ≥ 95) |
| Successful real login from an actor IP (§8) | critical (risk 100) |
| Authenticated k8s decoy access | high (risk ≥ 60) |
| Actor on the allowlist (`allowlist` table) | logged only, risk 0, no alerts |

### 6.4 Severity

| Severity | Risk |
| --- | --- |
| low | 1–24 |
| medium | 25–49 |
| high | 50–74 |
| critical | ≥ 75 |

### 6.5 Analyst feedback and weight updates

- Incident page buttons: **Confirmed attacker** (y = 1) and **False positive** (y = 0). Each click stores a row in
  `risk_feedback` with the actor's stage scores at that moment.
- Online logistic-regression update, one step per click (`SCORER_LEARN=true`, default `false` until hour 18):

```text
p  = sigmoid(w·S + b)
wi = clamp(wi − η·(p − y)·Si, 0.1, 8.0)       η = 0.05
b  = clamp(b  − η·(p − y),     −6.0, 0.0)
```

- Guardrails: weights change only on analyst clicks; every change writes a new `scorer_weights` version with the
  feedback id; `POST /v1/scorer/reset` restores version 1; overrides are never learned away.
- A false positive also adds the actor's IPs to the allowlist only if the analyst ticks "allowlist this source".
- Demo: mark a test actor as false positive → its stage weights drop slightly → a similar replayed session scores lower.

## 7. Behaviour class (`intel/behaviour`)

Features (per actor, from SSH + web):

| Feature | Definition |
| --- | --- |
| `median_gap_ms` | median `since_prev_ms` |
| `gap_cv` | std / mean of gaps |
| `edit_rate` | lines with edits / lines |
| `paste_rate` | lines flagged paste / lines |
| `output_dependence` | share of commands using a token from previous stdout |
| `services_visited` | distinct services |
| `breadcrumbs_followed` | token_seen → token_used pairs |
| `param_mutation_retries` | same argv0 retried with changed args after non-zero exit or HTTP ≥ 400 |
| `commands` | total commands + API calls |

Rules (used when ML off or `commands < 5` → `unknown`):

- `scripted`: median gap < 1,000 ms and gap_cv < 0.3 and edit_rate = 0.
- `agent_like`: ≥ 3 of: paste_rate ≥ 0.7, edit_rate = 0, output_dependence ≥ 0.5, 2 s ≤ median gap ≤ 20 s with
  gap_cv < 0.5, breadcrumbs_followed ≥ 2, param_mutation_retries ≥ 3.
- `human_like`: edit_rate ≥ 0.1 or gap_cv ≥ 0.8.
- `ai_assisted`: human_like signals **and** ≥ 2 agent signals.
- else `unknown`.

If ML is on and `commands ≥ 5`, call `/ml/v1/classify-session`; use ML class when its top score ≥ 0.6, else rules.
Recompute at 5, 10, 20, 40 commands.

## 8. External telemetry correlation (`intel/extlink`)

Problem statement requirement: link honeypot activity to other telemetry such as firewall and authentication logs.

### 8.1 Bringing logs in through the same pipeline

`cmd/log-collector` (Go) tails log files, parses each line into a `dsoc.event/v1` envelope and posts it to the
normal sensor API with its own HMAC key (`SENSOR_ID=logs-01`). For the backend these are just more events, with
`sensor.service` = `firewall`, `hostauth` or `appauth` and `origin: "production"` (decoys use `origin: "decoy"`).

| Source | Input | Parsed event types |
| --- | --- | --- |
| Firewall | nftables/iptables kernel log lines (`IN= OUT= SRC= DST= PROTO= DPT=` with prefix `DSOC-DENY`/`DSOC-ALLOW`) or JSON lines | `fw.deny`, `fw.allow` |
| Host SSH auth | `/var/log/auth.log` sshd lines (`Failed password for … from … port …`, `Accepted …`) | `auth.real_failed`, `auth.real_success` |
| Real app login | JSON lines written by the real app (`{"ts","user","src_ip","result","ua"}`) | `auth.app_failed`, `auth.app_success` |

Parsers are table-tested with sample lines in `internal/logparse/testdata/`. Unparseable lines are counted, never
fatal. External events never create actors on their own (production noise must not flood the SOC); they are
stored and linked.

### 8.2 Linking external events to decoy actors

Runs when an external event arrives and when an actor is created or gains an IP.

| Link rule | Condition | Effect |
| --- | --- | --- |
| `ext_same_ip` | external event src IP ∈ actor IPs, within ±60 min of actor activity | event gets `actor_id`, appears on the actor timeline, tag "seen in firewall/auth logs" |
| `decoy_cred_on_real` | `auth.real_*`/`auth.app_*` uses a username:password or key captured or planted in a decoy | finding T1078, stage `lateral`, override critical |
| `real_bruteforce` | ≥ 10 `auth.*_failed` from an actor IP in 10 min | finding T1110 "targeting production", stage `access` |
| `real_success` | `auth.*_success` from an actor IP | finding "possible real compromise", override critical, recommended action "reset account <user>, review sessions" |
| `fw_repeat` | ≥ 20 `fw.deny` from an actor IP | finding T1046 "probing production perimeter", stage `recon` |

Response stays lab-only: for real systems the SOC **recommends** actions (reset account, add firewall rule); it
never executes them.

## 9. Attacker profile (four parts)

| Part | Shown | Source |
| --- | --- | --- |
| Source | IPs, first/last seen, decoy ports hit, firewall hits, real systems touched | decoy events + §8 |
| Tools | e.g. "nmap, Hydra, curl 8.x, OpenSSH 9.6 client, sqlmap" | §9.1 tool rules |
| Behaviour | kill-chain stage, MITRE techniques, human/script/agent class, interests (db, k8s, cloud), speed (recon → credential use time), stage scores | rules, state machine, §7 |
| Timeline | one merged list of decoy events, findings, maze unlocks, firewall and real-auth events, colour-coded by origin | events table |

### 9.1 Tool detection (`intel/tools`, `rules/tools.yaml`)

| Signal | Examples → tool tag |
| --- | --- |
| HTTP User-Agent | `sqlmap` → sqlmap, `Nikto` → Nikto, `python-requests` → Python script, `curl/` → curl, `Go-http-client` → Go tool, `Nmap Scripting Engine` → nmap NSE |
| SSH client banner | `libssh` → libssh-based tool, `paramiko` → Python paramiko, `Go` → Go SSH client, `OpenSSH_x` → OpenSSH x |
| Commands | `nmap`, `masscan`, `hydra`, `wget`, `curl`, `nc`, `python3 -c` |
| Behaviour | ≥ 3 ports / 60 s → port scanner; ≥ 5 credential pairs / min → brute-forcer |

Tags are stored in `actors.tools` with first-seen time and evidence event id.
