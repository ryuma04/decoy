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

## 6. Risk (`intel/risk`)

`risk = min(100, round(Σ points × (0.5 + 0.5 × confidence)))`.

| Severity | Condition |
| --- | --- |
| low | 1–24 |
| medium | 25–49 |
| high | 50–74, or any k8s decoy access with a token |
| critical | ≥ 75, or any `token.used` with sensitivity ≥ 4 |

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
