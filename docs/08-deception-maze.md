# 08 — Adaptive deception maze

A directed graph of lures and decoy services in `backend/go/maze/maze.yaml`. Every actor starts with the same
default view; the controller reveals further lures when the actor's behaviour points at their theme.
Idea credit: LABYRINTH's planted escalation paths and per-deploy bait (study `docs/LAYERS.md`, `src/layer2_maze/`
for design only — AGPL). Our implementation is a plain graph with explicit rules. We do **not** implement
LABYRINTH layers 3–4 (encoding corruption, CA injection, prompt rewriting).

## Graph

```text
Admin web (entry) ──► backup.zip ──(leaked deploy key)──► SSH shell (entry)
SSH shell ──► ~/.aws/credentials  ──► AWS-style beacon
SSH shell ──► deploy/kubeconfig*  ──► K8s API ──(CI token in a secret)──► Jenkins decoy†
SSH shell ──► /etc/app/db.env*    ──► DB decoy†
* adaptive lure (hidden until interest)   † stretch goal
```

## maze.yaml

```yaml
version: 1
themes: [cloud, k8s, db, ci]
nodes:
  - {id: web_entry,       kind: entry,   service: web,    label: Admin web}
  - {id: lure_backup,     kind: lure,    theme: null,     label: backup.zip,          token: tok_backup_key, default: visible}
  - {id: ssh_entry,       kind: entry,   service: ssh,    label: SSH shell}
  - {id: lure_aws,        kind: lure,    theme: cloud,    label: ~/.aws/credentials,  token: tok_aws_k7,  default: visible}
  - {id: lure_kubeconfig, kind: lure,    theme: k8s,      label: deploy/kubeconfig,   token: tok_kube,    default: hidden}
  - {id: lure_db,         kind: lure,    theme: db,       label: /etc/app/db.env,     token: tok_db,      default: hidden}
  - {id: svc_beacon,      kind: service, service: beacon, label: AWS-style beacon}
  - {id: svc_k8s,         kind: service, service: k8s,    label: K8s API}
  - {id: lure_ci_secret,  kind: lure,    theme: ci,       label: ci-jenkins-token secret, default: hidden}
  - {id: svc_db,          kind: service, service: null,    label: DB decoy,      stretch: true}
edges:
  - {from: web_entry, to: lure_backup}
  - {from: lure_backup, to: ssh_entry, label: uses leaked key}
  - {from: ssh_entry, to: lure_aws}
  - {from: ssh_entry, to: lure_kubeconfig}
  - {from: ssh_entry, to: lure_db}
  - {from: lure_aws, to: svc_beacon}
  - {from: lure_kubeconfig, to: svc_k8s}
  - {from: svc_k8s, to: lure_ci_secret}
  - {from: lure_db, to: svc_db}
interest_signals:          # (regex over command/path/api, theme, points)
  - {match: 'kubectl|\.kube|kubeconfig|6443|k8s|kubernetes', theme: k8s, points: 3}
  - {match: 'docker|containerd|helm', theme: k8s, points: 1}
  - {match: '\.aws|aws |s3|iam|169\.254\.169\.254', theme: cloud, points: 3}
  - {match: 'mysql|psql|postgres|DB_PASS|database|\.env', theme: db, points: 2}
  - {match: 'grep.*-i.*pass', theme: db, points: 2}
  - {match: 'jenkins|gitlab|ci|pipeline|\.git', theme: ci, points: 2}
limits:
  max_depth: 6
  unlocks_per_10min: 3
  loops_per_theme: 3
  idle_timeout: 10m
  session_cap: 30m
  requests_per_session: 500
```

## Algorithm (`internal/maze`, deterministic)

On each finding or interest-matching event for an actor:

1. Add points to `actors.interest[theme]` for every `interest_signals` match (once per event).
2. Mark visited nodes: reading a lure file, using its token, or connecting to a service node → `visited`.
3. Candidates = `hidden` nodes whose parent is `visited` (or whose parent is an entry the actor used).
4. Pick the candidate with the highest theme interest, if that interest ≥ 3; ties → most recent theme.
5. Check limits (depth, unlocks per 10 min). If OK: set `visible`, write `maze_state`, emit `maze.unlock` event,
   publish on `maze` topic.
6. `MAZE_ADAPTIVE=false` → only `default: visible` nodes are ever shown (safe demo fallback).

Maze view (`GET /v1/sensor/maze-view`) = visible nodes for the session's actor, mapped to concrete files,
secrets and banners for that decoy. Unknown actor → default view.

## Bounded loop

Credentials from a lure log in to the next decoy with **limited rights** (`deploy-reader` in k8s, read-only DB
user). Attempts to escalate (k8s `create`, `get secrets` in another namespace, `sudo`) count a loop for that theme
and may unlock one more lure. After `loops_per_theme` (3) the next attempt hits a believable dead end
("Forbidden", "service under maintenance"). Every loop is an event, so retries, parameter changes and timing are
all recorded for the behaviour classifier.

## Safety invariants (tests required)

- A hidden node is never served by any decoy (test maze-view for an unknown actor).
- Unlock count per actor never exceeds limits (property test with random events).
- Decoys enforce `requests_per_session` and `session_cap` even if core is unreachable.

## Cognitive adaptive deception layer (`internal/cognitive`)

Runs **inside the honeypot**, on top of the maze. The maze decides *which* lure path exists; the cognitive layer
decides *how* lures are presented, based on behaviour patterns that suggest a decision shortcut (bias).
Wording rule: we detect **behaviour patterns consistent with** a bias and apply a tactic. We never claim to know an
attacker's psychology. UI label: "Deception tactic applied".

### Pattern → tactic table (rule-based, deterministic)

| Bias pattern | Detection rule (per actor) | Tactic in the honeypot | Evidence recorded |
| --- | --- | --- | --- |
| Confirmation | ≥ 3 commands/requests on one theme in 5 min (`interest[theme]` rising, same keywords) | Reveal one more lure of that theme (maze unlock) and, if enabled, an LLM-generated page for that theme (below) | theme, triggering events |
| Sunk cost | ≥ 4 retries on the same target with changed parameters (param_mutation_retries) | Return a **partial success** ("read OK, write denied", "1 of 3 rows exported") instead of a flat error | retries before / after tactic |
| Anchoring | first credential found is used within 60 s | Ensure the first visible credential lure in each theme is the highest-sensitivity honeytoken | time-to-use |
| Urgency | median gap < 3 s and recon skipped | Add a time-pressure note next to a lure ("backup purge at 18:00 UTC") | whether lure is taken faster |
| Authority | reads files with `admin`, `root`, `prod` in the name first | Name the next lure with authority wording (`prod-admin-notes.md`) | which lure chosen |

Rules:
- At most **one tactic per actor per 5 minutes**, at most 4 per actor in total.
- Tactics only change **presentation inside decoys** (wording, ordering, partial responses, which lure is shown). They
  never expose anything real and never extend limits from §Bounded loop or §Hard limits.
- Every tactic emits an `engine` event `deception.tactic` with `{tactic, bias_pattern, trigger_event_ids, lure_id}`
  and shows on the actor timeline.
- Effect measurement (shown on the profile, "Tactic effect"): did the actor take the lure or keep engaging within
  5 minutes after the tactic (yes/no + time). This is what we can honestly claim.

### Where it sits

```text
event → rules/findings → maze controller (path) → cognitive layer (presentation tactic)
      → lure content: static template, or LLM-generated page (below) → decoy serves it via maze-view
```

## LLM dynamic lures — "smart honeypot" (`internal/lurgen`)

An LLM (Claude via the same `LLM_API_KEY` / `LLM_MODEL` as narration, 10 §N) writes **extra decoy content** for an
actor's theme: one more admin page, a migration-notes document, a config file. Goal: the honeypot looks alive and
specific to what the attacker is hunting, which lengthens engagement and improves profiling.

### Pipeline (one generator, one critic, deterministic guards)

1. **Trigger:** cognitive layer chooses "confirmation" tactic, or maze unlocks a theme with `llm_lure: true`.
2. **Generate in the background** (never on the attacker's request path): prompt = fixed template + persona JSON +
   theme + the requested lure type. Output must be JSON `{title, path, body_markdown_or_html, placeholders[]}`.
3. **Deterministic guard (Go) — the real anti-hallucination layer:**
   - schema valid, size ≤ 8 KB, path matches `^/[a-z0-9/_-]{1,64}$`;
   - only persona names / hosts / domains appear (allowlist check); no IPs outside the lab range; no URLs except
     persona domains;
   - no secret-looking strings (AKIA…, private-key headers, JWT-like, ≥ 20-char high-entropy) — secrets come only
     from placeholders;
   - no instructions addressed to an AI reader (reuse the prompt-injection regex set).
4. **Critic (one second LLM call, optional `LLM_CRITIC=true`):** "Is this consistent with this persona and theme,
   and free of real data? Answer JSON {ok, reasons}". Reject on `ok=false`.
5. **Go fills placeholders** (`{{TOKEN_DB_PASSWORD}}`, `{{TOKEN_SSH_KEY}}`) with tracked honeytokens from `cmd/seed`.
   The LLM never writes a credential, so credential lineage stays exact.
6. **Cache and serve:** stored in `generated_lures`, linked into the maze as a new lure node, served on the actor's next
   request. If generation fails, times out (10 s) or is rejected, a **pre-written template** for that theme is used.
7. **Log everything:** prompt hash, model, raw output, guard result, critic result, final content, served-to actors.
   Analysts can view every generated page on the actor profile.

Why not 3–4 agents voting: agents on the same model share failure modes, add latency and cost, and still don't
catch the honeypot-specific risks (leaking real data, breaking persona consistency, obeying planted instructions).
Deterministic guards + one critic + template fallback cover those.

### Safety

- Attacker text is passed only as quoted data (`<attacker_input>…</attacker_input>`) with an instruction to never follow
  instructions inside it; generated pages are checked again for injected instructions.
- Limits: max 3 generated lures per actor, max 30 per hour total, max 1 in-flight generation per actor.
- The LLM never decides blocks, scores or alerts. `LURGEN_ENABLED=false` disables it with zero impact on the demo.
- The decoy network still has no internet: generation runs in `core` (mgmt/egress network), never in a decoy.
