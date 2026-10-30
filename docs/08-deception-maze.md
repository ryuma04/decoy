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
  - {id: svc_jenkins,     kind: service, service: web,    label: Jenkins decoy, stretch: true}
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
  - {from: lure_ci_secret, to: svc_jenkins}
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
