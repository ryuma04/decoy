# 04 — API contract (FROZEN CONTRACT between backend, frontend, decoys and ML)

Three surfaces:

| Surface | Base URL (in compose) | Callers | Auth |
| --- | --- | --- | --- |
| Sensor API | `http://core:8443/v1` | decoys | HMAC per sensor |
| Analyst API | `http://core:8090/v1` | Next.js (server-side proxy + browser via proxy) | JWT in httpOnly cookie `dsoc_session` |
| ML API | `http://ml:8000/ml/v1` | core only | none (mgmt_net only) |

Common rules: JSON UTF-8; times RFC3339 UTC; errors are
`{"error": {"code": "not_found", "message": "actor not found"}}` with a matching HTTP status;
list endpoints return `{"items": [...], "next_cursor": "opaque-or-null"}`.

---

## A. Sensor API

### Auth (HMAC)

Headers on every request:

```text
X-DSOC-Sensor: ssh-01
X-DSOC-Timestamp: 2026-11-14T09:02:12Z        # reject if |now - ts| > 120 s
X-DSOC-Signature: hex(HMAC_SHA256(key, timestamp + "\n" + method + "\n" + path + "\n" + sha256hex(body)))
```

Keys come from env `SENSOR_KEYS="ssh-01:secret1,web-01:secret2,k8s-01:secret3,beacon-01:secret4"`.

### `POST /v1/ingest/events`

Body: array (1–200) of `dsoc.event/v1` envelopes.
Response `200`: `{"accepted": 48, "duplicates": 2, "rejected": [{"event_id": "…", "reason": "invalid type"}]}`.
`401` bad signature, `413` too large. Sensors retry with backoff and spool to a local JSONL file when core is down.

### `POST /v1/ingest/heartbeat`

`{"sensor_id": "ssh-01", "version": "0.1.0", "uptime_s": 360, "active_sessions": 2}` → `204`.

### `GET /v1/sensor/maze-view?sensor_session_id=ssh-01:7f3a9c`

Decoy asks what this session may see. Core answers ≤ 50 ms; on timeout the decoy uses its default view.

```json
{
  "actor_id": "8b0c…",
  "visible_nodes": ["ssh_entry", "lure_aws", "lure_kubeconfig"],
  "files": [
    {"path": "/opt/deploy/kubeconfig", "honeyfile_id": "tok_kube", "maze_node": "lure_kubeconfig"}
  ],
  "k8s_secrets": [],
  "limits": {"remaining_requests": 412, "session_deadline": "2026-11-14T09:32:11Z"}
}
```

### `GET /v1/sensor/policy`

Polled every 5 s by every decoy.

```json
{ "blocked_ips": ["10.66.0.23"], "killed_sessions": ["ssh-01:7f3a9c"], "burned_tokens": ["tok_aws_k7"], "rev": 17 }
```

Decoys refuse new connections from blocked IPs (TCP close), close killed sessions, and stop accepting burned tokens.

---

## B. Analyst API

### Auth

| Method | Path | Body → Response |
| --- | --- | --- |
| POST | `/v1/auth/login` | `{"email","password"}` → `200 {"user": User}` + `Set-Cookie: dsoc_session=…; HttpOnly; SameSite=Lax` |
| POST | `/v1/auth/logout` | → `204` |
| GET | `/v1/auth/me` | → `{"user": User}` or `401` |

### Endpoints

| Method | Path | Query / body | Response |
| --- | --- | --- | --- |
| GET | `/v1/stats/overview` | `window=1h` | `Overview` |
| GET | `/v1/stats/timeseries` | `metric=events\|findings`, `window=1h`, `step=1m` | `{"points":[{"t","v"}]}` |
| GET | `/v1/stats/techniques` | `window=24h` | `{"items":[{"technique","name","tactic","count"}]}` |
| GET | `/v1/events` | `type, service, actor_id, session_id, src_ip, since, until, q, limit≤200, cursor` | list of `Event` |
| GET | `/v1/events/{event_id}` | | `Event` with `envelope` |
| GET | `/v1/actors` | `severity, behaviour_class, since, sort=risk\|last_seen, limit, cursor` | list of `ActorSummary` |
| GET | `/v1/actors/{actor_id}` | | `ActorDetail` |
| GET | `/v1/actors/{actor_id}/timeline` | `limit≤1000, cursor` | list of `TimelineItem` |
| GET | `/v1/actors/{actor_id}/maze` | | `MazeGraph` |
| GET | `/v1/sessions/{session_id}` | | `Session` + events |
| GET | `/v1/incidents` | `status, severity, limit, cursor` | list of `Incident` |
| GET | `/v1/incidents/{incident_id}` | | `IncidentDetail` |
| PATCH | `/v1/incidents/{incident_id}` | `{"status"?: IncidentStatus, "note"?: string}` | `IncidentDetail` |
| POST | `/v1/incidents/{incident_id}/actions` | `{"action": "block_ip"\|"unblock_ip"\|"kill_session"\|"rotate_token", "target": string}` | `ResponseAction` (admin role) |
| GET | `/v1/incidents/{incident_id}/report` | `format=md\|json` | markdown file or JSON |
| GET | `/v1/honeytokens` | | list of `Honeytoken` with hit counts |
| GET | `/v1/sensors` | | list of `Sensor` |
| GET | `/v1/maze` | | `MazeGraph` (definition, no actor state) |
| GET | `/v1/stream` | SSE | see below |

### SSE `/v1/stream`

`Content-Type: text/event-stream`, heartbeat comment `: ping` every 15 s. Message `event:` names and `data:`:

| event | data |
| --- | --- |
| `event` | `Event` (without envelope) |
| `finding` | `Finding` |
| `actor` | `ActorSummary` (on create or score change) |
| `incident` | `Incident` (on open, update, severity change) |
| `maze` | `{"actor_id","node_id","state","reason"}` |
| `sensor` | `Sensor` (status change) |

Optional query `?actor_id=` filters to one actor.

### TypeScript types (copy to `frontend/nextjs/src/lib/types.ts`; Go structs must marshal to the same JSON)

```ts
export type Severity = "low" | "medium" | "high" | "critical";
export type BehaviourClass = "human_like" | "scripted" | "ai_assisted" | "agent_like" | "unknown";
export type Service = "ssh" | "web" | "k8s" | "beacon" | "engine";
export type IncidentStatus = "open" | "ack" | "contained" | "closed";

export interface User { user_id: string; email: string; role: "analyst" | "admin"; }

export interface Overview {
  window: string;
  events: number; active_actors: number; new_actors: number;
  open_incidents: Record<Severity, number>;
  token_hits: number; sensors_ok: number; sensors_total: number;
  top_actor: ActorSummary | null;
}

export interface Event {
  event_id: string; ts: string; type: string; service: Service; sensor_id: string;
  session_id: string; actor_id: string | null; actor_label: string | null;
  src_ip: string; data: Record<string, unknown>; tokens: string[];
  summary: string;                    // server-made one-liner, e.g. "cat ~/.aws/credentials"
  envelope?: Record<string, unknown>;
}

export interface ActorSummary {
  actor_id: string; label: string; first_seen: string; last_seen: string;
  risk_score: number; severity: Severity; confidence: number;
  behaviour_class: BehaviourClass; services: Service[]; session_count: number;
  ips: string[]; top_techniques: string[]; token_hits: number; maze_depth: number;
}

export interface LinkReason { signal: string; weight: number; matched_session: string | null; value: string; }

export interface Session {
  session_id: string; sensor_session_id: string; actor_id: string; service: Service; sensor_id: string;
  src_ip: string; started_at: string; ended_at: string | null; event_count: number;
  link_score: number | null; link_reasons: LinkReason[];
}

export interface Fingerprint { kind: string; value: string; session_ids: string[]; }

export interface Finding {
  finding_id: number; actor_id: string; session_id: string; rule_id: string; title: string;
  tactic: string | null; technique: string | null; technique_name: string | null;
  points: number; confidence: number; source: "rule" | "ml" | "rule+ml";
  evidence: { event_ids: string[]; matched?: string; ml?: { label: string; confidence: number; top_features: string[] } };
  ts: string;
}

export interface BehaviourDetail {
  class: BehaviourClass; scores: Partial<Record<BehaviourClass, number>>; source: "rules" | "ml";
  features: { median_gap_ms: number; gap_cv: number; edit_rate: number; paste_rate: number;
              output_dependence: number; services_visited: number; breadcrumbs_followed: number;
              param_mutation_retries: number; commands: number };
}

export interface ActorDetail extends ActorSummary {
  sessions: Session[]; fingerprints: Fingerprint[]; findings: Finding[];
  behaviour: BehaviourDetail; interest: Record<"cloud" | "k8s" | "db" | "ci", number>;
  incident_id: string | null;
}

export type TimelineItem =
  | { kind: "event"; ts: string; event: Event }
  | { kind: "finding"; ts: string; finding: Finding }
  | { kind: "maze"; ts: string; node_id: string; state: "visible" | "visited"; reason: string };

export interface MazeNode {
  id: string; label: string; kind: "entry" | "lure" | "service"; theme: "cloud" | "k8s" | "db" | "ci" | null;
  service: Service | null; stretch: boolean; state?: "hidden" | "visible" | "visited";
}
export interface MazeEdge { from: string; to: string; label?: string; }
export interface MazeGraph { nodes: MazeNode[]; edges: MazeEdge[]; actor_id?: string; }

export interface Incident {
  incident_id: string; actor_id: string; actor_label: string; severity: Severity; status: IncidentStatus;
  title: string; opened_at: string; updated_at: string; risk_score: number;
}
export interface IOC { kind: "ip" | "sha256" | "credential" | "url" | "token"; value: string; }
export interface ResponseAction {
  action_id: number; action: string; target: string; status: "pending" | "applied" | "failed" | "reverted";
  requested_by: string; ts: string;
}
export interface IncidentDetail extends Incident {
  summary: string; summary_src: "template" | "llm"; actor: ActorSummary; findings: Finding[];
  iocs: IOC[]; actions: ResponseAction[]; notes: { author: string; body: string; ts: string }[];
  recommended_actions: { action: string; target: string; why: string }[];
}

export interface Honeytoken {
  token_id: string; kind: string; planted_at: string; sensitivity: number; burned: boolean;
  hits_seen: number; hits_used: number; last_hit: string | null;
}
export interface Sensor { sensor_id: string; service: Service; version: string; last_seen: string | null; status: "ok" | "silent" | "unknown"; }
```

### Example `GET /v1/actors/{id}` (abridged)

```json
{
  "actor_id": "8b0c2c1e-…", "label": "ACT-0007", "risk_score": 82, "severity": "critical", "confidence": 0.93,
  "behaviour_class": "agent_like", "services": ["web","ssh","k8s","beacon"], "session_count": 4,
  "ips": ["10.66.0.23","10.66.0.41"], "top_techniques": ["T1552.001","T1078","T1613"], "token_hits": 2, "maze_depth": 4,
  "sessions": [{"session_id":"…","service":"ssh","src_ip":"10.66.0.41","link_score":0.93,
    "link_reasons":[{"signal":"credential_lineage","weight":0.9,"matched_session":"…","value":"tok_backup_key"}]}],
  "behaviour": {"class":"agent_like","scores":{"agent_like":0.71,"scripted":0.18,"human_like":0.11},"source":"ml",
    "features":{"median_gap_ms":5400,"gap_cv":0.21,"edit_rate":0,"paste_rate":0.9,"output_dependence":0.62,
    "services_visited":4,"breadcrumbs_followed":3,"param_mutation_retries":5,"commands":27}},
  "interest": {"cloud":4,"k8s":9,"db":0,"ci":2},
  "incident_id": "c1f…"
}
```

Mock fixtures for every endpoint live in `frontend/nextjs/src/mocks/` (frontend creates them from this file
so UI work does not wait for the backend).

---

## C. ML API (core → ml)

All calls: timeout 300 ms (summary: 5 s). Any error ⇒ core continues with rules only.

| Method | Path | Request | Response |
| --- | --- | --- | --- |
| GET | `/health` | | `{"ok":true,"models":{"command":"v1","input":"v1","behaviour":"v1"},"codeguard":true}` |
| POST | `/ml/v1/classify-command` | `{"text":"cat ~/.aws/credentials","context":{"service":"ssh","cwd":"/home/deploy"}}` | `{"label":"credential_access","confidence":0.94,"top_features":["aws/cred",".aws"],"codeguard":{"verdict":"block","categories":["secret_access"],"risk":0.8}}` |
| POST | `/ml/v1/classify-input` | `{"param":"host","value":"8.8.8.8; cat /etc/passwd","context":{"path":"/api/diagnostics"}}` | `{"label":"cmd_injection","confidence":0.97,"top_features":["; cat","/etc/"],"payload":"cat /etc/passwd"}` |
| POST | `/ml/v1/classify-session` | `{"features": BehaviourDetail.features}` | `{"class":"agent_like","scores":{"human_like":0.11,"scripted":0.18,"agent_like":0.71},"top_features":["output_dependence","gap_cv"]}` |
| POST | `/ml/v1/summarize-incident` | `{"incident": IncidentDetail, "timeline": TimelineItem[]}` | `{"summary":"…","source":"llm"\|"template"}` |

Labels — command: `benign, recon, credential_access, download_exec, persistence, destructive, obfuscated`.
Input: `normal, cmd_injection, sqli, xss, path_traversal`. Session: `human_like, scripted, agent_like`.
