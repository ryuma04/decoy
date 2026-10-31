# 02 — Event schema `dsoc.event/v1` (FROZEN CONTRACT)

Every decoy emits this envelope. Sensors report facts only; they never decide severity.
Changing this file requires telling the whole team.

## Envelope

```json
{
  "schema": "dsoc.event/v1",
  "origin": "decoy",
  "event_id": "01JC9Q7X3M2K8V5T0R4N6P1W2Z",
  "ts": "2026-11-14T09:02:11.481Z",
  "sensor": { "id": "ssh-01", "service": "ssh", "maze_node": "ssh_entry" },
  "session": { "sensor_session_id": "ssh-01:7f3a9c", "seq": 14 },
  "src": { "ip": "10.66.0.23", "port": 51544 },
  "dst": { "port": 2222 },
  "type": "shell.command",
  "data": { "raw": "cat /home/deploy/.aws/credentials", "argv0": "cat", "cwd": "/home/deploy", "exit": 0 },
  "client": { "ssh_banner": "SSH-2.0-OpenSSH_9.6", "ssh_key_fp": "SHA256:…", "ua": null },
  "timing": { "since_prev_ms": 4210, "keystrokes": 34, "edits": 2, "paste": false },
  "tokens": ["tok_aws_k7"]
}
```

## Field rules

| Field | Type | Required | Rule |
| --- | --- | --- | --- |
| `schema` | string | yes | exactly `dsoc.event/v1` |
| `event_id` | ULID | yes | made by sensor; unique; retries are idempotent |
| `ts` | RFC3339 ms UTC | yes | sensor clock; reject if > 5 min in future |
| `sensor.id` | string | yes | must match the HMAC key id |
| `sensor.service` | enum | yes | `ssh`, `web`, `dbadmin`, `k8s`, `beacon`, `engine`, `firewall`, `hostauth`, `appauth` |
| `origin` | enum | yes | `decoy` (decoys, engine) or `production` (external logs via `cmd/log-collector`, see 07 §8) |
| `sensor.maze_node` | string | no | maze node the interaction belongs to |
| `session.sensor_session_id` | string | yes | `<sensor.id>:<random>`; one per TCP connection (or per web cookie / per k8s token+IP for 30 min) |
| `session.seq` | int | yes | starts at 0, +1 per event in session |
| `src.ip` / `src.port` | string / int | yes | attacker side |
| `dst.port` | int | yes | decoy port |
| `type` | enum | yes | see table below |
| `data` | object | yes | per-type fields below; may be `{}` |
| `client` | object | no | fingerprint inputs; omit unknown keys (no empty strings) |
| `timing` | object | no | SSH only for now; see behaviour features |
| `tokens` | string[] | no | honeytoken ids recognised in this interaction |

Limits: envelope ≤ 64 KB; `data.raw` ≤ 4 KB (set `data.truncated: true` when cut). Batch ≤ 200 envelopes.

## Event types

| Type | Emitted by | `data` fields |
| --- | --- | --- |
| `conn.open` | all | — |
| `conn.close` | all | `duration_ms`, `bytes_in`, `bytes_out`, `reason` (`client`, `timeout`, `limit`, `killed`) |
| `auth.attempt` | ssh, web, k8s | `username`, `password` (string, may be null), `key_fp`, `method` (`password`,`publickey`,`form`,`bearer`), `success` (bool) |
| `shell.command` | ssh | `raw`, `argv0`, `args` (string[]), `cwd`, `exit`, `stdout_tokens` (≤ 50 path/word tokens from the simulated output) |
| `file.read` | ssh, web | `path`, `honeyfile_id` (nullable), `bytes` |
| `file.download` | web | `path`, `honeyfile_id`, `bytes` |
| `file.upload` | ssh | `path`, `sha256`, `size` (content quarantined, never executed) |
| `http.request` | web, k8s, beacon | `method`, `path`, `query` (object), `body_sample` (≤1 KB), `status`, `ua` |
| `k8s.api_call` | k8s | `verb` (`get`,`list`,`create`,`delete`,`watch`), `resource`, `namespace`, `name`, `authenticated` |
| `token.used` | any | `token_id`, `token_kind`, `via` (e.g. `aws_api`, `k8s_bearer`, `ssh_key`, `url_fetch`, `db_login`) |
| `input.suspicious` | web | `param`, `value`, `separator` (e.g. `;`), `payload` (part after separator) — set by decoy's cheap pre-check, engine re-checks |
| `scan.detected` | engine | `ports` (int[]), `window_s` |
| `maze.unlock` | engine | `actor_id`, `from_node`, `to_node`, `theme`, `reason` |
| `sensor.heartbeat` | all | `version`, `uptime_s`, `active_sessions` |
| `fw.deny` / `fw.allow` | log-collector (firewall) | `dst_ip`, `dst_port`, `proto`, `rule` |
| `auth.real_failed` / `auth.real_success` | log-collector (host sshd) | `username`, `method`, `host` |
| `auth.app_failed` / `auth.app_success` | log-collector (real app) | `username`, `ua`, `app` |

External (`origin: production`) events use `session.sensor_session_id = "<sensor.id>:<src_ip>:<yyyymmddhh>"`
(one pseudo-session per source IP per hour) and never carry passwords in clear: the collector stores
`password_hash` (SHA-256, salted per deployment) so `decoy_cred_on_real` can match against decoy credentials hashed the same way.

`timing` (SSH shell lines): `since_prev_ms` (gap since previous command finished printing), `keystrokes`,
`edits` (backspace/delete/arrow edits), `paste` (true if ≥ 8 chars arrived in one read).

## Go type (backend/go/internal/event/event.go)

```go
type Envelope struct {
    Schema  string          `json:"schema"`
    Origin  string          `json:"origin"`
    EventID string          `json:"event_id"`
    TS      time.Time       `json:"ts"`
    Sensor  Sensor          `json:"sensor"`
    Session SessionRef      `json:"session"`
    Src     Endpoint        `json:"src"`
    Dst     struct{ Port int `json:"port"` } `json:"dst"`
    Type    string          `json:"type"`
    Data    json.RawMessage `json:"data"`
    Client  *Client         `json:"client,omitempty"`
    Timing  *Timing         `json:"timing,omitempty"`
    Tokens  []string        `json:"tokens,omitempty"`
}
```

Derived (engine) events use the same envelope with `sensor.id = "engine"`, `sensor.service = "engine"`.
