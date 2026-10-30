# 03 — Database (PostgreSQL 16)

Events are append-only. Everything else is derived and can be rebuilt by replaying events
(`cmd/core replay --from <ts>`). Migrations live in `backend/go/migrations/` (golang-migrate, embedded with
`embed.FS`, applied on core start-up).

## 0001_init.up.sql

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  user_id       uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email         text UNIQUE NOT NULL,
  password_hash text NOT NULL,              -- bcrypt
  role          text NOT NULL CHECK (role IN ('analyst','admin')),
  created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sensors (
  sensor_id   text PRIMARY KEY,
  service     text NOT NULL,
  version     text,
  last_seen   timestamptz,
  status      text NOT NULL DEFAULT 'unknown'  -- ok | silent | unknown
);

CREATE TABLE actors (
  actor_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  label           text UNIQUE NOT NULL,          -- ACT-0001
  first_seen      timestamptz NOT NULL,
  last_seen       timestamptz NOT NULL,
  risk_score      int  NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
  severity        text NOT NULL DEFAULT 'low',
  confidence      real NOT NULL DEFAULT 1.0,
  behaviour_class text NOT NULL DEFAULT 'unknown',  -- human_like|scripted|ai_assisted|agent_like|unknown
  behaviour_score jsonb,                         -- {"human_like":0.1,"scripted":0.2,"agent_like":0.7,"source":"rules|ml"}
  interest        jsonb NOT NULL DEFAULT '{"cloud":0,"k8s":0,"db":0,"ci":0}',
  merged_into     uuid REFERENCES actors
);
CREATE SEQUENCE actor_label_seq;

CREATE TABLE sessions (
  session_id        uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sensor_session_id text UNIQUE NOT NULL,
  actor_id          uuid REFERENCES actors,
  link_score        real,
  link_reasons      jsonb,      -- [{"signal":"ssh_key","weight":0.9,"matched_session":"…","value":"SHA256:…"}]
  sensor_id         text NOT NULL REFERENCES sensors,
  service           text NOT NULL,
  src_ip            inet NOT NULL,
  started_at        timestamptz NOT NULL,
  ended_at          timestamptz,
  event_count       int NOT NULL DEFAULT 0,
  maze_depth        int NOT NULL DEFAULT 0
);
CREATE INDEX sessions_actor ON sessions(actor_id);
CREATE INDEX sessions_ip_time ON sessions(src_ip, started_at DESC);

CREATE TABLE events (
  event_id    text PRIMARY KEY,
  session_id  uuid REFERENCES sessions,
  actor_id    uuid REFERENCES actors,       -- denormalised for fast timelines; updated on merge
  ts          timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  type        text NOT NULL,
  sensor_id   text NOT NULL,
  service     text NOT NULL,
  src_ip      inet NOT NULL,
  data        jsonb NOT NULL,
  envelope    jsonb NOT NULL
);
CREATE INDEX events_session_ts ON events(session_id, ts);
CREATE INDEX events_actor_ts   ON events(actor_id, ts);
CREATE INDEX events_type_ts    ON events(type, ts DESC);
CREATE INDEX events_ts         ON events(ts DESC);

CREATE TABLE fingerprints (
  session_id uuid REFERENCES sessions,
  kind       text NOT NULL,   -- ssh_banner|ssh_key|hassh|ua|ja4|cred_pair|cmd_shingles|token_seen|token_used
  value      text NOT NULL,
  ts         timestamptz NOT NULL,
  PRIMARY KEY (session_id, kind, value)
);
CREATE INDEX fingerprints_kv ON fingerprints(kind, value, ts DESC);

CREATE TABLE honeytokens (
  token_id    text PRIMARY KEY,                -- tok_aws_k7
  kind        text NOT NULL,                   -- aws_key|kubeconfig|honeyfile|db_cred|url|ssh_key
  planted_at  text NOT NULL,                   -- ssh:/home/deploy/.aws/credentials
  maze_node   text,
  match_value text NOT NULL,                   -- what decoys look for (access key id, bearer token, password, path)
  sensitivity int  NOT NULL DEFAULT 3 CHECK (sensitivity BETWEEN 1 AND 5),
  burned      boolean NOT NULL DEFAULT false,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE token_hits (
  hit_id    bigserial PRIMARY KEY,
  token_id  text REFERENCES honeytokens,
  event_id  text REFERENCES events,
  actor_id  uuid REFERENCES actors,
  kind      text NOT NULL,                     -- seen (file read) | used (credential used)
  ts        timestamptz NOT NULL
);

CREATE TABLE findings (
  finding_id  bigserial PRIMARY KEY,
  session_id  uuid REFERENCES sessions,
  actor_id    uuid REFERENCES actors,
  rule_id     text NOT NULL,
  title       text NOT NULL,
  tactic      text,                            -- TA0006
  technique   text,                            -- T1552.001
  points      int NOT NULL,
  confidence  real NOT NULL DEFAULT 1.0,
  source      text NOT NULL DEFAULT 'rule',    -- rule | ml | rule+ml
  evidence    jsonb NOT NULL,                  -- {"event_ids":[…],"matched":"cat ~/.aws/credentials","ml":{…}}
  ts          timestamptz NOT NULL
);
CREATE UNIQUE INDEX findings_once ON findings(actor_id, rule_id);  -- one per actor per rule
CREATE INDEX findings_actor_ts ON findings(actor_id, ts);

CREATE TABLE incidents (
  incident_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  actor_id    uuid UNIQUE REFERENCES actors,  -- one open incident per actor
  severity    text NOT NULL,
  status      text NOT NULL DEFAULT 'open',    -- open | ack | contained | closed
  title       text NOT NULL,
  summary     text,
  summary_src text,                            -- template | llm
  opened_at   timestamptz NOT NULL,
  updated_at  timestamptz NOT NULL,
  notified_at timestamptz,
  notified_severity text
);

CREATE TABLE incident_notes (
  note_id     bigserial PRIMARY KEY,
  incident_id uuid REFERENCES incidents,
  author      uuid REFERENCES users,
  body        text NOT NULL,
  ts          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE response_actions (
  action_id   bigserial PRIMARY KEY,
  incident_id uuid REFERENCES incidents,
  action      text NOT NULL,                   -- block_ip | kill_session | rotate_token | unblock_ip
  target      text NOT NULL,                   -- ip, session_id or token_id
  requested_by uuid REFERENCES users,
  status      text NOT NULL DEFAULT 'pending', -- pending | applied | failed | reverted
  ts          timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE policy (                           -- what decoys must enforce, polled every 5 s
  kind   text NOT NULL,                         -- blocked_ip | killed_session | burned_token
  value  text NOT NULL,
  until  timestamptz,
  PRIMARY KEY (kind, value)
);

CREATE TABLE maze_state (
  actor_id    uuid REFERENCES actors,
  node_id     text NOT NULL,
  state       text NOT NULL,                   -- hidden | visible | visited
  loops       int NOT NULL DEFAULT 0,
  unlocked_by text,
  updated_at  timestamptz NOT NULL,
  PRIMARY KEY (actor_id, node_id)
);

CREATE VIEW iocs AS
  SELECT DISTINCT 'ip' AS kind, host(src_ip) AS value, actor_id FROM events WHERE actor_id IS NOT NULL
  UNION SELECT 'sha256', data->>'sha256', actor_id FROM events WHERE type = 'file.upload'
  UNION SELECT 'credential', (data->>'username') || ':' || (data->>'password'), actor_id
        FROM events WHERE type = 'auth.attempt' AND data->>'password' IS NOT NULL
  UNION SELECT 'url', data->'args'->>0, actor_id FROM events
        WHERE type = 'shell.command' AND data->>'argv0' IN ('wget','curl');
```

## Merge procedure (actor B merged into A)

In one transaction: `UPDATE sessions SET actor_id=A WHERE actor_id=B`; same for `events`, `findings`
(drop duplicates violating `findings_once`), `token_hits`, `maze_state` (keep the more advanced state);
`UPDATE actors SET merged_into=A WHERE actor_id=B`; recompute A's risk; close B's incident into A's.
