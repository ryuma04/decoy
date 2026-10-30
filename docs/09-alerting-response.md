# 09 — Alerting, incidents, response, reports

## Incidents (`internal/alert`)

- One incident per actor (`incidents.actor_id` unique). Opened when the actor first reaches **medium**.
- Title template: `<severity>: <top finding title> by <ACT-xxxx> (<n> services)`.
- Updated on every finding; `updated_at` bumps; severity only goes up automatically (analyst may close).
- Merge of actors merges incidents (keep older; append notes "merged from …").

## Notification policy

| Severity | Channel | Timing |
| --- | --- | --- |
| low | dashboard | — |
| medium | Discord digest | every 15 min, one message listing new medium incidents |
| high | Discord | immediately |
| critical | Discord with `@here` + Slack | immediately |

Re-notify only when severity rises; cooldown 10 min per incident. Notifier interface:

```go
type Notifier interface { Notify(ctx context.Context, n Notification) error }
```

Implementations: `discord.go`, `slack.go`, `log.go` (always on). Webhook failures retry 3× with backoff and
never block the engine (own goroutine + queue).

### Discord payload

```json
{
  "content": "@here",
  "embeds": [{
    "title": "CRITICAL — Honeytoken used by ACT-0007",
    "url": "http://localhost:3000/incidents/c1f…",
    "color": 15158332,
    "fields": [
      {"name": "Risk", "value": "82 / 100", "inline": true},
      {"name": "Behaviour", "value": "agent-like", "inline": true},
      {"name": "Services", "value": "web, ssh, k8s, beacon", "inline": true},
      {"name": "Trigger", "value": "token.used tok_aws_k7 (AWS-style key) via aws_api"},
      {"name": "Recent activity", "value": "• downloaded internal-backup.zip\n• SSH login with leaked key\n• cat ~/.aws/credentials\n• kubectl get secrets\n• AWS API call with lure key"},
      {"name": "ATT&CK", "value": "T1552.001, T1078, T1613"}
    ],
    "footer": {"text": "Deception SOC · lab environment"},
    "timestamp": "2026-11-14T09:05:40Z"
  }]
}
```

Colours: low 3447003, medium 16776960, high 15105570, critical 15158332. Slack uses Block Kit with the same fields.

## Response actions (`internal/response`) — lab only

| Action | Effect | Reversible |
| --- | --- | --- |
| `block_ip` | insert `policy(blocked_ip, ip, until = now+24h)`; decoys refuse new connections within 5 s | `unblock_ip` |
| `kill_session` | `policy(killed_session, sensor_session_id)`; decoy closes it | n/a |
| `rotate_token` | mark `honeytokens.burned`, `policy(burned_token)`; `cmd/seed --rotate <id>` plants a new one | yes (seed) |

Every action → `response_actions` row with `requested_by`, published on `incident` topic. Admin role only.
We never touch host firewalls or real infrastructure; `block_ip` is enforced by our decoys.

**Recommended actions** in `IncidentDetail` are generated from findings, e.g. token used → "rotate token, block IP";
ssh persistence → "kill session, block IP". Each one has a "why" sentence.

## Incident report (`internal/report`)

`GET /v1/incidents/{id}/report?format=md` returns:

1. Header: incident id, actor label, severity, risk, status, time range.
2. Summary (ML summary if available, else template from findings).
3. ATT&CK table: technique, name, tactic, evidence count, first seen.
4. Timeline (top 50 items).
5. Linked sessions with link reasons.
6. IOCs from the `iocs` view + used tokens.
7. Actions taken and recommended real-world fixes per technique (static map in `report/fixes.go`), e.g.
   T1552.001 → "scan repos and hosts for plaintext credentials; use a secrets manager".
8. Disclaimer: correlation is behavioural association, not identity.
