package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ryuma04/decoy/backend/internal/event"
)

// StoredEvent is one row of `events` joined with its actor label.
type StoredEvent struct {
	EventID    string
	SessionID  string
	ActorID    *string
	ActorLabel *string
	TS         time.Time
	Type       string
	Origin     string
	SensorID   string
	Service    string
	SrcIP      string
	Data       json.RawMessage
	Envelope   json.RawMessage
	Tokens     []string
	NewSession bool // first event of a new session (ingest only)
}

// IngestResult reports what happened to one batch.
type IngestResult struct {
	Accepted   []StoredEvent
	Duplicates int
}

// IngestBatch stores valid envelopes in one transaction: session mapping, dedup on event_id, event counts.
// raws[i] is the original JSON of envs[i] (stored as `envelope`).
func (s *Store) IngestBatch(ctx context.Context, sensorID string, envs []event.Envelope, raws []json.RawMessage) (IngestResult, error) {
	var res IngestResult
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		res = IngestResult{}
		service := ""
		if len(envs) > 0 {
			service = envs[0].Sensor.Service
		}
		if _, err := tx.Exec(ctx, `INSERT INTO sensors (sensor_id, service, last_seen, status) VALUES ($1, $2, now(), 'ok')
			ON CONFLICT (sensor_id) DO UPDATE SET last_seen = now(), status = 'ok'`, sensorID, service); err != nil {
			return err
		}
		for i := range envs {
			e := &envs[i]
			var sessionID string
			var inserted bool
			err := tx.QueryRow(ctx, `INSERT INTO sessions (sensor_session_id, sensor_id, service, src_ip, started_at)
				VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT (sensor_session_id) DO UPDATE SET started_at = LEAST(sessions.started_at, EXCLUDED.started_at)
				RETURNING session_id, (xmax = 0)`,
				e.Session.SensorSessionID, sensorID, e.Sensor.Service, e.Src.IP, e.TS).Scan(&sessionID, &inserted)
			if err != nil {
				return fmt.Errorf("session for %s: %w", e.EventID, err)
			}
			var actorID *string
			tag, err := tx.Exec(ctx, `INSERT INTO events (event_id, session_id, actor_id, ts, type, origin, sensor_id, service, src_ip, data, envelope)
				SELECT $1, $2, s.actor_id, $3, $4, $5, $6, $7, $8, $9, $10 FROM sessions s WHERE s.session_id = $2
				ON CONFLICT (event_id) DO NOTHING`,
				e.EventID, sessionID, e.TS, e.Type, e.Origin, sensorID, e.Sensor.Service, e.Src.IP, []byte(e.Data), []byte(raws[i]))
			if err != nil {
				return fmt.Errorf("insert %s: %w", e.EventID, err)
			}
			if tag.RowsAffected() == 0 {
				res.Duplicates++
				continue
			}
			endedAt := (*time.Time)(nil)
			if e.Type == "conn.close" {
				endedAt = &e.TS
			}
			if err := tx.QueryRow(ctx, `UPDATE sessions SET event_count = event_count + 1, ended_at = COALESCE($2, ended_at)
				WHERE session_id = $1 RETURNING actor_id`, sessionID, endedAt).Scan(&actorID); err != nil {
				return err
			}
			res.Accepted = append(res.Accepted, StoredEvent{
				EventID: e.EventID, SessionID: sessionID, ActorID: actorID, TS: e.TS, Type: e.Type, Origin: e.Origin,
				SensorID: sensorID, Service: e.Sensor.Service, SrcIP: e.Src.IP, Data: e.Data, Envelope: raws[i],
				Tokens: e.Tokens, NewSession: inserted,
			})
		}
		return nil
	})
	return res, err
}

// Heartbeat records a sensor heartbeat.
func (s *Store) Heartbeat(ctx context.Context, sensorID, service, version string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO sensors (sensor_id, service, version, last_seen, status) VALUES ($1, $2, $3, now(), 'ok')
		ON CONFLICT (sensor_id) DO UPDATE SET version = EXCLUDED.version, last_seen = now(), status = 'ok'`,
		sensorID, service, version)
	return err
}

// EventFilter holds the query parameters of GET /v1/events.
type EventFilter struct {
	Type, Service, ActorID, SessionID, SrcIP, Q string
	Since, Until                                time.Time
	Limit                                       int
	Cursor                                      string
}

const eventCols = `e.event_id, e.session_id, e.actor_id, a.label, e.ts, e.type, e.origin, e.sensor_id, e.service,
	host(e.src_ip), e.data, e.envelope`

func scanEvent(row pgx.Row) (StoredEvent, error) {
	var ev StoredEvent
	var sessionID *string
	err := row.Scan(&ev.EventID, &sessionID, &ev.ActorID, &ev.ActorLabel, &ev.TS, &ev.Type, &ev.Origin, &ev.SensorID,
		&ev.Service, &ev.SrcIP, &ev.Data, &ev.Envelope)
	if sessionID != nil {
		ev.SessionID = *sessionID
	}
	if err == nil {
		var env struct {
			Tokens []string `json:"tokens"`
		}
		_ = json.Unmarshal(ev.Envelope, &env)
		ev.Tokens = env.Tokens
	}
	return ev, err
}

// ListEvents returns events newest first with an opaque cursor for the next page ("" when done).
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]StoredEvent, string, error) {
	where := []string{"true"}
	args := []any{}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if f.Type != "" {
		add("e.type = ?", f.Type)
	}
	if f.Service != "" {
		add("e.service = ?", f.Service)
	}
	if f.ActorID != "" {
		add("e.actor_id::text = ?", f.ActorID)
	}
	if f.SessionID != "" {
		add("e.session_id::text = ?", f.SessionID)
	}
	if f.SrcIP != "" {
		add("host(e.src_ip) = ?", f.SrcIP)
	}
	if !f.Since.IsZero() {
		add("e.ts >= ?", f.Since)
	}
	if !f.Until.IsZero() {
		add("e.ts < ?", f.Until)
	}
	if f.Q != "" {
		add("(e.data::text ILIKE ? OR e.type ILIKE ?)", "%"+f.Q+"%") // both ? share one parameter
	}
	if f.Cursor != "" {
		ts, id, err := decodeCursor(f.Cursor)
		if err != nil {
			return nil, "", err
		}
		args = append(args, ts, id)
		where = append(where, fmt.Sprintf("(e.ts, e.event_id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	args = append(args, limit+1)
	q := fmt.Sprintf(`SELECT %s FROM events e LEFT JOIN actors a ON a.actor_id = e.actor_id
		WHERE %s ORDER BY e.ts DESC, e.event_id DESC LIMIT $%d`, eventCols, strings.Join(where, " AND "), len(args))
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	var out []StoredEvent
	for rows.Next() {
		ev, err := scanEvent(rows)
		if err != nil {
			return nil, "", err
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		last := out[len(out)-1]
		next = encodeCursor(last.TS, last.EventID)
	}
	return out, next, nil
}

// GetEvent returns one event.
func (s *Store) GetEvent(ctx context.Context, id string) (StoredEvent, error) {
	ev, err := scanEvent(s.Pool.QueryRow(ctx, `SELECT `+eventCols+` FROM events e LEFT JOIN actors a ON a.actor_id = e.actor_id
		WHERE e.event_id = $1`, id))
	return ev, notFound(err)
}

func encodeCursor(ts time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(ts.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeCursor(c string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("bad cursor")
	}
	tsStr, id, ok := strings.Cut(string(b), "|")
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if !ok || err != nil {
		return time.Time{}, "", fmt.Errorf("bad cursor")
	}
	return ts, id, nil
}
