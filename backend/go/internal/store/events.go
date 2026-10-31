package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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

// IngestBatch stores valid envelopes: session mapping, dedup on event_id, event counts.
// raws[i] is the original JSON of envs[i] (stored as `envelope`).
//
// Everything goes to Postgres as ONE pipelined batch (one network round trip). pgx sends a batch with a
// single Sync, so Postgres runs it as one implicit transaction: all of it commits or none does.
// Statements run in order, so each event insert sees the session upserted just before it.
func (s *Store) IngestBatch(ctx context.Context, sensorID string, envs []event.Envelope, raws []json.RawMessage) (IngestResult, error) {
	var res IngestResult
	if len(envs) == 0 {
		return res, nil
	}
	b := &pgx.Batch{}
	b.Queue(`INSERT INTO sensors (sensor_id, service, last_seen, status) VALUES ($1, $2, now(), 'ok')
		ON CONFLICT (sensor_id) DO UPDATE SET last_seen = now(), status = 'ok'`, sensorID, envs[0].Sensor.Service)

	firstOf := map[string]int{} // sensor_session_id -> index of its first event in this batch
	order := []string{}
	for i := range envs {
		sid := envs[i].Session.SensorSessionID
		if _, ok := firstOf[sid]; !ok {
			firstOf[sid] = i
			order = append(order, sid)
		}
	}
	for _, sid := range order {
		e := &envs[firstOf[sid]]
		b.Queue(`INSERT INTO sessions (sensor_session_id, sensor_id, service, src_ip, started_at)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (sensor_session_id) DO UPDATE SET started_at = LEAST(sessions.started_at, EXCLUDED.started_at)
			RETURNING session_id, (xmax = 0)`, sid, sensorID, e.Sensor.Service, e.Src.IP, e.TS)
	}
	for i := range envs {
		e := &envs[i]
		var endedAt *time.Time
		if e.Type == "conn.close" {
			endedAt = &e.TS
		}
		// Insert the event (skipped on duplicate id) and bump its session in the same statement.
		b.Queue(`WITH s AS (SELECT session_id, actor_id FROM sessions WHERE sensor_session_id = $1),
			ins AS (INSERT INTO events (event_id, session_id, actor_id, ts, type, origin, sensor_id, service, src_ip, data, envelope)
				SELECT $2, s.session_id, s.actor_id, $3, $4, $5, $6, $7, $8, $9, $10 FROM s
				ON CONFLICT (event_id) DO NOTHING RETURNING session_id)
			UPDATE sessions SET event_count = event_count + 1, ended_at = COALESCE($11, ended_at)
			FROM ins WHERE sessions.session_id = ins.session_id
			RETURNING sessions.session_id, sessions.actor_id`,
			e.Session.SensorSessionID, e.EventID, e.TS, e.Type, e.Origin, sensorID, e.Sensor.Service, e.Src.IP,
			[]byte(e.Data), []byte(raws[i]), endedAt)
	}

	br := s.Pool.SendBatch(ctx, b)
	defer br.Close()
	if _, err := br.Exec(); err != nil {
		return res, fmt.Errorf("sensor upsert: %w", err)
	}
	newSession := map[string]bool{}
	for _, sid := range order {
		var id string
		var inserted bool
		if err := br.QueryRow().Scan(&id, &inserted); err != nil {
			return res, fmt.Errorf("session %s: %w", sid, err)
		}
		newSession[sid] = inserted
	}
	for i := range envs {
		e := &envs[i]
		var sessionID string
		var actorID *string
		err := br.QueryRow().Scan(&sessionID, &actorID)
		if errors.Is(err, pgx.ErrNoRows) {
			res.Duplicates++
			continue
		}
		if err != nil {
			return res, fmt.Errorf("insert %s: %w", e.EventID, err)
		}
		isFirst := firstOf[e.Session.SensorSessionID] == i && newSession[e.Session.SensorSessionID]
		res.Accepted = append(res.Accepted, StoredEvent{
			EventID: e.EventID, SessionID: sessionID, ActorID: actorID, TS: e.TS, Type: e.Type, Origin: e.Origin,
			SensorID: sensorID, Service: e.Sensor.Service, SrcIP: e.Src.IP, Data: e.Data, Envelope: raws[i],
			Tokens: e.Tokens, NewSession: isFirst,
		})
	}
	if err := br.Close(); err != nil {
		return IngestResult{}, fmt.Errorf("commit batch: %w", err)
	}
	return res, nil
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
