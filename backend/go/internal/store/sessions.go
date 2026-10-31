package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// SessionRow is one row of `sessions`.
type SessionRow struct {
	SessionID       string
	SensorSessionID string
	ActorID         *string
	LinkScore       *float64
	LinkReasons     json.RawMessage
	SensorID        string
	Service         string
	SrcIP           string
	StartedAt       time.Time
	EndedAt         *time.Time
	EventCount      int
	MazeDepth       int
}

const sessionCols = `session_id, sensor_session_id, actor_id, link_score, link_reasons, sensor_id, service, host(src_ip),
	started_at, ended_at, event_count, maze_depth`

func scanSession(row pgx.Row) (SessionRow, error) {
	var s SessionRow
	var score *float32
	err := row.Scan(&s.SessionID, &s.SensorSessionID, &s.ActorID, &score, &s.LinkReasons, &s.SensorID, &s.Service,
		&s.SrcIP, &s.StartedAt, &s.EndedAt, &s.EventCount, &s.MazeDepth)
	if score != nil {
		v := float64(*score)
		s.LinkScore = &v
	}
	return s, notFound(err)
}

func (s *Store) Session(ctx context.Context, id string) (SessionRow, error) {
	return scanSession(s.Pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE session_id::text = $1`, id))
}

func (s *Store) SessionBySensorID(ctx context.Context, sensorSessionID string) (SessionRow, error) {
	return scanSession(s.Pool.QueryRow(ctx, `SELECT `+sessionCols+` FROM sessions WHERE sensor_session_id = $1`, sensorSessionID))
}

func (s *Store) SessionsOfActor(ctx context.Context, actorID string) ([]SessionRow, error) {
	return s.querySessions(ctx, `SELECT `+sessionCols+` FROM sessions WHERE actor_id::text = $1 ORDER BY started_at`, actorID)
}

func (s *Store) querySessions(ctx context.Context, q string, args ...any) ([]SessionRow, error) {
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SessionRow
	for rows.Next() {
		r, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// CandidateActors returns actors with a session in the last 24 h that shares a fingerprint with the given
// session, or comes from the same /24 (07 §2 step 1). Oldest actor first.
func (s *Store) CandidateActors(ctx context.Context, sessionID string) ([]string, error) {
	rows, err := s.Pool.Query(ctx, `
		WITH me AS (SELECT session_id, src_ip, started_at FROM sessions WHERE session_id::text = $1)
		SELECT DISTINCT o.actor_id::text, a.first_seen FROM sessions o JOIN actors a ON a.actor_id = o.actor_id, me
		WHERE o.actor_id IS NOT NULL AND a.merged_into IS NULL AND o.session_id <> me.session_id
		  AND o.started_at > me.started_at - interval '24 hours'
		  AND (set_masklen(o.src_ip, 24)::cidr = set_masklen(me.src_ip, 24)::cidr
		       OR EXISTS (SELECT 1 FROM fingerprints f1 JOIN fingerprints f2 ON f1.kind = f2.kind AND f1.value = f2.value
		                  WHERE f1.session_id = me.session_id AND f2.session_id = o.session_id)
		       OR EXISTS (SELECT 1 FROM fingerprints f1 JOIN fingerprints f2 ON f1.value = f2.value
		                  AND ((f1.kind = 'token_used' AND f2.kind = 'token_seen') OR (f1.kind = 'token_seen' AND f2.kind = 'token_used'))
		                  WHERE f1.session_id = me.session_id AND f2.session_id = o.session_id))
		ORDER BY a.first_seen`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		var fs time.Time
		if err := rows.Scan(&id, &fs); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// AttachSession links a session (and its events) to an actor with a score and reasons.
func (s *Store) AttachSession(ctx context.Context, sessionID, actorID string, score float64, reasons any) error {
	b, _ := json.Marshal(reasons)
	return s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE sessions SET actor_id = $2, link_score = $3, link_reasons = $4 WHERE session_id::text = $1`,
			sessionID, actorID, score, b); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE events SET actor_id = $2 WHERE session_id::text = $1`, sessionID, actorID)
		return err
	})
}

// MergeActors moves everything of `from` into `into` (03 §Merge procedure).
func (s *Store) MergeActors(ctx context.Context, into, from string) error {
	return s.Tx(ctx, func(tx pgx.Tx) error {
		stmts := []string{
			`UPDATE sessions SET actor_id = $1 WHERE actor_id::text = $2`,
			`UPDATE events SET actor_id = $1 WHERE actor_id::text = $2`,
			`DELETE FROM findings f WHERE f.actor_id::text = $2 AND EXISTS (SELECT 1 FROM findings g WHERE g.actor_id::text = $1 AND g.rule_id = f.rule_id)`,
			`UPDATE findings SET actor_id = $1 WHERE actor_id::text = $2`,
			`UPDATE token_hits SET actor_id = $1 WHERE actor_id::text = $2`,
			`UPDATE deception_tactics SET actor_id = $1 WHERE actor_id::text = $2`,
			`DELETE FROM maze_state m WHERE m.actor_id::text = $2 AND EXISTS (SELECT 1 FROM maze_state n WHERE n.actor_id::text = $1 AND n.node_id = m.node_id)`,
			`UPDATE maze_state SET actor_id = $1 WHERE actor_id::text = $2`,
			`UPDATE actors SET first_seen = LEAST(first_seen, (SELECT first_seen FROM actors WHERE actor_id::text = $2)),
				last_seen = GREATEST(last_seen, (SELECT last_seen FROM actors WHERE actor_id::text = $2)) WHERE actor_id::text = $1`,
			`UPDATE actors SET merged_into = $1 WHERE actor_id::text = $2`,
		}
		for _, q := range stmts {
			if _, err := tx.Exec(ctx, q, into, from); err != nil {
				return err
			}
		}
		// Keep the older incident; note the merge.
		_, err := tx.Exec(ctx, `
			WITH b AS (SELECT incident_id FROM incidents WHERE actor_id::text = $2)
			INSERT INTO incident_notes (incident_id, body)
			SELECT i.incident_id, 'merged from ' || (SELECT label FROM actors WHERE actor_id::text = $2)
			FROM incidents i WHERE i.actor_id::text = $1 AND EXISTS (SELECT 1 FROM b)`, into, from)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE incidents SET status = 'closed', actor_id = NULL WHERE actor_id::text = $2
			AND EXISTS (SELECT 1 FROM incidents WHERE actor_id::text = $1)`, into, from)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE incidents SET actor_id = $1 WHERE actor_id::text = $2`, into, from)
		return err
	})
}

// Fingerprint is one (kind, value) of a session (07 §1).
type Fingerprint struct {
	SessionID, Kind, Value string
	TS                     time.Time
}

// AddFingerprints inserts rows; returns how many were new.
func (s *Store) AddFingerprints(ctx context.Context, fps []Fingerprint) (int, error) {
	if len(fps) == 0 {
		return 0, nil
	}
	b := &pgx.Batch{}
	for _, f := range fps {
		b.Queue(`INSERT INTO fingerprints (session_id, kind, value, ts) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
			f.SessionID, f.Kind, f.Value, f.TS)
	}
	br := s.Pool.SendBatch(ctx, b)
	defer br.Close()
	n := 0
	for range fps {
		tag, err := br.Exec()
		if err != nil {
			return n, err
		}
		n += int(tag.RowsAffected())
	}
	return n, br.Close()
}

// FingerprintsOf returns every fingerprint of the given sessions.
func (s *Store) FingerprintsOf(ctx context.Context, sessionIDs []string) ([]Fingerprint, error) {
	rows, err := s.Pool.Query(ctx, `SELECT session_id::text, kind, value, ts FROM fingerprints
		WHERE session_id::text = ANY($1) ORDER BY kind, value`, sessionIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fingerprint
	for rows.Next() {
		var f Fingerprint
		if err := rows.Scan(&f.SessionID, &f.Kind, &f.Value, &f.TS); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
