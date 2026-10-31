package store

import (
	"context"
	"encoding/json"
	"time"
)

// FindingRow is one row of `findings`.
type FindingRow struct {
	FindingID  int64
	SessionID  *string
	ActorID    string
	RuleID     string
	Title      string
	Tactic     *string
	Technique  *string
	Points     int
	Confidence float64
	Stage      string
	Source     string
	Evidence   json.RawMessage
	TS         time.Time
}

// AddFinding inserts a finding once per actor per rule (unique index). Returns (row, true) when new.
func (s *Store) AddFinding(ctx context.Context, f FindingRow) (FindingRow, bool, error) {
	err := s.Pool.QueryRow(ctx, `INSERT INTO findings (session_id, actor_id, rule_id, title, tactic, technique, points,
		confidence, stage, source, evidence, ts) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (actor_id, rule_id) DO NOTHING RETURNING finding_id`,
		f.SessionID, f.ActorID, f.RuleID, f.Title, f.Tactic, f.Technique, f.Points, f.Confidence, f.Stage, f.Source,
		[]byte(f.Evidence), f.TS).Scan(&f.FindingID)
	if err != nil {
		if notFound(err) == ErrNotFound {
			return f, false, nil
		}
		return f, false, err
	}
	return f, true, nil
}

func (s *Store) FindingsOfActor(ctx context.Context, actorID string) ([]FindingRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT finding_id, session_id::text, actor_id::text, rule_id, title, tactic, technique,
		points, confidence, stage, source, evidence, ts FROM findings WHERE actor_id::text = $1 ORDER BY ts`, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FindingRow
	for rows.Next() {
		var f FindingRow
		var conf float32
		if err := rows.Scan(&f.FindingID, &f.SessionID, &f.ActorID, &f.RuleID, &f.Title, &f.Tactic, &f.Technique,
			&f.Points, &conf, &f.Stage, &f.Source, &f.Evidence, &f.TS); err != nil {
			return nil, err
		}
		f.Confidence = float64(conf)
		out = append(out, f)
	}
	return out, rows.Err()
}

// TechniqueCounts counts findings per technique since t (GET /v1/stats/techniques).
func (s *Store) TechniqueCounts(ctx context.Context, since time.Time) (map[string]int, error) {
	rows, err := s.Pool.Query(ctx, `SELECT technique, count(*) FROM findings WHERE technique IS NOT NULL AND ts >= $1
		GROUP BY technique ORDER BY count(*) DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var t string
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		out[t] = n
	}
	return out, rows.Err()
}

// Honeytoken is one row of `honeytokens` with hit counts.
type Honeytoken struct {
	TokenID     string
	Kind        string
	PlantedAt   string
	MazeNode    *string
	MatchValue  string
	Sensitivity int
	Burned      bool
	HitsSeen    int
	HitsUsed    int
	LastHit     *time.Time
}

func (s *Store) Honeytokens(ctx context.Context) ([]Honeytoken, error) {
	rows, err := s.Pool.Query(ctx, `SELECT h.token_id, h.kind, h.planted_at, h.maze_node, h.match_value, h.sensitivity, h.burned,
		count(*) FILTER (WHERE t.kind = 'seen'), count(*) FILTER (WHERE t.kind = 'used'), max(t.ts)
		FROM honeytokens h LEFT JOIN token_hits t ON t.token_id = h.token_id GROUP BY h.token_id ORDER BY h.token_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Honeytoken
	for rows.Next() {
		var h Honeytoken
		if err := rows.Scan(&h.TokenID, &h.Kind, &h.PlantedAt, &h.MazeNode, &h.MatchValue, &h.Sensitivity, &h.Burned,
			&h.HitsSeen, &h.HitsUsed, &h.LastHit); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UpsertHoneytoken is used by cmd/seed.
func (s *Store) UpsertHoneytoken(ctx context.Context, h Honeytoken) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO honeytokens (token_id, kind, planted_at, maze_node, match_value, sensitivity)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (token_id) DO UPDATE SET kind = EXCLUDED.kind,
		planted_at = EXCLUDED.planted_at, maze_node = EXCLUDED.maze_node, match_value = EXCLUDED.match_value,
		sensitivity = EXCLUDED.sensitivity, burned = false`,
		h.TokenID, h.Kind, h.PlantedAt, h.MazeNode, h.MatchValue, h.Sensitivity)
	return err
}

// AddTokenHit records a honeytoken seen (file read) or used (credential used).
func (s *Store) AddTokenHit(ctx context.Context, tokenID, eventID, actorID, kind string, ts time.Time) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO token_hits (token_id, event_id, actor_id, kind, ts)
		SELECT $1, $2, $3::uuid, $4, $5 WHERE EXISTS (SELECT 1 FROM honeytokens WHERE token_id = $1)`,
		tokenID, eventID, actorID, kind, ts)
	return err
}

// TokenSensitivity returns 0 for unknown tokens.
func (s *Store) TokenSensitivity(ctx context.Context, tokenID string) int {
	var n int
	_ = s.Pool.QueryRow(ctx, `SELECT sensitivity FROM honeytokens WHERE token_id = $1`, tokenID).Scan(&n)
	return n
}

// ActorTokenHits counts used/seen hits of an actor and the highest used sensitivity.
func (s *Store) ActorTokenHits(ctx context.Context, actorID string) (hits int, maxUsedSens int, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT count(*), COALESCE(max(h.sensitivity) FILTER (WHERE t.kind = 'used'), 0)
		FROM token_hits t JOIN honeytokens h ON h.token_id = t.token_id WHERE t.actor_id::text = $1`, actorID).Scan(&hits, &maxUsedSens)
	return
}
