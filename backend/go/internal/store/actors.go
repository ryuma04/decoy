package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Actor is one row of `actors`.
type Actor struct {
	ActorID           string
	Label             string
	FirstSeen         time.Time
	LastSeen          time.Time
	RiskScore         int
	Severity          string
	Confidence        float64
	BehaviourClass    string
	BehaviourScore    json.RawMessage
	Interest          map[string]int
	StageScores       map[string]float64
	RiskBreakdown     json.RawMessage
	Tools             json.RawMessage
	TouchedProduction bool
	MergedInto        *string
}

const actorCols = `actor_id, label, first_seen, last_seen, risk_score, severity, confidence, behaviour_class,
	behaviour_score, interest, stage_scores, risk_breakdown, tools, touched_production, merged_into`

func scanActor(row pgx.Row) (Actor, error) {
	var a Actor
	var interest, stages []byte
	err := row.Scan(&a.ActorID, &a.Label, &a.FirstSeen, &a.LastSeen, &a.RiskScore, &a.Severity, &a.Confidence,
		&a.BehaviourClass, &a.BehaviourScore, &interest, &stages, &a.RiskBreakdown, &a.Tools, &a.TouchedProduction, &a.MergedInto)
	if err != nil {
		return a, notFound(err)
	}
	_ = json.Unmarshal(interest, &a.Interest)
	_ = json.Unmarshal(stages, &a.StageScores)
	return a, nil
}

// CreateActor inserts a new actor with the next ACT-%04d label.
func (s *Store) CreateActor(ctx context.Context, ts time.Time) (Actor, error) {
	return scanActor(s.Pool.QueryRow(ctx, `INSERT INTO actors (label, first_seen, last_seen)
		VALUES ('ACT-' || lpad(nextval('actor_label_seq')::text, 4, '0'), $1, $1) RETURNING `+actorCols, ts))
}

func (s *Store) Actor(ctx context.Context, id string) (Actor, error) {
	return scanActor(s.Pool.QueryRow(ctx, `SELECT `+actorCols+` FROM actors WHERE actor_id::text = $1`, id))
}

// ActorByLabel lets the API accept "ACT-0007" as well as the uuid.
func (s *Store) ActorByLabel(ctx context.Context, label string) (Actor, error) {
	return scanActor(s.Pool.QueryRow(ctx, `SELECT `+actorCols+` FROM actors WHERE label = $1`, label))
}

// ActorFilter holds GET /v1/actors parameters.
type ActorFilter struct {
	Severity, BehaviourClass string
	Since                    time.Time
	SortByRisk               bool
	Limit, Offset            int
}

func (s *Store) ListActors(ctx context.Context, f ActorFilter) ([]Actor, error) {
	order := "last_seen DESC"
	if f.SortByRisk {
		order = "risk_score DESC, last_seen DESC"
	}
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, fmt.Sprintf(`SELECT %s FROM actors WHERE merged_into IS NULL
		AND ($1 = '' OR severity = $1) AND ($2 = '' OR behaviour_class = $2) AND ($3::timestamptz IS NULL OR last_seen >= $3)
		ORDER BY %s LIMIT $4 OFFSET $5`, actorCols, order),
		f.Severity, f.BehaviourClass, nullTime(f.Since), limit+1, f.Offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Actor
	for rows.Next() {
		a, err := scanActor(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ActorScore is what the engine writes after scoring.
type ActorScore struct {
	RiskScore         int
	Severity          string
	Confidence        float64
	StageScores       map[string]float64
	RiskBreakdown     any
	TouchedProduction bool
}

func (s *Store) UpdateActorScore(ctx context.Context, id string, sc ActorScore) error {
	stages, _ := json.Marshal(sc.StageScores)
	bd, _ := json.Marshal(sc.RiskBreakdown)
	_, err := s.Pool.Exec(ctx, `UPDATE actors SET risk_score = $2, severity = $3, confidence = $4, stage_scores = $5,
		risk_breakdown = $6, touched_production = touched_production OR $7, last_seen = GREATEST(last_seen, now())
		WHERE actor_id::text = $1`, id, sc.RiskScore, sc.Severity, sc.Confidence, stages, bd, sc.TouchedProduction)
	return err
}

// UpdateActorBehaviour persists behaviour_class and behaviour_score.
func (s *Store) UpdateActorBehaviour(ctx context.Context, id string, class string, score any) error {
	b, _ := json.Marshal(score)
	_, err := s.Pool.Exec(ctx, `UPDATE actors SET behaviour_class = $2, behaviour_score = $3, last_seen = GREATEST(last_seen, now())
		WHERE actor_id::text = $1`, id, class, b)
	return err
}

// TouchActor moves last_seen forward.
func (s *Store) TouchActor(ctx context.Context, id string, ts time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE actors SET last_seen = GREATEST(last_seen, $2) WHERE actor_id::text = $1`, id, ts)
	return err
}

// SetInterest stores the maze interest counters (08).
func (s *Store) SetInterest(ctx context.Context, id string, interest map[string]int) error {
	b, _ := json.Marshal(interest)
	_, err := s.Pool.Exec(ctx, `UPDATE actors SET interest = $2 WHERE actor_id::text = $1`, id, b)
	return err
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
