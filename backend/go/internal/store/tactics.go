package store

import (
	"context"
	"encoding/json"
	"time"
)

// TacticRow is one applied cognitive-deception tactic (08 §Cognitive, deception_tactics table).
type TacticRow struct {
	TacticID        int64           `json:"tactic_id"`
	ActorID         string          `json:"actor_id"`
	BiasPattern     string          `json:"bias_pattern"`
	Tactic          string          `json:"tactic"`
	LureID          *string         `json:"lure_id"`
	TriggerEventIDs []string        `json:"trigger_event_ids"`
	Effect          json.RawMessage `json:"effect"`
	TS              time.Time       `json:"ts"`
}

// AddTactic records a tactic a decoy reported with a deception.tactic event.
func (s *Store) AddTactic(ctx context.Context, t TacticRow) error {
	effect := []byte(t.Effect)
	if len(effect) == 0 {
		effect = []byte(`{}`)
	}
	if t.TriggerEventIDs == nil {
		t.TriggerEventIDs = []string{}
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO deception_tactics (actor_id, bias_pattern, tactic, lure_id, trigger_event_ids, effect, ts)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7)`, t.ActorID, t.BiasPattern, t.Tactic, t.LureID, t.TriggerEventIDs, effect, t.TS)
	return err
}

// TacticsOfActor lists an actor's tactics, newest first.
func (s *Store) TacticsOfActor(ctx context.Context, actorID string) ([]TacticRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT tactic_id, actor_id::text, bias_pattern, tactic, lure_id, trigger_event_ids,
		COALESCE(effect, '{}'::jsonb), ts FROM deception_tactics WHERE actor_id::text = $1 ORDER BY ts DESC LIMIT 200`, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TacticRow{}
	for rows.Next() {
		var t TacticRow
		if err := rows.Scan(&t.TacticID, &t.ActorID, &t.BiasPattern, &t.Tactic, &t.LureID, &t.TriggerEventIDs, &t.Effect, &t.TS); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
