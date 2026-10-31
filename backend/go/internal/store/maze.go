package store

import (
	"context"
	"strings"
	"time"
)

// MazeNodes returns node -> state for an actor, and the unlock times (maze_state.unlocked_by set).
func (s *Store) MazeNodes(ctx context.Context, actorID string) (map[string]string, []time.Time, error) {
	rows, err := s.Pool.Query(ctx, `SELECT node_id, state, unlocked_by, updated_at FROM maze_state WHERE actor_id::text = $1`, actorID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	nodes := map[string]string{}
	var unlocks []time.Time
	for rows.Next() {
		var id, state string
		var by *string
		var ts time.Time
		if err := rows.Scan(&id, &state, &by, &ts); err != nil {
			return nil, nil, err
		}
		nodes[id] = state
		if by != nil && *by != "" {
			unlocks = append(unlocks, ts)
		}
	}
	return nodes, unlocks, rows.Err()
}

// SetMazeNode writes a node state. visited never goes back to visible; unlockedBy is kept once set.
func (s *Store) SetMazeNode(ctx context.Context, actorID, nodeID, state, unlockedBy string) error {
	var by any
	if unlockedBy != "" {
		by = unlockedBy
	}
	_, err := s.Pool.Exec(ctx, `INSERT INTO maze_state (actor_id, node_id, state, unlocked_by, updated_at)
		VALUES ($1::uuid, $2, $3, $4, now())
		ON CONFLICT (actor_id, node_id) DO UPDATE SET
		  state = CASE WHEN maze_state.state = 'visited' THEN 'visited' ELSE EXCLUDED.state END,
		  unlocked_by = COALESCE(maze_state.unlocked_by, EXCLUDED.unlocked_by), updated_at = now()`,
		actorID, nodeID, state, by)
	return err
}

// LureFiles maps maze node -> planted path for one service, from honeytokens.planted_at ("ssh:/path").
func (s *Store) LureFiles(ctx context.Context, service string) (map[string][2]string, error) {
	rows, err := s.Pool.Query(ctx, `SELECT maze_node, planted_at, token_id FROM honeytokens WHERE maze_node IS NOT NULL AND NOT burned`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][2]string{}
	for rows.Next() {
		var node, planted, token string
		if err := rows.Scan(&node, &planted, &token); err != nil {
			return nil, err
		}
		if svc, path, ok := strings.Cut(planted, ":"); ok && svc == service {
			out[node] = [2]string{path, token}
		}
	}
	return out, rows.Err()
}
