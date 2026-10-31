package store

import (
	"context"
)

// ActorStats are the aggregates ActorSummary needs (04 §B).
type ActorStats struct {
	Services      []string
	IPs           []string
	SessionCount  int
	TopTechniques []string
	TokenHits     int
	MazeDepth     int
	LastStage     string // stage of the latest finding ("" when none)
}

func (s *Store) ActorStats(ctx context.Context, actorID string) (ActorStats, error) {
	var st ActorStats
	err := s.Pool.QueryRow(ctx, `SELECT
		COALESCE((SELECT array_agg(DISTINCT service ORDER BY service) FROM sessions WHERE actor_id::text = $1), '{}'),
		COALESCE((SELECT array_agg(DISTINCT host(src_ip)) FROM sessions WHERE actor_id::text = $1), '{}'),
		(SELECT count(*) FROM sessions WHERE actor_id::text = $1),
		COALESCE((SELECT array_agg(technique) FROM (SELECT technique FROM findings WHERE actor_id::text = $1 AND technique IS NOT NULL
			GROUP BY technique ORDER BY sum(points) DESC LIMIT 3) t), '{}'),
		(SELECT count(*) FROM token_hits WHERE actor_id::text = $1),
		COALESCE((SELECT count(*) FROM maze_state WHERE actor_id::text = $1 AND state = 'visited'), 0),
		COALESCE((SELECT stage FROM findings WHERE actor_id::text = $1 ORDER BY
			CASE stage WHEN 'lateral' THEN 4 WHEN 'post_access' THEN 3 WHEN 'access' THEN 2 ELSE 1 END DESC LIMIT 1), '')`,
		actorID).Scan(&st.Services, &st.IPs, &st.SessionCount, &st.TopTechniques, &st.TokenHits, &st.MazeDepth, &st.LastStage)
	return st, err
}

// ActorConfidence = mean link score of the actor's sessions; the first session counts 1.0 (07 §2 step 6).
func (s *Store) ActorConfidence(ctx context.Context, actorID string) (float64, error) {
	var c float64
	err := s.Pool.QueryRow(ctx, `SELECT COALESCE(avg(COALESCE(link_score, 1.0)), 1.0) FROM sessions WHERE actor_id::text = $1`,
		actorID).Scan(&c)
	return c, err
}
