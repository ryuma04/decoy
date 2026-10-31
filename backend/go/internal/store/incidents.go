package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------- scorer weights (07 §6) ----------

type ScorerWeights struct {
	Version      int
	Weights      map[string]float64
	Bias         float64
	LearningRate float64
	FeedbackID   *int64
	CreatedAt    time.Time
}

func (s *Store) ActiveWeights(ctx context.Context) (ScorerWeights, error) {
	var w ScorerWeights
	var raw []byte
	var bias, lr float32
	err := s.Pool.QueryRow(ctx, `SELECT version, weights, bias, learning_rate, feedback_id, created_at FROM scorer_weights
		WHERE active ORDER BY version DESC LIMIT 1`).Scan(&w.Version, &raw, &bias, &lr, &w.FeedbackID, &w.CreatedAt)
	if err != nil {
		return w, notFound(err)
	}
	w.Bias, w.LearningRate = float64(bias), float64(lr)
	err = json.Unmarshal(raw, &w.Weights)
	return w, err
}

// SaveWeights writes a new active version (previous ones become inactive).
func (s *Store) SaveWeights(ctx context.Context, w ScorerWeights) (int, error) {
	b, _ := json.Marshal(w.Weights)
	var v int
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE scorer_weights SET active = false WHERE active`); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO scorer_weights (weights, bias, learning_rate, feedback_id) VALUES ($1, $2, $3, $4)
			RETURNING version`, b, w.Bias, w.LearningRate, w.FeedbackID).Scan(&v)
	})
	return v, err
}

// ResetWeights re-activates version 1.
func (s *Store) ResetWeights(ctx context.Context) error {
	return s.Tx(ctx, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE scorer_weights SET active = false`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE scorer_weights SET active = true WHERE version = 1`)
		return err
	})
}

type Feedback struct {
	ActorID, IncidentID string
	Label               int
	StageScores         map[string]float64
	Features            any
	PredictedP          float64
	Author              string
	Allowlisted         bool
}

func (s *Store) AddFeedback(ctx context.Context, f Feedback) (int64, error) {
	st, _ := json.Marshal(f.StageScores)
	feat, _ := json.Marshal(f.Features)
	var id int64
	err := s.Pool.QueryRow(ctx, `INSERT INTO risk_feedback (actor_id, incident_id, label, stage_scores, features, predicted_p,
		author, allowlisted) VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7::uuid, $8) RETURNING feedback_id`,
		f.ActorID, f.IncidentID, f.Label, st, feat, f.PredictedP, f.Author, f.Allowlisted).Scan(&id)
	return id, err
}

func (s *Store) FeedbackCounts(ctx context.Context) (confirmed, falsePositive int, err error) {
	err = s.Pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE label = 1), count(*) FILTER (WHERE label = 0) FROM risk_feedback`).
		Scan(&confirmed, &falsePositive)
	return
}

// ---------- incidents (09) ----------

type IncidentRow struct {
	IncidentID       string
	ActorID          *string
	Severity         string
	Status           string
	Title            string
	Summary          *string
	SummarySrc       *string
	OpenedAt         time.Time
	UpdatedAt        time.Time
	NotifiedAt       *time.Time
	NotifiedSeverity *string
}

const incidentCols = `incident_id::text, actor_id::text, severity, status, title, summary, summary_src, opened_at, updated_at,
	notified_at, notified_severity`

func scanIncident(row pgx.Row) (IncidentRow, error) {
	var i IncidentRow
	err := row.Scan(&i.IncidentID, &i.ActorID, &i.Severity, &i.Status, &i.Title, &i.Summary, &i.SummarySrc, &i.OpenedAt,
		&i.UpdatedAt, &i.NotifiedAt, &i.NotifiedSeverity)
	return i, notFound(err)
}

func (s *Store) Incident(ctx context.Context, id string) (IncidentRow, error) {
	return scanIncident(s.Pool.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE incident_id::text = $1`, id))
}

func (s *Store) IncidentOfActor(ctx context.Context, actorID string) (IncidentRow, error) {
	return scanIncident(s.Pool.QueryRow(ctx, `SELECT `+incidentCols+` FROM incidents WHERE actor_id::text = $1`, actorID))
}

// UpsertIncident opens the actor's incident or updates title/severity (severity only rises; caller decides).
func (s *Store) UpsertIncident(ctx context.Context, actorID, severity, title string) (IncidentRow, bool, error) {
	var created bool
	row := s.Pool.QueryRow(ctx, `INSERT INTO incidents (actor_id, severity, title, opened_at, updated_at)
		VALUES ($1::uuid, $2, $3, now(), now())
		ON CONFLICT (actor_id) DO UPDATE SET severity = EXCLUDED.severity, title = EXCLUDED.title, updated_at = now()
		RETURNING `+incidentCols+`, (xmax = 0)`, actorID, severity, title)
	var i IncidentRow
	err := row.Scan(&i.IncidentID, &i.ActorID, &i.Severity, &i.Status, &i.Title, &i.Summary, &i.SummarySrc, &i.OpenedAt,
		&i.UpdatedAt, &i.NotifiedAt, &i.NotifiedSeverity, &created)
	return i, created, err
}

func (s *Store) MarkNotified(ctx context.Context, incidentID, severity string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET notified_at = now(), notified_severity = $2 WHERE incident_id::text = $1`,
		incidentID, severity)
	return err
}

func (s *Store) SetIncidentSummary(ctx context.Context, incidentID, summary, src string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET summary = $2, summary_src = $3 WHERE incident_id::text = $1`, incidentID, summary, src)
	return err
}

func (s *Store) SetIncidentStatus(ctx context.Context, incidentID, status string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE incidents SET status = $2, updated_at = now() WHERE incident_id::text = $1`, incidentID, status)
	return err
}

func (s *Store) ListIncidents(ctx context.Context, status, severity string, limit int) ([]IncidentRow, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.Pool.Query(ctx, `SELECT `+incidentCols+` FROM incidents WHERE actor_id IS NOT NULL
		AND ($1 = '' OR status = $1) AND ($2 = '' OR severity = $2) ORDER BY updated_at DESC LIMIT $3`, status, severity, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IncidentRow
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

type Note struct {
	Author string
	Body   string
	TS     time.Time
}

func (s *Store) AddNote(ctx context.Context, incidentID, author, body string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO incident_notes (incident_id, author, body) VALUES ($1::uuid, $2::uuid, $3)`,
		incidentID, author, body)
	return err
}

func (s *Store) Notes(ctx context.Context, incidentID string) ([]Note, error) {
	rows, err := s.Pool.Query(ctx, `SELECT COALESCE(u.email, 'system'), n.body, n.ts FROM incident_notes n
		LEFT JOIN users u ON u.user_id = n.author WHERE n.incident_id::text = $1 ORDER BY n.ts`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.Author, &n.Body, &n.TS); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---------- response actions → policy (09, lab only) ----------

type ActionRow struct {
	ActionID    int64
	Action      string
	Target      string
	Status      string
	RequestedBy string
	TS          time.Time
}

// ApplyAction writes the policy row decoys enforce and the audit row, in one transaction.
func (s *Store) ApplyAction(ctx context.Context, incidentID, action, target, userID string) (ActionRow, error) {
	var a ActionRow
	err := s.Tx(ctx, func(tx pgx.Tx) error {
		var q string
		switch action {
		case "block_ip":
			q = `INSERT INTO policy (kind, value, until) VALUES ('blocked_ip', $1, now() + interval '24 hours')
				ON CONFLICT (kind, value) DO UPDATE SET until = EXCLUDED.until`
		case "unblock_ip":
			q = `DELETE FROM policy WHERE kind = 'blocked_ip' AND value = $1`
		case "kill_session":
			q = `INSERT INTO policy (kind, value, until) VALUES ('killed_session', $1, now() + interval '1 hour')
				ON CONFLICT (kind, value) DO NOTHING`
		case "rotate_token":
			if _, err := tx.Exec(ctx, `UPDATE honeytokens SET burned = true WHERE token_id = $1`, target); err != nil {
				return err
			}
			q = `INSERT INTO policy (kind, value) VALUES ('burned_token', $1) ON CONFLICT (kind, value) DO NOTHING`
		}
		if _, err := tx.Exec(ctx, q, target); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `INSERT INTO response_actions (incident_id, action, target, requested_by, status)
			VALUES ($1::uuid, $2, $3, $4::uuid, 'applied') RETURNING action_id, action, target, status, COALESCE(requested_by::text, ''), ts`,
			incidentID, action, target, userID).Scan(&a.ActionID, &a.Action, &a.Target, &a.Status, &a.RequestedBy, &a.TS)
	})
	return a, err
}

func (s *Store) Actions(ctx context.Context, incidentID string) ([]ActionRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT a.action_id, a.action, a.target, a.status, COALESCE(u.email, ''), a.ts
		FROM response_actions a LEFT JOIN users u ON u.user_id = a.requested_by WHERE a.incident_id::text = $1 ORDER BY a.ts`, incidentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionRow
	for rows.Next() {
		var a ActionRow
		if err := rows.Scan(&a.ActionID, &a.Action, &a.Target, &a.Status, &a.RequestedBy, &a.TS); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---------- sensors, allowlist, IOCs, stats ----------

type SensorRow struct {
	SensorID, Service, Version string
	LastSeen                   *time.Time
	Status                     string
}

func (s *Store) Sensors(ctx context.Context) ([]SensorRow, error) {
	rows, err := s.Pool.Query(ctx, `SELECT sensor_id, service, COALESCE(version, ''), last_seen,
		CASE WHEN last_seen IS NULL THEN 'unknown' WHEN last_seen < now() - interval '90 seconds' THEN 'silent' ELSE 'ok' END
		FROM sensors ORDER BY sensor_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SensorRow
	for rows.Next() {
		var r SensorRow
		if err := rows.Scan(&r.SensorID, &r.Service, &r.Version, &r.LastSeen, &r.Status); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Allowlisted reports whether ip falls in an allowlist CIDR.
func (s *Store) Allowlisted(ctx context.Context, ip string) bool {
	var ok bool
	_ = s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM allowlist WHERE $1::inet <<= cidr)`, ip).Scan(&ok)
	return ok
}

func (s *Store) AddAllowlist(ctx context.Context, cidr, reason, userID string) error {
	_, err := s.Pool.Exec(ctx, `INSERT INTO allowlist (cidr, reason, added_by) VALUES ($1::cidr, $2, $3::uuid)
		ON CONFLICT (cidr) DO UPDATE SET reason = EXCLUDED.reason`, cidr, reason, userID)
	return err
}

type IOC struct{ Kind, Value string }

func (s *Store) IOCs(ctx context.Context, actorID string) ([]IOC, error) {
	rows, err := s.Pool.Query(ctx, `SELECT kind, value FROM iocs WHERE actor_id::text = $1 AND value IS NOT NULL
		UNION SELECT 'token', token_id FROM token_hits WHERE actor_id::text = $1 AND kind = 'used' ORDER BY 1, 2`, actorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IOC
	for rows.Next() {
		var i IOC
		if err := rows.Scan(&i.Kind, &i.Value); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

type Overview struct {
	Events, ActiveActors, NewActors, TokenHits, SensorsOK, SensorsTotal int
	OpenIncidents                                                       map[string]int
}

func (s *Store) Overview(ctx context.Context, since time.Time) (Overview, error) {
	o := Overview{OpenIncidents: map[string]int{"low": 0, "medium": 0, "high": 0, "critical": 0}}
	err := s.Pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM events WHERE ts >= $1),
		(SELECT count(*) FROM actors WHERE merged_into IS NULL AND last_seen >= $1),
		(SELECT count(*) FROM actors WHERE merged_into IS NULL AND first_seen >= $1),
		(SELECT count(*) FROM token_hits WHERE ts >= $1),
		(SELECT count(*) FROM sensors WHERE last_seen >= now() - interval '90 seconds'),
		(SELECT count(*) FROM sensors)`, since).
		Scan(&o.Events, &o.ActiveActors, &o.NewActors, &o.TokenHits, &o.SensorsOK, &o.SensorsTotal)
	if err != nil {
		return o, err
	}
	rows, err := s.Pool.Query(ctx, `SELECT severity, count(*) FROM incidents WHERE status <> 'closed' AND actor_id IS NOT NULL GROUP BY severity`)
	if err != nil {
		return o, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var n int
		if err := rows.Scan(&sev, &n); err != nil {
			return o, err
		}
		o.OpenIncidents[sev] = n
	}
	return o, rows.Err()
}

type Point struct {
	T time.Time `json:"t"`
	V int       `json:"v"`
}

// Timeseries counts events or findings per step bucket since t.
func (s *Store) Timeseries(ctx context.Context, metric string, since time.Time, step time.Duration) ([]Point, error) {
	table := "events"
	if metric == "findings" {
		table = "findings"
	}
	rows, err := s.Pool.Query(ctx, `SELECT to_timestamp(floor(extract(epoch FROM ts) / $2) * $2) AS b, count(*)
		FROM `+table+` WHERE ts >= $1 GROUP BY b ORDER BY b`, since, step.Seconds())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	got := map[int64]int{}
	for rows.Next() {
		var t time.Time
		var n int
		if err := rows.Scan(&t, &n); err != nil {
			return nil, err
		}
		got[t.Unix()] = n
	}
	var out []Point
	start := since.Truncate(step)
	for t := start; !t.After(time.Now()); t = t.Add(step) {
		out = append(out, Point{T: t.UTC(), V: got[t.Unix()]})
	}
	return out, rows.Err()
}


// SaveNarration stores a generated or templated narrative (09 Readable message text).
func (s *Store) SaveNarration(ctx context.Context, kind, refID, factsHash, headline, body string, bullets []string, source string, model *string) error {
	b, err := json.Marshal(bullets)
	if err != nil {
		b = []byte("[]")
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO narrations (kind, ref_id, facts_hash, headline, body, bullets, source, model, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now())
		ON CONFLICT (kind, ref_id, facts_hash) DO UPDATE SET
			headline = EXCLUDED.headline,
			body = EXCLUDED.body,
			bullets = EXCLUDED.bullets,
			source = EXCLUDED.source,
			model = EXCLUDED.model`,
		kind, refID, factsHash, headline, body, b, source, model)
	return err
}
