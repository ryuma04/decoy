package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
	"github.com/ryuma04/decoy/backend/internal/intel/risk"
	"github.com/ryuma04/decoy/backend/internal/maze"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// DBRoutes registers the endpoints that read the intel tables (04 §B). Needs s.DB.
func (s *Server) DBRoutes(mux *http.ServeMux) {
	authed := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.Require(false, h) }
	admin := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.Require(true, h) }
	mux.HandleFunc("GET /v1/actors", authed(s.listActors))
	mux.HandleFunc("GET /v1/actors/{id}", authed(s.getActor))
	mux.HandleFunc("GET /v1/actors/{id}/timeline", authed(s.actorTimeline))
	mux.HandleFunc("GET /v1/actors/{id}/external", authed(s.actorExternal))
	mux.HandleFunc("GET /v1/sessions/{id}", authed(s.getSession))
	mux.HandleFunc("GET /v1/stats/overview", authed(s.overview))
	mux.HandleFunc("GET /v1/stats/timeseries", authed(s.timeseries))
	mux.HandleFunc("GET /v1/stats/techniques", authed(s.techniques))
	mux.HandleFunc("GET /v1/honeytokens", authed(s.honeytokens))
	mux.HandleFunc("GET /v1/sensors", authed(s.sensors))
	mux.HandleFunc("GET /v1/scorer", authed(s.scorer))
	mux.HandleFunc("GET /v1/maze", authed(s.mazeDefinition))
	mux.HandleFunc("GET /v1/actors/{id}/maze", authed(s.actorMaze))
	mux.HandleFunc("POST /v1/scorer/reset", admin(s.scorerReset))
}

func (s *Server) actor(w http.ResponseWriter, r *http.Request) (store.Actor, bool) {
	id := r.PathValue("id")
	var a store.Actor
	var err error
	if strings.HasPrefix(id, "ACT-") {
		a, err = s.DB.ActorByLabel(r.Context(), id)
	} else {
		a, err = s.DB.Actor(r.Context(), id)
	}
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "actor not found")
		return a, false
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return a, false
	}
	if a.MergedInto != nil { // follow merges so old links keep working
		return s.actorByID(w, r, *a.MergedInto)
	}
	return a, true
}

func (s *Server) actorByID(w http.ResponseWriter, r *http.Request, id string) (store.Actor, bool) {
	a, err := s.DB.Actor(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "actor not found")
		return a, false
	}
	return a, true
}

func (s *Server) listActors(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ActorFilter{Severity: q.Get("severity"), BehaviourClass: q.Get("behaviour_class"), SortByRisk: q.Get("sort") != "last_seen"}
	f.Limit, _ = strconv.Atoi(q.Get("limit"))
	f.Offset, _ = strconv.Atoi(q.Get("cursor"))
	if since, err := parseTime(q.Get("since")); err == nil {
		f.Since = since
	}
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	actors, err := s.DB.ListActors(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	next := ""
	if len(actors) > f.Limit {
		actors = actors[:f.Limit]
		next = strconv.Itoa(f.Offset + f.Limit)
	}
	items := make([]dto.ActorSummary, 0, len(actors))
	for _, a := range actors {
		sum, err := dto.Summary(r.Context(), s.DB, a)
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
			return
		}
		items = append(items, sum)
	}
	writeJSON(w, http.StatusOK, newList(items, next))
}

type behaviourDetail struct {
	Class    string             `json:"class"`
	Scores   map[string]float64 `json:"scores"`
	Source   string             `json:"source"`
	Features map[string]float64 `json:"features"`
}

type fingerprintOut struct {
	Kind       string   `json:"kind"`
	Value      string   `json:"value"`
	SessionIDs []string `json:"session_ids"`
}

type actorDetail struct {
	dto.ActorSummary
	RiskBreakdown risk.Breakdown   `json:"risk_breakdown"`
	ToolTags      []dto.ToolTag    `json:"tool_tags"`
	External      map[string]any   `json:"external"`
	Sessions      []dto.Session    `json:"sessions"`
	Fingerprints  []fingerprintOut `json:"fingerprints"`
	Findings      []dto.Finding    `json:"findings"`
	Behaviour     behaviourDetail  `json:"behaviour"`
	Interest      map[string]int   `json:"interest"`
	IncidentID    *string          `json:"incident_id"`
	Narrative     *json.RawMessage `json:"narrative"`
}

var featureNames = []string{"median_gap_ms", "gap_cv", "edit_rate", "paste_rate", "output_dependence", "services_visited",
	"breadcrumbs_followed", "param_mutation_retries", "commands"}

func (s *Server) getActor(w http.ResponseWriter, r *http.Request) {
	a, ok := s.actor(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	sum, err := dto.Summary(ctx, s.DB, a)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	sessions, _ := s.DB.SessionsOfActor(ctx, a.ActorID)
	findings, _ := s.DB.FindingsOfActor(ctx, a.ActorID)
	d := actorDetail{ActorSummary: sum, ToolTags: []dto.ToolTag{}, Sessions: []dto.Session{}, Fingerprints: []fingerprintOut{},
		Findings: []dto.Finding{}, Interest: map[string]int{"cloud": 0, "k8s": 0, "db": 0, "ci": 0},
		External: map[string]any{"firewall_denies": 0, "real_auth_failed": 0, "real_auth_success": 0, "systems": []string{}}}
	_ = json.Unmarshal(a.Tools, &d.ToolTags)
	if d.ToolTags == nil {
		d.ToolTags = []dto.ToolTag{}
	}
	for k, v := range a.Interest {
		d.Interest[k] = v
	}
	if len(a.RiskBreakdown) > 0 {
		_ = json.Unmarshal(a.RiskBreakdown, &d.RiskBreakdown)
	}
	if d.RiskBreakdown.StageScores == nil {
		d.RiskBreakdown = risk.Score(risk.StageScores(nil, 1), risk.Initial(), risk.Facts{})
	}
	ids := []string{}
	for _, se := range sessions {
		d.Sessions = append(d.Sessions, dto.FromSession(se))
		ids = append(ids, se.SessionID)
	}
	for _, f := range findings {
		d.Findings = append(d.Findings, dto.FromFinding(f))
	}
	if fps, err := s.DB.FingerprintsOf(ctx, ids); err == nil {
		byKV := map[string]*fingerprintOut{}
		var order []string
		for _, f := range fps {
			if f.Kind == "cmd_shingles" {
				continue
			}
			k := f.Kind + "\x00" + f.Value
			if byKV[k] == nil {
				byKV[k] = &fingerprintOut{Kind: f.Kind, Value: f.Value, SessionIDs: []string{}}
				order = append(order, k)
			}
			byKV[k].SessionIDs = append(byKV[k].SessionIDs, f.SessionID)
		}
		for _, k := range order {
			d.Fingerprints = append(d.Fingerprints, *byKV[k])
		}
	}
	// Behaviour features are not computed yet (docs/17 row 5): report "unknown" with zeroed features.
	d.Behaviour = behaviourDetail{Class: a.BehaviourClass, Scores: map[string]float64{}, Source: "rules", Features: map[string]float64{}}
	for _, n := range featureNames {
		d.Behaviour.Features[n] = 0
	}
	d.Behaviour.Features["services_visited"] = float64(len(sum.Services))
	if inc, err := s.DB.IncidentOfActor(ctx, a.ActorID); err == nil {
		d.IncidentID = &inc.IncidentID
	}
	writeJSON(w, http.StatusOK, d)
}

type timelineItem struct {
	Kind    string       `json:"kind"`
	TS      time.Time    `json:"ts"`
	Event   *Event       `json:"event,omitempty"`
	Finding *dto.Finding `json:"finding,omitempty"`
}

func (s *Server) actorTimeline(w http.ResponseWriter, r *http.Request) {
	a, ok := s.actor(w, r)
	if !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	evs, _, err := s.DB.ListEvents(r.Context(), store.EventFilter{ActorID: a.ActorID, Limit: 200})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	findings, _ := s.DB.FindingsOfActor(r.Context(), a.ActorID)
	items := []timelineItem{}
	for _, ev := range evs {
		e := toEvent(ev, false)
		items = append(items, timelineItem{Kind: "event", TS: e.TS, Event: &e})
	}
	for _, f := range findings {
		fd := dto.FromFinding(f)
		items = append(items, timelineItem{Kind: "finding", TS: fd.TS, Finding: &fd})
	}
	sort.SliceStable(items, func(i, j int) bool { return items[i].TS.Before(items[j].TS) })
	if len(items) > limit {
		items = items[len(items)-limit:]
	}
	writeJSON(w, http.StatusOK, newList(items, ""))
}

func (s *Server) actorExternal(w http.ResponseWriter, r *http.Request) {
	a, ok := s.actor(w, r)
	if !ok {
		return
	}
	evs, _, err := s.DB.ListEvents(r.Context(), store.EventFilter{ActorID: a.ActorID, Limit: 200})
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	out := []Event{}
	for _, ev := range evs {
		if ev.Origin == "production" {
			out = append(out, toEvent(ev, false))
		}
	}
	writeJSON(w, http.StatusOK, newList(out, ""))
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	se, err := s.DB.Session(r.Context(), r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "session not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	evs, _, _ := s.DB.ListEvents(r.Context(), store.EventFilter{SessionID: se.SessionID, Limit: 200})
	items := make([]Event, len(evs))
	for i, ev := range evs {
		items[i] = toEvent(ev, false)
	}
	writeJSON(w, http.StatusOK, map[string]any{"session": dto.FromSession(se), "events": items})
}

func windowOf(r *http.Request, def time.Duration) (time.Duration, string) {
	q := r.URL.Query().Get("window")
	if d, err := time.ParseDuration(q); err == nil && d > 0 && d <= 30*24*time.Hour {
		return d, q
	}
	return def, strings.TrimSuffix(strings.TrimSuffix(def.String(), "0s"), "0m")
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) {
	win, label := windowOf(r, time.Hour)
	o, err := s.DB.Overview(r.Context(), time.Now().Add(-win))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	var top *dto.ActorSummary
	if as, err := s.DB.ListActors(r.Context(), store.ActorFilter{SortByRisk: true, Limit: 1}); err == nil && len(as) > 0 {
		if sum, err := dto.Summary(r.Context(), s.DB, as[0]); err == nil {
			top = &sum
		}
	}
	mlOn, narration := false, "template"
	if s.ML != nil {
		ok, n := s.ML.Health(r.Context())
		mlOn = ok
		if n == "llm" {
			narration = "llm"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"window": label, "events": o.Events, "active_actors": o.ActiveActors, "new_actors": o.NewActors,
		"open_incidents": o.OpenIncidents, "token_hits": o.TokenHits, "sensors_ok": o.SensorsOK,
		"sensors_total": o.SensorsTotal, "top_actor": top, "ml_input": mlOn, "narration": narration,
	})
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	win, _ := windowOf(r, time.Hour)
	step, err := time.ParseDuration(r.URL.Query().Get("step"))
	if err != nil || step < time.Minute {
		step = time.Minute
	}
	if win/step > 1440 {
		step = win / 1440
	}
	pts, err := s.DB.Timeseries(r.Context(), r.URL.Query().Get("metric"), time.Now().Add(-win), step)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	if pts == nil {
		pts = []store.Point{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"points": pts})
}

func (s *Server) techniques(w http.ResponseWriter, r *http.Request) {
	win, _ := windowOf(r, 24*time.Hour)
	counts, err := s.DB.TechniqueCounts(r.Context(), time.Now().Add(-win))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	type item struct {
		Technique string `json:"technique"`
		Name      string `json:"name"`
		Tactic    string `json:"tactic"`
		Count     int    `json:"count"`
	}
	items := []item{}
	for id, n := range counts {
		t, _ := mitre.Lookup(id)
		items = append(items, item{Technique: id, Name: t.Name, Tactic: t.Tactic, Count: n})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Count > items[j].Count })
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) honeytokens(w http.ResponseWriter, r *http.Request) {
	hs, err := s.DB.Honeytokens(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	type out struct {
		TokenID     string     `json:"token_id"`
		Kind        string     `json:"kind"`
		PlantedAt   string     `json:"planted_at"`
		Sensitivity int        `json:"sensitivity"`
		Burned      bool       `json:"burned"`
		HitsSeen    int        `json:"hits_seen"`
		HitsUsed    int        `json:"hits_used"`
		LastHit     *time.Time `json:"last_hit"`
	}
	items := []out{}
	for _, h := range hs {
		items = append(items, out{h.TokenID, h.Kind, h.PlantedAt, h.Sensitivity, h.Burned, h.HitsSeen, h.HitsUsed, h.LastHit})
	}
	writeJSON(w, http.StatusOK, newList(items, ""))
}

func (s *Server) sensors(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Sensors(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	type out struct {
		SensorID string     `json:"sensor_id"`
		Service  string     `json:"service"`
		Version  string     `json:"version"`
		LastSeen *time.Time `json:"last_seen"`
		Status   string     `json:"status"`
	}
	items := []out{}
	for _, x := range rows {
		items = append(items, out{x.SensorID, x.Service, x.Version, x.LastSeen, x.Status})
	}
	writeJSON(w, http.StatusOK, newList(items, ""))
}

func (s *Server) scorerState(r *http.Request) (map[string]any, error) {
	wts, err := s.DB.ActiveWeights(r.Context())
	if err != nil {
		return nil, err
	}
	conf, fp, err := s.DB.FeedbackCounts(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{"version": wts.Version, "weights": wts.Weights, "bias": wts.Bias, "learning_rate": wts.LearningRate,
		"learning_enabled": s.ScorerLearn, "feedback_confirmed": conf, "feedback_false_positive": fp,
		"updated_at": wts.CreatedAt.UTC()}, nil
}

func (s *Server) scorer(w http.ResponseWriter, r *http.Request) {
	st, err := s.scorerState(r)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) scorerReset(w http.ResponseWriter, r *http.Request) {
	if err := s.DB.ResetWeights(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	s.scorer(w, r)
}

func (s *Server) mazeDefinition(w http.ResponseWriter, _ *http.Request) {
	if s.MazeGraph == nil {
		writeError(w, http.StatusServiceUnavailable, "maze_unavailable", "maze graph not loaded")
		return
	}
	writeJSON(w, http.StatusOK, s.MazeGraph.Out(nil, ""))
}

func (s *Server) actorMaze(w http.ResponseWriter, r *http.Request) {
	a, ok := s.actor(w, r)
	if !ok {
		return
	}
	if s.MazeGraph == nil {
		writeError(w, http.StatusServiceUnavailable, "maze_unavailable", "maze graph not loaded")
		return
	}
	nodes, unlocks, err := s.DB.MazeNodes(r.Context(), a.ActorID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	writeJSON(w, http.StatusOK, s.MazeGraph.Out(&maze.State{Nodes: nodes, Unlocks: unlocks}, a.ActorID))
}
