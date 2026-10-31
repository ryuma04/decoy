// Package dto holds the analyst-API JSON shapes from 04 §B that both the engine (SSE) and the API return.
// snake_case, nullable fields present as null, slices never null.
package dto

import (
	"context"
	"encoding/json"
	"time"

	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
	"github.com/ryuma04/decoy/backend/internal/store"
)

type ActorSummary struct {
	ActorID           string    `json:"actor_id"`
	Label             string    `json:"label"`
	FirstSeen         time.Time `json:"first_seen"`
	LastSeen          time.Time `json:"last_seen"`
	RiskScore         int       `json:"risk_score"`
	Severity          string    `json:"severity"`
	Confidence        float64   `json:"confidence"`
	BehaviourClass    string    `json:"behaviour_class"`
	Services          []string  `json:"services"`
	SessionCount      int       `json:"session_count"`
	IPs               []string  `json:"ips"`
	TopTechniques     []string  `json:"top_techniques"`
	TokenHits         int       `json:"token_hits"`
	MazeDepth         int       `json:"maze_depth"`
	KillChainStage    string    `json:"kill_chain_stage"`
	TouchedProduction bool      `json:"touched_production"`
	Tools             []string  `json:"tools"`
}

type ToolTag struct {
	Tool      string `json:"tool"`
	FirstSeen string `json:"first_seen"`
	EventID   string `json:"event_id"`
	Evidence  string `json:"evidence"`
}

// Stats is the store dependency of the builders.
type Stats interface {
	ActorStats(ctx context.Context, actorID string) (store.ActorStats, error)
}

func Summary(ctx context.Context, st Stats, a store.Actor) (ActorSummary, error) {
	s, err := st.ActorStats(ctx, a.ActorID)
	if err != nil {
		return ActorSummary{}, err
	}
	stage := s.LastStage
	if stage == "" {
		stage = "recon"
	}
	tools := []string{}
	var tags []ToolTag
	_ = json.Unmarshal(a.Tools, &tags)
	for _, t := range tags {
		tools = append(tools, t.Tool)
	}
	return ActorSummary{
		ActorID: a.ActorID, Label: a.Label, FirstSeen: a.FirstSeen.UTC(), LastSeen: a.LastSeen.UTC(),
		RiskScore: a.RiskScore, Severity: a.Severity, Confidence: round2(a.Confidence), BehaviourClass: a.BehaviourClass,
		Services: nz(s.Services), SessionCount: s.SessionCount, IPs: nz(s.IPs), TopTechniques: nz(s.TopTechniques),
		TokenHits: s.TokenHits, MazeDepth: s.MazeDepth, KillChainStage: stage, TouchedProduction: a.TouchedProduction,
		Tools: tools,
	}, nil
}

type FindingML struct {
	Label       string   `json:"label"`
	Confidence  float64  `json:"confidence"`
	Risk        float64  `json:"risk"`
	TopFeatures []string `json:"top_features"`
	WasEncoded  bool     `json:"was_encoded"`
}

type FindingEvidence struct {
	EventIDs []string   `json:"event_ids"`
	Matched  string     `json:"matched,omitempty"`
	ML       *FindingML `json:"ml,omitempty"`
}

type Finding struct {
	FindingID     int64           `json:"finding_id"`
	ActorID       string          `json:"actor_id"`
	SessionID     string          `json:"session_id"`
	RuleID        string          `json:"rule_id"`
	Title         string          `json:"title"`
	Tactic        *string         `json:"tactic"`
	Technique     *string         `json:"technique"`
	TechniqueName *string         `json:"technique_name"`
	Stage         string          `json:"stage"`
	Points        int             `json:"points"`
	Confidence    float64         `json:"confidence"`
	Source        string          `json:"source"`
	Evidence      FindingEvidence `json:"evidence"`
	TS            time.Time       `json:"ts"`
}

func FromFinding(f store.FindingRow) Finding {
	out := Finding{FindingID: f.FindingID, ActorID: f.ActorID, RuleID: f.RuleID, Title: f.Title, Tactic: f.Tactic,
		Technique: f.Technique, Stage: f.Stage, Points: f.Points, Confidence: round2(f.Confidence), Source: f.Source,
		TS: f.TS.UTC(), Evidence: FindingEvidence{EventIDs: []string{}}}
	if f.SessionID != nil {
		out.SessionID = *f.SessionID
	}
	if f.Technique != nil {
		if t, ok := mitre.Lookup(*f.Technique); ok {
			out.TechniqueName = &t.Name
			if out.Tactic == nil {
				out.Tactic = &t.TacticID
			}
		}
	}
	_ = json.Unmarshal(f.Evidence, &out.Evidence)
	if out.Evidence.EventIDs == nil {
		out.Evidence.EventIDs = []string{}
	}
	return out
}

type LinkReason struct {
	Signal         string  `json:"signal"`
	Weight         float64 `json:"weight"`
	MatchedSession *string `json:"matched_session"`
	Value          string  `json:"value"`
}

type Session struct {
	SessionID       string       `json:"session_id"`
	SensorSessionID string       `json:"sensor_session_id"`
	ActorID         string       `json:"actor_id"`
	Service         string       `json:"service"`
	SensorID        string       `json:"sensor_id"`
	SrcIP           string       `json:"src_ip"`
	StartedAt       time.Time    `json:"started_at"`
	EndedAt         *time.Time   `json:"ended_at"`
	EventCount      int          `json:"event_count"`
	LinkScore       *float64     `json:"link_score"`
	LinkReasons     []LinkReason `json:"link_reasons"`
}

func FromSession(s store.SessionRow) Session {
	out := Session{SessionID: s.SessionID, SensorSessionID: s.SensorSessionID, Service: s.Service, SensorID: s.SensorID,
		SrcIP: s.SrcIP, StartedAt: s.StartedAt.UTC(), EndedAt: s.EndedAt, EventCount: s.EventCount, LinkScore: s.LinkScore,
		LinkReasons: []LinkReason{}}
	if s.ActorID != nil {
		out.ActorID = *s.ActorID
	}
	_ = json.Unmarshal(s.LinkReasons, &out.LinkReasons)
	if out.LinkReasons == nil {
		out.LinkReasons = []LinkReason{}
	}
	return out
}

func nz(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

func round2(v float64) float64 { return float64(int(v*100+0.5)) / 100 }
