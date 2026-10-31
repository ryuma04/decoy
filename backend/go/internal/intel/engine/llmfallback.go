package engine

import (
	"context"
	"encoding/json"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
	"github.com/ryuma04/decoy/backend/internal/mlclient"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// LLM fallback (07 §4.3): when no rule matches a shell command or k8s call, ask the LLM to map it to one technique
// from our allow-list. The finding is advisory: source "llm", 5 points, never an override, one per actor per technique.
const (
	llmPoints        = 5
	llmMinConfidence = 0.6
	llmParallel      = 4
	llmCacheMax      = 5000
)

var (
	llmSem    = make(chan struct{}, llmParallel)
	llmMu     sync.Mutex
	llmCache  = map[string]*mlclient.MapTechniqueResult{} // normalised action -> answer (nil technique cached too)
	llmDigits = regexp.MustCompile(`\d+`)
	// Navigation and typos never go to the LLM.
	llmTrivial = regexp.MustCompile(`^(cd(\s+\S+)?|pwd|clear|exit|logout|help|history|ls(\s+[\w./~-]+)?)$`)
)

var tacticStage = map[string]string{
	"TA0043": "recon", "TA0001": "access",
	"TA0008": "lateral", "TA0010": "lateral", "TA0011": "lateral", "TA0040": "lateral",
}

func llmAction(ev store.StoredEvent, d map[string]any) string {
	str := func(k string) string { v, _ := d[k].(string); return v }
	switch ev.Type {
	case "shell.command":
		raw := strings.TrimSpace(str("raw"))
		if raw == "" || len(raw) > 500 || llmTrivial.MatchString(raw) {
			return ""
		}
		return raw
	case "k8s.api_call":
		return strings.TrimSpace(strings.Join([]string{str("verb"), str("resource"), str("namespace"), str("path")}, " "))
	}
	return ""
}

// llmFallback runs in the background so the event pipeline never waits for the LLM.
func (e *Engine) llmFallback(ev store.StoredEvent, actorID, action string) {
	if e.ML == nil || action == "" {
		return
	}
	key := ev.Service + "|" + ev.Type + "|" + llmDigits.ReplaceAllString(strings.Join(strings.Fields(action), " "), "0")
	llmMu.Lock()
	cached, hit := llmCache[key]
	llmMu.Unlock()
	select {
	case llmSem <- struct{}{}:
	default:
		if !hit {
			return // busy: skip rather than queue; rules already ran
		}
	}
	go func() {
		defer func() { <-llmSem }()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res := cached
		if res == nil {
			allowed := []mlclient.AllowedTechnique{}
			for _, t := range mitre.All() {
				allowed = append(allowed, mlclient.AllowedTechnique{ID: t.ID, Name: t.Name})
			}
			r, err := e.ML.MapTechnique(ctx, mlclient.MapTechniqueRequest{Service: ev.Service, EventType: ev.Type,
				Action: action, Allowed: allowed})
			if err != nil {
				slog.Debug("llm fallback skipped", "err", err)
				return
			}
			res = &r
			llmMu.Lock()
			if len(llmCache) >= llmCacheMax {
				llmCache = map[string]*mlclient.MapTechniqueResult{}
			}
			llmCache[key] = res
			llmMu.Unlock()
		}
		if res.Technique == nil || res.Confidence < llmMinConfidence {
			return
		}
		t, ok := mitre.Lookup(*res.Technique)
		if !ok {
			return
		}
		stage := tacticStage[t.TacticID]
		if stage == "" {
			stage = "post_access"
		}
		tech, tactic := t.ID, t.TacticID
		evidence, _ := json.Marshal(dto.FindingEvidence{EventIDs: []string{ev.EventID}, Matched: action,
			ML: &dto.FindingML{Label: "llm:" + res.Model, Confidence: res.Confidence, Risk: res.Confidence, TopFeatures: []string{res.Reason}}})
		sid := ev.SessionID
		f, added, err := e.Store.AddFinding(ctx, store.FindingRow{SessionID: &sid, ActorID: actorID, RuleID: "llm_" + t.ID,
			Title: t.Name + " (LLM-mapped)", Tactic: &tactic, Technique: &tech, Points: llmPoints, Confidence: res.Confidence,
			Stage: stage, Source: "llm", Evidence: evidence, TS: ev.TS})
		if err != nil || !added {
			return
		}
		slog.Info("llm fallback finding", "actor", actorID, "technique", t.ID, "confidence", res.Confidence)
		e.Bus.Publish(bus.TopicFinding, dto.FromFinding(f))
		if err := e.Rescore(ctx, actorID); err != nil {
			slog.Warn("rescore after llm finding", "err", err)
		}
	}()
}
