// Package engine runs the intelligence pipeline per stored event (07):
// fingerprint → honeytoken → correlate → rules (+ input risk) → findings → risk → publish.
// Events are processed sequentially per session shard, so correlation and scoring have no races.
package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"strings"
	"sync"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/dto"
	"github.com/ryuma04/decoy/backend/internal/intel/behaviour"
	"github.com/ryuma04/decoy/backend/internal/intel/correlate"
	"github.com/ryuma04/decoy/backend/internal/intel/inputrisk"
	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
	"github.com/ryuma04/decoy/backend/internal/intel/risk"
	"github.com/ryuma04/decoy/backend/internal/intel/rules"
	"github.com/ryuma04/decoy/backend/internal/maze"
	"github.com/ryuma04/decoy/backend/internal/mlclient"
	"github.com/ryuma04/decoy/backend/internal/store"
)

const workers = 4

// Features supplies rolling per-session / per-actor features (07 §3, §7) to session- and actor-scope rules.
// Not built yet (docs/17 row 5); with nil, only event-scope rules fire.
type Features interface {
	Observe(ev store.StoredEvent)
	Session(sessionID string) map[string]float64
	Actor(actorID string) map[string]float64
}

type Engine struct {
	Store    *store.Store
	Bus      bus.Bus
	Rules    *rules.Set
	ML       *mlclient.Client
	Features Features
	Maze     *maze.Controller

	mu       sync.Mutex
	commands map[string][]string // session id -> recent commands (for cmd_shingles)
	scan     *scanDetector
}

// Run consumes events from the bus until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	e.commands = map[string][]string{}
	e.scan = newScanDetector()
	ch, stop := e.Bus.Subscribe(10000, bus.TopicEvent)
	defer stop()
	shards := make([]chan store.StoredEvent, workers)
	var wg sync.WaitGroup
	for i := range shards {
		shards[i] = make(chan store.StoredEvent, 2500)
		wg.Add(1)
		go func(in <-chan store.StoredEvent) {
			defer wg.Done()
			for ev := range in {
				e.safeProcess(ctx, ev)
			}
		}(shards[i])
	}
	defer func() {
		for _, s := range shards {
			close(s)
		}
		wg.Wait()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case m, ok := <-ch:
			if !ok {
				return
			}
			ev, ok := m.Value.(store.StoredEvent)
			if !ok || ev.Origin == "production" {
				continue // external telemetry is linked separately (07 §8), never creates actors
			}
			h := fnv.New32a()
			h.Write([]byte(ev.SessionID))
			shards[h.Sum32()%workers] <- ev
		}
	}
}

func (e *Engine) safeProcess(ctx context.Context, ev store.StoredEvent) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("intel panic", "event_id", ev.EventID, "panic", r)
		}
	}()
	if err := e.Process(ctx, ev); err != nil {
		slog.Error("intel failed", "event_id", ev.EventID, "err", err)
	}
}

// Process runs the pipeline for one event.
func (e *Engine) Process(ctx context.Context, ev store.StoredEvent) error {
	if e.Features != nil {
		e.Features.Observe(ev)
	}
	// 1. fingerprints (+ command shingles at 5, 10, 20 commands)
	fps := fingerprints(ev)
	if fp, ok := e.shingles(ev); ok {
		fps = append(fps, fp)
	}
	newFP, err := e.Store.AddFingerprints(ctx, fps)
	if err != nil {
		return fmt.Errorf("fingerprints: %w", err)
	}

	// 2. correlation: on a new session, or when a new fingerprint appears. The event's own actor_id was
	// captured at ingest, before correlation ran, so read the session's current actor.
	sess, err := e.Store.Session(ctx, ev.SessionID)
	if err != nil {
		return fmt.Errorf("session: %w", err)
	}
	actorID := deref(sess.ActorID)
	if ev.NewSession || actorID == "" || newFP > 0 {
		id, err := e.correlate(ctx, ev, actorID)
		if err != nil {
			return fmt.Errorf("correlate: %w", err)
		}
		actorID = id
	}
	if actorID == "" {
		return nil
	}
	_ = e.Store.TouchActor(ctx, actorID, ev.TS)
	if e.Features != nil && actorID != "" {
		if assoc, ok := e.Features.(interface{ Associate(sessionID, actorID string) }); ok {
			assoc.Associate(ev.SessionID, actorID)
		}
	}

	// 3. honeytoken hits
	data := map[string]any{}
	_ = json.Unmarshal(ev.Data, &data)
	tokenSens := 0
	for _, hit := range tokenHits(ev, data) {
		if err := e.Store.AddTokenHit(ctx, hit.token, ev.EventID, actorID, hit.kind, ev.TS); err != nil {
			slog.Warn("token hit", "err", err)
		}
		if hit.kind == "used" {
			tokenSens = max(tokenSens, e.Store.TokenSensitivity(ctx, hit.token))
		}
	}

	// 3b. a decoy applied a cognitive tactic (08 §Cognitive): keep it for the actor's tactics panel
	if ev.Type == "deception.tactic" {
		e.recordTactic(ctx, ev, actorID, data)
	}

	// 4. rules: event scope (+ input risk for web inputs, + injected payload as a shell command)
	var matches []hit
	in := rules.Input{Type: ev.Type, Data: data, TokenSens: tokenSens}
	matches = append(matches, plain(e.Rules.Evaluate("event", in))...)
	for _, val := range webInputs(ev, data) {
		g := inputrisk.Grade(ctx, e.ML, val.param, val.value, ev.Service, val.path, val.field)
		if g.Label == "normal" {
			continue
		}
		ir := rules.Input{Type: ev.Type, Data: map[string]any{"value": val.value},
			InputRisk: &rules.InputRisk{Label: g.Label, Risk: g.Risk, Source: g.Source}}
		ml := &dto.FindingML{Label: g.Label, Confidence: g.Risk, Risk: g.Risk, TopFeatures: g.TopFeatures, WasEncoded: g.WasEncoded}
		if ml.TopFeatures == nil {
			ml.TopFeatures = []string{}
		}
		for _, m := range e.Rules.Evaluate("event", ir) {
			matches = append(matches, hit{m: m, ml: ml})
		}
		if g.Payload != "" {
			argv0, _, _ := strings.Cut(g.Payload, " ")
			matches = append(matches, plain(e.Rules.Evaluate("event", rules.Input{Type: "shell.command",
				Data: map[string]any{"raw": g.Payload, "argv0": argv0}}))...)
		}
	}
	eventMatches := len(matches) // session / actor rules below match on every event; the LLM fallback looks at these only
	if e.Features != nil {
		matches = append(matches, plain(e.Rules.Evaluate("session", rules.Input{Features: e.Features.Session(ev.SessionID)}))...)
		matches = append(matches, plain(e.Rules.Evaluate("actor", rules.Input{Features: e.Features.Actor(actorID)}))...)
		actorFeat := e.Features.Actor(actorID)
		cmds := int(actorFeat["commands"])
		if cmds == 5 || cmds == 10 || cmds == 20 || cmds == 40 {
			res := behaviour.Classify(actorFeat)
			if err := e.Store.UpdateActorBehaviour(ctx, actorID, res.Class, res); err != nil {
				slog.Warn("update actor behaviour", "err", err)
			}
		}
	}

	// 4b. adaptive maze (08): interest, visited nodes, maybe one unlock
	if e.Maze != nil {
		if a, err := e.Store.Actor(ctx, actorID); err == nil {
			if err := e.Maze.Observe(ctx, actorID, ev, a.Interest); err != nil {
				slog.Warn("maze", "err", err)
			}
		}
	}

	// 5. port sweep across decoys (derived scan.detected)
	if ports, ok := e.scan.observe(ev); ok {
		matches = append(matches, plain(e.Rules.Evaluate("event", rules.Input{Type: "scan.detected",
			Data: map[string]any{"ports": ports, "window_s": 60}}))...)
	}

	// 5b. nothing matched a command / k8s call: LLM fallback in the background (07 §4.3)
	if eventMatches == 0 {
		e.llmFallback(ev, actorID, llmAction(ev, data))
	}

	// 6. findings (once per actor per rule) → risk
	newFindings := 0
	for _, h := range matches {
		if f, ok, err := e.addFinding(ctx, ev, actorID, h.m, h.ml); err != nil {
			slog.Warn("finding", "rule", h.m.Rule.ID, "err", err)
		} else if ok {
			newFindings++
			e.Bus.Publish(bus.TopicFinding, dto.FromFinding(f))
		}
	}
	if newFindings > 0 || tokenSens > 0 || ev.NewSession {
		return e.Rescore(ctx, actorID)
	}
	return nil
}

// correlate attaches the event's session to the best actor ≥ 0.60, merges others, or creates a new actor.
func (e *Engine) correlate(ctx context.Context, ev store.StoredEvent, current string) (string, error) {
	cands, err := e.Store.CandidateActors(ctx, ev.SessionID)
	if err != nil {
		return current, err
	}
	me, err := e.sessionSig(ctx, ev.SessionID)
	if err != nil {
		return current, err
	}
	var results []correlate.Result
	for _, a := range cands {
		if a == current {
			continue
		}
		sess, err := e.Store.SessionsOfActor(ctx, a)
		if err != nil {
			return current, err
		}
		sigs := make([]correlate.Session, 0, len(sess))
		for _, s := range sess {
			sig, err := e.sessionSig(ctx, s.SessionID)
			if err != nil {
				return current, err
			}
			sigs = append(sigs, sig)
		}
		results = append(results, correlate.Score(me, a, sigs))
	}
	d := correlate.Decide(results)
	switch {
	case current == "" && d.AttachTo == "":
		a, err := e.Store.CreateActor(ctx, ev.TS)
		if err != nil {
			return "", err
		}
		if err := e.Store.AttachSession(ctx, ev.SessionID, a.ActorID, 1.0, []correlate.Reason{}); err != nil {
			return "", err
		}
		slog.Info("new actor", "actor", a.Label, "session", ev.SessionID)
		return a.ActorID, nil
	case current == "" && d.AttachTo != "":
		if err := e.Store.AttachSession(ctx, ev.SessionID, d.AttachTo, d.Best.Score, d.Best.Reasons); err != nil {
			return "", err
		}
		for _, m := range d.Merge {
			if err := e.merge(ctx, d.AttachTo, m); err != nil {
				return d.AttachTo, err
			}
		}
		return d.AttachTo, nil
	case current != "" && d.AttachTo != "":
		// Already attached to `current` and now also ≥ 0.60 with another actor: merge (older wins).
		into, from := e.older(ctx, current, d.AttachTo)
		if err := e.merge(ctx, into, from); err != nil {
			return current, err
		}
		for _, m := range d.Merge {
			if m != into {
				if err := e.merge(ctx, into, m); err != nil {
					return into, err
				}
			}
		}
		return into, nil
	}
	return current, nil
}

func (e *Engine) older(ctx context.Context, a, b string) (string, string) {
	x, err1 := e.Store.Actor(ctx, a)
	y, err2 := e.Store.Actor(ctx, b)
	if err1 != nil || err2 != nil || !y.FirstSeen.Before(x.FirstSeen) {
		return a, b
	}
	return b, a
}

func (e *Engine) merge(ctx context.Context, into, from string) error {
	if into == from {
		return nil
	}
	if err := e.Store.MergeActors(ctx, into, from); err != nil {
		return err
	}
	slog.Info("actors merged", "into", into, "from", from)
	return e.Rescore(ctx, into)
}

// sessionSig builds the correlation view of one session from its row and fingerprints.
func (e *Engine) sessionSig(ctx context.Context, sessionID string) (correlate.Session, error) {
	s, err := e.Store.Session(ctx, sessionID)
	if err != nil {
		return correlate.Session{}, err
	}
	sig := correlate.Session{ID: s.SessionID, ActorID: deref(s.ActorID), Service: s.Service, IP: s.SrcIP, Start: s.StartedAt}
	if s.EndedAt != nil {
		sig.End = *s.EndedAt
	}
	fps, err := e.Store.FingerprintsOf(ctx, []string{sessionID})
	if err != nil {
		return sig, err
	}
	for _, f := range fps {
		switch f.Kind {
		case "ssh_banner":
			sig.SSHBanner = f.Value
		case "hassh":
			sig.HASSH = f.Value
		case "ua":
			sig.UA = f.Value
		case "ja4":
			sig.JA4 = f.Value
		case "ssh_key":
			sig.SSHKeys = append(sig.SSHKeys, f.Value)
		case "cred_pair":
			sig.CredPairs = append(sig.CredPairs, f.Value)
		case "token_seen":
			sig.TokensSeen = append(sig.TokensSeen, f.Value)
		case "token_used":
			sig.TokensUsed = append(sig.TokensUsed, f.Value)
		case "cmd_shingles":
			sig.Shingles = decodeSig(f.Value) // latest one wins (sorted by value is fine: any is a valid estimate)
		}
	}
	return sig, nil
}

func (e *Engine) addFinding(ctx context.Context, ev store.StoredEvent, actorID string, m rules.Match, ml *dto.FindingML) (store.FindingRow, bool, error) {
	var tactic, technique *string
	if m.Rule.Technique != "" {
		t := m.Rule.Technique
		technique = &t
		if mt, ok := mitre.Lookup(t); ok {
			tactic = &mt.TacticID
		}
	}
	ev2 := dto.FindingEvidence{EventIDs: []string{ev.EventID}, Matched: m.Matched, ML: ml}
	evidence, _ := json.Marshal(ev2)
	sid := ev.SessionID
	return e.Store.AddFinding(ctx, store.FindingRow{SessionID: &sid, ActorID: actorID, RuleID: m.Rule.ID, Title: m.Rule.Title,
		Tactic: tactic, Technique: technique, Points: m.Points, Confidence: m.Confidence, Stage: m.Rule.Stage,
		Source: m.Source, Evidence: evidence, TS: ev.TS})
}

// Rescore recomputes stage scores, risk and severity for an actor and publishes the actor summary.
func (e *Engine) Rescore(ctx context.Context, actorID string) error {
	a, err := e.Store.Actor(ctx, actorID)
	if err != nil {
		return err
	}
	findings, err := e.Store.FindingsOfActor(ctx, actorID)
	if err != nil {
		return err
	}
	conf, err := e.Store.ActorConfidence(ctx, actorID)
	if err != nil {
		return err
	}
	fs := make([]risk.Finding, len(findings))
	k8sAuth := false
	for i, f := range findings {
		fs[i] = risk.Finding{Stage: f.Stage, Points: f.Points}
		if f.RuleID == "container_discovery" || f.RuleID == "container_secrets" {
			k8sAuth = true // the k8s decoy only serves these with a valid lure token (06 §3)
		}
	}
	w, err := e.weights(ctx)
	if err != nil {
		return err
	}
	_, maxSens, err := e.Store.ActorTokenHits(ctx, actorID)
	if err != nil {
		return err
	}
	stats, err := e.Store.ActorStats(ctx, actorID)
	if err != nil {
		return err
	}
	allow := false
	for _, ip := range stats.IPs {
		if e.Store.Allowlisted(ctx, ip) {
			allow = true
		}
	}
	stages := risk.StageScores(fs, conf)
	b := risk.Score(stages, w, risk.Facts{MaxUsedTokenSensitivity: maxSens, AuthenticatedK8s: k8sAuth, Allowlisted: allow,
		DecoyCredOnReal:  a.TouchedProduction && hasRule(findings, "decoy_cred_on_real"),
		RealLoginSuccess: hasRule(findings, "real_success")})
	if err := e.Store.UpdateActorScore(ctx, actorID, store.ActorScore{RiskScore: b.Risk, Severity: risk.Severity(b.Risk),
		Confidence: conf, StageScores: stages, RiskBreakdown: b}); err != nil {
		return err
	}
	a, err = e.Store.Actor(ctx, actorID)
	if err != nil {
		return err
	}
	sum, err := dto.Summary(ctx, e.Store, a)
	if err != nil {
		return err
	}
	e.Bus.Publish(bus.TopicActor, sum)
	return nil
}

func (e *Engine) weights(ctx context.Context) (risk.Weights, error) {
	sw, err := e.Store.ActiveWeights(ctx)
	if err != nil {
		return risk.Initial(), nil
	}
	return risk.Weights{Version: sw.Version, W: sw.Weights, Bias: sw.Bias, LearningRate: sw.LearningRate}, nil
}

// ---------- helpers ----------

type tokenHit struct{ token, kind string }

func tokenHits(ev store.StoredEvent, d map[string]any) []tokenHit {
	var out []tokenHit
	seen := map[string]bool{}
	add := func(t, kind string) {
		if t != "" && !seen[t+kind] {
			seen[t+kind] = true
			out = append(out, tokenHit{t, kind})
		}
	}
	switch ev.Type {
	case "token.used":
		if t, _ := d["token_id"].(string); t != "" {
			add(t, "used")
		}
		for _, t := range ev.Tokens {
			add(t, "used")
		}
	case "file.read", "file.download":
		if t, _ := d["honeyfile_id"].(string); t != "" {
			add(t, "seen")
		}
		for _, t := range ev.Tokens {
			add(t, "seen")
		}
	}
	return out
}

type webInput struct{ param, value, path, field string }

// webInputs lists the attacker-typed values of an event that the input-risk grader should see (07 §4.1).
func webInputs(ev store.StoredEvent, d map[string]any) []webInput {
	var out []webInput
	str := func(k string) string { v, _ := d[k].(string); return v }
	switch ev.Type {
	case "input.suspicious":
		out = append(out, webInput{str("param"), str("value"), str("path"), "query"})
	case "http.request":
		if q, ok := d["query"].(map[string]any); ok {
			for k, v := range q {
				if s, ok := v.(string); ok && len(out) < 10 && len(s) <= 1024 {
					out = append(out, webInput{k, s, str("path"), "query"})
				}
			}
		}
		if p := str("path"); strings.ContainsAny(p, "%\\") || strings.Contains(p, "..") {
			out = append(out, webInput{"path", p, p, "path"})
		}
	case "auth.attempt":
		if ev.Service == "web" {
			out = append(out, webInput{"username", str("username"), "/login", "username"})
		}
	}
	return out
}

// hit is a rule match plus the input-risk details that produced it (nil for plain rules).
type hit struct {
	m  rules.Match
	ml *dto.FindingML
}

func plain(ms []rules.Match) []hit {
	out := make([]hit, len(ms))
	for i, m := range ms {
		out[i] = hit{m: m}
	}
	return out
}

func hasRule(fs []store.FindingRow, id string) bool {
	for _, f := range fs {
		if f.RuleID == id {
			return true
		}
	}
	return false
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (e *Engine) recordTactic(ctx context.Context, ev store.StoredEvent, actorID string, d map[string]any) {
	str := func(k string) string { v, _ := d[k].(string); return v }
	t := store.TacticRow{ActorID: actorID, BiasPattern: str("bias_pattern"), Tactic: str("tactic"), TS: ev.TS,
		TriggerEventIDs: []string{ev.EventID}}
	if t.Tactic == "" {
		return
	}
	if t.BiasPattern == "" {
		t.BiasPattern = "unspecified"
	}
	if l := str("lure_id"); l != "" {
		t.LureID = &l
	}
	if ids, ok := d["trigger_event_ids"].([]any); ok {
		for _, x := range ids {
			if s, ok := x.(string); ok && len(t.TriggerEventIDs) < 20 {
				t.TriggerEventIDs = append(t.TriggerEventIDs, s)
			}
		}
	}
	if eff, ok := d["effect"]; ok {
		t.Effect, _ = json.Marshal(eff)
	}
	if err := e.Store.AddTactic(ctx, t); err != nil {
		slog.Warn("record tactic", "err", err)
	}
}
