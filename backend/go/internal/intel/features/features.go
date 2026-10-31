// Package features computes per-session and per-actor rolling features (07 §3, §7).
// It supplies features to session and actor rules (rules/rules.yaml) and to behaviour classification.
package features

import (
	"encoding/json"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/store"
)

type sessionData struct {
	mu sync.Mutex

	sessionID string
	actorID   string
	services  map[string]bool

	// Auth features
	failedAuthTimes  []time.Time
	pairs            map[string]bool // "username:password"
	successfulLogins int

	// Commands and timing
	commands   int
	gaps       []float64
	totalLines int
	editLines  int
	pasteLines int

	// Output dependence (07 §3)
	prevStdoutTokens  map[string]bool
	outputDepHits     int
	outputDepEligible int

	// Param mutation retries (07 §7)
	lastFailedArgv0      string
	lastFailedArgs       []string
	lastFailedHTTPPath   string
	paramMutationRetries int

	// Honeytokens seen & used
	tokensSeen map[string]bool
	tokensUsed map[string]bool

	latestTS time.Time
}

func newSessionData(sessionID string) *sessionData {
	return &sessionData{
		sessionID:        sessionID,
		services:         map[string]bool{},
		pairs:            map[string]bool{},
		prevStdoutTokens: map[string]bool{},
		tokensSeen:       map[string]bool{},
		tokensUsed:       map[string]bool{},
	}
}

// Provider implements engine.Features and tracks features in memory.
type Provider struct {
	mu sync.RWMutex

	sessions        map[string]*sessionData
	actorSessions   map[string]map[string]bool
	sessionToActor  map[string]string
	actorTokensSeen map[string]map[string]bool
	actorTokensUsed map[string]map[string]bool
	actorServices   map[string]map[string]bool
}

// New creates an initialized features provider.
func New() *Provider {
	return &Provider{
		sessions:        map[string]*sessionData{},
		actorSessions:   map[string]map[string]bool{},
		sessionToActor:  map[string]string{},
		actorTokensSeen: map[string]map[string]bool{},
		actorTokensUsed: map[string]map[string]bool{},
		actorServices:   map[string]map[string]bool{},
	}
}

// Associate links a session ID to an actor ID.
func (p *Provider) Associate(sessionID, actorID string) {
	if sessionID == "" || actorID == "" {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	p.sessionToActor[sessionID] = actorID
	if p.actorSessions[actorID] == nil {
		p.actorSessions[actorID] = map[string]bool{}
	}
	p.actorSessions[actorID][sessionID] = true

	if sess, ok := p.sessions[sessionID]; ok {
		sess.mu.Lock()
		sess.actorID = actorID
		if p.actorServices[actorID] == nil {
			p.actorServices[actorID] = map[string]bool{}
		}
		for s := range sess.services {
			p.actorServices[actorID][s] = true
		}
		if p.actorTokensSeen[actorID] == nil {
			p.actorTokensSeen[actorID] = map[string]bool{}
		}
		for t := range sess.tokensSeen {
			p.actorTokensSeen[actorID][t] = true
		}
		if p.actorTokensUsed[actorID] == nil {
			p.actorTokensUsed[actorID] = map[string]bool{}
		}
		for t := range sess.tokensUsed {
			p.actorTokensUsed[actorID][t] = true
		}
		sess.mu.Unlock()
	}
}

// Observe updates session and actor state from one stored event.
func (p *Provider) Observe(ev store.StoredEvent) {
	if ev.SessionID == "" {
		return
	}

	p.mu.Lock()
	sess, ok := p.sessions[ev.SessionID]
	if !ok {
		sess = newSessionData(ev.SessionID)
		p.sessions[ev.SessionID] = sess
	}
	actorID := ""
	if ev.ActorID != nil && *ev.ActorID != "" {
		actorID = *ev.ActorID
		p.sessionToActor[ev.SessionID] = actorID
		if p.actorSessions[actorID] == nil {
			p.actorSessions[actorID] = map[string]bool{}
		}
		p.actorSessions[actorID][ev.SessionID] = true
	} else if aid, ok := p.sessionToActor[ev.SessionID]; ok {
		actorID = aid
	}
	p.mu.Unlock()

	sess.mu.Lock()
	defer sess.mu.Unlock()

	if actorID != "" {
		sess.actorID = actorID
	}
	if ev.TS.After(sess.latestTS) {
		sess.latestTS = ev.TS
	}
	if ev.Service != "" {
		sess.services[ev.Service] = true
	}

	// Parse event data.
	var data map[string]any
	if len(ev.Data) > 0 {
		_ = json.Unmarshal(ev.Data, &data)
	}

	// Parse timing from envelope if available.
	var timing *event.Timing
	if len(ev.Envelope) > 0 {
		var envMeta struct {
			Timing *event.Timing `json:"timing,omitempty"`
		}
		if err := json.Unmarshal(ev.Envelope, &envMeta); err == nil && envMeta.Timing != nil {
			timing = envMeta.Timing
		}
	}

	switch ev.Type {
	case "auth.attempt":
		success, _ := data["success"].(bool)
		u, _ := data["username"].(string)
		pass := ""
		if pStr, ok := data["password"].(string); ok {
			pass = pStr
		}
		if u != "" || pass != "" {
			sess.pairs[u+":"+pass] = true
		}
		if success {
			sess.successfulLogins++
		} else {
			sess.failedAuthTimes = append(sess.failedAuthTimes, ev.TS)
		}

	case "shell.command":
		sess.commands++
		raw, _ := data["raw"].(string)
		argv0, _ := data["argv0"].(string)
		exitCode := 0
		if ex, ok := data["exit"].(float64); ok {
			exitCode = int(ex)
		}

		var args []string
		if argsArr, ok := data["args"].([]any); ok {
			for _, a := range argsArr {
				if s, ok := a.(string); ok {
					args = append(args, s)
				}
			}
		}

		// Timing measurements.
		if timing != nil {
			sess.totalLines++
			if timing.SincePrevMS > 0 {
				sess.gaps = append(sess.gaps, float64(timing.SincePrevMS))
			}
			if timing.Edits > 0 {
				sess.editLines++
			}
			if timing.Paste {
				sess.pasteLines++
			}
		}

		// Output dependence: check if any arg or raw word matches previous stdout token.
		if len(sess.prevStdoutTokens) > 0 {
			sess.outputDepEligible++
			hit := false
			for _, arg := range args {
				if sess.prevStdoutTokens[arg] {
					hit = true
					break
				}
			}
			if !hit && raw != "" {
				for _, word := range strings.Fields(raw) {
					if sess.prevStdoutTokens[word] {
						hit = true
						break
					}
				}
			}
			if hit {
				sess.outputDepHits++
			}
		}

		// Update prev stdout tokens.
		sess.prevStdoutTokens = map[string]bool{}
		if tokensArr, ok := data["stdout_tokens"].([]any); ok {
			for _, t := range tokensArr {
				if s, ok := t.(string); ok {
					sess.prevStdoutTokens[s] = true
				}
			}
		}

		// Param mutation retries: same argv0 retried with changed args after non-zero exit.
		if sess.lastFailedArgv0 != "" && sess.lastFailedArgv0 == argv0 && !argsEqual(sess.lastFailedArgs, args) {
			sess.paramMutationRetries++
		}
		if exitCode != 0 {
			sess.lastFailedArgv0 = argv0
			sess.lastFailedArgs = args
		} else {
			sess.lastFailedArgv0 = ""
			sess.lastFailedArgs = nil
		}

	case "http.request":
		sess.commands++
		path, _ := data["path"].(string)
		status := 0
		if st, ok := data["status"].(float64); ok {
			status = int(st)
		}
		if sess.lastFailedHTTPPath != "" && sess.lastFailedHTTPPath == path {
			sess.paramMutationRetries++
		}
		if status >= 400 {
			sess.lastFailedHTTPPath = path
		} else {
			sess.lastFailedHTTPPath = ""
		}

	case "k8s.api_call":
		sess.commands++

	case "file.read", "file.download":
		if hID, ok := data["honeyfile_id"].(string); ok && hID != "" {
			sess.tokensSeen[hID] = true
		}
		for _, t := range ev.Tokens {
			if t != "" {
				sess.tokensSeen[t] = true
			}
		}

	case "token.used":
		if tID, ok := data["token_id"].(string); ok && tID != "" {
			sess.tokensUsed[tID] = true
		}
		for _, t := range ev.Tokens {
			if t != "" {
				sess.tokensUsed[t] = true
			}
		}
	}

	// Sync to actor maps if actor is known.
	if actorID != "" {
		p.mu.Lock()
		if p.actorServices[actorID] == nil {
			p.actorServices[actorID] = map[string]bool{}
		}
		p.actorServices[actorID][ev.Service] = true

		if p.actorTokensSeen[actorID] == nil {
			p.actorTokensSeen[actorID] = map[string]bool{}
		}
		for t := range sess.tokensSeen {
			p.actorTokensSeen[actorID][t] = true
		}

		if p.actorTokensUsed[actorID] == nil {
			p.actorTokensUsed[actorID] = map[string]bool{}
		}
		for t := range sess.tokensUsed {
			p.actorTokensUsed[actorID][t] = true
		}
		p.mu.Unlock()
	}
}

// Session returns features for a single session.
func (p *Provider) Session(sessionID string) map[string]float64 {
	p.mu.RLock()
	sess, ok := p.sessions[sessionID]
	p.mu.RUnlock()

	if !ok {
		return map[string]float64{
			"failed_auths_5m":   0,
			"distinct_pairs":    0,
			"successful_logins": 0,
			"commands":          0,
			"services_visited":  0,
		}
	}

	sess.mu.Lock()
	defer sess.mu.Unlock()

	cutoff := sess.latestTS.Add(-5 * time.Minute)
	failed5m := 0
	for _, t := range sess.failedAuthTimes {
		if !t.Before(cutoff) {
			failed5m++
		}
	}

	return map[string]float64{
		"failed_auths_5m":   float64(failed5m),
		"distinct_pairs":    float64(len(sess.pairs)),
		"successful_logins": float64(sess.successfulLogins),
		"commands":          float64(sess.commands),
		"services_visited":  float64(len(sess.services)),
	}
}

// Actor aggregates features across all sessions belonging to an actor.
func (p *Provider) Actor(actorID string) map[string]float64 {
	p.mu.RLock()
	sessIDs := p.actorSessions[actorID]
	var sessions []*sessionData
	for sid := range sessIDs {
		if s, ok := p.sessions[sid]; ok {
			sessions = append(sessions, s)
		}
	}
	actorServices := p.actorServices[actorID]
	actorTokensSeen := p.actorTokensSeen[actorID]
	actorTokensUsed := p.actorTokensUsed[actorID]
	p.mu.RUnlock()

	var totalCommands int
	var allGaps []float64
	var totalLines int
	var editLines int
	var pasteLines int
	var outputDepHits int
	var outputDepEligible int
	var paramMutationRetries int
	var successfulLogins int
	var failedAuthTimes []time.Time
	var latestTS time.Time
	pairs := map[string]bool{}
	services := map[string]bool{}
	tokensSeen := map[string]bool{}
	tokensUsed := map[string]bool{}

	for s := range actorServices {
		services[s] = true
	}
	for t := range actorTokensSeen {
		tokensSeen[t] = true
	}
	for t := range actorTokensUsed {
		tokensUsed[t] = true
	}

	for _, sess := range sessions {
		sess.mu.Lock()
		totalCommands += sess.commands
		allGaps = append(allGaps, sess.gaps...)
		totalLines += sess.totalLines
		editLines += sess.editLines
		pasteLines += sess.pasteLines
		outputDepHits += sess.outputDepHits
		outputDepEligible += sess.outputDepEligible
		paramMutationRetries += sess.paramMutationRetries
		successfulLogins += sess.successfulLogins
		failedAuthTimes = append(failedAuthTimes, sess.failedAuthTimes...)
		for s := range sess.services {
			services[s] = true
		}
		for t := range sess.tokensSeen {
			tokensSeen[t] = true
		}
		for t := range sess.tokensUsed {
			tokensUsed[t] = true
		}
		for pr := range sess.pairs {
			pairs[pr] = true
		}
		if sess.latestTS.After(latestTS) {
			latestTS = sess.latestTS
		}
		sess.mu.Unlock()
	}

	// Breadcrumbs followed: token_seen -> token_used pairs.
	breadcrumbsFollowed := 0
	for t := range tokensSeen {
		if tokensUsed[t] {
			breadcrumbsFollowed++
		}
	}

	medianGap := calcMedian(allGaps)
	gapCV := calcCV(allGaps)

	editRate := 0.0
	pasteRate := 0.0
	if totalLines > 0 {
		editRate = float64(editLines) / float64(totalLines)
		pasteRate = float64(pasteLines) / float64(totalLines)
	}

	outputDep := 0.0
	if outputDepEligible > 0 {
		outputDep = float64(outputDepHits) / float64(outputDepEligible)
	}

	cutoff := latestTS.Add(-5 * time.Minute)
	failed5m := 0
	for _, t := range failedAuthTimes {
		if !t.Before(cutoff) {
			failed5m++
		}
	}

	return map[string]float64{
		"median_gap_ms":          round2(medianGap),
		"gap_cv":                 round2(gapCV),
		"edit_rate":              round2(editRate),
		"paste_rate":             round2(pasteRate),
		"output_dependence":      round2(outputDep),
		"services_visited":       float64(len(services)),
		"breadcrumbs_followed":   float64(breadcrumbsFollowed),
		"param_mutation_retries": float64(paramMutationRetries),
		"commands":               float64(totalCommands),
		"failed_auths_5m":        float64(failed5m),
		"distinct_pairs":         float64(len(pairs)),
		"successful_logins":      float64(successfulLogins),
	}
}

func calcMedian(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := make([]float64, len(xs))
	copy(sorted, xs)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2.0
}

func calcCV(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	sum := 0.0
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	if mean <= 0 {
		return 0
	}
	varianceSum := 0.0
	for _, x := range xs {
		diff := x - mean
		varianceSum += diff * diff
	}
	variance := varianceSum / float64(len(xs)-1)
	stdDev := math.Sqrt(variance)
	return stdDev / mean
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

func argsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

