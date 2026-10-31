// Package narrate produces the readable text for incidents, actors and alerts (10 §N): the LLM through the
// ML service when available, otherwise a deterministic template built only from facts.
package narrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/mlclient"
)

// Narrative matches `Narrative` in 04 §B.
type Narrative struct {
	Headline    string    `json:"headline"`
	Text        string    `json:"text"`
	Bullets     []string  `json:"bullets"`
	Source      string    `json:"source"` // llm | template
	Model       *string   `json:"model"`
	GeneratedAt time.Time `json:"generated_at"`
}

// Facts is what narration may use. Everything here comes from our own tables.
type Facts struct {
	ActorLabel          string
	Severity            string
	Risk                int
	Behaviour           string
	Services            []string
	IPs                 []string
	Tokens              []string
	Findings            []Finding
	Recommended         []string
	DashboardURL        string
	TouchedProduction   bool
	FirstSeen, LastSeen time.Time
}

type Finding struct {
	Title     string
	Technique string
	TS        time.Time
}

// Template is the always-available text (10 §N "Template fallback").
func Template(f Facts) Narrative {
	techniques := []string{}
	seen := map[string]bool{}
	for _, x := range f.Findings {
		if x.Technique != "" && !seen[x.Technique] {
			seen[x.Technique] = true
			techniques = append(techniques, x.Technique)
		}
	}
	sort.Strings(techniques)
	steps := []string{}
	for i, x := range f.Findings {
		if i == 6 {
			break
		}
		steps = append(steps, strings.ToLower(x.Title[:1])+x.Title[1:])
	}
	ist := time.FixedZone("IST", 5*3600+1800)
	when := ""
	if !f.FirstSeen.IsZero() {
		when = fmt.Sprintf(" between %s and %s IST", f.FirstSeen.In(ist).Format("15:04"), f.LastSeen.In(ist).Format("15:04"))
	}
	n := len(f.Services)
	unit := map[bool]string{true: "decoy", false: "decoys"}[n == 1]
	text := fmt.Sprintf("%s (%s, risk %d) touched %d %s%s.", f.ActorLabel, f.Severity, f.Risk, n, unit, when)
	if len(steps) > 0 {
		text += " Key steps: " + strings.Join(steps, "; ") + "."
	}
	if len(techniques) > 0 {
		text += " Techniques: " + strings.Join(techniques, ", ") + "."
	}
	if f.TouchedProduction {
		text += " A real (production) system was involved."
	}
	if len(f.Recommended) > 0 {
		text += " Recommended: " + strings.Join(f.Recommended, ", ") + "."
	}
	headline := fmt.Sprintf("%s active on %s", f.ActorLabel, strings.Join(f.Services, ", "))
	if len(f.Findings) > 0 {
		headline = fmt.Sprintf("%s: %s", f.ActorLabel, f.Findings[len(f.Findings)-1].Title)
	}
	bullets := []string{}
	if len(f.Tokens) > 0 {
		bullets = append(bullets, "Honeytokens: "+strings.Join(f.Tokens, ", "))
	}
	if len(f.IPs) > 0 {
		bullets = append(bullets, "Source IPs: "+strings.Join(f.IPs, ", "))
	}
	for _, r := range f.Recommended {
		if len(bullets) == 5 {
			break
		}
		bullets = append(bullets, "Suggested: "+r)
	}
	return Narrative{Headline: headline, Text: text, Bullets: bullets, Source: "template", GeneratedAt: time.Now().UTC()}
}

// Narrator calls the LLM (with cache and an hourly cap) and falls back to the template.
type Narrator struct {
	ML          *mlclient.Client
	MaxPerHour  int
	mu          sync.Mutex
	cache       map[string]Narrative
	windowStart time.Time
	calls       int
}

// Narrate returns LLM text when possible, else the template. kind: alert | actor | incident | event.
func (n *Narrator) Narrate(ctx context.Context, kind, refID string, f Facts, attacker []string, timeout time.Duration) Narrative {
	tmpl := Template(f)
	if n == nil || !n.ML.Enabled() {
		return tmpl
	}
	key := cacheKey(kind, refID, f)
	n.mu.Lock()
	if n.cache == nil {
		n.cache = map[string]Narrative{}
	}
	if c, ok := n.cache[key]; ok {
		n.mu.Unlock()
		return c
	}
	if time.Since(n.windowStart) > time.Hour {
		n.windowStart, n.calls = time.Now(), 0
	}
	if n.MaxPerHour > 0 && n.calls >= n.MaxPerHour {
		n.mu.Unlock()
		return tmpl
	}
	n.calls++
	n.mu.Unlock()

	req := mlclient.NarrateRequest{Kind: kind, RefID: refID, Audience: "dashboard", AttackerStrings: trimAll(attacker, 200, 20),
		Facts: mlclient.NarrateFacts{ActorLabel: &f.ActorLabel, Severity: &f.Severity, RiskScore: &f.Risk,
			BehaviourClass: &f.Behaviour, Services: nz(f.Services), IPs: nz(f.IPs), Tokens: nz(f.Tokens),
			RecommendedActions: nz(f.Recommended), DashboardURL: f.DashboardURL, TouchedProduction: f.TouchedProduction,
			Findings: []mlclient.FactFinding{}, Timeline: []mlclient.FactLine{}}}
	for i, x := range f.Findings {
		if i == 15 {
			break
		}
		t := x.Technique
		req.Facts.Findings = append(req.Facts.Findings, mlclient.FactFinding{Title: x.Title, Technique: &t, TS: x.TS.UTC().Format(time.RFC3339)})
	}
	out, err := n.ML.Narrate(ctx, req, timeout)
	if err != nil {
		return tmpl
	}
	model := out.Model
	res := Narrative{Headline: out.Headline, Text: out.Text, Bullets: nz(out.Bullets), Source: "llm", Model: &model, GeneratedAt: time.Now().UTC()}
	n.mu.Lock()
	if len(n.cache) > 500 {
		n.cache = map[string]Narrative{}
	}
	n.cache[key] = res
	n.mu.Unlock()
	return res
}

func cacheKey(kind, ref string, f Facts) string {
	b, _ := json.Marshal(f)
	h := sha256.Sum256(append([]byte(kind+"|"+ref+"|"), b...))
	return hex.EncodeToString(h[:])
}

func trimAll(xs []string, n, max int) []string {
	out := []string{}
	for _, x := range xs {
		if len(out) == max {
			break
		}
		if len(x) > n {
			x = x[:n]
		}
		out = append(out, x)
	}
	return out
}

func nz(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}
