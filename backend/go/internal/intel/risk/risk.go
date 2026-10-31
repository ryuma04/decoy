// Package risk computes the actor risk score (07 §6): per-stage scores, a single-neuron (logistic) combiner,
// hard overrides on top, and weight updates only from analyst feedback. Deterministic.
package risk

import (
	"math"
)

var Stages = []string{"recon", "access", "post_access", "lateral"}

// Weights is one version of the combiner (scorer_weights row).
type Weights struct {
	Version      int                `json:"version"`
	W            map[string]float64 `json:"weights"`
	Bias         float64            `json:"bias"`
	LearningRate float64            `json:"learning_rate"`
}

// Initial is version 1 from 03 / 07 §6.2.
func Initial() Weights {
	return Weights{Version: 1, W: map[string]float64{"recon": 1, "access": 2, "post_access": 3, "lateral": 4},
		Bias: -3, LearningRate: 0.05}
}

// Finding is the part of a finding the scorer needs.
type Finding struct {
	Stage  string
	Points int
}

// Override conditions (07 §6.3). Fields are facts about the actor.
type Facts struct {
	MaxUsedTokenSensitivity int  // highest sensitivity of a honeytoken used (0 = none)
	DecoyCredOnReal         bool // decoy credential used on a real system
	RealLoginSuccess        bool // successful real login from an actor IP
	AuthenticatedK8s        bool // authenticated access to the k8s decoy
	ConfirmedExploit        bool // injection finding where rules and the input-risk model agree (confidence >= 0.9)
	HoneyfileRead           bool // read or downloaded a planted honeyfile (nobody legitimate ever opens one)
	Allowlisted             bool
}

// Breakdown matches RiskBreakdown in 04.
type Breakdown struct {
	P              float64            `json:"p"`
	Z              float64            `json:"z"`
	WeightsVersion int                `json:"weights_version"`
	StageScores    map[string]float64 `json:"stage_scores"`
	Contributions  map[string]float64 `json:"contributions"`
	Bias           float64            `json:"bias"`
	Override       *string            `json:"override"`
	Risk           int                `json:"-"`
}

// StageScores sums finding points per stage, scaled by (0.5 + 0.5 × confidence), capped at 100 (07 §6.1).
func StageScores(findings []Finding, confidence float64) map[string]float64 {
	conf := math.Max(0, math.Min(1, confidence))
	out := map[string]float64{}
	for _, s := range Stages {
		out[s] = 0
	}
	for _, f := range findings {
		if _, ok := out[f.Stage]; ok {
			out[f.Stage] += float64(f.Points)
		}
	}
	for s, v := range out {
		out[s] = math.Min(100, round1(v*(0.5+0.5*conf)))
	}
	return out
}

func sigmoid(z float64) float64 { return 1 / (1 + math.Exp(-z)) }

// Score combines stage scores with the neuron, then applies overrides.
func Score(stage map[string]float64, w Weights, f Facts) Breakdown {
	b := Breakdown{WeightsVersion: w.Version, StageScores: stage, Contributions: map[string]float64{}, Bias: w.Bias}
	z := w.Bias
	for _, s := range Stages {
		c := w.W[s] * stage[s] / 100
		b.Contributions[s] = round3(c)
		z += c
	}
	b.Z, b.P = round3(z), round3(sigmoid(z))
	b.Risk = int(math.Round(100 * sigmoid(z)))

	override := func(name string, min int) {
		if b.Risk < min {
			b.Risk = min
		}
		if b.Override == nil {
			n := name
			b.Override = &n
		}
	}
	switch {
	case f.Allowlisted:
		n := "allowlisted"
		b.Override, b.Risk = &n, 0
		return b
	case f.RealLoginSuccess:
		override("real_login_success", 100)
	case f.DecoyCredOnReal:
		override("decoy_credential_on_real_system", 95)
	}
	if f.MaxUsedTokenSensitivity >= 4 {
		override("token_used_sensitivity_"+itoa(f.MaxUsedTokenSensitivity), 90)
	}
	if f.AuthenticatedK8s {
		override("authenticated_k8s_access", 60)
	}
	// One exploit attempt or one lure touch is already a real intrusion signal: at least medium, even before the
	// actor moves through more stages (the neuron alone gives ~6 for a single access finding).
	if f.HoneyfileRead {
		override("honeyfile_read", 40)
	}
	if f.ConfirmedExploit {
		override("confirmed_exploit_attempt", 35)
	}
	return b
}

// Severity maps risk to the 07 §6.4 bands.
func Severity(risk int) string {
	switch {
	case risk >= 75:
		return "critical"
	case risk >= 50:
		return "high"
	case risk >= 25:
		return "medium"
	default:
		return "low"
	}
}

// Update applies one online logistic-regression step for an analyst label (y=1 confirmed, y=0 false positive)
// and returns the next weights version (07 §6.5). Overrides are not part of the neuron, so they are never learned away.
func Update(w Weights, stage map[string]float64, y float64) Weights {
	z := w.Bias
	for _, s := range Stages {
		z += w.W[s] * stage[s] / 100
	}
	p := sigmoid(z)
	next := Weights{Version: w.Version + 1, W: map[string]float64{}, LearningRate: w.LearningRate}
	for _, s := range Stages {
		next.W[s] = round4(clamp(w.W[s]-w.LearningRate*(p-y)*stage[s]/100, 0.1, 8.0))
	}
	next.Bias = round4(clamp(w.Bias-w.LearningRate*(p-y), -6.0, 0.0))
	return next
}

func clamp(v, lo, hi float64) float64 { return math.Max(lo, math.Min(hi, v)) }
func round1(v float64) float64        { return math.Round(v*10) / 10 }
func round3(v float64) float64        { return math.Round(v*1000) / 1000 }
func round4(v float64) float64        { return math.Round(v*10000) / 10000 }

func itoa(n int) string {
	if n >= 0 && n <= 9 {
		return string(rune('0' + n))
	}
	return "n"
}
