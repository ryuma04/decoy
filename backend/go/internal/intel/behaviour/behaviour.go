// Package behaviour classifies an actor's behaviour pattern (07 §7).
// Wording: behaviour classes describe behaviour, never identity.
package behaviour

import "math"

// Standard behaviour classes.
const (
	ClassHumanLike  = "human_like"
	ClassScripted   = "scripted"
	ClassAIAssisted = "ai_assisted"
	ClassAgentLike  = "agent_like"
	ClassUnknown    = "unknown"
)

var FeatureNames = []string{
	"median_gap_ms",
	"gap_cv",
	"edit_rate",
	"paste_rate",
	"output_dependence",
	"services_visited",
	"breadcrumbs_followed",
	"param_mutation_retries",
	"commands",
}

// Result holds the classification outcome (04, 07 §7).
type Result struct {
	Class    string             `json:"class"`
	Scores   map[string]float64 `json:"scores"`
	Source   string             `json:"source"`
	Features map[string]float64 `json:"features"`
}

// Classify applies the deterministic rules from 07 §7.
func Classify(features map[string]float64) Result {
	featCopy := make(map[string]float64, len(FeatureNames))
	for _, k := range FeatureNames {
		featCopy[k] = features[k]
	}

	medianGap := featCopy["median_gap_ms"]
	gapCV := featCopy["gap_cv"]
	editRate := featCopy["edit_rate"]
	pasteRate := featCopy["paste_rate"]
	outputDep := featCopy["output_dependence"]
	breadcrumbs := featCopy["breadcrumbs_followed"]
	mutationRetries := featCopy["param_mutation_retries"]
	commands := featCopy["commands"]

	// 1. Scripted conditions (3 conditions):
	// median gap < 1,000 ms, gap_cv < 0.3, edit_rate = 0
	scriptedCount := 0
	if medianGap > 0 && medianGap < 1000 {
		scriptedCount++
	}
	if gapCV < 0.3 {
		scriptedCount++
	}
	if editRate == 0 {
		scriptedCount++
	}
	scoreScripted := float64(scriptedCount) / 3.0

	// 2. Agent-like conditions (6 signals):
	// - paste_rate >= 0.7
	// - edit_rate = 0
	// - output_dependence >= 0.5
	// - 2 s <= median gap <= 20 s with gap_cv < 0.5
	// - breadcrumbs_followed >= 2
	// - param_mutation_retries >= 3
	agentSignals := 0
	if pasteRate >= 0.7 {
		agentSignals++
	}
	if editRate == 0 {
		agentSignals++
	}
	if outputDep >= 0.5 {
		agentSignals++
	}
	if medianGap >= 2000 && medianGap <= 20000 && gapCV < 0.5 {
		agentSignals++
	}
	if breadcrumbs >= 2 {
		agentSignals++
	}
	if mutationRetries >= 3 {
		agentSignals++
	}
	scoreAgent := float64(agentSignals) / 6.0

	// 3. Human-like conditions (2 conditions):
	// edit_rate >= 0.1 or gap_cv >= 0.8
	humanSignals := 0
	if editRate >= 0.1 {
		humanSignals++
	}
	if gapCV >= 0.8 {
		humanSignals++
	}
	scoreHuman := float64(humanSignals) / 2.0

	// 4. AI-assisted condition:
	// human_like signals and >= 2 agent signals
	scoreAIAssisted := (math.Min(1.0, float64(humanSignals)) + math.Min(1.0, float64(agentSignals)/2.0)) / 2.0

	scores := map[string]float64{
		ClassScripted:   round2(scoreScripted),
		ClassAgentLike:  round2(scoreAgent),
		ClassHumanLike:  round2(scoreHuman),
		ClassAIAssisted: round2(scoreAIAssisted),
	}

	if commands < 5 {
		return Result{
			Class:    ClassUnknown,
			Scores:   scores,
			Source:   "rules",
			Features: featCopy,
		}
	}

	var class string
	switch {
	case scriptedCount == 3:
		class = ClassScripted
	case humanSignals >= 1 && agentSignals >= 2:
		class = ClassAIAssisted
	case agentSignals >= 3:
		class = ClassAgentLike
	case humanSignals >= 1:
		class = ClassHumanLike
	default:
		class = ClassUnknown
	}

	return Result{
		Class:    class,
		Scores:   scores,
		Source:   "rules",
		Features: featCopy,
	}
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

