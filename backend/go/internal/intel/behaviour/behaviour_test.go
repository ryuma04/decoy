package behaviour

import (
	"testing"
)

func TestClassifyUnder5Commands(t *testing.T) {
	feat := map[string]float64{
		"commands":      4,
		"median_gap_ms": 500,
		"gap_cv":        0.1,
		"edit_rate":     0,
	}
	res := Classify(feat)
	if res.Class != ClassUnknown {
		t.Fatalf("expected unknown for commands < 5, got %s", res.Class)
	}
	// Even though class is unknown, scores are calculated for UI bars
	if res.Scores[ClassScripted] != 1.0 {
		t.Errorf("scripted score: got %v, want 1.0", res.Scores[ClassScripted])
	}
}

func TestClassifyScripted(t *testing.T) {
	// median gap < 1,000 ms, gap_cv < 0.3, edit_rate = 0
	feat := map[string]float64{
		"commands":      10,
		"median_gap_ms": 400,
		"gap_cv":        0.15,
		"edit_rate":     0,
	}
	res := Classify(feat)
	if res.Class != ClassScripted {
		t.Fatalf("expected scripted, got %s", res.Class)
	}
	if res.Scores[ClassScripted] != 1.0 {
		t.Errorf("scripted score: got %v, want 1.0", res.Scores[ClassScripted])
	}
}

func TestClassifyAgentLike(t *testing.T) {
	// >= 3 of:
	// paste_rate >= 0.7, edit_rate = 0, output_dependence >= 0.5,
	// 2 s <= median gap <= 20 s with gap_cv < 0.5, breadcrumbs_followed >= 2, param_mutation_retries >= 3
	feat := map[string]float64{
		"commands":               12,
		"paste_rate":             0.8,  // signal 1
		"edit_rate":              0,    // signal 2
		"output_dependence":      0.6,  // signal 3
		"median_gap_ms":          5000, // signal 4
		"gap_cv":                 0.2,  // signal 4
		"breadcrumbs_followed":   0,
		"param_mutation_retries": 0,
	}
	res := Classify(feat)
	if res.Class != ClassAgentLike {
		t.Fatalf("expected agent_like, got %s", res.Class)
	}
	// 4 signals met out of 6 -> 4/6 = 0.67
	if res.Scores[ClassAgentLike] != 0.67 {
		t.Errorf("agent_like score: got %v, want 0.67", res.Scores[ClassAgentLike])
	}
}

func TestClassifyHumanLike(t *testing.T) {
	// edit_rate >= 0.1 or gap_cv >= 0.8
	feat := map[string]float64{
		"commands":      8,
		"edit_rate":     0.25, // human signal 1
		"gap_cv":        0.4,
		"median_gap_ms": 3000,
	}
	res := Classify(feat)
	if res.Class != ClassHumanLike {
		t.Fatalf("expected human_like, got %s", res.Class)
	}
	if res.Scores[ClassHumanLike] != 0.5 {
		t.Errorf("human_like score: got %v, want 0.5", res.Scores[ClassHumanLike])
	}
}

func TestClassifyAIAssisted(t *testing.T) {
	// human_like signals AND >= 2 agent signals
	feat := map[string]float64{
		"commands":          15,
		"edit_rate":         0.15, // human signal 1
		"paste_rate":        0.9,  // agent signal 1
		"output_dependence": 0.7,  // agent signal 2
		"median_gap_ms":     4000, // agent signal 3
		"gap_cv":            0.3,  // agent signal 3
	}
	res := Classify(feat)
	if res.Class != ClassAIAssisted {
		t.Fatalf("expected ai_assisted, got %s", res.Class)
	}
	if res.Scores[ClassAIAssisted] != 1.0 {
		t.Errorf("ai_assisted score: got %v, want 1.0", res.Scores[ClassAIAssisted])
	}
}

func TestAllFeaturesPresentInResult(t *testing.T) {
	feat := map[string]float64{
		"commands": 5,
	}
	res := Classify(feat)
	for _, k := range FeatureNames {
		if _, ok := res.Features[k]; !ok {
			t.Errorf("missing feature in result: %s", k)
		}
	}
}

