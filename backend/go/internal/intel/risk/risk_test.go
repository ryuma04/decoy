package risk

import (
	"math"
	"testing"
)

func TestLightReconStaysLow(t *testing.T) {
	st := StageScores([]Finding{{"recon", 5}}, 1)
	b := Score(st, Initial(), Facts{})
	if b.Risk >= 25 || Severity(b.Risk) != "low" {
		t.Fatalf("risk %d", b.Risk)
	}
}

func TestFullChainIsCritical(t *testing.T) {
	st := StageScores([]Finding{{"recon", 5}, {"access", 10}, {"access", 20}, {"post_access", 15}, {"post_access", 15},
		{"post_access", 5}, {"lateral", 15}, {"lateral", 20}, {"lateral", 15}}, 1)
	// With the v1 weights (07 §6.2) the neuron alone puts a full chain at "high" (z ≈ 0.7, risk 67);
	// the honeytoken-used override (07 §6.3) is what makes the demo actor critical.
	b := Score(st, Initial(), Facts{})
	if Severity(b.Risk) != "high" {
		t.Fatalf("neuron only: risk %d z %.2f", b.Risk, b.Z)
	}
	if withToken := Score(st, Initial(), Facts{MaxUsedTokenSensitivity: 5}); Severity(withToken.Risk) != "critical" {
		t.Fatalf("with token: risk %d", withToken.Risk)
	}
	sum := b.Bias
	for _, s := range Stages {
		sum += b.Contributions[s]
	}
	if math.Abs(sum-b.Z) > 0.01 {
		t.Fatalf("contributions %.3f do not add up to z %.3f", sum, b.Z)
	}
}

func TestConfidenceScalesStages(t *testing.T) {
	full := StageScores([]Finding{{"access", 40}}, 1)["access"]
	loose := StageScores([]Finding{{"access", 40}}, 0)["access"]
	if full != 40 || loose != 20 {
		t.Fatalf("full %v loose %v", full, loose)
	}
	if capped := StageScores([]Finding{{"lateral", 500}}, 1)["lateral"]; capped != 100 {
		t.Fatalf("cap %v", capped)
	}
}

func TestOverrides(t *testing.T) {
	zero := StageScores(nil, 1)
	cases := []struct {
		f    Facts
		min  int
		name string
	}{
		{Facts{MaxUsedTokenSensitivity: 5}, 90, "token_used_sensitivity_5"},
		{Facts{DecoyCredOnReal: true}, 95, "decoy_credential_on_real_system"},
		{Facts{RealLoginSuccess: true}, 100, "real_login_success"},
		{Facts{AuthenticatedK8s: true}, 60, "authenticated_k8s_access"},
	}
	for _, c := range cases {
		b := Score(zero, Initial(), c.f)
		if b.Risk < c.min || b.Override == nil || *b.Override != c.name {
			t.Errorf("%+v: risk %d override %v", c.f, b.Risk, b.Override)
		}
	}
	if b := Score(StageScores([]Finding{{"lateral", 100}}, 1), Initial(), Facts{Allowlisted: true}); b.Risk != 0 {
		t.Fatalf("allowlisted risk %d", b.Risk)
	}
	if b := Score(zero, Initial(), Facts{MaxUsedTokenSensitivity: 2}); b.Override != nil {
		t.Fatal("low-sensitivity token must not override")
	}
}

func TestFeedbackMovesWeightsAndIsBounded(t *testing.T) {
	st := map[string]float64{"recon": 20, "access": 50, "post_access": 40, "lateral": 0}
	w := Initial()
	before := Score(st, w, Facts{}).P
	fp := Update(w, st, 0)
	if fp.Version != 2 || fp.W["access"] >= w.W["access"] || fp.Bias >= w.Bias {
		t.Fatalf("false positive should lower weights: %+v", fp)
	}
	if fp.W["lateral"] != w.W["lateral"] {
		t.Fatal("stage with score 0 must not change")
	}
	// One step with η = 0.05 moves p by well under one risk point; it must still move it down.
	if after := Score(st, fp, Facts{}).P; after >= before {
		t.Fatalf("p did not drop: %v -> %v", before, after)
	}
	conf := Update(w, st, 1)
	if conf.W["access"] <= w.W["access"] {
		t.Fatal("confirmed should raise weights")
	}
	x := w
	for i := 0; i < 5000; i++ {
		x = Update(x, map[string]float64{"recon": 100, "access": 100, "post_access": 100, "lateral": 100}, 0)
	}
	for _, s := range Stages {
		if x.W[s] < 0.1 {
			t.Fatalf("weight %s below clamp: %v", s, x.W[s])
		}
	}
	if x.Bias < -6 {
		t.Fatalf("bias below clamp: %v", x.Bias)
	}
	if b := Score(StageScores(nil, 1), x, Facts{MaxUsedTokenSensitivity: 5}); b.Risk < 90 {
		t.Fatal("overrides must not be learned away")
	}
}

func TestSeverityBands(t *testing.T) {
	for risk, want := range map[int]string{0: "low", 24: "low", 25: "medium", 49: "medium", 50: "high", 74: "high", 75: "critical", 100: "critical"} {
		if got := Severity(risk); got != want {
			t.Errorf("%d: %s want %s", risk, got, want)
		}
	}
}

func TestSingleIntrusionSignalIsAtLeastMedium(t *testing.T) {
	one := StageScores([]Finding{{Stage: "access", Points: 15}}, 1)
	if b := Score(one, Initial(), Facts{}); b.Risk >= 25 {
		t.Fatalf("plain single finding should stay low, got %d", b.Risk)
	}
	if b := Score(one, Initial(), Facts{ConfirmedExploit: true}); b.Risk < 35 || Severity(b.Risk) != "medium" || *b.Override != "confirmed_exploit_attempt" {
		t.Fatalf("confirmed exploit: risk %d override %v", b.Risk, b.Override)
	}
	if b := Score(StageScores(nil, 1), Initial(), Facts{HoneyfileRead: true}); b.Risk < 40 {
		t.Fatalf("honeyfile read: risk %d", b.Risk)
	}
	if b := Score(one, Initial(), Facts{ConfirmedExploit: true, MaxUsedTokenSensitivity: 5}); b.Risk != 90 {
		t.Fatalf("token used must still win: %d", b.Risk)
	}
}
