package features

import (
	"encoding/json"
	"math"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/intel/behaviour"
	"github.com/ryuma04/decoy/backend/internal/intel/rules"
	"github.com/ryuma04/decoy/backend/internal/store"
)

func TestAuthFeatures(t *testing.T) {
	p := New()
	now := time.Now()

	actorID := "act-01"
	sessID := "sess-01"

	// 1. Successful auth
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "auth.attempt",
		TS:        now.Add(-6 * time.Minute),
		Data:      json.RawMessage(`{"username":"deploy","password":"pw1","success":true}`),
	})

	// 2. Failed auth (older than 5 min)
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "auth.attempt",
		TS:        now.Add(-6 * time.Minute),
		Data:      json.RawMessage(`{"username":"root","password":"bad1","success":false}`),
	})

	// 3-7. 5 failed auths within 5 min
	for i := 0; i < 5; i++ {
		p.Observe(store.StoredEvent{
			SessionID: sessID,
			ActorID:   &actorID,
			Type:      "auth.attempt",
			TS:        now.Add(-time.Duration(4-i) * time.Minute),
			Data:      json.RawMessage(`{"username":"admin","password":"p` + string(rune('a'+i)) + `","success":false}`),
		})
	}

	sf := p.Session(sessID)
	if sf["successful_logins"] != 1 {
		t.Errorf("successful_logins: got %v, want 1", sf["successful_logins"])
	}
	if sf["failed_auths_5m"] != 5 {
		t.Errorf("failed_auths_5m: got %v, want 5", sf["failed_auths_5m"])
	}
	// Distinct pairs: deploy:pw1, root:bad1, admin:pa, admin:pb, admin:pc, admin:pd, admin:pe -> 7
	if sf["distinct_pairs"] != 7 {
		t.Errorf("distinct_pairs: got %v, want 7", sf["distinct_pairs"])
	}

	af := p.Actor(actorID)
	if af["failed_auths_5m"] != 5 {
		t.Errorf("actor failed_auths_5m: got %v, want 5", af["failed_auths_5m"])
	}
	if af["distinct_pairs"] != 7 {
		t.Errorf("actor distinct_pairs: got %v, want 7", af["distinct_pairs"])
	}
}

func TestCommandAndTimingFeatures(t *testing.T) {
	p := New()
	now := time.Now()
	actorID := "act-02"
	sessID := "sess-02"

	// 4 commands with timings:
	// 1: since_prev=1000, keystrokes=5, edits=0, paste=false
	// 2: since_prev=2000, keystrokes=10, edits=1, paste=false
	// 3: since_prev=3000, keystrokes=20, edits=0, paste=true
	// 4: since_prev=4000, keystrokes=20, edits=2, paste=true
	timings := []event.Timing{
		{SincePrevMS: 1000, Keystrokes: 5, Edits: 0, Paste: false},
		{SincePrevMS: 2000, Keystrokes: 10, Edits: 1, Paste: false},
		{SincePrevMS: 3000, Keystrokes: 20, Edits: 0, Paste: true},
		{SincePrevMS: 4000, Keystrokes: 20, Edits: 2, Paste: true},
	}

	for i, tm := range timings {
		envBytes, _ := json.Marshal(map[string]any{"timing": tm})
		p.Observe(store.StoredEvent{
			SessionID: sessID,
			ActorID:   &actorID,
			Type:      "shell.command",
			Service:   "ssh",
			TS:        now.Add(time.Duration(i) * time.Second),
			Envelope:  envBytes,
			Data:      json.RawMessage(`{"argv0":"ls","raw":"ls -la"}`),
		})
	}

	af := p.Actor(actorID)
	if af["commands"] != 4 {
		t.Errorf("commands: got %v, want 4", af["commands"])
	}

	// Gaps: [1000, 2000, 3000, 4000] -> median is (2000+3000)/2 = 2500
	if af["median_gap_ms"] != 2500 {
		t.Errorf("median_gap_ms: got %v, want 2500", af["median_gap_ms"])
	}

	// CV = std / mean
	// mean = 2500
	// variance = ((1000-2500)^2 + (2000-2500)^2 + (3000-2500)^2 + (4000-2500)^2) / 3 = (2250000 + 250000 + 250000 + 2250000) / 3 = 5000000 / 3 = 1666666.67
	// std = sqrt(1666666.67) = 1290.99
	// cv = 1290.99 / 2500 = 0.516 -> 0.52
	if math.Abs(af["gap_cv"]-0.52) > 0.02 {
		t.Errorf("gap_cv: got %v, want ~0.52", af["gap_cv"])
	}

	// Edit rate: 2 out of 4 lines had edits -> 0.5
	if af["edit_rate"] != 0.5 {
		t.Errorf("edit_rate: got %v, want 0.5", af["edit_rate"])
	}

	// Paste rate: 2 out of 4 lines had paste -> 0.5
	if af["paste_rate"] != 0.5 {
		t.Errorf("paste_rate: got %v, want 0.5", af["paste_rate"])
	}
}

func TestOutputDependence(t *testing.T) {
	p := New()
	now := time.Now()
	actorID := "act-03"
	sessID := "sess-03"

	// Command 1: outputs tokens "target.txt", "notes.md"
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now,
		Data:      json.RawMessage(`{"argv0":"ls","raw":"ls","stdout_tokens":["target.txt","notes.md"]}`),
	})

	// Command 2: uses "target.txt" (hit!)
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now.Add(time.Second),
		Data:      json.RawMessage(`{"argv0":"cat","args":["target.txt"],"raw":"cat target.txt","stdout_tokens":["secret123"]}`),
	})

	// Command 3: does not use secret123 (miss)
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now.Add(2 * time.Second),
		Data:      json.RawMessage(`{"argv0":"whoami","raw":"whoami","stdout_tokens":["deploy"]}`),
	})

	af := p.Actor(actorID)
	// Out of 2 eligible subsequent commands, 1 had output dependence -> 0.5
	if af["output_dependence"] != 0.5 {
		t.Errorf("output_dependence: got %v, want 0.5", af["output_dependence"])
	}
}

func TestBreadcrumbsFollowed(t *testing.T) {
	p := New()
	now := time.Now()
	actorID := "act-04"
	sessID := "sess-04"

	// 1. Read honeyfile tok_aws_k7
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "file.read",
		TS:        now,
		Data:      json.RawMessage(`{"path":"/home/deploy/.aws/credentials","honeyfile_id":"tok_aws_k7"}`),
	})

	// 2. Read honeyfile tok_kube
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "file.read",
		TS:        now.Add(time.Second),
		Data:      json.RawMessage(`{"path":"/opt/deploy/kubeconfig","honeyfile_id":"tok_kube"}`),
	})

	// 3. Token used for tok_aws_k7
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "token.used",
		TS:        now.Add(2 * time.Second),
		Data:      json.RawMessage(`{"token_id":"tok_aws_k7","token_kind":"aws_key"}`),
	})

	af := p.Actor(actorID)
	if af["breadcrumbs_followed"] != 1 {
		t.Errorf("breadcrumbs_followed: got %v, want 1", af["breadcrumbs_followed"])
	}

	// 4. Token used for tok_kube -> breadcrumbs becomes 2
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "token.used",
		TS:        now.Add(3 * time.Second),
		Data:      json.RawMessage(`{"token_id":"tok_kube","token_kind":"kubeconfig"}`),
	})

	af = p.Actor(actorID)
	if af["breadcrumbs_followed"] != 2 {
		t.Errorf("breadcrumbs_followed: got %v, want 2", af["breadcrumbs_followed"])
	}
}

func TestParamMutationRetries(t *testing.T) {
	p := New()
	now := time.Now()
	actorID := "act-05"
	sessID := "sess-05"

	// Command 1: cat missing1.txt fails (exit: 1)
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now,
		Data:      json.RawMessage(`{"argv0":"cat","args":["missing1.txt"],"exit":1}`),
	})

	// Command 2: same argv0 "cat" retried with "missing2.txt" -> mutation retry!
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now.Add(time.Second),
		Data:      json.RawMessage(`{"argv0":"cat","args":["missing2.txt"],"exit":1}`),
	})

	// Command 3: same argv0 "cat" retried with "valid.txt" -> mutation retry #2
	p.Observe(store.StoredEvent{
		SessionID: sessID,
		ActorID:   &actorID,
		Type:      "shell.command",
		TS:        now.Add(2 * time.Second),
		Data:      json.RawMessage(`{"argv0":"cat","args":["valid.txt"],"exit":0}`),
	})

	af := p.Actor(actorID)
	if af["param_mutation_retries"] != 2 {
		t.Errorf("param_mutation_retries: got %v, want 2", af["param_mutation_retries"])
	}
}

func TestMultiSessionActorAggregation(t *testing.T) {
	p := New()
	now := time.Now()
	actorID := "act-06"

	// Session 1 on SSH
	p.Observe(store.StoredEvent{
		SessionID: "sess-ssh",
		ActorID:   &actorID,
		Type:      "shell.command",
		Service:   "ssh",
		TS:        now,
		Data:      json.RawMessage(`{"argv0":"id","raw":"id"}`),
	})

	// Session 2 on Web
	p.Observe(store.StoredEvent{
		SessionID: "sess-web",
		ActorID:   &actorID,
		Type:      "http.request",
		Service:   "web",
		TS:        now.Add(time.Second),
		Data:      json.RawMessage(`{"method":"GET","path":"/admin"}`),
	})

	// Session 3 on K8s (correlated later via Associate)
	p.Observe(store.StoredEvent{
		SessionID: "sess-k8s",
		Type:      "k8s.api_call",
		Service:   "k8s",
		TS:        now.Add(2 * time.Second),
		Data:      json.RawMessage(`{"verb":"list","resource":"pods"}`),
	})
	p.Associate("sess-k8s", actorID)

	af := p.Actor(actorID)
	if af["commands"] != 3 {
		t.Errorf("commands: got %v, want 3", af["commands"])
	}
	if af["services_visited"] != 3 {
		t.Errorf("services_visited: got %v, want 3", af["services_visited"])
	}
}

func TestRulesFireFromFeatures(t *testing.T) {
	ruleSet, err := rules.Load("../../../rules/rules.yaml")
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}

	p := New()
	now := time.Now()
	actorID := "act-rules"
	sessID := "sess-guess"

	// 1. Password guessing rule: 5 failed auths in 5m
	for i := 0; i < 5; i++ {
		p.Observe(store.StoredEvent{
			SessionID: sessID,
			ActorID:   &actorID,
			Type:      "auth.attempt",
			Service:   "ssh",
			TS:        now.Add(time.Duration(i) * time.Second),
			Data:      json.RawMessage(`{"username":"root","password":"bad","success":false}`),
		})
	}
	sFeat := p.Session(sessID)
	sessionMatches := ruleSet.Evaluate("session", rules.Input{Features: sFeat})
	hasPasswordGuessing := false
	for _, m := range sessionMatches {
		if m.Rule.ID == "password_guessing" {
			hasPasswordGuessing = true
			break
		}
	}
	if !hasPasswordGuessing {
		t.Errorf("password_guessing rule did not fire from features: %+v", sFeat)
	}

	// 2. Interactive shell rule: successful login + 1 command
	sessShell := "sess-shell"
	p.Observe(store.StoredEvent{
		SessionID: sessShell,
		ActorID:   &actorID,
		Type:      "auth.attempt",
		Service:   "ssh",
		TS:        now.Add(10 * time.Second),
		Data:      json.RawMessage(`{"username":"deploy","password":"pw","success":true}`),
	})
	p.Observe(store.StoredEvent{
		SessionID: sessShell,
		ActorID:   &actorID,
		Type:      "shell.command",
		Service:   "ssh",
		TS:        now.Add(11 * time.Second),
		Data:      json.RawMessage(`{"argv0":"whoami","raw":"whoami"}`),
	})
	sShellFeat := p.Session(sessShell)
	shellMatches := ruleSet.Evaluate("session", rules.Input{Features: sShellFeat})
	hasInteractiveShell := false
	for _, m := range shellMatches {
		if m.Rule.ID == "interactive_shell" {
			hasInteractiveShell = true
			break
		}
	}
	if !hasInteractiveShell {
		t.Errorf("interactive_shell rule did not fire from features: %+v", sShellFeat)
	}

	// 3. Multi-decoy rule: actor active on >= 3 services
	p.Observe(store.StoredEvent{
		SessionID: "sess-web",
		ActorID:   &actorID,
		Type:      "http.request",
		Service:   "web",
		TS:        now.Add(12 * time.Second),
		Data:      json.RawMessage(`{"path":"/login"}`),
	})
	p.Observe(store.StoredEvent{
		SessionID: "sess-k8s",
		ActorID:   &actorID,
		Type:      "k8s.api_call",
		Service:   "k8s",
		TS:        now.Add(13 * time.Second),
		Data:      json.RawMessage(`{"resource":"pods"}`),
	})
	aFeat := p.Actor(actorID)
	actorMatches := ruleSet.Evaluate("actor", rules.Input{Features: aFeat})
	hasMultiDecoy := false
	for _, m := range actorMatches {
		if m.Rule.ID == "multi_decoy" {
			hasMultiDecoy = true
			break
		}
	}
	if !hasMultiDecoy {
		t.Errorf("multi_decoy rule did not fire from actor features: %+v", aFeat)
	}

	// 4. Verify behaviour classification on the actor features
	p.Observe(store.StoredEvent{
		SessionID: sessShell,
		ActorID:   &actorID,
		Type:      "shell.command",
		Service:   "ssh",
		TS:        now.Add(14 * time.Second),
		Data:      json.RawMessage(`{"argv0":"id","raw":"id"}`),
	})
	aFeat = p.Actor(actorID)
	bRes := behaviour.Classify(aFeat)
	if bRes.Class == "" {
		t.Error("expected non-empty behaviour class")
	}
	for _, k := range behaviour.FeatureNames {
		if _, ok := bRes.Features[k]; !ok {
			t.Errorf("missing behaviour feature %s", k)
		}
	}
}
