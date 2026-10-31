package alert

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/dto"
)

func TestPayloadShapeDiscord(t *testing.T) {
	var got discordPayload
	var mu sync.Mutex

	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		mu.Lock()
		_ = json.Unmarshal(body, &got)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	n := NewNotifier(Config{
		DiscordURL:   discordSrv.URL,
		DashboardURL: "http://soc.local:3000",
		InitialBackoff: 5 * time.Millisecond,
	})

	inc := Incident{
		IncidentID: "c1f-test-1",
		ActorID:    "act-1",
		ActorLabel: "ACT-0007",
		Severity:   "critical",
		Title:      "Token stolen and used against beacon",
		RiskScore:  85,
	}
	act := dto.ActorSummary{
		ActorID:        "act-1",
		Label:          "ACT-0007",
		Severity:       "critical",
		RiskScore:      85,
		BehaviourClass: "agent-like",
		Services:       []string{"ssh", "web", "beacon"},
	}

	err := n.DispatchSync(context.Background(), ImmediateAll, inc, act)
	if err != nil {
		t.Fatalf("DispatchSync failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if got.Content != "@here" {
		t.Errorf("expected content @here for critical, got %q", got.Content)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("expected 1 embed, got %d", len(got.Embeds))
	}
	emb := got.Embeds[0]
	if !strings.HasPrefix(emb.Title, "CRITICAL — ") {
		t.Errorf("expected title to start with 'CRITICAL — ', got %q", emb.Title)
	}
	if emb.Color != Colour("critical") {
		t.Errorf("expected color %d, got %d", Colour("critical"), emb.Color)
	}
	if emb.URL != "http://soc.local:3000/incidents/c1f-test-1" {
		t.Errorf("unexpected url %q", emb.URL)
	}

	// Verify fields
	fieldMap := map[string]string{}
	for _, f := range emb.Fields {
		fieldMap[f.Name] = f.Value
	}
	if fieldMap["Risk"] != "85 / 100" {
		t.Errorf("expected Risk field '85 / 100', got %q", fieldMap["Risk"])
	}
	if fieldMap["Behaviour"] != "agent-like" {
		t.Errorf("expected Behaviour 'agent-like', got %q", fieldMap["Behaviour"])
	}
	if fieldMap["Services"] != "ssh, web, beacon" {
		t.Errorf("expected Services 'ssh, web, beacon', got %q", fieldMap["Services"])
	}
	if !strings.Contains(emb.Footer.Text, "Deception SOC · lab environment") {
		t.Errorf("unexpected footer %q", emb.Footer.Text)
	}
}

func TestPayloadShapeSlack(t *testing.T) {
	var got slackPayload
	var mu sync.Mutex

	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		mu.Lock()
		_ = json.Unmarshal(body, &got)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer slackSrv.Close()

	n := NewNotifier(Config{
		SlackURL:     slackSrv.URL,
		DashboardURL: "http://soc.local:3000",
		InitialBackoff: 5 * time.Millisecond,
	})

	inc := Incident{
		IncidentID: "c1f-test-2",
		ActorID:    "act-2",
		ActorLabel: "ACT-0008",
		Severity:   "critical",
		Title:      "Plant deploy key used",
		RiskScore:  90,
	}
	act := dto.ActorSummary{
		ActorID:        "act-2",
		Label:          "ACT-0008",
		Severity:       "critical",
		RiskScore:      90,
		BehaviourClass: "scripted",
		Services:       []string{"ssh"},
	}

	err := n.DispatchSync(context.Background(), ImmediateAll, inc, act)
	if err != nil {
		t.Fatalf("DispatchSync failed: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()

	if len(got.Blocks) < 4 {
		t.Fatalf("expected at least 4 blocks, got %d", len(got.Blocks))
	}
	// Header block
	if got.Blocks[0].Type != "header" || !strings.HasPrefix(got.Blocks[0].Text.Text, "CRITICAL — ") {
		t.Errorf("expected header block with 'CRITICAL — ', got %+v", got.Blocks[0])
	}
	// Section block
	if got.Blocks[1].Type != "section" {
		t.Errorf("expected section block, got %s", got.Blocks[1].Type)
	}
	// Fields block
	if got.Blocks[2].Type != "section" || len(got.Blocks[2].Fields) == 0 {
		t.Errorf("expected section with fields, got %+v", got.Blocks[2])
	}
	// Context block
	if got.Blocks[3].Type != "context" || len(got.Blocks[3].Elements) == 0 {
		t.Errorf("expected context block with elements, got %+v", got.Blocks[3])
	}
	if !strings.Contains(got.Blocks[3].Elements[0].Text, "http://soc.local:3000/incidents/c1f-test-2") {
		t.Errorf("expected dashboard url in context, got %q", got.Blocks[3].Elements[0].Text)
	}
}

func TestNoMentionInjection(t *testing.T) {
	var gotDiscord discordPayload
	var mu sync.Mutex

	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		_ = json.Unmarshal(body, &gotDiscord)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	n := NewNotifier(Config{
		DiscordURL:   discordSrv.URL,
		DashboardURL: "http://localhost:3000",
		InitialBackoff: 5 * time.Millisecond,
	})

	// Case 1: High severity with mention injection in title
	incHigh := Incident{
		IncidentID: "inc-high",
		ActorID:    "act-1",
		ActorLabel: "ACT-0001",
		Severity:   "high",
		Title:      "Injected @everyone and @here and <@123456> attack <!channel>",
		RiskScore:  60,
	}
	actHigh := dto.ActorSummary{
		ActorID:   "act-1",
		Label:     "ACT-0001",
		Severity:  "high",
		RiskScore: 60,
	}

	err := n.DispatchSync(context.Background(), Immediate, incHigh, actHigh)
	if err != nil {
		t.Fatalf("DispatchSync failed: %v", err)
	}

	mu.Lock()
	rawJSON, _ := json.Marshal(gotDiscord)
	mu.Unlock()

	rawStr := string(rawJSON)
	if strings.Contains(rawStr, "@everyone") {
		t.Errorf("payload contains injected @everyone: %s", rawStr)
	}
	if strings.Contains(rawStr, "@here") {
		t.Errorf("high severity payload contains @here: %s", rawStr)
	}
	if strings.Contains(rawStr, "<@123456>") {
		t.Errorf("payload contains user mention <@123456>: %s", rawStr)
	}
	if strings.Contains(rawStr, "<!channel>") {
		t.Errorf("payload contains slack mention <!channel>: %s", rawStr)
	}

	// Case 2: Critical severity - @here is allowed ONLY in content, nowhere in embeds
	incCrit := Incident{
		IncidentID: "inc-crit",
		ActorID:    "act-2",
		ActorLabel: "ACT-0002",
		Severity:   "critical",
		Title:      "Malicious title @everyone and @here and @attacker",
		RiskScore:  95,
	}
	actCrit := dto.ActorSummary{
		ActorID:   "act-2",
		Label:     "ACT-0002",
		Severity:  "critical",
		RiskScore: 95,
	}

	err = n.DispatchSync(context.Background(), ImmediateAll, incCrit, actCrit)
	if err != nil {
		t.Fatalf("DispatchSync critical failed: %v", err)
	}

	mu.Lock()
	embJSON, _ := json.Marshal(gotDiscord.Embeds)
	mu.Unlock()

	embStr := string(embJSON)
	if strings.Contains(embStr, "@everyone") {
		t.Errorf("embeds contains @everyone: %s", embStr)
	}
	if strings.Contains(embStr, "@here") {
		t.Errorf("embeds contains @here: %s", embStr)
	}
	if gotDiscord.Content != "@here" {
		t.Errorf("expected root content to be @here for critical, got %q", gotDiscord.Content)
	}
}

func TestRetriesWithBackoff(t *testing.T) {
	var attempts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cur := atomic.AddInt32(&attempts, 1)
		if cur < 3 {
			http.Error(w, "transient error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	n := NewNotifier(Config{
		DiscordURL:     srv.URL,
		InitialBackoff: 5 * time.Millisecond,
	})

	inc := Incident{
		IncidentID: "inc-retry",
		ActorID:    "act-retry",
		Severity:   "high",
		Title:      "Retry test",
	}
	act := dto.ActorSummary{ActorID: "act-retry", Severity: "high"}

	err := n.DispatchSync(context.Background(), Immediate, inc, act)
	if err != nil {
		t.Fatalf("expected dispatch to succeed after retries, got %v", err)
	}

	if atomic.LoadInt32(&attempts) != 3 {
		t.Errorf("expected exactly 3 attempts, got %d", atomic.LoadInt32(&attempts))
	}

	// Always failing server - should exhaust 3 retries (4 total attempts)
	var failAttempts int32
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&failAttempts, 1)
		http.Error(w, "always fail", http.StatusInternalServerError)
	}))
	defer failSrv.Close()

	nFail := NewNotifier(Config{
		DiscordURL:     failSrv.URL,
		InitialBackoff: 2 * time.Millisecond,
	})

	err = nFail.DispatchSync(context.Background(), Immediate, inc, act)
	if err == nil {
		t.Fatalf("expected error from exhausted retries, got nil")
	}
	if atomic.LoadInt32(&failAttempts) != 4 {
		t.Errorf("expected 4 total attempts (initial + 3 retries), got %d", atomic.LoadInt32(&failAttempts))
	}
}

func TestMediumDigest(t *testing.T) {
	var got discordPayload
	var calls int32

	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	n := NewNotifier(Config{
		DiscordURL:   discordSrv.URL,
		DashboardURL: "http://soc.local:3000",
	})

	inc1 := Incident{IncidentID: "med-1", ActorLabel: "ACT-0001", Severity: "medium", Title: "Port scan"}
	act1 := dto.ActorSummary{ActorID: "act-1", Label: "ACT-0001", Severity: "medium"}

	inc2 := Incident{IncidentID: "med-2", ActorLabel: "ACT-0002", Severity: "medium", Title: "Fake login try"}
	act2 := dto.ActorSummary{ActorID: "act-2", Label: "ACT-0002", Severity: "medium"}

	// Dispatching medium should NOT send immediately
	_ = n.DispatchSync(context.Background(), Digest, inc1, act1)
	_ = n.DispatchSync(context.Background(), Digest, inc2, act2)

	if atomic.LoadInt32(&calls) != 0 {
		t.Fatalf("expected 0 immediate webhook calls for digest items, got %d", atomic.LoadInt32(&calls))
	}

	// Flush digest
	err := n.FlushDigest(context.Background())
	if err != nil {
		t.Fatalf("FlushDigest failed: %v", err)
	}

	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("expected 1 webhook call after FlushDigest, got %d", atomic.LoadInt32(&calls))
	}

	if got.Content != "" {
		t.Errorf("expected no @here in digest content, got %q", got.Content)
	}
	if len(got.Embeds) != 1 {
		t.Fatalf("expected 1 digest embed, got %d", len(got.Embeds))
	}
	emb := got.Embeds[0]
	if !strings.Contains(emb.Title, "MEDIUM DIGEST — 2 new incidents") {
		t.Errorf("unexpected digest title %q", emb.Title)
	}
	if emb.Color != Colour("medium") {
		t.Errorf("expected color %d, got %d", Colour("medium"), emb.Color)
	}
	if !strings.Contains(emb.Description, "med-1") || !strings.Contains(emb.Description, "med-2") {
		t.Errorf("digest description missing incident IDs: %s", emb.Description)
	}
}

func TestHighSeverityDiscordOnly(t *testing.T) {
	var discordCalls int32
	var slackCalls int32

	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&discordCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&slackCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackSrv.Close()

	n := NewNotifier(Config{
		DiscordURL: discordSrv.URL,
		SlackURL:   slackSrv.URL,
		InitialBackoff: 5 * time.Millisecond,
	})

	inc := Incident{IncidentID: "high-1", Severity: "high", Title: "Suspicious probe"}
	act := dto.ActorSummary{ActorID: "act-h", Severity: "high"}

	err := n.DispatchSync(context.Background(), Immediate, inc, act)
	if err != nil {
		t.Fatalf("DispatchSync failed: %v", err)
	}

	if atomic.LoadInt32(&discordCalls) != 1 {
		t.Errorf("expected 1 Discord call, got %d", atomic.LoadInt32(&discordCalls))
	}
	if atomic.LoadInt32(&slackCalls) != 0 {
		t.Errorf("expected 0 Slack calls for high severity, got %d", atomic.LoadInt32(&slackCalls))
	}
}

func TestAsyncQueue(t *testing.T) {
	var discordCalls int32
	var slackCalls int32

	discordSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&discordCalls, 1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer discordSrv.Close()

	slackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&slackCalls, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer slackSrv.Close()

	n := NewNotifier(Config{
		DiscordURL:     discordSrv.URL,
		SlackURL:       slackSrv.URL,
		InitialBackoff: 5 * time.Millisecond,
		DigestInterval: 1 * time.Hour,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go n.Run(ctx)

	inc := Incident{IncidentID: "async-crit", Severity: "critical", Title: "Critical async alert"}
	act := dto.ActorSummary{ActorID: "act-async", Severity: "critical"}

	// Notify must be non-blocking and return nil immediately
	start := time.Now()
	err := n.Notify(ctx, ImmediateAll, inc, act)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if elapsed > 50*time.Millisecond {
		t.Errorf("Notify took too long (%v), expected non-blocking", elapsed)
	}

	// Wait up to 2 seconds for worker to process
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&discordCalls) == 1 && atomic.LoadInt32(&slackCalls) == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if atomic.LoadInt32(&discordCalls) != 1 {
		t.Errorf("expected 1 Discord call, got %d", atomic.LoadInt32(&discordCalls))
	}
	if atomic.LoadInt32(&slackCalls) != 1 {
		t.Errorf("expected 1 Slack call, got %d", atomic.LoadInt32(&slackCalls))
	}
}

// TestWebhookMockIntegration tests against the webhook-mock server pattern (docs/09, cmd/webhook-mock).
func TestWebhookMockIntegration(t *testing.T) {
	var mu sync.Mutex
	var got []json.RawMessage

	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET /received", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})

	mockSrv := httptest.NewServer(mux)
	defer mockSrv.Close()

	n := NewNotifier(Config{
		DiscordURL:     mockSrv.URL + "/discord",
		SlackURL:       mockSrv.URL + "/slack",
		DashboardURL:   "http://localhost:3000",
		InitialBackoff: 5 * time.Millisecond,
	})

	inc := Incident{
		IncidentID: "crit-mock-1",
		ActorID:    "act-007",
		ActorLabel: "ACT-0007",
		Severity:   "critical",
		Title:      "Token stolen and used",
		RiskScore:  92,
	}
	act := dto.ActorSummary{
		ActorID:        "act-007",
		Label:          "ACT-0007",
		Severity:       "critical",
		RiskScore:      92,
		BehaviourClass: "agent-like",
		Services:       []string{"web", "ssh", "beacon"},
	}

	// Dispatch critical incident
	err := n.DispatchSync(context.Background(), ImmediateAll, inc, act)
	if err != nil {
		t.Fatalf("DispatchSync failed: %v", err)
	}

	// Query /received from webhook-mock
	resp, err := http.Get(mockSrv.URL + "/received")
	if err != nil {
		t.Fatalf("failed to query mock /received: %v", err)
	}
	defer resp.Body.Close()

	var received []json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&received); err != nil {
		t.Fatalf("failed to decode received messages: %v", err)
	}

	// Must produce exactly one Discord and one Slack message
	if len(received) != 2 {
		t.Fatalf("expected 2 received messages (1 Discord + 1 Slack), got %d", len(received))
	}

	// Inspect messages
	var hasDiscord, hasSlack bool
	for _, raw := range received {
		s := string(raw)
		if strings.Contains(s, `"embeds"`) && strings.Contains(s, `"@here"`) {
			hasDiscord = true
		}
		if strings.Contains(s, `"blocks"`) && strings.Contains(s, `"header"`) {
			hasSlack = true
		}
	}
	if !hasDiscord {
		t.Errorf("webhook-mock did not receive expected Discord payload with @here")
	}
	if !hasSlack {
		t.Errorf("webhook-mock did not receive expected Slack payload with blocks")
	}
}

func TestLiveWebhooksManual(t *testing.T) {
	if os.Getenv("TEST_LIVE_WEBHOOKS") != "1" {
		t.Skip("skipping manual live webhook test")
	}
	discordURL := os.Getenv("DISCORD_WEBHOOK_URL")
	slackURL := os.Getenv("SLACK_WEBHOOK_URL")
	if discordURL == "" || slackURL == "" {
		t.Skip("skipping manual live webhook test: DISCORD_WEBHOOK_URL or SLACK_WEBHOOK_URL not set")
	}

	n := NewNotifier(Config{
		DiscordURL:   discordURL,
		SlackURL:     slackURL,
		DashboardURL: "http://localhost:3000",
	})

	inc := Incident{
		IncidentID: "c1f-live-test",
		ActorID:    "act-0007",
		ActorLabel: "ACT-0007",
		Severity:   "critical",
		Title:      "Plant cloud key used against beacon endpoint",
		RiskScore:  88,
	}

	act := dto.ActorSummary{
		ActorID:        "act-0007",
		Label:          "ACT-0007",
		Severity:       "critical",
		RiskScore:      88,
		BehaviourClass: "agent-like",
		Services:       []string{"web", "ssh", "k8s", "beacon"},
	}

	err := n.DispatchSync(context.Background(), ImmediateAll, inc, act)
	if err != nil {
		t.Fatalf("live webhook dispatch failed: %v", err)
	}
}
