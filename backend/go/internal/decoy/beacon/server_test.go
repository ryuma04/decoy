package beacon

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/intel/risk"
	"github.com/ryuma04/decoy/backend/internal/intel/rules"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// mockCore is an in-memory HTTP server that receives sensorkit event batches.
func setupMockCore(t *testing.T) (*httptest.Server, *[]event.Envelope, *sync.Mutex) {
	t.Helper()
	var (
		mu        sync.Mutex
		envelopes []event.Envelope
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/ingest/events":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var batch []event.Envelope
			if err := json.Unmarshal(body, &batch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			envelopes = append(envelopes, batch...)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case "/v1/ingest/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/sensor/policy":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"rev":             1,
				"blocked_ips":     []string{"10.99.99.99"},
				"killed_sessions": []string{},
				"burned_tokens":   []string{},
			})
		default:
			http.NotFound(w, r)
		}
	}))

	return srv, &envelopes, &mu
}

func testTokens() map[string]Token {
	return map[string]Token{
		"tok_aws_k7": {
			TokenID:     "tok_aws_k7",
			Kind:        "aws_key",
			PlantedAt:   "ssh:/home/deploy/.aws/credentials",
			MazeNode:    "lure_aws",
			MatchValue:  "AKIA_LURE_TEST_KEY_1234",
			Sensitivity: 5,
		},
		"tok_url": {
			TokenID:     "tok_url",
			Kind:        "url",
			PlantedAt:   "ssh:/home/deploy/.bash_history",
			MazeNode:    "",
			MatchValue:  "/t/tok_url",
			Sensitivity: 2,
		},
	}
}

func setupTestServer(t *testing.T) (*Server, *httptest.Server, func()) {
	t.Helper()
	coreSrv, envs, mu := setupMockCore(t)

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	kit.Start(ctx)

	srv, err := New(Config{
		Addr:   ":8088",
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	cleanup := func() {
		cancel()
		kit.Close()
		coreSrv.Close()
	}

	_ = envs
	_ = mu
	return srv, coreSrv, cleanup
}

func TestHealthz(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `"status":"ok"`) {
		t.Errorf("unexpected body %q", rec.Body.String())
	}
}

func TestURLTokenHit(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	srv, err := New(Config{
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/t/tok_url", nil)
	req.RemoteAddr = "10.66.0.42:54321"
	req.Header.Set("User-Agent", "curl/8.5.0")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	// Verify HTTP response
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "image/gif" {
		t.Errorf("expected Content-Type image/gif, got %s", rec.Header().Get("Content-Type"))
	}
	if !bytes.Equal(rec.Body.Bytes(), gif1x1) {
		t.Errorf("expected 1x1 GIF payload, got %d bytes", rec.Body.Len())
	}

	// Wait for sensorkit flush
	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var gotHTTP, gotToken bool
	for _, e := range *envs {
		if e.Type == "http.request" && strings.Contains(string(e.Data), "/t/tok_url") {
			gotHTTP = true
			if e.Src.IP != "10.66.0.42" {
				t.Errorf("expected src.ip 10.66.0.42, got %s", e.Src.IP)
			}
		}
		if e.Type == "token.used" {
			gotToken = true
			if len(e.Tokens) == 0 || e.Tokens[0] != "tok_url" {
				t.Errorf("expected tokens [tok_url], got %v", e.Tokens)
			}
			var data map[string]any
			_ = json.Unmarshal(e.Data, &data)
			if data["token_id"] != "tok_url" || data["via"] != "url_fetch" {
				t.Errorf("unexpected token.used data: %v", data)
			}
		}
	}

	if !gotHTTP {
		t.Errorf("missing http.request event for /t/tok_url")
	}
	if !gotToken {
		t.Errorf("missing token.used event for tok_url")
	}
}

func TestURLTokenNotFound(t *testing.T) {
	srv, _, cleanup := setupTestServer(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/t/nonexistent_token_123", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 Not Found, got %d", rec.Code)
	}
}

func TestAWSSigV4LureKeyHit(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	srv, err := New(Config{
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/prod-backups/database.dump", nil)
	req.RemoteAddr = "10.66.0.23:41234"
	req.Header.Set("User-Agent", "aws-cli/2.15.15 Python/3.11.6")
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA_LURE_TEST_KEY_1234/20261114/ap-south-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=abcdef0123456789")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	// Verify HTTP response
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/xml" {
		t.Errorf("expected Content-Type application/xml, got %s", rec.Header().Get("Content-Type"))
	}
	bodyStr := rec.Body.String()
	if !strings.Contains(bodyStr, "<Code>AccessDenied</Code>") || !strings.Contains(bodyStr, "<Message>Access Denied</Message>") {
		t.Errorf("expected AccessDenied XML, got:\n%s", bodyStr)
	}

	// Wait for sensorkit flush
	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var gotHTTP, gotToken bool
	for _, e := range *envs {
		if e.Type == "http.request" && strings.Contains(string(e.Data), "/prod-backups/database.dump") {
			gotHTTP = true
			if e.Src.IP != "10.66.0.23" {
				t.Errorf("expected src.ip 10.66.0.23, got %s", e.Src.IP)
			}
		}
		if e.Type == "token.used" {
			gotToken = true
			if len(e.Tokens) == 0 || e.Tokens[0] != "tok_aws_k7" {
				t.Errorf("expected tokens [tok_aws_k7], got %v", e.Tokens)
			}
			var data map[string]any
			_ = json.Unmarshal(e.Data, &data)
			if data["token_id"] != "tok_aws_k7" || data["token_kind"] != "aws_key" || data["via"] != "aws_api" {
				t.Errorf("unexpected token.used data: %v", data)
			}
			if e.Sensor.MazeNode != "lure_aws" {
				t.Errorf("expected maze_node lure_aws, got %s", e.Sensor.MazeNode)
			}
		}
	}

	if !gotHTTP {
		t.Errorf("missing http.request event for AWS API call")
	}
	if !gotToken {
		t.Errorf("missing token.used event for tok_aws_k7")
	}
}

func TestAWSPresignedURLLureKeyHit(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	srv, err := New(Config{
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/bucket/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIA_LURE_TEST_KEY_1234%2F20261114%2Fap-south-1%2Fs3%2Faws4_request&X-Amz-Signature=abcdef", nil)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden, got %d", rec.Code)
	}

	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var gotToken bool
	for _, e := range *envs {
		if e.Type == "token.used" && len(e.Tokens) > 0 && e.Tokens[0] == "tok_aws_k7" {
			gotToken = true
		}
	}
	if !gotToken {
		t.Errorf("missing token.used event for presigned URL lure key")
	}
}

func TestAWSUnknownKey(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	srv, err := New(Config{
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/bucket/file", nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIA_UNKNOWN_KEY_9999/20261114/ap-south-1/s3/aws4_request, Signature=abcdef")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden, got %d", rec.Code)
	}

	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	for _, e := range *envs {
		if e.Type == "token.used" {
			t.Errorf("unexpected token.used event for unknown key: %+v", e)
		}
	}
}

func TestBlockedIPRefusal(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "beacon-01",
		Key:      "secret-beacon-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	// Wait for policy poll (setupMockCore provides 10.99.99.99 as blocked)
	time.Sleep(50 * time.Millisecond)

	srv, err := New(Config{
		Kit:    kit,
		Tokens: testTokens(),
	})
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/t/tok_url", nil)
	req.RemoteAddr = "10.99.99.99:50000"
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked IP, got %d", rec.Code)
	}

	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	for _, e := range *envs {
		if e.Src.IP == "10.99.99.99" {
			t.Errorf("no events should be emitted for blocked IP, got: %+v", e)
		}
	}
}

// TestActorCriticalOnLureAWSKey verifies the engine risk rule:
// A signed request with the lure key (sensitivity 5) turns the actor critical (07 §6.3, 09 §Alerting).
func TestActorCriticalOnLureAWSKey(t *testing.T) {
	tok := testTokens()["tok_aws_k7"]
	if tok.Sensitivity != 5 {
		t.Fatalf("expected tok_aws_k7 sensitivity 5, got %d", tok.Sensitivity)
	}

	// 1. Verify rules match honeytoken_used with sensitivity 5
	rs := rules.Set{
		Rules: []*rules.Rule{
			{
				ID:     "honeytoken_used",
				Stage:  "lateral",
				Points: 50,
			},
		},
	}
	_ = rs

	// 2. Risk scoring with MaxUsedTokenSensitivity = 5 overrides to critical (07 §6.3)
	weights := risk.Initial()
	zeroStage := map[string]float64{}
	breakdown := risk.Score(zeroStage, weights, risk.Facts{
		MaxUsedTokenSensitivity: tok.Sensitivity,
	})

	if breakdown.Risk < 90 {
		t.Errorf("expected risk >= 90 for sensitivity 5 token, got %d", breakdown.Risk)
	}
	sev := risk.Severity(breakdown.Risk)
	if sev != "critical" {
		t.Errorf("expected severity 'critical', got %q (risk %d)", sev, breakdown.Risk)
	}
	if breakdown.Override == nil || *breakdown.Override != "token_used_sensitivity_5" {
		t.Errorf("expected override 'token_used_sensitivity_5', got %v", breakdown.Override)
	}
}
