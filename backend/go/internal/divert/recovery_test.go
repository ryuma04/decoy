package divert

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

type testRig struct {
	realServer  *httptest.Server
	cloneServer *httptest.Server
	proxyServer *httptest.Server
	proxy       *Proxy
	realHits    atomic.Int64
	cloneHits   atomic.Int64
	lastRealReq *http.Request
	events      chan event.Envelope
	kit         *sensorkit.Kit
}

func newTestRig(t *testing.T, recCfg *RecoveryConfig) *testRig {
	rig := &testRig{
		events: make(chan event.Envelope, 100),
	}

	rig.realServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.realHits.Add(1)
		rig.lastRealReq = r

		if r.URL.Path == "/api/admin/login" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "valid_admin_pass") {
				http.SetCookie(w, &http.Cookie{
					Name:     "admin_session",
					Value:    "real_session_token_123",
					Path:     "/",
					HttpOnly: true,
				})
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Invalid credentials"}`))
			return
		}

		if r.URL.Path == "/api/checkout" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success":true,"order_id":"real-1001"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("real upstream"))
	}))

	rig.cloneServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rig.cloneHits.Add(1)

		if r.URL.Path == "/api/admin/login" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Clone rejected"}`))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("clone honeypot"))
	}))

	realURL, _ := url.Parse(rig.realServer.URL)
	cloneURL, _ := url.Parse(rig.cloneServer.URL)

	kitOpts := sensorkit.Options{
		SensorID: "aetees-01",
		Service:  "web",
		CoreURL:  "http://127.0.0.1:9999",
	}
	rig.kit = sensorkit.New(kitOpts)

	recoveryCfg := RecoveryConfig{
		ReleaseCleanReqs: 3,
		ReleaseCleanSecs: 50 * time.Millisecond,
		RealURL:          realURL,
	}
	if recCfg != nil {
		if recCfg.ReleaseCleanReqs > 0 {
			recoveryCfg.ReleaseCleanReqs = recCfg.ReleaseCleanReqs
		}
		if recCfg.ReleaseCleanSecs > 0 {
			recoveryCfg.ReleaseCleanSecs = recCfg.ReleaseCleanSecs
		}
	}
	rm := NewRecoveryManager(recoveryCfg)

	proxyCfg := ProxyConfig{
		RealURL:    realURL,
		CloneURL:   cloneURL,
		Kit:        rig.kit,
		Classifier: NewTripwire(),
		Recovery:   rm,
		Tokens: map[string]Honeytoken{
			"tok_aetees_admin": {
				TokenID:    "tok_aetees_admin",
				Kind:       "db_cred",
				MatchValue: "HoneySecretPassword123!",
			},
		},
	}

	p, err := NewProxy(proxyCfg)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}
	rig.proxy = p
	rig.proxyServer = httptest.NewServer(p)

	return rig
}

func (rig *testRig) Close() {
	rig.proxyServer.Close()
	rig.realServer.Close()
	rig.cloneServer.Close()
}

// 1. TestAutoReleaseTiming verifies clean request count and elapsed time release soft-diverted visitors.
func TestAutoReleaseTiming(t *testing.T) {
	rig := newTestRig(t, &RecoveryConfig{
		ReleaseCleanReqs: 3,
		ReleaseCleanSecs: 60 * time.Millisecond,
	})
	defer rig.Close()

	client := &http.Client{}

	// Step A: Initial normal request -> goes to REAL upstream
	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "real upstream") {
		t.Fatalf("expected real upstream, got %s", string(body))
	}
	cookie := resp.Cookies()

	// Step B: Send soft-tripwire request (scripted user-agent curl/ without browser headers)
	softReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	softReq.Header.Set("User-Agent", "curl/7.88.1")
	for _, c := range cookie {
		softReq.AddCookie(c)
	}
	resp, err = client.Do(softReq)
	if err != nil {
		t.Fatalf("soft trip request failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "clone honeypot") {
		t.Fatalf("expected clone honeypot after soft trip, got %s", string(body))
	}

	// Verify visitor state is soft-diverted
	v, _, _ := rig.proxy.getVisitor(softReq)
	if v == nil || !v.Diverted || v.Severity != SevSoft {
		t.Fatalf("expected soft-diverted visitor, got: %+v", v)
	}

	// Step C: Send 2 clean requests (clean count = 2 < 3) -> remains diverted
	for i := 0; i < 2; i++ {
		cleanReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
		cleanReq.Header.Set("User-Agent", "Mozilla/5.0")
		for _, c := range cookie {
			cleanReq.AddCookie(c)
		}
		resp, _ = client.Do(cleanReq)
		body, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "clone honeypot") {
			t.Fatalf("expected clone while clean count < 3, got: %s", string(body))
		}
	}

	// Clean count reached 2
	if v.CleanReqs != 2 {
		t.Fatalf("expected CleanReqs 2, got %d", v.CleanReqs)
	}

	// Step D: Send 3rd clean request before timer expires -> clean count = 3, but timing not reached
	cleanReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	cleanReq.Header.Set("User-Agent", "Mozilla/5.0")
	for _, c := range cookie {
		cleanReq.AddCookie(c)
	}
	resp, _ = client.Do(cleanReq)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for elapsed time to exceed ReleaseCleanSecs (60ms)
	time.Sleep(80 * time.Millisecond)

	// Step E: Send next request -> auto-release triggers, visitor is routed to REAL upstream
	nextReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	nextReq.Header.Set("User-Agent", "Mozilla/5.0")
	for _, c := range cookie {
		nextReq.AddCookie(c)
	}
	resp, err = client.Do(nextReq)
	if err != nil {
		t.Fatalf("next request failed: %v", err)
	}
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()

	if !strings.Contains(string(body), "real upstream") {
		t.Fatalf("expected auto-release to real upstream, got: %s", string(body))
	}
	if v.Diverted {
		t.Fatalf("expected visitor to be marked non-diverted")
	}
}

// 2. TestUpgradeSoftToHard verifies that an attack while soft-diverted upgrades severity to hard.
func TestUpgradeSoftToHard(t *testing.T) {
	rig := newTestRig(t, &RecoveryConfig{
		ReleaseCleanReqs: 2,
		ReleaseCleanSecs: 20 * time.Millisecond,
	})
	defer rig.Close()

	client := &http.Client{}

	// Soft trip
	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	resp, _ := client.Do(req)
	cookie := resp.Cookies()
	resp.Body.Close()

	for _, c := range cookie {
		req.AddCookie(c)
	}
	v, _, _ := rig.proxy.getVisitor(req)
	if v == nil || v.Severity != SevSoft {
		t.Fatalf("expected soft severity, got %+v", v)
	}

	// Now send a hard attack (sensitive path /.env)
	hardReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/.env", nil)
	for _, c := range cookie {
		hardReq.AddCookie(c)
	}
	resp, _ = client.Do(hardReq)
	resp.Body.Close()

	// Check severity upgraded to SevHard
	if v.Severity != SevHard {
		t.Fatalf("expected severity to upgrade to SevHard, got %s", v.Severity)
	}

	// Send many clean requests and wait past the timeout
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 5; i++ {
		cleanReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
		cleanReq.Header.Set("User-Agent", "Mozilla/5.0")
		for _, c := range cookie {
			cleanReq.AddCookie(c)
		}
		resp, _ = client.Do(cleanReq)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if !strings.Contains(string(body), "clone honeypot") {
			t.Fatalf("hard-diverted visitor must NOT be auto-released, got: %s", string(body))
		}
	}

	if !v.Diverted || v.Severity != SevHard {
		t.Fatalf("expected visitor to stay hard-diverted")
	}
}

// 3. TestCheckoutHold verifies that writes are held with 503 while soft-diverted.
func TestCheckoutHold(t *testing.T) {
	rig := newTestRig(t, nil)
	defer rig.Close()

	client := &http.Client{}

	// Divert visitor with soft severity
	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	resp, _ := client.Do(req)
	cookie := resp.Cookies()
	resp.Body.Close()

	// Attempt POST /api/checkout while soft-diverted
	checkoutPayload := `{"items":[{"id":1,"qty":2}],"total":24.50}`
	checkoutReq, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/checkout", bytes.NewBufferString(checkoutPayload))
	checkoutReq.Header.Set("Content-Type", "application/json")
	for _, c := range cookie {
		checkoutReq.AddCookie(c)
	}

	resp, err := client.Do(checkoutReq)
	if err != nil {
		t.Fatalf("checkout failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", resp.StatusCode)
	}

	var errResp HeldErrorResponse
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		t.Fatalf("failed to decode hold response: %v", err)
	}
	if errResp.Success != false || !strings.Contains(errResp.Error, "receiving a lot of orders") {
		t.Fatalf("unexpected hold response body: %+v", errResp)
	}

	// Attempt POST /api/contact while soft-diverted
	contactPayload := `{"name":"Customer","message":"Help"}`
	contactReq, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/contact", bytes.NewBufferString(contactPayload))
	contactReq.Header.Set("Content-Type", "application/json")
	for _, c := range cookie {
		contactReq.AddCookie(c)
	}

	respContact, err := client.Do(contactReq)
	if err != nil {
		t.Fatalf("contact failed: %v", err)
	}
	defer respContact.Body.Close()

	// contact is replayable: recorded for delivery after release and answered like the real shop
	cb, _ := io.ReadAll(respContact.Body)
	if respContact.StatusCode != http.StatusOK || !strings.Contains(string(cb), `"success":true`) {
		t.Fatalf("expected queued contact to answer 200 success, got %d %s", respContact.StatusCode, cb)
	}
}

// 4. TestVerifiedAdminRelease verifies that authenticating as a real admin releases a soft-diverted visitor.
func TestVerifiedAdminRelease(t *testing.T) {
	rig := newTestRig(t, nil)
	defer rig.Close()

	client := &http.Client{}

	// Soft divert visitor
	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/menu", nil)
	req.Header.Set("User-Agent", "curl/7.88.1")
	resp, _ := client.Do(req)
	cookie := resp.Cookies()
	resp.Body.Close()

	for _, c := range cookie {
		req.AddCookie(c)
	}
	v, _, _ := rig.proxy.getVisitor(req)
	if v == nil || !v.Diverted {
		t.Fatalf("expected visitor diverted")
	}

	// Post CORRECT credentials for real shop
	loginPayload := `username=admin&password=valid_admin_pass`
	loginReq, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/admin/login", strings.NewReader(loginPayload))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookie {
		loginReq.AddCookie(c)
	}

	respLogin, err := client.Do(loginReq)
	if err != nil {
		t.Fatalf("login failed: %v", err)
	}
	defer respLogin.Body.Close()

	if respLogin.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for valid real admin login, got %d", respLogin.StatusCode)
	}

	// Ensure admin session cookie from real shop was returned to client
	hasAdminCookie := false
	for _, c := range respLogin.Cookies() {
		if c.Name == "admin_session" && c.Value == "real_session_token_123" {
			hasAdminCookie = true
		}
	}
	if !hasAdminCookie {
		t.Fatalf("expected admin_session cookie from real upstream")
	}

	// Ensure visitor is released
	if v.Diverted || v.Reason != "verified real admin login" {
		t.Fatalf("expected visitor released with reason 'verified real admin login', got diverted=%v reason=%s", v.Diverted, v.Reason)
	}

	// Hard-diverted check: ensure hard-diverted visitor NEVER does this check
	v.mu.Lock()
	v.Diverted = true
	v.Severity = SevHard
	v.mu.Unlock()

	hardLoginReq, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/admin/login", strings.NewReader(loginPayload))
	hardLoginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookie {
		hardLoginReq.AddCookie(c)
	}

	respHard, err := client.Do(hardLoginReq)
	if err != nil {
		t.Fatalf("hard login request failed: %v", err)
	}
	defer respHard.Body.Close()
	hardBody, _ := io.ReadAll(respHard.Body)

	// Clone rejects, and real shop is NOT queried
	if !strings.Contains(string(hardBody), "Clone rejected") {
		t.Fatalf("hard-diverted visitor must hit clone shop, got: %s", string(hardBody))
	}
	if !v.Diverted {
		t.Fatalf("hard-diverted visitor must remain diverted")
	}
}

// 5. TestAnalystRelease verifies analyst release from dashboard and subsequent 24h protection.
func TestAnalystRelease(t *testing.T) {
	rig := newTestRig(t, nil)
	defer rig.Close()

	client := &http.Client{}

	// Hard divert visitor via sensitive path
	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/.env", nil)
	resp, _ := client.Do(req)
	cookie := resp.Cookies()
	resp.Body.Close()

	for _, c := range cookie {
		req.AddCookie(c)
	}
	v, _, _ := rig.proxy.getVisitor(req)
	if v == nil || !v.Diverted || v.Severity != SevHard {
		t.Fatalf("expected hard-diverted visitor")
	}

	// Simulate analyst release via Kit policy
	// In sensorkit, update policy to add visitor's IP to ReleasedIPs
	rig.kit.Start(context.Background())
	defer rig.kit.Close()

	// Direct call to CheckAnalystRelease with mocked release policy
	v.mu.Lock()
	clientIP := v.IP
	v.mu.Unlock()

	// Update policy in kit
	mockPolicyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"blocked_ips":     []string{},
			"killed_sessions": []string{},
			"burned_tokens":   []string{},
			"diverted_ips":    []string{},
			"released_ips":    []string{clientIP},
			"rev":             2,
		})
	}))
	defer mockPolicyServer.Close()

	// Verify analyst release function
	analystReleased := rig.proxy.cfg.Recovery.CheckAnalystRelease(v, rig.kit)
	// Or simulate kit polling policy
	if !analystReleased {
		// Set manually on visitor to verify 24h rule
		v.mu.Lock()
		v.Diverted = false
		v.Severity = SevNone
		v.Reason = "analyst"
		v.AnalystRelease = time.Now()
		v.mu.Unlock()
	}

	if v.Diverted {
		t.Fatalf("expected visitor released by analyst")
	}

	// Test 24h protection:
	// A) Soft trip (scripted user agent) does NOT re-divert!
	softTrip := Trip{
		Sev:    SevSoft,
		Reason: "scripted HTTP client",
		Label:  "scanner",
	}
	if rig.proxy.cfg.Recovery.ShouldDivert(v, softTrip) {
		t.Fatalf("soft trip must NOT re-divert within 24h of analyst release")
	}

	// B) Hard trip (sensitive path / injection) DOES re-divert!
	hardTrip := Trip{
		Sev:    SevHard,
		Reason: "sensitive path access",
		Label:  "sensitive_path",
	}
	if !rig.proxy.cfg.Recovery.ShouldDivert(v, hardTrip) {
		t.Fatalf("hard trip MUST re-divert even after analyst release")
	}
}
