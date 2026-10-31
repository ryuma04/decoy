package divert

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// setupLuresTacticsRig creates an environment for testing lures and cognitive tactics.
func setupLuresTacticsRig(t *testing.T) (*testRig, string) {
	t.Helper()

	tempDir, err := os.MkdirTemp("", "tactics_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	realServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env.bak" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("real shop: not found"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("real shop homepage"))
	}))

	cloneServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/admin/login" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), "password=BakeAdmin2026%21Secret") || strings.Contains(string(body), "password=BakeAdmin2026!Secret") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"success":true,"admin":true,"data":"synthetic"}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Invalid credentials"}`))
			return
		}

		if r.URL.Path == "/clone-page" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!DOCTYPE html><html><head><title>Clone Shop</title></head><body><h1>Welcome</h1></body></html>`))
			return
		}

		if r.URL.Path == "/admin/staff-report" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 Not Found"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("clone shop homepage"))
	}))

	realURL, _ := url.Parse(realServer.URL)
	cloneURL, _ := url.Parse(cloneServer.URL)

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "aetees-01",
		Service:  "web",
		CoreURL:  "http://127.0.0.1:9999",
	})

	lm := NewLureManager("TokAdminSecret99!", "TokDBSecret42!", "/invoices/view/canary-1002")
	tm := NewTacticsManager(tempDir, "", "BakeAdmin2026!Secret")

	proxyCfg := ProxyConfig{
		RealURL:    realURL,
		CloneURL:   cloneURL,
		Kit:        kit,
		Classifier: NewTripwire(),
		Recovery: NewRecoveryManager(RecoveryConfig{
			RealURL: realURL,
		}),
		Lures:   lm,
		Tactics: tm,
		Tokens: map[string]Honeytoken{
			"tok_aetees_admin": {
				TokenID:    "tok_aetees_admin",
				Kind:       "admin_password",
				MatchValue: "TokAdminSecret99!",
			},
			"tok_db": {
				TokenID:    "tok_db",
				Kind:       "db_password",
				MatchValue: "TokDBSecret42!",
			},
			"tok_aetees_invoice": {
				TokenID:    "tok_aetees_invoice",
				Kind:       "url",
				MatchValue: "/invoices/view/canary-1002",
			},
		},
	}

	p, err := NewProxy(proxyCfg)
	if err != nil {
		t.Fatalf("failed to create proxy: %v", err)
	}

	proxyServer := httptest.NewServer(p)

	rig := &testRig{
		realServer:  realServer,
		cloneServer: cloneServer,
		proxyServer: proxyServer,
		proxy:       p,
		kit:         kit,
	}

	return rig, tempDir
}

// 1. TestLures verifies that diverted visitors receive the four planted lures with correct tokens.
func TestLures(t *testing.T) {
	rig, tempDir := setupLuresTacticsRig(t)
	defer rig.Close()
	defer os.RemoveAll(tempDir)

	client := &http.Client{}

	// Step 1: Divert visitor via tripwire probe
	tripReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/?id=1%20UNION%20SELECT%20null,null--", nil)
	tripReq.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(tripReq)
	if err != nil {
		t.Fatalf("failed tripwire request: %v", err)
	}
	cookies := resp.Cookies()
	_ = resp.Body.Close()

	// Helper to send request with visitor cookie
	send := func(path string) (*http.Response, []byte) {
		req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+path, nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s failed: %v", path, err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res, b
	}

	// Lure 1: /.env.bak
	res1, body1 := send("/.env.bak")
	if res1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /.env.bak, got %d", res1.StatusCode)
	}
	bodyStr := string(body1)
	if !strings.Contains(bodyStr, "ADMIN_PASSWORD=\"TokAdminSecret99!\"") {
		t.Errorf("expected tok_aetees_admin in /.env.bak, got: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "TokDBSecret42!") {
		t.Errorf("expected tok_db in /.env.bak, got: %s", bodyStr)
	}

	// Lure 2: /backup/ directory listing
	res2, body2 := send("/backup/")
	if res2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for /backup/, got %d", res2.StatusCode)
	}
	if !strings.Contains(string(body2), "aetees_db_FINAL.sql.gz") {
		t.Errorf("expected listing of aetees_db_FINAL.sql.gz, got: %s", string(body2))
	}

	// Lure 3: /backup/aetees_db_FINAL.sql.gz
	res3, body3 := send("/backup/aetees_db_FINAL.sql.gz")
	if res3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for sql.gz, got %d", res3.StatusCode)
	}
	if res3.Header.Get("Content-Type") != "application/gzip" {
		t.Errorf("expected application/gzip, got %s", res3.Header.Get("Content-Type"))
	}
	// Verify gzip decompression
	gzr, err := gzip.NewReader(bytes.NewReader(body3))
	if err != nil {
		t.Fatalf("failed to create gzip reader: %v", err)
	}
	sqlBytes, err := io.ReadAll(gzr)
	if err != nil {
		t.Fatalf("failed to read gunzip content: %v", err)
	}
	if !strings.Contains(string(sqlBytes), "/invoices/view/canary-1002") {
		t.Errorf("expected canary invoice link in gunzipped sql, got: %s", string(sqlBytes))
	}

	// Lure 4: Canary invoice URL
	res4, body4 := send("/invoices/view/canary-1002")
	if res4.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for canary invoice, got %d", res4.StatusCode)
	}
	if !strings.Contains(string(body4), "#INV-2026-1002") {
		t.Errorf("expected invoice page with #INV-2026-1002, got: %s", string(body4))
	}
}

// 2. TestTactics_FalseSuccess verifies that after 3 failed admin logins, body is rewritten to clone credentials.
func TestTactics_FalseSuccess(t *testing.T) {
	rig, tempDir := setupLuresTacticsRig(t)
	defer rig.Close()
	defer os.RemoveAll(tempDir)

	client := &http.Client{}

	// Step 1: Divert visitor via tripwire probe
	tripReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/.git/config", nil)
	tripReq.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(tripReq)
	if err != nil {
		t.Fatalf("failed tripwire request: %v", err)
	}
	cookies := resp.Cookies()
	_ = resp.Body.Close()

	for _, c := range cookies {
		tripReq.AddCookie(c)
	}

	v, _, _ := rig.proxy.getVisitor(tripReq)
	if v == nil {
		t.Fatalf("expected visitor to be tracked")
	}

	// Send 3 failed login attempts
	for i := 1; i <= 3; i++ {
		form := url.Values{}
		form.Set("username", "admin")
		form.Set("password", "wrongpass123")
		req, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/admin/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("login attempt %d failed: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("attempt %d: expected 401 Unauthorized, got %d", i, res.StatusCode)
		}
	}

	// 4th login attempt: false_success should trigger, rewriting body to BakeAdmin2026!Secret
	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "attacker_guess_999")
	req, _ := http.NewRequest(http.MethodPost, rig.proxyServer.URL+"/api/admin/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("4th login attempt failed: %v", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Errorf("4th login: expected 200 OK via false_success, got %d", res.StatusCode)
	}
	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "synthetic") {
		t.Errorf("expected synthetic clone admin session, got: %s", string(body))
	}

	// Verify tactic fired once
	v.mu.Lock()
	emitted := v.TacticsEmitted["false_success"]
	v.mu.Unlock()
	if !emitted {
		t.Errorf("expected false_success tactic to be recorded as emitted")
	}
}

// 3. TestTactics_SunkCostExport verifies export progress climbs, stalls at 97%, then completes and serves CSV.
func TestTactics_SunkCostExport(t *testing.T) {
	rig, tempDir := setupLuresTacticsRig(t)
	defer rig.Close()
	defer os.RemoveAll(tempDir)

	client := &http.Client{}

	// Divert visitor
	tripReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/?cmd=id", nil)
	tripReq.Header.Set("User-Agent", "Mozilla/5.0")
	resp, _ := client.Do(tripReq)
	cookies := resp.Cookies()
	_ = resp.Body.Close()

	for _, c := range cookies {
		tripReq.AddCookie(c)
	}

	v, _, _ := rig.proxy.getVisitor(tripReq)

	pollExport := func() map[string]any {
		req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/api/admin/export", nil)
		for _, c := range cookies {
			req.AddCookie(c)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("poll export failed: %v", err)
		}
		defer res.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return out
	}

	// Poll 1: 30%
	p1 := pollExport()
	if int(p1["progress"].(float64)) != 30 {
		t.Errorf("poll 1: expected progress 30, got %v", p1["progress"])
	}

	// Poll 2: 65%
	p2 := pollExport()
	if int(p2["progress"].(float64)) != 65 {
		t.Errorf("poll 2: expected progress 65, got %v", p2["progress"])
	}

	// Poll 3: 88%
	p3 := pollExport()
	if int(p3["progress"].(float64)) != 88 {
		t.Errorf("poll 3: expected progress 88, got %v", p3["progress"])
	}

	// Polls 4, 5, 6: Stalled at 97%
	for i := 4; i <= 6; i++ {
		pi := pollExport()
		if int(pi["progress"].(float64)) != 97 {
			t.Errorf("poll %d: expected stalled progress 97, got %v", i, pi["progress"])
		}
	}

	// Verify sunk_cost_export tactic recorded
	v.mu.Lock()
	emitted := v.TacticsEmitted["sunk_cost_export"]
	v.mu.Unlock()
	if !emitted {
		t.Errorf("expected sunk_cost_export tactic to be marked emitted")
	}

	// Poll 7: 100% complete with download url
	p7 := pollExport()
	if int(p7["progress"].(float64)) != 100 {
		t.Errorf("poll 7: expected progress 100, got %v", p7["progress"])
	}
	if p7["status"] != "complete" || p7["download_url"] != "/api/admin/export/download" {
		t.Errorf("poll 7: expected complete status with download_url, got: %v", p7)
	}

	// Download CSV
	dlReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/api/admin/export/download", nil)
	for _, c := range cookies {
		dlReq.AddCookie(c)
	}
	dlRes, err := client.Do(dlReq)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	defer dlRes.Body.Close()
	csvBody, _ := io.ReadAll(dlRes.Body)
	if !strings.Contains(string(csvBody), "Rohan Verma") {
		t.Errorf("expected synthetic customers in CSV, got: %s", string(csvBody))
	}
}

// 4. TestTactics_Breadcrumb verifies HTML comment injection into clone HTML pages.
func TestTactics_Breadcrumb(t *testing.T) {
	rig, tempDir := setupLuresTacticsRig(t)
	defer rig.Close()
	defer os.RemoveAll(tempDir)

	client := &http.Client{}

	// Divert visitor
	tripReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/.env", nil)
	tripReq.Header.Set("User-Agent", "Mozilla/5.0")
	resp, _ := client.Do(tripReq)
	cookies := resp.Cookies()
	_ = resp.Body.Close()

	req, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/clone-page", nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("clone-page request failed: %v", err)
	}
	defer res.Body.Close()

	body, _ := io.ReadAll(res.Body)
	expectedComment := "<!-- DEBUG: Migration in progress. Remove /.env.bak and /backup/ before production release. -->"
	if !strings.Contains(string(body), expectedComment) {
		t.Errorf("expected breadcrumb comment injected, got: %s", string(body))
	}

	// Verify Content-Length updated
	if res.ContentLength != int64(len(body)) {
		t.Errorf("expected Content-Length %d, got %d", len(body), res.ContentLength)
	}
}

// 5. TestTactics_Tarpit verifies delay is applied when visitor exceeds 60 req/min.
func TestTactics_Tarpit(t *testing.T) {
	tm := NewTacticsManager(".data", "", "secret")
	v := &Visitor{
		ID:             "v_tarpit_test",
		TacticsEmitted: make(map[string]bool),
	}

	now := time.Now()
	// Simulate 65 requests within 1 minute
	for i := 0; i < 65; i++ {
		v.RequestTimes = append(v.RequestTimes, now)
	}

	start := time.Now()
	delay := tm.CheckTarpit(v)
	elapsed := time.Since(start)

	if delay <= 0 {
		t.Errorf("expected tarpit delay for 65 requests, got %v", delay)
	}
	if elapsed < delay {
		t.Errorf("expected actual sleep of at least %v, got %v", delay, elapsed)
	}
	if !v.TacticsEmitted["tarpit"] {
		t.Errorf("expected tarpit tactic marked as emitted")
	}
}

// 6. TestTactics_LLMPage_GuardAndCache verifies output guard and cache hit on second request.
func TestTactics_LLMPage_GuardAndCache(t *testing.T) {
	rig, tempDir := setupLuresTacticsRig(t)
	defer rig.Close()
	defer os.RemoveAll(tempDir)

	client := &http.Client{}

	// Divert visitor
	tripReq, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/?exec=cat%20/etc/passwd", nil)
	tripReq.Header.Set("User-Agent", "Mozilla/5.0")
	resp, _ := client.Do(tripReq)
	cookies := resp.Cookies()
	_ = resp.Body.Close()

	// 1. First request to /admin/staff-report (Clone returns 404, LLM page intercepts)
	req1, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/admin/staff-report", nil)
	for _, c := range cookies {
		req1.AddCookie(c)
	}
	res1, err := client.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer res1.Body.Close()

	if res1.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK for themed LLM page, got %d", res1.StatusCode)
	}
	body1, _ := io.ReadAll(res1.Body)
	bodyStr1 := string(body1)

	// Shop theme checks: colours #5a3424, #f8ecc2, fonts Oswald, Inter
	if !strings.Contains(bodyStr1, "#5a3424") || !strings.Contains(bodyStr1, "#f8ecc2") {
		t.Errorf("expected Aetees shop colours in LLM page, got: %s", bodyStr1)
	}
	if !strings.Contains(bodyStr1, "Oswald") || !strings.Contains(bodyStr1, "Inter") {
		t.Errorf("expected Oswald and Inter fonts in LLM page, got: %s", bodyStr1)
	}

	// 2. Second request to same path (Should be a CACHE HIT)
	req2, _ := http.NewRequest(http.MethodGet, rig.proxyServer.URL+"/admin/staff-report", nil)
	for _, c := range cookies {
		req2.AddCookie(c)
	}
	res2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer res2.Body.Close()

	if res2.StatusCode != http.StatusOK {
		t.Errorf("expected 200 OK on cached request, got %d", res2.StatusCode)
	}
	body2, _ := io.ReadAll(res2.Body)
	if string(body2) != bodyStr1 {
		t.Errorf("expected exact cached content on second request")
	}

	// 3. Output guard rejection test:
	// If generated body has <script> or external link, guard must reject and return false (fallback to 404)
	tm := NewTacticsManager(tempDir, "", "secret")
	v := &Visitor{ID: "guard_test"}
	rec := httptest.NewRecorder()

	badHTMLScript := `<div><script>alert('pwned')</script></div>`
	if !scriptTagRegex.MatchString(badHTMLScript) {
		t.Errorf("expected scriptTagRegex to detect <script>")
	}

	badHTMLLink := `<div><a href="https://evil-attacker.com/steal">Click here</a></div>`
	if !hasExternalLink(badHTMLLink) {
		t.Errorf("expected hasExternalLink to detect external domain")
	}

	cleanHTMLLink := `<div><a href="https://aetees-bakehouse.internal/menu">Internal</a></div>`
	if hasExternalLink(cleanHTMLLink) {
		t.Errorf("expected hasExternalLink to allow internal domain")
	}

	// Verify CheckLLMPage falls back to 404 for uninteresting paths
	uninterestingReq, _ := http.NewRequest(http.MethodGet, "/random/path/unknown", nil)
	handled := tm.CheckLLMPage(rec, uninterestingReq, v, http.StatusNotFound)
	if handled {
		t.Errorf("expected uninteresting path to not be handled by CheckLLMPage")
	}
}
