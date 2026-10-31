package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const testSensorKey = "test-sensor-key-123456789"

type inMemoryTransport struct {
	handler http.Handler
}

func (t *inMemoryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

type testCore struct {
	mu             sync.Mutex
	events         []event.Envelope
	blockedIPs     []string
	killedSessions []string
	burnedTokens   []string
	policyRev      atomic.Int64
}

func (c *testCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
	}
	_, _ = sensorauth.Verify(r, body, map[string]string{"web-01": testSensorKey}, time.Now())

	switch r.URL.Path {
	case "/v1/ingest/events":
		var envs []event.Envelope
		_ = json.Unmarshal(body, &envs)
		c.mu.Lock()
		c.events = append(c.events, envs...)
		c.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"accepted":1}`))
	case "/v1/ingest/heartbeat":
		w.WriteHeader(http.StatusNoContent)
	case "/v1/sensor/policy":
		c.mu.Lock()
		resp, _ := json.Marshal(map[string]any{
			"blocked_ips":     c.blockedIPs,
			"killed_sessions": c.killedSessions,
			"burned_tokens":   c.burnedTokens,
			"rev":             c.policyRev.Load(),
		})
		c.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	case "/v1/sensor/maze-view":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"visible_nodes":["web_entry","lure_backup","lure_db"]}`))
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (c *testCore) getEvents() []event.Envelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := make([]event.Envelope, len(c.events))
	copy(cp, c.events)
	return cp
}

func setupTestServer(t *testing.T, core *testCore) (*Server, *sensorkit.Kit) {
	t.Helper()
	p := persona.Generate("test-seed-web")

	httpClient := &http.Client{
		Transport: &inMemoryTransport{handler: core},
		Timeout:   2 * time.Second,
	}

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "web-01",
		Key:      testSensorKey,
		CoreURL:  "http://core.internal:8443",
		Service:  "web",
		DataDir:  t.TempDir(),
		Version:  "0.1.0",
		HTTP:     httpClient,
	})
	kit.Start(context.Background())

	srv, err := NewServer(ServerConfig{
		Kit:          kit,
		Persona:      p,
		ListenAddr:   ":8080",
		DstPort:      8080,
		DataDir:      t.TempDir(),
		SeedDir:      t.TempDir(),
		TokenDB:      "test_db_token_xyz99",
		MinLatencyMS: 0,
		MaxLatencyMS: 0, // no sleep in tests
		MaxRequests:  500,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv, kit
}

func waitForEvents(t *testing.T, core *testCore, typ string, count int) []event.Envelope {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		var matched []event.Envelope
		for _, e := range core.getEvents() {
			if e.Type == typ {
				matched = append(matched, e)
			}
		}
		if len(matched) >= count {
			return matched
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d events of type %s", count, typ)
	return nil
}

func TestLoginGet(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "192.168.1.50:41234"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, srv.cfg.Persona.Company) {
		t.Errorf("login page does not contain company name: %s", body)
	}
	if !strings.Contains(body, `<form method="POST" action="/login">`) {
		t.Errorf("login form missing: %s", body)
	}
	cookie := rec.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != "sid" {
		t.Errorf("expected sid cookie to be set")
	}

	evs := waitForEvents(t, core, "http.request", 1)
	if evs[0].Type != "http.request" {
		t.Errorf("expected http.request event, got %s", evs[0].Type)
	}
}

func TestLoginPostFormFails(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	form := url.Values{}
	form.Set("username", "admin")
	form.Set("password", "supersecret123")

	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "192.168.1.50:41234"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Invalid username or password") {
		t.Errorf("missing error message in response")
	}

	authEvs := waitForEvents(t, core, "auth.attempt", 1)
	d := authEvs[0].DataMap()
	if d["username"] != "admin" || d["method"] != "form" || d["success"] != false {
		t.Errorf("bad auth.attempt data: %+v", d)
	}
}

func TestAPILoginPostJSON(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	reqBody := `{"username":"deploy","password":"Password99!"}`
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "192.168.1.50:41234"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if res["error"] != "unauthorized" {
		t.Errorf("unexpected error payload: %+v", res)
	}

	authEvs := waitForEvents(t, core, "auth.attempt", 1)
	d := authEvs[0].DataMap()
	if d["username"] != "deploy" || d["success"] != false {
		t.Errorf("bad auth.attempt data: %+v", d)
	}
}

func TestRobotsTxt(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "Disallow: /admin/backup") || !strings.Contains(body, "Disallow: /api/diagnostics") {
		t.Errorf("robots.txt missing expected disallow lines: %s", body)
	}
}

func TestAdminBackupListing(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/admin/backup", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "internal-backup.zip") {
		t.Errorf("backup listing missing internal-backup.zip: %s", body)
	}
}

func TestBackupZipDownload(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/admin/backup/internal-backup.zip", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/zip" {
		t.Errorf("expected application/zip, got %s", rec.Header().Get("Content-Type"))
	}

	// Verify valid zip containing deploy_id_ed25519 and notes.txt
	zr, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("invalid zip archive: %v", err)
	}
	files := make(map[string]bool)
	for _, f := range zr.File {
		files[f.Name] = true
	}
	if !files["deploy_id_ed25519"] || !files["notes.txt"] {
		t.Errorf("zip archive missing expected files, got %+v", files)
	}

	// Verify file.download event with honeytoken
	dlEvs := waitForEvents(t, core, "file.download", 1)
	if dlEvs[0].Sensor.MazeNode != "lure_backup" {
		t.Errorf("expected maze_node lure_backup, got %s", dlEvs[0].Sensor.MazeNode)
	}
	if len(dlEvs[0].Tokens) == 0 || dlEvs[0].Tokens[0] != "tok_backup_key" {
		t.Errorf("expected tokens [tok_backup_key], got %+v", dlEvs[0].Tokens)
	}
	d := dlEvs[0].DataMap()
	if d["honeyfile_id"] != "tok_backup_key" {
		t.Errorf("expected honeyfile_id tok_backup_key, got %+v", d)
	}
}

func TestDotEnvRead(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/.env", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "DB_PASSWORD=test_db_token_xyz99") {
		t.Errorf("/.env missing db password token: %s", body)
	}

	readEvs := waitForEvents(t, core, "file.read", 1)
	if len(readEvs[0].Tokens) == 0 || readEvs[0].Tokens[0] != "tok_db" {
		t.Errorf("expected token tok_db, got %+v", readEvs[0].Tokens)
	}
	d := readEvs[0].DataMap()
	if d["honeyfile_id"] != "tok_db" || d["path"] != "/.env" {
		t.Errorf("bad file.read data: %+v", d)
	}
}

func TestConfigPhpBakRead(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/config.php.bak", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "test_db_token_xyz99") {
		t.Errorf("/config.php.bak missing db password: %s", body)
	}

	readEvs := waitForEvents(t, core, "file.read", 1)
	if len(readEvs[0].Tokens) == 0 || readEvs[0].Tokens[0] != "tok_db" {
		t.Errorf("expected token tok_db, got %+v", readEvs[0].Tokens)
	}
}

func TestDiagnosticsCleanPing(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics?host=8.8.8.8", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "PING 8.8.8.8") {
		t.Errorf("unexpected ping output: %s", body)
	}

	// Should emit http.request, but NO input.suspicious
	evs := waitForEvents(t, core, "http.request", 1)
	for _, e := range evs {
		if e.Type == "input.suspicious" {
			t.Errorf("clean ping should not emit input.suspicious")
		}
	}
}

func TestDiagnosticsCommandInjection(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics?host=127.0.0.1;id", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "uid=1001(app)") {
		t.Errorf("expected simulated id output, got: %s", body)
	}

	suspEvs := waitForEvents(t, core, "input.suspicious", 1)
	d := suspEvs[0].DataMap()
	if d["param"] != "host" || d["separator"] != ";" || d["payload"] != "id" {
		t.Errorf("bad input.suspicious data: %+v", d)
	}
}

func TestDiagnosticsCatPasswd(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/api/diagnostics?host="+url.QueryEscape("127.0.0.1&&cat /etc/passwd"), nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "root:x:0:0:root") || !strings.Contains(body, "deploy:x:1000:1000") {
		t.Errorf("expected simulated /etc/passwd, got: %s", body)
	}

	suspEvs := waitForEvents(t, core, "input.suspicious", 1)
	d := suspEvs[0].DataMap()
	if d["separator"] != "&&" || d["payload"] != "cat /etc/passwd" {
		t.Errorf("bad input.suspicious data: %+v", d)
	}
}

func TestNotFoundNginx(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	req := httptest.NewRequest(http.MethodGet, "/non-existent-page", nil)
	req.RemoteAddr = "10.0.0.1:5544"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "nginx/1.18.0 (Ubuntu)") {
		t.Errorf("expected nginx style 404, got: %s", body)
	}
}

func TestSessionCookiePersistence(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	// 1st request without cookie
	req1 := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req1.RemoteAddr = "10.0.0.1:5544"
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)

	cookies := rec1.Result().Cookies()
	var sidCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sid" {
			sidCookie = c
			break
		}
	}
	if sidCookie == nil {
		t.Fatalf("sid cookie was not returned in response")
	}

	// 2nd request with cookie
	req2 := httptest.NewRequest(http.MethodGet, "/admin/backup", nil)
	req2.RemoteAddr = "10.0.0.1:5544"
	req2.AddCookie(sidCookie)
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)

	evs := waitForEvents(t, core, "http.request", 2)
	if evs[0].Session.SensorSessionID != evs[1].Session.SensorSessionID {
		t.Errorf("sessions should match across cookie requests: %s vs %s",
			evs[0].Session.SensorSessionID, evs[1].Session.SensorSessionID)
	}
	if evs[1].Session.Seq != 1 {
		t.Errorf("expected seq 1 for second request in session, got %d", evs[1].Session.Seq)
	}
}

func TestBlockedIPRefused(t *testing.T) {
	core := &testCore{
		blockedIPs: []string{"198.51.100.77"},
	}
	core.policyRev.Store(1)

	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	// Wait for policy to sync
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.RemoteAddr = "198.51.100.77:12345"
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for blocked IP, got %d", rec.Code)
	}
}

func TestKilledSessionRefused(t *testing.T) {
	core := &testCore{}
	srv, kit := setupTestServer(t, core)
	defer kit.Close()

	// First request to establish session
	req1 := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	req1.RemoteAddr = "10.0.0.1:5544"
	rec1 := httptest.NewRecorder()
	srv.ServeHTTP(rec1, req1)

	var sid string
	for _, c := range rec1.Result().Cookies() {
		if c.Name == "sid" {
			sid = c.Value
			break
		}
	}

	// Mark session killed in policy
	core.mu.Lock()
	core.killedSessions = []string{sid}
	core.policyRev.Add(1)
	core.mu.Unlock()

	// Wait for kit policy ticker to poll the update
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if kit.Killed(sid) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/login", nil)
	req2.RemoteAddr = "10.0.0.1:5544"
	req2.AddCookie(&http.Cookie{Name: "sid", Value: sid})
	rec2 := httptest.NewRecorder()
	srv.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for killed session, got %d", rec2.Code)
	}
}
