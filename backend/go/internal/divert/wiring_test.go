package divert

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// fakeCore records every event batch the proxy's sensorkit sends, as core's ingest would receive it.
type fakeCore struct {
	srv    *httptest.Server
	mu     sync.Mutex
	events []event.Envelope
	policy string // JSON served at /v1/sensor/policy
}

func newFakeCore(t *testing.T) *fakeCore {
	fc := &fakeCore{}
	fc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/sensor/policy" {
			fc.mu.Lock()
			p := fc.policy
			fc.mu.Unlock()
			if p == "" {
				p = `{"rev":1}`
			}
			_, _ = w.Write([]byte(p))
			return
		}
		if r.URL.Path == "/v1/ingest/events" {
			var envs []event.Envelope
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &envs)
			fc.mu.Lock()
			fc.events = append(fc.events, envs...)
			fc.mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(fc.srv.Close)
	return fc
}

// waitFor returns the received events of a type once at least n exist (sensorkit flushes every second).
func (fc *fakeCore) waitFor(t *testing.T, typ string, n int) []event.Envelope {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		fc.mu.Lock()
		var out []event.Envelope
		for _, e := range fc.events {
			if e.Type == typ {
				out = append(out, e)
			}
		}
		fc.mu.Unlock()
		if len(out) >= n || time.Now().After(deadline) {
			return out
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func newWiredProxy(t *testing.T, core *fakeCore) (*httptest.Server, *Proxy) {
	t.Helper()
	upstream := func(name string) *httptest.Server {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/missing" {
				w.WriteHeader(http.StatusNotFound)
			}
			_, _ = w.Write([]byte(name))
		}))
		t.Cleanup(s.Close)
		return s
	}
	realURL, _ := url.Parse(upstream("real").URL)
	cloneURL, _ := url.Parse(upstream("clone").URL)
	kit := sensorkit.New(sensorkit.Options{SensorID: "aetees-01", Key: "0123456789abcdef0123", CoreURL: core.srv.URL,
		Service: "web", DataDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	kit.Start(ctx)
	t.Cleanup(func() { kit.Close(); cancel() })
	p, err := NewProxy(ProxyConfig{RealURL: realURL, CloneURL: cloneURL, Kit: kit, Classifier: NewTripwire(),
		Recovery: NewRecoveryManager(RecoveryConfig{RealURL: realURL}),
		Tokens:   map[string]Honeytoken{"tok_aetees_admin": {TokenID: "tok_aetees_admin", Kind: "db_cred", MatchValue: "HoneyPass-42!"}}})
	if err != nil {
		t.Fatal(err)
	}
	s := httptest.NewServer(p)
	t.Cleanup(s.Close)
	return s, p
}

func browserGet(t *testing.T, client *http.Client, u string, cookies []*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

// Diverted requests reach core with their status code and the query as an object (02), so core's input-risk
// model grades each parameter.
func TestDivertedRequestReportsStatusAndQueryObject(t *testing.T) {
	core := newFakeCore(t)
	srv, _ := newWiredProxy(t, core)
	client := &http.Client{}

	resp, _ := browserGet(t, client, srv.URL+"/.env.bak", nil) // hard trip: diverted
	cookies := resp.Cookies()
	browserGet(t, client, srv.URL+"/missing?q=cake&page=2", cookies)

	reqs := core.waitFor(t, "http.request", 2)
	var found bool
	for _, e := range reqs {
		var d map[string]any
		_ = json.Unmarshal(e.Data, &d)
		if d["path"] != "/missing" {
			continue
		}
		found = true
		if st, _ := d["status"].(float64); st != http.StatusNotFound {
			t.Errorf("status = %v, want 404", d["status"])
		}
		q, ok := d["query"].(map[string]any)
		if !ok || q["q"] != "cake" || q["page"] != "2" {
			t.Errorf("query = %#v, want object {q: cake, page: 2}", d["query"])
		}
	}
	if !found {
		t.Fatal("no http.request event for /missing reached core")
	}
}

// A honeytoken used by an already-diverted visitor keeps one session (one timeline) and makes the divert hard.
func TestHoneytokenWhileDivertedKeepsSession(t *testing.T) {
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	client := &http.Client{}

	resp, _ := browserGet(t, client, srv.URL+"/.env.bak", nil)
	cookies := resp.Cookies()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/admin/login", strings.NewReader(`{"username":"admin","password":"HoneyPass-42!"}`))
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	r2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()

	v, _, _ := p.getVisitor(req)
	if v == nil || v.DivertCount != 1 || v.Severity != SevHard {
		t.Fatalf("visitor = %+v, want one divert, severity hard", v)
	}
	if n := len(core.waitFor(t, "session.diverted", 1)); n != 1 {
		t.Fatalf("session.diverted events = %d, want 1", n)
	}
	used := core.waitFor(t, "token.used", 1)
	if len(used) != 1 {
		t.Fatalf("token.used events = %d, want 1", len(used))
	}
	auth := core.waitFor(t, "auth.attempt", 1)
	if len(auth) != 1 {
		t.Fatal("no auth.attempt for the admin login")
	}
	var d map[string]any
	_ = json.Unmarshal(auth[0].Data, &d)
	if d["username"] != "admin" {
		t.Errorf("auth.attempt username = %v, want admin (read from the JSON body)", d["username"])
	}
	sessions := map[string]bool{}
	for _, typ := range []string{"session.diverted", "token.used", "auth.attempt", "http.request"} {
		for _, e := range core.waitFor(t, typ, 1) {
			sessions[e.Session.SensorSessionID] = true
		}
	}
	if len(sessions) != 1 {
		t.Errorf("events spread over %d sessions, want 1: %v", len(sessions), sessions)
	}
}

// A normal shopper is never diverted and nothing about them is sent to core.
func TestNormalShopperSendsNothing(t *testing.T) {
	core := newFakeCore(t)
	srv, _ := newWiredProxy(t, core)
	client := &http.Client{}
	var cookies []*http.Cookie
	for i, u := range []string{"/", "/menu", "/api/products", "/api/products?search=red+velvet", "/cart"} {
		resp, body := browserGet(t, client, srv.URL+u, cookies)
		if i == 0 {
			cookies = resp.Cookies()
		}
		if body != "real" || resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: got %q %d, want the real shop", u, body, resp.StatusCode)
		}
	}
	time.Sleep(1500 * time.Millisecond) // one sensorkit flush
	core.mu.Lock()
	defer core.mu.Unlock()
	for _, e := range core.events {
		if e.Type != "sensor.heartbeat" {
			t.Errorf("normal shopper produced a %s event", e.Type)
		}
	}
}

// A normal page load pulls many JS/CSS/image files; that must not look like a high request rate.
func TestPageLoadAssetsDoNotTripRate(t *testing.T) {
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	client := &http.Client{}
	resp, _ := browserGet(t, client, srv.URL+"/", nil)
	cookies := resp.Cookies()
	for i := 0; i < 60; i++ {
		browserGet(t, client, fmt.Sprintf("%s/_next/static/chunks/%d.js", srv.URL, i), cookies)
		browserGet(t, client, fmt.Sprintf("%s/images/cake-%d.webp.png", srv.URL, i), cookies)
	}
	resp, body := browserGet(t, client, srv.URL+"/menu", cookies)
	if body != "real" {
		t.Fatalf("after a heavy page load got %q, want the real shop", body)
	}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/menu", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if v, _, _ := p.getVisitor(req); v == nil || v.Diverted || len(v.RequestTimes) > 5 {
		t.Fatalf("visitor = %+v; assets must not count as requests", v)
	}
	_ = resp
}

// Only real page/API visits count towards auto-release: assets and the shop's timer polls do not.
func TestCleanRequestsIgnoreAssetsAndPolls(t *testing.T) {
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	client := &http.Client{}
	resp, _ := browserGet(t, client, srv.URL+"/.env.bak", nil) // diverted
	cookies := resp.Cookies()
	for i := 0; i < 20; i++ {
		browserGet(t, client, fmt.Sprintf("%s/_next/static/chunks/%d.js", srv.URL, i), cookies)
		browserGet(t, client, srv.URL+"/api/queue/validate", cookies)
	}
	browserGet(t, client, srv.URL+"/menu", cookies)
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/menu", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	v, _, _ := p.getVisitor(req)
	if v == nil || v.CleanReqs != 1 {
		t.Fatalf("CleanReqs = %+v, want 1 (only /menu)", v)
	}
}

func TestIPv6LoopbackIsLocalhost(t *testing.T) {
	if ip, port := parseRemoteAddr("[::1]:51234"); ip != "127.0.0.1" || port != 51234 {
		t.Fatalf("got %s:%d", ip, port)
	}
	if ip, _ := parseRemoteAddr("192.168.1.9:80"); ip != "192.168.1.9" {
		t.Fatalf("got %s", ip)
	}
}

// Lure touches must reach core as events (they feed honeytoken_read and the risk floor), not only return 200.
func TestLureReadsReachCore(t *testing.T) {
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	p.cfg.Lures = NewLureManager("HoneyPass-42!", "DbPass-1", "/invoices/view/abc123")
	client := &http.Client{}
	resp, body := browserGet(t, client, srv.URL+"/.env.bak", nil)
	if !strings.Contains(body, "HoneyPass-42!") {
		t.Fatalf("lure body = %q", body)
	}
	cookies := resp.Cookies()
	browserGet(t, client, srv.URL+"/backup/aetees_db_FINAL.sql.gz", cookies)

	reads := core.waitFor(t, "file.read", 1)
	if len(reads) == 0 {
		t.Fatal("no file.read event for /.env.bak reached core")
	}
	var d map[string]any
	_ = json.Unmarshal(reads[0].Data, &d)
	if d["honeyfile_id"] != "tok_aetees_admin" || d["path"] != "/.env.bak" {
		t.Errorf("file.read data = %v", d)
	}
	if dl := core.waitFor(t, "file.download", 1); len(dl) == 0 {
		t.Error("no file.download event for the backup dump reached core")
	}
}


// False success: after 3 failed admin logins the clone receives the clone's credentials as JSON (what Aetees parses).
func TestFalseSuccessKeepsJSON(t *testing.T) {
	var got, hosts, xff []string
	var leaked bool
	var mu sync.Mutex
	clone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		if r.URL.Path == "/api/admin/login" {
			got = append(got, string(b))
			hosts = append(hosts, r.Host)
			xff = append(xff, r.Header.Get("X-Forwarded-For"))
		}
		leaked = leaked || r.Header.Get(falseSuccessHeader) != ""
		mu.Unlock()
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer clone.Close()
	cloneURL, _ := url.Parse(clone.URL)
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	p.cfg.CloneURL = cloneURL
	p2, _ := NewProxy(ProxyConfig{RealURL: p.cfg.RealURL, CloneURL: cloneURL, Kit: p.cfg.Kit, Classifier: NewTripwire(),
		Recovery: NewRecoveryManager(RecoveryConfig{RealURL: p.cfg.RealURL}), Tokens: p.cfg.Tokens,
		Tactics: NewTacticsManager(t.TempDir(), "", "Clone-Admin-PW")})
	srv2 := httptest.NewServer(p2)
	defer srv2.Close()
	_ = srv
	client := &http.Client{}
	resp, _ := browserGet(t, client, srv2.URL+"/.env.bak", nil) // diverted
	cookies := resp.Cookies()
	for i := 0; i < 5; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv2.URL+"/api/admin/login", strings.NewReader(`{"username":"maaz","password":"guess`+fmt.Sprint(i)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	last := got[len(got)-1]
	var body map[string]any
	if err := json.Unmarshal([]byte(last), &body); err != nil {
		t.Fatalf("clone got non-JSON login body %q", last)
	}
	if body["username"] != "admin" || body["password"] != "Clone-Admin-PW" {
		t.Fatalf("clone got %v, want the clone's admin credentials", body)
	}
	public := strings.TrimPrefix(srv2.URL, "http://")
	if hosts[len(hosts)-1] != public {
		t.Errorf("clone saw Host %q, want the public host %q", hosts[len(hosts)-1], public)
	}
	if !strings.HasPrefix(xff[len(xff)-1], "10.254.") || !strings.HasPrefix(xff[0], "127.0.0.1") {
		t.Errorf("X-Forwarded-For = first %q, false-success %q; want the client IP, then a fresh identity", xff[0], xff[len(xff)-1])
	}
	if leaked {
		t.Error("internal false-success marker header reached the clone")
	}
}

// An analyst release applies once; a new hard trip afterwards stays diverted (no divert/release loop).
func TestAnalystReleaseAppliesOnce(t *testing.T) {
	core := newFakeCore(t)
	srv, p := newWiredProxy(t, core)
	client := &http.Client{}
	resp, _ := browserGet(t, client, srv.URL+"/.env.bak", nil) // hard divert
	cookies := resp.Cookies()

	core.mu.Lock()
	core.policy = `{"released_ips":["127.0.0.1"],"rev":2}`
	core.mu.Unlock()
	deadline := time.Now().Add(8 * time.Second)
	for !p.cfg.Kit.Released("127.0.0.1") && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if _, body := browserGet(t, client, srv.URL+"/menu", cookies); body != "real" {
		t.Fatalf("after release got %q, want real", body)
	}
	time.Sleep(5 * time.Millisecond)
	browserGet(t, client, srv.URL+"/.git/config", cookies) // new hard trip after the release
	for i := 0; i < 5; i++ {
		if _, body := browserGet(t, client, srv.URL+"/menu", cookies); body != "clone" {
			t.Fatalf("request %d after new hard trip got %q, want clone (release must not re-apply)", i, body)
		}
	}
	if n := len(core.waitFor(t, "session.released", 1)); n != 1 {
		t.Fatalf("session.released events = %d, want exactly 1", n)
	}
}

func TestSecureCookieDroppedOnlyOnPlainHTTP(t *testing.T) {
	mk := func(tls bool) *http.Response {
		req := httptest.NewRequest(http.MethodPost, "http://shop/api/admin/login", nil)
		if !tls {
			req.TLS = nil
		}
		resp := &http.Response{Header: http.Header{}, Request: req}
		resp.Header.Add("Set-Cookie", "admin_token=abc; Path=/; Max-Age=86400; Secure; HttpOnly; SameSite=lax")
		return resp
	}
	plain := mk(false)
	insecureCookiesOnHTTP(plain)
	if c := plain.Header.Get("Set-Cookie"); strings.Contains(strings.ToLower(c), "secure") || !strings.Contains(c, "HttpOnly") {
		t.Fatalf("plain HTTP cookie = %q, want Secure removed and HttpOnly kept", c)
	}
	secure := mk(true)
	secure.Request.TLS = &tls.ConnectionState{}
	insecureCookiesOnHTTP(secure)
	if c := secure.Header.Get("Set-Cookie"); !strings.Contains(c, "Secure") {
		t.Fatalf("TLS cookie = %q, want unchanged", c)
	}
}
