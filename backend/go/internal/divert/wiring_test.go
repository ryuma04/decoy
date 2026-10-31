package divert

import (
	"context"
	"encoding/json"
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
}

func newFakeCore(t *testing.T) *fakeCore {
	fc := &fakeCore{}
	fc.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
