package divert

import (
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
)

// heldRig: a real shop that records what reaches it, a clone, and the proxy with fast auto-release.
type heldRig struct {
	srv      *httptest.Server
	proxy    *Proxy
	mu       sync.Mutex
	got      []string // bodies of POST /api/contact that reached the REAL shop
	failNext int      // answer 500 this many times (transient failure)
}

func newHeldRig(t *testing.T) *heldRig {
	t.Helper()
	h := &heldRig{}
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/contact" {
			b, _ := io.ReadAll(r.Body)
			h.mu.Lock()
			defer h.mu.Unlock()
			if h.failNext > 0 {
				h.failNext--
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			h.got = append(h.got, string(b))
			_, _ = w.Write([]byte(`{"success":true}`))
			return
		}
		_, _ = w.Write([]byte("real"))
	}))
	clone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("clone")) }))
	t.Cleanup(real.Close)
	t.Cleanup(clone.Close)
	realURL, _ := url.Parse(real.URL)
	cloneURL, _ := url.Parse(clone.URL)
	core := newFakeCore(t)
	_, base := newWiredProxy(t, core)
	p, err := NewProxy(ProxyConfig{RealURL: realURL, CloneURL: cloneURL, Kit: base.cfg.Kit, Classifier: NewTripwire(),
		Recovery: NewRecoveryManager(RecoveryConfig{RealURL: realURL, ReleaseCleanReqs: 2, ReleaseCleanSecs: 30 * time.Millisecond})})
	if err != nil {
		t.Fatal(err)
	}
	h.proxy = p
	h.srv = httptest.NewServer(p)
	t.Cleanup(h.srv.Close)
	old := replayBackoff
	replayBackoff = []time.Duration{10 * time.Millisecond}
	t.Cleanup(func() { replayBackoff = old })
	return h
}

func (h *heldRig) do(t *testing.T, method, path, ua, body string, cookies []*http.Cookie) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, h.srv.URL+path, strings.NewReader(body))
	req.Header.Set("User-Agent", ua)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(b)
}

const browser = "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0"

// softDivert makes a fresh visitor soft-diverted (a scripted client is a soft trip) and returns its cookies.
func (h *heldRig) softDivert(t *testing.T) []*http.Cookie {
	t.Helper()
	resp, _ := h.do(t, http.MethodGet, "/", browser, "", nil)
	cookies := resp.Cookies()
	h.do(t, http.MethodGet, "/menu", "curl/8.4.0", "", cookies)
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/", nil)
	req.Header.Set("User-Agent", browser)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if v, _, _ := h.proxy.getVisitor(req); v == nil || !v.Diverted || v.Severity != SevSoft {
		t.Fatalf("setup: visitor not soft-diverted: %+v", v)
	}
	return cookies
}

func (h *heldRig) delivered(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		h.mu.Lock()
		got := append([]string(nil), h.got...)
		h.mu.Unlock()
		if len(got) >= n || time.Now().After(deadline) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestHeldContactIsQueuedThenReplayedOnRelease(t *testing.T) {
	h := newHeldRig(t)
	cookies := h.softDivert(t)
	msg := `{"name":"Riya","email":"riya@example.com","message":"Mom's cake; less sugar -- urgent"}`
	resp, body := h.do(t, http.MethodPost, "/api/contact", browser, msg, cookies)
	if resp.StatusCode != 200 || !strings.Contains(body, `"success":true`) {
		t.Fatalf("held contact answered %d %s, want the shop's success", resp.StatusCode, body)
	}
	if got := h.delivered(t, 0); len(got) != 0 {
		t.Fatal("held message reached the real shop before release")
	}
	time.Sleep(40 * time.Millisecond)
	for i := 0; i < 3; i++ { // clean visits -> auto-release
		h.do(t, http.MethodGet, "/menu", browser, "", cookies)
	}
	got := h.delivered(t, 1)
	if len(got) != 1 || got[0] != msg {
		t.Fatalf("real shop received %q, want the held message exactly once", got)
	}
	time.Sleep(100 * time.Millisecond)
	if again := h.delivered(t, 2); len(again) != 1 {
		t.Fatalf("replayed %d times, want once", len(again))
	}
}

func TestCheckoutIsNeverQueued(t *testing.T) {
	h := newHeldRig(t)
	cookies := h.softDivert(t)
	resp, body := h.do(t, http.MethodPost, "/api/checkout", browser, `{"items":[1]}`, cookies)
	if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "try again") {
		t.Fatalf("checkout while held: %d %s, want the try-again answer", resp.StatusCode, body)
	}
}

func TestQueueFullFallsBackToTryAgain(t *testing.T) {
	h := newHeldRig(t)
	cookies := h.softDivert(t)
	for i := 0; i < maxHeldPerVisitor; i++ {
		h.do(t, http.MethodPost, "/api/contact", browser, fmt.Sprintf(`{"message":"m%d"}`, i), cookies)
	}
	resp, body := h.do(t, http.MethodPost, "/api/contact", browser, `{"message":"one too many"}`, cookies)
	var j map[string]any
	_ = json.Unmarshal([]byte(body), &j)
	if resp.StatusCode != http.StatusServiceUnavailable || j["success"] != false {
		t.Fatalf("over-full queue answered %d %s, want try-again", resp.StatusCode, body)
	}
}

func TestHardTripDiscardsHeldActions(t *testing.T) {
	h := newHeldRig(t)
	cookies := h.softDivert(t)
	h.do(t, http.MethodPost, "/api/contact", browser, `{"message":"queued"}`, cookies)
	h.do(t, http.MethodGet, "/.env.bak", browser, "", cookies) // hard trip: now an attacker
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+"/", nil)
	req.Header.Set("User-Agent", browser)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	v, _, _ := h.proxy.getVisitor(req)
	if v == nil || v.Severity != SevHard || len(v.Held) != 0 {
		t.Fatalf("after hard trip: %+v, want hard with an empty queue", v)
	}
	time.Sleep(100 * time.Millisecond)
	if got := h.delivered(t, 0); len(got) != 0 {
		t.Fatalf("an attacker's held message reached the real shop: %q", got)
	}
}

func TestReplayRetriesTransientFailure(t *testing.T) {
	h := newHeldRig(t)
	h.failNext = 1
	cookies := h.softDivert(t)
	h.do(t, http.MethodPost, "/api/contact", browser, `{"message":"retry me"}`, cookies)
	time.Sleep(40 * time.Millisecond)
	for i := 0; i < 3; i++ {
		h.do(t, http.MethodGet, "/menu", browser, "", cookies)
	}
	if got := h.delivered(t, 1); len(got) != 1 {
		t.Fatalf("after one 500 the replay should retry and deliver; got %q", got)
	}
}
