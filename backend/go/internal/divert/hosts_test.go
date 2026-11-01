package divert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const (
	adminHost    = "aeteesadmin.example.com"
	mainHost     = "shop.example.com"
	realStaffPW  = "Real-Staff-PW-77"
	honeyAdminPW = "HoneyPass-42!"
	realAdminTok = "real-admin-token-abc"
)

// hostRig: a fake real shop (accepts realStaffPW, sets admin_token), a fake clone, fake core, and the proxy.
type hostRig struct {
	srv        *httptest.Server
	core       *fakeCore
	mu         sync.Mutex
	realLogins []string // bodies of login copies the real shop received
	realXFF    []string
}

func newHostRig(t *testing.T, shadow bool) *hostRig {
	t.Helper()
	rig := &hostRig{core: newFakeCore(t)}
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/admin/login":
			b, _ := io.ReadAll(r.Body)
			rig.mu.Lock()
			rig.realLogins = append(rig.realLogins, string(b))
			rig.realXFF = append(rig.realXFF, r.Header.Get("X-Forwarded-For"))
			rig.mu.Unlock()
			if strings.Contains(string(b), realStaffPW) {
				http.SetCookie(w, &http.Cookie{Name: "admin_token", Value: realAdminTok, Path: "/", HttpOnly: true})
				_, _ = w.Write([]byte(`{"success":true}`))
				return
			}
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Invalid credentials"}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/admin/logout":
			http.SetCookie(w, &http.Cookie{Name: "admin_token", Value: "", Path: "/", MaxAge: -1})
			_, _ = w.Write([]byte(`{"success":true}`))
		case strings.HasPrefix(r.URL.Path, "/nothing-here"):
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("real"))
		default:
			_, _ = w.Write([]byte("real"))
		}
	}))
	clone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/api/admin/login" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"success":false,"error":"Invalid credentials"}`))
			return
		}
		_, _ = w.Write([]byte("clone"))
	}))
	t.Cleanup(real.Close)
	t.Cleanup(clone.Close)
	realURL, _ := url.Parse(real.URL)
	cloneURL, _ := url.Parse(clone.URL)
	kit := sensorkit.New(sensorkit.Options{SensorID: "aetees-01", Key: "0123456789abcdef0123", CoreURL: rig.core.srv.URL,
		Service: "web", DataDir: t.TempDir()})
	ctx, cancel := context.WithCancel(context.Background())
	kit.Start(ctx)
	t.Cleanup(func() { kit.Close(); cancel() })
	p, err := NewProxy(ProxyConfig{RealURL: realURL, CloneURL: cloneURL, Kit: kit, Classifier: NewTripwire(),
		Recovery:        NewRecoveryManager(RecoveryConfig{RealURL: realURL}),
		Tokens:          map[string]Honeytoken{"tok_aetees_admin": {TokenID: "tok_aetees_admin", Kind: "db_cred", MatchValue: honeyAdminPW}},
		TrustCloudflare: true, Shadow: shadow, AdminHosts: []string{adminHost}})
	if err != nil {
		t.Fatal(err)
	}
	rig.srv = httptest.NewServer(p)
	t.Cleanup(rig.srv.Close)
	return rig
}

func jarClient(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// do sends a request as if cloudflared forwarded it for visitor ip on host.
func (rig *hostRig) do(t *testing.T, c *http.Client, method, host, path, ip, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, rig.srv.URL+path, rd)
	req.Host = host
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0")
	req.Header.Set("CF-Connecting-IP", ip)
	req.Header.Set("X-Forwarded-Proto", "https")
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp.StatusCode, string(b)
}

func eventData(t *testing.T, raw json.RawMessage) map[string]any {
	var d map[string]any
	_ = json.Unmarshal(raw, &d)
	return d
}

func TestEdgeAddrTrustsCloudflareOnlyFromLoopback(t *testing.T) {
	trusted := &Proxy{cfg: ProxyConfig{TrustCloudflare: true}}
	untrusted := &Proxy{cfg: ProxyConfig{}}
	mk := func(remote, cf, xff, proto string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "http://shop/", nil)
		r.RemoteAddr = remote
		if cf != "" {
			r.Header.Set("CF-Connecting-IP", cf)
		}
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		if proto != "" {
			r.Header.Set("X-Forwarded-Proto", proto)
		}
		return r
	}
	cases := []struct {
		name       string
		p          *Proxy
		r          *http.Request
		wantIP     string
		wantSecure bool
	}{
		{"loopback + CF header", trusted, mk("127.0.0.1:5555", "203.0.113.9", "", "https"), "203.0.113.9", true},
		{"ipv6 loopback + CF header", trusted, mk("[::1]:5555", "2001:db8::7", "", ""), "2001:db8::7", false},
		{"loopback + XFF only", trusted, mk("127.0.0.1:5555", "", "198.51.100.4, 10.0.0.1", ""), "198.51.100.4", false},
		{"non-loopback peer forging header", trusted, mk("192.168.1.50:5555", "203.0.113.9", "", "https"), "192.168.1.50", false},
		{"header absent", trusted, mk("127.0.0.1:5555", "", "", ""), "127.0.0.1", false},
		{"garbage header", trusted, mk("127.0.0.1:5555", "not-an-ip", "", ""), "127.0.0.1", false},
		{"trust disabled", untrusted, mk("127.0.0.1:5555", "203.0.113.9", "", "https"), "127.0.0.1", false},
	}
	for _, c := range cases {
		ip, _, secure := c.p.edgeAddr(c.r)
		if ip != c.wantIP || secure != c.wantSecure {
			t.Errorf("%s: got ip=%s secure=%v, want ip=%s secure=%v", c.name, ip, secure, c.wantIP, c.wantSecure)
		}
	}
}

func TestSecureCookiesKeptBehindCloudflareHTTPS(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "admin_token=x; Path=/; Secure; HttpOnly")
		_, _ = w.Write([]byte("ok"))
	}))
	defer up.Close()
	u, _ := url.Parse(up.URL)
	p, _ := NewProxy(ProxyConfig{RealURL: u, CloneURL: u, TrustCloudflare: true})
	s := httptest.NewServer(p)
	defer s.Close()
	get := func(proto string) []string {
		req, _ := http.NewRequest(http.MethodGet, s.URL+"/", nil)
		if proto != "" {
			req.Header.Set("X-Forwarded-Proto", proto)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Values("Set-Cookie")
	}
	for _, c := range get("https") {
		if !strings.Contains(c, "Secure") {
			t.Fatalf("behind Cloudflare HTTPS cookie %q lost Secure", c)
		}
	}
	for _, c := range get("") {
		if strings.HasPrefix(c, "admin_token") && strings.Contains(c, "Secure") {
			t.Fatalf("plain HTTP cookie %q kept Secure", c)
		}
	}
}

func TestShadowModeReportsButNeverDiverts(t *testing.T) {
	rig := newHostRig(t, true)
	c := jarClient(t)
	const ip = "203.0.113.20"

	for _, path := range []string{"/", "/menu", "/cart"} { // normal shopper: nothing reported
		if _, body := rig.do(t, c, http.MethodGet, mainHost, path, ip, ""); body != "real" {
			t.Fatalf("%s got %q, want real", path, body)
		}
	}
	for i := 0; i < 2; i++ { // the same lure twice: real shop both times, one event
		if _, body := rig.do(t, c, http.MethodGet, mainHost, "/.env.bak", ip, ""); body != "real" {
			t.Fatalf("shadow lure got %q, want real", body)
		}
	}
	if _, body := rig.do(t, c, http.MethodGet, mainHost, "/search?q=1'+OR+'1'='1", ip, ""); body != "real" {
		t.Fatalf("shadow sqli got %q, want real", body)
	}
	if _, body := rig.do(t, c, http.MethodPost, mainHost, "/api/contact", ip, `{"note":"`+honeyAdminPW+`"}`); body != "real" {
		t.Fatalf("shadow honeytoken got %q, want real", body)
	}

	evs := rig.core.waitFor(t, "session.diverted", 3)
	if len(evs) != 3 {
		t.Fatalf("shadow session.diverted = %d, want 3 (lure once, sqli, honeytoken)", len(evs))
	}
	for _, e := range evs {
		d := eventData(t, e.Data)
		if d["shadow"] != true {
			t.Fatalf("event %v lacks shadow:true", d)
		}
		if e.Src.IP != ip {
			t.Fatalf("event src ip = %s, want visitor's Cloudflare IP %s", e.Src.IP, ip)
		}
	}
	if n := len(rig.core.waitFor(t, "token.used", 1)); n != 1 {
		t.Fatalf("token.used = %d, want 1", n)
	}
	time.Sleep(1200 * time.Millisecond)
	if n := len(rig.core.waitFor(t, "http.request", 0)); n != 0 {
		t.Fatalf("shadow mode sent %d http.request events, want 0 (no monitoring)", n)
	}
}

func TestShadowModeDoesNotApplyToAdminHost(t *testing.T) {
	rig := newHostRig(t, true)
	if _, body := rig.do(t, jarClient(t), http.MethodGet, adminHost, "/", "203.0.113.30", ""); body != "clone" {
		t.Fatalf("admin host in shadow mode got %q, want clone (always live)", body)
	}
}

func TestAdminHostHoneypotAndStaffLogin(t *testing.T) {
	rig := newHostRig(t, false)
	const attacker, staff = "198.51.100.66", "203.0.113.5"

	// Unknown visitor: clone, one session.diverted labelled admin_subdomain.
	ac := jarClient(t)
	if _, body := rig.do(t, ac, http.MethodGet, adminHost, "/", attacker, ""); body != "clone" {
		t.Fatalf("unknown visitor got %q, want clone", body)
	}
	// Wrong passwords: real shop gets a copy with the attacker's IP (its lockout applies), visitor stays in the clone.
	for i := 0; i < 3; i++ {
		code, _ := rig.do(t, ac, http.MethodPost, adminHost, "/api/admin/login", attacker, `{"username":"admin","password":"guess-`+string(rune('a'+i))+`"}`)
		if code != http.StatusUnauthorized {
			t.Fatalf("wrong password %d: status %d, want clone 401", i, code)
		}
	}
	// Honeytoken password: clone + token.used, never sent to the real shop.
	rig.do(t, ac, http.MethodPost, adminHost, "/api/admin/login", attacker, `{"username":"admin","password":"`+honeyAdminPW+`"}`)
	if n := len(rig.core.waitFor(t, "token.used", 1)); n != 1 {
		t.Fatalf("token.used = %d, want 1", n)
	}
	rig.mu.Lock()
	for i, b := range rig.realLogins {
		if strings.Contains(b, honeyAdminPW) {
			t.Fatal("honeytoken password was sent to the real shop")
		}
		if rig.realXFF[i] != attacker {
			t.Fatalf("real shop saw X-Forwarded-For %q, want attacker IP %s", rig.realXFF[i], attacker)
		}
	}
	rig.mu.Unlock()
	if _, body := rig.do(t, ac, http.MethodGet, adminHost, "/dashboard", attacker, ""); body != "clone" {
		t.Fatalf("attacker after failed logins got %q, want clone", body)
	}

	// Staff: same URL, starts in the clone, real password -> real shop from then on.
	sc := jarClient(t)
	if _, body := rig.do(t, sc, http.MethodGet, adminHost, "/", staff, ""); body != "clone" {
		t.Fatalf("staff first visit got %q, want clone", body)
	}
	code, body := rig.do(t, sc, http.MethodPost, adminHost, "/api/admin/login", staff, `{"username":"admin","password":"`+realStaffPW+`"}`)
	if code != http.StatusOK || !strings.Contains(body, `"success":true`) {
		t.Fatalf("staff login = %d %q, want the real shop's 200", code, body)
	}
	rel := rig.core.waitFor(t, "session.released", 1)
	if len(rel) != 1 || eventData(t, rel[0].Data)["reason"] != "verified staff login" {
		t.Fatalf("session.released = %v, want one 'verified staff login'", rel)
	}
	time.Sleep(1200 * time.Millisecond)
	rig.core.mu.Lock()
	before := len(rig.core.events)
	rig.core.mu.Unlock()
	for _, p := range []string{"/dashboard", "/orders", "/products", "/api/orders", "/categories"} {
		if _, body := rig.do(t, sc, http.MethodGet, adminHost, p, staff, ""); body != "real" {
			t.Fatalf("staff %s got %q, want real", p, body)
		}
	}
	time.Sleep(1200 * time.Millisecond)
	rig.core.mu.Lock()
	for _, e := range rig.core.events[before:] {
		if e.Type != "sensor.heartbeat" {
			t.Fatalf("staff browsing produced event %s, want none", e.Type)
		}
	}
	rig.core.mu.Unlock()

	// Logout: back to unverified, next visit is the clone again.
	rig.do(t, sc, http.MethodPost, adminHost, "/api/admin/logout", staff, `{}`)
	if _, body := rig.do(t, sc, http.MethodGet, adminHost, "/dashboard", staff, ""); body != "clone" {
		t.Fatalf("after logout got %q, want clone", body)
	}

	// The main host never takes the admin path.
	if _, body := rig.do(t, jarClient(t), http.MethodGet, mainHost, "/", "203.0.113.99", ""); body != "real" {
		t.Fatalf("main host got %q, want real", body)
	}

	// No password string anywhere in what reached the SOC.
	time.Sleep(1200 * time.Millisecond)
	rig.core.mu.Lock()
	defer rig.core.mu.Unlock()
	for _, e := range rig.core.events {
		raw, _ := json.Marshal(e)
		for _, pw := range []string{realStaffPW, "guess-a", "guess-b", "guess-c"} {
			if strings.Contains(string(raw), pw) {
				t.Fatalf("event %s contains password %q: %s", e.Type, pw, raw)
			}
		}
	}
}

// Cookie-less scanners (curl, nikto) count as one visitor, so the 404 tripwire fires for them.
func TestCookielessScannerAccumulates(t *testing.T) {
	rig := newHostRig(t, false)
	plain := &http.Client{} // no jar: never returns the visitor cookie
	var last string
	for i := 0; i < 25; i++ {
		_, last = rig.do(t, plain, http.MethodGet, mainHost, "/nothing-here-"+string(rune('a'+i))+"/x", "198.51.100.7", "")
	}
	if last != "clone" {
		t.Fatalf("cookie-less scanner after 25 probes got %q, want clone (one visitor, 404/rate trip)", last)
	}
}

func TestBodySampleRedactsPasswords(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/admin/login", nil)
	got := bodySample(r, []byte(`{"username":"admin","password":"S3cret!","nested":{"newPassword":"x2"}}`))
	if strings.Contains(got, "S3cret") || strings.Contains(got, "x2") || !strings.Contains(got, "admin") {
		t.Fatalf("json sample = %s", got)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	got = bodySample(r, []byte(`username=admin&password=S3cret%21`))
	if strings.Contains(got, "S3cret") || !strings.Contains(got, "admin") {
		t.Fatalf("form sample = %s", got)
	}
}

// The clone never sees X-Forwarded-Proto (it would break its own rewrites) and its absolute http redirects reach an
// HTTPS visitor as https, as the real shop's would.
func TestCloneRedirectsStayHTTPS(t *testing.T) {
	var sawProto string
	clone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Header.Get("X-Forwarded-Proto")
		http.Redirect(w, r, "http://"+r.Host+"/login", http.StatusTemporaryRedirect)
	}))
	defer clone.Close()
	u, _ := url.Parse(clone.URL)
	p, _ := NewProxy(ProxyConfig{RealURL: u, CloneURL: u, TrustCloudflare: true, AdminHosts: []string{adminHost}})
	s := httptest.NewServer(p)
	defer s.Close()
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/dashboard", nil)
	req.Host = adminHost
	req.Header.Set("X-Forwarded-Proto", "https")
	resp, err := jarClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if sawProto != "" {
		t.Fatalf("clone received X-Forwarded-Proto %q, want none", sawProto)
	}
	if loc := resp.Header.Get("Location"); loc != "https://"+adminHost+"/login" {
		t.Fatalf("Location = %q, want https://%s/login", loc, adminHost)
	}
}

// TestRealShopGetsPlainHTTPAndHTTPSRedirects: the real shop is loopback-only too; if it sees
// X-Forwarded-Proto: https its middleware rewrites (aeteesadmin /dashboard -> /admin/dashboard) are proxied to
// https://<loopback> and 500. It must get plain HTTP, and its absolute http:// redirects go back out as https.
func TestRealShopGetsPlainHTTPAndHTTPSRedirects(t *testing.T) {
	var sawProto = "unset"
	real := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawProto = r.Header.Get("X-Forwarded-Proto")
		http.Redirect(w, r, "http://"+r.Host+"/", http.StatusTemporaryRedirect)
	}))
	defer real.Close()
	clone := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("main-site visitor in shadow mode reached the clone")
	}))
	defer clone.Close()
	ru, _ := url.Parse(real.URL)
	cu, _ := url.Parse(clone.URL)
	p, _ := NewProxy(ProxyConfig{RealURL: ru, CloneURL: cu, TrustCloudflare: true, Shadow: true, AdminHosts: []string{adminHost}})
	s := httptest.NewServer(p)
	defer s.Close()
	req, _ := http.NewRequest(http.MethodGet, s.URL+"/admin", nil)
	req.Host = "www.aeteesbakehouse.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36")
	resp, err := jarClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if sawProto != "" {
		t.Fatalf("real shop received X-Forwarded-Proto %q, want none", sawProto)
	}
	if loc := resp.Header.Get("Location"); loc != "https://www.aeteesbakehouse.com/" {
		t.Fatalf("Location = %q, want https://www.aeteesbakehouse.com/", loc)
	}
}

func TestBackgroundPollsNotRecorded(t *testing.T) {
	get := func(u string) *http.Request { r, _ := http.NewRequest(http.MethodGet, u, nil); return r }
	post, _ := http.NewRequest(http.MethodPost, "http://x/api/queue/validate", nil)
	cases := []struct {
		name string
		r    *http.Request
		trip Trip
		want bool
	}{
		{"timer poll", get("http://x/api/queue/validate?sessionId=abc"), Trip{}, true},
		{"status poll", get("http://x/api/queue/status"), Trip{Sev: SevNone}, true},
		{"poll with payload", get("http://x/api/queue/validate?sessionId=1;cat+/etc/passwd"), Trip{Sev: SevSoft, Reason: "cmd"}, false},
		{"POST to poll path", post, Trip{}, false},
		{"admin page", get("http://x/admin/dashboard"), Trip{}, false},
	}
	for _, c := range cases {
		if got := quietPoll(c.r, c.trip); got != c.want {
			t.Errorf("%s: quietPoll = %v, want %v", c.name, got, c.want)
		}
	}
}
