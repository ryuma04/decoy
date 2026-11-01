package divert

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const (
	VisitorCookieName = "_aet_v"
	SlideWindow5m     = 5 * time.Minute
	SlideWindow10m    = 10 * time.Minute
	SlideWindow1m     = 1 * time.Minute
)

// ProxyConfig defines reverse proxy routing and intelligence parameters.
type ProxyConfig struct {
	RealURL    *url.URL
	CloneURL   *url.URL
	Kit        *sensorkit.Kit
	Classifier Classifier
	Recovery   *RecoveryManager
	Lures      *LureManager
	Tactics    *TacticsManager
	Tokens     map[string]Honeytoken

	// TrustCloudflare: requests from a loopback peer (cloudflared) carry the visitor's real IP in
	// CF-Connecting-IP and its scheme in X-Forwarded-Proto. Never trusted from any other peer.
	TrustCloudflare bool
	// Shadow: on every host except AdminHosts, detect and report ("would divert") but never divert.
	Shadow bool
	// AdminHosts are always live: unknown visitors get the clone, verified staff get the real shop.
	AdminHosts []string
}

// Proxy implements same-URL diversion between real and clone upstreams (docs/18 Task 9).
type Proxy struct {
	cfg        ProxyConfig
	realProxy  *httputil.ReverseProxy
	cloneProxy *httputil.ReverseProxy
	mu         sync.RWMutex
	visitors   map[string]*Visitor
	cookieless map[string]string // cookielessKey -> visitor ID
	lastEvict  time.Time
}

const visitorCtxKey ctxKey = 2

// visitorIdleTTL: a visitor unseen this long is forgotten (a returning one simply starts fresh).
const visitorIdleTTL = 24 * time.Hour

// NewProxy builds the divert reverse proxy.
func NewProxy(cfg ProxyConfig) (*Proxy, error) {
	if cfg.RealURL == nil || cfg.CloneURL == nil {
		return nil, fmt.Errorf("both RealURL and CloneURL are required")
	}
	if cfg.Classifier == nil {
		cfg.Classifier = NewTripwire()
	}
	if cfg.Recovery == nil {
		cfg.Recovery = NewRecoveryManager(RecoveryConfig{
			RealURL: cfg.RealURL,
		})
	}
	if cfg.Lures == nil {
		adminTok := ""
		dbTok := ""
		invTok := ""
		if t, ok := cfg.Tokens["tok_aetees_admin"]; ok {
			adminTok = t.MatchValue
		}
		if t, ok := cfg.Tokens["tok_db"]; ok {
			dbTok = t.MatchValue
		}
		if t, ok := cfg.Tokens["tok_aetees_invoice"]; ok {
			invTok = t.MatchValue
		}
		cfg.Lures = NewLureManager(adminTok, dbTok, invTok)
	}
	if cfg.Tactics == nil {
		adminPW := "BakeAdmin2026!Secret"
		if t, ok := cfg.Tokens["tok_aetees_admin"]; ok && t.MatchValue != "" {
			adminPW = t.MatchValue
		}
		cfg.Tactics = NewTacticsManager(".data", "", adminPW)
	}

	p := &Proxy{
		cfg:        cfg,
		visitors:   make(map[string]*Visitor),
		cookieless: make(map[string]string),
	}

	p.realProxy = httputil.NewSingleHostReverseProxy(cfg.RealURL)
	p.cloneProxy = httputil.NewSingleHostReverseProxy(cfg.CloneURL)

	p.setupProxyDirector(p.realProxy, cfg.RealURL, false)
	p.setupProxyDirector(p.cloneProxy, cfg.CloneURL, true)

	p.setupResponseModifiers()

	return p, nil
}

func (p *Proxy) setupProxyDirector(rp *httputil.ReverseProxy, target *url.URL, isClone bool) {
	origDirector := rp.Director
	rp.Director = func(req *http.Request) {
		host := req.Host
		origDirector(req)
		req.Host = host // keep the public Host: both copies build identical URLs and never see their internal address
		if isClone {
			req.Header.Set("Accept-Encoding", "identity")
		}
		// Both shops listen on loopback only (next start -H 127.0.0.1); told "https" they proxy their own
		// middleware rewrites (aeteesadmin /dashboard -> /admin/dashboard) to https://<loopback> and 500. They get
		// plain HTTP, and secureUpstreamRedirect turns their absolute redirects back into https URLs.
		req.Header.Del("X-Forwarded-Proto")
		clientIP, _ := parseRemoteAddr(req.RemoteAddr)
		if isClone && req.Header.Get(falseSuccessHeader) != "" {
			// false_success: a fresh client identity, so the clone's own login lockout (filled by the attacker's
			// failed tries) does not block the moment we let them in
			clientIP = fmt.Sprintf("10.254.%d.%d", time.Now().UnixNano()%250+1, time.Now().UnixNano()/7%250+1)
		}
		req.Header.Del(falseSuccessHeader)
		req.Header.Set("X-Forwarded-For", clientIP)
	}
}

func (p *Proxy) setupResponseModifiers() {
	p.realProxy.ModifyResponse = func(resp *http.Response) error {
		p.recordResponseStats(resp)
		insecureCookiesOnHTTP(resp)
		secureUpstreamRedirect(resp)
		return nil
	}
	p.cloneProxy.ModifyResponse = func(resp *http.Response) error {
		p.recordResponseStats(resp)
		insecureCookiesOnHTTP(resp)
		secureUpstreamRedirect(resp)
		p.handleCloneResponse(resp)
		return nil
	}
}

// insecureCookiesOnHTTP: the shops run as production builds and mark cookies Secure. When the visitor reached the
// proxy over plain HTTP (the lab), a browser would drop those cookies and nobody could log in, so the flag is removed
// for both upstreams alike. Behind TLS (production) cookies pass through unchanged.
// Behind Cloudflare (TrustCloudflare + X-Forwarded-Proto: https) the visitor is on HTTPS and nothing is changed.
func insecureCookiesOnHTTP(resp *http.Response) {
	if resp.Request == nil || isSecureRequest(resp.Request) {
		return
	}
	stripSecureCookies(resp.Header)
}

func (p *Proxy) handleCloneResponse(resp *http.Response) {
	req := resp.Request
	if req == nil {
		return
	}
	v, _, _ := p.getVisitor(req)
	if v == nil {
		return
	}

	v.mu.Lock()
	isDiverted := v.Diverted
	v.mu.Unlock()

	if !isDiverted {
		return
	}

	// 1. LLM / Decoy page generation for 404 on interesting paths
	if resp.StatusCode == http.StatusNotFound {
		path := strings.ToLower(req.URL.Path)
		for _, ip := range interestingPaths {
			if strings.Contains(path, ip) {
				cacheKey := hashPath(path)
				var pageHTML string
				if cached, ok := p.cfg.Tactics.getCached(cacheKey); ok {
					pageHTML = cached
				} else {
					title, bodyHTML := p.cfg.Tactics.generateLureContent(req.URL.Path)
					if !scriptTagRegex.MatchString(bodyHTML) && !hasExternalLink(bodyHTML) {
						pageHTML = p.cfg.Tactics.wrapShopTheme(title, bodyHTML)
						p.cfg.Tactics.saveCache(cacheKey, pageHTML)
					}
				}
				if pageHTML != "" {
					resp.StatusCode = http.StatusOK
					resp.Header.Set("Content-Type", "text/html; charset=utf-8")
					resp.Body = ioNopCloser(bytes.NewReader([]byte(pageHTML)))
					resp.ContentLength = int64(len(pageHTML))
					resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(pageHTML)))
					p.cfg.Tactics.emitTacticOnce(v, "llm_page", "curiosity", "", map[string]any{"path": path})
					return
				}
				break
			}
		}
	}

	// 2. Breadcrumb anchoring injection into HTML
	p.cfg.Tactics.InjectBreadcrumb(resp, v)
}

func (p *Proxy) recordResponseStats(resp *http.Response) {
	req := resp.Request
	if req == nil {
		return
	}
	v, _, _ := p.getVisitor(req)
	if v == nil {
		return
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	if resp.StatusCode == http.StatusNotFound {
		v.NotFoundTimes = append(v.NotFoundTimes, now)
	}
	if req.URL.Path == "/api/admin/login" && resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		v.FailedLogins = append(v.FailedLogins, now)
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r, clientIP, clientPort, secure := p.withEdge(r)

	// 1. Kit Blocked check
	if p.cfg.Kit != nil && p.cfg.Kit.Blocked(clientIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. Identify or initialize visitor + assign persistent cookie
	v, visitorKey, isNewCookie := p.getOrCreateVisitor(r, clientIP)
	r = r.WithContext(context.WithValue(r.Context(), visitorCtxKey, v)) // response hooks find the same visitor
	if isNewCookie {
		http.SetCookie(w, &http.Cookie{
			Name:     VisitorCookieName,
			Value:    visitorKey,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
		})
	}

	// Read and buffer request body
	body, err := DrainBody(r)
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// 3. Analyst release check (Kit.Released wins over everything)
	if p.cfg.Recovery.CheckAnalystRelease(v, p.cfg.Kit) {
		slog.Info("visitor released by analyst", "ip", clientIP, "visitor", v.ID)
	}

	adminHost := p.isAdminHost(r)
	if p.cfg.Shadow && !adminHost {
		p.serveShadow(w, r, v, body, clientIP, clientPort)
		return
	}
	if adminHost && p.staffPassthrough(w, r, v, body) {
		return
	}

	// 4. Core policy divert check
	if p.cfg.Kit != nil && p.cfg.Kit.Diverted(clientIP) && !p.cfg.Kit.Released(clientIP) {
		v.mu.Lock()
		if !v.Diverted {
			p.divertLocked(v, SevHard, "core policy", "policy", clientIP, clientPort)
		}
		v.mu.Unlock()
	}

	// 5. Honeytoken detection in body or URL
	ht, tokenHit := p.checkHoneytokens(r, body)
	if tokenHit {
		v.mu.Lock()
		if v.Diverted { // already in the clone: keep the same session (one timeline), just make it hard
			v.Severity = SevHard
			v.Reason = "honeytoken used: " + ht.TokenID
			v.Label = "honeytoken"
		} else {
			p.divertLocked(v, SevHard, "honeytoken used: "+ht.TokenID, "honeytoken", clientIP, clientPort)
		}
		sess := v.Session
		v.mu.Unlock()

		if sess != nil {
			sess.Event("token.used", "", map[string]any{
				"token_id":   ht.TokenID,
				"token_kind": ht.Kind,
				"via":        "request_content",
			}, nil, []string{ht.TokenID})
		}
	}

	// 5b. Admin honeypot host: every unknown visitor starts in the clone; a login the real shop accepts makes the
	// visitor staff (never for a honeytoken password: that one belongs to the clone).
	if adminHost {
		if !tokenHit && p.verifyStaffLogin(w, r, v, body, clientIP) {
			return
		}
		v.mu.Lock()
		if !v.Diverted && !analystProtected(v) {
			p.divertLocked(v, SevHard, adminSubdomainWhy, "admin_subdomain", clientIP, clientPort)
		}
		v.mu.Unlock()
	}

	// 6. Recovery logic for soft-diverted visitors
	v.mu.Lock()
	isSoftDiverted := v.Diverted && v.Severity == SevSoft
	v.mu.Unlock()

	if isSoftDiverted {
		// Verified admin check: POST /api/admin/login tested against REAL upstream
		if p.cfg.Recovery.CheckVerifiedAdmin(w, r, v, body) {
			return
		}

		// Hold writes: POST /api/checkout and POST /api/contact blocked with 503
		if p.cfg.Recovery.CheckHoldWrites(w, r, v, body) {
			return
		}
	}

	// 7. Evaluate tripwire classification
	view := p.buildVisitorView(v)
	trip := p.cfg.Classifier.Classify(r, body, view)

	v.mu.Lock()
	divertedAtStart := v.Diverted
	v.mu.Unlock()

	if divertedAtStart {
		if trip.Sev == SevHard {
			p.cfg.Recovery.UpgradeToHard(v, trip.Reason, trip.Label)
		} else if trip.Sev == SevSoft {
			v.mu.Lock()
			v.CleanReqs = 0
			v.LastTrip = time.Now()
			v.mu.Unlock()
		} else if countsAsPageRequest(r.URL.Path) && !isBackgroundPoll(r.URL.Path) {
			v.mu.Lock()
			v.CleanReqs++ // only real page/API visits count towards auto-release, not assets or idle polling
			v.mu.Unlock()
		}
	} else {
		if p.cfg.Recovery.ShouldDivert(v, trip) {
			v.mu.Lock()
			p.divertLocked(v, trip.Sev, trip.Reason, trip.Label, clientIP, clientPort)
			v.mu.Unlock()
		}
	}

	v.mu.Lock()
	isDivertedNow := v.Diverted
	divertedSession := v.Session
	v.mu.Unlock()

	// 8. Auto-release check after request processing
	if isDivertedNow {
		if p.cfg.Recovery.CheckAutoRelease(v) {
			v.mu.Lock()
			isDivertedNow = v.Diverted
			divertedSession = nil
			v.mu.Unlock()
			slog.Info("visitor auto-released after clean behavior", "ip", clientIP, "visitor", v.ID)
		}
	}

	// 9. Monitoring for diverted visitors: report each request to core after it is answered, with its status
	if isDivertedNow && divertedSession != nil && !isStaticAsset(r.URL.Path) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		w = rec
		reqBody := body
		defer func() { p.emitDivertedMonitoring(divertedSession, r, reqBody, trip, rec.status) }()
	}

	// 10. Diverted-only cognitive tactics & planted lures
	if isDivertedNow {
		// Cognitive tactic: tarpit (growing delay up to 2s if > 60 req/min)
		if p.cfg.Tactics != nil {
			p.cfg.Tactics.CheckTarpit(v)
		}

		// Planted lures: /.env.bak, /backup/, /backup/aetees_db_FINAL.sql.gz, canary invoice
		if p.cfg.Lures != nil && p.cfg.Lures.HandleLures(w, r, v) {
			return
		}

		// Cognitive tactic: sunk_cost_export (/api/admin/export stalls near 97%)
		if p.cfg.Tactics != nil && p.cfg.Tactics.HandleSunkCostExport(w, r, v) {
			return
		}

		// Cognitive tactic: false_success (after 3 failed admin logins, rewrites body to clone credentials)
		if p.cfg.Tactics != nil {
			if rewritten, ok := p.cfg.Tactics.CheckFalseSuccess(r, body, v); ok {
				body = rewritten
			}
		}
	}

	// 11. Forward to upstream (Clone if diverted, Real if normal)
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
	if isDivertedNow {
		p.cloneProxy.ServeHTTP(w, r)
	} else {
		p.realProxy.ServeHTTP(w, r)
	}
}

func (p *Proxy) divertLocked(v *Visitor, sev Severity, reason, label, clientIP string, clientPort int) {
	v.Diverted = true
	v.Severity = sev
	v.Reason = reason
	v.Label = label
	v.DivertedAt = time.Now()
	v.LastTrip = time.Now()
	v.CleanReqs = 0
	v.DivertCount++

	if p.cfg.Kit != nil {
		sessID := fmt.Sprintf("%s:%s:%d", p.cfg.Kit.ID(), v.ID, v.DivertCount)
		v.Session = p.cfg.Kit.SessionWithID(sessID, clientIP, clientPort, 8200)
		v.Session.Event("session.diverted", "", SessionDivertedData{
			Reason:   reason,
			Severity: sev,
			Label:    label,
		}, nil, nil)
	}
}

func (p *Proxy) checkHoneytokens(r *http.Request, body []byte) (Honeytoken, bool) {
	if len(p.cfg.Tokens) == 0 {
		return Honeytoken{}, false
	}

	bodyStr := string(body)
	pathAndQuery := r.URL.RequestURI()

	for _, ht := range p.cfg.Tokens {
		if ht.MatchValue == "" {
			continue
		}
		if len(bodyStr) > 0 && strings.Contains(bodyStr, ht.MatchValue) {
			return ht, true
		}
		if strings.Contains(pathAndQuery, ht.MatchValue) {
			return ht, true
		}
	}
	return Honeytoken{}, false
}

// quietPoll: a plain GET of a timer endpoint (QueueGuard, every 30 s) that tripped nothing says nothing about the
// visitor; recording it buries the attacker's real steps in the live feed. Anything carrying a payload is recorded.
func quietPoll(r *http.Request, trip Trip) bool {
	return r.Method == http.MethodGet && isBackgroundPoll(r.URL.Path) && (trip.Sev == "" || trip.Sev == SevNone)
}

func (p *Proxy) emitDivertedMonitoring(sess *sensorkit.Session, r *http.Request, body []byte, trip Trip, status int) {
	if quietPoll(r, trip) {
		return
	}
	sample := bodySample(r, body)
	query := map[string]any{} // object, as 02 specifies: core grades each value with the input-risk model
	for k, vs := range r.URL.Query() {
		if len(vs) == 1 {
			query[k] = vs[0]
		} else {
			query[k] = vs
		}
	}

	sess.Event("http.request", "", map[string]any{
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       query,
		"status":      status,
		"ua":          r.UserAgent(),
		"body_sample": sample,
	}, nil, nil)

	if r.Method == http.MethodPost && r.URL.Path == "/api/admin/login" {
		var creds struct {
			Username string `json:"username"`
		}
		_ = json.Unmarshal(body, &creds) // the shop's login posts JSON
		sess.Event("auth.attempt", "", map[string]any{
			"method":   "form",
			"username": creds.Username,
			"success":  status == http.StatusOK,
		}, nil, nil)
	}

	if trip.Label == "cmd_injection" || trip.Label == "sqli" || trip.Label == "xss" || trip.Label == "path_traversal" {
		sess.Event("input.suspicious", "", map[string]any{
			"param": trip.Param,
			"value": trip.Value,
			"path":  r.URL.Path,
		}, nil, nil)
	}
}

// statusRecorder remembers the status written to the visitor (for the http.request event).
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (p *Proxy) getVisitor(r *http.Request) (*Visitor, string, bool) {
	if v, ok := r.Context().Value(visitorCtxKey).(*Visitor); ok && v != nil {
		return v, v.ID, false
	}
	if cookie, err := r.Cookie(VisitorCookieName); err == nil && cookie.Value != "" {
		p.mu.RLock()
		v, ok := p.visitors[cookie.Value]
		p.mu.RUnlock()
		if ok {
			return v, cookie.Value, false
		}
		return nil, cookie.Value, false
	}
	clientIP, _ := parseRemoteAddr(r.RemoteAddr)
	key := cookielessKey(clientIP, r.UserAgent())
	p.mu.RLock()
	defer p.mu.RUnlock()
	if id, ok := p.cookieless[key]; ok {
		return p.visitors[id], id, false
	}
	return nil, key, false
}

// cookielessKey groups clients that never send our visitor cookie back (scanners, curl, scripts) by IP and
// User-Agent, so their 404s, failed logins and request rate add up as one visitor.
func cookielessKey(ip, ua string) string { return ip + "|" + ua }

func (p *Proxy) getOrCreateVisitor(r *http.Request, clientIP string) (*Visitor, string, bool) {
	now := time.Now()
	touch := func(v *Visitor, cookieSeen bool) {
		v.mu.Lock()
		v.LastSeen = now
		if cookieSeen {
			v.CookieSeen = true
		}
		if countsAsPageRequest(r.URL.Path) { // a page load fetches dozens of assets; only pages/API count
			v.RequestTimes = recentTimes(append(v.RequestTimes, now), time.Minute)
		}
		v.mu.Unlock()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.evictLocked(now)

	if cookie, err := r.Cookie(VisitorCookieName); err == nil && cookie.Value != "" {
		if v, ok := p.visitors[cookie.Value]; ok {
			touch(v, true)
			return v, cookie.Value, false
		}
		v := &Visitor{ID: cookie.Value, IP: clientIP, UA: r.UserAgent(), RequestTimes: []time.Time{now}, LastSeen: now, CookieSeen: true}
		p.visitors[cookie.Value] = v
		return v, cookie.Value, false
	}

	// No cookie: the same cookie-less client (same IP + UA, never sent our cookie back) stays one visitor.
	// A browser returns the cookie on its next request, so two shoppers behind one NAT are never merged.
	key := cookielessKey(clientIP, r.UserAgent())
	if id, ok := p.cookieless[key]; ok {
		if v, ok := p.visitors[id]; ok {
			v.mu.Lock()
			seen := v.CookieSeen
			v.mu.Unlock()
			if !seen {
				touch(v, false)
				return v, id, true
			}
		}
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	newKey := hex.EncodeToString(b)
	v := &Visitor{ID: newKey, IP: clientIP, UA: r.UserAgent(), RequestTimes: []time.Time{now}, LastSeen: now}
	p.visitors[newKey] = v
	p.cookieless[key] = newKey
	return v, newKey, true
}

// evictLocked forgets visitors idle for visitorIdleTTL (bounded memory on a public site). Runs at most once a minute.
func (p *Proxy) evictLocked(now time.Time) {
	if now.Sub(p.lastEvict) < time.Minute {
		return
	}
	p.lastEvict = now
	for id, v := range p.visitors {
		v.mu.Lock()
		idle := now.Sub(v.LastSeen) > visitorIdleTTL
		v.mu.Unlock()
		if idle {
			delete(p.visitors, id)
		}
	}
	for k, id := range p.cookieless {
		if _, ok := p.visitors[id]; !ok {
			delete(p.cookieless, k)
		}
	}
}

func (p *Proxy) buildVisitorView(v *Visitor) VisitorView {
	v.mu.Lock()
	defer v.mu.Unlock()

	now := time.Now()
	cutoff5m := now.Add(-SlideWindow5m)
	cutoff10m := now.Add(-SlideWindow10m)
	cutoff1m := now.Add(-SlideWindow1m)

	notFounds := 0
	for _, t := range v.NotFoundTimes {
		if t.After(cutoff5m) {
			notFounds++
		}
	}

	failedLogins := 0
	for _, t := range v.FailedLogins {
		if t.After(cutoff10m) {
			failedLogins++
		}
	}

	reqsPerMin := 0
	for _, t := range v.RequestTimes {
		if t.After(cutoff1m) {
			reqsPerMin++
		}
	}

	return VisitorView{
		NotFound5m:      notFounds,
		FailedLogins10m: failedLogins,
		RequestsPerMin:  reqsPerMin,
	}
}

// countsAsPageRequest: pages and API calls, not the JS/CSS/image/font files a page load pulls in.
func countsAsPageRequest(path string) bool { return !isStaticAsset(path) }

// isBackgroundPoll: requests the shop's own pages send on a timer while a tab is open.
func isBackgroundPoll(path string) bool {
	return path == "/api/queue/validate" || path == "/api/queue/status"
}

// recentTimes keeps only the timestamps inside the window (bounded memory per visitor).
func recentTimes(ts []time.Time, window time.Duration) []time.Time {
	cut := time.Now().Add(-window)
	i := 0
	for i < len(ts) && ts[i].Before(cut) {
		i++
	}
	return ts[i:]
}

func isStaticAsset(path string) bool {
	p := strings.ToLower(path)
	if strings.HasPrefix(p, "/_next/") {
		return true
	}
	for _, ext := range []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".js", ".woff", ".woff2", ".ttf"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func parseRemoteAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 0
	}
	if host == "::1" { // same machine over IPv6: one identity, so dashboard policy for 127.0.0.1 applies
		host = "127.0.0.1"
	}
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
