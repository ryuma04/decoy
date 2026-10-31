package divert

import (
	"encoding/json"
	"bytes"
	"crypto/rand"
	"encoding/hex"
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
}

// Proxy implements same-URL diversion between real and clone upstreams (docs/18 Task 9).
type Proxy struct {
	cfg        ProxyConfig
	realProxy  *httputil.ReverseProxy
	cloneProxy *httputil.ReverseProxy
	mu         sync.RWMutex
	visitors   map[string]*Visitor
}

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
		cfg:      cfg,
		visitors: make(map[string]*Visitor),
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
		origDirector(req)
		req.Host = target.Host
		if isClone {
			req.Header.Set("Accept-Encoding", "identity")
		}
		if clientIP, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
	}
}

func (p *Proxy) setupResponseModifiers() {
	p.realProxy.ModifyResponse = func(resp *http.Response) error {
		p.recordResponseStats(resp)
		return nil
	}
	p.cloneProxy.ModifyResponse = func(resp *http.Response) error {
		p.recordResponseStats(resp)
		p.handleCloneResponse(resp)
		return nil
	}
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
	clientIP, clientPort := parseRemoteAddr(r.RemoteAddr)

	// 1. Kit Blocked check
	if p.cfg.Kit != nil && p.cfg.Kit.Blocked(clientIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// 2. Identify or initialize visitor + assign persistent cookie
	v, visitorKey, isNewCookie := p.getOrCreateVisitor(r, clientIP)
	if isNewCookie {
		http.SetCookie(w, &http.Cookie{
			Name:     VisitorCookieName,
			Value:    visitorKey,
			Path:     "/",
			HttpOnly: true,
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

	// 4. Core policy divert check
	if p.cfg.Kit != nil && p.cfg.Kit.Diverted(clientIP) && !p.cfg.Kit.Released(clientIP) {
		v.mu.Lock()
		if !v.Diverted {
			p.divertLocked(v, SevHard, "core policy", "policy", clientIP, clientPort)
		}
		v.mu.Unlock()
	}

	// 5. Honeytoken detection in body or URL
	if ht, matched := p.checkHoneytokens(r, body); matched {
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
		} else {
			v.mu.Lock()
			v.CleanReqs++
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

func (p *Proxy) emitDivertedMonitoring(sess *sensorkit.Session, r *http.Request, body []byte, trip Trip, status int) {
	sample := string(body)
	if len(sample) > 512 {
		sample = sample[:512]
	}
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
	clientIP, _ := parseRemoteAddr(r.RemoteAddr)
	if cookie, err := r.Cookie(VisitorCookieName); err == nil && cookie.Value != "" {
		p.mu.RLock()
		v, ok := p.visitors[cookie.Value]
		p.mu.RUnlock()
		if ok {
			return v, cookie.Value, false
		}
		return nil, cookie.Value, false
	}

	// Fallback key: IP + User-Agent
	key := fmt.Sprintf("%s:%s", clientIP, r.UserAgent())
	p.mu.RLock()
	v := p.visitors[key]
	p.mu.RUnlock()
	return v, key, false
}

func (p *Proxy) getOrCreateVisitor(r *http.Request, clientIP string) (*Visitor, string, bool) {
	if cookie, err := r.Cookie(VisitorCookieName); err == nil && cookie.Value != "" {
		p.mu.Lock()
		defer p.mu.Unlock()
		if v, ok := p.visitors[cookie.Value]; ok {
			now := time.Now()
			v.RequestTimes = append(v.RequestTimes, now)
			return v, cookie.Value, false
		}
		v := &Visitor{
			ID:           cookie.Value,
			IP:           clientIP,
			UA:           r.UserAgent(),
			RequestTimes: []time.Time{time.Now()},
		}
		p.visitors[cookie.Value] = v
		return v, cookie.Value, false
	}

	// Create random cookie for first response
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	newKey := hex.EncodeToString(b)

	p.mu.Lock()
	defer p.mu.Unlock()
	v := &Visitor{
		ID:           newKey,
		IP:           clientIP,
		UA:           r.UserAgent(),
		RequestTimes: []time.Time{time.Now()},
	}
	p.visitors[newKey] = v
	return v, newKey, true
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
	port := 0
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	return host, port
}
