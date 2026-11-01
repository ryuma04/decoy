package divert

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Two operating modes per host (docs/20 Phase 2 C + D):
//   - SHADOW (main shop while ProxyConfig.Shadow is set): every check runs as in live mode, but every visitor is
//     forwarded to the REAL shop. A visitor that would have been diverted produces one session.diverted event
//     per distinct reason, marked {"shadow": true}. No lures, tactics, holds or per-request monitoring.
//   - ADMIN HONEYPOT (hosts in ProxyConfig.AdminHosts, always live): only staff use that host, so every unknown
//     visitor is served the clone. A visitor whose login the REAL shop accepts becomes staff and is passed to the
//     real shop on the same URL, silently, until they log out or lose the real admin_token cookie.

const (
	adminCookieName   = "admin_token"
	maxShadowReasons  = 32
	adminSubdomainWhy = "admin subdomain"
)

// ShadowDivertedData is session.diverted for a visitor the proxy would have diverted but did not (shadow mode).
type ShadowDivertedData struct {
	Reason   string   `json:"reason"`
	Severity Severity `json:"severity"`
	Label    string   `json:"label,omitempty"`
	Shadow   bool     `json:"shadow"`
	Path     string   `json:"path,omitempty"`
}

func (p *Proxy) isAdminHost(r *http.Request) bool {
	h := requestHost(r)
	for _, a := range p.cfg.AdminHosts {
		if a != "" && h == a {
			return true
		}
	}
	return false
}

// serveShadow runs the detections for a main-site visitor in shadow mode, reports what would have happened and
// always forwards to the real shop.
func (p *Proxy) serveShadow(w http.ResponseWriter, r *http.Request, v *Visitor, body []byte, clientIP string, clientPort int) {
	var trips []Trip
	if p.cfg.Kit != nil && p.cfg.Kit.Diverted(clientIP) && !p.cfg.Kit.Released(clientIP) {
		trips = append(trips, Trip{Sev: SevHard, Reason: "core policy", Label: "policy"})
	}
	ht, tokenHit := p.checkHoneytokens(r, body)
	if tokenHit {
		trips = append(trips, Trip{Sev: SevHard, Reason: "honeytoken used: " + ht.TokenID, Label: "honeytoken"})
	}
	if trip := p.cfg.Classifier.Classify(r, body, p.buildVisitorView(v)); p.cfg.Recovery.ShouldDivert(v, trip) {
		trips = append(trips, trip)
	}
	for _, t := range trips {
		p.reportShadow(v, t, r.URL.Path, clientIP, clientPort)
	}
	if tokenHit {
		v.mu.Lock()
		sess := v.ShadowSession
		v.mu.Unlock()
		if sess != nil {
			sess.Event("token.used", "", map[string]any{
				"token_id": ht.TokenID, "token_kind": ht.Kind, "via": "request_content",
			}, nil, []string{ht.TokenID})
		}
	}
	restoreBody(r, body)
	p.realProxy.ServeHTTP(w, r)
}

// reportShadow sends one "would divert" event per visitor and reason.
func (p *Proxy) reportShadow(v *Visitor, t Trip, path, clientIP string, clientPort int) {
	if p.cfg.Kit == nil {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.ShadowSeen == nil {
		v.ShadowSeen = map[string]bool{}
	}
	if v.ShadowSeen[t.Reason] || len(v.ShadowSeen) >= maxShadowReasons {
		return
	}
	v.ShadowSeen[t.Reason] = true
	if v.ShadowSession == nil {
		v.ShadowSession = p.cfg.Kit.SessionWithID(fmt.Sprintf("%s:%s:shadow", p.cfg.Kit.ID(), v.ID), clientIP, clientPort, 8200)
	}
	v.ShadowSession.Event("session.diverted", "", ShadowDivertedData{
		Reason: t.Reason, Severity: t.Sev, Label: t.Label, Shadow: true, Path: path,
	}, nil, nil)
}

// staffPassthrough forwards a verified staff visitor to the real shop with no events. It returns false (and
// forgets the verification) once the visitor no longer carries the real admin_token it was given.
func (p *Proxy) staffPassthrough(w http.ResponseWriter, r *http.Request, v *Visitor, body []byte) bool {
	v.mu.Lock()
	staff, tok := v.Staff, v.StaffToken
	v.mu.Unlock()
	if !staff {
		return false
	}
	c, err := r.Cookie(adminCookieName)
	if err != nil || c.Value == "" || c.Value != tok {
		p.unverifyStaff(v)
		return false
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/admin/logout" {
		p.unverifyStaff(v) // this request still reaches the real shop so its cookie is cleared there
	}
	restoreBody(r, body)
	p.realProxy.ServeHTTP(w, r)
	return true
}

func (p *Proxy) unverifyStaff(v *Visitor) {
	v.mu.Lock()
	v.Staff, v.StaffToken = false, ""
	v.mu.Unlock()
}

// verifyStaffLogin: a login on the admin host is first tried against the REAL shop. If the real shop accepts it
// the visitor becomes staff, the clone session ends with session.released, and the real response (with the real
// admin_token cookie) is returned. Otherwise nothing is written and the request continues to the clone.
func (p *Proxy) verifyStaffLogin(w http.ResponseWriter, r *http.Request, v *Visitor, body []byte, clientIP string) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/api/admin/login" {
		return false
	}
	resp, respBody, ok := p.cfg.Recovery.TryRealLogin(r, body, clientIP)
	if !ok {
		return false
	}
	token := ""
	for _, c := range resp.Cookies() {
		if c.Name == adminCookieName && c.Value != "" {
			token = c.Value
		}
	}
	if token == "" {
		return false // accepted without a session cookie: nothing to bind staff status to, stay in the clone
	}
	v.mu.Lock()
	sess := v.Session
	v.Staff, v.StaffToken = true, token
	v.Diverted, v.Severity, v.Reason, v.Session = false, SevNone, "verified staff login", nil
	v.FailedLogins = nil
	v.mu.Unlock()
	if sess != nil {
		sess.Event("session.released", "", SessionReleasedData{Reason: "verified staff login"}, nil, nil)
	}
	writeUpstream(w, r, resp, respBody)
	return true
}

// analystProtected: the analyst released this visitor's IP within the last 24 h.
func analystProtected(v *Visitor) bool {
	return !v.AnalystRelease.IsZero() && time.Since(v.AnalystRelease) < AnalystProtectionWindow
}

func restoreBody(r *http.Request, body []byte) {
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
	}
}
