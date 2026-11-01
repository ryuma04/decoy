package divert

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const (
	DefaultReleaseCleanReqs = 12
	DefaultReleaseCleanSecs = 120 * time.Second
	AnalystProtectionWindow = 24 * time.Hour
)

// RecoveryConfig defines thresholds for auto-recovery and verification.
type RecoveryConfig struct {
	ReleaseCleanReqs int
	ReleaseCleanSecs time.Duration
	RealURL          *url.URL
	HTTPClient       *http.Client
}

// RecoveryManager handles false-positive auto-release, write holds, verified admin logins,
// and analyst releases (docs/18 Task 11).
type RecoveryManager struct {
	cfg RecoveryConfig
}

// NewRecoveryManager initializes the recovery manager with configuration or env defaults.
func NewRecoveryManager(cfg RecoveryConfig) *RecoveryManager {
	if cfg.ReleaseCleanReqs <= 0 {
		if v, err := strconv.Atoi(os.Getenv("RELEASE_CLEAN_REQS")); err == nil && v > 0 {
			cfg.ReleaseCleanReqs = v
		} else {
			cfg.ReleaseCleanReqs = DefaultReleaseCleanReqs
		}
	}
	if cfg.ReleaseCleanSecs <= 0 {
		if v, err := strconv.Atoi(os.Getenv("RELEASE_CLEAN_SECS")); err == nil && v > 0 {
			cfg.ReleaseCleanSecs = time.Duration(v) * time.Second
		} else {
			cfg.ReleaseCleanSecs = DefaultReleaseCleanSecs
		}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // do not follow redirects, capture cookies and 302
			},
		}
	}
	return &RecoveryManager{cfg: cfg}
}

// CheckAutoRelease evaluates whether a soft-diverted visitor has satisfied clean behavior criteria.
func (rm *RecoveryManager) CheckAutoRelease(v *Visitor) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if !v.Diverted || v.Severity != SevSoft {
		return false
	}

	sinceTrip := time.Since(v.LastTrip)
	if v.LastTrip.IsZero() {
		sinceTrip = time.Since(v.DivertedAt)
	}

	if v.CleanReqs >= rm.cfg.ReleaseCleanReqs && sinceTrip >= rm.cfg.ReleaseCleanSecs {
		v.Diverted = false
		v.Severity = SevNone
		secs := int(sinceTrip.Seconds())
		if secs < 0 {
			secs = 0
		}

		if v.Session != nil {
			v.Session.Event("session.released", "", SessionReleasedData{
				Reason:        "auto: clean behaviour",
				CleanRequests: v.CleanReqs,
				Seconds:       secs,
			}, nil, nil)
			v.Session = nil
		}
		return true
	}
	return false
}

// UpgradeToHard transitions a soft-diverted visitor to hard diversion when an unmistakable attack is detected.
func (rm *RecoveryManager) UpgradeToHard(v *Visitor, reason, label string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.Diverted && v.Severity == SevSoft {
		v.Severity = SevHard
		v.Reason = reason
		v.Label = label
	}
}

// CheckHoldWrites blocks POST /api/checkout and POST /api/contact while soft-diverted,
// returning the shop's own 503 error shape and logging http.request with held: true.
func (rm *RecoveryManager) CheckHoldWrites(w http.ResponseWriter, r *http.Request, v *Visitor, body []byte) bool {
	v.mu.Lock()
	isSoftDiverted := v.Diverted && v.Severity == SevSoft
	sess := v.Session
	v.mu.Unlock()

	if !isSoftDiverted || r.Method != http.MethodPost {
		return false
	}

	path := r.URL.Path
	if path != "/api/checkout" && path != "/api/contact" {
		return false
	}

	// Emit http.request event with held: true
	if sess != nil {
		sess.Event("http.request", "", map[string]any{
			"method":      r.Method,
			"path":        path,
			"query":       r.URL.RawQuery,
			"status":      http.StatusServiceUnavailable,
			"ua":          r.UserAgent(),
			"body_sample": bodySample(r, body),
			"held":        true,
		}, nil, nil)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	resp := HeldErrorResponse{
		Success: false,
		Error:   "We're receiving a lot of orders right now. Please try again in a minute.",
	}
	_ = json.NewEncoder(w).Encode(resp)
	return true
}

// CheckVerifiedAdmin checks POST /api/admin/login against the REAL upstream for soft-diverted visitors.
// If valid, releases the visitor and returns the real upstream response with cookies.
// For hard-diverted visitors, it never checks the real upstream.
func (rm *RecoveryManager) CheckVerifiedAdmin(w http.ResponseWriter, r *http.Request, v *Visitor, body []byte) bool {
	v.mu.Lock()
	isSoftDiverted := v.Diverted && v.Severity == SevSoft
	sess := v.Session
	v.mu.Unlock()

	if !isSoftDiverted || r.Method != http.MethodPost || r.URL.Path != "/api/admin/login" {
		return false
	}

	resp, respBody, accepted := rm.TryRealLogin(r, body, v.IP)
	if !accepted {
		return false
	}

	// Release visitor: verified real admin login
	v.mu.Lock()
	v.Diverted = false
	v.Severity = SevNone
	v.Reason = "verified real admin login"
	v.mu.Unlock()

	if sess != nil {
		sess.Event("session.released", "", SessionReleasedData{
			Reason: "verified real admin login",
		}, nil, nil)
	}

	writeUpstream(w, r, resp, respBody)
	return true
}

// TryRealLogin sends a copy of a login POST to the REAL shop and reports whether it accepted the credentials.
// The copy carries the visitor's real IP, so the shop's own brute-force lockout applies to it. Neither the
// request body nor the response is kept.
func (rm *RecoveryManager) TryRealLogin(r *http.Request, body []byte, clientIP string) (*http.Response, []byte, bool) {
	if rm.cfg.RealURL == nil {
		return nil, nil, false
	}
	realTarget := rm.cfg.RealURL.ResolveReference(r.URL)
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, realTarget.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, false
	}
	for k, vv := range r.Header {
		for _, val := range vv {
			req.Header.Add(k, val)
		}
	}
	req.Host = r.Host
	req.Header.Set("X-Forwarded-For", clientIP)

	resp, err := rm.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, nil, false
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, nil, false
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		return resp, respBody, false
	}
	var jsonResp struct {
		Success *bool  `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &jsonResp); err == nil {
		if (jsonResp.Success != nil && !*jsonResp.Success) || jsonResp.Error != "" {
			return resp, respBody, false
		}
	}
	return resp, respBody, true
}

// writeUpstream relays a response fetched outside the reverse proxy (headers, status, body) to the visitor.
func writeUpstream(w http.ResponseWriter, r *http.Request, resp *http.Response, body []byte) {
	if !isSecureRequest(r) {
		stripSecureCookies(resp.Header)
	}
	for k, vv := range resp.Header {
		for _, val := range vv {
			w.Header().Add(k, val)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}

// CheckAnalystRelease handles manual releases triggered by analysts from the dashboard.
func (rm *RecoveryManager) CheckAnalystRelease(v *Visitor, kit *sensorkit.Kit) bool {
	if kit == nil {
		return false
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	if !kit.Released(v.IP) {
		v.AnalystRelease, v.ReleaseRev = time.Time{}, 0
		return false
	}
	// A release applies once, to diversions that existed when the analyst clicked it. A new hard trip afterwards
	// sticks (docs/18 Task 11). Clicking Release again changes the policy revision and re-arms it.
	if rev := kit.Policy().Rev; v.AnalystRelease.IsZero() || rev != v.ReleaseRev {
		v.AnalystRelease, v.ReleaseRev = time.Now(), rev
	}
	if v.Diverted && !v.DivertedAt.After(v.AnalystRelease) {
		v.Diverted = false
		v.Severity = SevNone
		v.Reason = "analyst"
		if v.Session != nil {
			v.Session.Event("session.released", "", SessionReleasedData{
				Reason: "analyst",
			}, nil, nil)
			v.Session = nil
		}
		return true
	}
	return false
}

// ShouldDivert determines if a visitor should be diverted based on trip severity and analyst protection.
func (rm *RecoveryManager) ShouldDivert(v *Visitor, trip Trip) bool {
	v.mu.Lock()
	defer v.mu.Unlock()

	if trip.Sev == SevNone {
		return false
	}

	// Hard trips always divert regardless of analyst protection
	if trip.Sev == SevHard {
		return true
	}

	// Soft trip: check if protected by analyst release within 24 hours
	if !v.AnalystRelease.IsZero() && time.Since(v.AnalystRelease) < AnalystProtectionWindow {
		return false
	}

	return trip.Sev == SevSoft
}
