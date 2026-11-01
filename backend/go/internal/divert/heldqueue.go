package divert

// Held actions (false-positive recovery, docs/09 §Recovery): while a visitor is SOFT-diverted, safe write requests
// to allow-listed endpoints are recorded instead of executed, and answered the way the real shop would. When the
// visitor is released (clean behaviour, analyst, verified login) they are replayed once on the real shop.
// Checkout is never queued (payment needs the customer); a visitor who turns HARD loses the queue (attacker).

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// replayable lists the endpoints whose held requests may be re-sent to the real shop after release.
var replayable = map[string]bool{"/api/contact": true}

const (
	maxHeldPerVisitor = 5
	maxHeldBody       = 16 << 10
	heldTTL           = 24 * time.Hour
	replayAttempts    = 3
)

var replayBackoff = []time.Duration{time.Second, 3 * time.Second} // between attempts; tests shorten it

// HeldAction is one recorded request waiting for the visitor's release.
type HeldAction struct {
	Path        string
	ContentType string
	UA          string
	Body        []byte
	At          time.Time
}

// queueHeld records a replayable request. False: not queued (queue full, body too large): the caller falls back to
// the "please try again" answer so nothing is ever silently lost.
func (rm *RecoveryManager) queueHeld(v *Visitor, r *http.Request, body []byte) bool {
	if !replayable[r.URL.Path] || len(body) == 0 || len(body) > maxHeldBody {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if len(v.Held) >= maxHeldPerVisitor {
		return false
	}
	v.Held = append(v.Held, HeldAction{Path: r.URL.Path, ContentType: r.Header.Get("Content-Type"), UA: r.UserAgent(),
		Body: append([]byte(nil), body...), At: time.Now()})
	return true
}

// takeHeldLocked removes and returns the still-valid held actions. The caller holds v.mu.
func takeHeldLocked(v *Visitor) []HeldAction {
	var out []HeldAction
	for _, a := range v.Held {
		if time.Since(a.At) < heldTTL {
			out = append(out, a)
		}
	}
	v.Held = nil
	return out
}

// startReplay re-sends held actions to the real shop in the background, once each, with retries for transient
// failures. Results are reported on the visitor's (now released) session so the analyst sees what was done.
func (rm *RecoveryManager) startReplay(ip string, acts []HeldAction, sess *sensorkit.Session) {
	if len(acts) == 0 || rm.cfg.RealURL == nil {
		return
	}
	go func() {
		for _, a := range acts {
			status, attempts := rm.replayOne(ip, a)
			outcome := "delivered"
			if status < 200 || status > 299 {
				outcome = "failed"
				slog.Warn("held action replay failed", "path", a.Path, "status", status, "attempts", attempts)
			}
			if sess != nil {
				sess.Event("http.request", "", map[string]any{
					"method": http.MethodPost, "path": a.Path, "status": status, "ua": a.UA,
					"replay": true, "outcome": outcome, "attempts": attempts, "held_seconds": int(time.Since(a.At).Seconds()),
				}, nil, nil)
			}
		}
	}()
}

// replayOne posts one held action to the real shop. Retries on network errors, 429 and 5xx; a 4xx means the shop
// rejected the content itself, so it is not retried.
func (rm *RecoveryManager) replayOne(ip string, a HeldAction) (int, int) {
	client := rm.cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	target := strings.TrimRight(rm.cfg.RealURL.String(), "/") + a.Path
	status := 0
	for attempt := 1; attempt <= replayAttempts; attempt++ {
		req, err := http.NewRequest(http.MethodPost, target, bytes.NewReader(a.Body))
		if err != nil {
			return 0, attempt
		}
		if a.ContentType != "" {
			req.Header.Set("Content-Type", a.ContentType)
		}
		req.Header.Set("User-Agent", a.UA)
		req.Header.Set("X-Forwarded-For", ip) // the shop's own spam limits still apply to this visitor
		resp, err := client.Do(req)
		if err == nil {
			status = resp.StatusCode
			resp.Body.Close()
			if status < 500 && status != http.StatusTooManyRequests {
				return status, attempt
			}
		}
		if attempt < replayAttempts {
			time.Sleep(replayBackoff[min(attempt-1, len(replayBackoff)-1)])
		}
	}
	return status, replayAttempts
}
