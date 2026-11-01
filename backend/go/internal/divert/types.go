package divert

import (
	"net/http"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// Severity indicates the seriousness of a tripwire detection.
type Severity string

const (
	SevNone Severity = "none"
	SevSoft Severity = "soft"
	SevHard Severity = "hard"
)

// Trip describes a detected condition.
type Trip struct {
	Sev    Severity `json:"sev"`
	Reason string   `json:"reason"`
	Label  string   `json:"label"`
	Param  string   `json:"param,omitempty"`
	Value  string   `json:"value,omitempty"`
}

// VisitorView provides request statistics for classification.
type VisitorView struct {
	NotFound5m      int `json:"not_found_5m"`
	FailedLogins10m int `json:"failed_logins_10m"`
	RequestsPerMin  int `json:"requests_per_min"`
}

// Classifier inspects incoming requests and visitor statistics.
type Classifier interface {
	Classify(r *http.Request, body []byte, v VisitorView) Trip
}

// Honeytoken represents a lure value that triggers diversion.
type Honeytoken struct {
	TokenID    string `json:"token_id"`
	Kind       string `json:"kind"`
	MatchValue string `json:"match_value"`
}

// Visitor tracks routing, detection, and recovery state for an individual visitor.
type Visitor struct {
	mu             sync.Mutex
	ID             string
	IP             string
	UA             string
	Diverted       bool
	Severity       Severity
	Reason         string
	Label          string
	DivertedAt     time.Time
	LastTrip       time.Time
	CleanReqs      int
	DivertCount    int
	Session        *sensorkit.Session
	AnalystRelease time.Time // when this visitor first saw the current analyst release of its IP
	ReleaseRev     int64     // policy revision of that release (a new click on Release changes it)
	TacticsEmitted map[string]bool
	Held           []HeldAction // soft-divert write requests recorded for replay on release (heldqueue.go)

	LastSeen   time.Time
	CookieSeen bool // the client sent our visitor cookie back (a browser), so it is never merged by IP+UA

	// Admin honeypot host: the real shop accepted this visitor's login; StaffToken is the admin_token it set.
	Staff      bool
	StaffToken string
	// Shadow mode: reasons already reported for this visitor, and its report session.
	ShadowSeen    map[string]bool
	ShadowSession *sensorkit.Session

	// Counters for sliding window metrics
	NotFoundTimes []time.Time
	FailedLogins  []time.Time
	RequestTimes  []time.Time
}

// SessionReleasedData is the event payload for session.released.
type SessionReleasedData struct {
	Reason        string `json:"reason"`
	CleanRequests int    `json:"clean_requests,omitempty"`
	Seconds       int    `json:"seconds,omitempty"`
	HeldReplayed  int    `json:"held_replayed,omitempty"` // held contact messages now being delivered to the real shop
}

// SessionDivertedData is the event payload for session.diverted.
type SessionDivertedData struct {
	Reason   string   `json:"reason"`
	Severity Severity `json:"severity"`
	Label    string   `json:"label,omitempty"`
}

// HeldErrorResponse matches the shop's own checkout/contact hold error shape.
type HeldErrorResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error"`
}
