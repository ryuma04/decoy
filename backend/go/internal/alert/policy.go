// Package alert turns incident changes into notifications (09): who gets told, when, and with what text.
package alert

import "time"

var rank = map[string]int{"low": 0, "medium": 1, "high": 2, "critical": 3}

// Rank orders severities (unknown = -1).
func Rank(sev string) int {
	if r, ok := rank[sev]; ok {
		return r
	}
	return -1
}

// OpensIncident: an incident opens when the actor first reaches medium (09).
func OpensIncident(sev string) bool { return Rank(sev) >= rank["medium"] }

// Raise returns the new incident severity: it only goes up automatically.
func Raise(current, next string) string {
	if Rank(next) > Rank(current) {
		return next
	}
	return current
}

// Channel decides how a notification goes out.
type Channel int

const (
	None         Channel = iota // dashboard only
	Digest                      // medium: batched every 15 min
	Immediate                   // high: Discord now
	ImmediateAll                // critical: Discord with @here + Slack now
)

const (
	Cooldown       = 10 * time.Minute
	DigestInterval = 15 * time.Minute
)

// NotifyState is what the incident row remembers (incidents.notified_at / notified_severity).
type NotifyState struct {
	NotifiedAt       *time.Time
	NotifiedSeverity string
}

// Decide returns the channel for an incident at severity sev, given what was already sent.
// Re-notify only when severity rises, and not within the 10 min cooldown (09).
func Decide(sev string, st NotifyState, now time.Time) Channel {
	if st.NotifiedSeverity != "" && Rank(sev) <= Rank(st.NotifiedSeverity) {
		return None
	}
	if st.NotifiedAt != nil && now.Sub(*st.NotifiedAt) < Cooldown && sev != "critical" {
		return None // critical always gets through: it is the top step and only happens once
	}
	switch sev {
	case "critical":
		return ImmediateAll
	case "high":
		return Immediate
	case "medium":
		return Digest
	}
	return None
}

// Colour per severity for Discord embeds (09).
func Colour(sev string) int {
	switch sev {
	case "critical":
		return 15158332
	case "high":
		return 15105570
	case "medium":
		return 16776960
	}
	return 3447003
}
