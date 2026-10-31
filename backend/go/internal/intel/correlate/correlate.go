// Package correlate decides whether a new session belongs to an existing actor (07 §2).
// Noisy-OR over independent link signals: S = 1 − Π(1 − w). Pure and deterministic; storage is the caller's job.
package correlate

import (
	"math"
	"net/netip"
	"sort"
	"time"
)

const (
	Attach   = 0.60 // attach at S >= 0.60
	Possible = 0.40 // 0.40–0.59: shown as possible link, not merged
)

// Weights per signal (07 §2 table).
const (
	wCredentialLineage = 0.90
	wSSHKey            = 0.90
	wCredPair          = 0.40
	wIP30m             = 0.40
	wIP24h             = 0.20
	wClientFull        = 0.35
	wClientPartial     = 0.15
	wCmdSimilarityMax  = 0.40
	wCrossServiceHop   = 0.15
)

// Session is what correlation knows about one session.
type Session struct {
	ID         string
	ActorID    string // "" for the new session
	Service    string
	IP         string
	Start, End time.Time // End zero while open
	SSHBanner  string
	HASSH      string
	UA         string
	JA4        string
	SSHKeys    []string
	CredPairs  []string // already filtered: common pairs never get here
	TokensSeen []string
	TokensUsed []string
	Shingles   []uint64 // MinHash signature (see MinHash)
}

// Reason matches LinkReason in 04.
type Reason struct {
	Signal         string  `json:"signal"`
	Weight         float64 `json:"weight"`
	MatchedSession *string `json:"matched_session"`
	Value          string  `json:"value"`
}

// Result is the score of the new session against one actor.
type Result struct {
	ActorID string
	Score   float64
	Reasons []Reason
}

// Score compares the new session with every session of one actor. Each signal counts once (its best match).
func Score(n Session, actorID string, actorSessions []Session) Result {
	best := map[string]Reason{}
	add := func(signal string, w float64, matched, value string) {
		if cur, ok := best[signal]; !ok || w > cur.Weight {
			m := matched
			best[signal] = Reason{Signal: signal, Weight: round3(w), MatchedSession: &m, Value: value}
		}
	}
	for _, o := range actorSessions {
		if o.ID == n.ID {
			continue
		}
		// Credential lineage works in both orders: events from different sessions are processed in parallel,
		// so the session that used a token may be scored before the read that planted it is stored.
		for _, t := range n.TokensUsed {
			if contains(o.TokensSeen, t) {
				add("credential_lineage", wCredentialLineage, o.ID, t)
			}
		}
		for _, t := range n.TokensSeen {
			if contains(o.TokensUsed, t) {
				add("credential_lineage", wCredentialLineage, o.ID, t)
			}
		}
		for _, k := range n.SSHKeys {
			if contains(o.SSHKeys, k) {
				add("ssh_key", wSSHKey, o.ID, k)
			}
		}
		for _, p := range n.CredPairs {
			if contains(o.CredPairs, p) {
				add("cred_pair", wCredPair, o.ID, p)
			}
		}
		if n.IP != "" && n.IP == o.IP {
			gap := gapBetween(o, n)
			switch {
			case gap < 30*time.Minute:
				add("ip_30m", wIP30m, o.ID, n.IP)
			case gap < 24*time.Hour:
				add("ip_24h", wIP24h, o.ID, n.IP)
			}
		}
		if n.SSHBanner != "" && n.SSHBanner == o.SSHBanner {
			if n.HASSH != "" && n.HASSH == o.HASSH {
				add("client_ssh", wClientFull, o.ID, n.SSHBanner+" / "+n.HASSH)
			} else {
				add("client_ssh", wClientPartial, o.ID, n.SSHBanner)
			}
		}
		if n.UA != "" && n.UA == o.UA {
			if n.JA4 != "" && n.JA4 == o.JA4 {
				add("client_http", wClientFull, o.ID, n.UA+" / "+n.JA4)
			} else {
				add("client_http", wClientPartial, o.ID, n.UA)
			}
		}
		if j := Jaccard(n.Shingles, o.Shingles); j >= 0.5 {
			add("cmd_similarity", wCmdSimilarityMax*j, o.ID, "jaccard "+ftoa2(j))
		}
		if o.Service != n.Service && !o.End.IsZero() && sameSlash24(n.IP, o.IP) {
			if d := n.Start.Sub(o.End); d >= 0 && d < 120*time.Second {
				add("cross_service_hop", wCrossServiceHop, o.ID, o.Service+" → "+n.Service)
			}
		}
	}
	// ip_30m and ip_24h are exclusive.
	if _, ok := best["ip_30m"]; ok {
		delete(best, "ip_24h")
	}
	reasons := make([]Reason, 0, len(best))
	prod := 1.0
	for _, r := range best {
		prod *= 1 - r.Weight
		reasons = append(reasons, r)
	}
	sort.Slice(reasons, func(i, j int) bool {
		if reasons[i].Weight != reasons[j].Weight {
			return reasons[i].Weight > reasons[j].Weight
		}
		return reasons[i].Signal < reasons[j].Signal
	})
	return Result{ActorID: actorID, Score: round3(1 - prod), Reasons: reasons}
}

// Decision is what to do with a new session given its scores against candidate actors.
type Decision struct {
	AttachTo string   // actor to attach to ("" = create a new actor)
	Best     Result   // best-scoring result
	Merge    []string // other actors that also reach Attach: merge them into AttachTo (older wins, caller decides order)
	Possible []Result // 0.40–0.59
}

// Decide picks the best actor ≥ 0.60; ties go to the actor listed first (caller passes oldest first).
func Decide(results []Result) Decision {
	var d Decision
	for _, r := range results {
		switch {
		case r.Score >= Attach:
			if d.AttachTo == "" || r.Score > d.Best.Score {
				if d.AttachTo != "" {
					d.Merge = append(d.Merge, d.AttachTo)
				}
				d.AttachTo, d.Best = r.ActorID, r
			} else {
				d.Merge = append(d.Merge, r.ActorID)
			}
		case r.Score >= Possible:
			d.Possible = append(d.Possible, r)
		}
	}
	return d
}

func gapBetween(o, n Session) time.Duration {
	end := o.End
	if end.IsZero() {
		end = o.Start
	}
	if n.Start.Before(end) {
		return 0
	}
	return n.Start.Sub(end)
}

func sameSlash24(a, b string) bool {
	pa, err1 := netip.ParseAddr(a)
	pb, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil || !pa.Is4() || !pb.Is4() {
		return false
	}
	x, y := pa.As4(), pb.As4()
	return x[0] == y[0] && x[1] == y[1] && x[2] == y[2]
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

func ftoa2(v float64) string {
	n := int(math.Round(v * 100))
	return string([]byte{byte('0' + n/100), '.', byte('0' + n/10%10), byte('0' + n%10)})
}
