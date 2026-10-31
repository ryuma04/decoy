package store

import (
	"context"
)

// Policy is what decoys must enforce (04 §A GET /v1/sensor/policy).
type Policy struct {
	BlockedIPs     []string `json:"blocked_ips"`
	KilledSessions []string `json:"killed_sessions"`
	BurnedTokens   []string `json:"burned_tokens"`
	DivertedIPs    []string `json:"diverted_ips"`
	ReleasedIPs    []string `json:"released_ips"`
	Rev            int64    `json:"rev"`
}

// Policy reads the active policy rows. Rev changes whenever the set changes (hash of contents).
func (s *Store) Policy(ctx context.Context) (Policy, error) {
	p := Policy{BlockedIPs: []string{}, KilledSessions: []string{}, BurnedTokens: []string{}, DivertedIPs: []string{}, ReleasedIPs: []string{}}
	rows, err := s.Pool.Query(ctx, `SELECT kind, value, COALESCE(until::text, '') FROM policy WHERE until IS NULL OR until > now() ORDER BY kind, value`)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	var h uint64 = 14695981039346656037
	for rows.Next() {
		var kind, value, until string
		if err := rows.Scan(&kind, &value, &until); err != nil {
			return p, err
		}
		switch kind {
		case "blocked_ip":
			p.BlockedIPs = append(p.BlockedIPs, value)
		case "killed_session":
			p.KilledSessions = append(p.KilledSessions, value)
		case "burned_token":
			p.BurnedTokens = append(p.BurnedTokens, value)
		case "diverted_ip":
			p.DivertedIPs = append(p.DivertedIPs, value)
		case "released_ip":
			p.ReleasedIPs = append(p.ReleasedIPs, value)
		}
		for _, c := range []byte(kind + "=" + value + "@" + until + ";") { // until: a repeated action renews it -> new rev
			h = (h ^ uint64(c)) * 1099511628211 // FNV-1a
		}
	}
	p.Rev = int64(h >> 1)
	return p, rows.Err()
}
