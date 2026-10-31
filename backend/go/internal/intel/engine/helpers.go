package engine

import (
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/intel/correlate"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// shingles keeps each session's recent commands and emits a cmd_shingles fingerprint at 5, 10 and 20 commands (07 §1).
func (e *Engine) shingles(ev store.StoredEvent) (store.Fingerprint, bool) {
	if ev.Type != "shell.command" {
		return store.Fingerprint{}, false
	}
	var d struct {
		Raw string `json:"raw"`
	}
	_ = json.Unmarshal(ev.Data, &d)
	if strings.TrimSpace(d.Raw) == "" {
		return store.Fingerprint{}, false
	}
	e.mu.Lock()
	cmds := append(e.commands[ev.SessionID], d.Raw)
	if len(cmds) > 40 {
		cmds = cmds[len(cmds)-40:]
	}
	e.commands[ev.SessionID] = cmds
	if len(e.commands) > 5000 { // bound memory: drop everything; fingerprints already stored stay valid
		e.commands = map[string][]string{ev.SessionID: cmds}
	}
	n := len(cmds)
	snapshot := append([]string(nil), cmds...)
	e.mu.Unlock()
	if n != 5 && n != 10 && n != 20 {
		return store.Fingerprint{}, false
	}
	return store.Fingerprint{SessionID: ev.SessionID, Kind: "cmd_shingles", Value: encodeSig(correlate.MinHash(snapshot)), TS: ev.TS}, true
}

func encodeSig(sig []uint64) string {
	b := make([]byte, 8*len(sig))
	for i, v := range sig {
		for j := 0; j < 8; j++ {
			b[8*i+j] = byte(v >> (56 - 8*j))
		}
	}
	return hex.EncodeToString(b)
}

func decodeSig(s string) []uint64 {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 8*correlate.Perms {
		return nil
	}
	out := make([]uint64, correlate.Perms)
	for i := range out {
		var v uint64
		for j := 0; j < 8; j++ {
			v = v<<8 | uint64(b[8*i+j])
		}
		out[i] = v
	}
	return out
}

// scanDetector flags ≥ 3 distinct decoy ports touched by one IP within 60 s (07 rule port_sweep), once per window.
type scanDetector struct {
	mu       sync.Mutex
	seen     map[string]map[int]time.Time // ip -> port -> last seen
	reported map[string]time.Time
}

func newScanDetector() *scanDetector {
	return &scanDetector{seen: map[string]map[int]time.Time{}, reported: map[string]time.Time{}}
}

const scanWindow = 60 * time.Second

func (s *scanDetector) observe(ev store.StoredEvent) ([]int, bool) {
	if ev.Type != "conn.open" && ev.Type != "http.request" {
		return nil, false
	}
	var env struct {
		Dst struct {
			Port int `json:"port"`
		} `json:"dst"`
	}
	_ = json.Unmarshal(ev.Envelope, &env)
	if env.Dst.Port == 0 {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ports := s.seen[ev.SrcIP]
	if ports == nil {
		ports = map[int]time.Time{}
		s.seen[ev.SrcIP] = ports
	}
	ports[env.Dst.Port] = ev.TS
	var recent []int
	for p, t := range ports {
		if ev.TS.Sub(t) <= scanWindow {
			recent = append(recent, p)
		} else {
			delete(ports, p)
		}
	}
	if len(recent) < 3 || ev.TS.Sub(s.reported[ev.SrcIP]) < scanWindow {
		return nil, false
	}
	s.reported[ev.SrcIP] = ev.TS
	sort.Ints(recent)
	return recent, true
}
