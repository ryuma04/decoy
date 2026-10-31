package engine

import (
	_ "embed"
	"encoding/json"
	"strings"

	"github.com/ryuma04/decoy/backend/internal/store"
)

//go:embed common_creds.txt
var commonCredsTxt string

// commonCreds are username:password pairs too common to link sessions (07 §1 cred_pair).
var commonCreds = func() map[string]bool {
	m := map[string]bool{}
	for _, l := range strings.Split(commonCredsTxt, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			m[strings.ToLower(l)] = true
		}
	}
	return m
}()

// fingerprints extracts fingerprint rows from one stored event (07 §1). cmd_shingles is added by the engine.
func fingerprints(ev store.StoredEvent) []store.Fingerprint {
	var env struct {
		Client *struct {
			SSHBanner string `json:"ssh_banner"`
			SSHKeyFP  string `json:"ssh_key_fp"`
			HASSH     string `json:"hassh"`
			UA        string `json:"ua"`
			JA4       string `json:"ja4"`
		} `json:"client"`
	}
	_ = json.Unmarshal(ev.Envelope, &env)
	d := map[string]any{}
	_ = json.Unmarshal(ev.Data, &d)
	str := func(k string) string { v, _ := d[k].(string); return v }

	var out []store.Fingerprint
	add := func(kind, value string) {
		if value != "" && len(value) <= 512 && ev.SessionID != "" {
			out = append(out, store.Fingerprint{SessionID: ev.SessionID, Kind: kind, Value: value, TS: ev.TS})
		}
	}
	if c := env.Client; c != nil {
		add("ssh_banner", c.SSHBanner)
		add("ssh_key", c.SSHKeyFP)
		add("hassh", c.HASSH)
		add("ua", c.UA)
		add("ja4", c.JA4)
	}
	switch ev.Type {
	case "auth.attempt":
		add("ssh_key", str("key_fp"))
		if u, p := str("username"), str("password"); u != "" && p != "" {
			pair := u + ":" + p
			if !commonCreds[strings.ToLower(pair)] {
				add("cred_pair", pair)
			}
		}
	case "http.request":
		add("ua", str("ua"))
	case "file.read", "file.download":
		add("token_seen", str("honeyfile_id"))
	case "token.used":
		add("token_used", str("token_id"))
	}
	for _, t := range ev.Tokens {
		if ev.Type == "token.used" {
			add("token_used", t)
		} else {
			add("token_seen", t)
		}
	}
	return out
}
