// Package logparse turns external telemetry lines into dsoc.event/v1 fields (07 §8): firewall (nftables /
// iptables kernel log or JSON), host SSH auth (sshd lines in auth.log) and real-app logins (JSON lines).
// Unparseable lines return ok=false and are counted by the collector, never fatal.
package logparse

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Parsed is one external event before it is wrapped in an envelope.
type Parsed struct {
	Service string // firewall | hostauth | appauth
	Type    string // fw.deny | fw.allow | auth.real_failed | auth.real_success | auth.app_failed | auth.app_success
	TS      time.Time
	SrcIP   string
	SrcPort int
	DstPort int
	Data    map[string]any
}

var (
	kv       = regexp.MustCompile(`([A-Z]+)=(\S*)`)
	sshdLine = regexp.MustCompile(`sshd\[\d+\]: (Failed|Accepted) (password|publickey|keyboard-interactive/pam) for (invalid user )?(\S+) from (\S+) port (\d+)`)
	syslogTS = regexp.MustCompile(`^(\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})`)
)

// Firewall parses an nftables/iptables kernel log line with prefix DSOC-DENY / DSOC-ALLOW, or a JSON line
// {"ts","action","src","sport","dst","dport","proto","rule"}.
func Firewall(line string, now time.Time) (Parsed, bool) {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "{") {
		var j struct {
			TS     string `json:"ts"`
			Action string `json:"action"`
			Src    string `json:"src"`
			Sport  int    `json:"sport"`
			Dst    string `json:"dst"`
			Dport  int    `json:"dport"`
			Proto  string `json:"proto"`
			Rule   string `json:"rule"`
		}
		if json.Unmarshal([]byte(line), &j) != nil || !validIP(j.Src) {
			return Parsed{}, false
		}
		typ := map[bool]string{true: "fw.allow", false: "fw.deny"}[strings.EqualFold(j.Action, "allow") || strings.EqualFold(j.Action, "accept")]
		return Parsed{Service: "firewall", Type: typ, TS: parseTS(j.TS, now), SrcIP: j.Src, SrcPort: j.Sport, DstPort: j.Dport,
			Data: map[string]any{"dst_ip": j.Dst, "dst_port": j.Dport, "proto": strings.ToLower(j.Proto), "rule": j.Rule}}, true
	}
	var typ string
	switch {
	case strings.Contains(line, "DSOC-DENY"):
		typ = "fw.deny"
	case strings.Contains(line, "DSOC-ALLOW"):
		typ = "fw.allow"
	default:
		return Parsed{}, false
	}
	f := map[string]string{}
	for _, m := range kv.FindAllStringSubmatch(line, -1) {
		f[m[1]] = m[2]
	}
	if !validIP(f["SRC"]) {
		return Parsed{}, false
	}
	sport, _ := strconv.Atoi(f["SPT"])
	dport, _ := strconv.Atoi(f["DPT"])
	rule := "DSOC-DENY"
	if typ == "fw.allow" {
		rule = "DSOC-ALLOW"
	}
	return Parsed{Service: "firewall", Type: typ, TS: syslogTime(line, now), SrcIP: f["SRC"], SrcPort: sport, DstPort: dport,
		Data: map[string]any{"dst_ip": f["DST"], "dst_port": dport, "proto": strings.ToLower(f["PROTO"]), "rule": rule}}, true
}

// HostAuth parses sshd "Failed/Accepted <method> for <user> from <ip> port <n>" lines.
func HostAuth(line, host string, now time.Time) (Parsed, bool) {
	m := sshdLine.FindStringSubmatch(line)
	if m == nil || !validIP(m[5]) {
		return Parsed{}, false
	}
	port, _ := strconv.Atoi(m[6])
	typ := map[bool]string{true: "auth.real_success", false: "auth.real_failed"}[m[1] == "Accepted"]
	method := m[2]
	if strings.HasPrefix(method, "keyboard") {
		method = "password"
	}
	return Parsed{Service: "hostauth", Type: typ, TS: syslogTime(line, now), SrcIP: m[5], SrcPort: port, DstPort: 22,
		Data: map[string]any{"username": m[4], "method": method, "host": host, "invalid_user": m[3] != ""}}, true
}

// AppLogin parses the real app's JSON login log {"ts","user","src_ip","result","ua","password"?}.
// A password, if present, is never kept in clear: it is replaced by a salted SHA-256 (02 §External events),
// so decoy credentials hashed the same way can be matched (07 §8.2 decoy_cred_on_real).
func AppLogin(line, app, salt string, now time.Time) (Parsed, bool) {
	var j struct {
		TS       string `json:"ts"`
		User     string `json:"user"`
		SrcIP    string `json:"src_ip"`
		Result   string `json:"result"`
		UA       string `json:"ua"`
		Password string `json:"password"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(line)), &j) != nil || !validIP(j.SrcIP) || j.User == "" {
		return Parsed{}, false
	}
	ok := strings.EqualFold(j.Result, "success") || strings.EqualFold(j.Result, "ok")
	d := map[string]any{"username": j.User, "ua": j.UA, "app": app}
	if j.Password != "" {
		d["password_hash"] = HashSecret(salt, j.Password)
	}
	return Parsed{Service: "appauth", Type: map[bool]string{true: "auth.app_success", false: "auth.app_failed"}[ok],
		TS: parseTS(j.TS, now), SrcIP: j.SrcIP, DstPort: 443, Data: d}, true
}

// HashSecret is the per-deployment salted hash used for credential matching.
func HashSecret(salt, secret string) string {
	h := sha256.Sum256([]byte(salt + "\x00" + secret))
	return hex.EncodeToString(h[:])
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func parseTS(s string, now time.Time) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC()
	}
	return now.UTC()
}

// syslogTime reads "Nov 14 09:02:11" (no year, local time) and falls back to now.
func syslogTime(line string, now time.Time) time.Time {
	m := syslogTS.FindStringSubmatch(line)
	if m == nil {
		return now.UTC()
	}
	t, err := time.ParseInLocation("Jan _2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local)
	if err != nil {
		t, err = time.ParseInLocation("Jan 2 15:04:05", strings.Join(strings.Fields(m[1]), " "), time.Local)
		if err != nil {
			return now.UTC()
		}
	}
	t = time.Date(now.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), 0, time.Local)
	if t.After(now.Add(24 * time.Hour)) { // December line read in January
		t = t.AddDate(-1, 0, 0)
	}
	return t.UTC()
}
