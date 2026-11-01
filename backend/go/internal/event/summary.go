package event

import (
	"fmt"
	"strings"
)

// Summary returns the short deterministic one-liner shown in the live feed (Event.summary in 04).
// It never calls an LLM; narration (10 §N) is per alert / actor / on demand.
func Summary(typ string, d map[string]any) string {
	s := func(k string) string {
		v, _ := d[k].(string)
		return v
	}
	n := func(k string) string {
		switch v := d[k].(type) {
		case float64:
			return fmt.Sprintf("%.0f", v)
		case nil:
			return ""
		default:
			return fmt.Sprint(v)
		}
	}
	var out string
	switch typ {
	case "conn.open":
		out = "connection opened"
	case "conn.close":
		out = "connection closed"
		if r := s("reason"); r != "" {
			out += " (" + r + ")"
		}
	case "auth.attempt":
		res := "failed"
		if b, _ := d["success"].(bool); b {
			res = "succeeded"
		}
		who := s("username")
		if who == "" {
			who = "?"
		}
		out = fmt.Sprintf("%s login as %s %s", orDefault(s("method"), "login"), who, res)
	case "shell.command":
		out = s("raw")
	case "file.read":
		out = "read " + s("path")
	case "file.download":
		out = "downloaded " + s("path")
	case "file.upload":
		out = fmt.Sprintf("uploaded %s (%s bytes)", s("path"), n("size"))
	case "http.request":
		out = strings.TrimSpace(fmt.Sprintf("%s %s → %s", s("method"), s("path"), n("status")))
	case "k8s.api_call":
		out = strings.TrimSpace(fmt.Sprintf("k8s %s %s %s", s("verb"), s("resource"), s("namespace")))
	case "token.used":
		out = fmt.Sprintf("honeytoken %s used via %s", s("token_id"), s("via"))
	case "input.suspicious":
		out = fmt.Sprintf("suspicious input in %s: %s", s("param"), s("value"))
	case "scan.detected":
		out = "port sweep detected"
	case "maze.unlock":
		out = fmt.Sprintf("maze unlocked %s (%s)", s("to_node"), s("theme"))
	case "sensor.heartbeat":
		out = "heartbeat"
	case "fw.deny", "fw.allow":
		out = fmt.Sprintf("firewall %s %s:%s", strings.TrimPrefix(typ, "fw."), s("dst_ip"), n("dst_port"))
	case "auth.real_failed", "auth.real_success", "auth.app_failed", "auth.app_success":
		out = fmt.Sprintf("%s login as %s %s", map[bool]string{true: "real SSH", false: "app"}[strings.HasPrefix(typ, "auth.real")],
			s("username"), map[bool]string{true: "succeeded", false: "failed"}[strings.HasSuffix(typ, "success")])
	case "deception.tactic":
		out = "deception tactic applied: " + s("tactic")
	case "db.query":
		out = "SQL: " + s("query")
		if e := s("error"); e != "" {
			out += " (error " + e + ")"
		}
	case "session.diverted":
		if shadow, _ := d["shadow"].(bool); shadow {
			out = "would divert (shadow mode, visitor kept on the real site): " + s("reason")
		} else {
			out = "visitor diverted to the honeypot clone: " + s("reason")
		}
	case "session.released":
		out = "visitor released back to the real site: " + s("reason")
	default:
		out = typ
	}
	if len(out) > 200 {
		out = out[:197] + "..."
	}
	return out
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
