// Package inputrisk grades one attacker-typed value (07 §4.1): a deterministic pattern check, the ML
// input-risk model when available, and the combination of both into one label + risk 0–1.
package inputrisk

import (
	"context"
	"net/url"
	"regexp"
	"strings"

	"github.com/ryuma04/decoy/backend/internal/mlclient"
)

// Result is what the rule engine sees (rules.InputRisk) plus details for evidence.
type Result struct {
	Label       string
	Risk        float64
	Source      string // rule | ml | rule+ml
	TopFeatures []string
	Payload     string
	WasEncoded  bool
}

var (
	plain    = regexp.MustCompile(`^[A-Za-z0-9 _.,@:/+-]{0,64}$`)
	notPlain = regexp.MustCompile(`(?i)\.\.|--|file:|(^|/)(etc|proc|root|var/log|windows)/|\.ini\b`)

	// Same families the web decoy pre-checks (06 §2), re-run here after decoding. Order matters: a shell
	// separator followed by a command beats a sensitive path inside that command.
	patterns = []struct {
		label string
		re    *regexp.Regexp
	}{
		{"sqli", regexp.MustCompile(`(?i)'\s*(or|and)\s+['"\d]|union\s+(all\s+)?select|;\s*(drop|insert|update|delete|exec)\b|\b(sleep|pg_sleep|benchmark|waitfor\s+delay)\s*\(|'\s*(--|#|/\*)`)},
		{"xss", regexp.MustCompile(`(?i)<\s*script|javascript:|\bon(error|load|focus|mouseover|toggle)\s*=|<\s*(svg|img|iframe|object|embed|base|meta)\b`)},
		{"cmd_injection", regexp.MustCompile("(;|&&|\\|\\||\\||`|\\$\\(|\n)\\s*[a-z/.]")},
		{"path_traversal", regexp.MustCompile(`(\.\.[/\\]){2,}|^\.\.[/\\]|(^|/)etc/(passwd|shadow|hosts)\b|win\.ini|boot\.ini|^file:`)},
	}
)

// IsPlain is the fast path: plain values never reach the model and get risk 0 (same rule as the ML service).
func IsPlain(v string) bool { return plain.MatchString(v) && !notPlain.MatchString(v) }

// Decode URL-decodes up to twice.
func Decode(v string) (string, bool) {
	out := v
	for i := 0; i < 2; i++ {
		d, err := url.QueryUnescape(out)
		if err != nil || d == out {
			break
		}
		out = d
	}
	return out, out != v
}

// RuleCheck returns the first matching family on the decoded value ("" when nothing matches).
func RuleCheck(v string) string {
	d, _ := Decode(v)
	for _, p := range patterns {
		if p.re.MatchString(d) {
			return p.label
		}
	}
	return ""
}

var sep = regexp.MustCompile("\\$\\(|&&|\\|\\||\n|;|\\||`")

// Payload is the text after the first shell separator (decoded).
func Payload(v string) string {
	d, _ := Decode(v)
	loc := sep.FindStringIndex(d)
	if loc == nil {
		return ""
	}
	p := strings.TrimSpace(d[loc[1]:])
	p = strings.TrimSuffix(strings.TrimSuffix(p, ")"), "`")
	if len(p) > 500 {
		p = p[:500]
	}
	return strings.TrimSpace(p)
}

const ruleRisk = 0.9

// Grade combines the rule check and the model (07 §4.1 step 3). ml may be nil (ML off).
func Grade(ctx context.Context, ml *mlclient.Client, param, value, service, path, field string) Result {
	if IsPlain(value) {
		return Result{Label: "normal"}
	}
	ruleLabel := RuleCheck(value)
	_, enc := Decode(value)
	var model *mlclient.InputResult
	if ml.Enabled() {
		if r, err := ml.ClassifyInput(ctx, param, value, service, path, field); err == nil {
			model = &r
		}
	}
	var res Result
	switch {
	case model != nil && ruleLabel != "" && model.Label == ruleLabel:
		res = Result{Label: ruleLabel, Risk: max(ruleRisk, model.Risk), Source: "rule+ml"}
	case model != nil && ruleLabel == "":
		res = Result{Label: model.Label, Risk: model.Risk, Source: "ml"}
	case model != nil && ruleLabel != "" && model.Label != ruleLabel:
		if model.Risk >= 0.8 && model.Label != "normal" {
			res = Result{Label: model.Label, Risk: model.Risk, Source: "ml"}
		} else {
			res = Result{Label: ruleLabel, Risk: ruleRisk, Source: "rule"}
		}
	case ruleLabel != "":
		res = Result{Label: ruleLabel, Risk: ruleRisk, Source: "rule"}
	default:
		return Result{Label: "normal", WasEncoded: enc}
	}
	res.WasEncoded = enc
	if model != nil {
		res.TopFeatures = model.TopFeatures
		res.WasEncoded = res.WasEncoded || model.WasEncoded
	}
	if res.Label == "cmd_injection" {
		if model != nil && model.Payload != nil {
			res.Payload = *model.Payload
		} else {
			res.Payload = Payload(value)
		}
	}
	return res
}
