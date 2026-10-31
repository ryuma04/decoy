package inputrisk

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ryuma04/decoy/backend/internal/mlclient"
)

func TestFastPathMatchesMLService(t *testing.T) {
	for _, v := range []string{"deploy", "a.b-c.com", "Priya Patel", "10.0.0.12", "priya@x.com"} {
		if !IsPlain(v) {
			t.Errorf("%q should be plain", v)
		}
	}
	for _, v := range []string{"/etc/passwd", "../x", "x--", "a;b", "file:///x", "C:/windows/win.ini"} {
		if IsPlain(v) {
			t.Errorf("%q must not be plain", v)
		}
	}
}

func TestRuleCheckFamilies(t *testing.T) {
	cases := map[string]string{
		"8.8.8.8; cat /etc/passwd":      "cmd_injection",
		"8.8.8.8%3Bid":                  "cmd_injection",
		"x$(whoami)":                    "cmd_injection",
		"' OR '1'='1":                   "sqli",
		"1 UNION SELECT a FROM b":       "sqli",
		"<script>alert(1)</script>":     "xss",
		"<img src=x onerror=alert(1)>":  "xss",
		"../../../etc/passwd":           "path_traversal",
		"%2e%2e%2f%2e%2e%2fetc%2fhosts": "path_traversal",
		"O'Brien":                       "",
		"Q3 report final":               "",
	}
	for v, want := range cases {
		if got := RuleCheck(v); got != want {
			t.Errorf("%q: got %q want %q", v, got, want)
		}
	}
}

func TestPayload(t *testing.T) {
	for v, want := range map[string]string{"8.8.8.8; cat /etc/passwd": "cat /etc/passwd", "x$(id)": "id", "a`uname -a`": "uname -a", "plain": ""} {
		if got := Payload(v); got != want {
			t.Errorf("%q: %q want %q", v, got, want)
		}
	}
}

func mlServer(body string) (*mlclient.Client, func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
	return mlclient.New(srv.URL), srv.Close
}

func TestGradeCombinations(t *testing.T) {
	ctx := context.Background()
	if r := Grade(ctx, nil, "host", "8.8.8.8; id", "web", "/api/diagnostics", "query"); r.Label != "cmd_injection" || r.Risk != 0.9 || r.Source != "rule" || r.Payload != "id" {
		t.Fatalf("rule only: %+v", r)
	}
	if r := Grade(ctx, nil, "q", "deploy", "web", "/", "query"); r.Label != "normal" || r.Risk != 0 {
		t.Fatalf("plain: %+v", r)
	}
	agree, stop := mlServer(`{"label":"cmd_injection","risk":0.97,"scores":{},"top_features":["; id"],"payload":"id","was_encoded":false}`)
	defer stop()
	if r := Grade(ctx, agree, "host", "8.8.8.8; id", "web", "/", "query"); r.Source != "rule+ml" || r.Risk != 0.97 || len(r.TopFeatures) != 1 {
		t.Fatalf("agree: %+v", r)
	}
	onlyML, stop2 := mlServer(`{"label":"xss","risk":0.82,"scores":{},"top_features":["<style"],"payload":null,"was_encoded":true}`)
	defer stop2()
	if r := Grade(ctx, onlyML, "q", "<style>@import'//e.test'</style>", "web", "/", "query"); r.Source != "ml" || r.Label != "xss" || !r.WasEncoded {
		t.Fatalf("ml only: %+v", r)
	}
	weak, stop3 := mlServer(`{"label":"sqli","risk":0.6,"scores":{},"top_features":[],"payload":null,"was_encoded":false}`)
	defer stop3()
	if r := Grade(ctx, weak, "host", "8.8.8.8; id", "web", "/", "query"); r.Label != "cmd_injection" || r.Source != "rule" {
		t.Fatalf("disagree, weak model: %+v", r)
	}
}
