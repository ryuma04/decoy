package ssh

import (
	"strings"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/fakefs"
	"github.com/ryuma04/decoy/backend/internal/persona"
)

func newShell(t *testing.T, user string) *Shell {
	t.Helper()
	p := persona.Generate("test-seed")
	u, _ := p.User(user)
	lures := []Lure{
		{Path: "/home/deploy/.aws/credentials", Content: "[default]\naws_access_key_id = AKIATEST\n", HoneyfileID: "tok_aws_k7", MazeNode: "lure_aws", Owner: "deploy"},
		{Path: "/opt/deploy/kubeconfig", Content: "apiVersion: v1\n", HoneyfileID: "tok_kube", MazeNode: "lure_kubeconfig", Owner: "deploy", Hidden: true},
	}
	return &Shell{FS: fakefs.NewSession(BaseTree(p, lures)), P: p, User: u, Cwd: u.Home,
		History: func() []string { return []string{"id"} }, Started: time.Now()}
}

func TestBasicCommands(t *testing.T) {
	sh := newShell(t, "deploy")
	cases := map[string]string{
		"whoami":        "deploy\n",
		"pwd":           "/home/deploy\n",
		"hostname":      sh.P.Hostname + "\n",
		"echo hi there": "hi there\n",
	}
	for line, want := range cases {
		if r := sh.Run(line); r.Output != want || r.Exit != 0 {
			t.Errorf("%q: got %q exit %d", line, r.Output, r.Exit)
		}
	}
	if r := sh.Run("id"); !strings.Contains(r.Output, "uid=1001(deploy)") {
		t.Errorf("id: %q", r.Output)
	}
	if r := sh.Run("uname -a"); !strings.Contains(r.Output, sh.P.Kernel) {
		t.Errorf("uname: %q", r.Output)
	}
	if r := sh.Run("nmap -sS 10.0.0.0/24"); r.Exit != 127 || !strings.Contains(r.Output, "command not found") || r.Argv0 != "nmap" {
		t.Errorf("unknown: %+v", r)
	}
}

func TestCatReportsHoneyfileRead(t *testing.T) {
	sh := newShell(t, "deploy")
	r := sh.Run("cat ~/.aws/credentials")
	if !strings.Contains(r.Output, "AKIATEST") || len(r.Reads) != 1 || r.Reads[0].HoneyfileID != "tok_aws_k7" ||
		r.Reads[0].Path != "/home/deploy/.aws/credentials" {
		t.Fatalf("%+v", r)
	}
	if r := sh.Run("cat /etc/shadow"); r.Exit != 1 || !strings.Contains(r.Output, "Permission denied") {
		t.Fatalf("shadow readable by deploy: %+v", r)
	}
}

func TestHiddenLureInvisibleUntilUnlocked(t *testing.T) {
	sh := newShell(t, "deploy")
	if r := sh.Run("cat /opt/deploy/kubeconfig"); r.Exit != 1 {
		t.Fatalf("hidden lure served: %+v", r)
	}
	if r := sh.Run("ls /opt/deploy"); strings.Contains(r.Output, "kubeconfig") {
		t.Fatalf("hidden lure listed: %q", r.Output)
	}
	sh.FS.SetVisible([]string{"lure_kubeconfig"})
	if r := sh.Run("cat /opt/deploy/kubeconfig"); r.Exit != 0 || r.Reads[0].HoneyfileID != "tok_kube" {
		t.Fatalf("unlocked lure not served: %+v", r)
	}
}

func TestOperatorsAndRedirect(t *testing.T) {
	sh := newShell(t, "deploy")
	r := sh.Run("cd /nope && echo no; echo yes || echo never")
	if !strings.Contains(r.Output, "No such file") || strings.Contains(r.Output, "no\n") || !strings.Contains(r.Output, "yes\n") ||
		strings.Contains(r.Output, "never") {
		t.Fatalf("operators: %q", r.Output)
	}
	sh.Run("echo hello > /tmp/x")
	if r := sh.Run("cat /tmp/x"); r.Output != "hello\n" {
		t.Fatalf("redirect: %q", r.Output)
	}
	if r := sh.Run(`echo "a ; b"`); r.Output != "a ; b\n" {
		t.Fatalf("quotes: %q", r.Output)
	}
	if r := sh.Run("cat /etc/hostname | cat"); r.Output != sh.P.Hostname+"\n" {
		t.Fatalf("pipe: %q", r.Output)
	}
}

func TestLsAndCd(t *testing.T) {
	sh := newShell(t, "deploy")
	if r := sh.Run("ls -la"); !strings.Contains(r.Output, ".aws") || !strings.Contains(r.Output, "notes.txt") {
		t.Fatalf("ls -la: %q", r.Output)
	}
	if r := sh.Run("ls"); strings.Contains(r.Output, ".bashrc") {
		t.Fatalf("ls shows dotfiles: %q", r.Output)
	}
	sh.Run("cd /etc")
	if r := sh.Run("pwd"); r.Output != "/etc\n" {
		t.Fatalf("cd: %q", r.Output)
	}
	if r := sh.Run("exit"); !r.Logout {
		t.Fatal("exit did not log out")
	}
}

func TestStdoutTokens(t *testing.T) {
	sh := newShell(t, "deploy")
	r := sh.Run("ls -a /home/deploy")
	found := false
	for _, tok := range r.StdoutTokens {
		if tok == "notes.txt" {
			found = true
		}
	}
	if !found || len(r.StdoutTokens) > 50 {
		t.Fatalf("tokens %v", r.StdoutTokens)
	}
}
