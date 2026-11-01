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

func TestNewSystemInfoCommands(t *testing.T) {
	sh := newShell(t, "deploy")
	table := []struct {
		cmd      string
		wantExit int
		contains string
	}{
		{"ps", 0, "bash"},
		{"ps aux", 0, "USER"},
		{"ps -ef", 0, "UID"},
		{"top", 0, "Tasks:"},
		{"w", 0, "USER"},
		{"uptime", 0, "load average"},
		{"date", 0, "UTC"},
		{"df", 0, "/dev/sda1"},
		{"df -h", 0, "39G"},
		{"free", 0, "Mem:"},
		{"free -m", 0, "Mem:"},
		{"free -h", 0, "Mem:"},
		{"env", 0, "SHELL=/bin/bash"},
		{"printenv USER", 0, "deploy"},
		{"netstat", 0, "ESTABLISHED"},
		{"ss", 0, "LISTEN"},
		{"ip a", 0, sh.P.InternalIP},
		{"ip route", 0, "default via"},
		{"ifconfig", 0, sh.P.InternalIP},
		{"which ls", 0, "/usr/bin/ls"},
		{"which nonexistentcommand123", 1, ""},
		{"crontab -l", 1, "no crontab for deploy"},
		{"crontab", 1, "usage error"},
		{"mysql", 1, "Can't connect to local MySQL server"},
		{"psql", 2, "connection to server on socket"},
		{"docker", 1, "Cannot connect to the Docker daemon"},
		{"kubectl", 1, "The connection to the server localhost:8080 was refused"},
		{"python3 -c 'print(1)'", 0, ""},
		{"perl -e 'print 1'", 0, ""},
		{"bash -c 'echo 1'", 0, ""},
		{"sh -c 'echo 1'", 0, ""},
		{"nc -lvp 4444", 0, ""},
		{"export FOO=BAR", 0, ""},
		{"export", 0, "USER="},
		{"alias", 0, "alias ll="},
		{"alias ll='ls -l'", 0, ""},
		{"sleep 1", 0, ""},
	}

	for _, tc := range table {
		r := sh.Run(tc.cmd)
		if r.Exit != tc.wantExit {
			t.Errorf("%q: expected exit %d, got %d (output: %q)", tc.cmd, tc.wantExit, r.Exit, r.Output)
		}
		if tc.contains != "" && !strings.Contains(r.Output, tc.contains) {
			t.Errorf("%q: output %q does not contain %q", tc.cmd, r.Output, tc.contains)
		}
	}
}

func TestFindHiddenLureAndWalk(t *testing.T) {
	sh := newShell(t, "deploy")
	// find before unlock
	r := sh.Run("find /opt")
	if strings.Contains(r.Output, "kubeconfig") {
		t.Fatalf("find revealed hidden lure: %q", r.Output)
	}

	// find after unlock
	sh.FS.SetVisible([]string{"lure_kubeconfig"})
	r = sh.Run("find /opt")
	if !strings.Contains(r.Output, "/opt/deploy/kubeconfig") {
		t.Fatalf("find failed to list unlocked lure: %q", r.Output)
	}

	// find with -name
	r = sh.Run(`find /home/deploy -name "*.txt"`)
	if !strings.Contains(r.Output, "notes.txt") {
		t.Fatalf("find -name notes.txt failed: %q", r.Output)
	}

	// find with -type d
	r = sh.Run("find /etc -type d")
	if strings.Contains(r.Output, "/etc/shadow") || !strings.Contains(r.Output, "/etc/app") {
		t.Fatalf("find -type d error: %q", r.Output)
	}
}

func TestGrepHeadTailWcHoneyfileReads(t *testing.T) {
	sh := newShell(t, "deploy")

	// grep
	rGrep := sh.Run("grep AKIA ~/.aws/credentials")
	if rGrep.Exit != 0 || !strings.Contains(rGrep.Output, "AKIATEST") || len(rGrep.Reads) != 1 || rGrep.Reads[0].HoneyfileID != "tok_aws_k7" {
		t.Fatalf("grep honeyfile read failed: %+v", rGrep)
	}
	// grep -l
	rGrepL := sh.Run("grep -l AKIA ~/.aws/credentials")
	if rGrepL.Exit != 0 || !strings.Contains(rGrepL.Output, ".aws/credentials") {
		t.Fatalf("grep -l failed: %+v", rGrepL)
	}
	// grep -n
	rGrepN := sh.Run("grep -n AKIA ~/.aws/credentials")
	if rGrepN.Exit != 0 || !strings.Contains(rGrepN.Output, ":") {
		t.Fatalf("grep -n failed: %+v", rGrepN)
	}
	// grep stdin
	rGrepStdin := sh.Run("echo hello world | grep world")
	if rGrepStdin.Exit != 0 || rGrepStdin.Output != "hello world\n" {
		t.Fatalf("grep stdin failed: %+v", rGrepStdin)
	}

	// head
	rHead := sh.Run("head -n 1 ~/.aws/credentials")
	if rHead.Exit != 0 || !strings.Contains(rHead.Output, "[default]") || len(rHead.Reads) != 1 || rHead.Reads[0].HoneyfileID != "tok_aws_k7" {
		t.Fatalf("head honeyfile read failed: %+v", rHead)
	}
	rHeadStdin := sh.Run("head -n 2 /etc/passwd")
	if !strings.Contains(rHeadStdin.Output, "root:") || !strings.Contains(rHeadStdin.Output, "daemon:") {
		t.Fatalf("head stdin failed: %+v", rHeadStdin)
	}

	// tail
	rTail := sh.Run("tail -n 1 ~/.aws/credentials")
	if rTail.Exit != 0 || !strings.Contains(rTail.Output, "AKIATEST") || len(rTail.Reads) != 1 || rTail.Reads[0].HoneyfileID != "tok_aws_k7" {
		t.Fatalf("tail honeyfile read failed: %+v", rTail)
	}

	// wc
	rWc := sh.Run("wc -l ~/.aws/credentials")
	if rWc.Exit != 0 || len(rWc.Reads) != 1 || rWc.Reads[0].HoneyfileID != "tok_aws_k7" {
		t.Fatalf("wc honeyfile read failed: %+v", rWc)
	}
	rWcStdin := sh.Run("cat /etc/passwd | wc -l")
	if rWcStdin.Exit != 0 || rWcStdin.Output == "0\n" {
		t.Fatalf("wc stdin failed: %+v", rWcStdin)
	}
}

func TestOverlayChangesIsolatedPerSession(t *testing.T) {
	sh1 := newShell(t, "deploy")
	sh2 := newShell(t, "deploy")

	// touch & isolation
	r1 := sh1.Run("touch /tmp/created_in_s1.txt")
	if r1.Exit != 0 {
		t.Fatalf("touch failed: %+v", r1)
	}
	if sh1.Run("cat /tmp/created_in_s1.txt").Exit != 0 {
		t.Fatalf("file not found in session 1")
	}
	if sh2.Run("cat /tmp/created_in_s1.txt").Exit == 0 {
		t.Fatalf("file leaked into session 2!")
	}

	// mkdir -p & isolation
	rMkdir := sh1.Run("mkdir -p /tmp/d1/d2")
	if rMkdir.Exit != 0 {
		t.Fatalf("mkdir -p failed: %+v", rMkdir)
	}
	if !strings.Contains(sh1.Run("ls /tmp/d1").Output, "d2") {
		t.Fatalf("d2 not found in s1")
	}
	if sh2.Run("ls /tmp/d1").Exit == 0 {
		t.Fatalf("mkdir leaked into s2!")
	}

	// cp honeyfile
	rCp := sh1.Run("cp ~/.aws/credentials /tmp/copied_cred")
	if rCp.Exit != 0 || len(rCp.Reads) != 1 || rCp.Reads[0].HoneyfileID != "tok_aws_k7" {
		t.Fatalf("cp failed or missed honeyfile read: %+v", rCp)
	}
	if !strings.Contains(sh1.Run("cat /tmp/copied_cred").Output, "AKIATEST") {
		t.Fatalf("copied content missing in s1")
	}
	if sh2.Run("cat /tmp/copied_cred").Exit == 0 {
		t.Fatalf("copied file leaked into s2!")
	}

	// mv
	rMv := sh1.Run("mv /tmp/copied_cred /tmp/moved_cred")
	if rMv.Exit != 0 {
		t.Fatalf("mv failed: %+v", rMv)
	}
	if sh1.Run("cat /tmp/copied_cred").Exit == 0 {
		t.Fatalf("source still exists after mv")
	}
	if !strings.Contains(sh1.Run("cat /tmp/moved_cred").Output, "AKIATEST") {
		t.Fatalf("moved file missing content")
	}

	// chmod & chown
	if r := sh1.Run("chmod 700 /tmp/moved_cred"); r.Exit != 0 {
		t.Fatalf("chmod failed: %+v", r)
	}
	if r := sh1.Run("chown root /tmp/moved_cred"); r.Exit != 0 {
		t.Fatalf("chown failed: %+v", r)
	}

	// rm
	if r := sh1.Run("rm -rf /tmp/d1 /tmp/moved_cred"); r.Exit != 0 {
		t.Fatalf("rm failed: %+v", r)
	}
	if sh1.Run("cat /tmp/moved_cred").Exit == 0 {
		t.Fatalf("removed file still exists in s1")
	}
}

func TestWgetAndCurl(t *testing.T) {
	sh := newShell(t, "deploy")

	// wget
	rWget := sh.Run("wget http://s3.example.com/deploy.sh")
	if rWget.Exit != 0 || !strings.Contains(rWget.Output, "200 OK") || !strings.Contains(rWget.Output, "saved") {
		t.Fatalf("wget failed: %+v", rWget)
	}
	if sh.FS.Get("/home/deploy/deploy.sh") == nil {
		t.Fatalf("wget did not create output file in overlay")
	}

	// curl -o
	rCurl := sh.Run("curl -s http://example.com/test.bin -o /tmp/test.bin")
	if rCurl.Exit != 0 {
		t.Fatalf("curl failed: %+v", rCurl)
	}
	if sh.FS.Get("/tmp/test.bin") == nil {
		t.Fatalf("curl -o did not create output file in overlay")
	}
}

func TestSudoAndSuFlows(t *testing.T) {
	// 1. Non-interactive shell: sudo & su fail
	shNonInteractive := newShell(t, "deploy")
	shNonInteractive.Interactive = false

	rSudoNonInt := shNonInteractive.Run("sudo ls")
	if rSudoNonInt.Exit != 1 || !strings.Contains(rSudoNonInt.Output, "a terminal is required") {
		t.Fatalf("non-interactive sudo should fail: %+v", rSudoNonInt)
	}
	rSuNonInt := shNonInteractive.Run("su")
	if rSuNonInt.Exit != 1 || !strings.Contains(rSuNonInt.Output, "must be run from a terminal") {
		t.Fatalf("non-interactive su should fail: %+v", rSuNonInt)
	}

	// 2. Interactive shell: password prompt & answer sequence
	shInt := newShell(t, "deploy")
	shInt.Interactive = true

	rSudo := shInt.Run("sudo whoami")
	if !shInt.PasswordPending() || rSudo.SecretPrompt == "" {
		t.Fatalf("interactive sudo should prompt for password: %+v", rSudo)
	}
	a1 := shInt.AnswerPassword("wrong1")
	if !shInt.PasswordPending() || !strings.Contains(a1.Output, "Sorry, try again") || a1.SecretPrompt == "" {
		t.Fatalf("first wrong password should prompt again: %+v", a1)
	}
	a2 := shInt.AnswerPassword("wrong2")
	if !shInt.PasswordPending() || !strings.Contains(a2.Output, "Sorry, try again") || a2.SecretPrompt == "" {
		t.Fatalf("second wrong password should prompt again: %+v", a2)
	}
	a3 := shInt.AnswerPassword("wrong3")
	if shInt.PasswordPending() || !strings.Contains(a3.Output, "3 incorrect password attempts") || a3.SecretPrompt != "" {
		t.Fatalf("third wrong password should terminate: %+v", a3)
	}

	// su
	rSu := shInt.Run("su")
	if !shInt.PasswordPending() || rSu.SecretPrompt != "Password: " {
		t.Fatalf("su should prompt for password: %+v", rSu)
	}
	aSu := shInt.AnswerPassword("wrong")
	if shInt.PasswordPending() || !strings.Contains(aSu.Output, "Authentication failure") || aSu.SecretPrompt != "" {
		t.Fatalf("su wrong password should fail: %+v", aSu)
	}

	// 3. Root user: sudo runs command directly
	shRoot := newShell(t, "root")
	rRoot := shRoot.Run("sudo whoami")
	if rRoot.Exit != 0 || rRoot.Output != "root\n" {
		t.Fatalf("root sudo whoami failed: %+v", rRoot)
	}
}

func TestNoFixedClockAndIPWget(t *testing.T) {
	if strings.Contains(clockNow(), "12:34:56") && time.Now().UTC().Format("15:04:05") != "12:34:56" {
		t.Fatal("clock is fixed")
	}
	if !isIPv4Literal("203.0.113.9") || isIPv4Literal("example.com") || isIPv4Literal("1.2.3.256") {
		t.Fatal("isIPv4Literal wrong")
	}
}
