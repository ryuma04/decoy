package ssh

import (
	"strings"
	"testing"
)

func TestMoreCommandsLookLikeUbuntu(t *testing.T) {
	sh := newShell(t, "deploy")
	cases := []struct{ line, want string }{
		{"dmesg", "Operation not permitted"},
		{"journalctl -xe", "Users in groups 'adm', 'systemd-journal'"},
		{"strace -p 1", "ptrace(PTRACE_SEIZE"},
		{"apt install nmap", "are you root?"},
		{"systemctl status ssh", "OpenBSD Secure Shell server"},
		{"systemctl restart nginx", "Interactive authentication required"},
		{"lsof", "/usr/bin/bash"},
		{"lsblk", "sda3"},
		{"ping -c 2 10.0.0.9", "100% packet loss"},
		{"ssh root@10.0.0.9", "Connection timed out"},
		{"dig example.com", "no servers could be reached"},
		{"traceroute 8.8.8.8", "sudo apt install inetutils-traceroute"},
		{"man ls", "minimized"},
	}
	for _, c := range cases {
		if r := sh.Run(c.line); !strings.Contains(r.Output, c.want) {
			t.Errorf("%q: got %q, want it to contain %q", c.line, r.Output, c.want)
		}
	}
}

func TestTextToolsWorkOnFakeFiles(t *testing.T) {
	sh := newShell(t, "deploy")
	cases := []struct{ line, want string }{
		{"cat /etc/passwd | awk -F: '{print $1}' | sort | head -3", "\n"},
		{"cut -d: -f1 /etc/passwd | grep deploy", "deploy\n"},
		{"echo hello world | sed 's/world/there/'", "hello there\n"},
		{"echo b a b | tr ' ' '\\n' | sort | uniq -c", "2 b"},
		{"echo -n secret | base64", "c2VjcmV0"},
		{"echo c2VjcmV0 | base64 -d", "secret"},
		{"seq 3 | xargs echo", "1 2 3\n"},
		{"echo abc | rev", "cba\n"},
		{"printf x | sha256sum", "  -\n"},
	}
	for _, c := range cases {
		if r := sh.Run(c.line); !strings.Contains(r.Output, c.want) {
			t.Errorf("%q: got %q, want it to contain %q", c.line, r.Output, c.want)
		}
	}
	if r := sh.Run("awk -F: '{print $1}' /etc/passwd"); !strings.Contains(r.Output, "root\n") || len(r.Reads) == 0 {
		t.Errorf("awk on a file must read it (file.read event): %+v", r)
	}
}

func TestShellVariablesSubstitutionLoops(t *testing.T) {
	sh := newShell(t, "deploy")
	cases := []struct{ line, want string }{
		{"echo $HOME", sh.User.Home + "\n"},
		{"X=42; echo value=$X", "value=42\n"},
		{"export DB=orders; echo ${DB}", "orders\n"},
		{"echo ${NOPE:-fallback}", "fallback\n"},
		{"echo '$HOME stays literal'", "$HOME stays literal\n"},
		{"echo I am $(whoami)", "I am deploy\n"},
		{"echo `hostname`", sh.P.Hostname + "\n"},
		{"for u in a b c; do echo user-$u; done", "user-a\nuser-b\nuser-c\n"},
		{"echo -e 'x\\ny' | while read l; do echo got $l; done", "got"},
		{"false; echo $?", "1\n"},
	}
	for _, c := range cases {
		if r := sh.Run(c.line); !strings.Contains(r.Output, c.want) {
			t.Errorf("%q: got %q, want it to contain %q", c.line, r.Output, c.want)
		}
	}
}

func TestLoopsAreBounded(t *testing.T) {
	sh := newShell(t, "deploy")
	r := sh.Run("for i in $(seq 1 1000); do echo $i; done")
	if n := strings.Count(r.Output, "\n"); n != maxLoopIterations {
		t.Fatalf("loop ran %d times, want the cap %d", n, maxLoopIterations)
	}
	if r := sh.Run("echo $(echo $(echo $(echo $(echo deep))))"); r.Exit != 0 {
		t.Fatalf("nested substitution must stay bounded and not fail: %+v", r)
	}
}
