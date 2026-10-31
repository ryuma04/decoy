package logparse

import (
	"testing"
	"time"
)

var now = time.Date(2026, 11, 14, 9, 30, 0, 0, time.Local)

func TestFirewall(t *testing.T) {
	cases := []struct {
		line    string
		ok      bool
		typ, ip string
		dport   int
	}{
		{"Nov 14 09:02:11 real-target kernel: DSOC-DENY IN=eth0 OUT= MAC=02:42 SRC=10.66.0.23 DST=10.66.0.50 LEN=60 TOS=0x00 PROTO=TCP SPT=51544 DPT=22 WINDOW=64240 SYN",
			true, "fw.deny", "10.66.0.23", 22},
		{"Nov 14 09:02:12 real-target kernel: DSOC-ALLOW IN=eth0 SRC=10.66.0.23 DST=10.66.0.50 PROTO=TCP SPT=51545 DPT=443",
			true, "fw.allow", "10.66.0.23", 443},
		{`{"ts":"2026-11-14T09:02:13Z","action":"deny","src":"10.66.0.41","sport":4000,"dst":"10.66.0.50","dport":3306,"proto":"TCP","rule":"r7"}`,
			true, "fw.deny", "10.66.0.41", 3306},
		{"Nov 14 09:02:11 real-target kernel: some other line SRC=10.66.0.23", false, "", "", 0},
		{"garbage", false, "", "", 0},
		{"Nov 14 09:02:11 x kernel: DSOC-DENY SRC=not-an-ip DPT=22", false, "", "", 0},
	}
	for _, c := range cases {
		p, ok := Firewall(c.line, now)
		if ok != c.ok || (ok && (p.Type != c.typ || p.SrcIP != c.ip || p.DstPort != c.dport || p.Service != "firewall")) {
			t.Errorf("%q: ok=%v %+v", c.line, ok, p)
		}
	}
	p, _ := Firewall(cases[0].line, now)
	if p.TS.In(time.Local).Hour() != 9 || p.TS.In(time.Local).Minute() != 2 {
		t.Errorf("syslog time: %v", p.TS)
	}
}

func TestHostAuth(t *testing.T) {
	cases := []struct {
		line          string
		ok            bool
		typ, user, ip string
	}{
		{"Nov 14 09:05:01 real-target sshd[812]: Failed password for deploy from 10.66.0.23 port 51600 ssh2", true, "auth.real_failed", "deploy", "10.66.0.23"},
		{"Nov 14 09:05:02 real-target sshd[812]: Failed password for invalid user oracle from 10.66.0.23 port 51601 ssh2", true, "auth.real_failed", "oracle", "10.66.0.23"},
		{"Nov 14 09:05:03 real-target sshd[813]: Accepted publickey for deploy from 10.66.0.41 port 51700 ssh2: ED25519 SHA256:abc", true, "auth.real_success", "deploy", "10.66.0.41"},
		{"Nov 14 09:05:04 real-target sshd[813]: pam_unix(sshd:session): session opened for user deploy", false, "", "", ""},
	}
	for _, c := range cases {
		p, ok := HostAuth(c.line, "real-target", now)
		if ok != c.ok || (ok && (p.Type != c.typ || p.Data["username"] != c.user || p.SrcIP != c.ip || p.Service != "hostauth")) {
			t.Errorf("%q: ok=%v %+v", c.line, ok, p)
		}
	}
}

func TestAppLoginHashesPassword(t *testing.T) {
	p, ok := AppLogin(`{"ts":"2026-11-14T09:06:00Z","user":"deploy","src_ip":"10.66.0.23","result":"failed","ua":"curl/8.5","password":"S3cret!"}`, "tickets", "salt1", now)
	if !ok || p.Type != "auth.app_failed" || p.Service != "appauth" {
		t.Fatalf("%v %+v", ok, p)
	}
	if _, clear := p.Data["password"]; clear || p.Data["password_hash"] != HashSecret("salt1", "S3cret!") {
		t.Fatalf("password must only be stored hashed: %+v", p.Data)
	}
	if HashSecret("salt1", "x") == HashSecret("salt2", "x") {
		t.Fatal("salt must change the hash")
	}
	if p, ok := AppLogin(`{"user":"a","src_ip":"10.0.0.1","result":"success"}`, "tickets", "s", now); !ok || p.Type != "auth.app_success" || !p.TS.Equal(now.UTC()) {
		t.Fatalf("%v %+v", ok, p)
	}
	for _, bad := range []string{"not json", `{"user":"a","src_ip":"x"}`, `{"src_ip":"10.0.0.1"}`} {
		if _, ok := AppLogin(bad, "t", "s", now); ok {
			t.Errorf("accepted %q", bad)
		}
	}
}
