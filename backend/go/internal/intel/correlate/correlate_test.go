package correlate

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 14, 9, 0, 0, 0, time.UTC)

func newSess(mut func(*Session)) Session {
	s := Session{ID: "new", Service: "ssh", IP: "10.66.0.41", Start: t0.Add(10 * time.Minute)}
	mut(&s)
	return s
}

func old(mut func(*Session)) Session {
	s := Session{ID: "old", ActorID: "A", Service: "web", IP: "10.9.9.9", Start: t0, End: t0.Add(5 * time.Minute)}
	mut(&s)
	return s
}

func score(n, o Session) Result { return Score(n, "A", []Session{o}) }

func TestEachSignal(t *testing.T) {
	cases := []struct {
		name   string
		n, o   func(*Session)
		signal string
		weight float64
	}{
		{"credential lineage", func(s *Session) { s.TokensUsed = []string{"tok_backup_key"} },
			func(s *Session) { s.TokensSeen = []string{"tok_backup_key"} }, "credential_lineage", 0.90},
		{"ssh key", func(s *Session) { s.SSHKeys = []string{"SHA256:k"} }, func(s *Session) { s.SSHKeys = []string{"SHA256:k"} }, "ssh_key", 0.90},
		{"cred pair", func(s *Session) { s.CredPairs = []string{"deploy:Nwl2024!"} }, func(s *Session) { s.CredPairs = []string{"deploy:Nwl2024!"} }, "cred_pair", 0.40},
		{"ip 30m", func(s *Session) { s.IP = "10.66.0.23" }, func(s *Session) { s.IP = "10.66.0.23" }, "ip_30m", 0.40},
		{"ip 24h", func(s *Session) { s.IP = "10.66.0.23"; s.Start = t0.Add(3 * time.Hour) }, func(s *Session) { s.IP = "10.66.0.23" }, "ip_24h", 0.20},
		{"banner only", func(s *Session) { s.SSHBanner = "SSH-2.0-OpenSSH_9.6" }, func(s *Session) { s.SSHBanner = "SSH-2.0-OpenSSH_9.6" }, "client_ssh", 0.15},
		{"banner + hassh", func(s *Session) { s.SSHBanner, s.HASSH = "b", "h" }, func(s *Session) { s.SSHBanner, s.HASSH = "b", "h" }, "client_ssh", 0.35},
		{"ua only", func(s *Session) { s.UA = "curl/8.5" }, func(s *Session) { s.UA = "curl/8.5" }, "client_http", 0.15},
		{"cross service hop", func(s *Session) { s.IP = "10.66.0.41"; s.Start = t0.Add(5*time.Minute + 30*time.Second) },
			func(s *Session) { s.IP = "10.66.0.77" }, "cross_service_hop", 0.15},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := score(newSess(c.n), old(c.o))
			if len(r.Reasons) == 0 || r.Reasons[0].Signal != c.signal || r.Reasons[0].Weight != c.weight {
				t.Fatalf("got %+v", r.Reasons)
			}
			if r.Reasons[0].MatchedSession == nil || *r.Reasons[0].MatchedSession != "old" {
				t.Fatal("matched session missing")
			}
		})
	}
}

func TestCredentialLineageEitherOrder(t *testing.T) {
	// The read arrives after the use was already attributed to another actor.
	r := score(newSess(func(s *Session) { s.TokensSeen = []string{"tok_aws_k7"} }),
		old(func(s *Session) { s.TokensUsed = []string{"tok_aws_k7"} }))
	if r.Score != 0.90 || r.Reasons[0].Signal != "credential_lineage" {
		t.Fatalf("%+v", r)
	}
}

func TestIPAloneNeverAttaches(t *testing.T) {
	r := score(newSess(func(s *Session) { s.IP = "10.66.0.23" }), old(func(s *Session) { s.IP = "10.66.0.23" }))
	if r.Score != 0.40 {
		t.Fatalf("score %v", r.Score)
	}
	d := Decide([]Result{r})
	if d.AttachTo != "" || len(d.Possible) != 1 {
		t.Fatalf("IP alone must be a possible link only: %+v", d)
	}
}

func TestIPPlusBannerAttaches(t *testing.T) {
	same := func(s *Session) { s.IP = "10.66.0.23"; s.SSHBanner = "SSH-2.0-OpenSSH_9.6" }
	r := score(newSess(same), old(same))
	// 1 − (1−0.40)(1−0.15) = 0.49 with banner only; with banner+hassh: 1 − 0.6×0.65 = 0.61
	if r.Score != 0.49 {
		t.Fatalf("banner only score %v", r.Score)
	}
	full := func(s *Session) { same(s); s.HASSH = "h1" }
	r = score(newSess(full), old(full))
	if r.Score != 0.61 || Decide([]Result{r}).AttachTo != "A" {
		t.Fatalf("IP + banner + hassh must attach: %v", r.Score)
	}
}

func TestIP30mAnd24hExclusiveAndSignalsCountOnce(t *testing.T) {
	n := newSess(func(s *Session) { s.IP = "10.66.0.23" })
	a := old(func(s *Session) { s.ID = "a"; s.IP = "10.66.0.23" })
	b := old(func(s *Session) {
		s.ID = "b"
		s.IP = "10.66.0.23"
		s.Start = t0.Add(-5 * time.Hour)
		s.End = t0.Add(-4 * time.Hour)
	})
	r := Score(n, "A", []Session{a, b})
	if len(r.Reasons) != 1 || r.Reasons[0].Signal != "ip_30m" || r.Score != 0.40 {
		t.Fatalf("%+v", r)
	}
}

func TestDecideAttachAndMerge(t *testing.T) {
	d := Decide([]Result{{ActorID: "old", Score: 0.65}, {ActorID: "newer", Score: 0.93}, {ActorID: "maybe", Score: 0.45}, {ActorID: "no", Score: 0.1}})
	if d.AttachTo != "newer" || len(d.Merge) != 1 || d.Merge[0] != "old" || len(d.Possible) != 1 {
		t.Fatalf("%+v", d)
	}
	if d := Decide(nil); d.AttachTo != "" {
		t.Fatal("no candidates must create a new actor")
	}
}

func TestMinHashSimilarity(t *testing.T) {
	a := MinHash([]string{"uname -a", "cat /etc/passwd", "ls -la /home", "cat ~/.aws/credentials"})
	b := MinHash([]string{"uname -a", "cat /etc/passwd", "ls -la /home", "cat ~/.aws/credentials"})
	c := MinHash([]string{"df -h", "git status", "vim notes.txt", "systemctl status nginx"})
	if Jaccard(a, b) != 1 {
		t.Fatalf("same commands: %v", Jaccard(a, b))
	}
	if Jaccard(a, c) > 0.2 {
		t.Fatalf("different commands: %v", Jaccard(a, c))
	}
	r := score(newSess(func(s *Session) { s.Shingles = a }), old(func(s *Session) { s.Shingles = b }))
	if r.Reasons[0].Signal != "cmd_similarity" || r.Reasons[0].Weight != 0.40 {
		t.Fatalf("%+v", r.Reasons)
	}
	if MinHash(nil) != nil || Jaccard(nil, a) != 0 {
		t.Fatal("empty input")
	}
}
