package event

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 14, 9, 2, 12, 0, time.UTC)

func valid() Envelope {
	return Envelope{
		Schema: Schema, Origin: "decoy", EventID: NewID(now), TS: now.Add(-time.Second),
		Sensor:  Sensor{ID: "ssh-01", Service: "ssh", MazeNode: "ssh_entry"},
		Session: SessionRef{SensorSessionID: "ssh-01:7f3a9c", Seq: 14},
		Src:     Endpoint{IP: "10.66.0.23", Port: 51544}, Dst: Dst{Port: 2222},
		Type:    "shell.command",
		Data:    json.RawMessage(`{"raw":"cat /home/deploy/.aws/credentials","argv0":"cat"}`),
	}
}

func TestValidateAcceptsDocExample(t *testing.T) {
	e := valid()
	if err := e.Validate("ssh-01", now); err != nil {
		t.Fatalf("valid envelope rejected: %v", err)
	}
}

func TestValidateEveryTypeAccepted(t *testing.T) {
	for typ := range Types {
		e := valid()
		e.Type = typ
		if ProductionServices[e.Sensor.Service] {
			continue
		}
		if err := e.Validate("ssh-01", now); err != nil {
			t.Errorf("type %s rejected: %v", typ, err)
		}
	}
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Envelope)
		want   string
	}{
		{"schema", func(e *Envelope) { e.Schema = "dsoc.event/v2" }, "schema"},
		{"event id", func(e *Envelope) { e.EventID = "not-a-ulid" }, "ULID"},
		{"future ts", func(e *Envelope) { e.TS = now.Add(6 * time.Minute) }, "future"},
		{"zero ts", func(e *Envelope) { e.TS = time.Time{} }, "ts is required"},
		{"sensor mismatch", func(e *Envelope) { e.Sensor.ID = "web-01" }, "does not match"},
		{"service", func(e *Envelope) { e.Sensor.Service = "ftp" }, "sensor.service"},
		{"origin", func(e *Envelope) { e.Origin = "lab" }, "origin"},
		{"decoy claims production", func(e *Envelope) { e.Origin = "production" }, "only for"},
		{"firewall as decoy", func(e *Envelope) { e.Sensor.Service = "firewall" }, "requires origin"},
		{"session prefix", func(e *Envelope) { e.Session.SensorSessionID = "web-01:x" }, "sensor_session_id"},
		{"seq", func(e *Envelope) { e.Session.Seq = -1 }, "seq"},
		{"ip", func(e *Envelope) { e.Src.IP = "10.66.0" }, "src.ip"},
		{"port", func(e *Envelope) { e.Dst.Port = 70000 }, "port"},
		{"type", func(e *Envelope) { e.Type = "shell.exec" }, "type"},
		{"data missing", func(e *Envelope) { e.Data = nil }, "data is required"},
		{"data array", func(e *Envelope) { e.Data = json.RawMessage(`[1]`) }, "JSON object"},
		{"raw too long", func(e *Envelope) {
			e.Data = json.RawMessage(`{"raw":"` + strings.Repeat("a", MaxRawSize+1) + `"}`)
		}, "4 KB"},
		{"empty token", func(e *Envelope) { e.Tokens = []string{""} }, "token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := valid()
			c.mutate(&e)
			err := e.Validate("ssh-01", now)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestProductionEventAccepted(t *testing.T) {
	e := valid()
	e.Sensor = Sensor{ID: "logs-01", Service: "firewall"}
	e.Origin = "production"
	e.Session.SensorSessionID = "logs-01:10.66.0.23:2026111409"
	e.Type = "fw.deny"
	e.Data = json.RawMessage(`{"dst_ip":"10.66.0.10","dst_port":22,"proto":"tcp","rule":"DSOC-DENY"}`)
	if err := e.Validate("logs-01", now); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeBatch(t *testing.T) {
	e := valid()
	b, _ := json.Marshal([]Envelope{e, e})
	envs, raws, err := DecodeBatch(b)
	if err != nil || len(envs) != 2 || len(raws) != 2 || envs[1].EventID != e.EventID {
		t.Fatalf("decode: %v %d", err, len(envs))
	}
	if _, _, err := DecodeBatch([]byte(`{}`)); err == nil {
		t.Fatal("object accepted as batch")
	}
	if _, _, err := DecodeBatch([]byte(`[]`)); err == nil {
		t.Fatal("empty batch accepted")
	}
	big := "[" + strings.Repeat(`{},`, MaxBatch) + `{}]`
	if _, _, err := DecodeBatch([]byte(big)); err == nil {
		t.Fatal("oversized batch accepted")
	}
}

func TestNewIDMonotonic(t *testing.T) {
	a, b := NewID(now), NewID(now)
	if a >= b {
		t.Fatalf("ids not increasing: %s %s", a, b)
	}
}

func TestSummary(t *testing.T) {
	cases := map[string]struct {
		typ  string
		data map[string]any
		want string
	}{
		"command": {"shell.command", map[string]any{"raw": "cat ~/.aws/credentials"}, "cat ~/.aws/credentials"},
		"auth":    {"auth.attempt", map[string]any{"username": "root", "method": "password", "success": false}, "password login as root failed"},
		"token":   {"token.used", map[string]any{"token_id": "tok_aws_k7", "via": "aws_api"}, "honeytoken tok_aws_k7 used via aws_api"},
		"http":    {"http.request", map[string]any{"method": "GET", "path": "/robots.txt", "status": float64(200)}, "GET /robots.txt → 200"},
		"real":    {"auth.app_success", map[string]any{"username": "deploy"}, "app login as deploy succeeded"},
	}
	for name, c := range cases {
		if got := Summary(c.typ, c.data); got != c.want {
			t.Errorf("%s: got %q want %q", name, got, c.want)
		}
	}
}
