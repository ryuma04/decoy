package sensorkit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
)

const key = "secret-key-0123456789"

type fakeCore struct {
	mu     sync.Mutex
	events map[string]event.Envelope
	down   atomic.Bool
	hb     atomic.Int64
}

func (c *fakeCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	if _, err := sensorauth.Verify(r, body, map[string]string{"ssh-01": key}, time.Now()); err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	if c.down.Load() {
		http.Error(w, "down", 503)
		return
	}
	switch r.URL.Path {
	case "/v1/ingest/events":
		var envs []event.Envelope
		_ = json.Unmarshal(body, &envs)
		c.mu.Lock()
		for _, e := range envs {
			if err := e.Validate("ssh-01", time.Now()); err != nil {
				c.mu.Unlock()
				http.Error(w, err.Error(), 400)
				return
			}
			c.events[e.EventID] = e
		}
		c.mu.Unlock()
		w.Write([]byte(`{"accepted":1}`))
	case "/v1/ingest/heartbeat":
		c.hb.Add(1)
		w.WriteHeader(204)
	case "/v1/sensor/policy":
		w.Write([]byte(`{"blocked_ips":["10.66.0.99"],"killed_sessions":[],"burned_tokens":["tok_aws_k7"],"rev":3}`))
	}
}

func (c *fakeCore) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestDeliverSpoolReplayAndPolicy(t *testing.T) {
	core := &fakeCore{events: map[string]event.Envelope{}}
	srv := httptest.NewServer(core)
	defer srv.Close()
	dir := t.TempDir()
	kit := New(Options{SensorID: "ssh-01", Key: key, CoreURL: srv.URL, Service: "ssh", DataDir: dir})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)

	if !kit.Blocked("10.66.0.99") || !kit.Burned("tok_aws_k7") || kit.Blocked("10.66.0.1") {
		t.Fatal("policy not loaded at start")
	}

	s := kit.NewSession("10.66.0.23", 5000, 2222)
	e0 := s.Event("conn.open", "ssh_entry", nil, nil, nil)
	e1 := s.Event("shell.command", "ssh_entry", map[string]any{"raw": "id"}, &event.Timing{SincePrevMS: 1200, Keystrokes: 2}, nil)
	if e0.Session.Seq != 0 || e1.Session.Seq != 1 {
		t.Fatalf("seq %d %d", e0.Session.Seq, e1.Session.Seq)
	}
	waitFor(t, "delivery", func() bool { return core.count() == 2 })

	// Core down: events are retried, then spooled when the kit closes.
	core.down.Store(true)
	s.Event("shell.command", "", map[string]any{"raw": "whoami"}, nil, nil)
	time.Sleep(1500 * time.Millisecond)
	kit.Close()
	if _, err := os.Stat(kit.spoolPath()); err != nil {
		t.Fatalf("expected spool file: %v", err)
	}

	// Core back: a new kit replays the spool on start.
	core.down.Store(false)
	kit2 := New(Options{SensorID: "ssh-01", Key: key, CoreURL: srv.URL, Service: "ssh", DataDir: dir})
	kit2.Start(ctx)
	defer kit2.Close()
	waitFor(t, "replay", func() bool { return core.count() == 3 })
	if _, err := os.Stat(kit.spoolPath()); !os.IsNotExist(err) {
		t.Fatal("spool not removed after replay")
	}
}
