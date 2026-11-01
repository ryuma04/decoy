package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
	"github.com/ryuma04/decoy/backend/internal/store"
)

var now = time.Date(2026, 11, 14, 9, 2, 12, 0, time.UTC)

const key = "secret-key-0123456789"

type fakeStore struct {
	seen       map[string]bool
	heartbeats int
}

func (f *fakeStore) IngestBatch(_ context.Context, sensorID string, envs []event.Envelope, raws []json.RawMessage) (store.IngestResult, error) {
	var res store.IngestResult
	for _, e := range envs {
		if f.seen[e.EventID] {
			res.Duplicates++
			continue
		}
		f.seen[e.EventID] = true
		res.Accepted = append(res.Accepted, store.StoredEvent{EventID: e.EventID, Type: e.Type, SensorID: sensorID})
	}
	return res, nil
}

func (f *fakeStore) Heartbeat(context.Context, string, string, string) error {
	f.heartbeats++
	return nil
}
func (f *fakeStore) Policy(context.Context) (store.Policy, error) {
	return store.Policy{BlockedIPs: []string{"10.66.0.23"}, KilledSessions: []string{}, BurnedTokens: []string{}, Rev: 1}, nil
}

func setup() (*Server, *fakeStore, <-chan bus.Message) {
	fs := &fakeStore{seen: map[string]bool{}}
	b := bus.NewMemory()
	ch, _ := b.Subscribe(100, bus.TopicEvent, bus.TopicSensor)
	return &Server{Store: fs, Bus: b, Keys: map[string]string{"ssh-01": key}, Now: func() time.Time { return now }}, fs, ch
}

func envelope(seq int) event.Envelope {
	return event.Envelope{
		Schema: event.Schema, Origin: "decoy", EventID: event.NewID(now), TS: now,
		Sensor: event.Sensor{ID: "ssh-01", Service: "ssh"}, Session: event.SessionRef{SensorSessionID: "ssh-01:abc", Seq: seq},
		Src: event.Endpoint{IP: "10.66.0.23", Port: 5000}, Dst: event.Dst{Port: 2222},
		Type: "shell.command", Data: json.RawMessage(`{"raw":"id"}`),
	}
}

func do(t *testing.T, s *Server, method, path string, body []byte, signKey string) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	s.Routes(mux)
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if signKey != "" {
		sensorauth.Sign(r, "ssh-01", signKey, body, now)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestIngestAcceptsDedupsAndRejects(t *testing.T) {
	s, _, ch := setup()
	good := envelope(0)
	bad := envelope(1)
	bad.Type = "nope"
	body, _ := json.Marshal([]event.Envelope{good, bad})

	w := do(t, s, "POST", "/v1/ingest/events", body, key)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	var resp ingestResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Accepted != 1 || resp.Duplicates != 0 || len(resp.Rejected) != 1 || resp.Rejected[0].EventID != bad.EventID {
		t.Fatalf("resp %+v", resp)
	}
	if m := <-ch; m.Topic != bus.TopicEvent || m.Value.(store.StoredEvent).EventID != good.EventID {
		t.Fatalf("published %+v", m)
	}

	// Same batch again: idempotent.
	w = do(t, s, "POST", "/v1/ingest/events", body, key)
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Accepted != 0 || resp.Duplicates != 1 {
		t.Fatalf("retry resp %+v", resp)
	}
}

func TestIngestAuth(t *testing.T) {
	s, _, _ := setup()
	body, _ := json.Marshal([]event.Envelope{envelope(0)})
	if w := do(t, s, "POST", "/v1/ingest/events", body, "wrong-key-0123456789"); w.Code != 401 {
		t.Fatalf("bad key: %d", w.Code)
	}
	if w := do(t, s, "POST", "/v1/ingest/events", body, ""); w.Code != 401 {
		t.Fatalf("no auth: %d", w.Code)
	}
}

func TestIngestBadBatch(t *testing.T) {
	s, _, _ := setup()
	if w := do(t, s, "POST", "/v1/ingest/events", []byte(`{"not":"array"}`), key); w.Code != 400 {
		t.Fatalf("status %d", w.Code)
	}
}

func TestHeartbeatAndPolicy(t *testing.T) {
	s, fs, ch := setup()
	hb := []byte(`{"sensor_id":"ssh-01","version":"0.1.0","uptime_s":360,"active_sessions":2}`)
	if w := do(t, s, "POST", "/v1/ingest/heartbeat", hb, key); w.Code != 204 {
		t.Fatalf("heartbeat %d", w.Code)
	}
	if fs.heartbeats != 1 {
		t.Fatal("heartbeat not stored")
	}
	if m := <-ch; m.Topic != bus.TopicSensor || m.Value.(SensorStatus).Service != "ssh" {
		t.Fatalf("published %+v", m)
	}
	w := do(t, s, "GET", "/v1/sensor/policy", nil, key)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"blocked_ips":["10.66.0.23"]`)) {
		t.Fatalf("policy %d %s", w.Code, w.Body)
	}
}

func TestServiceFromID(t *testing.T) {
	for id, want := range map[string]string{"ssh-01": "ssh", "web-01": "web", "db-01": "db", "k8s-01": "k8s",
		"beacon-01": "beacon", "dbadmin-01": "dbadmin", "logs-01": "firewall", "engine": "engine"} {
		if got := ServiceFromID(id); got != want {
			t.Errorf("ServiceFromID(%q) = %q, want %q", id, got, want)
		}
	}
}
