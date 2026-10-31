// Package sensorkit is the shared decoy client (05): build envelopes, batch (1 s or 50 events), HMAC-sign,
// retry with backoff, spool to a local JSONL file while core is down, heartbeat, and poll policy.
//
// Decoys talk to core only through this package. It never executes anything and writes only to DataDir.
package sensorkit

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
)

const (
	batchSize     = 50
	flushEvery    = time.Second
	queueSize     = 10000
	heartbeatTick = 30 * time.Second
	policyTick    = 5 * time.Second
	spoolMaxBytes = 50 << 20
)

type Options struct {
	SensorID string
	Key      string
	CoreURL  string
	Service  string // ssh, web, k8s, beacon, firewall ...
	Origin   string // decoy (default) or production
	DataDir  string // spool lives here
	Version  string
	HTTP     *http.Client
}

type Kit struct {
	o        Options
	queue    chan event.Envelope
	started  time.Time
	sessions atomic.Int64

	policyMu sync.RWMutex
	policy   Policy

	spoolMu sync.Mutex
	done    chan struct{}
	wg      sync.WaitGroup
}

// Policy mirrors GET /v1/sensor/policy.
type Policy struct {
	BlockedIPs     []string `json:"blocked_ips"`
	KilledSessions []string `json:"killed_sessions"`
	BurnedTokens   []string `json:"burned_tokens"`
	Rev            int64    `json:"rev"`
	blocked        map[string]bool
	killed         map[string]bool
	burned         map[string]bool
}

func New(o Options) *Kit {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 5 * time.Second}
	}
	if o.Origin == "" {
		o.Origin = "decoy"
	}
	if o.Version == "" {
		o.Version = "0.1.0"
	}
	return &Kit{o: o, queue: make(chan event.Envelope, queueSize), started: time.Now(), done: make(chan struct{})}
}

// Start runs the sender, heartbeat and policy loops until ctx ends. Close flushes what is queued.
func (k *Kit) Start(ctx context.Context) {
	k.wg.Add(3)
	go k.sendLoop(ctx)
	go k.every(ctx, heartbeatTick, k.heartbeat)
	go k.every(ctx, policyTick, k.pollPolicy)
	k.pollPolicy(ctx)
}

// Close stops the loops after a final flush (pending events are spooled if core is down).
func (k *Kit) Close() {
	close(k.done)
	k.wg.Wait()
}

// Emit queues an envelope. It never blocks the decoy: a full queue spools straight to disk.
func (k *Kit) Emit(e event.Envelope) {
	select {
	case k.queue <- e:
	default:
		k.spool([]event.Envelope{e})
	}
}

// ---------- sessions ----------

// Session numbers the events of one connection / web cookie / token+IP window.
type Session struct {
	kit     *Kit
	ID      string
	SrcIP   string
	SrcPort int
	DstPort int
	Client  *event.Client
	seq     atomic.Int64
}

// NewSession creates a session with id "<sensor id>:<random>".
func (k *Kit) NewSession(srcIP string, srcPort, dstPort int) *Session {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return k.SessionWithID(fmt.Sprintf("%s:%s", k.o.SensorID, hex.EncodeToString(b)), srcIP, srcPort, dstPort)
}

// SessionWithID is for sessions keyed by something the decoy chooses (e.g. a web cookie).
func (k *Kit) SessionWithID(id, srcIP string, srcPort, dstPort int) *Session {
	return &Session{kit: k, ID: id, SrcIP: srcIP, SrcPort: srcPort, DstPort: dstPort}
}

// Open / Done track active sessions for the heartbeat.
func (k *Kit) Open()      { k.sessions.Add(1) }
func (k *Kit) Done()      { k.sessions.Add(-1) }
func (k *Kit) ID() string { return k.o.SensorID }

// Event builds and emits one envelope with the next seq. data is marshalled to JSON.
func (s *Session) Event(typ, mazeNode string, data any, timing *event.Timing, tokens []string) event.Envelope {
	raw, err := json.Marshal(data)
	if err != nil || data == nil {
		raw = []byte(`{}`)
	}
	now := time.Now().UTC()
	e := event.Envelope{
		Schema: event.Schema, Origin: s.kit.o.Origin, EventID: event.NewID(now), TS: now,
		Sensor:  event.Sensor{ID: s.kit.o.SensorID, Service: s.kit.o.Service, MazeNode: mazeNode},
		Session: event.SessionRef{SensorSessionID: s.ID, Seq: int(s.seq.Add(1) - 1)},
		Src:     event.Endpoint{IP: s.SrcIP, Port: s.SrcPort}, Dst: event.Dst{Port: s.DstPort},
		Type: typ, Data: raw, Client: s.Client, Timing: timing, Tokens: tokens,
	}
	s.kit.Emit(e)
	return e
}

// ---------- policy ----------

func (k *Kit) Policy() Policy {
	k.policyMu.RLock()
	defer k.policyMu.RUnlock()
	return k.policy
}

func (k *Kit) Blocked(ip string) bool       { return k.Policy().blocked[ip] }
func (k *Kit) Killed(sessionID string) bool { return k.Policy().killed[sessionID] }
func (k *Kit) Burned(tokenID string) bool   { return k.Policy().burned[tokenID] }

func (k *Kit) pollPolicy(ctx context.Context) {
	var p Policy
	if err := k.get(ctx, "/v1/sensor/policy", &p); err != nil {
		slog.Debug("policy poll failed; keeping last policy", "err", err)
		return
	}
	p.blocked, p.killed, p.burned = toSet(p.BlockedIPs), toSet(p.KilledSessions), toSet(p.BurnedTokens)
	k.policyMu.Lock()
	if p.Rev != k.policy.Rev {
		slog.Info("policy updated", "rev", p.Rev, "blocked", len(p.BlockedIPs), "killed", len(p.KilledSessions))
	}
	k.policy = p
	k.policyMu.Unlock()
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// MazeView asks core what this session may see; callers fall back to their default view on error.
func (k *Kit) MazeView(ctx context.Context, sensorSessionID string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	return k.get(ctx, "/v1/sensor/maze-view?sensor_session_id="+sensorSessionID, out)
}

// ---------- transport ----------

func (k *Kit) every(ctx context.Context, d time.Duration, fn func(context.Context)) {
	defer k.wg.Done()
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-k.done:
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

func (k *Kit) heartbeat(ctx context.Context) {
	body, _ := json.Marshal(map[string]any{"sensor_id": k.o.SensorID, "version": k.o.Version,
		"uptime_s": int64(time.Since(k.started).Seconds()), "active_sessions": k.sessions.Load()})
	if _, err := k.post(ctx, "/v1/ingest/heartbeat", body); err != nil {
		slog.Debug("heartbeat failed", "err", err)
	}
}

func (k *Kit) sendLoop(ctx context.Context) {
	defer k.wg.Done()
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	var batch []event.Envelope
	backoff := time.Duration(0)
	nextTry := time.Time{}
	flush := func(final bool) {
		if len(batch) == 0 {
			return
		}
		if !final && time.Now().Before(nextTry) {
			if len(batch) >= queueSize/2 {
				k.spool(batch)
				batch = nil
			}
			return
		}
		if err := k.send(ctx, batch); err != nil {
			backoff = min(max(2*backoff, time.Second), 30*time.Second)
			nextTry = time.Now().Add(backoff)
			slog.Warn("send failed, will retry", "events", len(batch), "retry_in", backoff, "err", err)
			if final || len(batch) >= 4*batchSize {
				k.spool(batch)
				batch = nil
			}
			return
		}
		batch, backoff = nil, 0
		k.replaySpool(ctx)
	}
	k.replaySpool(ctx)
	for {
		select {
		case e := <-k.queue:
			batch = append(batch, e)
			if len(batch) >= batchSize && time.Now().After(nextTry) {
				flush(false)
			}
		case <-t.C:
			flush(false)
		case <-k.done:
			k.drain(&batch)
			flush(true)
			return
		case <-ctx.Done():
			k.drain(&batch)
			flush(true)
			return
		}
	}
}

func (k *Kit) drain(batch *[]event.Envelope) {
	for {
		select {
		case e := <-k.queue:
			*batch = append(*batch, e)
		default:
			return
		}
	}
}

// send posts in chunks of at most 200 (04 §A).
func (k *Kit) send(ctx context.Context, envs []event.Envelope) error {
	for start := 0; start < len(envs); start += event.MaxBatch {
		end := min(start+event.MaxBatch, len(envs))
		body, err := json.Marshal(envs[start:end])
		if err != nil {
			return err
		}
		status, err := k.post(ctx, "/v1/ingest/events", body)
		if err != nil {
			return err
		}
		if status == http.StatusUnauthorized || status == http.StatusBadRequest {
			// Retrying cannot fix these; drop rather than loop forever (logged loudly).
			slog.Error("core refused batch", "status", status, "events", end-start)
			continue
		}
		if status != http.StatusOK {
			return fmt.Errorf("core status %d", status)
		}
	}
	return nil
}

func (k *Kit) post(ctx context.Context, path string, body []byte) (int, error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.o.CoreURL+path, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	sensorauth.Sign(req, k.o.SensorID, k.o.Key, body, time.Now())
	resp, err := k.o.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode, nil
}

func (k *Kit) get(ctx context.Context, pathAndQuery string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.o.CoreURL+pathAndQuery, nil)
	if err != nil {
		return err
	}
	sensorauth.Sign(req, k.o.SensorID, k.o.Key, nil, time.Now())
	resp, err := k.o.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("core status %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// ---------- spool (JSONL in DataDir) ----------

func (k *Kit) spoolPath() string { return filepath.Join(k.o.DataDir, "spool-"+k.o.SensorID+".jsonl") }

func (k *Kit) spool(envs []event.Envelope) {
	if k.o.DataDir == "" {
		slog.Error("core unreachable and no DataDir: dropping events", "events", len(envs))
		return
	}
	k.spoolMu.Lock()
	defer k.spoolMu.Unlock()
	if st, err := os.Stat(k.spoolPath()); err == nil && st.Size() > spoolMaxBytes {
		slog.Error("spool full, dropping events", "events", len(envs))
		return
	}
	f, err := os.OpenFile(k.spoolPath(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Error("spool open failed", "err", err)
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, e := range envs {
		b, _ := json.Marshal(e)
		w.Write(b)
		w.WriteByte('\n')
	}
	_ = w.Flush()
	slog.Warn("spooled events to disk", "events", len(envs), "file", k.spoolPath())
}

// replaySpool sends spooled events once core answers again; event_id dedup makes replays idempotent.
func (k *Kit) replaySpool(ctx context.Context) {
	k.spoolMu.Lock()
	defer k.spoolMu.Unlock()
	f, err := os.Open(k.spoolPath())
	if err != nil {
		return
	}
	var envs []event.Envelope
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), event.MaxEnvelopeSize+1024)
	for sc.Scan() {
		var e event.Envelope
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			envs = append(envs, e)
		}
	}
	f.Close()
	if len(envs) == 0 {
		_ = os.Remove(k.spoolPath())
		return
	}
	if err := k.send(ctx, envs); err != nil {
		return
	}
	_ = os.Remove(k.spoolPath())
	slog.Info("replayed spooled events", "events", len(envs))
}
