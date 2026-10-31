package api

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/store"
)

const (
	clientBuffer = 256
	pingEvery    = 15 * time.Second
)

type sseMsg struct {
	name    string
	data    []byte
	actorID string
}

type sseClient struct {
	ch      chan sseMsg
	actorID string // optional ?actor_id= filter
}

// Hub fans bus messages out to every connected browser (04 §B SSE). Slow clients drop messages, never block.
type Hub struct {
	mu      sync.Mutex
	clients map[*sseClient]struct{}
	Ping    time.Duration
}

func NewHub() *Hub { return &Hub{clients: map[*sseClient]struct{}{}, Ping: pingEvery} }

// Run consumes the bus until the channel closes.
func (h *Hub) Run(b bus.Bus) {
	ch, _ := b.Subscribe(4096, bus.AllTopics...)
	for m := range ch {
		msg, ok := encode(m)
		if !ok {
			continue
		}
		h.mu.Lock()
		for c := range h.clients {
			if c.actorID != "" && c.actorID != msg.actorID {
				continue
			}
			select {
			case c.ch <- msg:
			default: // slow client: drop
			}
		}
		h.mu.Unlock()
	}
}

func encode(m bus.Message) (sseMsg, bool) {
	v := m.Value
	if ev, ok := v.(store.StoredEvent); ok {
		v = toEvent(ev, false)
	}
	data, err := json.Marshal(v)
	if err != nil {
		slog.Error("sse encode", "topic", m.Topic, "err", err)
		return sseMsg{}, false
	}
	var probe struct {
		ActorID *string `json:"actor_id"`
	}
	_ = json.Unmarshal(data, &probe)
	msg := sseMsg{name: string(m.Topic), data: data}
	if probe.ActorID != nil {
		msg.actorID = *probe.ActorID
	}
	return msg, true
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "internal", "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	c := &sseClient{ch: make(chan sseMsg, clientBuffer), actorID: r.URL.Query().Get("actor_id")}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()

	fmt.Fprint(w, "retry: 3000\n: connected\n\n")
	fl.Flush()
	ping := time.NewTicker(h.Ping)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			fl.Flush()
		case m := <-c.ch:
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", m.name, m.data); err != nil {
				return
			}
			fl.Flush()
		}
	}
}

// Clients reports the number of connected browsers.
func (h *Hub) Clients() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}
