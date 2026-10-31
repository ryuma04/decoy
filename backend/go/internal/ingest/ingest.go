// Package ingest serves the sensor API (04 §A): HMAC auth, validation, dedup, session mapping, persist, publish.
// It never runs detection logic; intel subscribes to the bus.
package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
	"github.com/ryuma04/decoy/backend/internal/store"
)

const maxBatchBytes = 13 << 20

// Store is the part of store.Store that ingest needs (an interface so handlers are testable).
type Store interface {
	IngestBatch(ctx context.Context, sensorID string, envs []event.Envelope, raws []json.RawMessage) (store.IngestResult, error)
	Heartbeat(ctx context.Context, sensorID, service, version string) error
	Policy(ctx context.Context) (store.Policy, error)
}

type Server struct {
	Store Store
	Bus   bus.Bus
	Keys  map[string]string
	Now   func() time.Time
}

type rejected struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}

type ingestResponse struct {
	Accepted   int        `json:"accepted"`
	Duplicates int        `json:"duplicates"`
	Rejected   []rejected `json:"rejected"`
}

// Routes registers the sensor API on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/ingest/events", s.auth(s.events))
	mux.HandleFunc("POST /v1/ingest/heartbeat", s.auth(s.heartbeat))
	mux.HandleFunc("GET /v1/sensor/policy", s.auth(s.policy))
	mux.HandleFunc("GET /v1/sensor/maze-view", s.auth(s.mazeView))
}

type authedHandler func(w http.ResponseWriter, r *http.Request, sensorID string, body []byte)

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) auth(next authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBatchBytes))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				writeError(w, http.StatusRequestEntityTooLarge, "too_large", "batch exceeds 13 MB")
				return
			}
			writeError(w, http.StatusBadRequest, "bad_body", "could not read body")
			return
		}
		id, err := sensorauth.Verify(r, body, s.Keys, s.now())
		if err != nil {
			slog.Warn("sensor auth failed", "sensor", r.Header.Get(sensorauth.HeaderSensor), "err", err, "remote", r.RemoteAddr)
			writeError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		next(w, r, id, body)
	}
}

func (s *Server) events(w http.ResponseWriter, r *http.Request, sensorID string, body []byte) {
	envs, raws, err := event.DecodeBatch(body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_batch", err.Error())
		return
	}
	resp := ingestResponse{Rejected: []rejected{}}
	now := s.now()
	var okEnvs []event.Envelope
	var okRaws []json.RawMessage
	for i := range envs {
		reason := ""
		switch {
		case len(raws[i]) > event.MaxEnvelopeSize:
			reason = "envelope exceeds 64 KB"
		default:
			if err := envs[i].Validate(sensorID, now); err != nil {
				reason = err.Error()
			}
		}
		if reason != "" {
			resp.Rejected = append(resp.Rejected, rejected{EventID: envs[i].EventID, Reason: reason})
			continue
		}
		okEnvs = append(okEnvs, envs[i])
		okRaws = append(okRaws, raws[i])
	}
	if len(okEnvs) > 0 {
		res, err := s.Store.IngestBatch(r.Context(), sensorID, okEnvs, okRaws)
		if err != nil {
			slog.Error("ingest store failed", "sensor", sensorID, "err", err)
			writeError(w, http.StatusServiceUnavailable, "store_unavailable", "could not store batch; retry")
			return
		}
		resp.Accepted, resp.Duplicates = len(res.Accepted), res.Duplicates
		for _, ev := range res.Accepted { // after commit: intel and SSE work off the request path
			s.Bus.Publish(bus.TopicEvent, ev)
		}
	}
	if len(resp.Rejected) > 0 {
		slog.Warn("ingest rejected events", "sensor", sensorID, "count", len(resp.Rejected), "first", resp.Rejected[0].Reason)
	}
	writeJSON(w, http.StatusOK, resp)
}

type heartbeatBody struct {
	SensorID       string `json:"sensor_id"`
	Version        string `json:"version"`
	UptimeS        int64  `json:"uptime_s"`
	ActiveSessions int    `json:"active_sessions"`
}

// SensorStatus is published on the sensor topic.
type SensorStatus struct {
	SensorID string    `json:"sensor_id"`
	Service  string    `json:"service"`
	Version  string    `json:"version"`
	LastSeen time.Time `json:"last_seen"`
	Status   string    `json:"status"`
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, sensorID string, body []byte) {
	var hb heartbeatBody
	if err := json.Unmarshal(body, &hb); err != nil || (hb.SensorID != "" && hb.SensorID != sensorID) {
		writeError(w, http.StatusBadRequest, "bad_heartbeat", "body must be a heartbeat for the authenticated sensor")
		return
	}
	svc := ServiceFromID(sensorID)
	if err := s.Store.Heartbeat(r.Context(), sensorID, svc, hb.Version); err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "could not store heartbeat")
		return
	}
	s.Bus.Publish(bus.TopicSensor, SensorStatus{SensorID: sensorID, Service: svc, Version: hb.Version, LastSeen: s.now().UTC(), Status: "ok"})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) policy(w http.ResponseWriter, r *http.Request, _ string, _ []byte) {
	p, err := s.Store.Policy(r.Context())
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "policy unavailable")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// mazeView returns the default view until the maze controller exists (M2 step 8 / M5).
func (s *Server) mazeView(w http.ResponseWriter, r *http.Request, _ string, _ []byte) {
	if r.URL.Query().Get("sensor_session_id") == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "sensor_session_id is required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"actor_id": nil, "visible_nodes": []string{"web_entry", "lure_backup", "ssh_entry", "lure_aws"},
		"files": []any{}, "k8s_secrets": []any{},
		"limits": map[string]any{"remaining_requests": 500, "session_deadline": s.now().UTC().Add(30 * time.Minute)},
	})
}

// ServiceFromID maps a sensor id like "ssh-01" to its service (log collectors report "firewall").
func ServiceFromID(id string) string {
	prefix, _, _ := strings.Cut(id, "-")
	switch prefix {
	case "ssh", "web", "k8s", "beacon", "dbadmin":
		return prefix
	case "logs":
		return "firewall"
	}
	return "engine"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
