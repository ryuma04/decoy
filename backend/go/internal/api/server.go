// Package api serves the analyst API (04 §B): REST + SSE behind a JWT cookie.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/store"
)

const maxBodyBytes = 64 << 10

// Store is the part of store.Store the analyst API uses.
type Store interface {
	UserByEmail(ctx context.Context, email string) (store.User, error)
	ListEvents(ctx context.Context, f store.EventFilter) ([]store.StoredEvent, string, error)
	GetEvent(ctx context.Context, id string) (store.StoredEvent, error)
}

type Server struct {
	Store   Store
	Bus     bus.Bus
	Auth    *Auth
	Hub     *Hub
	limiter loginLimiter
}

// Routes registers every analyst endpoint on mux.
func (s *Server) Routes(mux *http.ServeMux) {
	authed := func(h http.HandlerFunc) http.HandlerFunc { return s.Auth.Require(false, h) }
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.HandleFunc("POST /v1/auth/logout", s.logout)
	mux.HandleFunc("GET /v1/auth/me", authed(s.me))
	mux.HandleFunc("GET /v1/events", authed(s.listEvents))
	mux.HandleFunc("GET /v1/events/{event_id}", authed(s.getEvent))
	mux.HandleFunc("GET /v1/stream", authed(s.Hub.ServeHTTP))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]bool{"ok": true}) })
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{Type: q.Get("type"), Service: q.Get("service"), ActorID: q.Get("actor_id"),
		SessionID: q.Get("session_id"), SrcIP: q.Get("src_ip"), Q: q.Get("q"), Cursor: q.Get("cursor")}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "since must be RFC3339")
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "until must be RFC3339")
		return
	}
	if l := q.Get("limit"); l != "" {
		if f.Limit, err = strconv.Atoi(l); err != nil || f.Limit < 1 || f.Limit > 200 {
			writeError(w, http.StatusBadRequest, "bad_request", "limit must be 1-200")
			return
		}
	}
	evs, next, err := s.Store.ListEvents(r.Context(), f)
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	items := make([]Event, len(evs))
	for i, ev := range evs {
		items[i] = toEvent(ev, false)
	}
	writeJSON(w, http.StatusOK, newList(items, next))
}

func (s *Server) getEvent(w http.ResponseWriter, r *http.Request) {
	ev, err := s.Store.GetEvent(r.Context(), r.PathValue("event_id"))
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, http.StatusNotFound, "not_found", "event not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	writeJSON(w, http.StatusOK, toEvent(ev, true))
}

func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}
