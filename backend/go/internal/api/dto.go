package api

import (
	"encoding/json"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/store"
)

// Event matches the TypeScript `Event` in 04 §B (snake_case, nullable fields present as null).
type Event struct {
	EventID    string          `json:"event_id"`
	TS         time.Time       `json:"ts"`
	Type       string          `json:"type"`
	Origin     string          `json:"origin"`
	Service    string          `json:"service"`
	SensorID   string          `json:"sensor_id"`
	SessionID  string          `json:"session_id"`
	ActorID    *string         `json:"actor_id"`
	ActorLabel *string         `json:"actor_label"`
	SrcIP      string          `json:"src_ip"`
	Data       json.RawMessage `json:"data"`
	Tokens     []string        `json:"tokens"`
	Summary    string          `json:"summary"`
	Envelope   json.RawMessage `json:"envelope,omitempty"`
}

func toEvent(ev store.StoredEvent, withEnvelope bool) Event {
	data := map[string]any{}
	_ = json.Unmarshal(ev.Data, &data)
	out := Event{
		EventID: ev.EventID, TS: ev.TS.UTC(), Type: ev.Type, Origin: ev.Origin, Service: ev.Service,
		SensorID: ev.SensorID, SessionID: ev.SessionID, ActorID: ev.ActorID, ActorLabel: ev.ActorLabel,
		SrcIP: ev.SrcIP, Data: ev.Data, Tokens: ev.Tokens, Summary: event.Summary(ev.Type, data),
	}
	if out.Tokens == nil {
		out.Tokens = []string{}
	}
	if len(out.Data) == 0 {
		out.Data = json.RawMessage(`{}`)
	}
	if withEnvelope {
		out.Envelope = ev.Envelope
	}
	return out
}

// User matches `User` in 04 §B.
type User struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Role   string `json:"role"`
}

type list[T any] struct {
	Items      []T     `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func newList[T any](items []T, next string) list[T] {
	if items == nil {
		items = []T{}
	}
	l := list[T]{Items: items}
	if next != "" {
		l.NextCursor = &next
	}
	return l
}
