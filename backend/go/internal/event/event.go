// Package event defines the dsoc.event/v1 envelope (02-event-schema, frozen contract) and its validation.
package event

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

const (
	Schema          = "dsoc.event/v1"
	MaxEnvelopeSize = 64 << 10
	MaxRawSize      = 4 << 10
	MaxBatch        = 200
	MaxFutureSkew   = 5 * time.Minute
)

type Envelope struct {
	Schema  string          `json:"schema"`
	Origin  string          `json:"origin"`
	EventID string          `json:"event_id"`
	TS      time.Time       `json:"ts"`
	Sensor  Sensor          `json:"sensor"`
	Session SessionRef      `json:"session"`
	Src     Endpoint        `json:"src"`
	Dst     Dst             `json:"dst"`
	Type    string          `json:"type"`
	Data    json.RawMessage `json:"data"`
	Client  *Client         `json:"client,omitempty"`
	Timing  *Timing         `json:"timing,omitempty"`
	Tokens  []string        `json:"tokens,omitempty"`
}

type Sensor struct {
	ID       string `json:"id"`
	Service  string `json:"service"`
	MazeNode string `json:"maze_node,omitempty"`
}

type SessionRef struct {
	SensorSessionID string `json:"sensor_session_id"`
	Seq             int    `json:"seq"`
}

type Endpoint struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

type Dst struct {
	Port int `json:"port"`
}

// Client holds fingerprint inputs. Unknown values are omitted, never empty strings.
type Client struct {
	SSHBanner string `json:"ssh_banner,omitempty"`
	SSHKeyFP  string `json:"ssh_key_fp,omitempty"`
	HASSH     string `json:"hassh,omitempty"`
	UA        string `json:"ua,omitempty"`
	JA4       string `json:"ja4,omitempty"`
}

// Timing is per shell line (02 §timing).
type Timing struct {
	SincePrevMS int64 `json:"since_prev_ms"`
	Keystrokes  int   `json:"keystrokes"`
	Edits       int   `json:"edits"`
	Paste       bool  `json:"paste"`
}

var Services = set("ssh", "web", "dbadmin", "k8s", "beacon", "engine", "firewall", "hostauth", "appauth")
var Origins = set("decoy", "production")

// Types lists every event type in 02 plus the engine types used by 08 (deception.tactic).
var Types = set(
	"conn.open", "conn.close", "auth.attempt", "shell.command", "file.read", "file.download", "file.upload",
	"http.request", "k8s.api_call", "token.used", "input.suspicious", "scan.detected", "maze.unlock",
	"sensor.heartbeat", "fw.deny", "fw.allow", "auth.real_failed", "auth.real_success", "auth.app_failed",
	"auth.app_success", "deception.tactic",
)

// ProductionServices may only appear with origin=production (07 §8).
var ProductionServices = set("firewall", "hostauth", "appauth")

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// ValidationError explains why one envelope was rejected (returned in the ingest response).
type ValidationError struct{ Reason string }

func (e *ValidationError) Error() string { return e.Reason }

func invalid(format string, args ...any) error {
	return &ValidationError{Reason: fmt.Sprintf(format, args...)}
}

// Validate checks one envelope against the field rules of 02. sensorID is the authenticated sensor.
func (e *Envelope) Validate(sensorID string, now time.Time) error {
	switch {
	case e.Schema != Schema:
		return invalid("schema must be %s", Schema)
	case !validULID(e.EventID):
		return invalid("event_id must be a ULID")
	case e.TS.IsZero():
		return invalid("ts is required")
	case e.TS.After(now.Add(MaxFutureSkew)):
		return invalid("ts is more than 5 min in the future")
	case e.Sensor.ID != sensorID:
		return invalid("sensor.id does not match the authenticated sensor")
	case !Services[e.Sensor.Service]:
		return invalid("invalid sensor.service")
	case !Origins[e.Origin]:
		return invalid("invalid origin")
	case ProductionServices[e.Sensor.Service] && e.Origin != "production":
		return invalid("service %s requires origin production", e.Sensor.Service)
	case !ProductionServices[e.Sensor.Service] && e.Origin == "production":
		return invalid("origin production is only for firewall, hostauth, appauth")
	case !strings.HasPrefix(e.Session.SensorSessionID, e.Sensor.ID+":") || len(e.Session.SensorSessionID) > 200:
		return invalid("session.sensor_session_id must be <sensor.id>:<random>")
	case e.Session.Seq < 0:
		return invalid("session.seq must be >= 0")
	case !validIP(e.Src.IP):
		return invalid("src.ip is not an IP address")
	case e.Src.Port < 0 || e.Src.Port > 65535 || e.Dst.Port < 0 || e.Dst.Port > 65535:
		return invalid("port out of range")
	case !Types[e.Type]:
		return invalid("invalid type")
	}
	if len(e.Data) == 0 {
		return invalid("data is required (may be {})")
	}
	var data map[string]any
	if err := json.Unmarshal(e.Data, &data); err != nil || data == nil {
		return invalid("data must be a JSON object")
	}
	if raw, ok := data["raw"].(string); ok && len(raw) > MaxRawSize {
		return invalid("data.raw exceeds 4 KB (truncate and set data.truncated)")
	}
	for _, t := range e.Tokens {
		if t == "" || len(t) > 64 {
			return invalid("invalid token id")
		}
	}
	return nil
}

func validULID(s string) bool {
	if len(s) != ulid.EncodedSize {
		return false
	}
	_, err := ulid.ParseStrict(s)
	return err == nil
}

func validIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// DataMap decodes Data into a map (empty map on error).
func (e *Envelope) DataMap() map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(e.Data, &m)
	return m
}

var (
	entropyMu sync.Mutex
	entropy   = ulid.Monotonic(rand.Reader, 0)
)

// NewID returns a new ULID string (monotonic within a millisecond).
func NewID(t time.Time) string {
	entropyMu.Lock()
	defer entropyMu.Unlock()
	return ulid.MustNew(ulid.Timestamp(t), entropy).String()
}

// DecodeBatch parses a JSON array of envelopes, keeping each element's raw bytes for storage.
func DecodeBatch(body []byte) ([]Envelope, []json.RawMessage, error) {
	var raws []json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&raws); err != nil {
		return nil, nil, errors.New("body must be a JSON array of envelopes")
	}
	if len(raws) == 0 || len(raws) > MaxBatch {
		return nil, nil, fmt.Errorf("batch must hold 1-%d envelopes", MaxBatch)
	}
	envs := make([]Envelope, len(raws))
	for i, raw := range raws {
		if len(raw) > MaxEnvelopeSize {
			envs[i] = Envelope{}
			continue
		}
		if err := json.Unmarshal(raw, &envs[i]); err != nil {
			envs[i] = Envelope{}
		}
	}
	return envs, raws, nil
}
