// Package mlclient calls the ML service (04 §C) with per-call timeouts and a circuit breaker.
// Every error means "continue without ML": callers fall back to rules or templates.
package mlclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

var (
	ErrOff    = errors.New("ml: disabled")
	ErrOpen   = errors.New("ml: circuit open")
	ErrLLMOff = errors.New("ml: narration has no LLM key")
)

const (
	classifyTimeout = 300 * time.Millisecond
	narrateTimeout  = 5 * time.Second
	breakAfter      = 5
	breakFor        = 30 * time.Second
)

type Client struct {
	base string
	http *http.Client
	mu   sync.Mutex
	// one breaker per endpoint
	fails     map[string]int
	openUntil map[string]time.Time
	now       func() time.Time
}

// New returns nil when url is empty (ML off); all methods on a nil client return ErrOff.
func New(url string) *Client {
	if url == "" {
		return nil
	}
	return &Client{base: url, http: &http.Client{}, fails: map[string]int{}, openUntil: map[string]time.Time{}, now: time.Now}
}

func (c *Client) Enabled() bool { return c != nil }

// InputResult matches the classify-input response.
type InputResult struct {
	Label       string             `json:"label"`
	Risk        float64            `json:"risk"`
	Scores      map[string]float64 `json:"scores"`
	TopFeatures []string           `json:"top_features"`
	Payload     *string            `json:"payload"`
	WasEncoded  bool               `json:"was_encoded"`
}

func (c *Client) ClassifyInput(ctx context.Context, param, value, service, path, field string) (InputResult, error) {
	var out InputResult
	err := c.post(ctx, "/ml/v1/classify-input", classifyTimeout, map[string]any{
		"param": param, "value": value, "context": map[string]any{"service": service, "path": path, "field": field},
	}, &out)
	return out, err
}

// NarrateRequest / NarrateResult match 04 §C.
type NarrateRequest struct {
	Kind            string       `json:"kind"`
	RefID           string       `json:"ref_id"`
	Audience        string       `json:"audience"`
	Facts           NarrateFacts `json:"facts"`
	AttackerStrings []string     `json:"attacker_strings"`
}

type NarrateFacts struct {
	ActorLabel         *string       `json:"actor_label"`
	Severity           *string       `json:"severity"`
	RiskScore          *int          `json:"risk_score"`
	BehaviourClass     *string       `json:"behaviour_class"`
	Services           []string      `json:"services"`
	IPs                []string      `json:"ips"`
	Tokens             []string      `json:"tokens"`
	Findings           []FactFinding `json:"findings"`
	Timeline           []FactLine    `json:"timeline"`
	RecommendedActions []string      `json:"recommended_actions"`
	DashboardURL       string        `json:"dashboard_url"`
	TouchedProduction  bool          `json:"touched_production"`
}

type FactFinding struct {
	Title     string  `json:"title"`
	Technique *string `json:"technique"`
	TS        string  `json:"ts"`
}

type FactLine struct {
	TS   string `json:"ts"`
	Line string `json:"line"`
}

type NarrateResult struct {
	Headline   string            `json:"headline"`
	Text       string            `json:"text"`
	Bullets    []string          `json:"bullets"`
	Source     string            `json:"source"`
	Model      string            `json:"model"`
	PromptHash string            `json:"prompt_hash"`
	Guard      map[string]string `json:"guard"`
}

// Narrate calls the LLM narration; timeout is capped at 5 s (callers pass 3 s for alerts).
func (c *Client) Narrate(ctx context.Context, req NarrateRequest, timeout time.Duration) (NarrateResult, error) {
	if timeout <= 0 || timeout > narrateTimeout {
		timeout = narrateTimeout
	}
	var out NarrateResult
	err := c.post(ctx, "/ml/v1/narrate", timeout, req, &out)
	return out, err
}

// Health reports whether the service answers and whether narration has an LLM.
func (c *Client) Health(ctx context.Context) (ok bool, narration string) {
	if c == nil {
		return false, "off"
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/health", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return false, "off"
	}
	defer resp.Body.Close()
	var h struct {
		OK        bool   `json:"ok"`
		Narration string `json:"narration"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&h) != nil {
		return false, "off"
	}
	return h.OK, h.Narration
}

func (c *Client) post(ctx context.Context, path string, timeout time.Duration, in, out any) error {
	if c == nil {
		return ErrOff
	}
	if c.isOpen(path) {
		return ErrOpen
	}
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		c.result(path, false)
		return fmt.Errorf("ml %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusServiceUnavailable && path == "/ml/v1/narrate" {
		c.result(path, true) // service is healthy, it just has no key
		return ErrLLMOff
	}
	if resp.StatusCode != http.StatusOK {
		c.result(path, false)
		return fmt.Errorf("ml %s: status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out); err != nil {
		c.result(path, false)
		return fmt.Errorf("ml %s: bad response: %w", path, err)
	}
	c.result(path, true)
	return nil
}

func (c *Client) isOpen(path string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now().Before(c.openUntil[path])
}

// result updates the breaker: 5 consecutive failures open it for 30 s.
func (c *Client) result(path string, ok bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ok {
		c.fails[path] = 0
		return
	}
	c.fails[path]++
	if c.fails[path] >= breakAfter {
		c.openUntil[path] = c.now().Add(breakFor)
		c.fails[path] = 0
	}
}
