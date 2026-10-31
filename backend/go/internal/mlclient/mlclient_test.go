package mlclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestNilClientIsOff(t *testing.T) {
	var c *Client = New("")
	if c.Enabled() {
		t.Fatal("empty URL must disable ML")
	}
	if _, err := c.ClassifyInput(context.Background(), "q", "x", "web", "/", "query"); !errors.Is(err, ErrOff) {
		t.Fatalf("err %v", err)
	}
}

func TestClassifyInputAndBreaker(t *testing.T) {
	var fail atomic.Bool
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if fail.Load() {
			w.WriteHeader(500)
			return
		}
		w.Write([]byte(`{"label":"sqli","risk":0.97,"scores":{"normal":0.03},"top_features":["' or"],"payload":null,"was_encoded":false}`))
	}))
	defer srv.Close()
	c := New(srv.URL)
	r, err := c.ClassifyInput(context.Background(), "q", "' or 1=1", "web", "/", "query")
	if err != nil || r.Label != "sqli" || r.Risk != 0.97 {
		t.Fatalf("%+v %v", r, err)
	}
	fail.Store(true)
	for i := 0; i < breakAfter; i++ {
		_, _ = c.ClassifyInput(context.Background(), "q", "x", "web", "/", "query")
	}
	before := calls.Load()
	if _, err := c.ClassifyInput(context.Background(), "q", "x", "web", "/", "query"); !errors.Is(err, ErrOpen) {
		t.Fatalf("breaker should be open: %v", err)
	}
	if calls.Load() != before {
		t.Fatal("open breaker must not call the service")
	}
	now := time.Now().Add(breakFor + time.Second)
	c.now = func() time.Time { return now }
	fail.Store(false)
	if _, err := c.ClassifyInput(context.Background(), "q", "x", "web", "/", "query"); err != nil {
		t.Fatalf("breaker should close after 30 s: %v", err)
	}
}

func TestTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond)
	}))
	defer srv.Close()
	start := time.Now()
	if _, err := New(srv.URL).ClassifyInput(context.Background(), "q", "x", "web", "/", "query"); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("classify timeout is 300 ms")
	}
}

func TestNarrateLLMOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		w.Write([]byte(`{"error":{"code":"llm_off"}}`))
	}))
	defer srv.Close()
	if _, err := New(srv.URL).Narrate(context.Background(), NarrateRequest{Kind: "actor"}, time.Second); !errors.Is(err, ErrLLMOff) {
		t.Fatalf("err %v", err)
	}
}
