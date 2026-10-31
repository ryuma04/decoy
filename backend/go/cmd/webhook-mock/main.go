// Command webhook-mock logs every Discord/Slack payload it receives, so tests and demos never hit real
// webhooks (13). GET /received returns the payloads seen so far.
package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
)

func main() {
	var mu sync.Mutex
	var got []json.RawMessage
	http.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		mu.Lock()
		got = append(got, b)
		mu.Unlock()
		slog.Info("webhook", "path", r.URL.Path, "bytes", len(b), "body", string(b))
		w.WriteHeader(http.StatusNoContent)
	})
	http.HandleFunc("GET /received", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(got)
	})
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":9000"
	}
	slog.Info("webhook mock listening", "addr", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}
