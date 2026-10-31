// Command decoy-k8s is the Kubernetes API decoy server (06 §3).
// Listens on port 6443 with self-signed TLS.
// Emulates a Kubernetes API server, emitting dsoc.event/v1 envelopes to core via sensorkit.
// Never executes commands or touches real cluster infrastructure.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ryuma04/decoy/backend/internal/config"
	decoyK8s "github.com/ryuma04/decoy/backend/internal/decoy/k8s"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if os.Getenv("SENSOR_ID") == "" {
		_ = os.Setenv("SENSOR_ID", "k8s-01")
	}
	if os.Getenv("SENSOR_KEY") == "" {
		_ = os.Setenv("SENSOR_KEY", "k8s-secret-key-16ch")
	}

	cfg, err := config.LoadSensor(":6443")
	if err != nil {
		slog.Error("failed to load sensor config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Load persona
	personaPath := filepath.Join(cfg.SeedDir, "out", "persona.json")
	if _, err := os.Stat(personaPath); err != nil {
		alt := filepath.Join(cfg.SeedDir, "persona.json")
		if _, err := os.Stat(alt); err == nil {
			personaPath = alt
		} else {
			personaPath = filepath.Join("seed", "out", "persona.json")
		}
	}
	p := persona.Load(personaPath, os.Getenv("PERSONA_SEED"))
	slog.Info("persona loaded", "company", p.Company, "host", p.Hostname)

	// Load honeytokens
	toks, err := decoyK8s.LoadTokensFromSeed(cfg.SeedDir)
	if err != nil {
		slog.Warn("could not load tokens from seed", "err", err)
	} else {
		slog.Info("tokens loaded from seed", "count", len(toks))
	}

	kit := sensorkit.New(sensorkit.Options{
		SensorID: cfg.SensorID,
		Key:      cfg.Key,
		CoreURL:  cfg.CoreURL,
		Service:  "k8s",
		Origin:   "decoy",
		DataDir:  cfg.DataDir,
	})
	kit.Start(ctx)
	defer kit.Close()

	srv, err := decoyK8s.New(decoyK8s.Config{
		Addr:    cfg.Addr,
		Kit:     kit,
		Persona: p,
		Tokens:  toks,
		SeedDir: cfg.SeedDir,
	})
	if err != nil {
		slog.Error("failed to create k8s server", "err", err)
		os.Exit(1)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelShutdown()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("decoy-k8s listening (TLS)", "addr", cfg.Addr, "sensor_id", cfg.SensorID)
	if err := srv.ListenAndServeTLS(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("k8s server error", "err", err)
		os.Exit(1)
	}
}
