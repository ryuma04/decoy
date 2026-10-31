// Command decoy-beacon is the beacon decoy server (06 §4).
// Emulates an AWS S3 endpoint returning AccessDenied on lure SigV4 credentials,
// and serves 1x1 transparent GIFs for lure tracking URLs.
// Never executes commands or touches real cloud APIs.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ryuma04/decoy/backend/internal/config"
	"github.com/ryuma04/decoy/backend/internal/decoy/beacon"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	if os.Getenv("SENSOR_ID") == "" {
		_ = os.Setenv("SENSOR_ID", "beacon-01")
	}
	if os.Getenv("SENSOR_KEY") == "" {
		_ = os.Setenv("SENSOR_KEY", "beacon-secret-key-16ch")
	}

	cfg, err := config.LoadSensor(":8088")
	if err != nil {
		slog.Error("failed to load sensor config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: cfg.SensorID,
		Key:      cfg.Key,
		CoreURL:  cfg.CoreURL,
		Service:  "beacon",
		Origin:   "decoy",
		DataDir:  cfg.DataDir,
	})
	kit.Start(ctx)
	defer kit.Close()

	toks, err := beacon.LoadTokensFromSeed(cfg.SeedDir)
	if err != nil {
		slog.Warn("could not load tokens from seed", "err", err)
	} else {
		slog.Info("tokens loaded from seed", "count", len(toks))
	}

	srv, err := beacon.New(beacon.Config{
		Addr:    cfg.Addr,
		Kit:     kit,
		Tokens:  toks,
		SeedDir: cfg.SeedDir,
	})
	if err != nil {
		slog.Error("failed to create beacon server", "err", err)
		os.Exit(1)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancelShutdown := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancelShutdown()
		_ = srv.Shutdown(shutdownCtx)
	}()

	slog.Info("decoy-beacon listening", "addr", cfg.Addr, "sensor_id", cfg.SensorID)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("beacon server error", "err", err)
		os.Exit(1)
	}
}

