// Command decoy-web is the Web decoy server (06 §2).
// Emulates an admin web application, emitting dsoc.event/v1 envelopes to core via sensorkit.
// Never executes anything real.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/ryuma04/decoy/backend/internal/config"
	decoyWeb "github.com/ryuma04/decoy/backend/internal/decoy/web"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.LoadSensor(":8080")
	if err != nil {
		slog.Error("failed to load sensor config", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Load persona.
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
	slog.Info("persona loaded", "company", p.Company, "host", p.Hostname, "path", personaPath)

	// Parse dstPort from Addr.
	dstPort := 8080
	if _, portStr, err := net.SplitHostPort(cfg.Addr); err == nil {
		fmt.Sscanf(portStr, "%d", &dstPort)
	}

	// Sensorkit client.
	kit := sensorkit.New(sensorkit.Options{
		SensorID: cfg.SensorID,
		Key:      cfg.Key,
		CoreURL:  cfg.CoreURL,
		Service:  "web",
		DataDir:  cfg.DataDir,
		Version:  "0.1.0",
	})
	kit.Start(ctx)
	defer kit.Close()

	// Build and run server.
	srv, err := decoyWeb.NewServer(decoyWeb.ServerConfig{
		Kit:        kit,
		Persona:    p,
		ListenAddr: cfg.Addr,
		DstPort:    dstPort,
		DataDir:    cfg.DataDir,
		SeedDir:    cfg.SeedDir,
	})
	if err != nil {
		slog.Error("failed to create web decoy server", "err", err)
		os.Exit(1)
	}

	slog.Info("starting web decoy server", "addr", cfg.Addr, "sensor_id", cfg.SensorID)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("web server stopped", "err", err)
	}
}

