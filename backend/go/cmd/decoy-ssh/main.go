// Command decoy-ssh is the SSH decoy server (06 §1).
// Emulates an OpenSSH server over fakefs, emitting dsoc.event/v1 envelopes to core via sensorkit.
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
	decoySSH "github.com/ryuma04/decoy/backend/internal/decoy/ssh"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.LoadSensor(":2222")
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

	// Load lures.
	lures, err := decoySSH.LoadLuresFromSeed(cfg.SeedDir)
	if err != nil {
		slog.Warn("could not load lures from seed, using default lures", "err", err)
	} else {
		slog.Info("lures loaded", "count", len(lures))
	}

	// Load deploy key.
	deployKey, err := decoySSH.ParseDeployKeyFromSeed(cfg.SeedDir)
	if err != nil {
		slog.Warn("could not load deploy key from seed", "err", err)
	} else {
		slog.Info("deploy key loaded", "fp", deployKey.Fingerprint)
	}

	// Persistent host key.
	signer, err := decoySSH.LoadOrGenerateHostKey(cfg.DataDir)
	if err != nil {
		slog.Error("failed to load or generate host key", "err", err)
		os.Exit(1)
	}

	// Parse dstPort from Addr.
	dstPort := 2222
	if _, portStr, err := net.SplitHostPort(cfg.Addr); err == nil {
		fmt.Sscanf(portStr, "%d", &dstPort)
	}

	// Sensorkit client.
	kit := sensorkit.New(sensorkit.Options{
		SensorID: cfg.SensorID,
		Key:      cfg.Key,
		CoreURL:  cfg.CoreURL,
		Service:  "ssh",
		DataDir:  cfg.DataDir,
		Version:  "0.1.0",
	})
	kit.Start(ctx)
	defer kit.Close()

	// Build and run server.
	srv, err := decoySSH.NewServer(decoySSH.ServerConfig{
		Kit:        kit,
		Persona:    p,
		Lures:      lures,
		DeployKey:  deployKey,
		ListenAddr: cfg.Addr,
		DstPort:    dstPort,
	})
	if err != nil {
		slog.Error("failed to create ssh decoy server", "err", err)
		os.Exit(1)
	}
	srv.AddHostKey(signer)

	slog.Info("starting ssh decoy server", "addr", cfg.Addr, "sensor_id", cfg.SensorID)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("ssh server stopped", "err", err)
	}
}

