// Command decoy-db is the database decoy (06 §5): a PostgreSQL wire-protocol server with fake data that accepts
// the planted tok_db credential and reports every query to core via sensorkit. Never executes anything.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ryuma04/decoy/backend/internal/config"
	"github.com/ryuma04/decoy/backend/internal/decoy/beacon"
	decoydb "github.com/ryuma04/decoy/backend/internal/decoy/db"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	cfg, err := config.LoadSensor(":5432")
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	p := persona.Load(filepath.Join(cfg.SeedDir, "out", "persona.json"), os.Getenv("PERSONA_SEED"))
	tokens, err := beacon.LoadTokensFromSeed(cfg.SeedDir)
	if err != nil {
		slog.Error("tokens", "err", err)
		os.Exit(1)
	}
	dstPort := 5432 // what the planted db.env advertises, whatever port the lab listens on
	if v := os.Getenv("ADVERTISED_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &dstPort)
	} else if _, ps, err := net.SplitHostPort(cfg.Addr); err == nil {
		fmt.Sscanf(ps, "%d", &dstPort)
	}

	kit := sensorkit.New(sensorkit.Options{SensorID: cfg.SensorID, Key: cfg.Key, CoreURL: cfg.CoreURL, Service: "db",
		DataDir: cfg.DataDir, Version: "0.1.0"})
	kit.Start(ctx)
	defer kit.Close()

	var aliases []string // DB_ALIASES: comma-separated database names that planted lures advertise
	for _, a := range strings.Split(os.Getenv("DB_ALIASES"), ",") {
		if a = strings.TrimSpace(a); a != "" {
			aliases = append(aliases, a)
		}
	}
	srv := decoydb.New(decoydb.Config{Addr: cfg.Addr, Kit: kit, Persona: p, DBPass: tokens["tok_db"].MatchValue, DstPort: dstPort,
		Aliases: aliases})
	slog.Info("starting db decoy", "addr", cfg.Addr, "sensor_id", cfg.SensorID, "company", p.Company)
	if err := srv.ListenAndServe(ctx); err != nil {
		slog.Error("db decoy stopped", "err", err)
	}
}
