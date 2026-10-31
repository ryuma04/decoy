// Command core runs the Deception SOC core: sensor API, intel, alerting and the analyst API in one process.
//
//	core serve        migrate, then serve the sensor API (SENSOR_ADDR) and analyst API (ANALYST_ADDR)
//	core migrate      apply database migrations and exit
//	core seed-admin   create or reset the admin user from SOC_ADMIN_EMAIL / SOC_ADMIN_PASSWORD
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ryuma04/decoy/backend/internal/alert"
	"github.com/ryuma04/decoy/backend/internal/api"
	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/config"
	"github.com/ryuma04/decoy/backend/internal/incident"
	"github.com/ryuma04/decoy/backend/internal/ingest"
	"github.com/ryuma04/decoy/backend/internal/intel/engine"
	"github.com/ryuma04/decoy/backend/internal/intel/features"
	"github.com/ryuma04/decoy/backend/internal/intel/rules"
	"github.com/ryuma04/decoy/backend/internal/maze"
	"github.com/ryuma04/decoy/backend/internal/mlclient"
	"github.com/ryuma04/decoy/backend/internal/narrate"
	"github.com/ryuma04/decoy/backend/internal/store"
)

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	if cmd == "healthcheck" { // container healthcheck: distroless images have no curl
		addr := os.Getenv("ANALYST_ADDR")
		if addr == "" || addr[0] == ':' {
			addr = "127.0.0.1" + addr
		}
		resp, err := (&http.Client{Timeout: 3 * time.Second}).Get("http://" + addr + "/healthz")
		if err != nil || resp.StatusCode != http.StatusOK {
			os.Exit(1)
		}
		os.Exit(0)
	}
	cfg, err := config.LoadCore()
	setupLogging(cfg.LogLevel)
	if err != nil {
		fatal("config", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "migrate":
		if err := store.Migrate(cfg.DatabaseURL); err != nil {
			fatal("migrate", err)
		}
		slog.Info("migrations applied")
	case "seed-admin":
		if err := seedAdmin(ctx, cfg); err != nil {
			fatal("seed-admin", err)
		}
	case "serve":
		if err := serve(ctx, cfg); err != nil {
			fatal("serve", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "usage: core [serve|migrate|seed-admin]\n")
		os.Exit(64)
	}
}

func seedAdmin(ctx context.Context, cfg config.Core) error {
	if cfg.AdminEmail == "" || len(cfg.AdminPassword) < 8 {
		return errors.New("SOC_ADMIN_EMAIL and SOC_ADMIN_PASSWORD (>= 8 chars) are required")
	}
	if err := store.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	hash, err := api.HashPassword(cfg.AdminPassword)
	if err != nil {
		return err
	}
	if err := st.UpsertUser(ctx, cfg.AdminEmail, hash, "admin"); err != nil {
		return err
	}
	slog.Info("admin user ready", "email", cfg.AdminEmail)
	return nil
}

func serve(ctx context.Context, cfg config.Core) error {
	if len(cfg.SensorKeys) == 0 {
		return errors.New("SENSOR_KEYS is empty: no decoy could authenticate")
	}
	if err := store.Migrate(cfg.DatabaseURL); err != nil {
		return err
	}
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	b := bus.NewMemory()
	hub := api.NewHub()
	go hub.Run(b)

	rs, err := rules.Load(cfg.RulesPath)
	if err != nil {
		return err
	}
	ml := mlclient.New(cfg.MLURL)
	mg, err := maze.Load(cfg.MazePath)
	if err != nil {
		return err
	}
	mc := &maze.Controller{Graph: mg, Store: st, Bus: b, Adaptive: cfg.MazeAdaptive}
	feat := features.New()
	eng := &engine.Engine{Store: st, Bus: b, Rules: rs, ML: ml, Maze: mc, Features: feat}
	go eng.Run(ctx)
	narrator := &narrate.Narrator{ML: ml, MaxPerHour: cfg.NarrateMaxHr}
	notifier := alert.NewNotifier(alert.Config{
		DiscordURL:   cfg.DiscordURL,
		SlackURL:     cfg.SlackURL,
		DashboardURL: cfg.DashboardURL,
		Narrator:     narrator,
		Store:        st,
	})
	go notifier.Run(ctx)
	go (&incident.Manager{Store: st, Bus: b, Notify: notifier.Notify}).Run(ctx)
	slog.Info("intel engine started", "rules", len(rs.Rules), "ml", ml.Enabled())

	sensorMux := http.NewServeMux()
	(&ingest.Server{Store: st, Bus: b, Keys: cfg.SensorKeys, Maze: mc}).Routes(sensorMux)
	analystMux := http.NewServeMux()
	(&api.Server{Store: st, Bus: b, Hub: hub, DB: st, ML: ml, ScorerLearn: cfg.ScorerLearn, Narrator: narrator, DashboardURL: cfg.DashboardURL, MazeGraph: mg, Features: feat,
		Auth: &api.Auth{Secret: cfg.JWTSecret, TTL: cfg.SessionTTL, Secure: cfg.CookieSecure}}).Routes(analystMux)

	servers := []*http.Server{
		{Addr: cfg.SensorAddr, Handler: logRequests("sensor", sensorMux), ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second},
		// No WriteTimeout on the analyst server: /v1/stream is long-lived.
		{Addr: cfg.AnalystAddr, Handler: logRequests("analyst", analystMux), ReadHeaderTimeout: 5 * time.Second},
	}
	errc := make(chan error, len(servers))
	for _, s := range servers {
		go func(s *http.Server) {
			slog.Info("listening", "addr", s.Addr)
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- fmt.Errorf("%s: %w", s.Addr, err)
			}
		}(s)
	}
	slog.Info("core started", "sensors", len(cfg.SensorKeys), "ml", cfg.MLURL != "")

	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	slog.Info("core stopped")
	return nil
}

func logRequests(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		h.ServeHTTP(rw, r)
		if r.URL.Path != "/v1/stream" {
			slog.Debug("http", "api", name, "method", r.Method, "path", r.URL.Path, "status", rw.status, "ms", time.Since(start).Milliseconds())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// Flush keeps SSE working through the logging wrapper.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func setupLogging(level string) {
	var l slog.Level
	_ = l.UnmarshalText([]byte(level))
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
}

func fatal(what string, err error) {
	slog.Error(what+" failed", "err", err)
	os.Exit(1)
}
