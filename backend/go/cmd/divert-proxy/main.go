// Command divert-proxy routes traffic between the real Aetees shop and the honeypot clone (06 §Divert, docs/18 Tasks 9-12).
// Never executes anything real.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ryuma04/decoy/backend/internal/divert"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func loadTokens(seedDir string) map[string]divert.Honeytoken {
	paths := []string{
		filepath.Join(seedDir, "out", "tokens.json"),
		filepath.Join("seed", "out", "tokens.json"),
		filepath.Join("..", "seed", "out", "tokens.json"),
		filepath.Join("backend", "go", "seed", "out", "tokens.json"),
		filepath.Join("..", "backend", "go", "seed", "out", "tokens.json"),
	}

	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			var tokens map[string]divert.Honeytoken
			if err := json.Unmarshal(b, &tokens); err == nil {
				slog.Info("loaded honeytokens", "count", len(tokens), "path", p)
				return tokens
			}
		}
	}

	slog.Warn("could not find tokens.json; using default token identifiers")
	return map[string]divert.Honeytoken{
		"tok_aetees_admin": {
			TokenID:    "tok_aetees_admin",
			Kind:       "admin_password",
			MatchValue: "BakeAdmin2026!Secret",
		},
		"tok_db": {
			TokenID:    "tok_db",
			Kind:       "db_password",
			MatchValue: "AeteesDbPass42!",
		},
		"tok_aetees_invoice": {
			TokenID:    "tok_aetees_invoice",
			Kind:       "url",
			MatchValue: "/invoices/view/a8f9c0e21b4d3e5f",
		},
	}
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	listenAddr := env("LISTEN_ADDR", ":8200")
	realURLStr := env("REAL_URL", "http://127.0.0.1:3100")
	cloneURLStr := env("CLONE_URL", "http://127.0.0.1:3101")
	coreURLStr := env("CORE_URL", "http://127.0.0.1:8443")
	mlURLStr := env("ML_URL", "http://127.0.0.1:8000")
	dataDir := env("DATA_DIR", ".data")
	seedDir := env("SEED_DIR", "seed")
	sensorID := env("SENSOR_ID", "aetees-01")
	sensorKey := os.Getenv("SENSOR_KEY")

	realURL, err := url.Parse(realURLStr)
	if err != nil {
		slog.Error("invalid REAL_URL", "err", err)
		os.Exit(1)
	}

	cloneURL, err := url.Parse(cloneURLStr)
	if err != nil {
		slog.Error("invalid CLONE_URL", "err", err)
		os.Exit(1)
	}

	tokens := loadTokens(seedDir)

	adminToken := "BakeAdmin2026!Secret"
	if t, ok := tokens["tok_aetees_admin"]; ok && t.MatchValue != "" {
		adminToken = t.MatchValue
	}
	dbToken := "AeteesDbPass42!"
	if t, ok := tokens["tok_db"]; ok && t.MatchValue != "" {
		dbToken = t.MatchValue
	}
	invoiceToken := "/invoices/view/a8f9c0e21b4d3e5f"
	if t, ok := tokens["tok_aetees_invoice"]; ok && t.MatchValue != "" {
		invoiceToken = t.MatchValue
	}

	var kit *sensorkit.Kit
	if sensorKey != "" {
		kit = sensorkit.New(sensorkit.Options{
			SensorID: sensorID,
			Key:      sensorKey,
			CoreURL:  coreURLStr,
			Service:  "web",
			DataDir:  dataDir,
			Version:  "0.1.0",
		})
	} else {
		slog.Warn("SENSOR_KEY not set; running divert proxy without sensorkit uplink")
	}

	recoveryMgr := divert.NewRecoveryManager(divert.RecoveryConfig{
		RealURL: realURL,
	})
	lureMgr := divert.NewLureManager(adminToken, dbToken, invoiceToken)
	tacticsMgr := divert.NewTacticsManager(dataDir, mlURLStr, adminToken)
	tripwire := divert.NewTripwire()

	proxyCfg := divert.ProxyConfig{
		RealURL:    realURL,
		CloneURL:   cloneURL,
		Kit:        kit,
		Classifier: tripwire,
		Recovery:   recoveryMgr,
		Lures:      lureMgr,
		Tactics:    tacticsMgr,
		Tokens:     tokens,
	}

	proxy, err := divert.NewProxy(proxyCfg)
	if err != nil {
		slog.Error("failed to create divert proxy", "err", err)
		os.Exit(1)
	}

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go func() {
		slog.Info("divert proxy listening", "addr", listenAddr, "real", realURLStr, "clone", cloneURLStr)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("divert proxy failed", "err", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	slog.Info("shutting down divert proxy")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if kit != nil {
		kit.Close()
	}
	_ = server.Shutdown(shutdownCtx)
	slog.Info("divert proxy stopped")
}
