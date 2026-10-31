// Command send-sample posts a few signed sample events to core through sensorkit (14: lets core and the
// dashboard be tested before the decoys exist). Uses SENSOR_ID, SENSOR_KEY, CORE_URL.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"time"

	"github.com/ryuma04/decoy/backend/internal/config"
	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	ip := flag.String("ip", "10.66.0.23", "source IP to report")
	tactic := flag.Bool("tactic", false, "also send a deception.tactic event (tests the actor's tactics panel)")
	flag.Parse()
	cfg, err := config.LoadSensor(":0")
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	kit := sensorkit.New(sensorkit.Options{SensorID: cfg.SensorID, Key: cfg.Key, CoreURL: cfg.CoreURL,
		Service: "ssh", DataDir: os.TempDir()})
	ctx := context.Background()
	kit.Start(ctx)
	s := kit.NewSession(*ip, 50000, 2222)
	s.Client = &event.Client{SSHBanner: "SSH-2.0-OpenSSH_9.6"}
	s.Event("conn.open", "ssh_entry", map[string]any{}, nil, nil)
	for _, c := range []string{"whoami", "pwd", "ls -la"} {
		s.Event("shell.command", "ssh_entry", map[string]any{"raw": c, "argv0": c[:2], "cwd": "/home/deploy", "exit": 0},
			&event.Timing{SincePrevMS: 1500, Keystrokes: len(c)}, nil)
	}
	if *tactic {
		s.Event("deception.tactic", "ssh_entry", map[string]any{"tactic": "sunk_cost_export", "bias_pattern": "sunk_cost",
			"lure_id": "lure_backup", "effect": map[string]any{"polls": 7, "seconds_spent": 95}}, nil, nil)
	}
	s.Event("conn.close", "ssh_entry", map[string]any{"duration_ms": 4000, "reason": "client"}, nil, nil)
	time.Sleep(1500 * time.Millisecond) // one flush interval
	kit.Close()
	slog.Info("sample sent", "session", s.ID)
}
