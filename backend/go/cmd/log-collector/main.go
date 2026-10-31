// Command log-collector tails external log files (07 §8.1) and sends each parsed line to core as a
// dsoc.event/v1 envelope with origin "production" through sensorkit.
//
//	LOG_SOURCES=fw:/logs/fw.log,hostauth:/logs/auth.log,appauth:/logs/app-login.jsonl
//	CRED_SALT   salt for hashing passwords seen in app login logs (02 §External events)
package main

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ryuma04/decoy/backend/internal/config"
	"github.com/ryuma04/decoy/backend/internal/logparse"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

func main() {
	cfg, err := config.LoadSensor(":0")
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	sources := os.Getenv("LOG_SOURCES")
	if sources == "" {
		sources = "fw:/logs/fw.log,hostauth:/logs/auth.log,appauth:/logs/app-login.jsonl"
	}
	salt := os.Getenv("CRED_SALT")
	if salt == "" {
		salt = "dsoc-default-salt"
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	kits := map[string]*sensorkit.Kit{}
	for _, svc := range []string{"firewall", "hostauth", "appauth"} {
		k := sensorkit.New(sensorkit.Options{SensorID: cfg.SensorID, Key: cfg.Key, CoreURL: cfg.CoreURL, Service: svc,
			Origin: "production", DataDir: cfg.DataDir})
		k.Start(ctx)
		defer k.Close()
		kits[svc] = k
	}
	var bad atomic.Int64
	for _, src := range strings.Split(sources, ",") {
		kind, path, ok := strings.Cut(strings.TrimSpace(src), ":")
		if !ok {
			slog.Error("bad LOG_SOURCES entry", "entry", src)
			continue
		}
		go tail(ctx, path, func(line string) {
			now := time.Now()
			var p logparse.Parsed
			var ok bool
			switch kind {
			case "fw":
				p, ok = logparse.Firewall(line, now)
			case "hostauth":
				p, ok = logparse.HostAuth(line, "real-target", now)
			case "appauth":
				p, ok = logparse.AppLogin(line, "real-app", salt, now)
			}
			if !ok {
				if n := bad.Add(1); n%100 == 1 {
					slog.Warn("unparseable lines", "count", n, "source", kind)
				}
				return
			}
			emit(kits[p.Service], cfg.SensorID, p)
		})
	}
	slog.Info("log collector running", "sources", sources)
	<-ctx.Done()
}

// emit wraps one parsed line in an envelope. External events use one pseudo-session per source IP per hour (02).
func emit(k *sensorkit.Kit, sensorID string, p logparse.Parsed) {
	sid := sensorID + ":" + p.SrcIP + ":" + p.TS.UTC().Format("2006010215")
	s := k.SessionWithID(sid, p.SrcIP, p.SrcPort, p.DstPort)
	s.Event(p.Type, "", p.Data, nil, nil)
}

// tail follows a file from its current end, reopening it when it is rotated or truncated.
func tail(ctx context.Context, path string, fn func(string)) {
	var f *os.File
	var r *bufio.Reader
	var offset int64
	open := func(fromEnd bool) bool {
		var err error
		if f, err = os.Open(path); err != nil {
			return false
		}
		if fromEnd {
			offset, _ = f.Seek(0, io.SeekEnd)
		} else {
			offset = 0
		}
		r = bufio.NewReader(f)
		return true
	}
	for f == nil {
		if open(true) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
	defer func() { f.Close() }()
	partial := ""
	for {
		line, err := r.ReadString('\n')
		if err == nil {
			offset += int64(len(line))
			fn(strings.TrimRight(partial+line, "\r\n"))
			partial = ""
			continue
		}
		partial += line
		offset += int64(len(line))
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
		if st, err := os.Stat(path); err == nil && st.Size() < offset { // truncated or rotated
			f.Close()
			if !open(false) {
				continue
			}
			partial = ""
		}
	}
}
