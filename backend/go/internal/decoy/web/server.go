package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"html/template"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const (
	defaultIdleTimeout  = 10 * time.Minute
	defaultSessionCap   = 30 * time.Minute
	defaultMaxRequests  = 500
	defaultMinLatencyMS = 30
	defaultMaxLatencyMS = 150
)

type ServerConfig struct {
	Kit          *sensorkit.Kit
	Persona      persona.Persona
	ListenAddr   string
	DstPort      int
	DataDir      string
	SeedDir      string
	TokenDB      string
	MinLatencyMS int
	MaxLatencyMS int
	IdleTimeout  time.Duration
	SessionCap   time.Duration
	MaxRequests  int
}

type webSession struct {
	id        string
	srcIP     string
	srcPort   int
	kitSess   *sensorkit.Session
	createdAt time.Time
	lastSeen  time.Time
	reqCount  int
}

type Server struct {
	cfg      ServerConfig
	backup   *BackupManager
	loginTmpl *template.Template
	listener net.Listener

	mu       sync.Mutex
	sessions map[string]*webSession

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

const loginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>{{.Company}} Internal Admin</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; }
    .card { position: relative; background: #1e293b; padding: 2rem; border-radius: 8px; width: 340px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); border: 1px solid #334155; }
    .star { position: absolute; top: 8px; right: 8px; font-size: 1.5rem; color: #ffdd00; }

    h2 { margin-top: 0; font-size: 1.25rem; color: #38bdf8; text-align: center; }
    .subtitle { font-size: 0.85rem; color: #94a3b8; text-align: center; margin-bottom: 1.5rem; }
    .error { background: #ef444420; border: 1px solid #ef4444; color: #fca5a5; padding: 0.5rem; border-radius: 4px; font-size: 0.85rem; margin-bottom: 1rem; }
    label { font-size: 0.8rem; color: #cbd5e1; display: block; margin-bottom: 0.25rem; }
    input[type="text"], input[type="password"] { width: 100%; box-sizing: border-box; padding: 0.5rem; border: 1px solid #475569; border-radius: 4px; background: #0f172a; color: #fff; margin-bottom: 1rem; }
    button { width: 100%; padding: 0.6rem; background: #0284c7; color: white; border: none; border-radius: 4px; font-weight: bold; cursor: pointer; }
    button:hover { background: #0369a1; }
    .footer { margin-top: 1.5rem; text-align: center; font-size: 0.75rem; color: #64748b; }
  </style>
</head>
<body>
  <div class="card">
    <h2>{{.Company}}</h2>
    <div class="subtitle">Internal Administration Portal</div>
    {{if .Error}}<div class="error">{{.Error}}</div>{{end}}
    <form method="POST" action="/login">
      <label for="username">Username</label>
      <input type="text" id="username" name="username" required autofocus autocomplete="username">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" required autocomplete="current-password">
      <button type="submit">Sign In</button>
    </form>
    <div class="footer">Authorized personnel only &bull; Host: {{.Hostname}}</div>
  </div>
  <div style="position:fixed;bottom:8px;right:8px;font-size:11px;color:#eab308;opacity:0.85;pointer-events:none;user-select:none;z-index:99999;" title="Decoy Honeypot Active">★</div>
</body>
</html>`

func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.SessionCap <= 0 {
		cfg.SessionCap = defaultSessionCap
	}
	if cfg.MaxRequests <= 0 {
		cfg.MaxRequests = defaultMaxRequests
	}
	if cfg.MinLatencyMS <= 0 && cfg.MaxLatencyMS <= 0 {
		cfg.MinLatencyMS = defaultMinLatencyMS
		cfg.MaxLatencyMS = defaultMaxLatencyMS
	}
	if cfg.TokenDB == "" {
		cfg.TokenDB = LoadDBTokenFromSeed(cfg.SeedDir)
		if cfg.TokenDB == "" {
			cfg.TokenDB = "db_pass_secret_2026"
		}
	}

	bm, err := NewBackupManager(cfg.SeedDir, cfg.Persona)
	if err != nil {
		return nil, fmt.Errorf("backup manager: %w", err)
	}

	tmpl, err := template.New("login").Parse(loginHTML)
	if err != nil {
		return nil, fmt.Errorf("parse login template: %w", err)
	}

	return &Server{
		cfg:       cfg,
		backup:    bm,
		loginTmpl: tmpl,
		sessions:  make(map[string]*webSession),
	}, nil
}

func LoadDBTokenFromSeed(seedDir string) string {
	candidates := []string{
		filepath.Join(seedDir, "out", "tokens.json"),
		filepath.Join(seedDir, "tokens.json"),
		filepath.Join("seed", "out", "tokens.json"),
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var tokens map[string]struct {
			TokenID    string `json:"token_id"`
			MatchValue string `json:"match_value"`
		}
		if err := json.Unmarshal(data, &tokens); err == nil {
			if tok, ok := tokens["tok_db"]; ok && tok.MatchValue != "" {
				return tok.MatchValue
			}
		}
	}
	return ""
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.simulateLatency()

	clientIP, clientPort := s.extractClient(r)

	// Check if IP is blocked by policy
	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(clientIP) {
		slog.Warn("refusing connection from blocked IP", "ip", clientIP)
		http.Error(w, "Forbidden: IP address blocked by security policy", http.StatusForbidden)
		return
	}

	sess := s.getOrCreateSession(r, clientIP, clientPort, w)
	if sess == nil {
		http.Error(w, "Too Many Requests: session limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Check if session has been killed by policy
	if s.cfg.Kit != nil && s.cfg.Kit.Killed(sess.id) {
		slog.Warn("refusing request from killed session", "session_id", sess.id)
		http.Error(w, "Forbidden: session terminated by security policy", http.StatusForbidden)
		return
	}

	// Dispatch route
	path := r.URL.Path
	switch {
	case path == "/" || path == "/login":
		if r.Method == http.MethodPost {
			s.handleLoginPost(w, r, sess)
		} else {
			s.handleLoginGet(w, r, sess)
		}
	case path == "/api/login":
		if r.Method == http.MethodPost {
			s.handleAPILogin(w, r, sess)
		} else {
			s.handleNotFound(w, r, sess)
		}
	case path == "/robots.txt":
		s.handleRobotsTxt(w, r, sess)
	case path == "/admin/backup":
		s.handleAdminBackupListing(w, r, sess)
	case path == "/admin/backup/internal-backup.zip":
		s.handleBackupZipDownload(w, r, sess)
	case path == "/admin/backup/schema-20261001.sql.gz":
		s.handleBackupSchemaDownload(w, r, sess)
	case path == "/admin/backup/system-migration.log":
		s.handleBackupMigrationLog(w, r, sess)
	case path == "/.env":
		s.handleDotEnv(w, r, sess, "/.env")
	case path == "/config.php.bak":
		s.handleDotEnv(w, r, sess, "/config.php.bak")
	case path == "/api/diagnostics":
		s.handleDiagnostics(w, r, sess)
	default:
		s.handleNotFound(w, r, sess)
	}
}

func (s *Server) simulateLatency() {
	if s.cfg.MaxLatencyMS <= 0 {
		return
	}
	delta := s.cfg.MaxLatencyMS - s.cfg.MinLatencyMS
	if delta <= 0 {
		time.Sleep(time.Duration(s.cfg.MinLatencyMS) * time.Millisecond)
		return
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	ms := s.cfg.MinLatencyMS + int(n.Int64())
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func (s *Server) extractClient(r *http.Request) (string, int) {
	host, portStr, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
		portStr = "0"
	}
	if host == "::1" || host == "" {
		host = "127.0.0.1"
	}
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return host, port
}

func (s *Server) getOrCreateSession(r *http.Request, clientIP string, clientPort int, w http.ResponseWriter) *webSession {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	sensorID := "web-01"
	if s.cfg.Kit != nil {
		sensorID = s.cfg.Kit.ID()
	}

	var sessID string
	var found *webSession

	// 1. Check for cookie "sid"
	if cookie, err := r.Cookie("sid"); err == nil && cookie.Value != "" {
		val := cookie.Value
		if strings.HasPrefix(val, sensorID+":") {
			if existing, ok := s.sessions[val]; ok {
				// Check session validity
				if now.Sub(existing.lastSeen) <= s.cfg.IdleTimeout && now.Sub(existing.createdAt) <= s.cfg.SessionCap {
					found = existing
					sessID = val
				}
			}
		}
	}

	// 2. If no valid session from cookie, fall back to ip+ua hash for rolling 30m window
	if found == nil {
		ua := r.UserAgent()
		windowIdx := now.Unix() / int64(s.cfg.SessionCap.Seconds())
		h := fnv.New64a()
		h.Write([]byte(fmt.Sprintf("%s:%s:%d", clientIP, ua, windowIdx)))
		sessID = fmt.Sprintf("%s:%016x", sensorID, h.Sum64())

		if existing, ok := s.sessions[sessID]; ok {
			if now.Sub(existing.lastSeen) <= s.cfg.IdleTimeout && now.Sub(existing.createdAt) <= s.cfg.SessionCap {
				found = existing
			}
		}
	}

	// 3. Create fresh session if not found
	if found == nil {
		if sessID == "" {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			sessID = fmt.Sprintf("%s:%s", sensorID, hex.EncodeToString(b))
		}

		var kitSess *sensorkit.Session
		if s.cfg.Kit != nil {
			kitSess = s.cfg.Kit.SessionWithID(sessID, clientIP, clientPort, s.cfg.DstPort)
			ua := r.UserAgent()
			kitSess.Client = &event.Client{UA: ua}
		}

		found = &webSession{
			id:        sessID,
			srcIP:     clientIP,
			srcPort:   clientPort,
			kitSess:   kitSess,
			createdAt: now,
			lastSeen:  now,
			reqCount:  0,
		}
		s.sessions[sessID] = found
	}

	// Check max requests
	if found.reqCount >= s.cfg.MaxRequests {
		return nil
	}

	found.lastSeen = now
	found.reqCount++

	// Set or refresh cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sid",
		Value:    found.id,
		Path:     "/",
		MaxAge:   int(s.cfg.SessionCap.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	return found
}

func (s *Server) emitHTTPRequest(sess *webSession, r *http.Request, status int, bodySample string) {
	if sess.kitSess == nil {
		return
	}
	queryMap := make(map[string]any)
	for k, v := range r.URL.Query() {
		if len(v) == 1 {
			queryMap[k] = v[0]
		} else {
			queryMap[k] = v
		}
	}

	sess.kitSess.Event("http.request", "web_entry", map[string]any{
		"method":      r.Method,
		"path":        r.URL.Path,
		"query":       queryMap,
		"body_sample": bodySample,
		"status":      status,
		"ua":          r.UserAgent(),
	}, nil, nil)
}

// ---------------- Route Handlers ----------------

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request, sess *webSession) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.loginTmpl.Execute(w, map[string]string{
		"Company":  s.cfg.Persona.Company,
		"Hostname": s.cfg.Persona.Hostname,
		"Error":    "",
	})
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request, sess *webSession) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Emit auth.attempt (method form, always fails as per 06 §2)
	if sess.kitSess != nil {
		sess.kitSess.Event("auth.attempt", "web_entry", map[string]any{
			"method":   "form",
			"username": username,
			"password": password,
			"key_fp":   "",
			"success":  false,
		}, nil, nil)
	}

	bodySample := fmt.Sprintf("username=%s&password=%s", username, strings.Repeat("*", len(password)))
	s.emitHTTPRequest(sess, r, http.StatusUnauthorized, bodySample)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = s.loginTmpl.Execute(w, map[string]string{
		"Company":  s.cfg.Persona.Company,
		"Hostname": s.cfg.Persona.Hostname,
		"Error":    "Invalid username or password",
	})
}

func (s *Server) handleAPILogin(w http.ResponseWriter, r *http.Request, sess *webSession) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
	var creds struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.Unmarshal(body, &creds)

	if sess.kitSess != nil {
		sess.kitSess.Event("auth.attempt", "web_entry", map[string]any{
			"method":   "form",
			"username": creds.Username,
			"password": creds.Password,
			"key_fp":   "",
			"success":  false,
		}, nil, nil)
	}

	s.emitHTTPRequest(sess, r, http.StatusUnauthorized, string(body))

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   "unauthorized",
		"message": "Invalid username or password",
	})
}

func (s *Server) handleRobotsTxt(w http.ResponseWriter, r *http.Request, sess *webSession) {
	content := "User-agent: *\nDisallow: /admin/backup\nDisallow: /api/diagnostics\n"
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleAdminBackupListing(w http.ResponseWriter, r *http.Request, sess *webSession) {
	html := `<!DOCTYPE html>
<html>
<head><title>Index of /admin/backup</title></head>
<body bgcolor="white">
<h1>Index of /admin/backup</h1><hr><pre><a href="../">../</a>
<a href="/admin/backup/internal-backup.zip">internal-backup.zip</a>     30-Oct-2026 14:22             2418
<a href="/admin/backup/schema-20261001.sql.gz">schema-20261001.sql.gz</a>  01-Oct-2026 03:00            84920
<a href="/admin/backup/system-migration.log">system-migration.log</a>    15-Oct-2026 09:15            12480
</pre><hr>
<div style="position:fixed;bottom:8px;right:8px;font-size:11px;color:#eab308;opacity:0.85;pointer-events:none;user-select:none;z-index:99999;" title="Decoy Honeypot Active">★</div>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleBackupZipDownload(w http.ResponseWriter, r *http.Request, sess *webSession) {
	data := s.backup.ZipData()

	if sess.kitSess != nil {
		sess.kitSess.Event("file.download", "lure_backup", map[string]any{
			"path":          "/admin/backup/internal-backup.zip",
			"honeyfile_id":  "tok_backup_key",
			"bytes":         len(data),
		}, nil, []string{"tok_backup_key"})
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="internal-backup.zip"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)

	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleBackupSchemaDownload(w http.ResponseWriter, r *http.Request, sess *webSession) {
	data := s.backup.SchemaData()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="schema-20261001.sql.gz"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleBackupMigrationLog(w http.ResponseWriter, r *http.Request, sess *webSession) {
	data := s.backup.MigrationLog()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleDotEnv(w http.ResponseWriter, r *http.Request, sess *webSession, path string) {
	var content string
	domain := s.cfg.Persona.Domain
	if domain == "" {
		domain = "internal"
	}

	if path == "/.env" {
		content = fmt.Sprintf(`APP_NAME=AdminPortal
APP_ENV=production
APP_KEY=base64:4vT9Q1Z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r=
APP_DEBUG=false
APP_URL=http://localhost:8080

DB_CONNECTION=pgsql
DB_HOST=db.%s
DB_PORT=5432
DB_DATABASE=orders
DB_USERNAME=app
DB_PASSWORD=%s
`, domain, s.cfg.TokenDB)
	} else {
		// config.php.bak
		content = fmt.Sprintf(`<?php
return [
    'db' => [
        'driver' => 'pgsql',
        'host' => 'db.%s',
        'port' => 5432,
        'database' => 'orders',
        'username' => 'app',
        'password' => '%s',
    ],
    'secret' => '4vT9Q1Z2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r',
];
`, domain, s.cfg.TokenDB)
	}

	if sess.kitSess != nil {
		sess.kitSess.Event("file.read", "lure_db", map[string]any{
			"path":         path,
			"honeyfile_id": "tok_db",
			"bytes":        len(content),
		}, nil, []string{"tok_db"})
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(content))
	s.emitHTTPRequest(sess, r, http.StatusOK, "")
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, r *http.Request, sess *webSession) {
	host := r.URL.Query().Get("host")
	if host == "" {
		// Go's url.ParseQuery may reject unescaped semicolons or ampersands in RawQuery.
		// Extract raw host parameter directly from RawQuery if present.
		raw := r.URL.RawQuery
		if idx := strings.Index(raw, "host="); idx != -1 {
			val := raw[idx+5:]
			if ampIdx := strings.Index(val, "&"); ampIdx != -1 {
				val = val[:ampIdx]
			}
			if unescaped, err := url.QueryUnescape(val); err == nil {
				host = unescaped
			} else {
				host = val
			}
		}
	}
	if host == "" && r.Method == http.MethodPost {
		host = r.FormValue("host")
	}

	check := CheckInput(host)

	if check.IsSuspicious && sess.kitSess != nil {
		sess.kitSess.Event("input.suspicious", "web_entry", map[string]any{
			"param":     "host",
			"value":     host,
			"separator": check.Separator,
			"payload":   check.Payload,
			"path":      "/api/diagnostics",
		}, nil, nil)
	}

	output := EmulateDiagnosticsOutput(host, check, s.cfg.Persona)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(output))

	s.emitHTTPRequest(sess, r, http.StatusOK, fmt.Sprintf("host=%s", host))
}

func (s *Server) handleNotFound(w http.ResponseWriter, r *http.Request, sess *webSession) {
	html := `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.18.0 (Ubuntu)</center>
</body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(html))
	s.emitHTTPRequest(sess, r, http.StatusNotFound, "")
}

// ListenAndServe runs the HTTP server.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln
	slog.Info("web decoy listening", "addr", ln.Addr())

	httpServer := &http.Server{
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-s.ctx.Done()
		_ = httpServer.Shutdown(context.Background())
		_ = ln.Close()
	}()

	err = httpServer.Serve(ln)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
