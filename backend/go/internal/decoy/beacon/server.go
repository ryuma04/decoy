// Package beacon implements the HTTP beacon decoy server (06 §4).
// Emulates an AWS S3 endpoint returning AccessDenied on lure SigV4 credentials,
// and serves 1x1 transparent GIFs for lure tracking URLs.
// Never calls real AWS or executes commands.
package beacon

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// Standard 43-byte 1x1 transparent GIF (06 §4).
var gif1x1 = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00,
	0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00,
	0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
	0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

// Token matches the honeytoken schema from seed/out/tokens.json.
type Token struct {
	TokenID     string `json:"token_id"`
	Kind        string `json:"kind"`
	PlantedAt   string `json:"planted_at"`
	MazeNode    string `json:"maze_node"`
	MatchValue  string `json:"match_value"`
	Sensitivity int    `json:"sensitivity"`
}

// LoadTokensFromSeed loads tokens from seed/out/tokens.json or candidate paths.
func LoadTokensFromSeed(seedDir string) (map[string]Token, error) {
	candidatePaths := []string{
		filepath.Join(seedDir, "out", "tokens.json"),
		filepath.Join(seedDir, "tokens.json"),
		filepath.Join("seed", "out", "tokens.json"),
		filepath.Join("..", "seed", "out", "tokens.json"),
		filepath.Join("..", "..", "seed", "out", "tokens.json"),
	}

	var data []byte
	var err error
	for _, p := range candidatePaths {
		if data, err = os.ReadFile(p); err == nil {
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read tokens.json: %w", err)
	}

	var tokens map[string]Token
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("unmarshal tokens.json: %w", err)
	}
	return tokens, nil
}

// Config configures the beacon decoy HTTP server.
type Config struct {
	Addr    string
	Kit     *sensorkit.Kit
	Tokens  map[string]Token
	SeedDir string
}

// Server is the beacon HTTP server.
type Server struct {
	cfg    Config
	tokens map[string]Token
	mu     sync.RWMutex
	server *http.Server
}

// New creates a new beacon decoy Server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":8088"
	}
	toks := cfg.Tokens
	if toks == nil {
		var err error
		toks, err = LoadTokensFromSeed(cfg.SeedDir)
		if err != nil {
			slog.Debug("beacon: no tokens loaded from seed", "err", err)
			toks = map[string]Token{}
		}
	}

	s := &Server{
		cfg:    cfg,
		tokens: toks,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/", s.handleRequest)

	s.server = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	return s, nil
}

// SetTokens updates the in-memory honeytoken map.
func (s *Server) SetTokens(toks map[string]Token) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens = toks
}

// Handler returns the HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// ListenAndServe runs the HTTP server.
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}

// Serve serves connections from an existing listener.
func (s *Server) Serve(l net.Listener) error {
	return s.server.Serve(l)
}

// Shutdown gracefully shuts down the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request) {
	srcIP, srcPort := parseRemoteAddr(r.RemoteAddr)
	dstPort := parseDstPort(r.Host, s.cfg.Addr)

	// Check blocked IP policy
	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(srcIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var sess *sensorkit.Session
	if s.cfg.Kit != nil {
		sess = s.cfg.Kit.NewSession(srcIP, srcPort, dstPort)
		if ua := r.UserAgent(); ua != "" {
			sess.Client = &event.Client{UA: ua}
		}
	}

	// URL token check: GET /t/{token_id}
	if strings.HasPrefix(r.URL.Path, "/t/") {
		s.handleURLToken(w, r, sess)
		return
	}

	// AWS-style endpoint check (SigV4 authorization or generic S3 request)
	s.handleAWSEndpoint(w, r, sess)
}

func (s *Server) handleURLToken(w http.ResponseWriter, r *http.Request, sess *sensorkit.Session) {
	tokenID := strings.TrimPrefix(r.URL.Path, "/t/")
	qMap := parseQueryMap(r)

	s.mu.RLock()
	tok, found := s.findURLToken(tokenID, r.URL.Path)
	s.mu.RUnlock()

	if !found {
		if sess != nil {
			sess.Event("http.request", "", map[string]any{
				"method": r.Method,
				"path":   r.URL.Path,
				"query":  qMap,
				"status": http.StatusNotFound,
				"ua":     r.UserAgent(),
			}, nil, nil)
		}
		http.NotFound(w, r)
		return
	}

	// Found URL token!
	if sess != nil {
		sess.Event("http.request", tok.MazeNode, map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  qMap,
			"status": http.StatusOK,
			"ua":     r.UserAgent(),
		}, nil, nil)

		sess.Event("token.used", tok.MazeNode, map[string]any{
			"token_id":   tok.TokenID,
			"token_kind": "url",
			"via":        "url_fetch",
		}, nil, []string{tok.TokenID})
	}

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Content-Length", strconv.Itoa(len(gif1x1)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(gif1x1)
	}
}

func (s *Server) handleAWSEndpoint(w http.ResponseWriter, r *http.Request, sess *sensorkit.Session) {
	accessKey := extractAWSAccessKey(r)
	qMap := parseQueryMap(r)

	s.mu.RLock()
	tok, found := s.findAWSKey(accessKey)
	s.mu.RUnlock()

	reqID := randomHex(8)
	hostID := randomHex(16) + "="

	if found {
		// Lure AWS key used!
		if sess != nil {
			sess.Event("http.request", tok.MazeNode, map[string]any{
				"method": r.Method,
				"path":   r.URL.Path,
				"query":  qMap,
				"status": http.StatusForbidden,
				"ua":     r.UserAgent(),
			}, nil, nil)

			sess.Event("token.used", tok.MazeNode, map[string]any{
				"token_id":   tok.TokenID,
				"token_kind": "aws_key",
				"via":        "aws_api",
			}, nil, []string{tok.TokenID})
		}
	} else if sess != nil {
		sess.Event("http.request", "", map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  qMap,
			"status": http.StatusForbidden,
			"ua":     r.UserAgent(),
		}, nil, nil)
	}

	// Always reply with AWS-style AccessDenied XML (06 §4)
	w.Header().Set("Content-Type", "application/xml")
	w.Header().Set("x-amz-request-id", reqID)
	w.Header().Set("x-amz-id-2", hostID)
	w.WriteHeader(http.StatusForbidden)

	xmlBody := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<Error>
  <Code>AccessDenied</Code>
  <Message>Access Denied</Message>
  <RequestId>%s</RequestId>
  <HostId>%s</HostId>
</Error>`, reqID, hostID)
	_, _ = w.Write([]byte(xmlBody))
}

func (s *Server) findURLToken(tokenID, fullPath string) (Token, bool) {
	for _, t := range s.tokens {
		if t.Kind == "url" {
			if t.TokenID == tokenID || t.MatchValue == fullPath || strings.TrimPrefix(t.MatchValue, "/t/") == tokenID {
				return t, true
			}
		}
	}
	return Token{}, false
}

func (s *Server) findAWSKey(accessKey string) (Token, bool) {
	if accessKey == "" {
		return Token{}, false
	}
	for _, t := range s.tokens {
		if t.Kind == "aws_key" && t.MatchValue == accessKey {
			return t, true
		}
	}
	return Token{}, false
}

func extractAWSAccessKey(r *http.Request) string {
	// 1. Check Authorization header: AWS4-HMAC-SHA256 Credential=AKIA.../date/region/s3/aws4_request
	auth := r.Header.Get("Authorization")
	if auth != "" {
		if idx := strings.Index(auth, "Credential="); idx != -1 {
			cred := auth[idx+len("Credential="):]
			if slashIdx := strings.Index(cred, "/"); slashIdx != -1 {
				return cred[:slashIdx]
			}
			if end := strings.IndexAny(cred, ", "); end != -1 {
				return cred[:end]
			}
			return cred
		}
	}

	// 2. Check query param: X-Amz-Credential=AKIA.../date/region/s3/aws4_request
	qCred := r.URL.Query().Get("X-Amz-Credential")
	if qCred != "" {
		if slashIdx := strings.Index(qCred, "/"); slashIdx != -1 {
			return qCred[:slashIdx]
		}
		return qCred
	}

	return ""
}

func parseRemoteAddr(remoteAddr string) (string, int) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0
	}
	if host == "::1" {
		host = "127.0.0.1"
	}
	if parsed := net.ParseIP(host); parsed != nil {
		if ip4 := parsed.To4(); ip4 != nil {
			host = ip4.String()
		}
	}
	port, _ := strconv.Atoi(portStr)
	return host, port
}

func parseDstPort(hostHeader, fallbackAddr string) int {
	if hostHeader != "" {
		if _, portStr, err := net.SplitHostPort(hostHeader); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				return p
			}
		}
	}
	if fallbackAddr != "" {
		if _, portStr, err := net.SplitHostPort(fallbackAddr); err == nil {
			if p, err := strconv.Atoi(portStr); err == nil {
				return p
			}
		}
	}
	return 8088
}

func parseQueryMap(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			out[k] = v[0]
		}
	}
	return out
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return strings.ToUpper(hex.EncodeToString(b))
}
