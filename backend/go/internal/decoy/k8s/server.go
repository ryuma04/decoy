// Package k8s implements the Kubernetes API decoy server (06 §3).
// Emulates a Kubernetes API server over self-signed TLS on port 6443.
// Returns 401 Unauthorized without the lure bearer token (tok_kube),
// discovery/namespaces/pods/secrets/nodes when authenticated, and 403 Forbidden on writes.
// Never calls real Kubernetes or executes commands.
package k8s

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

// Token matches the honeytoken schema from seed/out/tokens.json.
type Token struct {
	TokenID     string `json:"token_id"`
	Kind        string `json:"kind"`
	PlantedAt   string `json:"planted_at"`
	MazeNode    string `json:"maze_node"`
	MatchValue  string `json:"match_value"`
	Sensitivity int    `json:"sensitivity"`
}

// LoadTokensFromSeed loads honeytokens from seed/out/tokens.json or candidate paths.
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

// GenerateSelfSignedCert generates a valid self-signed TLS certificate for the K8s API decoy.
func GenerateSelfSignedCert(domain string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "kubernetes",
			Organization: []string{"system:masters"},
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,

		DNSNames: []string{
			"kubernetes",
			"kubernetes.default",
			"kubernetes.default.svc",
			"kubernetes.default.svc.cluster.local",
			"localhost",
			"k8s." + domain,
			domain,
		},
		IPAddresses: []net.IP{
			net.ParseIP("127.0.0.1"),
			net.ParseIP("10.66.0.1"),
			net.ParseIP("10.96.0.1"),
		},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

// Config configures the Kubernetes API decoy server.
type Config struct {
	Addr       string
	Kit        *sensorkit.Kit
	Persona    persona.Persona
	Tokens     map[string]Token
	SeedDir    string
	TLSConfig  *tls.Config
}

type sessionEntry struct {
	sess     *sensorkit.Session
	lastSeen time.Time
}

// Server is the Kubernetes API decoy HTTP server.
type Server struct {
	cfg        Config
	tokens     map[string]Token
	persona    persona.Persona
	mu         sync.RWMutex
	sessions   map[string]*sessionEntry
	sessionsMu sync.Mutex
	server     *http.Server
}

// New creates a new Kubernetes API decoy Server.
func New(cfg Config) (*Server, error) {
	if cfg.Addr == "" {
		cfg.Addr = ":6443"
	}
	toks := cfg.Tokens
	if toks == nil {
		var err error
		toks, err = LoadTokensFromSeed(cfg.SeedDir)
		if err != nil {
			slog.Debug("k8s: no tokens loaded from seed", "err", err)
			toks = map[string]Token{}
		}
	}
	p := cfg.Persona
	if p.Hostname == "" {
		p = persona.Generate("dsoc-default")
	}

	s := &Server{
		cfg:      cfg,
		tokens:   toks,
		persona:  p,
		sessions: make(map[string]*sessionEntry),
	}

	tlsConfig := cfg.TLSConfig
	if tlsConfig == nil {
		cert, err := GenerateSelfSignedCert(p.Domain)
		if err != nil {
			return nil, fmt.Errorf("generate self-signed cert: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/livez", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleHealthz)
	mux.HandleFunc("/version", s.handleVersion)
	mux.HandleFunc("/", s.handleAPI)

	s.server = &http.Server{
		Addr:              cfg.Addr,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
	}

	return s, nil
}

// Handler returns the HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.server.Handler
}

// ListenAndServeTLS starts the TLS server.
func (s *Server) ListenAndServeTLS() error {
	return s.server.ListenAndServeTLS("", "")
}

// ServeTLS serves TLS connections from a net.Listener.
func (s *Server) ServeTLS(l net.Listener) error {
	return s.server.Serve(tls.NewListener(l, s.server.TLSConfig))
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}

// getOrCreateSession returns a sensorkit Session with 30-minute idle TTL (02 §session).
func (s *Server) getOrCreateSession(srcIP string, srcPort, dstPort int, token string, ua string) *sensorkit.Session {
	if s.cfg.Kit == nil {
		return nil
	}

	key := fmt.Sprintf("%s:%s", srcIP, token)
	now := time.Now()

	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if entry, ok := s.sessions[key]; ok {
		if now.Sub(entry.lastSeen) < 30*time.Minute {
			entry.lastSeen = now
			return entry.sess
		}
	}

	sess := s.cfg.Kit.NewSession(srcIP, srcPort, dstPort)
	if ua != "" {
		sess.Client = &event.Client{UA: ua}
	}
	s.sessions[key] = &sessionEntry{sess: sess, lastSeen: now}
	return sess
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	// GET /healthz, /livez, /readyz: 200 without auth (as real API servers do, 06 §3)
	srcIP, srcPort := parseRemoteAddr(r.RemoteAddr)
	dstPort := parseDstPort(r.Host, s.cfg.Addr)

	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(srcIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sess := s.getOrCreateSession(srcIP, srcPort, dstPort, "", r.UserAgent())
	if sess != nil {
		sess.Event("k8s.api_call", "", map[string]any{
			"verb":          "get",
			"resource":      strings.TrimPrefix(r.URL.Path, "/"),
			"namespace":     "",
			"name":          "",
			"authenticated": false,
		}, nil, nil)
		sess.Event("http.request", "", map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  parseQueryMap(r),
			"status": http.StatusOK,
			"ua":     r.UserAgent(),
		}, nil, nil)
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	// GET /version: 200 without auth (as real API servers do, 06 §3)
	srcIP, srcPort := parseRemoteAddr(r.RemoteAddr)
	dstPort := parseDstPort(r.Host, s.cfg.Addr)

	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(srcIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sess := s.getOrCreateSession(srcIP, srcPort, dstPort, "", r.UserAgent())
	if sess != nil {
		sess.Event("k8s.api_call", "", map[string]any{
			"verb":          "get",
			"resource":      "version",
			"namespace":     "",
			"name":          "",
			"authenticated": false,
		}, nil, nil)
		sess.Event("http.request", "", map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  parseQueryMap(r),
			"status": http.StatusOK,
			"ua":     r.UserAgent(),
		}, nil, nil)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(versionResponse())
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	srcIP, srcPort := parseRemoteAddr(r.RemoteAddr)
	dstPort := parseDstPort(r.Host, s.cfg.Addr)

	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(srcIP) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	bearerToken := ""
	if strings.HasPrefix(authHeader, "Bearer ") {
		bearerToken = strings.TrimPrefix(authHeader, "Bearer ")
	}

	sess := s.getOrCreateSession(srcIP, srcPort, dstPort, bearerToken, r.UserAgent())

	// Validate lure bearer token
	s.mu.RLock()
	lureToken, isValidToken := s.matchLureToken(bearerToken)
	s.mu.RUnlock()

	// Parse K8s API request target (verb, resource, namespace, name)
	reqInfo := parseK8sRequest(r)

	// Emit auth.attempt
	if authHeader != "" {
		username := ""
		if isValidToken {
			username = "deploy-reader"
		}
		if sess != nil {
			sess.Event("auth.attempt", lureToken.MazeNode, map[string]any{
				"username": username,
				"method":   "bearer",
				"success":  isValidToken,
			}, nil, nil)
		}
	}

	// Unauthenticated request -> 401 Unauthorized (06 §3)
	if !isValidToken {
		if authHeader == "" && sess != nil {
			sess.Event("auth.attempt", "", map[string]any{
				"username": "",
				"method":   "bearer",
				"success":  false,
			}, nil, nil)
		}
		if sess != nil {
			sess.Event("k8s.api_call", "", map[string]any{
				"verb":          reqInfo.Verb,
				"resource":      reqInfo.Resource,
				"namespace":     reqInfo.Namespace,
				"name":          reqInfo.Name,
				"authenticated": false,
			}, nil, nil)
			sess.Event("http.request", "", map[string]any{
				"method": r.Method,
				"path":   r.URL.Path,
				"query":  parseQueryMap(r),
				"status": http.StatusUnauthorized,
				"ua":     r.UserAgent(),
			}, nil, nil)
		}

		w.Header().Set("WWW-Authenticate", "Bearer")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(unauthorizedResponse())
		return
	}

	// Authenticated request with lure token!
	if sess != nil {
		sess.Event("token.used", lureToken.MazeNode, map[string]any{
			"token_id":   lureToken.TokenID,
			"token_kind": "kubeconfig",
			"via":        "k8s_bearer",
		}, nil, []string{lureToken.TokenID})

		sess.Event("k8s.api_call", lureToken.MazeNode, map[string]any{
			"verb":          reqInfo.Verb,
			"resource":      reqInfo.Resource,
			"namespace":     reqInfo.Namespace,
			"name":          reqInfo.Name,
			"authenticated": true,
		}, nil, nil)
	}

	// Writes (POST, PUT, PATCH, DELETE) -> 403 Forbidden ("deploy-reader" RBAC, 06 §3)
	if r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete {
		if sess != nil {
			sess.Event("http.request", lureToken.MazeNode, map[string]any{
				"method": r.Method,
				"path":   r.URL.Path,
				"query":  parseQueryMap(r),
				"status": http.StatusForbidden,
				"ua":     r.UserAgent(),
			}, nil, nil)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(forbiddenResponse(reqInfo.Verb, reqInfo.Resource, reqInfo.Namespace))
		return
	}

	// GET discovery and read endpoints
	s.handleAuthenticatedRead(w, r, sess, reqInfo, lureToken)
}

func (s *Server) handleAuthenticatedRead(w http.ResponseWriter, r *http.Request, sess *sensorkit.Session, reqInfo k8sRequestInfo, lureToken Token) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	w.Header().Set("Content-Type", "application/json")

	var responseObj any
	status := http.StatusOK

	switch {
	case path == "/api":
		responseObj = apiVersionsResponse()

	case path == "/apis":
		responseObj = apiGroupListResponse()

	case path == "/api/v1":
		responseObj = apiV1ResourceListResponse()

	case path == "/api/v1/namespaces":
		responseObj = namespacesResponse()

	case strings.HasPrefix(path, "/api/v1/namespaces/") && reqInfo.Resource == "namespaces" && reqInfo.Name != "":
		responseObj = namespaceObject(reqInfo.Name)

	case reqInfo.Resource == "pods":
		if reqInfo.Name != "" {
			pod := findPod(reqInfo.Namespace, reqInfo.Name, s.persona)
			if pod == nil {
				status = http.StatusNotFound
				responseObj = notFoundStatus("Pod", reqInfo.Name)
			} else {
				responseObj = pod
			}
		} else {
			responseObj = podsListResponse(reqInfo.Namespace, s.persona)
		}

	case reqInfo.Resource == "secrets":
		// Query maze view for visible secrets
		visibleSecrets := s.getMazeSecrets(sess)
		dbPass := s.getDBPassword()

		if reqInfo.Name != "" {
			sec := findSecret(reqInfo.Namespace, reqInfo.Name, s.persona, visibleSecrets, dbPass)
			if sec == nil {
				status = http.StatusNotFound
				responseObj = notFoundStatus("Secret", reqInfo.Name)
			} else {
				responseObj = sec
			}
		} else {
			responseObj = secretsListResponse(reqInfo.Namespace, s.persona, visibleSecrets, dbPass)
		}

	case reqInfo.Resource == "nodes":
		if reqInfo.Name != "" {
			node := findNode(reqInfo.Name, s.persona)
			if node == nil {
				status = http.StatusNotFound
				responseObj = notFoundStatus("Node", reqInfo.Name)
			} else {
				responseObj = node
			}
		} else {
			responseObj = nodesListResponse(s.persona)
		}

	default:
		// Generic empty list for other resources (e.g. deployments, services)
		responseObj = emptyListResponse(reqInfo.Resource)
	}

	if sess != nil {
		sess.Event("http.request", lureToken.MazeNode, map[string]any{
			"method": r.Method,
			"path":   r.URL.Path,
			"query":  parseQueryMap(r),
			"status": status,
			"ua":     r.UserAgent(),
		}, nil, nil)
	}

	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(responseObj)
}

func (s *Server) matchLureToken(bearer string) (Token, bool) {
	if bearer == "" {
		return Token{}, false
	}
	// Check tok_kube explicitly or any kubeconfig token
	for _, t := range s.tokens {
		if t.Kind == "kubeconfig" && t.MatchValue == bearer {
			return t, true
		}
	}
	// Also check by token_id "tok_kube"
	if tok, ok := s.tokens["tok_kube"]; ok && tok.MatchValue == bearer {
		return tok, true
	}
	return Token{}, false
}

func (s *Server) getDBPassword() string {
	if tok, ok := s.tokens["tok_db"]; ok && tok.MatchValue != "" {
		return tok.MatchValue
	}
	return "s3cr3tDBp@ss"
}

func (s *Server) getMazeSecrets(sess *sensorkit.Session) map[string]bool {
	visible := map[string]bool{}
	if sess == nil || s.cfg.Kit == nil {
		return visible
	}

	var mv struct {
		K8sSecrets   []string `json:"k8s_secrets"`
		VisibleNodes []string `json:"visible_nodes"`
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if err := s.cfg.Kit.MazeView(ctx, sess.ID, &mv); err == nil {
		for _, sec := range mv.K8sSecrets {
			visible[sec] = true
		}
	}
	return visible
}

type k8sRequestInfo struct {
	Verb      string
	Resource  string
	Namespace string
	Name      string
}

func parseK8sRequest(r *http.Request) k8sRequestInfo {
	info := k8sRequestInfo{}

	// Determine verb
	if r.URL.Query().Get("watch") == "true" {
		info.Verb = "watch"
	} else {
		switch r.Method {
		case http.MethodGet:
			info.Verb = "get"
		case http.MethodPost:
			info.Verb = "create"
		case http.MethodPut, http.MethodPatch:
			info.Verb = "patch"
		case http.MethodDelete:
			info.Verb = "delete"
		default:
			info.Verb = strings.ToLower(r.Method)
		}
	}

	p := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(p, "/")

	// /api/v1/namespaces/{ns}/pods/{name}
	// /api/v1/namespaces/{ns}/secrets
	// /api/v1/nodes/{name}
	// /api/v1/pods
	// /api/v1/namespaces
	for i := 0; i < len(parts); i++ {
		if parts[i] == "namespaces" {
			if i+1 < len(parts) {
				info.Namespace = parts[i+1]
				if i+2 < len(parts) {
					info.Resource = parts[i+2]
					if i+3 < len(parts) {
						info.Name = parts[i+3]
					}
					break
				} else {
					info.Resource = "namespaces"
					info.Name = parts[i+1]
					break
				}
			} else {
				info.Resource = "namespaces"
				break
			}
		}
	}

	if info.Resource == "" {
		if len(parts) >= 3 && (parts[0] == "api" || parts[0] == "apis") {
			info.Resource = parts[len(parts)-1]
			if len(parts) >= 4 && parts[len(parts)-2] != "v1" {
				info.Resource = parts[len(parts)-2]
				info.Name = parts[len(parts)-1]
			}
		} else if len(parts) > 0 {
			info.Resource = parts[len(parts)-1]
		}
	}

	// Refine verb to "list" when accessing a collection
	if r.Method == http.MethodGet && info.Name == "" && info.Verb == "get" {
		if info.Resource == "pods" || info.Resource == "secrets" || info.Resource == "namespaces" || info.Resource == "nodes" {
			info.Verb = "list"
		}
	}

	return info
}

// K8s API JSON Model Builders (06 §3).

func versionResponse() map[string]any {
	return map[string]any{
		"major":        "1",
		"minor":        "30",
		"gitVersion":   "v1.30.2",
		"gitCommit":    "39683505b630ff2121012f3c7b461846c143db9a",
		"gitTreeState": "clean",
		"buildDate":    "2024-06-11T20:20:41Z",
		"goVersion":    "go1.22.4",
		"compiler":     "gc",
		"platform":     "linux/amd64",
	}
}

func apiVersionsResponse() map[string]any {
	return map[string]any{
		"kind":     "APIVersions",
		"versions": []string{"v1"},
		"serverAddressByClientCIDRs": []map[string]string{
			{"clientCIDR": "0.0.0.0/0", "serverAddress": "10.66.0.1:6443"},
		},
	}
}

func apiGroupListResponse() map[string]any {
	return map[string]any{
		"kind":       "APIGroupList",
		"apiVersion": "v1",
		"groups": []map[string]any{
			{
				"name": "apps",
				"versions": []map[string]string{
					{"groupVersion": "apps/v1", "version": "v1"},
				},
				"preferredVersion": map[string]string{
					"groupVersion": "apps/v1",
					"version":      "v1",
				},
			},
		},
	}
}

func apiV1ResourceListResponse() map[string]any {
	return map[string]any{
		"kind":         "APIResourceList",
		"apiVersion":   "v1",
		"groupVersion": "v1",
		"resources": []map[string]any{
			{"name": "namespaces", "singularName": "namespace", "namespaced": false, "kind": "Namespace", "verbs": []string{"get", "list", "watch"}},
			{"name": "pods", "singularName": "pod", "namespaced": true, "kind": "Pod", "verbs": []string{"get", "list", "watch"}},
			{"name": "secrets", "singularName": "secret", "namespaced": true, "kind": "Secret", "verbs": []string{"get", "list", "watch"}},
			{"name": "nodes", "singularName": "node", "namespaced": false, "kind": "Node", "verbs": []string{"get", "list", "watch"}},
		},
	}
}

func namespacesResponse() map[string]any {
	return map[string]any{
		"kind":       "NamespaceList",
		"apiVersion": "v1",
		"metadata":   map[string]any{"resourceVersion": "1000"},
		"items": []map[string]any{
			{"metadata": map[string]any{"name": "default", "creationTimestamp": "2026-01-01T00:00:00Z"}, "status": map[string]any{"phase": "Active"}},
			{"metadata": map[string]any{"name": "kube-system", "creationTimestamp": "2026-01-01T00:00:00Z"}, "status": map[string]any{"phase": "Active"}},
			{"metadata": map[string]any{"name": "ci", "creationTimestamp": "2026-01-01T00:00:00Z"}, "status": map[string]any{"phase": "Active"}},
			{"metadata": map[string]any{"name": "payments", "creationTimestamp": "2026-01-01T00:00:00Z"}, "status": map[string]any{"phase": "Active"}},
		},
	}
}

func namespaceObject(name string) map[string]any {
	return map[string]any{
		"kind":       "Namespace",
		"apiVersion": "v1",
		"metadata": map[string]any{
			"name":              name,
			"creationTimestamp": "2026-01-01T00:00:00Z",
		},
		"status": map[string]any{"phase": "Active"},
	}
}

func buildPersonaPods(p persona.Persona) []map[string]any {
	prefix := p.HostPrefix
	if prefix == "" {
		prefix = "nwl"
	}

	return []map[string]any{
		// default namespace pods
		makePod(prefix+"-frontend-7f9b8c-x4y2z", "default", "10.244.1.10", "node-01"),
		makePod(prefix+"-api-5c8d7e-9a1b2", "default", "10.244.1.11", "node-01"),
		makePod(prefix+"-worker-6b9f1a-k3m4n", "default", "10.244.2.15", "node-02"),
		// ci namespace pods
		makePod("jenkins-agent-0", "ci", "10.244.2.20", "node-02"),
		// payments namespace pods
		makePod(prefix+"-payment-service-7d8f9a-1c2b3", "payments", "10.244.1.12", "node-01"),
		// kube-system pods
		makePod("coredns-6f5b9c-7x8y9", "kube-system", "10.244.0.5", "control-plane-01"),
		makePod("kube-proxy-8k9l0", "kube-system", "10.244.0.6", "control-plane-01"),
	}
}

func makePod(name, namespace, podIP, nodeName string) map[string]any {
	return map[string]any{
		"kind":       "Pod",
		"apiVersion": "v1",
		"metadata": map[string]any{
			"name":              name,
			"namespace":         namespace,
			"creationTimestamp": "2026-01-01T00:00:00Z",
			"labels": map[string]string{
				"app": name,
			},
		},
		"spec": map[string]any{
			"nodeName": nodeName,
			"containers": []map[string]any{
				{
					"name":  "app",
					"image": "registry.internal/app:v1.2.0",
				},
			},
		},
		"status": map[string]any{
			"phase":  "Running",
			"podIP":  podIP,
			"hostIP": "10.66.0.10",
			"containerStatuses": []map[string]any{
				{
					"name":  "app",
					"ready": true,
					"state": map[string]any{
						"running": map[string]string{"startedAt": "2026-01-01T00:00:00Z"},
					},
				},
			},
		},
	}
}

func podsListResponse(ns string, p persona.Persona) map[string]any {
	allPods := buildPersonaPods(p)
	var items []map[string]any
	for _, pod := range allPods {
		meta := pod["metadata"].(map[string]any)
		if ns == "" || meta["namespace"] == ns {
			items = append(items, pod)
		}
	}
	return map[string]any{
		"kind":       "PodList",
		"apiVersion": "v1",
		"metadata":   map[string]any{"resourceVersion": "1000"},
		"items":      items,
	}
}

func findPod(ns, name string, p persona.Persona) map[string]any {
	for _, pod := range buildPersonaPods(p) {
		meta := pod["metadata"].(map[string]any)
		if (ns == "" || meta["namespace"] == ns) && meta["name"] == name {
			return pod
		}
	}
	return nil
}

func buildPersonaSecrets(p persona.Persona, visibleSecrets map[string]bool, dbPass string) []map[string]any {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

	secrets := []map[string]any{
		makeSecret("default-token-a1b2c", "default", "kubernetes.io/service-account-token", map[string]string{
			"token": b64("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9..."),
		}),
		makeSecret("default-token-d3e4f", "ci", "kubernetes.io/service-account-token", map[string]string{
			"token": b64("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9..."),
		}),
		makeSecret("default-token-g5h6i", "payments", "kubernetes.io/service-account-token", map[string]string{
			"token": b64("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9..."),
		}),
		makeSecret("coredns-token-j7k8l", "kube-system", "kubernetes.io/service-account-token", map[string]string{
			"token": b64("eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9..."),
		}),
	}

	// Secret "ci-jenkins-token" only when maze-visible (06 §3)
	if visibleSecrets["ci-jenkins-token"] {
		secrets = append(secrets, makeSecret("ci-jenkins-token", "ci", "Opaque", map[string]string{
			"token": b64("jenkins-api-token-nwl-2026!"),
		}))
	}

	// Secret "db-credentials" only when maze-visible (06 §3)
	if visibleSecrets["db-credentials"] {
		secrets = append(secrets, makeSecret("db-credentials", "default", "Opaque", map[string]string{
			"username": b64("app"),
			"password": b64(dbPass),
			"host":     b64("db." + p.Domain),
		}))
	}

	return secrets
}

func makeSecret(name, namespace, secType string, data map[string]string) map[string]any {
	return map[string]any{
		"kind":       "Secret",
		"apiVersion": "v1",
		"metadata": map[string]any{
			"name":              name,
			"namespace":         namespace,
			"creationTimestamp": "2026-01-01T00:00:00Z",
		},
		"type": secType,
		"data": data,
	}
}

func secretsListResponse(ns string, p persona.Persona, visibleSecrets map[string]bool, dbPass string) map[string]any {
	allSecrets := buildPersonaSecrets(p, visibleSecrets, dbPass)
	var items []map[string]any
	for _, sec := range allSecrets {
		meta := sec["metadata"].(map[string]any)
		if ns == "" || meta["namespace"] == ns {
			items = append(items, sec)
		}
	}
	return map[string]any{
		"kind":       "SecretList",
		"apiVersion": "v1",
		"metadata":   map[string]any{"resourceVersion": "1000"},
		"items":      items,
	}
}

func findSecret(ns, name string, p persona.Persona, visibleSecrets map[string]bool, dbPass string) map[string]any {
	for _, sec := range buildPersonaSecrets(p, visibleSecrets, dbPass) {
		meta := sec["metadata"].(map[string]any)
		if (ns == "" || meta["namespace"] == ns) && meta["name"] == name {
			return sec
		}
	}
	return nil
}

func nodesListResponse(p persona.Persona) map[string]any {
	prefix := p.HostPrefix
	if prefix == "" {
		prefix = "nwl"
	}

	nodes := []map[string]any{
		makeNode(prefix+"-control-plane-01", "10.66.0.10", true),
		makeNode(prefix+"-worker-01", "10.66.0.11", false),
		makeNode(prefix+"-worker-02", "10.66.0.12", false),
	}

	return map[string]any{
		"kind":       "NodeList",
		"apiVersion": "v1",
		"metadata":   map[string]any{"resourceVersion": "1000"},
		"items":      nodes,
	}
}

func findNode(name string, p persona.Persona) map[string]any {
	nodesList := nodesListResponse(p)
	for _, n := range nodesList["items"].([]map[string]any) {
		meta := n["metadata"].(map[string]any)
		if meta["name"] == name {
			return n
		}
	}
	return nil
}

func makeNode(name, internalIP string, isControlPlane bool) map[string]any {
	labels := map[string]string{
		"kubernetes.io/hostname":   name,
		"kubernetes.io/os":         "linux",
		"kubernetes.io/arch":       "amd64",
		"node.kubernetes.io/node":  "",
	}
	if isControlPlane {
		labels["node-role.kubernetes.io/control-plane"] = ""
	} else {
		labels["node-role.kubernetes.io/worker"] = ""
	}

	return map[string]any{
		"kind":       "Node",
		"apiVersion": "v1",
		"metadata": map[string]any{
			"name":              name,
			"creationTimestamp": "2026-01-01T00:00:00Z",
			"labels":            labels,
		},
		"status": map[string]any{
			"addresses": []map[string]string{
				{"type": "InternalIP", "address": internalIP},
				{"type": "Hostname", "address": name},
			},
			"conditions": []map[string]any{
				{"type": "Ready", "status": "True", "reason": "KubeletReady", "message": "kubelet is posting ready status"},
			},
			"nodeInfo": map[string]string{
				"kubeletVersion":   "v1.30.2",
				"osImage":          "Ubuntu 22.04.4 LTS",
				"kernelVersion":    "5.15.0-generic",
				"architecture":     "amd64",
				"operatingSystem": "linux",
			},
		},
	}
}

func unauthorizedResponse() map[string]any {
	return map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    "Unauthorized",
		"reason":     "Unauthorized",
		"code":       401,
	}
}

func forbiddenResponse(verb, resource, ns string) map[string]any {
	msg := fmt.Sprintf("%s is forbidden: User \"deploy-reader\" cannot %s resource \"%s\" in API group \"\"", resource, verb, resource)
	if ns != "" {
		msg = fmt.Sprintf("%s in the namespace \"%s\"", msg, ns)
	}
	return map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    msg,
		"reason":     "Forbidden",
		"details": map[string]any{
			"kind": resource,
		},
		"code": 403,
	}
}

func notFoundStatus(kind, name string) map[string]any {
	return map[string]any{
		"kind":       "Status",
		"apiVersion": "v1",
		"metadata":   map[string]any{},
		"status":     "Failure",
		"message":    fmt.Sprintf("%s %q not found", kind, name),
		"reason":     "NotFound",
		"details": map[string]any{
			"name": name,
			"kind": kind,
		},
		"code": 404,
	}
}

func emptyListResponse(resource string) map[string]any {
	return map[string]any{
		"kind":       "List",
		"apiVersion": "v1",
		"metadata":   map[string]any{"resourceVersion": "1000"},
		"items":      []any{},
	}
}

func parseRemoteAddr(remoteAddr string) (string, int) {
	host, portStr, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return remoteAddr, 0
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
	return 6443
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
