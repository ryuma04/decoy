package k8s

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const testBearer = "kube-bearer-token-deploy-reader-xyz123"

func testPersona() persona.Persona {
	return persona.Persona{
		Company:    "Northwind Logistics",
		Domain:     "northwind-logistics.internal",
		HostPrefix: "nwl",
		Hostname:   "nwl-app-01",
	}
}

func testTokens() map[string]Token {
	return map[string]Token{
		"tok_kube": {
			TokenID:     "tok_kube",
			Kind:        "kubeconfig",
			PlantedAt:   "ssh:/opt/deploy/kubeconfig",
			MazeNode:    "lure_kubeconfig",
			MatchValue:  testBearer,
			Sensitivity: 5,
		},
		"tok_db": {
			TokenID:     "tok_db",
			Kind:        "db_cred",
			MatchValue:  "db-secret-password-xyz",
			Sensitivity: 4,
		},
	}
}

// setupMockCore returns an in-memory HTTP server handling sensorkit events, policy, and maze-view.
func setupMockCore(t *testing.T, mazeSecrets []string) (*httptest.Server, *[]event.Envelope, *sync.Mutex) {
	t.Helper()
	var (
		mu        sync.Mutex
		envelopes []event.Envelope
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/ingest/events":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var batch []event.Envelope
			if err := json.Unmarshal(body, &batch); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			mu.Lock()
			envelopes = append(envelopes, batch...)
			mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case r.URL.Path == "/v1/ingest/heartbeat":
			w.WriteHeader(http.StatusOK)

		case r.URL.Path == "/v1/sensor/policy":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"rev":             1,
				"blocked_ips":     []string{"10.99.99.99"},
				"killed_sessions": []string{},
				"burned_tokens":   []string{},
			})

		case strings.HasPrefix(r.URL.Path, "/v1/sensor/maze-view"):
			w.Header().Set("Content-Type", "application/json")
			secs := mazeSecrets
			if secs == nil {
				secs = []string{}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"actor_id":      "act-1234",
				"visible_nodes": []string{"lure_kubeconfig"},
				"files":         []map[string]string{},
				"k8s_secrets":   secs,
				"limits": map[string]any{
					"remaining_requests": 500,
					"session_deadline":   time.Now().UTC().Add(30 * time.Minute),
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))

	return srv, &envelopes, &mu
}

func setupTestServer(t *testing.T, mazeSecrets []string) (*Server, func(), *[]event.Envelope, *sync.Mutex) {
	t.Helper()
	coreSrv, envs, mu := setupMockCore(t, mazeSecrets)

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "k8s-01",
		Key:      "secret-k8s-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "k8s",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	kit.Start(ctx)

	srv, err := New(Config{
		Addr:    ":6443",
		Kit:     kit,
		Persona: testPersona(),
		Tokens:  testTokens(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	cleanup := func() {
		cancel()
		kit.Close()
		coreSrv.Close()
	}

	return srv, cleanup, envs, mu
}

func TestTableVersionAndHealthz(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. GET /healthz without token -> 200 OK
	reqHealth := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	recHealth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recHealth, reqHealth)
	if recHealth.Code != http.StatusOK || recHealth.Body.String() != "ok" {
		t.Errorf("expected 200 ok, got %d %q", recHealth.Code, recHealth.Body.String())
	}

	// 2. GET /version without token -> 200 OK (as real API servers do, 06 §3)
	reqVer := httptest.NewRequest(http.MethodGet, "/version", nil)
	recVer := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recVer, reqVer)
	if recVer.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /version, got %d", recVer.Code)
	}
	var ver map[string]any
	if err := json.Unmarshal(recVer.Body.Bytes(), &ver); err != nil || ver["gitVersion"] != "v1.30.2" {
		t.Errorf("unexpected version response: %v", ver)
	}

	// 3. GET /version with valid token -> 200 OK
	reqVerAuth := httptest.NewRequest(http.MethodGet, "/version", nil)
	reqVerAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recVerAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recVerAuth, reqVerAuth)
	if recVerAuth.Code != http.StatusOK {
		t.Errorf("expected 200 OK for authenticated /version, got %d", recVerAuth.Code)
	}
}

func TestTableDiscoveryAPIs(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. GET /api without token -> 401 Unauthorized
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api", nil)
	recNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api without token, got %d", recNoAuth.Code)
	}
	var statusFail map[string]any
	_ = json.Unmarshal(recNoAuth.Body.Bytes(), &statusFail)
	if statusFail["kind"] != "Status" || statusFail["reason"] != "Unauthorized" {
		t.Errorf("expected Status Failure Unauthorized, got: %v", statusFail)
	}

	// 2. GET /api with valid lure token -> 200 discovery JSON
	reqAuth := httptest.NewRequest(http.MethodGet, "/api", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for /api with lure token, got %d", recAuth.Code)
	}
	var apiVer map[string]any
	_ = json.Unmarshal(recAuth.Body.Bytes(), &apiVer)
	if apiVer["kind"] != "APIVersions" {
		t.Errorf("expected APIVersions, got: %v", apiVer)
	}

	// 3. GET /apis without token -> 401
	reqApisNoAuth := httptest.NewRequest(http.MethodGet, "/apis", nil)
	recApisNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recApisNoAuth, reqApisNoAuth)
	if recApisNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /apis without token, got %d", recApisNoAuth.Code)
	}

	// 4. GET /apis with lure token -> 200 APIGroupList
	reqApisAuth := httptest.NewRequest(http.MethodGet, "/apis", nil)
	reqApisAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recApisAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recApisAuth, reqApisAuth)
	if recApisAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for /apis with lure token, got %d", recApisAuth.Code)
	}
	var apis map[string]any
	_ = json.Unmarshal(recApisAuth.Body.Bytes(), &apis)
	if apis["kind"] != "APIGroupList" {
		t.Errorf("expected APIGroupList, got: %v", apis)
	}
}

func TestTableNamespaces(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. GET /api/v1/namespaces without token -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	recNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for /api/v1/namespaces without token, got %d", recNoAuth.Code)
	}

	// 2. GET /api/v1/namespaces with lure token -> 200 with default, kube-system, ci, payments (06 §3)
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Errorf("expected 200 for /api/v1/namespaces with lure token, got %d", recAuth.Code)
	}

	var nsList struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recAuth.Body.Bytes(), &nsList); err != nil {
		t.Fatalf("unmarshal namespaces: %v", err)
	}
	if nsList.Kind != "NamespaceList" {
		t.Errorf("expected NamespaceList, got %s", nsList.Kind)
	}

	found := map[string]bool{}
	for _, item := range nsList.Items {
		found[item.Metadata.Name] = true
	}
	for _, expected := range []string{"default", "kube-system", "ci", "payments"} {
		if !found[expected] {
			t.Errorf("expected namespace %q in list, found: %v", expected, found)
		}
	}
}

func TestTablePods(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. GET /api/v1/namespaces/default/pods without token -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	recNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", recNoAuth.Code)
	}

	// 2. GET /api/v1/namespaces/default/pods with lure token -> 200 (3-6 persona pods, 06 §3)
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with lure token, got %d", recAuth.Code)
	}

	var podList struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recAuth.Body.Bytes(), &podList); err != nil {
		t.Fatalf("unmarshal pod list: %v", err)
	}
	if podList.Kind != "PodList" {
		t.Errorf("expected PodList, got %s", podList.Kind)
	}
	if len(podList.Items) < 3 {
		t.Errorf("expected 3-6 pods in default namespace, got %d", len(podList.Items))
	}
	for _, pod := range podList.Items {
		if pod.Metadata.Namespace != "default" {
			t.Errorf("expected namespace default, got %s", pod.Metadata.Namespace)
		}
		if !strings.HasPrefix(pod.Metadata.Name, "nwl-") {
			t.Errorf("expected pod name prefix 'nwl-', got %s", pod.Metadata.Name)
		}
	}
}

func TestTableSecretsMazeVisibility(t *testing.T) {
	// Case 1: Maze view has NO secrets unlocked
	srv1, cleanup1, _, _ := setupTestServer(t, []string{})
	defer cleanup1()

	reqNoSecrets := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	reqNoSecrets.Header.Set("Authorization", "Bearer "+testBearer)
	recNoSecrets := httptest.NewRecorder()
	srv1.Handler().ServeHTTP(recNoSecrets, reqNoSecrets)

	if recNoSecrets.Code != http.StatusOK {
		t.Fatalf("expected 200 for secrets, got %d", recNoSecrets.Code)
	}
	bodyStr1 := recNoSecrets.Body.String()
	if strings.Contains(bodyStr1, "ci-jenkins-token") {
		t.Errorf("ci-jenkins-token should NOT be visible when not in maze view")
	}
	if strings.Contains(bodyStr1, "db-credentials") {
		t.Errorf("db-credentials should NOT be visible when not in maze view")
	}

	// Case 2: Maze view has unlocked ci-jenkins-token and db-credentials (06 §3)
	srv2, cleanup2, _, _ := setupTestServer(t, []string{"ci-jenkins-token", "db-credentials"})
	defer cleanup2()

	reqWithSecrets := httptest.NewRequest(http.MethodGet, "/api/v1/secrets", nil)
	reqWithSecrets.Header.Set("Authorization", "Bearer "+testBearer)
	recWithSecrets := httptest.NewRecorder()
	srv2.Handler().ServeHTTP(recWithSecrets, reqWithSecrets)

	if recWithSecrets.Code != http.StatusOK {
		t.Fatalf("expected 200 for secrets with maze view, got %d", recWithSecrets.Code)
	}
	bodyStr2 := recWithSecrets.Body.String()
	if !strings.Contains(bodyStr2, "ci-jenkins-token") {
		t.Errorf("expected ci-jenkins-token to be visible when maze view lists it")
	}
	if !strings.Contains(bodyStr2, "db-credentials") {
		t.Errorf("expected db-credentials to be visible when maze view lists it")
	}
}

func TestTableNodes(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. GET /api/v1/nodes without token -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	recNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recNoAuth, reqNoAuth)
	if recNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without token, got %d", recNoAuth.Code)
	}

	// 2. GET /api/v1/nodes with lure token -> 200 with 3 nodes (06 §3)
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/nodes", nil)
	reqAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200 with lure token, got %d", recAuth.Code)
	}

	var nodeList struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name string `json:"name"`
			} `json:"metadata"`
		} `json:"items"`
	}
	if err := json.Unmarshal(recAuth.Body.Bytes(), &nodeList); err != nil {
		t.Fatalf("unmarshal node list: %v", err)
	}
	if nodeList.Kind != "NodeList" {
		t.Errorf("expected NodeList, got %s", nodeList.Kind)
	}
	if len(nodeList.Items) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(nodeList.Items))
	}
}

func TestTableWritesBlocked(t *testing.T) {
	srv, cleanup, _, _ := setupTestServer(t, nil)
	defer cleanup()

	// 1. POST without token -> 401
	reqPostNoAuth := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces/default/pods", strings.NewReader(`{"kind":"Pod"}`))
	recPostNoAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPostNoAuth, reqPostNoAuth)
	if recPostNoAuth.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for POST without token, got %d", recPostNoAuth.Code)
	}

	// 2. POST with lure token -> 403 Forbidden ("deploy-reader" RBAC, 06 §3)
	reqPostAuth := httptest.NewRequest(http.MethodPost, "/api/v1/namespaces/default/pods", strings.NewReader(`{"kind":"Pod"}`))
	reqPostAuth.Header.Set("Authorization", "Bearer "+testBearer)
	recPostAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPostAuth, reqPostAuth)
	if recPostAuth.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST with lure token, got %d", recPostAuth.Code)
	}
	var statusForbidden map[string]any
	_ = json.Unmarshal(recPostAuth.Body.Bytes(), &statusForbidden)
	if statusForbidden["kind"] != "Status" || statusForbidden["reason"] != "Forbidden" {
		t.Errorf("expected Status Failure Forbidden, got: %v", statusForbidden)
	}

	// 3. DELETE with lure token -> 403 Forbidden
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/namespaces/default/pods/nwl-frontend-01", nil)
	reqDel.Header.Set("Authorization", "Bearer "+testBearer)
	recDel := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusForbidden {
		t.Errorf("expected 403 for DELETE with lure token, got %d", recDel.Code)
	}

	// 4. PATCH with lure token -> 403 Forbidden
	reqPatch := httptest.NewRequest(http.MethodPatch, "/api/v1/namespaces/default/pods/nwl-frontend-01", strings.NewReader(`{}`))
	reqPatch.Header.Set("Authorization", "Bearer "+testBearer)
	recPatch := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPatch, reqPatch)
	if recPatch.Code != http.StatusForbidden {
		t.Errorf("expected 403 for PATCH with lure token, got %d", recPatch.Code)
	}
}

func TestEventEmissions(t *testing.T) {
	srv, cleanup, envs, mu := setupTestServer(t, nil)
	defer cleanup()

	// Send an authenticated request
	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	req.RemoteAddr = "10.66.0.42:51234"
	req.Header.Set("Authorization", "Bearer "+testBearer)
	req.Header.Set("User-Agent", "kubectl/v1.30.2 (linux/amd64)")
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}

	// Wait for sensorkit flush
	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var gotAuth, gotToken, gotK8sAPI, gotHTTP bool
	for _, e := range *envs {
		switch e.Type {
		case "auth.attempt":
			gotAuth = true
			var d map[string]any
			_ = json.Unmarshal(e.Data, &d)
			if d["method"] != "bearer" || d["success"] != true || d["username"] != "deploy-reader" {
				t.Errorf("unexpected auth.attempt: %v", d)
			}
		case "token.used":
			gotToken = true
			if len(e.Tokens) == 0 || e.Tokens[0] != "tok_kube" {
				t.Errorf("expected token tok_kube, got %v", e.Tokens)
			}
			var d map[string]any
			_ = json.Unmarshal(e.Data, &d)
			if d["via"] != "k8s_bearer" || d["token_id"] != "tok_kube" {
				t.Errorf("unexpected token.used data: %v", d)
			}
		case "k8s.api_call":
			gotK8sAPI = true
			var d map[string]any
			_ = json.Unmarshal(e.Data, &d)
			if d["resource"] != "pods" || d["namespace"] != "default" || d["authenticated"] != true {
				t.Errorf("unexpected k8s.api_call: %v", d)
			}
		case "http.request":
			gotHTTP = true
			var d map[string]any
			_ = json.Unmarshal(e.Data, &d)
			if d["path"] != "/api/v1/namespaces/default/pods" || d["status"] != float64(200) {
				t.Errorf("unexpected http.request data: %v", d)
			}
		}
	}

	if !gotAuth {
		t.Errorf("missing auth.attempt event")
	}
	if !gotToken {
		t.Errorf("missing token.used event")
	}
	if !gotK8sAPI {
		t.Errorf("missing k8s.api_call event")
	}
	if !gotHTTP {
		t.Errorf("missing http.request event")
	}
}

func TestBlockedIPRefusal(t *testing.T) {
	srv, cleanup, envs, mu := setupTestServer(t, nil)
	defer cleanup()

	// Wait for policy poll (10.99.99.99 is blocked)
	time.Sleep(50 * time.Millisecond)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/namespaces/default/pods", nil)
	req.RemoteAddr = "10.99.99.99:54321"
	req.Header.Set("Authorization", "Bearer "+testBearer)
	rec := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for blocked IP, got %d", rec.Code)
	}

	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	for _, e := range *envs {
		if e.Src.IP == "10.99.99.99" {
			t.Errorf("no events should be emitted for blocked IP, got: %+v", e)
		}
	}
}


// TestKubectlPlantedKubeconfigListPods verifies that kubectl using the planted kubeconfig
// (seed/out/tokens.json, tok_kube, insecure-skip-tls-verify: true) lists pods successfully over TLS.
func TestKubectlPlantedKubeconfigListPods(t *testing.T) {
	coreSrv, envs, mu := setupMockCore(t, nil)
	defer coreSrv.Close()

	kit := sensorkit.New(sensorkit.Options{
		SensorID: "k8s-01",
		Key:      "secret-k8s-key-16ch",
		CoreURL:  coreSrv.URL,
		Service:  "k8s",
		Origin:   "decoy",
		DataDir:  t.TempDir(),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	kit.Start(ctx)
	defer kit.Close()

	srv, err := New(Config{
		Addr:    "127.0.0.1:0", // dynamic local port
		Kit:     kit,
		Persona: testPersona(),
		Tokens:  testTokens(),
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Start local TLS server
	ts := httptest.NewUnstartedServer(srv.Handler())
	ts.TLS = srv.server.TLSConfig
	ts.StartTLS()
	defer ts.Close()

	// Client emulating kubectl with insecure-skip-tls-verify: true
	kubectlClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	// 1. kubectl get pods in default namespace
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/v1/namespaces/default/pods", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+testBearer)
	req.Header.Set("User-Agent", "kubectl/v1.30.2 (linux/amd64) kubernetes/3968350")
	req.Header.Set("Accept", "application/json")

	resp, err := kubectlClient.Do(req)
	if err != nil {
		t.Fatalf("kubectl request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 from kubectl list pods, got %d", resp.StatusCode)
	}

	var podList struct {
		Kind  string `json:"kind"`
		Items []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&podList); err != nil {
		t.Fatalf("failed to decode PodList: %v", err)
	}

	if podList.Kind != "PodList" {
		t.Errorf("expected Kind PodList, got %s", podList.Kind)
	}
	if len(podList.Items) == 0 {
		t.Fatalf("expected pods in default namespace, got 0")
	}

	for _, pod := range podList.Items {
		if pod.Metadata.Namespace != "default" {
			t.Errorf("expected namespace default, got %s", pod.Metadata.Namespace)
		}
		if pod.Status.Phase != "Running" {
			t.Errorf("expected pod phase Running, got %s", pod.Status.Phase)
		}
	}

	// Wait for sensorkit event emission
	time.Sleep(1200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	var gotTokenUsed bool
	for _, e := range *envs {
		if e.Type == "token.used" && len(e.Tokens) > 0 && e.Tokens[0] == "tok_kube" {
			gotTokenUsed = true
		}
	}
	if !gotTokenUsed {
		t.Errorf("expected token.used event for tok_kube when kubectl calls with planted kubeconfig")
	}
}
