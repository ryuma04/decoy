package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorauth"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
	golangSSH "golang.org/x/crypto/ssh"
)

const testSensorKey = "test-sensor-key-123456789"

type testCore struct {
	mu             sync.Mutex
	events         []event.Envelope
	blockedIPs     []string
	killedSessions []string
	burnedTokens   []string
	policyRev      atomic.Int64
}

func (c *testCore) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	_, _ = sensorauth.Verify(r, body, map[string]string{"ssh-01": testSensorKey}, time.Now())

	switch r.URL.Path {
	case "/v1/ingest/events":
		var envs []event.Envelope
		_ = json.Unmarshal(body, &envs)
		c.mu.Lock()
		c.events = append(c.events, envs...)
		c.mu.Unlock()
		w.Write([]byte(`{"accepted":1}`))
	case "/v1/ingest/heartbeat":
		w.WriteHeader(204)
	case "/v1/sensor/policy":
		c.mu.Lock()
		resp, _ := json.Marshal(map[string]any{
			"blocked_ips":     c.blockedIPs,
			"killed_sessions": c.killedSessions,
			"burned_tokens":   c.burnedTokens,
			"rev":             c.policyRev.Load(),
		})
		c.mu.Unlock()
		w.Write(resp)
	case "/v1/sensor/maze-view":
		w.Write([]byte(`{"visible_nodes":["ssh_entry","lure_aws"]}`))
	default:
		w.WriteHeader(404)
	}
}

func (c *testCore) getEvents() []event.Envelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]event.Envelope{}, c.events...)
}

func (c *testCore) hasEventType(typ string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, e := range c.events {
		if e.Type == typ {
			return true
		}
	}
	return false
}

type testEnv struct {
	server       *Server
	core         *testCore
	kit          *sensorkit.Kit
	p            persona.Persona
	deploySigner golangSSH.Signer
	deployKey    *DeployKey
	hostSigner   golangSSH.Signer
	addr         string
	cancel       context.CancelFunc
}

func setupTestEnv(t *testing.T, modifyCfg ...func(*ServerConfig)) *testEnv {
	t.Helper()

	core := &testCore{}
	srv := httptest.NewServer(core)
	t.Cleanup(srv.Close)

	dir := t.TempDir()
	kit := sensorkit.New(sensorkit.Options{
		SensorID: "ssh-01",
		Key:      testSensorKey,
		CoreURL:  srv.URL,
		Service:  "ssh",
		DataDir:  dir,
	})
	ctx, cancel := context.WithCancel(context.Background())
	kit.Start(ctx)
	t.Cleanup(func() {
		cancel()
		kit.Close()
	})

	p := persona.Generate("test-persona-seed")

	// Generate deploy key.
	_, privDeploy, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate deploy key: %v", err)
	}
	deploySigner, err := golangSSH.NewSignerFromKey(privDeploy)
	if err != nil {
		t.Fatalf("deploy signer: %v", err)
	}
	deployKey := &DeployKey{
		PublicKey:   deploySigner.PublicKey(),
		Fingerprint: golangSSH.FingerprintSHA256(deploySigner.PublicKey()),
		TokenID:     "tok_backup_key",
	}

	// Host key.
	hostSigner, err := LoadOrGenerateHostKey(dir)
	if err != nil {
		t.Fatalf("host signer: %v", err)
	}

	lures := []Lure{
		{
			Path:        "/home/deploy/.aws/credentials",
			Content:     "[default]\naws_access_key_id = AKIATEST\n",
			HoneyfileID: "tok_aws_k7",
			MazeNode:    "lure_aws",
			Owner:       "deploy",
		},
	}

	cfg := ServerConfig{
		Kit:          kit,
		Persona:      p,
		Lures:        lures,
		DeployKey:    deployKey,
		ListenAddr:   "127.0.0.1:0",
		DstPort:      2222,
		MinLatencyMS: 0,
		MaxLatencyMS: 0,
	}

	for _, m := range modifyCfg {
		m(&cfg)
	}

	server, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	server.AddHostKey(hostSigner)

	serverCtx, serverCancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		serverCancel()
		server.Close()
	})

	go func() {
		_ = server.ListenAndServe(serverCtx)
	}()

	// Wait for listener to be active.
	for i := 0; i < 50; i++ {
		if server.Addr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if server.Addr() == "" {
		t.Fatal("server failed to start listening")
	}

	return &testEnv{
		server:       server,
		core:         core,
		kit:          kit,
		p:            p,
		deploySigner: deploySigner,
		deployKey:    deployKey,
		hostSigner:   hostSigner,
		addr:         server.Addr(),
		cancel:       serverCancel,
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timeout waiting for condition")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// 1. Password auth success for deploy and root.
func TestPasswordAuthSuccess(t *testing.T) {
	env := setupTestEnv(t)

	// Test deploy user.
	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("failed to dial with deploy password: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("whoami")
	if err != nil {
		t.Fatalf("whoami: %v", err)
	}
	if strings.TrimSpace(string(out)) != "deploy" {
		t.Fatalf("unexpected output: %q", string(out))
	}

	// Wait for events to flush to core.
	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("auth.attempt") && env.core.hasEventType("shell.command")
	})

	events := env.core.getEvents()
	var authEvent *event.Envelope
	for _, e := range events {
		if e.Type == "auth.attempt" {
			authEvent = &e
			break
		}
	}
	if authEvent == nil {
		t.Fatal("auth.attempt event not found")
	}
	var data authAttemptData
	if err := json.Unmarshal(authEvent.Data, &data); err != nil {
		t.Fatalf("unmarshal auth data: %v", err)
	}
	if data.Username != "deploy" || !data.Success || data.Method != "password" {
		t.Fatalf("invalid auth.attempt data: %+v", data)
	}
}

// 2. Password auth failure for wrong password.
func TestPasswordAuthFailure(t *testing.T) {
	env := setupTestEnv(t)

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password("wrong-password-123")},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	_, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err == nil {
		t.Fatal("dial should have failed with wrong password")
	}

	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("auth.attempt")
	})

	var data authAttemptData
	for _, e := range env.core.getEvents() {
		if e.Type == "auth.attempt" {
			_ = json.Unmarshal(e.Data, &data)
			break
		}
	}
	if data.Success {
		t.Fatal("auth.attempt should have recorded failure")
	}
}

// 3. Public key auth with planted deploy key succeeds and emits token.used.
func TestPublicKeyAuthDeployKey(t *testing.T) {
	env := setupTestEnv(t)

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.PublicKeys(env.deploySigner)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("failed to dial with deploy key: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	defer sess.Close()

	out, err := sess.Output("id")
	if err != nil {
		t.Fatalf("id command: %v", err)
	}
	if !strings.Contains(string(out), "uid=1001(deploy)") {
		t.Fatalf("unexpected id output: %q", string(out))
	}

	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("token.used")
	})

	events := env.core.getEvents()
	var tokenEvent *event.Envelope
	for _, e := range events {
		if e.Type == "token.used" {
			tokenEvent = &e
			break
		}
	}
	if tokenEvent == nil {
		t.Fatal("token.used event not found")
	}
	var tData tokenUsedData
	_ = json.Unmarshal(tokenEvent.Data, &tData)
	if tData.TokenID != "tok_backup_key" || tData.Via != "ssh_key" {
		t.Fatalf("unexpected token.used data: %+v", tData)
	}
}

// 4. Public key auth rejected for unplanted key, but key_fp is recorded.
func TestPublicKeyAuthRejected(t *testing.T) {
	env := setupTestEnv(t)

	_, privOther, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := golangSSH.NewSignerFromKey(privOther)
	if err != nil {
		t.Fatal(err)
	}

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.PublicKeys(otherSigner)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	_, err = golangSSH.Dial("tcp", env.addr, cfg)
	if err == nil {
		t.Fatal("dial should have failed for unplanted key")
	}

	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("auth.attempt")
	})

	events := env.core.getEvents()
	var authEvent *event.Envelope
	for _, e := range events {
		if e.Type == "auth.attempt" {
			authEvent = &e
			break
		}
	}
	if authEvent == nil {
		t.Fatal("auth.attempt event not found")
	}
	var data authAttemptData
	_ = json.Unmarshal(authEvent.Data, &data)
	if data.Success || data.KeyFP == nil || *data.KeyFP == "" {
		t.Fatalf("key_fp should be recorded on failed public key attempt: %+v", data)
	}
}

// 5. Interactive PTY shell and command execution.
func TestPTYShellInteraction(t *testing.T) {
	env := setupTestEnv(t)

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	modes := golangSSH.TerminalModes{
		golangSSH.ECHO:          0,
		golangSSH.TTY_OP_ISPEED: 14400,
		golangSSH.TTY_OP_OSPEED: 14400,
	}
	if err := sess.RequestPty("xterm", 80, 24, modes); err != nil {
		t.Fatalf("request pty: %v", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin pipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}

	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	// Read initial prompt.
	buf := make([]byte, 1024)
	n, _ := stdout.Read(buf)
	if !strings.Contains(string(buf[:n]), "deploy@") {
		t.Fatalf("expected prompt, got: %q", string(buf[:n]))
	}

	// Send cat command reading the aws credentials honeyfile.
	_, _ = stdin.Write([]byte("cat ~/.aws/credentials\r"))

	// Read output until credentials are found.
	time.Sleep(100 * time.Millisecond)
	n, _ = stdout.Read(buf)
	out := string(buf[:n])
	if !strings.Contains(out, "AKIATEST") {
		t.Logf("output: %s", out)
	}

	_, _ = stdin.Write([]byte("exit\r"))

	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("file.read")
	})

	var readEvent *event.Envelope
	for _, e := range env.core.getEvents() {
		if e.Type == "file.read" {
			readEvent = &e
			break
		}
	}
	if readEvent == nil {
		t.Fatal("file.read event not found")
	}
	var rData fileReadData
	_ = json.Unmarshal(readEvent.Data, &rData)
	if rData.HoneyfileID == nil || *rData.HoneyfileID != "tok_aws_k7" {
		t.Fatalf("file.read should report honeyfile_id: %+v", rData)
	}
}

// 6. Idle timeout closes session with reason "timeout".
func TestIdleTimeout(t *testing.T) {
	env := setupTestEnv(t, func(c *ServerConfig) {
		c.IdleTimeout = 100 * time.Millisecond
	})

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	_ = stdin

	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	// Wait past idle timeout.
	time.Sleep(300 * time.Millisecond)

	waitForCondition(t, 4*time.Second, func() bool {
		for _, e := range env.core.getEvents() {
			if e.Type == "conn.close" {
				var data connCloseData
				_ = json.Unmarshal(e.Data, &data)
				if data.Reason == "timeout" {
					return true
				}
			}
		}
		return false
	})
}

// 7. Session cap closes session with reason "limit".
func TestSessionCap(t *testing.T) {
	env := setupTestEnv(t, func(c *ServerConfig) {
		c.SessionCap = 200 * time.Millisecond
	})

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	_ = stdin

	if err := sess.Shell(); err != nil {
		t.Fatalf("shell: %v", err)
	}

	time.Sleep(350 * time.Millisecond)

	waitForCondition(t, 4*time.Second, func() bool {
		for _, e := range env.core.getEvents() {
			if e.Type == "conn.close" {
				var data connCloseData
				_ = json.Unmarshal(e.Data, &data)
				if data.Reason == "limit" {
					return true
				}
			}
		}
		return false
	})
}

// 8. Command limit closes session with reason "limit".
func TestCommandLimit(t *testing.T) {
	env := setupTestEnv(t, func(c *ServerConfig) {
		c.MaxCommands = 2
	})

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	_ = sess.Shell()

	buf := make([]byte, 1024)
	_, _ = stdout.Read(buf) // prompt

	// Command 1
	_, _ = stdin.Write([]byte("pwd\r"))
	time.Sleep(50 * time.Millisecond)
	_, _ = stdout.Read(buf)

	// Command 2
	_, _ = stdin.Write([]byte("whoami\r"))
	time.Sleep(50 * time.Millisecond)
	_, _ = stdout.Read(buf)

	// Command 3 - should trigger command limit
	_, _ = stdin.Write([]byte("id\r"))
	time.Sleep(50 * time.Millisecond)

	waitForCondition(t, 3*time.Second, func() bool {
		for _, e := range env.core.getEvents() {
			if e.Type == "conn.close" {
				var data connCloseData
				_ = json.Unmarshal(e.Data, &data)
				if data.Reason == "limit" {
					return true
				}
			}
		}
		return false
	})
}

// 9. Blocked IP is refused.
func TestBlockedIPRefused(t *testing.T) {
	env := setupTestEnv(t)

	// Set 127.0.0.1 as blocked in policy.
	env.core.mu.Lock()
	env.core.blockedIPs = []string{"127.0.0.1"}
	env.core.policyRev.Add(1)
	env.core.mu.Unlock()

	// Wait for kit policy to poll the change.
	waitForCondition(t, 6*time.Second, func() bool {
		return env.kit.Blocked("127.0.0.1")
	})

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
	}

	_, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err == nil {
		t.Fatal("connection should have been refused for blocked IP")
	}
}

// 10. Killed session is terminated.
func TestKilledSession(t *testing.T) {
	env := setupTestEnv(t)

	cfg := &golangSSH.ClientConfig{
		User:            "deploy",
		Auth:            []golangSSH.AuthMethod{golangSSH.Password(env.p.DeployPassword)},
		HostKeyCallback: golangSSH.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}

	client, err := golangSSH.Dial("tcp", env.addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	defer sess.Close()

	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	_ = stdin

	_ = sess.Shell()

	// Wait for conn.open to arrive so we know session id.
	waitForCondition(t, 3*time.Second, func() bool {
		return env.core.hasEventType("conn.open")
	})

	var sessID string
	for _, e := range env.core.getEvents() {
		if e.Type == "conn.open" {
			sessID = e.Session.SensorSessionID
			break
		}
	}
	if sessID == "" {
		t.Fatal("session id not found")
	}

	// Update policy to kill session.
	env.core.mu.Lock()
	env.core.killedSessions = []string{sessID}
	env.core.policyRev.Add(1)
	env.core.mu.Unlock()

	// Wait for kit policy update and killed event.
	waitForCondition(t, 8*time.Second, func() bool {
		for _, e := range env.core.getEvents() {
			if e.Type == "conn.close" {
				var data connCloseData
				_ = json.Unmarshal(e.Data, &data)
				if data.Reason == "killed" {
					return true
				}
			}
		}
		return false
	})
}
