// Package ssh implements the SSH decoy network server (06 §1, 08 limits).
// It accepts connections, emits events through sensorkit, and enforces per-session limits.
// Nothing real is ever executed — all commands go through the Shell emulator.
package ssh

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"io"
	"encoding/pem"
	"fmt"
	"log/slog"
	mrand "math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ryuma04/decoy/backend/internal/event"
	"github.com/ryuma04/decoy/backend/internal/fakefs"
	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
	"golang.org/x/crypto/ssh"
)

const (
	serverVersion = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
	mazeNode      = "ssh_entry"

	defaultIdleTimeout  = 10 * time.Minute
	defaultSessionCap   = 30 * time.Minute
	defaultMaxCommands  = 500
	defaultMaxLatencyMS = 150
	defaultMinLatencyMS = 30
)

// DeployKey holds the planted ed25519 deploy key that triggers token.used.
type DeployKey struct {
	PublicKey   ssh.PublicKey
	Fingerprint string // "SHA256:..."
	TokenID     string
}

// ServerConfig holds everything the SSH server needs.
type ServerConfig struct {
	Kit          *sensorkit.Kit
	Persona      persona.Persona
	Lures        []Lure
	DeployKey    *DeployKey // nil if no planted key
	ListenAddr   string
	DstPort      int
	IdleTimeout  time.Duration
	SessionCap   time.Duration
	MaxCommands  int
	MinLatencyMS int
	MaxLatencyMS int
	DockerSandboxAddr string
}

// Server is the SSH decoy.
type Server struct {
	cfg       ServerConfig
	sshConfig *ssh.ServerConfig
	listener  net.Listener

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// countingConn tracks bytes in and out for conn.close events.
type countingConn struct {
	net.Conn
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

func (c *countingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.bytesIn.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.bytesOut.Add(int64(n))
	return n, err
}

// NewServer builds the SSH server with auth callbacks that emit events.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = defaultIdleTimeout
	}
	if cfg.SessionCap <= 0 {
		cfg.SessionCap = defaultSessionCap
	}
	if cfg.MaxCommands <= 0 {
		cfg.MaxCommands = defaultMaxCommands
	}
	if cfg.MinLatencyMS <= 0 && cfg.MaxLatencyMS <= 0 {
		cfg.MinLatencyMS = defaultMinLatencyMS
		cfg.MaxLatencyMS = defaultMaxLatencyMS
	}

	s := &Server{cfg: cfg}
	sshCfg := &ssh.ServerConfig{
		ServerVersion: serverVersion,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			return s.passwordCallback(conn, password)
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return s.publicKeyCallback(conn, key)
		},
	}
	s.sshConfig = sshCfg
	return s, nil
}

// LoadOrGenerateHostKey loads or creates a persistent ed25519 host key in dataDir.
func LoadOrGenerateHostKey(dataDir string) (ssh.Signer, error) {
	keyPath := filepath.Join(dataDir, "ssh_host_ed25519")
	data, err := os.ReadFile(keyPath)
	if err == nil {
		signer, err := ssh.ParsePrivateKey(data)
		if err == nil {
			return signer, nil
		}
		slog.Warn("failed to parse existing host key, regenerating", "err", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate host key: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, fmt.Errorf("marshal host key: %w", err)
	}
	pemData := pem.EncodeToMemory(block)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dataDir, err)
	}
	if err := os.WriteFile(keyPath, pemData, 0o600); err != nil {
		return nil, fmt.Errorf("write host key: %w", err)
	}
	slog.Info("generated host key", "path", keyPath)
	signer, err := ssh.ParsePrivateKey(pemData)
	if err != nil {
		return nil, fmt.Errorf("parse generated key: %w", err)
	}
	return signer, nil
}

// AddHostKey adds a host key signer to the server.
func (s *Server) AddHostKey(signer ssh.Signer) {
	s.sshConfig.AddHostKey(signer)
}

// ListenAndServe starts the SSH server. It blocks until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	ln, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.ListenAddr, err)
	}
	s.listener = ln
	slog.Info("ssh decoy listening", "addr", ln.Addr())

	go func() {
		<-s.ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if s.ctx.Err() != nil {
				break
			}
			slog.Debug("accept error", "err", err)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConn(conn)
		}()
	}
	s.wg.Wait()
	return nil
}

// Close stops the server and waits for connections to finish.
func (s *Server) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	s.wg.Wait()
}

// Addr returns the listener address, or "" if not started.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return ""
}

// ---------- per-connection state ----------

type connState struct {
	session   *sensorkit.Session
	user      persona.User
	banner    string
	keyFP     string // last public key fingerprint seen
	closeOnce sync.Once

	mazeMu        sync.Mutex
	mazeLastFetch time.Time
	mazeVisible   []string
}

func (st *connState) emitClose(durationMS int, bytesIn, bytesOut int64, reason string) {
	st.closeOnce.Do(func() {
		st.session.Event("conn.close", mazeNode, connCloseData{
			DurationMS: durationMS,
			BytesIn:    bytesIn,
			BytesOut:   bytesOut,
			Reason:     reason,
		}, nil, nil)
	})
}

var (
	connStatesMu sync.Mutex
	connStates   = map[string]*connState{}
)

func getOrCreateState(kit *sensorkit.Kit, remoteAddr net.Addr, dstPort int) *connState {
	connStatesMu.Lock()
	defer connStatesMu.Unlock()
	key := remoteAddr.String()
	if st, ok := connStates[key]; ok {
		return st
	}
	host, portStr, _ := net.SplitHostPort(key)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	sess := kit.NewSession(host, port, dstPort)
	st := &connState{session: sess}
	connStates[key] = st
	return st
}

func removeState(remoteAddr string) {
	connStatesMu.Lock()
	defer connStatesMu.Unlock()
	delete(connStates, remoteAddr)
}

// ---------- auth callbacks ----------

func (s *Server) passwordCallback(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	st := getOrCreateState(s.cfg.Kit, conn.RemoteAddr(), s.cfg.DstPort)
	st.banner = string(conn.ClientVersion())

	username := conn.User()
	pass := string(password)
	accepted := false

	p := s.cfg.Persona
	switch username {
	case "root":
		accepted = pass == p.RootPassword
	case "deploy":
		accepted = pass == p.DeployPassword
	default:
		accepted = false
	}

	st.session.Client = &event.Client{SSHBanner: st.banner}
	var keyFPRef *string
	if st.keyFP != "" {
		st.session.Client.SSHKeyFP = st.keyFP
		keyFPRef = &st.keyFP
	}

	// Emit auth.attempt for every try.
	st.session.Event("auth.attempt", mazeNode, authAttemptData{
		Username: username,
		Password: &pass,
		KeyFP:    keyFPRef,
		Method:   "password",
		Success:  accepted,
	}, nil, nil)

	if accepted {
		u, ok := p.User(username)
		if !ok {
			u = persona.User{Name: username, UID: 1000, Home: "/home/" + username, Shell: "/bin/bash"}
		}
		st.user = u
		return &ssh.Permissions{Extensions: map[string]string{"user": username}}, nil
	}
	return nil, fmt.Errorf("password rejected for %s", username)
}

func (s *Server) publicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	st := getOrCreateState(s.cfg.Kit, conn.RemoteAddr(), s.cfg.DstPort)
	st.banner = string(conn.ClientVersion())

	fp := ssh.FingerprintSHA256(key)
	st.keyFP = fp

	username := conn.User()
	accepted := false
	var tokens []string

	if s.cfg.DeployKey != nil && username == "deploy" {
		if s.cfg.DeployKey.PublicKey != nil && KeysEqual(key, s.cfg.DeployKey.PublicKey) {
			accepted = true
			tokens = []string{s.cfg.DeployKey.TokenID}
		} else if s.cfg.DeployKey.Fingerprint != "" && fp == s.cfg.DeployKey.Fingerprint {
			accepted = true
			tokens = []string{s.cfg.DeployKey.TokenID}
		}
	}

	st.session.Client = &event.Client{SSHBanner: st.banner, SSHKeyFP: fp}

	// Emit auth.attempt.
	st.session.Event("auth.attempt", mazeNode, authAttemptData{
		Username: username,
		KeyFP:    &fp,
		Method:   "publickey",
		Success:  accepted,
	}, nil, nil)

	// Emit token.used if planted key matched.
	if accepted && len(tokens) > 0 {
		st.session.Event("token.used", mazeNode, tokenUsedData{
			TokenID:   tokens[0],
			TokenKind: "ssh_key",
			Via:       "ssh_key",
		}, nil, tokens)
	}

	if accepted {
		u, _ := s.cfg.Persona.User(username)
		st.user = u
		return &ssh.Permissions{Extensions: map[string]string{"user": username}}, nil
	}
	return nil, fmt.Errorf("public key rejected for %s", username)
}

// KeysEqual compares two SSH public keys.
func KeysEqual(a, b ssh.PublicKey) bool {
	return a.Type() == b.Type() && sha256Bytes(a.Marshal()) == sha256Bytes(b.Marshal())
}

func sha256Bytes(b []byte) [32]byte { return sha256.Sum256(b) }

// ---------- connection handler ----------

func (s *Server) handleConn(rawConn net.Conn) {
	remoteAddr := rawConn.RemoteAddr().String()
	defer removeState(remoteAddr)
	defer rawConn.Close()

	host, _, _ := net.SplitHostPort(remoteAddr)

	// Refuse blocked IPs immediately (TCP close, docs/04 §A Policy).
	if s.cfg.Kit.Blocked(host) {
		slog.Debug("blocked IP, closing connection", "ip", host)
		return
	}

	cconn := &countingConn{Conn: rawConn}
	st := getOrCreateState(s.cfg.Kit, rawConn.RemoteAddr(), s.cfg.DstPort)
	s.cfg.Kit.Open()
	defer s.cfg.Kit.Done()

	// Emit conn.open.
	st.session.Event("conn.open", mazeNode, struct{}{}, nil, nil)

	connStart := time.Now()

	sconn, chans, reqs, err := ssh.NewServerConn(cconn, s.sshConfig)
	if err != nil {
		// Handshake or authentication failed.
		dur := int(time.Since(connStart).Milliseconds())
		st.emitClose(dur, cconn.bytesIn.Load(), cconn.bytesOut.Load(), "client")
		return
	}
	defer sconn.Close()
	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleSession(ch, requests, st, cconn, host, connStart)
		}()
	}

	dur := int(time.Since(connStart).Milliseconds())
	st.emitClose(dur, cconn.bytesIn.Load(), cconn.bytesOut.Load(), "client")
}

// ---------- session (shell/exec) handler ----------

func (s *Server) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request, st *connState,
	cconn *countingConn, host string, connStart time.Time) {

	defer ch.Close()

	if s.cfg.DockerSandboxAddr != "" {
		if s.proxyToSandbox(ch, reqs, st, cconn, host, connStart) {
			return
		}
	}

	base := BaseTree(s.cfg.Persona, s.cfg.Lures)
	fs := fakefs.NewSession(base)
	shell := &Shell{
		FS:   fs,
		P:    s.cfg.Persona,
		User: st.user,
		Cwd:  st.user.Home,
	}

	var editor *LineEditor
	cmdCount := 0
	prompt := s.makePrompt(st.user, shell.Cwd)
	lastOutputTime := time.Now()

	var historyMu sync.Mutex
	var history []string
	shell.History = func() []string {
		historyMu.Lock()
		defer historyMu.Unlock()
		return append([]string{}, history...)
	}
	shell.Started = connStart

	var execCmd string

	// Process session requests.
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "window-change":
			if req.WantReply {
				req.Reply(true, nil)
			}
		case "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			shell.Interactive = true
			editor = NewLineEditor(prompt)
			ch.Write([]byte(prompt))
			s.shellLoop(ch, editor, shell, st, fs, cconn, host, &cmdCount, connStart, &lastOutputTime, &historyMu, &history)
			return
		case "exec":
			if req.WantReply {
				req.Reply(true, nil)
			}
			if len(req.Payload) >= 4 {
				cmdLen := int(req.Payload[0])<<24 | int(req.Payload[1])<<16 | int(req.Payload[2])<<8 | int(req.Payload[3])
				if cmdLen > 0 && cmdLen <= len(req.Payload)-4 {
					execCmd = string(req.Payload[4 : 4+cmdLen])
				}
			}
			if execCmd == "" {
				return
			}
			s.execCommand(ch, execCmd, shell, st, fs, connStart, &lastOutputTime)
			return
		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

func (s *Server) makePrompt(u persona.User, cwd string) string {
	hostname := s.cfg.Persona.Hostname
	suffix := "$"
	if u.UID == 0 {
		suffix = "#"
	}
	dir := cwd
	if cwd == u.Home {
		dir = "~"
	} else if strings.HasPrefix(cwd, u.Home+"/") {
		dir = "~" + strings.TrimPrefix(cwd, u.Home)
	}
	return fmt.Sprintf("%s@%s:%s%s ", u.Name, hostname, dir, suffix)
}

type readResult struct {
	data []byte
	err  error
}

// shellLoop reads from the PTY channel, feeds to LineEditor, runs commands, and enforces limits.
func (s *Server) shellLoop(ch ssh.Channel, editor *LineEditor, shell *Shell,
	st *connState, fs *fakefs.FS, cconn *countingConn, host string, cmdCount *int, connStart time.Time,
	lastOutputTime *time.Time, historyMu *sync.Mutex, history *[]string) {

	defer ch.Close()

	idleTimer := time.NewTimer(s.cfg.IdleTimeout)
	capTimer := time.NewTimer(s.cfg.SessionCap)
	policyTicker := time.NewTicker(time.Second)
	defer idleTimer.Stop()
	defer capTimer.Stop()
	defer policyTicker.Stop()

	readCh := make(chan readResult, 16)
	stopReader := make(chan struct{})
	defer close(stopReader)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ch.Read(buf)
			if n > 0 {
				cpy := make([]byte, n)
				copy(cpy, buf[:n])
				select {
				case readCh <- readResult{data: cpy}:
				case <-stopReader:
					return
				}
			}
			if err != nil {
				select {
				case readCh <- readResult{err: err}:
				case <-stopReader:
				}
				return
			}
		}
	}()

	resetIdle := func() {
		if !idleTimer.Stop() {
			select {
			case <-idleTimer.C:
			default:
			}
		}
		idleTimer.Reset(s.cfg.IdleTimeout)
	}

	for {
		select {
		case <-capTimer.C:
			ch.Write([]byte("\r\nSession time limit reached.\r\n"))
			st.emitClose(int(time.Since(connStart).Milliseconds()), cconn.bytesIn.Load(), cconn.bytesOut.Load(), "limit")
			return

		case <-idleTimer.C:
			ch.Write([]byte("\r\nTimed out waiting for input.\r\n"))
			st.emitClose(int(time.Since(connStart).Milliseconds()), cconn.bytesIn.Load(), cconn.bytesOut.Load(), "timeout")
			return

		case <-policyTicker.C:
			if s.cfg.Kit.Blocked(host) || s.cfg.Kit.Killed(st.session.ID) {
				ch.Write([]byte("\r\nConnection closed by foreign host.\r\n"))
				st.emitClose(int(time.Since(connStart).Milliseconds()), cconn.bytesIn.Load(), cconn.bytesOut.Load(), "killed")
				return
			}

		case res, ok := <-readCh:
			if !ok || res.err != nil {
				return
			}
			resetIdle()

			echo, lines := editor.Feed(res.data)
			if echo != "" {
				ch.Write([]byte(echo))
			}

			for _, line := range lines {
				if line.EOF {
					ch.Write([]byte("logout\r\n"))
					return
				}
				if line.Cancel {
					if shell.PasswordPending() {
						shell.CancelPassword()
						editor.SetSecret(false)
					}
					prompt := s.makePrompt(shell.User, shell.Cwd)
					editor.SetPrompt(prompt)
					ch.Write([]byte(prompt))
					continue
				}

				if shell.PasswordPending() {
					ansRes := shell.AnswerPassword(line.Text)
					if ansRes.Output != "" {
						ch.Write([]byte(toCRLF(ansRes.Output)))
					}
					if ansRes.SecretPrompt != "" {
						ch.Write([]byte(ansRes.SecretPrompt))
						editor.SetSecret(true)
					} else {
						editor.SetSecret(false)
						prompt := s.makePrompt(shell.User, shell.Cwd)
						editor.SetPrompt(prompt)
						ch.Write([]byte(prompt))
					}
					continue
				}

				text := strings.TrimSpace(line.Text)
				if text == "" {
					prompt := s.makePrompt(shell.User, shell.Cwd)
					editor.SetPrompt(prompt)
					ch.Write([]byte(prompt))
					continue
				}

				// Check command limit.
				if *cmdCount >= s.cfg.MaxCommands {
					ch.Write([]byte("\r\nCommand limit reached.\r\n"))
					st.emitClose(int(time.Since(connStart).Milliseconds()), cconn.bytesIn.Load(), cconn.bytesOut.Load(), "limit")
					return
				}

				// Refresh maze view if command touches lures (ls, find, cat).
				s.maybeRefreshMazeView(fs, st, text)

				// Add latency.
				s.addLatency()

				sincePrev := time.Since(*lastOutputTime).Milliseconds()
				result := shell.Run(text)
				*lastOutputTime = time.Now()
				*cmdCount++

				historyMu.Lock()
				*history = append(*history, text)
				historyMu.Unlock()
				editor.AddHistory(text)

				// Emit shell.command event.
				timing := &event.Timing{
					SincePrevMS: sincePrev,
					Keystrokes:  line.Keystrokes,
					Edits:       line.Edits,
					Paste:       line.Paste,
				}
				st.session.Event("shell.command", mazeNode, shellCommandData{
					Raw:          text,
					Argv0:        result.Argv0,
					Args:         result.Args,
					Cwd:          shell.Cwd,
					Exit:         result.Exit,
					StdoutTokens: result.StdoutTokens,
				}, timing, nil)

				// Emit file.read events for any reads.
				for _, r := range result.Reads {
					var tokens []string
					var hIDRef *string
					if r.HoneyfileID != "" {
						tokens = []string{r.HoneyfileID}
						hIDRef = &r.HoneyfileID
					}
					st.session.Event("file.read", r.MazeNode, fileReadData{
						Path:        r.Path,
						HoneyfileID: hIDRef,
						Bytes:       r.Bytes,
					}, nil, tokens)
				}

				// Write output.
				if result.Output != "" {
					out := toCRLF(result.Output)
					ch.Write([]byte(out))
				}
				if result.Clear {
					ch.Write([]byte("\x1b[2J\x1b[H"))
				}

				if result.Logout {
					return
				}

				if result.SecretPrompt != "" {
					ch.Write([]byte(result.SecretPrompt))
					editor.SetSecret(true)
				} else {
					prompt := s.makePrompt(shell.User, shell.Cwd)
					editor.SetPrompt(prompt)
					ch.Write([]byte(prompt))
				}
			}
		}
	}
}

// execCommand handles `ssh host command` — emulated via Shell.
func (s *Server) execCommand(ch ssh.Channel, cmd string, shell *Shell,
	st *connState, fs *fakefs.FS, connStart time.Time, lastOutputTime *time.Time) {

	defer ch.Close()

	s.maybeRefreshMazeView(fs, st, cmd)
	s.addLatency()

	sincePrev := time.Since(*lastOutputTime).Milliseconds()
	result := shell.Run(cmd)
	*lastOutputTime = time.Now()

	// Emit shell.command.
	st.session.Event("shell.command", mazeNode, shellCommandData{
		Raw:          cmd,
		Argv0:        result.Argv0,
		Args:         result.Args,
		Cwd:          shell.Cwd,
		Exit:         result.Exit,
		StdoutTokens: result.StdoutTokens,
	}, &event.Timing{SincePrevMS: sincePrev, Keystrokes: len(cmd), Paste: true}, nil)

	for _, r := range result.Reads {
		var tokens []string
		var hIDRef *string
		if r.HoneyfileID != "" {
			tokens = []string{r.HoneyfileID}
			hIDRef = &r.HoneyfileID
		}
		st.session.Event("file.read", r.MazeNode, fileReadData{
			Path:        r.Path,
			HoneyfileID: hIDRef,
			Bytes:       r.Bytes,
		}, nil, tokens)
	}

	if result.Output != "" {
		ch.Write([]byte(result.Output))
	}

	exitMsg := ssh.Marshal(struct{ Status uint32 }{uint32(result.Exit)})
	ch.SendRequest("exit-status", false, exitMsg)
}

// ---------- maze view caching ----------

type mazeViewResponse struct {
	ActorID      string            `json:"actor_id"`
	VisibleNodes []string          `json:"visible_nodes"`
	Files        []mazeViewFile    `json:"files"`
	K8sSecrets   []json.RawMessage `json:"k8s_secrets"`
}

type mazeViewFile struct {
	Path        string `json:"path"`
	HoneyfileID string `json:"honeyfile_id"`
	MazeNode    string `json:"maze_node"`
}

func isMazeCommand(line string) bool {
	fields := strings.FieldsFunc(line, func(r rune) bool {
		return r == '|' || r == ';' || r == '&' || r == ' ' || r == '\t' || r == '>'
	})
	for _, f := range fields {
		b := filepath.Base(f)
		if b == "ls" || b == "find" || b == "cat" || b == "head" || b == "tail" || b == "grep" {
			return true
		}
	}
	return false
}

func (s *Server) maybeRefreshMazeView(fs *fakefs.FS, st *connState, line string) {
	if !isMazeCommand(line) {
		return
	}
	st.mazeMu.Lock()
	defer st.mazeMu.Unlock()

	// 2s cache.
	if time.Since(st.mazeLastFetch) < 2*time.Second {
		if len(st.mazeVisible) > 0 {
			fs.SetVisible(st.mazeVisible)
		}
		return
	}

	ctx := s.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	var view mazeViewResponse
	err := s.cfg.Kit.MazeView(ctx, st.session.ID, &view)
	if err == nil {
		st.mazeLastFetch = time.Now()
		st.mazeVisible = view.VisibleNodes
		fs.SetVisible(view.VisibleNodes)
	}
}

// ---------- data types for events ----------

type authAttemptData struct {
	Username string  `json:"username"`
	Password *string `json:"password"`
	KeyFP    *string `json:"key_fp"`
	Method   string  `json:"method"`
	Success  bool    `json:"success"`
}

type tokenUsedData struct {
	TokenID   string `json:"token_id"`
	TokenKind string `json:"token_kind"`
	Via       string `json:"via"`
}

type connCloseData struct {
	DurationMS int    `json:"duration_ms"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	Reason     string `json:"reason"`
}

type shellCommandData struct {
	Raw          string   `json:"raw"`
	Argv0        string   `json:"argv0"`
	Args         []string `json:"args,omitempty"`
	Cwd          string   `json:"cwd"`
	Exit         int      `json:"exit"`
	StdoutTokens []string `json:"stdout_tokens,omitempty"`
}

type fileReadData struct {
	Path        string  `json:"path"`
	HoneyfileID *string `json:"honeyfile_id"`
	Bytes       int     `json:"bytes"`
}

// ---------- helpers ----------

func (s *Server) addLatency() {
	if s.cfg.MaxLatencyMS <= 0 {
		return
	}
	minL := s.cfg.MinLatencyMS
	maxL := s.cfg.MaxLatencyMS
	if maxL < minL {
		maxL = minL
	}
	ms := minL
	if diff := maxL - minL; diff > 0 {
		ms += mrand.IntN(diff + 1)
	}
	time.Sleep(time.Duration(ms) * time.Millisecond)
}

func toCRLF(s string) string {
	var out strings.Builder
	out.Grow(len(s) + len(s)/10)
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' && (i == 0 || s[i-1] != '\r') {
			out.WriteByte('\r')
		}
		out.WriteByte(s[i])
	}
	return out.String()
}

// ParseDeployKeyFromSeed reads the deploy key from tokens.json and deploy_id_ed25519.pub if present.
func ParseDeployKeyFromSeed(seedDir string) (*DeployKey, error) {
	candidatePaths := []string{
		filepath.Join(seedDir, "out", "tokens.json"),
		filepath.Join(seedDir, "tokens.json"),
		filepath.Join("seed", "out", "tokens.json"),
	}

	var data []byte
	var err error
	var foundDir string
	for _, p := range candidatePaths {
		if data, err = os.ReadFile(p); err == nil {
			foundDir = filepath.Dir(p)
			break
		}
	}
	if err != nil {
		return nil, fmt.Errorf("read tokens.json: %w", err)
	}

	var tokens map[string]json.RawMessage
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("parse tokens.json: %w", err)
	}
	backupRaw, ok := tokens["tok_backup_key"]
	if !ok {
		return nil, fmt.Errorf("tok_backup_key not found in tokens.json")
	}
	var tok struct {
		MatchValue string `json:"match_value"`
	}
	if err := json.Unmarshal(backupRaw, &tok); err != nil {
		return nil, fmt.Errorf("parse tok_backup_key: %w", err)
	}

	pubKeyPath := filepath.Join(foundDir, "deploy_id_ed25519.pub")
	pubData, err := os.ReadFile(pubKeyPath)
	if err != nil {
		slog.Info("no deploy public key file found, matching by fingerprint", "path", pubKeyPath, "fp", tok.MatchValue)
		return &DeployKey{
			Fingerprint: tok.MatchValue,
			TokenID:     "tok_backup_key",
		}, nil
	}

	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubData)
	if err != nil {
		return nil, fmt.Errorf("parse deploy public key: %w", err)
	}
	return &DeployKey{
		PublicKey:   pubKey,
		Fingerprint: ssh.FingerprintSHA256(pubKey),
		TokenID:     "tok_backup_key",
	}, nil
}

// LoadLuresFromSeed reads lures from tokens.json.
func LoadLuresFromSeed(seedDir string) ([]Lure, error) {
	candidatePaths := []string{
		filepath.Join(seedDir, "out", "tokens.json"),
		filepath.Join(seedDir, "tokens.json"),
		filepath.Join("seed", "out", "tokens.json"),
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

	var tokens map[string]struct {
		TokenID  string `json:"token_id"`
		Path     string `json:"path"`
		Content  string `json:"content"`
		Hidden   bool   `json:"hidden"`
		MazeNode string `json:"maze_node"`
	}
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("parse tokens.json: %w", err)
	}
	var lures []Lure
	for _, t := range tokens {
		if t.Path == "" {
			continue
		}
		owner := "deploy"
		if strings.HasPrefix(t.Path, "/etc/") || strings.HasPrefix(t.Path, "/root/") {
			owner = "root"
		}
		lures = append(lures, Lure{
			Path:        t.Path,
			Content:     t.Content,
			HoneyfileID: t.TokenID,
			MazeNode:    t.MazeNode,
			Owner:       owner,
			Hidden:      t.Hidden,
		})
	}
	return lures, nil
}

func (s *Server) proxyToSandbox(ch ssh.Channel, reqs <-chan *ssh.Request, st *connState, cconn *countingConn, host string, connStart time.Time) bool {
	if s.cfg.DockerSandboxAddr == "" {
		return false
	}
	conn, err := net.DialTimeout("tcp", s.cfg.DockerSandboxAddr, 2*time.Second)
	if err != nil {
		return false
	}

	clientConfig := &ssh.ClientConfig{
		User: st.user.Name,
		Auth: []ssh.AuthMethod{
			ssh.Password("HalSummer2023!"),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	cClientConn, chans, rReqs, err := ssh.NewClientConn(conn, s.cfg.DockerSandboxAddr, clientConfig)
	if err != nil {
		conn.Close()
		return false
	}
	cClient := ssh.NewClient(cClientConn, chans, rReqs)
	defer cClient.Close()

	cSession, err := cClient.NewSession()
	if err != nil {
		return false
	}
	defer cSession.Close()

	sStdin, err := cSession.StdinPipe()
	if err != nil {
		return false
	}
	sStdout, err := cSession.StdoutPipe()
	if err != nil {
		return false
	}
	sStderr, err := cSession.StderrPipe()
	if err != nil {
		return false
	}

	go func() {
		for req := range reqs {
			switch req.Type {
			case "pty-req":
				term := "xterm-256color"
				if len(req.Payload) >= 4 {
					tLen := int(req.Payload[3])
					if len(req.Payload) >= 4+tLen {
						term = string(req.Payload[4 : 4+tLen])
					}
				}
				_ = cSession.RequestPty(term, 80, 24, ssh.TerminalModes{
					ssh.ECHO:          1,
					ssh.TTY_OP_ISPEED: 14400,
					ssh.TTY_OP_OSPEED: 14400,
				})
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "shell":
				_ = cSession.Shell()
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "window-change":
				if len(req.Payload) >= 8 {
					w := int(binary.BigEndian.Uint32(req.Payload[0:4]))
					h := int(binary.BigEndian.Uint32(req.Payload[4:8]))
					_ = cSession.WindowChange(h, w)
				}
				if req.WantReply {
					req.Reply(true, nil)
				}
			case "exec":
				cmd := ""
				if len(req.Payload) >= 4 {
					l := int(binary.BigEndian.Uint32(req.Payload[0:4]))
					if l > 0 && len(req.Payload) >= 4+l {
						cmd = string(req.Payload[4 : 4+l])
					}
				}
				_ = cSession.Start(cmd)
				if req.WantReply {
					req.Reply(true, nil)
				}
			default:
				if req.WantReply {
					req.Reply(false, nil)
				}
			}
		}
	}()

	var triggerMu sync.Mutex
	triggered := map[string]bool{}
	emitToken := func(tokenID, pth string) {
		triggerMu.Lock()
		defer triggerMu.Unlock()
		if triggered[tokenID] {
			return
		}
		triggered[tokenID] = true
		tokRef := tokenID
		st.session.Event("file.read", mazeNode, fileReadData{
			Path:        pth,
			HoneyfileID: &tokRef,
			Bytes:       len(tokenID),
		}, nil, []string{tokenID})
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer sStdin.Close()
		_, _ = io.Copy(sStdin, ch)
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := sStdout.Read(buf)
			if n > 0 {
				chunk := buf[:n]
				sChunk := string(chunk)
				if strings.Contains(sChunk, "AKIA3EXNNKIAOP2SNCD5") {
					emitToken("tok_aws_k7", "/home/deploy/.aws/credentials")
				}
				if strings.Contains(sChunk, "neaUPVW4RYGJViL9C8iUHxNtr8HULVBeiJKsY0Eg9Lq9GhMv") {
					emitToken("tok_kube", "/opt/deploy/kubeconfig")
				}
				_, _ = ch.Write(chunk)
			}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(ch.Stderr(), sStderr)
	}()

	_ = cSession.Wait()
	wg.Wait()

	st.emitClose(int(time.Since(connStart).Milliseconds()), cconn.bytesIn.Load(), cconn.bytesOut.Load(), "clean")
	return true
}
