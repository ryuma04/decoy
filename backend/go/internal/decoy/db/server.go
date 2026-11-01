// Package db is the database decoy (06 §5, maze node svc_db): a PostgreSQL wire-protocol server that accepts the
// planted DB credential (honeytoken tok_db, leaked in /etc/app/db.env and the web lures), answers queries from fake
// tables and reports every query to core. It never runs SQL: queries are matched by query.go against in-memory
// fake data, and it never executes, fetches or resolves anything real.
package db

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ryuma04/decoy/backend/internal/persona"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
)

const (
	protoV3       = 196608
	sslRequest    = 80877103
	gssEncRequest = 80877104
	cancelRequest = 80877102
	maxMessage    = 1 << 20
	idleTimeout   = 10 * time.Minute
	sessionCap    = 30 * time.Minute
	maxQueries    = 500
	serverVersion = "14.11 (Ubuntu 14.11-0ubuntu0.22.04.1)"
	defaultDBName = "orders"
)

// Config configures the decoy.
type Config struct {
	Addr     string
	Kit      *sensorkit.Kit
	Persona  persona.Persona
	DBPass   string // tok_db match value: the planted credential
	DstPort  int
	Database string
	// Aliases: other database names planted lures advertise (e.g. the Aetees /.env.bak DATABASE_URL); accepted like Database.
	Aliases []string
}

func (s *Server) knownDB(name string) bool {
	if name == s.cfg.Database {
		return true
	}
	for _, a := range s.cfg.Aliases {
		if a != "" && name == a {
			return true
		}
	}
	return false
}

// Server is the Postgres decoy listener.
type Server struct {
	cfg  Config
	data *Dataset
	ln   net.Listener
	wg   sync.WaitGroup
}

func New(cfg Config) *Server {
	if cfg.Database == "" {
		cfg.Database = defaultDBName
	}
	if cfg.DstPort == 0 {
		cfg.DstPort = 5432
	}
	return &Server{cfg: cfg, data: NewDataset(cfg.Persona)}
}

// ListenAndServe accepts connections until ctx ends.
func (s *Server) ListenAndServe(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Addr, err)
	}
	s.ln = ln
	slog.Info("db decoy listening", "addr", ln.Addr())
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

// Addr is the bound address (tests listen on :0).
func (s *Server) Addr() net.Addr {
	if s.ln == nil {
		return nil
	}
	return s.ln.Addr()
}

type conn struct {
	s       *Server
	c       net.Conn
	r       *bufio.Reader
	w       *bufio.Writer
	sess    *sensorkit.Session
	user    string
	db      string
	queries int
	stmts   map[string]string // prepared statement name -> query
	portals map[string]string // portal name -> query
	start   time.Time
}

func (s *Server) handle(ctx context.Context, nc net.Conn) {
	defer nc.Close()
	ip, port := splitAddr(nc.RemoteAddr())
	if s.cfg.Kit != nil && s.cfg.Kit.Blocked(ip) {
		return
	}
	c := &conn{s: s, c: nc, r: bufio.NewReader(nc), w: bufio.NewWriter(nc), stmts: map[string]string{},
		portals: map[string]string{}, start: time.Now()}
	if s.cfg.Kit != nil {
		c.sess = s.cfg.Kit.NewSession(ip, port, s.cfg.DstPort)
		s.cfg.Kit.Open()
		defer s.cfg.Kit.Done()
		c.event("conn.open", map[string]any{"client": "postgres"}, nil)
	}
	reason := "client"
	defer func() {
		c.event("conn.close", map[string]any{"duration_ms": time.Since(c.start).Milliseconds(), "reason": reason}, nil)
	}()
	_ = nc.SetDeadline(time.Now().Add(sessionCap))

	if !c.startup() {
		reason = "auth_failed"
		return
	}
	for {
		_ = nc.SetReadDeadline(time.Now().Add(idleTimeout))
		if s.cfg.Kit != nil && c.sess != nil && s.cfg.Kit.Killed(c.sess.ID) {
			c.fatal("57P01", "terminating connection due to administrator command")
			reason = "killed"
			return
		}
		typ, body, err := c.readMsg()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				reason = "timeout"
			}
			return
		}
		switch typ {
		case 'X':
			return
		case 'Q':
			c.simpleQuery(cstr(body))
		case 'P':
			name, rest := cut0(body)
			q, _ := cut0(rest)
			c.stmts[name] = q
			c.send('1', nil)
		case 'B':
			portal, rest := cut0(body)
			stmt, _ := cut0(rest)
			c.portals[portal] = c.stmts[stmt]
			c.send('2', nil)
		case 'D':
			if len(body) < 1 {
				continue
			}
			name, _ := cut0(body[1:])
			q := c.portals[name]
			if body[0] == 'S' {
				q = c.stmts[name]
				c.send('t', []byte{0, 0}) // no parameters
			}
			if res := c.s.data.Run(q, c.user, c.db); len(res.Columns) > 0 && res.Err == nil {
				c.rowDescription(res.Columns)
			} else {
				c.send('n', nil)
			}
		case 'E':
			name, _ := cut0(body)
			c.execute(c.portals[name], false)
		case 'C':
			c.send('3', nil)
		case 'S':
			c.ready()
		case 'H':
			_ = c.w.Flush()
		default:
			c.errorMsg("08P01", fmt.Sprintf("unsupported frontend message type %q", typ))
			c.ready()
		}
		if c.queries >= maxQueries {
			c.fatal("53300", "too many queries in this session")
			reason = "limit"
			return
		}
	}
}

// startup negotiates SSL (refused), reads the startup packet and checks the password.
func (c *conn) startup() bool {
	for {
		var n int32
		if err := binary.Read(c.r, binary.BigEndian, &n); err != nil || n < 8 || n > 10000 {
			return false
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(c.r, body); err != nil {
			return false
		}
		code := binary.BigEndian.Uint32(body[:4])
		switch code {
		case sslRequest, gssEncRequest:
			_, _ = c.c.Write([]byte{'N'})
			continue
		case cancelRequest:
			return false
		case protoV3:
		default:
			c.fatal("08P01", "unsupported frontend protocol")
			return false
		}
		params := map[string]string{}
		parts := strings.Split(string(body[4:]), "\x00")
		for i := 0; i+1 < len(parts); i += 2 {
			if parts[i] != "" {
				params[parts[i]] = parts[i+1]
			}
		}
		c.user = params["user"]
		c.db = params["database"]
		if c.db == "" {
			c.db = c.user
		}
		break
	}
	// cleartext password: lets us record which planted credential was used
	c.send('R', be32(3))
	_ = c.w.Flush()
	typ, body, err := c.readMsg()
	if err != nil || typ != 'p' {
		return false
	}
	pass := cstr(body)
	ok, token := c.s.checkPassword(c.user, pass)
	c.event("auth.attempt", map[string]any{"method": "password", "username": c.user, "password": pass,
		"success": ok, "database": c.db}, nil)
	if token != "" {
		c.event("token.used", map[string]any{"token_id": token, "token_kind": "db_cred", "via": "db_login"}, []string{token})
	}
	if !ok {
		time.Sleep(300 * time.Millisecond)
		c.fatal("28P01", fmt.Sprintf("password authentication failed for user %q", c.user))
		return false
	}
	if !c.s.knownDB(c.db) && c.db != "postgres" && c.db != c.user {
		c.fatal("3D000", fmt.Sprintf("database %q does not exist", c.db))
		return false
	}
	c.send('R', be32(0))
	for _, kv := range [][2]string{{"server_version", serverVersion}, {"server_encoding", "UTF8"},
		{"client_encoding", "UTF8"}, {"DateStyle", "ISO, MDY"}, {"integer_datetimes", "on"},
		{"standard_conforming_strings", "on"}, {"TimeZone", "Asia/Kolkata"}, {"application_name", ""}} {
		c.send('S', append(append([]byte(kv[0]), 0), append([]byte(kv[1]), 0)...))
	}
	c.send('K', append(be32(int32(time.Now().UnixNano()&0x7fff)), be32(int32(time.Now().Unix()&0x7fffffff))...))
	c.ready()
	return true
}

// checkPassword: the planted app credential (honeytoken) and the persona's weak postgres password are accepted.
func (s *Server) checkPassword(user, pass string) (bool, string) {
	if s.cfg.DBPass != "" && pass == s.cfg.DBPass {
		return true, "tok_db"
	}
	if user == "postgres" && s.cfg.Persona.RootPassword != "" && pass == s.cfg.Persona.RootPassword {
		return true, ""
	}
	return false, ""
}

func (c *conn) simpleQuery(sql string) {
	stmts := splitStatements(sql)
	if len(stmts) == 0 {
		c.send('I', nil)
	}
	for _, q := range stmts {
		if !c.execute(q, true) {
			break
		}
	}
	c.ready()
}

// execute answers one statement; withDescription is true for the simple protocol. Returns false on error.
func (c *conn) execute(q string, withDescription bool) bool {
	c.queries++
	res := c.s.data.Run(q, c.user, c.db)
	data := map[string]any{"query": truncate(q, 1000), "database": c.db, "user": c.user, "kind": res.Kind,
		"rows": len(res.Rows)}
	if res.Table != "" {
		data["table"] = res.Table
	}
	if res.Err != nil {
		data["error"] = res.Err.Code
	}
	c.event("db.query", data, nil)
	if res.Err != nil {
		c.errorMsg(res.Err.Code, res.Err.Msg)
		return false
	}
	if len(res.Columns) > 0 {
		if withDescription {
			c.rowDescription(res.Columns)
		}
		for _, row := range res.Rows {
			var b []byte
			b = append(b, be16(int16(len(row)))...)
			for _, v := range row {
				b = append(b, be32(int32(len(v)))...)
				b = append(b, v...)
			}
			c.send('D', b)
		}
	}
	c.send('C', append([]byte(res.Tag), 0))
	return true
}

func (c *conn) rowDescription(cols []string) {
	b := be16(int16(len(cols)))
	for _, name := range cols {
		b = append(b, name...)
		b = append(b, 0)
		b = append(b, be32(0)...)  // table oid
		b = append(b, be16(0)...)  // column number
		b = append(b, be32(25)...) // type oid: text
		b = append(b, be16(-1)...) // type size
		b = append(b, be32(-1)...) // type modifier
		b = append(b, be16(0)...)  // text format
	}
	c.send('T', b)
}

func (c *conn) ready() {
	c.send('Z', []byte{'I'})
	_ = c.w.Flush()
}

func (c *conn) errorMsg(code, msg string) {
	b := []byte{'S'}
	b = append(b, "ERROR\x00VERROR\x00C"...)
	b = append(b, code...)
	b = append(b, 0, 'M')
	b = append(b, msg...)
	b = append(b, 0, 0)
	c.send('E', b)
}

func (c *conn) fatal(code, msg string) {
	b := []byte("SFATAL\x00VFATAL\x00C" + code + "\x00M" + msg + "\x00\x00")
	c.send('E', b)
	_ = c.w.Flush()
}

func (c *conn) send(typ byte, body []byte) {
	_ = c.w.WriteByte(typ)
	_, _ = c.w.Write(be32(int32(len(body) + 4)))
	_, _ = c.w.Write(body)
}

func (c *conn) readMsg() (byte, []byte, error) {
	typ, err := c.r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	var n int32
	if err := binary.Read(c.r, binary.BigEndian, &n); err != nil {
		return 0, nil, err
	}
	if n < 4 || n > maxMessage {
		return 0, nil, fmt.Errorf("bad message length %d", n)
	}
	body := make([]byte, n-4)
	_, err = io.ReadFull(c.r, body)
	return typ, body, err
}

func (c *conn) event(typ string, data map[string]any, tokens []string) {
	if c.sess != nil {
		c.sess.Event(typ, "svc_db", data, nil, tokens)
	}
}

func splitAddr(a net.Addr) (string, int) {
	if t, ok := a.(*net.TCPAddr); ok {
		ip := t.IP.String()
		if ip == "::1" {
			ip = "127.0.0.1"
		}
		if ip4 := t.IP.To4(); ip4 != nil {
			ip = ip4.String()
		}
		return ip, t.Port
	}
	return "127.0.0.1", 0
}

func be32(v int32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, uint32(v)); return b }
func be16(v int16) []byte { b := make([]byte, 2); binary.BigEndian.PutUint16(b, uint16(v)); return b }

func cstr(b []byte) string { s, _ := cut0(b); return s }

func cut0(b []byte) (string, []byte) {
	for i, x := range b {
		if x == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
