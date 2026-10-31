package db

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ryuma04/decoy/backend/internal/persona"
)

const testPass = "Tok3nDbPassw0rd"

func startServer(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := New(Config{Addr: "127.0.0.1:0", Persona: persona.Generate("test-seed"), DBPass: testPass})
	go func() { _ = s.ListenAndServe(ctx) }()
	for i := 0; i < 100 && s.Addr() == nil; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if s.Addr() == nil {
		t.Fatal("server did not start")
	}
	return s.Addr().String()
}

func connect(t *testing.T, addr, user, pass string, simple bool) (*pgx.Conn, error) {
	t.Helper()
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s:%s@%s/orders?sslmode=disable&connect_timeout=3", user, pass, addr))
	if err != nil {
		t.Fatal(err)
	}
	if simple {
		cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

func TestWrongPasswordRejected(t *testing.T) {
	addr := startServer(t)
	_, err := connect(t, addr, "app", "guess", true)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "28P01" {
		t.Fatalf("want 28P01, got %v", err)
	}
}

func TestPlantedCredentialReadsFakeTables(t *testing.T) {
	addr := startServer(t)
	for _, simple := range []bool{true, false} {
		c, err := connect(t, addr, "app", testPass, simple)
		if err != nil {
			t.Fatalf("simple=%v: connect: %v", simple, err)
		}
		ctx := context.Background()
		var v string
		if err := c.QueryRow(ctx, "select version()").Scan(&v); err != nil || !strings.HasPrefix(v, "PostgreSQL 14") {
			t.Fatalf("simple=%v: version %q %v", simple, v, err)
		}
		rows, err := c.Query(ctx, "SELECT email, city FROM customers LIMIT 3")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for rows.Next() {
			var email, city string
			if err := rows.Scan(&email, &city); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(email, "@") {
				t.Fatalf("bad email %q", email)
			}
			n++
		}
		rows.Close()
		if n != 3 {
			t.Fatalf("simple=%v: want 3 rows, got %d", simple, n)
		}
		var cnt string
		if err := c.QueryRow(ctx, "select count(*) from payments").Scan(&cnt); err != nil || cnt != "60" {
			t.Fatalf("count %q %v", cnt, err)
		}
		_ = c.Close(ctx)
	}
}

func TestWritesAndPrivilegedCallsDenied(t *testing.T) {
	addr := startServer(t)
	c, err := connect(t, addr, "app", testPass, true)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(context.Background())
	for q, code := range map[string]string{
		"DELETE FROM customers":              "42501",
		"DROP TABLE orders":                  "42501",
		"COPY customers TO PROGRAM 'id'":     "42501",
		"SELECT pg_read_file('/etc/passwd')": "42501",
		"SELECT * FROM secrets":              "42P01",
		"SELECT nosuchcolumn FROM customers": "42703",
		"hello world":                        "42601",
	} {
		_, err := c.Exec(context.Background(), q)
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != code {
			t.Errorf("%q: want %s, got %v", q, code, err)
		}
	}
}

func TestQueryKinds(t *testing.T) {
	d := NewDataset(persona.Generate("x"))
	for q, kind := range map[string]string{
		"SELECT * FROM staff_users":                          "read",
		"select table_name from information_schema.tables":   "recon",
		"SELECT n.nspname FROM pg_catalog.pg_class c JOIN x": "recon",
		"UPDATE orders SET status='x'":                       "write",
		"select 1":                                           "session",
	} {
		if r := d.Run(q, "app", "orders"); r.Kind != kind {
			t.Errorf("%q: kind %s, want %s", q, r.Kind, kind)
		}
	}
	if r := d.Run("SELECT * FROM orders WHERE id = 1005", "app", "orders"); len(r.Rows) != 1 {
		t.Errorf("where id: %d rows", len(r.Rows))
	}
}

func TestSplitStatements(t *testing.T) {
	got := splitStatements("select 1; select 'a;b' ;; ")
	if len(got) != 2 || got[1] != "select 'a;b'" {
		t.Fatalf("%q", got)
	}
}
