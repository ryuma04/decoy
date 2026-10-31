package sensorauth

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"
)

var (
	now  = time.Date(2026, 11, 14, 9, 2, 12, 0, time.UTC)
	keys = map[string]string{"ssh-01": "secret-key-0123456789"}
)

// Fixed vector (computed independently with Python's hmac module) so a client in any language can check itself.
func TestSignatureFixedVector(t *testing.T) {
	const want = "bce177f545644979dc031d59e7676e1cd35d381666f94e007d4f7f35aea1be27"
	got := Signature("secret-key-0123456789", "2026-11-14T09:02:12Z", "POST", "/v1/ingest/events", []byte(`[]`))
	if got != want {
		t.Fatalf("got %s want %s", got, want)
	}
	if got != Signature("secret-key-0123456789", "2026-11-14T09:02:12Z", "post", "/v1/ingest/events", []byte(`[]`)) {
		t.Fatal("method must be case-insensitive")
	}
}

func TestVerify(t *testing.T) {
	body := []byte(`[{"x":1}]`)
	cases := []struct {
		name    string
		id, key string
		at      time.Time
		tamper  bool
		wantErr error
	}{
		{"ok", "ssh-01", "secret-key-0123456789", now, false, nil},
		{"wrong key", "ssh-01", "other-key-0123456789", now, false, ErrSignature},
		{"unknown sensor", "web-01", "secret-key-0123456789", now, false, ErrUnknown},
		{"old", "ssh-01", "secret-key-0123456789", now.Add(-3 * time.Minute), false, ErrSkew},
		{"future", "ssh-01", "secret-key-0123456789", now.Add(3 * time.Minute), false, ErrSkew},
		{"body changed", "ssh-01", "secret-key-0123456789", now, true, ErrSignature},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/v1/ingest/events", bytes.NewReader(body))
			Sign(r, c.id, c.key, body, c.at)
			b := body
			if c.tamper {
				b = []byte(`[{"x":2}]`)
			}
			id, err := Verify(r, b, keys, now)
			if err != c.wantErr {
				t.Fatalf("err = %v, want %v", err, c.wantErr)
			}
			if err == nil && id != "ssh-01" {
				t.Fatalf("id = %q", id)
			}
		})
	}
	r := httptest.NewRequest("POST", "/v1/ingest/events", nil)
	if _, err := Verify(r, nil, keys, now); err != ErrMissing {
		t.Fatalf("missing headers: %v", err)
	}
}
