package api

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ryuma04/decoy/backend/internal/bus"
	"github.com/ryuma04/decoy/backend/internal/store"
)

type fakeStore struct{ user store.User }

func (f *fakeStore) UserByEmail(_ context.Context, email string) (store.User, error) {
	if email != f.user.Email {
		return store.User{}, store.ErrNotFound
	}
	return f.user, nil
}

func (f *fakeStore) ListEvents(context.Context, store.EventFilter) ([]store.StoredEvent, string, error) {
	return []store.StoredEvent{{EventID: "01J", Type: "shell.command", Data: json.RawMessage(`{"raw":"id"}`)}}, "next", nil
}

func (f *fakeStore) GetEvent(_ context.Context, id string) (store.StoredEvent, error) {
	if id != "01J" {
		return store.StoredEvent{}, store.ErrNotFound
	}
	return store.StoredEvent{EventID: "01J", Type: "shell.command", Envelope: json.RawMessage(`{"x":1}`)}, nil
}

func newServer(t *testing.T) (*Server, *http.ServeMux, *bus.Memory) {
	t.Helper()
	hash, _ := HashPassword("correct horse")
	b := bus.NewMemory()
	hub := NewHub()
	hub.Ping = 20 * time.Millisecond
	go hub.Run(b)
	s := &Server{Store: &fakeStore{user: store.User{UserID: "u1", Email: "admin@soc.local", PasswordHash: hash, Role: "admin"}},
		Bus: b, Auth: &Auth{Secret: []byte(strings.Repeat("k", 32)), TTL: time.Hour}, Hub: hub}
	mux := http.NewServeMux()
	s.Routes(mux)
	return s, mux, b
}

func login(t *testing.T, mux *http.ServeMux, pw string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"email":"admin@soc.local","password":"`+pw+`"}`))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestLoginAndProtectedRoutes(t *testing.T) {
	_, mux, _ := newServer(t)
	if w := login(t, mux, "wrong"); w.Code != 401 {
		t.Fatalf("wrong password: %d", w.Code)
	}
	w := login(t, mux, "correct horse")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"role":"admin"`) {
		t.Fatalf("login %d %s", w.Code, w.Body)
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != cookieName || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("cookie %+v", cookie)
	}

	get := func(path string, withCookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if withCookie {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := get("/v1/events", false); w.Code != 401 {
		t.Fatalf("no cookie: %d", w.Code)
	}
	w = get("/v1/events", true)
	var l struct {
		Items      []map[string]any `json:"items"`
		NextCursor *string          `json:"next_cursor"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &l)
	if w.Code != 200 || len(l.Items) != 1 || l.Items[0]["summary"] != "id" || l.NextCursor == nil || *l.NextCursor != "next" {
		t.Fatalf("events %d %s", w.Code, w.Body)
	}
	if _, ok := l.Items[0]["actor_id"]; !ok {
		t.Fatal("actor_id must be present as null")
	}
	if w := get("/v1/events/01J", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"envelope":{"x":1}`) {
		t.Fatalf("event %d %s", w.Code, w.Body)
	}
	if w := get("/v1/events/nope", true); w.Code != 404 {
		t.Fatalf("missing event %d", w.Code)
	}
	if w := get("/v1/events?limit=500", true); w.Code != 400 {
		t.Fatalf("bad limit %d", w.Code)
	}
	if w := get("/v1/auth/me", true); !strings.Contains(w.Body.String(), "admin@soc.local") {
		t.Fatalf("me %s", w.Body)
	}
}

func TestLoginRateLimit(t *testing.T) {
	_, mux, _ := newServer(t)
	for i := 0; i < 10; i++ {
		login(t, mux, "wrong")
	}
	if w := login(t, mux, "correct horse"); w.Code != 429 {
		t.Fatalf("11th attempt: %d", w.Code)
	}
}

func TestExpiredTokenRejected(t *testing.T) {
	a := &Auth{Secret: []byte(strings.Repeat("k", 32)), TTL: time.Minute, Now: func() time.Time { return time.Now().Add(-time.Hour) }}
	tok, _ := a.Issue(User{UserID: "u1", Role: "admin"})
	a.Now = nil
	if _, err := a.Parse(tok); err == nil {
		t.Fatal("expired token accepted")
	}
	other := &Auth{Secret: []byte(strings.Repeat("x", 32)), TTL: time.Hour}
	tok2, _ := other.Issue(User{UserID: "u1", Role: "admin"})
	if _, err := a.Parse(tok2); err == nil {
		t.Fatal("token signed with another secret accepted")
	}
}

func TestStreamDeliversEvents(t *testing.T) {
	s, mux, b := newServer(t)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	tok, _ := s.Auth.Issue(User{UserID: "u1", Role: "analyst"})
	req, _ := http.NewRequest("GET", srv.URL+"/v1/stream", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: tok})
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("stream: %v %v", err, resp)
	}
	defer resp.Body.Close()
	for s.Hub.Clients() == 0 {
		time.Sleep(5 * time.Millisecond)
	}
	b.Publish(bus.TopicEvent, store.StoredEvent{EventID: "E1", Type: "shell.command", Data: json.RawMessage(`{"raw":"whoami"}`)})
	sc := bufio.NewScanner(resp.Body)
	deadline := time.After(2 * time.Second)
	got := make(chan string)
	go func() {
		var name string
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "event: ") {
				name = strings.TrimPrefix(line, "event: ")
			}
			if strings.HasPrefix(line, "data: ") && name == "event" {
				got <- line
				return
			}
		}
	}()
	select {
	case line := <-got:
		if !strings.Contains(line, `"summary":"whoami"`) {
			t.Fatalf("data %s", line)
		}
	case <-deadline:
		t.Fatal("no event within 2 s")
	}
}
