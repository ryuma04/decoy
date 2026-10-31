package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/ryuma04/decoy/backend/internal/store"
)

const cookieName = "dsoc_session"

type ctxKey struct{}

type claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

// Auth issues and checks the JWT session cookie.
type Auth struct {
	Secret []byte
	TTL    time.Duration
	Secure bool
	Now    func() time.Time
}

func (a *Auth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

func (a *Auth) Issue(u User) (string, error) {
	now := a.now()
	c := claims{Role: u.Role, Email: u.Email, RegisteredClaims: jwt.RegisteredClaims{
		Subject: u.UserID, IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(now.Add(a.TTL)),
		Issuer: "dsoc-core",
	}}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString(a.Secret)
}

func (a *Auth) Parse(token string) (User, error) {
	var c claims
	_, err := jwt.ParseWithClaims(token, &c, func(t *jwt.Token) (any, error) { return a.Secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer("dsoc-core"), jwt.WithTimeFunc(a.now))
	if err != nil {
		return User{}, err
	}
	if c.Subject == "" || (c.Role != "analyst" && c.Role != "admin") {
		return User{}, errors.New("bad claims")
	}
	return User{UserID: c.Subject, Email: c.Email, Role: c.Role}, nil
}

func (a *Auth) setCookie(w http.ResponseWriter, token string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: a.Secure,
		SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

// Require wraps h so it only runs for a logged-in user (admin=true: admin role only).
func (a *Auth) Require(admin bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "login required")
			return
		}
		u, err := a.Parse(c.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthorized", "session expired or invalid")
			return
		}
		if admin && u.Role != "admin" {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, u)))
	}
}

// CurrentUser returns the user set by Require.
func CurrentUser(r *http.Request) User {
	u, _ := r.Context().Value(ctxKey{}).(User)
	return u
}

// HashPassword is used by `core seed-admin`.
func HashPassword(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

// dummyHash is compared against when the email is unknown, so response time does not reveal which emails exist.
var dummyHash = sync.OnceValue(func() []byte {
	b, _ := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcrypt.DefaultCost)
	return b
})

// loginLimiter allows 10 login attempts per minute per client IP.
type loginLimiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

func (l *loginLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.hits == nil {
		l.hits = map[string][]time.Time{}
	}
	keep := l.hits[ip][:0]
	for _, t := range l.hits[ip] {
		if now.Sub(t) < time.Minute {
			keep = append(keep, t)
		}
	}
	if len(keep) >= 10 {
		l.hits[ip] = keep
		return false
	}
	l.hits[ip] = append(keep, now)
	return true
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allow(clientIP(r), s.Auth.now()) {
		writeError(w, http.StatusTooManyRequests, "rate_limited", "too many login attempts; wait a minute")
		return
	}
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.Store.UserByEmail(r.Context(), body.Email)
	if errors.Is(err, store.ErrNotFound) {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(body.Password)) // same cost as a real check
		writeError(w, http.StatusUnauthorized, "bad_credentials", "wrong email or password")
		return
	}
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "try again")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(body.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "bad_credentials", "wrong email or password")
		return
	}
	user := User{UserID: u.UserID, Email: u.Email, Role: u.Role}
	token, err := s.Auth.Issue(user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "could not issue session")
		return
	}
	s.Auth.setCookie(w, token, int(s.Auth.TTL.Seconds()))
	writeJSON(w, http.StatusOK, map[string]any{"user": user})
}

func (s *Server) logout(w http.ResponseWriter, _ *http.Request) {
	s.Auth.setCookie(w, "", -1)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"user": CurrentUser(r)})
}
