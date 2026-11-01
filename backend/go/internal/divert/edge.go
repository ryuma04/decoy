package divert

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Behind a Cloudflare Tunnel every request reaches the proxy from cloudflared on loopback over plain HTTP.
// These helpers recover the visitor's real address and scheme from Cloudflare's headers, but only when the
// operator enabled TrustCloudflare AND the TCP peer is loopback: from anywhere else the headers are forgeable.

type ctxKey int

const secureCtxKey ctxKey = 1

// edgeAddr returns the visitor's IP and port and whether the visitor's own connection used TLS.
func (p *Proxy) edgeAddr(r *http.Request) (ip string, port int, secure bool) {
	ip, port = parseRemoteAddr(r.RemoteAddr)
	secure = r.TLS != nil
	if !p.cfg.TrustCloudflare || !isLoopbackIP(ip) {
		return ip, port, secure
	}
	if h := cleanIP(r.Header.Get("CF-Connecting-IP")); h != "" {
		ip = h
	} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if h := cleanIP(strings.Split(xff, ",")[0]); h != "" {
			ip = h
		}
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		secure = true
	}
	return ip, port, secure
}

// withEdge rewrites the request so every later step (visitor key, policy, sensorkit session, X-Forwarded-For
// sent upstream) sees the visitor's real address, and remembers that the visitor is on HTTPS.
func (p *Proxy) withEdge(r *http.Request) (*http.Request, string, int, bool) {
	ip, port, secure := p.edgeAddr(r)
	r.RemoteAddr = net.JoinHostPort(ip, strconv.Itoa(port))
	if secure && r.TLS == nil {
		r = r.WithContext(context.WithValue(r.Context(), secureCtxKey, true))
	}
	return r, ip, port, secure
}

func isSecureRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	v, _ := r.Context().Value(secureCtxKey).(bool)
	return v
}

func isLoopbackIP(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.IsLoopback()
}

func cleanIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

// requestHost is the public Host of the request in lower case, without a port.
func requestHost(r *http.Request) string {
	h := strings.ToLower(strings.TrimSpace(r.Host))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// stripSecureCookies removes the Secure attribute from every Set-Cookie header (visitor on plain HTTP).
func stripSecureCookies(h http.Header) {
	cs := h.Values("Set-Cookie")
	if len(cs) == 0 {
		return
	}
	h.Del("Set-Cookie")
	for _, c := range cs {
		parts := strings.Split(c, ";")
		kept := parts[:1]
		for _, a := range parts[1:] {
			if !strings.EqualFold(strings.TrimSpace(a), "secure") {
				kept = append(kept, a)
			}
		}
		h.Add("Set-Cookie", strings.Join(kept, ";"))
	}
}

// bodySample is the first 512 bytes of a request body for the SOC, with every password-like field masked:
// a mistyped staff password must never reach events, logs or the database.
func bodySample(r *http.Request, body []byte) string {
	out := string(body)
	if len(body) > 0 {
		trimmed := strings.TrimSpace(out)
		switch {
		case strings.HasPrefix(trimmed, "{"):
			var m map[string]any
			if json.Unmarshal(body, &m) == nil {
				redactMap(m)
				if b, err := json.Marshal(m); err == nil {
					out = string(b)
				}
			} else if looksSecret(out) {
				out = "[redacted]"
			}
		case strings.Contains(strings.ToLower(r.Header.Get("Content-Type")), "x-www-form-urlencoded") || strings.Contains(out, "="):
			if q, err := url.ParseQuery(out); err == nil && len(q) > 0 {
				for k := range q {
					if isSecretKey(k) {
						q[k] = []string{"[redacted]"}
					}
				}
				out = q.Encode()
			} else if looksSecret(out) {
				out = "[redacted]"
			}
		}
	}
	if len(out) > 512 {
		out = out[:512]
	}
	return out
}

func redactMap(m map[string]any) {
	for k, v := range m {
		if isSecretKey(k) {
			m[k] = "[redacted]"
			continue
		}
		if sub, ok := v.(map[string]any); ok {
			redactMap(sub)
		}
	}
}

func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	return strings.Contains(k, "pass") || strings.Contains(k, "pwd")
}

func looksSecret(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "pass") || strings.Contains(s, "pwd")
}

// secureUpstreamRedirect: a visitor on HTTPS must get https:// redirects from either shop (both are told plain HTTP).
func secureUpstreamRedirect(resp *http.Response) {
	if resp.Request == nil || !isSecureRequest(resp.Request) {
		return
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, "http://") {
		return
	}
	u, err := url.Parse(loc)
	if err != nil || !strings.EqualFold(u.Hostname(), requestHost(resp.Request)) {
		return
	}
	u.Scheme = "https"
	if u.Port() == "80" {
		u.Host = u.Hostname()
	}
	resp.Header.Set("Location", u.String())
}
