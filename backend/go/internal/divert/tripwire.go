package divert

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/ryuma04/decoy/backend/internal/decoy/web"
)

var (
	sensitivePaths = []string{
		"/.env", "/.env.bak", "/.git", "/wp-admin", "/wp-login.php",
		"/config.php", "/backup.zip", "/etc/passwd", "/.aws", "/.ssh",
		"/phpmyadmin", "/.env.local", "/.env.production", "/web.config",
	}

	offensiveTools = []string{
		"sqlmap", "nikto", "nmap", "gobuster", "dirbuster",
		"hydra", "masscan", "wpscan", "acunetix", "nessus", "burpsuite",
	}

	scriptedClients = []string{
		"python-requests", "curl/", "wget/", "go-http-client/", "aiohttp", "httpie",
	}

	oddSearchRegex = regexp.MustCompile(`[~^\{\}\[\]\$]`)
)

// Tripwire satisfies the divert.Classifier interface (docs/18 Task 10).
type Tripwire struct{}

func NewTripwire() *Tripwire {
	return &Tripwire{}
}

// Classify inspects request attributes and visitor history.
func (tw *Tripwire) Classify(r *http.Request, body []byte, v VisitorView) Trip {
	path := strings.ToLower(r.URL.Path)
	ua := strings.ToLower(r.UserAgent())

	// 1. Hard check: files Next.js never serves
	for _, sp := range sensitivePaths {
		if strings.HasPrefix(path, sp) || strings.Contains(path, sp) {
			return Trip{
				Sev:    SevHard,
				Reason: "sensitive path access: " + path,
				Label:  "sensitive_path",
				Param:  "path",
				Value:  path,
			}
		}
	}

	// 2. Hard check: offensive tool user agents
	for _, tool := range offensiveTools {
		if strings.Contains(ua, tool) {
			return Trip{
				Sev:    SevHard,
				Reason: "offensive scanner user-agent: " + tool,
				Label:  "scanner",
				Param:  "User-Agent",
				Value:  r.UserAgent(),
			}
		}
	}

	// 3. Hard check: repeated failed admin logins
	if v.FailedLogins10m >= 5 {
		return Trip{
			Sev:    SevHard,
			Reason: "repeated failed admin logins",
			Label:  "bruteforce",
			Param:  "path",
			Value:  path,
		}
	}

	// 4. Hard check: injection payloads in query parameters, path, or body
	if trip, found := tw.checkInjections(r, body); found {
		return trip
	}

	// 5. Soft check: burst of 404s
	if v.NotFound5m >= 5 {
		return Trip{
			Sev:    SevSoft,
			Reason: "burst of 404 not found requests",
			Label:  "probe",
			Param:  "status",
			Value:  "404",
		}
	}

	// 6. Soft check: scripted client (curl/python without browser headers)
	for _, sc := range scriptedClients {
		if strings.Contains(ua, sc) && !strings.Contains(ua, "mozilla") && !strings.Contains(ua, "chrome") {
			return Trip{
				Sev:    SevSoft,
				Reason: "scripted HTTP client: " + sc,
				Label:  "scanner",
				Param:  "User-Agent",
				Value:  r.UserAgent(),
			}
		}
	}

	// 7. Soft check: odd characters in search query
	query := r.URL.Query()
	for param, vals := range query {
		if param == "q" || param == "search" || param == "query" {
			for _, val := range vals {
				if oddSearchRegex.MatchString(val) {
					return Trip{
						Sev:    SevSoft,
						Reason: "odd characters in search query",
						Label:  "probe",
						Param:  param,
						Value:  val,
					}
				}
			}
		}
	}

	// 8. Soft check: high request rate
	if v.RequestsPerMin >= 30 {
		return Trip{
			Sev:    SevSoft,
			Reason: "high request rate",
			Label:  "probe",
			Param:  "rate",
			Value:  "requests_per_min",
		}
	}

	// 9. Clean request
	return Trip{Sev: SevNone}
}

func (tw *Tripwire) checkInjections(r *http.Request, body []byte) (Trip, bool) {
	// Check query string
	for k, vv := range r.URL.Query() {
		for _, v := range vv {
			if res := web.CheckInput(v); res.IsSuspicious {
				label := classifyPrecheck(res)
				return Trip{
					Sev:    SevHard,
					Reason: "injection payload in query: " + k,
					Label:  label,
					Param:  k,
					Value:  v,
				}, true
			}
		}
	}

	// Check path traversal
	if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") {
		return Trip{
			Sev:    SevHard,
			Reason: "path traversal in URL path",
			Label:  "path_traversal",
			Param:  "path",
			Value:  r.URL.Path,
		}, true
	}

	// Check body for URL-encoded or form payloads
	if len(body) > 0 && len(body) <= 65536 {
		bodyStr := string(body)
		if vals, err := url.ParseQuery(bodyStr); err == nil && len(vals) > 0 {
			for k, vv := range vals {
				for _, v := range vv {
					if res := web.CheckInput(v); res.IsSuspicious {
						label := classifyPrecheck(res)
						return Trip{
							Sev:    SevHard,
							Reason: "injection payload in body param: " + k,
							Label:  label,
							Param:  k,
							Value:  v,
						}, true
					}
				}
			}
		} else {
			// Direct check on body text
			if res := web.CheckInput(bodyStr); res.IsSuspicious {
				label := classifyPrecheck(res)
				return Trip{
					Sev:    SevHard,
					Reason: "injection payload in request body",
					Label:  label,
					Param:  "body",
					Value:  res.Payload,
				}, true
			}
		}
	}

	return Trip{}, false
}

func classifyPrecheck(res web.PrecheckResult) string {
	p := strings.ToLower(res.Payload)
	s := strings.ToLower(res.Separator)
	combined := p + " " + s

	if strings.Contains(combined, "' or") || strings.Contains(combined, "union select") || strings.Contains(combined, "--") {
		return "sqli"
	}
	if strings.Contains(combined, "<script") || strings.Contains(combined, "javascript:") || strings.Contains(combined, "onerror") {
		return "xss"
	}
	if strings.Contains(combined, "..") || strings.Contains(combined, "/etc/") {
		return "path_traversal"
	}
	return "cmd_injection"
}

// DrainBody reads and returns the full request body while preserving r.Body.
func DrainBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
	return b, nil
}
