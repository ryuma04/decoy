package divert

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/ryuma04/decoy/backend/internal/decoy/web"
	"github.com/ryuma04/decoy/backend/internal/mlclient"
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

	oddSearchRegex = regexp.MustCompile(`[~^\{\}\[\]\$` + "`" + `]|(^'|'$|'\s|\s'|""|\")`)
)

// Tripwire satisfies the divert.Classifier interface (docs/18 Task 10).
type Tripwire struct {
	ml *mlclient.Client
}

func NewTripwire(ml ...*mlclient.Client) *Tripwire {
	var c *mlclient.Client
	if len(ml) > 0 {
		c = ml[0]
	}
	return &Tripwire{ml: c}
}

// Classify inspects request attributes and visitor history.
func (tw *Tripwire) Classify(r *http.Request, body []byte, v VisitorView) Trip {
	path := strings.ToLower(r.URL.Path)
	ua := strings.ToLower(r.UserAgent())

	// 1. Hard check: path traversal in URL path
	if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") {
		return Trip{
			Sev:    SevHard,
			Reason: "path traversal in URL path",
			Label:  "path_traversal",
			Param:  "path",
			Value:  r.URL.Path,
		}
	}

	// 2. Hard check: files Next.js never serves
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
	path := r.URL.Path

	// 1. Check path traversal in URL path
	if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.RawPath, "..") {
		return Trip{
			Sev:    SevHard,
			Reason: "path traversal in URL path",
			Label:  "path_traversal",
			Param:  "path",
			Value:  r.URL.Path,
		}, true
	}

	// 2. Check query string
	for k, vv := range r.URL.Query() {
		for _, v := range vv {
			if label, ok := tw.classifyValue(k, v, path, "query"); ok {
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

	// 3. Check body for URL-encoded, form, or raw payloads
	if len(body) > 0 && len(body) <= 65536 {
		bodyStr := string(body)
		if vals, err := url.ParseQuery(bodyStr); err == nil && len(vals) > 0 {
			for k, vv := range vals {
				for _, v := range vv {
					if label, ok := tw.classifyValue(k, v, path, "form"); ok {
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
			// Direct check on body text (JSON or raw)
			if label, ok := tw.classifyValue("body", bodyStr, path, "body"); ok {
				return Trip{
					Sev:    SevHard,
					Reason: "injection payload in request body",
					Label:  label,
					Param:  "body",
					Value:  bodyStr,
				}, true
			}
		}
	}

	return Trip{}, false
}

func (tw *Tripwire) classifyValue(param, val, path, field string) (string, bool) {
	// First check explicit path traversal
	if strings.Contains(val, "../") || strings.Contains(val, "..\\") {
		return "path_traversal", true
	}

	res := web.CheckInput(val)
	// ONLY values that match an actual exploitation separator trigger the pre-check!
	if !res.IsSuspicious || res.Separator == "" {
		return "", false
	}

	// If ML service is configured, query it
	if tw.ml != nil && tw.ml.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		mlRes, err := tw.ml.ClassifyInput(ctx, param, val, "web", path, field)
		if err == nil {
			if mlRes.Label != "normal" && mlRes.Label != "" {
				return mlRes.Label, true
			}
			if mlRes.Risk < 0.2 {
				return "", false
			}
		}
	}

	// Fallback to pre-check alone
	label := classifyPrecheck(res)
	return label, true
}

func classifyPrecheck(res web.PrecheckResult) string {
	s := strings.ToLower(res.Separator)
	p := strings.ToLower(res.Payload)

	// Check separator type
	switch s {
	case "' or", "union select", "--":
		return "sqli"
	case "<script":
		return "xss"
	case "../":
		return "path_traversal"
	case ";", "&&", "||", "|", "`", "$(", "%0a", "\n":
		return "cmd_injection"
	}

	// Fallback on payload
	if strings.Contains(p, "union select") || strings.Contains(p, "' or") || strings.Contains(p, "--") {
		return "sqli"
	}
	if strings.Contains(p, "<script") || strings.Contains(p, "javascript:") || strings.Contains(p, "onerror") {
		return "xss"
	}
	if strings.Contains(p, "../") || strings.Contains(p, "..\\") {
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
