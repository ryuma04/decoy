package divert

import (
	"bytes"
	"context"
	"encoding/json"
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

	oddSearchRegex = regexp.MustCompile(`[~^\{\}\[\]\$` + "`" + `]`)
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

	// 3. Hard check: offensive tool user agents
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

	// 4. Hard check: repeated failed admin logins
	if v.FailedLogins10m >= 5 {
		return Trip{
			Sev:    SevHard,
			Reason: "repeated failed admin logins",
			Label:  "bruteforce",
			Param:  "path",
			Value:  path,
		}
	}

	// 5. Injection payloads in query parameters, path, or body (JSON, form, raw)
	if trip, found := tw.checkInjections(r, body); found {
		return trip
	}

	// 6. Soft check: burst of 404s
	if v.NotFound5m >= 5 {
		return Trip{
			Sev:    SevSoft,
			Reason: "burst of 404 not found requests",
			Label:  "probe",
			Param:  "status",
			Value:  "404",
		}
	}

	// 7. Soft check: scripted client (curl/python without browser headers)
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

	// 8. Soft check: odd characters in search query
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

	// 9. Soft check: high request rate
	if v.RequestsPerMin >= 30 {
		return Trip{
			Sev:    SevSoft,
			Reason: "high request rate",
			Label:  "probe",
			Param:  "rate",
			Value:  "requests_per_min",
		}
	}

	// 10. Clean request
	return Trip{Sev: SevNone}
}

type bodyField struct {
	param string
	value string
}

func extractJSONStrings(data any, prefix string, out *[]bodyField) {
	switch v := data.(type) {
	case map[string]any:
		for k, val := range v {
			fullName := k
			if prefix != "" {
				fullName = prefix + "." + k
			}
			switch s := val.(type) {
			case string:
				*out = append(*out, bodyField{param: k, value: s})
			case map[string]any, []any:
				extractJSONStrings(s, fullName, out)
			}
		}
	case []any:
		for _, item := range v {
			extractJSONStrings(item, prefix, out)
		}
	}
}

func isFreeTextField(param string) bool {
	p := strings.ToLower(strings.TrimSpace(param))
	switch p {
	case "message", "notes", "note", "name", "address", "search", "q", "query", "comment", "comments", "feedback", "body":
		return true
	}
	for _, suffix := range []string{"_name", ".name", "-name", "_address", ".address", "-address", "_notes", "_message"} {
		if strings.HasSuffix(p, suffix) {
			if p == "filename" || p == "file_name" || p == "tablename" || p == "table_name" || p == "dbname" || p == "db_name" {
				return false
			}
			return true
		}
	}
	return false
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
			if trip, ok := tw.gradeParam(k, v, path, "query"); ok {
				return trip, true
			}
		}
	}

	// 3. Check body for JSON, form-encoded, or raw payloads
	if len(body) > 0 && len(body) <= 65536 {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		trimmed := bytes.TrimSpace(body)
		isJSON := strings.Contains(ct, "application/json") ||
			bytes.HasPrefix(trimmed, []byte("{")) ||
			bytes.HasPrefix(trimmed, []byte("["))

		if isJSON {
			var parsed any
			if err := json.Unmarshal(body, &parsed); err == nil {
				var fields []bodyField
				extractJSONStrings(parsed, "", &fields)
				for _, f := range fields {
					if trip, ok := tw.gradeParam(f.param, f.value, path, "json"); ok {
						return trip, true
					}
				}
				return Trip{}, false
			}
		}

		// Form body check
		if strings.Contains(ct, "application/x-www-form-urlencoded") || bytes.Contains(body, []byte("=")) {
			bodyStr := string(body)
			if vals, err := url.ParseQuery(bodyStr); err == nil && len(vals) > 0 {
				for k, vv := range vals {
					for _, v := range vv {
						if trip, ok := tw.gradeParam(k, v, path, "form"); ok {
							return trip, true
						}
					}
				}
				return Trip{}, false
			}
		}

		// Direct check on raw body
		bodyStr := string(body)
		if trip, ok := tw.gradeParam("body", bodyStr, path, "body"); ok {
			return trip, true
		}
	}

	return Trip{}, false
}

func (tw *Tripwire) gradeParam(param, val, path, field string) (Trip, bool) {
	if val == "" {
		return Trip{}, false
	}

	res := web.CheckInput(val)
	hasExploit := res.IsSuspicious && res.Separator != ""
	if !hasExploit {
		lower := strings.ToLower(val)
		if strings.Contains(lower, "<script") ||
			strings.Contains(lower, "union select") ||
			strings.Contains(lower, "javascript:") ||
			strings.Contains(lower, "onerror=") ||
			strings.Contains(lower, "../") ||
			strings.Contains(lower, "..\\") {
			hasExploit = true
		}
	}

	if !hasExploit {
		return Trip{}, false
	}

	// Free-text fields (message, notes, name, address, search):
	// Must NEVER be diverted on the separator pre-check alone.
	if isFreeTextField(param) {
		if tw.ml != nil && tw.ml.Enabled() {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			mlRes, err := tw.ml.ClassifyInput(ctx, param, val, "web", path, field)
			if err == nil {
				if mlRes.Risk >= 0.8 {
					lbl := mlRes.Label
					if lbl == "" || lbl == "normal" {
						lbl = classifyPrecheck(res)
					}
					return Trip{
						Sev:    SevHard,
						Reason: "injection payload in " + field + " param: " + param,
						Label:  lbl,
						Param:  param,
						Value:  val,
					}, true
				} else if mlRes.Risk >= 0.5 {
					lbl := mlRes.Label
					if lbl == "" || lbl == "normal" {
						lbl = classifyPrecheck(res)
					}
					return Trip{
						Sev:    SevSoft,
						Reason: "suspicious input in " + field + " param: " + param,
						Label:  lbl,
						Param:  param,
						Value:  val,
					}, true
				} else {
					// Pre-check matched, but model risk < 0.5 -> None!
					return Trip{}, false
				}
			}
		}

		// Model is down or error -> Soft (auto-release, checkout held)
		label := classifyPrecheck(res)
		return Trip{
			Sev:    SevSoft,
			Reason: "separator pre-check match (model down) in " + field + " param: " + param,
			Label:  label,
			Param:  param,
			Value:  val,
		}, true
	}

	// Non-free-text fields:
	if tw.ml != nil && tw.ml.Enabled() {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		mlRes, err := tw.ml.ClassifyInput(ctx, param, val, "web", path, field)
		if err == nil {
			if mlRes.Label != "normal" && mlRes.Label != "" && mlRes.Risk >= 0.5 {
				sev := SevHard
				if mlRes.Risk < 0.8 {
					sev = SevSoft
				}
				return Trip{
					Sev:    sev,
					Reason: "injection payload in " + field + " param: " + param,
					Label:  mlRes.Label,
					Param:  param,
					Value:  val,
				}, true
			}
			if mlRes.Risk < 0.2 {
				return Trip{}, false
			}
		}
	}

	// Fallback to pre-check alone for non-free-text fields
	label := classifyPrecheck(res)
	return Trip{
		Sev:    SevHard,
		Reason: "injection payload in " + field + " param: " + param,
		Label:  label,
		Param:  param,
		Value:  val,
	}, true
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
