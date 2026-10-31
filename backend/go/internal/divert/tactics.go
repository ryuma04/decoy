package divert

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	scriptTagRegex   = regexp.MustCompile(`(?i)<script\b[^>]*>([\s\S]*?)<\/script>`)
	hrefRegex        = regexp.MustCompile(`(?i)href\s*=\s*["'](https?://[^"']+)["']`)
	interestingPaths = []string{"admin", "internal", "staff", "report", "export", "config"}
)

func hasExternalLink(s string) bool {
	matches := hrefRegex.FindAllStringSubmatch(s, -1)
	for _, m := range matches {
		if len(m) > 1 {
			u, err := url.Parse(m[1])
			if err == nil {
				h := u.Hostname()
				if h != "localhost" && h != "127.0.0.1" && h != "aetees-bakehouse.internal" {
					return true
				}
			}
		}
	}
	return false
}

type DeceptionTacticEvent struct {
	Tactic      string `json:"tactic"`
	BiasPattern string `json:"bias_pattern"`
	LureID      string `json:"lure_id,omitempty"`
	Effect      any    `json:"effect"`
}

// TacticsManager manages cognitive deception tactics applied to diverted visitors (docs/18 Task 12).
type TacticsManager struct {
	mu           sync.Mutex
	dataDir      string
	mlURL        string
	cloneAdminPW string
	httpClient   *http.Client

	// Sunk cost export state per visitor
	exportMu    sync.Mutex
	exportPolls map[string]int
	exportStart map[string]time.Time

	// Cached LLM lure pages
	cacheMu sync.RWMutex
	pages   map[string]string
}

func NewTacticsManager(dataDir, mlURL, cloneAdminPW string) *TacticsManager {
	if dataDir == "" {
		dataDir = ".data"
	}
	_ = os.MkdirAll(filepath.Join(dataDir, "lure_pages"), 0755)

	return &TacticsManager{
		dataDir:      dataDir,
		mlURL:        mlURL,
		cloneAdminPW: cloneAdminPW,
		httpClient:   &http.Client{Timeout: 4 * time.Second},
		exportPolls:  make(map[string]int),
		exportStart:  make(map[string]time.Time),
		pages:        make(map[string]string),
	}
}

// CheckTarpit applies a progressive delay up to 2 seconds if request rate exceeds 60 req/min.
func (tm *TacticsManager) CheckTarpit(v *Visitor) time.Duration {
	v.mu.Lock()
	reqCount := len(v.RequestTimes)
	v.mu.Unlock()

	if reqCount <= 60 {
		return 0
	}

	delay := time.Duration(reqCount-60) * 100 * time.Millisecond
	if delay > 2*time.Second {
		delay = 2 * time.Second
	}

	tm.emitTacticOnce(v, "tarpit", "sunk_cost", "", map[string]any{"delay_ms": delay.Milliseconds()})

	time.Sleep(delay)
	return delay
}

// CheckFalseSuccess rewrites failed admin login attempts to the clone's valid password after 3 failures.
// Returns the rewritten body and true if rewritten.
func (tm *TacticsManager) CheckFalseSuccess(r *http.Request, body []byte, v *Visitor) ([]byte, bool) {
	if r.Method != http.MethodPost || r.URL.Path != "/api/admin/login" {
		return body, false
	}

	v.mu.Lock()
	failedLogins := len(v.FailedLogins)
	v.mu.Unlock()

	// Trigger false_success after 3 failed admin logins
	if failedLogins < 3 {
		return body, false
	}

	// Rewrite request body to valid clone admin credentials
	bodyStr := string(body)
	vals, err := url.ParseQuery(bodyStr)
	if err == nil {
		vals.Set("username", "admin")
		vals.Set("password", tm.cloneAdminPW)
		rewritten := []byte(vals.Encode())

		tm.emitTacticOnce(v, "false_success", "confirmation", "tok_aetees_admin", map[string]any{
			"reason": "granted synthetic admin session after 3 failures",
		})
		return rewritten, true
	}

	return body, false
}

// HandleSunkCostExport handles /api/admin/export with a progress meter that stalls near 97%.
func (tm *TacticsManager) HandleSunkCostExport(w http.ResponseWriter, r *http.Request, v *Visitor) bool {
	if r.URL.Path != "/api/admin/export" && r.URL.Path != "/api/admin/export/download" {
		return false
	}

	tm.exportMu.Lock()
	defer tm.exportMu.Unlock()

	if r.URL.Path == "/api/admin/export/download" {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="aetees_customers_export.csv"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("id,name,email,total_orders\n1,Rohan Verma,rohan@example.com,4\n2,Meera Nair,meera@example.com,7\n3,Priya Sharma,priya@example.com,2\n"))
		return true
	}

	vKey := v.ID
	if _, ok := tm.exportStart[vKey]; !ok {
		tm.exportStart[vKey] = time.Now()
		tm.exportPolls[vKey] = 0
	}

	tm.exportPolls[vKey]++
	polls := tm.exportPolls[vKey]
	elapsed := int(time.Since(tm.exportStart[vKey]).Seconds())

	progress := 25
	switch {
	case polls == 1:
		progress = 30
	case polls == 2:
		progress = 65
	case polls == 3:
		progress = 88
	case polls >= 4 && polls <= 6:
		// Stalls near 97% for several polls
		progress = 97
		tm.emitTacticOnce(v, "sunk_cost_export", "sunk_cost", "", map[string]any{
			"polls":         polls,
			"seconds_spent": elapsed,
		})
	default:
		progress = 100
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	resp := map[string]any{
		"job_id":   "exp_" + vKey[:8],
		"progress": progress,
		"status":   "processing",
	}
	if progress == 100 {
		resp["status"] = "complete"
		resp["download_url"] = "/api/admin/export/download"
	}
	_ = json.NewEncoder(w).Encode(resp)
	return true
}

// InjectBreadcrumb injects an anchoring comment into clone HTML pages pointing at lures.
func (tm *TacticsManager) InjectBreadcrumb(resp *http.Response, v *Visitor) {
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(ct, "text/html") {
		return
	}

	bodyBytes, err := ioReadAll(resp.Body)
	if err != nil {
		return
	}
	_ = resp.Body.Close()

	comment := []byte("\n<!-- DEBUG: Migration in progress. Remove /.env.bak and /backup/ before production release. -->\n")
	html := string(bodyBytes)

	idx := strings.LastIndex(strings.ToLower(html), "</body>")
	if idx == -1 {
		idx = strings.LastIndex(strings.ToLower(html), "</html>")
	}

	var newBody []byte
	if idx != -1 {
		newBody = append([]byte(html[:idx]), append(comment, []byte(html[idx:])...)...)
	} else {
		newBody = append(bodyBytes, comment...)
	}

	resp.Body = ioNopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))

	tm.emitTacticOnce(v, "breadcrumb", "anchoring", "lure_aetees_env", map[string]any{
		"comment": "pointing to .env.bak and /backup/",
	})
}

// CheckLLMPage generates a themed lure page if the clone returned 404 for an interesting path.
func (tm *TacticsManager) CheckLLMPage(w http.ResponseWriter, r *http.Request, v *Visitor, statusCode int) bool {
	if statusCode != http.StatusNotFound {
		return false
	}

	path := strings.ToLower(r.URL.Path)
	isInteresting := false
	for _, ip := range interestingPaths {
		if strings.Contains(path, ip) {
			isInteresting = true
			break
		}
	}
	if !isInteresting {
		return false
	}

	// 1. Check disk/memory cache
	cacheKey := hashPath(path)
	if cachedHTML, ok := tm.getCached(cacheKey); ok {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(cachedHTML))
		tm.emitTacticOnce(v, "llm_page", "curiosity", "", map[string]any{
			"path":   path,
			"cached": true,
		})
		return true
	}

	// 2. Generate plausible lure page
	title, bodyHTML := tm.generateLureContent(r.URL.Path)

	// 3. Output guard: reject scripts, external links, or invalid content
	if scriptTagRegex.MatchString(bodyHTML) || hasExternalLink(bodyHTML) {
		return false // fallback to 404
	}

	fullPage := tm.wrapShopTheme(title, bodyHTML)

	// Cache to disk and memory
	tm.saveCache(cacheKey, fullPage)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(fullPage))

	tm.emitTacticOnce(v, "llm_page", "curiosity", "", map[string]any{
		"path": path,
	})
	return true
}

// unsafeLureHTML is the Go-side second check on ML-generated pages (the ML service guards first).
var unsafeLureHTML = regexp.MustCompile(`(?i)<\s*(script|iframe|object|embed|form|meta|link|base|style)\b|\bon[a-z]+\s*=|javascript:|(src|href)\s*=\s*["']?(https?:)?//`)

func (tm *TacticsManager) generateLureContent(path string) (string, string) {
	if tm.mlURL != "" && tm.httpClient != nil {
		reqBody, _ := json.Marshal(map[string]string{
			"path": path,
			"site": "Aetees Bakehouse",
		})
		req, err := http.NewRequest(http.MethodPost, strings.TrimRight(tm.mlURL, "/")+"/ml/v1/lure-page", bytes.NewReader(reqBody))
		if err == nil {
			req.Header.Set("Content-Type", "application/json")
			resp, err := tm.httpClient.Do(req)
			if err == nil {
				defer resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					var lureResp struct {
						Title    string `json:"title"`
						BodyHTML string `json:"body_html"`
					}
					if err := json.NewDecoder(resp.Body).Decode(&lureResp); err == nil && lureResp.Title != "" && lureResp.BodyHTML != "" &&
						!unsafeLureHTML.MatchString(lureResp.BodyHTML) {
						return html.EscapeString(html.UnescapeString(lureResp.Title)), lureResp.BodyHTML
					}
				}
			}
		}
	}

	// Fallback deterministic themed content matching Aetees shop
	title := "Internal Portal — Aetees Bakehouse"
	body := fmt.Sprintf(`<div class="notice">
  <h3>Notice: Restricted Area (%s)</h3>
  <p>This portal is reserved for authorized bakery management and kitchen staff.</p>
  <p>To access order archives or export data, please log in with administrative credentials.</p>
</div>`, html.EscapeString(path))

	return title, body
}

func (tm *TacticsManager) wrapShopTheme(title, bodyHTML string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Oswald:wght@500;700&display=swap" rel="stylesheet">
  <style>
    body { font-family: 'Inter', sans-serif; background-color: #f8ecc2; color: #5a3424; margin: 0; padding: 2rem; }
    h1, h2, h3 { font-family: 'Oswald', sans-serif; color: #5a3424; }
    .card { background: #ffffff; border: 1px solid #e2caa0; border-radius: 8px; padding: 2rem; max-width: 600px; margin: 2rem auto; box-shadow: 0 4px 6px rgba(0,0,0,0.05); }
    .footer { text-align: center; font-size: 0.85rem; color: #8c5b3e; margin-top: 2rem; }
  </style>
</head>
<body>
  <div class="card">
    <h1>%s</h1>
    <hr style="border: none; border-top: 2px solid #5a3424; margin-bottom: 1.5rem;">
    %s
  </div>
  <div class="footer">&copy; 2026 Aetees Bakehouse. All rights reserved.</div>
</body>
</html>`, title, title, bodyHTML)
}

func (tm *TacticsManager) emitTacticOnce(v *Visitor, tactic, bias, lureID string, effect any) {
	v.mu.Lock()
	if v.TacticsEmitted == nil {
		v.TacticsEmitted = make(map[string]bool)
	}
	if v.TacticsEmitted[tactic] {
		v.mu.Unlock()
		return
	}
	v.TacticsEmitted[tactic] = true
	sess := v.Session
	v.mu.Unlock()

	if sess == nil {
		return
	}

	sess.Event("deception.tactic", "", DeceptionTacticEvent{
		Tactic:      tactic,
		BiasPattern: bias,
		LureID:      lureID,
		Effect:      effect,
	}, nil, nil)
}

func (tm *TacticsManager) getCached(key string) (string, bool) {
	tm.cacheMu.RLock()
	v, ok := tm.pages[key]
	tm.cacheMu.RUnlock()
	if ok {
		return v, true
	}

	// Try disk
	path := filepath.Join(tm.dataDir, "lure_pages", key+".html")
	b, err := os.ReadFile(path)
	if err == nil {
		tm.cacheMu.Lock()
		tm.pages[key] = string(b)
		tm.cacheMu.Unlock()
		return string(b), true
	}
	return "", false
}

func (tm *TacticsManager) saveCache(key, content string) {
	tm.cacheMu.Lock()
	tm.pages[key] = content
	tm.cacheMu.Unlock()

	path := filepath.Join(tm.dataDir, "lure_pages", key+".html")
	_ = os.WriteFile(path, []byte(content), 0644)
}

func hashPath(p string) string {
	h := sha256.Sum256([]byte(p))
	return hex.EncodeToString(h[:8])
}

// Helpers for body reading
func ioReadAll(r ioReader) ([]byte, error) {
	buf := new(bytes.Buffer)
	_, err := buf.ReadFrom(r)
	return buf.Bytes(), err
}

type ioReader interface {
	Read(p []byte) (n int, err error)
}

func ioNopCloser(r *bytes.Reader) ioReadCloser {
	return &nopCloser{r}
}

type ioReadCloser interface {
	Read(p []byte) (n int, err error)
	Close() error
}

type nopCloser struct {
	*bytes.Reader
}

func (n *nopCloser) Close() error { return nil }
