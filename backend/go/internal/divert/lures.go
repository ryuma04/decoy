package divert

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"github.com/ryuma04/decoy/backend/internal/sensorkit"
	"net/http"
	"strings"
	"sync"
)

// LureManager handles lures served exclusively to diverted visitors (docs/18 Task 12).
type LureManager struct {
	mu           sync.RWMutex
	adminToken   string
	dbToken      string
	invoiceToken string
	sqlGz        []byte
}

func NewLureManager(adminToken, dbToken, invoiceToken string) *LureManager {
	if adminToken == "" {
		adminToken = "BakeAdmin2026!Secret"
	}
	if dbToken == "" {
		dbToken = "AeteesDbPass42!"
	}
	if invoiceToken == "" {
		invoiceToken = "/invoices/view/a8f9c0e21b4d3e5f"
	}

	lm := &LureManager{
		adminToken:   adminToken,
		dbToken:      dbToken,
		invoiceToken: invoiceToken,
	}
	lm.generateSQLDump()
	return lm
}

func (lm *LureManager) generateSQLDump() {
	buf := new(bytes.Buffer)
	zw := gzip.NewWriter(buf)

	sql := fmt.Sprintf(`-- Aetees Bakehouse Database Backup
-- Dump completed on 2026-10-28 18:30:00 IST
-- Host: db.internal    Database: aetees_prod

CREATE TABLE customers (id INT PRIMARY KEY, name VARCHAR(100), email VARCHAR(100));
INSERT INTO customers VALUES (1, 'Rohan Verma', 'rohan@example.com');
INSERT INTO customers VALUES (2, 'Meera Nair', 'meera@example.com');

CREATE TABLE orders (id INT PRIMARY KEY, customer_id INT, amount DECIMAL(10,2), status VARCHAR(20), notes TEXT);
INSERT INTO orders VALUES (1001, 1, 1450.00, 'PAID', 'Express delivery requested');
INSERT INTO orders VALUES (1002, 2, 2890.00, 'PAID', 'Special canary order: view invoice at https://aetees-bakehouse.internal%s');
`, lm.invoiceToken)

	_, _ = zw.Write([]byte(sql))
	_ = zw.Close()
	lm.sqlGz = buf.Bytes()
}

// HandleLures checks if the request targets a planted lure file/path.
// Returns true if handled.
func (lm *LureManager) HandleLures(w http.ResponseWriter, r *http.Request, v *Visitor) bool {
	v.mu.Lock()
	isDiverted := v.Diverted
	sess := v.Session
	v.mu.Unlock()

	// Undiverted visitors never see any lure!
	if !isDiverted {
		return false
	}

	path := r.URL.Path

	// 1. Lure: /.env.bak
	if path == "/.env.bak" {
		lm.serveEnvBak(w, sess)
		return true
	}

	// 2. Lure: /backup/ directory listing
	if path == "/backup" || path == "/backup/" {
		lm.serveBackupDir(w, sess)
		return true
	}

	// 3. Lure: /backup/aetees_db_FINAL.sql.gz
	if path == "/backup/aetees_db_FINAL.sql.gz" {
		lm.serveBackupSQLGz(w, sess)
		return true
	}

	// 4. Lure: Canary invoice URL
	if strings.TrimSuffix(path, "/") == strings.TrimSuffix(lm.invoiceToken, "/") {
		lm.serveInvoiceCanary(w, sess)
		return true
	}

	return false
}

func (lm *LureManager) serveEnvBak(w http.ResponseWriter, sess *sensorkit.Session) {
	content := fmt.Sprintf(`# Aetees Production Environment Backup
NODE_ENV=production
PORT=3100
DATABASE_URL="postgresql://aetees_app:%s@db.internal:5432/aetees_prod"
JWT_SECRET="a7d2e9f0184b4c7d9a1e0b5f6c8d2a4e"
ADMIN_USER="admin"
ADMIN_PASSWORD="%s"
PAYMENT_GATEWAY_KEY="rzp_live_8f0a1c2d3e4b"
`, lm.dbToken, lm.adminToken)

	dataBytes := []byte(content)
	if sess != nil { // report the lure touch to core (sensorkit session of the diverted visitor)
		sess.Event("file.read", "lure_aetees_env", map[string]any{
			"path":         "/.env.bak",
			"honeyfile_id": "tok_aetees_admin",
			"bytes":        len(dataBytes),
		}, nil, []string{"tok_aetees_admin"})
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(dataBytes)
}

func (lm *LureManager) serveBackupDir(w http.ResponseWriter, sess *sensorkit.Session) {
	html := `<!DOCTYPE HTML>
<html>
<head><title>Index of /backup</title></head>
<body>
<h1>Index of /backup</h1>
<hr><pre>
<a href="../">../</a>
<a href="schema_2026.sql">schema_2026.sql</a>            12-Oct-2026 04:12               15042
<a href="aetees_db_FINAL.sql.gz">aetees_db_FINAL.sql.gz</a>     28-Oct-2026 18:30              124800
</pre><hr>
</body></html>`

	if sess != nil { // report the lure touch to core (sensorkit session of the diverted visitor)
		sess.Event("file.read", "lure_aetees_orders", map[string]any{
			"path":  "/backup/",
			"bytes": len(html),
		}, nil, nil)
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}

func (lm *LureManager) serveBackupSQLGz(w http.ResponseWriter, sess *sensorkit.Session) {
	lm.mu.RLock()
	gzData := lm.sqlGz
	lm.mu.RUnlock()

	if sess != nil { // report the lure touch to core (sensorkit session of the diverted visitor)
		sess.Event("file.download", "lure_aetees_orders", map[string]any{
			"path":         "/backup/aetees_db_FINAL.sql.gz",
			"honeyfile_id": "tok_aetees_invoice",
			"bytes":        len(gzData),
		}, nil, []string{"tok_aetees_invoice"})
	}

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="aetees_db_FINAL.sql.gz"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(gzData)
}

func (lm *LureManager) serveInvoiceCanary(w http.ResponseWriter, sess *sensorkit.Session) {
	html := `<!DOCTYPE html>
<html>
<head>
  <title>Invoice Viewer — Aetees Bakehouse</title>
  <style>body { font-family: sans-serif; background: #fdfaf5; color: #5a3424; padding: 2rem; }</style>
</head>
<body>
  <h2>Aetees Bakehouse — Internal Order Invoice</h2>
  <hr>
  <p><strong>Invoice:</strong> #INV-2026-1002</p>
  <p><strong>Customer:</strong> Meera Nair</p>
  <p><strong>Amount:</strong> ₹2,890.00</p>
  <p><strong>Status:</strong> Completed</p>
</body>
</html>`

	if sess != nil { // report the lure touch to core (sensorkit session of the diverted visitor)
		sess.Event("token.used", "lure_aetees_orders", map[string]any{
			"token_id":   "tok_aetees_invoice",
			"token_kind": "url",
			"via":        "url_fetch",
		}, nil, []string{"tok_aetees_invoice"})
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(html))
}
