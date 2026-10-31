package divert

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ryuma04/decoy/backend/internal/mlclient"
)

func TestTripwire_AttackLabels(t *testing.T) {
	tw := NewTripwire()

	tests := []struct {
		name        string
		method      string
		url         string
		headers     map[string]string
		body        string
		view        VisitorView
		wantSev     Severity
		wantLabel   string
		expectFound bool
	}{
		// 1. Sensitive path (Hard)
		{
			name:        "sensitive_path /.env",
			method:      "GET",
			url:         "http://localhost:8200/.env",
			wantSev:     SevHard,
			wantLabel:   "sensitive_path",
			expectFound: true,
		},
		{
			name:        "sensitive_path /.git/config",
			method:      "GET",
			url:         "http://localhost:8200/.git/config",
			wantSev:     SevHard,
			wantLabel:   "sensitive_path",
			expectFound: true,
		},
		{
			name:        "sensitive_path /wp-admin",
			method:      "GET",
			url:         "http://localhost:8200/wp-admin",
			wantSev:     SevHard,
			wantLabel:   "sensitive_path",
			expectFound: true,
		},
		{
			name:        "sensitive_path /config.php",
			method:      "GET",
			url:         "http://localhost:8200/config.php",
			wantSev:     SevHard,
			wantLabel:   "sensitive_path",
			expectFound: true,
		},

		// 2. Scanner (Hard offensive tool UA)
		{
			name:        "scanner sqlmap user agent",
			method:      "GET",
			url:         "http://localhost:8200/",
			headers:     map[string]string{"User-Agent": "sqlmap/1.5#stable"},
			wantSev:     SevHard,
			wantLabel:   "scanner",
			expectFound: true,
		},
		{
			name:        "scanner nikto user agent",
			method:      "GET",
			url:         "http://localhost:8200/",
			headers:     map[string]string{"User-Agent": "Nikto/2.1.6"},
			wantSev:     SevHard,
			wantLabel:   "scanner",
			expectFound: true,
		},
		{
			name:        "scanner gobuster user agent",
			method:      "GET",
			url:         "http://localhost:8200/",
			headers:     map[string]string{"User-Agent": "gobuster/3.1.0"},
			wantSev:     SevHard,
			wantLabel:   "scanner",
			expectFound: true,
		},

		// 3. Scanner (Soft scripted client without browser headers)
		{
			name:        "scanner python-requests user agent",
			method:      "GET",
			url:         "http://localhost:8200/menu",
			headers:     map[string]string{"User-Agent": "python-requests/2.28.1"},
			wantSev:     SevSoft,
			wantLabel:   "scanner",
			expectFound: true,
		},
		{
			name:        "scanner curl user agent",
			method:      "GET",
			url:         "http://localhost:8200/menu",
			headers:     map[string]string{"User-Agent": "curl/7.88.1"},
			wantSev:     SevSoft,
			wantLabel:   "scanner",
			expectFound: true,
		},

		// 4. Bruteforce (Hard repeated failed logins)
		{
			name:        "bruteforce admin login attempts",
			method:      "POST",
			url:         "http://localhost:8200/api/admin/login",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			view:        VisitorView{FailedLogins10m: 6},
			wantSev:     SevHard,
			wantLabel:   "bruteforce",
			expectFound: true,
		},

		// 5. SQLi (Hard)
		{
			name:        "sqli UNION SELECT in query",
			method:      "GET",
			url:         "http://localhost:8200/products?id=cake%20UNION%20SELECT%201,2,3--",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "sqli",
			expectFound: true,
		},
		{
			name:        "sqli ' OR 1=1 in form body",
			method:      "POST",
			url:         "http://localhost:8200/api/contact",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
			body:        "user_id=admin'+OR+1=1--&email=test@example.com",
			wantSev:     SevHard,
			wantLabel:   "sqli",
			expectFound: true,
		},

		// 6. XSS (Hard)
		{
			name:        "xss script tag in query",
			method:      "GET",
			url:         "http://localhost:8200/products?id=%3Cscript%3Ealert(1)%3C/script%3E",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "xss",
			expectFound: true,
		},
		{
			name:        "xss script tag in body",
			method:      "POST",
			url:         "http://localhost:8200/api/contact",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
			body:        "payload=%3Cscript%3Edocument.cookie%3C/script%3E",
			wantSev:     SevHard,
			wantLabel:   "xss",
			expectFound: true,
		},

		// 7. Command Injection (Hard)
		{
			name:        "cmd_injection semicolon separator",
			method:      "GET",
			url:         "http://localhost:8200/products?id=1%3B+cat+/etc/passwd",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "cmd_injection",
			expectFound: true,
		},
		{
			name:        "cmd_injection double ampersand in body",
			method:      "POST",
			url:         "http://localhost:8200/api/contact",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0", "Content-Type": "application/x-www-form-urlencoded"},
			body:        "cmd=test%26%26whoami",
			wantSev:     SevHard,
			wantLabel:   "cmd_injection",
			expectFound: true,
		},
		{
			name:        "cmd_injection backticks in query",
			method:      "GET",
			url:         "http://localhost:8200/products?cmd=%60id%60",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "cmd_injection",
			expectFound: true,
		},

		// 8. Path Traversal (Hard)
		{
			name:        "path_traversal ../ in URL path",
			method:      "GET",
			url:         "http://localhost:8200/../../etc/passwd",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "path_traversal",
			expectFound: true,
		},
		{
			name:        "path_traversal ../ in query param",
			method:      "GET",
			url:         "http://localhost:8200/view?file=../../../etc/shadow",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevHard,
			wantLabel:   "path_traversal",
			expectFound: true,
		},

		// 9. Probe (Soft burst 404, odd chars, rate)
		{
			name:        "probe burst of 404s",
			method:      "GET",
			url:         "http://localhost:8200/normal-page",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			view:        VisitorView{NotFound5m: 5},
			wantSev:     SevSoft,
			wantLabel:   "probe",
			expectFound: true,
		},
		{
			name:        "probe odd characters in search",
			method:      "GET",
			url:         "http://localhost:8200/search?q=cake%7E%5E",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			wantSev:     SevSoft,
			wantLabel:   "probe",
			expectFound: true,
		},
		{
			name:        "probe high request rate",
			method:      "GET",
			url:         "http://localhost:8200/menu",
			headers:     map[string]string{"User-Agent": "Mozilla/5.0"},
			view:        VisitorView{RequestsPerMin: 35},
			wantSev:     SevSoft,
			wantLabel:   "probe",
			expectFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			trip := tw.Classify(req, []byte(tt.body), tt.view)

			if trip.Sev != tt.wantSev {
				t.Errorf("got Sev %q, want %q (reason: %s)", trip.Sev, tt.wantSev, trip.Reason)
			}
			if trip.Label != tt.wantLabel {
				t.Errorf("got Label %q, want %q", trip.Label, tt.wantLabel)
			}
		})
	}
}

// TestTripwire_JSONBodiesAndFreeTextTests covers:
// 1. False positive fix: POST /api/contact with JSON {"message":"Mom's cake; less sugar -- urgent"}
//    -> None when model risk < 0.5, Soft when model is down.
// 2. Misses fix: SQL injection and XSS inside JSON request bodies are detected.
func TestTripwire_JSONBodiesAndFreeTextTests(t *testing.T) {
	// ML mock server returning results dynamically based on value content
	mlMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Param   string `json:"param"`
			Value   string `json:"value"`
			Context struct {
				Field string `json:"field"`
			} `json:"context"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")

		valLower := strings.ToLower(req.Value)

		// SQLi detection
		if strings.Contains(valLower, "union select") || strings.Contains(valLower, "' or") || strings.Contains(valLower, "--") && strings.Contains(valLower, "admin'") {
			_ = json.NewEncoder(w).Encode(mlclient.InputResult{
				Label: "sqli",
				Risk:  0.95,
			})
			return
		}

		// XSS detection
		if strings.Contains(valLower, "<script") || strings.Contains(valLower, "onerror") || strings.Contains(valLower, "javascript:") {
			_ = json.NewEncoder(w).Encode(mlclient.InputResult{
				Label: "xss",
				Risk:  0.92,
			})
			return
		}

		// Medium risk injection
		if strings.Contains(valLower, "suspicious_test_input") {
			_ = json.NewEncoder(w).Encode(mlclient.InputResult{
				Label: "sqli",
				Risk:  0.65,
			})
			return
		}

		// Normal customer messages (including ones with semicolons, apostrophes, dashes)
		_ = json.NewEncoder(w).Encode(mlclient.InputResult{
			Label: "normal",
			Risk:  0.08,
		})
	}))
	defer mlMock.Close()

	mlClient := mlclient.New(mlMock.URL)
	twWithML := NewTripwire(mlClient)
	twModelDown := NewTripwire(mlclient.New("http://127.0.0.1:54321")) // down

	tests := []struct {
		name      string
		tw        *Tripwire
		method    string
		url       string
		body      string
		wantSev   Severity
		wantLabel string
	}{
		// 1. FALSE POSITIVE FIX: JSON free-text message with semicolon & dashes
		{
			name:      "Mom's cake false positive fix with ML up -> SevNone",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"message":"Mom's cake; less sugar -- urgent"}`,
			wantSev:   SevNone,
			wantLabel: "",
		},
		{
			name:      "Mom's cake with ML down -> SevSoft (auto-release, checkout held)",
			tw:        twModelDown,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"message":"Mom's cake; less sugar -- urgent"}`,
			wantSev:   SevSoft,
			wantLabel: "cmd_injection",
		},

		// 2. MISSES FIX: SQL injection inside JSON request body
		{
			name:      "SQL injection inside JSON name field -> SevHard, sqli",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"name":"admin' OR 1=1--", "message":"hello"}`,
			wantSev:   SevHard,
			wantLabel: "sqli",
		},
		{
			name:      "SQL injection in JSON nested checkout address -> SevHard, sqli",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/checkout",
			body:      `{"name":"John","address":"123 Main St' UNION SELECT 1,2,3--"}`,
			wantSev:   SevHard,
			wantLabel: "sqli",
		},

		// 3. MISSES FIX: XSS inside JSON request body
		{
			name:      "XSS script inside JSON message field -> SevHard, xss",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"name":"John", "message":"<script>alert(1)</script>"}`,
			wantSev:   SevHard,
			wantLabel: "xss",
		},
		{
			name:      "XSS script inside JSON name field -> SevHard, xss",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"name":"<script>document.location='http://evil.com'</script>", "message":"Hi"}`,
			wantSev:   SevHard,
			wantLabel: "xss",
		},

		// 4. Free-text with model risk 0.5 - 0.8 -> SevSoft
		{
			name:      "Free text with medium model risk 0.65 -> SevSoft",
			tw:        twWithML,
			method:    "POST",
			url:       "http://localhost:8200/api/contact",
			body:      `{"message":"suspicious_test_input; drop table"}`,
			wantSev:   SevSoft,
			wantLabel: "sqli",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
			req.Header.Set("Content-Type", "application/json")

			trip := tt.tw.Classify(req, []byte(tt.body), VisitorView{})

			if trip.Sev != tt.wantSev {
				t.Errorf("got Sev %q, want %q (reason: %s)", trip.Sev, tt.wantSev, trip.Reason)
			}
			if trip.Label != tt.wantLabel {
				t.Errorf("got Label %q, want %q", trip.Label, tt.wantLabel)
			}
		})
	}
}

// TestTripwire_HarmlessCustomerMessages verifies that 20 harmless customer messages containing
// apostrophes, semicolons, "--", "OR", quotes and emoji all return None.
func TestTripwire_HarmlessCustomerMessages(t *testing.T) {
	mlMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// The ML model recognizes natural customer text and scores it as benign
		_ = json.NewEncoder(w).Encode(mlclient.InputResult{
			Label: "normal",
			Risk:  0.06,
		})
	}))
	defer mlMock.Close()

	tw := NewTripwire(mlclient.New(mlMock.URL))
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	harmlessMessages := []struct {
		name    string
		url     string
		payload string
	}{
		{
			name:    "Message 1 (apostrophe, semicolon, dashes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Mom's cake; less sugar -- urgent"}`,
		},
		{
			name:    "Message 2 (apostrophe, semicolon, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Can I order for tomorrow? It's my brother's birthday; please confirm! 🎂"}`,
		},
		{
			name:    "Message 3 (dashes, quotes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Special instructions: 1/2 kg 'chocolate truffle' -- no nuts please!"}`,
		},
		{
			name:    "Message 4 (semicolon, OR, apostrophe)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Hello; we'd like vanilla frosting OR chocolate if vanilla isn't available"}`,
		},
		{
			name:    "Message 5 (quotes, dashes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Happy 30th Birthday 'Sarah' -- from all of us! 🎉"}`,
		},
		{
			name:    "Message 6 (dashes, semicolon, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Please deliver between 4 PM -- 6 PM; ring the bell twice 🔔"}`,
		},
		{
			name:    "Message 7 (semicolon, dashes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Eggless cake; extra sprinkles -- thank you so much! 😊"}`,
		},
		{
			name:    "Message 8 (apostrophe, dashes, phone)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Is delivery available to Bandra West? It's urgent -- call me at 9876543210"}`,
		},
		{
			name:    "Message 9 (quotes, semicolon, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Could you write 'Best Mom Ever' in pink icing; thanks! ❤️"}`,
		},
		{
			name:    "Message 10 (semicolon, dashes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Two cupcakes; one blueberry muffin -- for takeaway at 5pm"}`,
		},
		{
			name:    "Message 11 (OR, semicolon, dashes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Please do NOT use peanuts OR tree nuts; severe allergy -- thank you!"}`,
		},
		{
			name:    "Message 12 (semicolon, dashes)",
			url:     "http://localhost:8200/api/checkout",
			payload: `{"name":"Aarav Mehta","notes":"Gate code is #1234; leave at doorstep -- thanks"}`,
		},
		{
			name:    "Message 13 (semicolon, dashes, quotes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Wedding anniversary cake; flavour: red velvet -- message: 'Together Forever' 💕"}`,
		},
		{
			name:    "Message 14 (semicolon, dashes, apostrophe)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Hi; can we change the pickup date to Sunday -- 3rd Nov? It's our anniversary"}`,
		},
		{
			name:    "Message 15 (quotes, dashes, emoji)",
			url:     "http://localhost:8200/api/checkout",
			payload: `{"name":"Pooja Shah","notes":"Gift message: 'Congratulations on your new home!' -- from John & Jane 🏡"}`,
		},
		{
			name:    "Message 16 (semicolon, dashes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Gluten-free cookies; almond flour -- please pack carefully"}`,
		},
		{
			name:    "Message 17 (quotes, dashes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Custom message: 'Happy Retirement Grandpa!' -- with love 👴🎂"}`,
		},
		{
			name:    "Message 18 (semicolon, dashes)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"I tried calling earlier; no answer -- could you please confirm my order #104?"}`,
		},
		{
			name:    "Message 19 (semicolon, OR, dashes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Fruit cake; extra kiwi OR strawberries -- surprise us! 🍓🥝"}`,
		},
		{
			name:    "Message 20 (semicolon, dashes, emoji)",
			url:     "http://localhost:8200/api/contact",
			payload: `{"message":"Grand opening cake; 2 tier -- deliver by 10:00 AM sharp; urgent 🎈"}`,
		},
	}

	if len(harmlessMessages) != 20 {
		t.Fatalf("expected exactly 20 harmless messages, got %d", len(harmlessMessages))
	}

	for _, tt := range harmlessMessages {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, tt.url, strings.NewReader(tt.payload))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("User-Agent", ua)
			req.Header.Set("Content-Type", "application/json")

			trip := tw.Classify(req, []byte(tt.payload), VisitorView{})

			if trip.Sev != SevNone {
				t.Errorf("false positive on harmless message [%s]: got Sev %q, label %q (reason: %s)",
					tt.name, trip.Sev, trip.Label, trip.Reason)
			}
		})
	}
}

// TestTripwire_NormalShopTraffic verifies that at least 20 normal requests from the real shop classify as None.
func TestTripwire_NormalShopTraffic(t *testing.T) {
	tw := NewTripwire()
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

	normalRequests := []struct {
		name   string
		method string
		url    string
		body   string
		ct     string
	}{
		// Navigation & Pages (12)
		{name: "Homepage", method: "GET", url: "http://localhost:8200/"},
		{name: "Menu Page", method: "GET", url: "http://localhost:8200/menu"},
		{name: "About Page", method: "GET", url: "http://localhost:8200/about"},
		{name: "Contact Page", method: "GET", url: "http://localhost:8200/contact"},
		{name: "Cart Page", method: "GET", url: "http://localhost:8200/cart"},
		{name: "Checkout Page", method: "GET", url: "http://localhost:8200/checkout"},
		{name: "Product Detail Cakes", method: "GET", url: "http://localhost:8200/products/chocolate-truffle-cake"},
		{name: "Product Detail Cheesecakes", method: "GET", url: "http://localhost:8200/products/blueberry-cheesecake"},
		{name: "Category Cakes", method: "GET", url: "http://localhost:8200/category/cakes"},
		{name: "Category Cheesecakes", method: "GET", url: "http://localhost:8200/category/cheesecakes"},
		{name: "Category Cookies", method: "GET", url: "http://localhost:8200/category/cookies"},
		{name: "Category Brownies", method: "GET", url: "http://localhost:8200/category/brownies"},

		// Static Assets (5)
		{name: "Next.js JS Chunk", method: "GET", url: "http://localhost:8200/_next/static/chunks/main.js"},
		{name: "Next.js App CSS", method: "GET", url: "http://localhost:8200/_next/static/css/app.css"},
		{name: "Cake Image", method: "GET", url: "http://localhost:8200/hero-cakes.jpg"},
		{name: "Cheesecake Image", method: "GET", url: "http://localhost:8200/cheesecake.png"},
		{name: "Favicon", method: "GET", url: "http://localhost:8200/favicon.ico"},

		// Search and Filter Queries (4)
		{name: "Search Chocolate", method: "GET", url: "http://localhost:8200/search?q=chocolate"},
		{name: "Search Eggless Cake", method: "GET", url: "http://localhost:8200/search?q=eggless+cake"},
		{name: "Search Bakery Word", method: "GET", url: "http://localhost:8200/search?q=fresh+baked+bread"},
		{name: "Filter Cheesecakes and Tag", method: "GET", url: "http://localhost:8200/menu?cat=Cheesecakes&tag=Bestseller"},

		// APIs & Submissions (5)
		{name: "API Products List", method: "GET", url: "http://localhost:8200/api/products"},
		{name: "API Categories List", method: "GET", url: "http://localhost:8200/api/categories"},
		{
			name:   "Contact Form Submission",
			method: "POST",
			url:    "http://localhost:8200/api/contact",
			body:   "name=Rohan+Verma&email=rohan%40example.com&phone=9876543210&message=I+would+like+to+inquire+about+custom+cakes",
			ct:     "application/x-www-form-urlencoded",
		},
		{
			name:   "Add to Cart JSON",
			method: "POST",
			url:    "http://localhost:8200/api/cart",
			body:   `{"productId":1,"quantity":2,"size":"1 kg"}`,
			ct:     "application/json",
		},
		{
			name:   "Checkout Order JSON",
			method: "POST",
			url:    "http://localhost:8200/api/checkout",
			body:   `{"name":"Meera Nair","email":"meera@example.com","address":"14, Palm Grove, Bandra West","postalCode":"400050"}`,
			ct:     "application/json",
		},
		{
			name:   "Normal Admin Login",
			method: "POST",
			url:    "http://localhost:8200/api/admin/login",
			body:   "username=admin&password=MySafeNormalPassword123",
			ct:     "application/x-www-form-urlencoded",
		},
	}

	if len(normalRequests) < 20 {
		t.Fatalf("expected at least 20 normal requests, got %d", len(normalRequests))
	}

	for _, tt := range normalRequests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.url, strings.NewReader(tt.body))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}
			req.Header.Set("User-Agent", ua)
			if tt.ct != "" {
				req.Header.Set("Content-Type", tt.ct)
			}

			// Clean visitor view
			view := VisitorView{
				NotFound5m:      0,
				FailedLogins10m: 0,
				RequestsPerMin:  8,
			}

			trip := tw.Classify(req, []byte(tt.body), view)

			if trip.Sev != SevNone {
				t.Errorf("false positive on normal request %s: got Sev %q, label %q (reason: %s)",
					tt.name, trip.Sev, trip.Label, trip.Reason)
			}
		})
	}
}

// TestTripwire_MLClientIntegration verifies ML client integration and fallback when ML is down.
func TestTripwire_MLClientIntegration(t *testing.T) {
	// 1. Mock ML server returning high-confidence SQLi classification
	mlMock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		res := mlclient.InputResult{
			Label: "sqli",
			Risk:  0.95,
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	defer mlMock.Close()

	mlClient := mlclient.New(mlMock.URL)
	twWithML := NewTripwire(mlClient)

	req, _ := http.NewRequest(http.MethodGet, "http://localhost:8200/search?q=admin%27%20OR%201=1--", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	trip := twWithML.Classify(req, nil, VisitorView{})
	if trip.Sev != SevHard || trip.Label != "sqli" {
		t.Errorf("expected Hard sqli from ML client, got Sev: %s, Label: %s", trip.Sev, trip.Label)
	}

	// 2. ML client pointing to closed server (down) - falls back to pre-check alone
	mlClientDown := mlclient.New("http://127.0.0.1:54321")
	twDown := NewTripwire(mlClientDown)

	reqNonFree, _ := http.NewRequest(http.MethodGet, "http://localhost:8200/products?id=admin%27%20OR%201=1--", nil)
	reqNonFree.Header.Set("User-Agent", "Mozilla/5.0")
	tripFallback := twDown.Classify(reqNonFree, nil, VisitorView{})
	if tripFallback.Sev != SevHard || tripFallback.Label != "sqli" {
		t.Errorf("expected Hard sqli from fallback precheck on non-free-text param, got Sev: %s, Label: %s", tripFallback.Sev, tripFallback.Label)
	}
}
