package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	port       = flag.Int("port", 8888, "HTTP port to bind")
	modeFlag   = flag.String("mode", "vulnerable", "Operating mode: vulnerable, remediated, incomplete_fix")
	canaryPath = flag.String("canary", "", "Path to traversal canary file")
)

type LabServer struct {
	mu           sync.RWMutex
	mode         string
	canaryFile   string
	docRoot      string
	requestsSeen int
}

func main() {
	flag.Parse()

	tempDir, err := os.MkdirTemp("", "felix_multiclass_lab_*")
	if err != nil {
		log.Fatalf("failed creating lab temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create document root
	docRoot := filepath.Join(tempDir, "www")
	_ = os.MkdirAll(docRoot, 0755)

	// Create canary file outside document root
	canaryFile := *canaryPath
	if canaryFile == "" {
		canaryFile = filepath.Join(tempDir, "canary_traversal.txt")
		_ = os.WriteFile(canaryFile, []byte("CANARY_FELIX_TRAVERSAL_VERIFIED_7749\n[extensions]\n"), 0644)
	}

	server := &LabServer{
		mode:       strings.ToLower(*modeFlag),
		canaryFile: canaryFile,
		docRoot:    docRoot,
	}

	mux := http.NewServeMux()

	// Mode control endpoints
	mux.HandleFunc("/_lab/mode", server.handleMode)
	mux.HandleFunc("/_lab/status", server.handleStatus)

	// Population B Vulnerable & Secure Endpoints
	mux.HandleFunc("/api/search", server.handleSearch)
	mux.HandleFunc("/api/search-secure", server.handleSearchSecure)

	mux.HandleFunc("/view", server.handleView)
	mux.HandleFunc("/view-secure", server.handleViewSecure)

	mux.HandleFunc("/fetch", server.handleFetch)
	mux.HandleFunc("/fetch-secure", server.handleFetchSecure)

	mux.HandleFunc("/download", server.handleDownload)
	mux.HandleFunc("/download-secure", server.handleDownloadSecure)

	mux.HandleFunc("/static/config.js", server.handleSecret)
	mux.HandleFunc("/static/config-secure.js", server.handleSecretSecure)

	mux.HandleFunc("/api/data", server.handleCORS)
	mux.HandleFunc("/api/data-secure", server.handleCORSSecure)

	mux.HandleFunc("/checkout/complete", server.handleCheckout)
	mux.HandleFunc("/checkout/complete-secure", server.handleCheckoutSecure)

	// Root index
	mux.HandleFunc("/", server.handleIndex)

	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	fmt.Printf("[+] Controlled Multi-Class Lab starting on http://%s (Mode: %s)\n", addr, server.mode)
	fmt.Printf("[+] Canary file staged at: %s\n", canaryFile)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server failure: %v", err)
	}
}

func (s *LabServer) handleMode(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if newMode := r.URL.Query().Get("set"); newMode != "" {
		s.mode = strings.ToLower(newMode)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"current_mode": s.mode,
	})
}

func (s *LabServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"mode":          s.mode,
		"requests_seen": s.requestsSeen,
		"canary_file":   s.canaryFile,
	})
}

func (s *LabServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.requestsSeen++
	s.mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`<!DOCTYPE html>
<html>
<head>
  <title>Controlled Multi-Class Lab</title>
  <script src="/static/config.js"></script>
</head>
<body>
  <h1>FELIX Multi-Class Validation Lab</h1>
  <p>Status: Ready</p>

  <h2>Vulnerable Endpoints</h2>
  <ul>
    <li><a href="/api/search?q=test">SQL Injection (/api/search?q=)</a></li>
    <li><a href="/view?name=User">Reflected XSS (/view?name=)</a></li>
    <li><a href="/fetch?url=http://127.0.0.1:8888/_lab/status">SSRF (/fetch?url=)</a></li>
    <li><a href="/download?file=readme.txt">Path Traversal (/download?file=)</a></li>
    <li><a href="/static/config.js">Config Secret Leak (/static/config.js)</a></li>
    <li><a href="/api/data">CORS Endpoint (/api/data)</a></li>
    <li><a href="/checkout/complete?order_id=101&price=100">Business Logic (/checkout/complete)</a></li>
  </ul>

  <h2>Forms</h2>
  <form id="search-form" action="/api/search" method="GET">
    <input type="text" name="q" value="test" />
    <input type="submit" value="Search" />
  </form>
  <form id="view-form" action="/view" method="GET">
    <input type="text" name="name" value="User" />
    <input type="submit" value="View" />
  </form>
  <form id="fetch-form" action="/fetch" method="GET">
    <input type="text" name="url" value="http://127.0.0.1:8888/_lab/status" />
    <input type="submit" value="Fetch" />
  </form>
  <form id="download-form" action="/download" method="GET">
    <input type="text" name="file" value="readme.txt" />
    <input type="submit" value="Download" />
  </form>
  <form id="checkout-form" action="/checkout/complete" method="GET">
    <input type="text" name="order_id" value="101" />
    <input type="text" name="price" value="100" />
    <input type="submit" value="Checkout" />
  </form>

  <h2>Negative Controls (Secure Endpoints)</h2>
  <ul>
    <li><a href="/api/search-secure?q=test">SQL Injection Secure (/api/search-secure?q=)</a></li>
    <li><a href="/view-secure?name=User">Reflected XSS Secure (/view-secure?name=)</a></li>
    <li><a href="/fetch-secure?url=http://example.com">SSRF Secure (/fetch-secure?url=)</a></li>
    <li><a href="/download-secure?file=readme.txt">Path Traversal Secure (/download-secure?file=)</a></li>
    <li><a href="/static/config-secure.js">Config Secret Secure (/static/config-secure.js)</a></li>
    <li><a href="/api/data-secure">CORS Secure (/api/data-secure)</a></li>
    <li><a href="/checkout/complete-secure?order_id=101&price=100">Business Logic Secure (/checkout/complete-secure)</a></li>
  </ul>
</body>
</html>`))
}

// 1. SQL Injection Endpoint: /api/search?q=
func (s *LabServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	q := r.URL.Query().Get("q")

	if mode == "remediated" {
		// Fully parameterized / safe query: treats single quote as literal
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":  "success",
			"results": []string{},
			"count":   0,
		})
		return
	}

	if mode == "incomplete_fix" {
		// Flawed fix: removes raw ' once, but misses urlencoded or escaped quotes
		if strings.Contains(q, "'") {
			q = strings.Replace(q, "'", "", 1)
		}
		if strings.Contains(q, "'") || strings.Contains(q, "%27") {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("sqlite3.OperationalError: near \"'\": syntax error"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"results": []string{}})
		return
	}

	// Vulnerable mode: differential error on single quote
	if strings.Contains(q, "'") {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("sqlite3.OperationalError: near \"'\": syntax error\nUnclosed quotation mark after the character string."))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"results": []string{"item1", "item2"},
		"query":   q,
	})
}

// Negative Control: /api/search-secure?q=
func (s *LabServer) handleSearchSecure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":  "success",
		"results": []string{},
		"safe":    true,
	})
}

// 2. Reflected XSS Endpoint: /view?name=
func (s *LabServer) handleView(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	name := r.URL.Query().Get("name")
	if name == "" {
		name = "Guest"
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if mode == "remediated" {
		// Contextual HTML escaping
		w.WriteHeader(http.StatusOK)
		safeName := html.EscapeString(name)
		_, _ = fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", safeName)
		return
	}

	if mode == "incomplete_fix" {
		// Flawed fix: only strips <script> tag, misses DOM markers or img onerror
		cleanName := strings.ReplaceAll(name, "<script>", "")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", cleanName)
		return
	}

	// Vulnerable: raw unescaped reflection
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", name)
}

// Negative Control: /view-secure?name=
func (s *LabServer) handleViewSecure(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "<html><body><h1>Hello, %s</h1></body></html>", html.EscapeString(name))
}

// 3. SSRF Endpoint: /fetch?url=
func (s *LabServer) handleFetch(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	target := r.URL.Query().Get("url")
	if target == "" {
		http.Error(w, "missing ?url parameter", http.StatusBadRequest)
		return
	}

	if mode == "remediated" {
		// Restrict to explicit public whitelist; reject loopback and RFC 1918
		u, err := url.Parse(target)
		if err != nil || u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" {
			http.Error(w, "Destination disallowed by egress firewall policy", http.StatusBadRequest)
			return
		}
		http.Error(w, "Whitelisted target fetch simulated", http.StatusOK)
		return
	}

	// Vulnerable mode: issues outbound HTTP GET to target
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(target)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprintf(w, "Fetch error: %v", err)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// Negative Control: /fetch-secure?url=
func (s *LabServer) handleFetchSecure(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Egress restricted: only internal proxies permitted", http.StatusBadRequest)
}

// 4. Path Traversal Endpoint: /download?file=
func (s *LabServer) handleDownload(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	canary := s.canaryFile
	docRoot := s.docRoot
	s.mu.RUnlock()

	fileParam := r.URL.Query().Get("file")
	if fileParam == "" {
		http.Error(w, "missing ?file", http.StatusBadRequest)
		return
	}

	if mode == "remediated" {
		// Strict canonical path boundary check
		cleanPath := filepath.Clean(filepath.Join(docRoot, fileParam))
		if !strings.HasPrefix(cleanPath, filepath.Clean(docRoot)) {
			http.Error(w, "Access Denied: Path escapes document root", http.StatusBadRequest)
			return
		}
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	if mode == "incomplete_fix" {
		// Flawed fix: removes single ../ once
		flawedParam := strings.Replace(fileParam, "../", "", 1)
		resolved := filepath.Clean(filepath.Join(docRoot, flawedParam))
		if strings.Contains(fileParam, "canary") {
			// Incomplete fix still allows bypass
			if data, err := os.ReadFile(canary); err == nil {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(data)
				return
			}
		}
		_ = resolved
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Vulnerable: if file param points to canary or traversal, return canary
	if strings.Contains(fileParam, "..") || strings.Contains(fileParam, "canary") {
		if data, err := os.ReadFile(canary); err == nil {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("[extensions]\ncanonical_canary_proof\n"))
			_, _ = w.Write(data)
			return
		}
	}

	http.Error(w, "File not found", http.StatusNotFound)
}

// Negative Control: /download-secure?file=
func (s *LabServer) handleDownloadSecure(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "Traversal rejected by canonical boundary", http.StatusBadRequest)
}

// 5. Secret Exposure: /static/config.js
func (s *LabServer) handleSecret(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	w.Header().Set("Content-Type", "application/javascript")
	if mode == "remediated" {
		_, _ = w.Write([]byte("// Config loaded dynamically via secure session cookies\nconst config = { apiBase: '/api' };\n"))
		return
	}

	// Leaked high-entropy AWS credential
	_, _ = w.Write([]byte("// Production App Configuration\nconst AWS_ACCESS_KEY = \"AKIAIOSFODNN7EXAMPLE\";\nconst REGION = \"us-east-1\";\n"))
}

// Negative Control: /static/config-secure.js
func (s *LabServer) handleSecretSecure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript")
	_, _ = w.Write([]byte("// Secure static asset without credentials\nconst appEnv = 'production';\n"))
}

// 6. Dangerous CORS Endpoint: /api/data
func (s *LabServer) handleCORS(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	if mode == "remediated" {
		// Strict static allowlist
		w.Header().Set("Access-Control-Allow-Origin", "https://app.felix.internal")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		return
	}

	// Vulnerable: reflects caller's origin with credentials allowed
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"sensitive_data": "secret_records_102"})
}

// Negative Control: /api/data-secure
func (s *LabServer) handleCORSSecure(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "https://app.felix.internal")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "clean"})
}

// 7. Business Logic Bypass: /checkout/complete
func (s *LabServer) handleCheckout(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mode := s.mode
	s.mu.RUnlock()

	if mode == "remediated" {
		// Enforce payment token presence
		if r.Header.Get("X-Payment-Token") == "" {
			http.Error(w, "Payment validation required before order completion", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"order_status":"completed","payment_verified":true}`))
		return
	}

	// Vulnerable: processes completion without checking payment verification
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"order_status":"completed","workflow_bypassed":true}`))
}

// Negative Control: /checkout/complete-secure
func (s *LabServer) handleCheckoutSecure(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "State machine enforcement: payment verification required", http.StatusBadRequest)
}
