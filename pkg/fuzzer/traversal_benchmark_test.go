package fuzzer

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TraversalBenchmarkVector defines an empirical benchmark case for path traversal evaluation.
type TraversalBenchmarkVector struct {
	ID               string
	Description      string
	IsVulnerable     bool
	ExpectedCategory FileSignatureCategory
}

// TestBenchmark_PathTraversalEngine evaluates the TraversalAnalyzer against a standardized 10-vector benchmark suite.
func TestBenchmark_PathTraversalEngine(t *testing.T) {
	// 1. Target Reachability Audit
	webgoatURL := "http://127.0.0.1:8082/WebGoat/login"
	webgoatReachable := checkHostReachability(webgoatURL)
	t.Logf("=== TARGET REACHABILITY AUDIT ===")
	t.Logf("  WebGoat (Port 8082)        : Reachable = %v", webgoatReachable)
	t.Logf("  Mock Traversal Fixture     : Loaded successfully (10 vectors)")

	// 2. Start deterministic mock server implementing 10 distinct traversal scenarios
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		rawQuery := r.URL.RawQuery

		// Vector 1: POSIX /etc/passwd unencoded traversal
		if posixVal := q.Get("posix_vuln"); posixVal != "" {
			if strings.Contains(posixVal, "etc/passwd") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("POSIX Viewer: default view"))
			return
		}

		// Vector 2: Windows win.ini backslash or forward slash traversal
		if winVal := q.Get("windows_vuln"); winVal != "" {
			lower := strings.ToLower(winVal)
			if strings.Contains(lower, `windows\win.ini`) || strings.Contains(lower, `windows/win.ini`) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("; for 16-bit app support\r\n[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Windows Viewer: default document"))
			return
		}

		// Vector 3: URL-encoded traversal (%2e%2e%2f)
		if strings.Contains(rawQuery, "encoded_vuln") {
			if strings.Contains(rawQuery, "%2e%2e%2f") || strings.Contains(rawQuery, "%252e%252e%252f") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"))
				return
			}
			if strings.Contains(rawQuery, "..") {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("Illegal characters not allowed"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Encoded Viewer: default view"))
			return
		}

		// Vector 4: Controlled canary file token
		if canaryVal := q.Get("canary_vuln"); canaryVal != "" {
			if strings.Contains(canaryVal, "felix_canary_proof.txt") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("FELIX_CANARY_TRAVERSAL_CONFIRMED_OK: Lab host verification passed"))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("Canary Viewer: index ready"))
			return
		}

		// Vector 5: Defended clean HTTP 404 Not Found
		if q.Get("defended_404") != "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("404 File Not Found"))
			return
		}

		// Vector 6: Defended clean HTTP 403 Forbidden
		if q.Get("defended_403") != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("403 Forbidden: Directory traversal attempt blocked by web application firewall"))
			return
		}

		// Vector 7: Defended clean HTTP 400 Bad Request
		if q.Get("defended_400") != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Illegal characters are not allowed in the query params"))
			return
		}

		// Vector 8: Defended HTTP 500 error page reflecting path in error message without file content
		if def500 := q.Get("defended_500"); def500 != "" {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(fmt.Sprintf("Internal Server Error: Failed to open file handle for: %s", def500)))
			return
		}

		// Vector 9: Defended HTTP 200 echoing parameter in HTML body without file content
		if defReflect := q.Get("defended_reflect"); defReflect != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(fmt.Sprintf("<html><body><h1>Search Results for: %s</h1><p>No matching documents found.</p></body></html>", defReflect)))
			return
		}

		// Vector 10: Defended font preview page with preexisting [fonts] section in baseline
		if q.Get("defended_baseline") != "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("<html><body><h1>Font Configuration</h1><pre>[fonts]\nVerdana=verdana.ttf</pre></body></html>"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Benchmark baseline response"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	// 10 Standardized Benchmark Vectors
	vectors := []TraversalBenchmarkVector{
		{ID: "posix_vuln", Description: "POSIX /etc/passwd Relative Traversal", IsVulnerable: true, ExpectedCategory: SignaturePOSIXPasswd},
		{ID: "windows_vuln", Description: "Windows win.ini Backslash & Slash Traversal", IsVulnerable: true, ExpectedCategory: SignatureWindowsIni},
		{ID: "encoded_vuln", Description: "URL-Encoded (%2e%2e%2f) Traversal Filter Bypass", IsVulnerable: true, ExpectedCategory: SignaturePOSIXPasswd},
		{ID: "canary_vuln", Description: "Controlled Canary File Token Retrieval", IsVulnerable: true, ExpectedCategory: SignatureCanary},
		{ID: "defended_404", Description: "Defended: Clean HTTP 404 Not Found", IsVulnerable: false},
		{ID: "defended_403", Description: "Defended: HTTP 403 Forbidden with Security Defense", IsVulnerable: false},
		{ID: "defended_400", Description: "Defended: HTTP 400 Bad Request Input Rejection", IsVulnerable: false},
		{ID: "defended_500", Description: "Defended: HTTP 500 Error Page Echoing Path", IsVulnerable: false},
		{ID: "defended_reflect", Description: "Defended: HTTP 200 Reflected Input in HTML Body", IsVulnerable: false},
		{ID: "defended_baseline", Description: "Defended: Preexisting [fonts] Marker in Baseline", IsVulnerable: false},
	}

	var tp, fp, tn, fn int

	for _, v := range vectors {
		t.Run(v.Description, func(t *testing.T) {
			paramVal := "test.txt"
			if v.ID == "encoded_vuln" {
				paramVal = "catalog"
			}
			reqURL := fmt.Sprintf("%s?%s=%s", ts.URL, v.ID, paramVal)
			req, err := http.NewRequest(http.MethodGet, reqURL, nil)
			if err != nil {
				t.Fatalf("Failed to create request for vector %s: %v", v.ID, err)
			}

			params, err := pe.Extract(req)
			if err != nil {
				t.Fatalf("Failed to extract parameters: %v", err)
			}

			var targetParam Parameter
			for _, p := range params {
				if p.Name == v.ID {
					targetParam = p
					break
				}
			}

			findings, err := analyzer.AnalyzeParameter(req, targetParam)
			if err != nil {
				t.Fatalf("AnalyzeParameter failed on vector %s: %v", v.ID, err)
			}

			hasConfirmed := false
			for _, f := range findings {
				if f.Confidence == TraversalConfidenceConfirmed {
					hasConfirmed = true
					break
				}
			}

			if v.IsVulnerable {
				if hasConfirmed {
					tp++
					t.Logf("PASS (True Positive): Vulnerable vector %q correctly confirmed as Path Traversal", v.ID)
				} else {
					fn++
					t.Errorf("FAIL (False Negative): Vulnerable vector %q was NOT confirmed", v.ID)
				}
			} else {
				if hasConfirmed {
					fp++
					t.Errorf("FAIL (False Positive): Defended vector %q was falsely confirmed as Path Traversal", v.ID)
				} else {
					tn++
					t.Logf("PASS (True Negative): Defended vector %q produced 0 false positives", v.ID)
				}
			}
		})
	}

	// 3. Precision, Recall, and Accuracy Metrics
	totalTested := tp + fp + tn + fn
	precision := 0.0
	if tp+fp > 0 {
		precision = float64(tp) / float64(tp+fp) * 100.0
	}
	recall := 0.0
	if tp+fn > 0 {
		recall = float64(tp) / float64(tp+fn) * 100.0
	}

	t.Logf("=== BENCHMARK ACCURACY RESULTS ===")
	t.Logf("  Benchmark Vectors Tested    : %d", totalTested)
	t.Logf("  Vulnerable Vectors Tested   : %d", tp+fn)
	t.Logf("  Defended Vectors Tested     : %d", tn+fp)
	t.Logf("  True Positives (TP)         : %d", tp)
	t.Logf("  False Positives (FP)        : %d", fp)
	t.Logf("  False Negatives (FN)        : %d", fn)
	t.Logf("  True Negatives (TN)         : %d", tn)
	t.Logf("  Path Traversal Precision    : %.2f%%", precision)
	t.Logf("  Path Traversal Recall       : %.2f%%", recall)
	t.Logf("  Defended False Positive Rate: %.2f%%", float64(fp)/float64(tn+fp)*100.0)

	if precision < 100.0 || recall < 100.0 || fp > 0 || fn > 0 {
		t.Fatalf("Benchmark accuracy thresholds breached: precision=%.2f%%, recall=%.2f%%, FP=%d, FN=%d",
			precision, recall, fp, fn)
	}

	// 4. Evidence Receipt Verification
	receiptPath := filepath.Join("..", "..", "test", "evidence", "phase2", "2.4_path_traversal_proof.json")
	receiptBytes, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatalf("Failed to read required evidence receipt at %s: %v", receiptPath, err)
	}

	var diskReceipt map[string]any
	if err := json.Unmarshal(receiptBytes, &diskReceipt); err != nil {
		t.Fatalf("Failed to parse evidence receipt at %s: %v", receiptPath, err)
	}

	expectedHash, ok := diskReceipt["sha256_hash"].(string)
	if !ok || expectedHash == "" {
		t.Fatalf("Receipt at %s is missing sha256_hash", receiptPath)
	}

	delete(diskReceipt, "sha256_hash")
	var verifyBuf bytes.Buffer
	encVerify := json.NewEncoder(&verifyBuf)
	encVerify.SetEscapeHTML(false)
	if err := encVerify.Encode(diskReceipt); err != nil {
		t.Fatalf("Failed to encode receipt for verification: %v", err)
	}
	computedHashBytes := bytes.TrimRight(verifyBuf.Bytes(), "\n")
	computedHashSum := sha256.Sum256(computedHashBytes)
	computedHash := hex.EncodeToString(computedHashSum[:])

	if computedHash != expectedHash {
		t.Fatalf("Evidence receipt SHA-256 verification mismatch: expected %s, got %s", expectedHash, computedHash)
	}
	t.Logf("Receipt SHA-256 cryptographically verified: %s (file: %s)", computedHash, receiptPath)
}

// TestLiveBenchmark_WebGoatPathTraversal verifies path traversal detection against live OWASP WebGoat.
func TestLiveBenchmark_WebGoatPathTraversal(t *testing.T) {
	baseURL := "http://127.0.0.1:8082/WebGoat"
	if !checkHostReachability(baseURL + "/login") {
		t.Skip("WebGoat is not running on 127.0.0.1:8082; skipping live test")
	}

	sessionCookie, err := obtainWebGoatSession(baseURL)
	if err != nil {
		t.Fatalf("Failed to obtain WebGoat session: %v", err)
	}

	pe := NewParameterExtractor()
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	analyzer := NewTraversalAnalyzer(client, pe)

	// WebGoat Path Traversal Profile Retrieval endpoint:
	// GET /WebGoat/PathTraversal/random-picture?id=1
	lessonURL := fmt.Sprintf("%s/PathTraversal/random-picture?id=1", baseURL)
	req, err := http.NewRequest(http.MethodGet, lessonURL, nil)
	if err != nil {
		t.Fatalf("Failed to create live request: %v", err)
	}
	req.AddCookie(sessionCookie)

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Failed to extract parameters: %v", err)
	}

	var idParam *Parameter
	for _, p := range params {
		if p.Name == "id" {
			pCopy := p
			idParam = &pCopy
			break
		}
	}

	if idParam == nil {
		t.Fatalf("Required parameter id not found in extracted parameters")
	}

	// 1. Analyze vulnerable parameter id
	findings, err := analyzer.AnalyzeParameter(req, *idParam)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed on live WebGoat id: %v", err)
	}

	var secretConfirmed bool
	var confirmedFinding TraversalFinding
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && (strings.Contains(f.Evidence, "You found it") || f.SignatureMatched == "OWASP WebGoat Path Traversal Secret") {
			secretConfirmed = true
			confirmedFinding = f
			break
		}
	}

	if !secretConfirmed {
		t.Fatalf("FAIL: Live WebGoat id was NOT confirmed as path traversal (findings count: %d)", len(findings))
	}
	t.Logf("Live WebGoat id CONFIRMED as Path Traversal: Payload=%s, Type=%s, Evidence=%s",
		confirmedFinding.Payload, confirmedFinding.Type, confirmedFinding.Evidence)

	// 2. Analyze defended parameter (safe id value with baseline request)
	safeURL := fmt.Sprintf("%s/PathTraversal/random-picture?safe_param=banner.png", baseURL)
	safeReq, err := http.NewRequest(http.MethodGet, safeURL, nil)
	if err != nil {
		t.Fatalf("Failed to create safe request: %v", err)
	}
	safeReq.AddCookie(sessionCookie)

	safeParams, err := pe.Extract(safeReq)
	if err != nil {
		t.Fatalf("Failed to extract safe parameters: %v", err)
	}

	var safeParam *Parameter
	for _, p := range safeParams {
		if p.Name == "safe_param" {
			pCopy := p
			safeParam = &pCopy
			break
		}
	}

	if safeParam != nil {
		safeFindings, err := analyzer.AnalyzeParameter(safeReq, *safeParam)
		if err != nil {
			t.Fatalf("AnalyzeParameter failed on safe_param: %v", err)
		}
		for _, f := range safeFindings {
			if f.Confidence == TraversalConfidenceConfirmed {
				t.Fatalf("FAIL: False positive on safe_param! Found: %+v", f)
			}
		}
		t.Logf("Live WebGoat safe_param produced 0 false positives (PASS)")
	}
}
