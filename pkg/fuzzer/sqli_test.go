package fuzzer

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDynamicContentMasking verifies that pre-comparison baseline diffing and regex masking
// neutralize volatile dynamic timestamps, CSRF nonces, and session tokens ([L2.1]).
func TestDynamicContentMasking(t *testing.T) {
	// Baseline 1 with timestamp and CSRF token A
	baseline1 := `<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
  <div id="header">Welcome user_42! Session: a1b2c3d4e5f60718293a4b5c6d7e8f90</div>
  <div id="meta">Server Time: 2026-10-29T12:00:01.123Z | Rendered in 0.045s</div>
  <form action="/update" method="POST">
    <input type="hidden" name="csrf_token" value="9876543210fedcba09876543210fedcba" />
    <input type="text" name="username" value="admin" />
  </form>
  <div id="content">Account Balance: $500.00</div>
</body>
</html>`

	// Baseline 2 with updated timestamp and rotated CSRF token B
	baseline2 := `<!DOCTYPE html>
<html>
<head><title>User Profile</title></head>
<body>
  <div id="header">Welcome user_42! Session: b2c3d4e5f60718293a4b5c6d7e8f90a1b2</div>
  <div id="meta">Server Time: 2026-10-29T12:00:02.456Z | Rendered in 0.052s</div>
  <form action="/update" method="POST">
    <input type="hidden" name="csrf_token" value="abcdef0123456789abcdef0123456789a" />
    <input type="text" name="username" value="admin" />
  </form>
  <div id="content">Account Balance: $500.00</div>
</body>
</html>`

	// 1. Raw similarity without dynamic masking shows divergence due to volatile nonces
	rawSim := LevenshteinSimilarity(baseline1, baseline2)
	if rawSim >= 0.95 {
		t.Fatalf("Expected raw baselines to exhibit dynamic jitter, but got similarity %.3f", rawSim)
	}

	// 2. Build DynamicMasker from the two baselines
	masker := NewDynamicMasker(baseline1, baseline2)
	masked1 := masker.Mask(baseline1)
	masked2 := masker.Mask(baseline2)

	// 3. Masked baselines must achieve near-perfect or 100% stable DOM similarity
	maskedSim := LevenshteinSimilarity(masked1, masked2)
	if maskedSim < 0.98 {
		t.Fatalf("Expected masked baselines to achieve >= 0.98 similarity, got %.3f", maskedSim)
	}

	skeleton1 := StripDOMSkeleton(masked1)
	skeleton2 := StripDOMSkeleton(masked2)
	skeletonSim := LevenshteinSimilarity(skeleton1, skeleton2)
	if skeletonSim != 1.0 {
		t.Fatalf("Expected masked DOM skeletons to be 100%% identical (1.0), got %.3f", skeletonSim)
	}
}

// TestBooleanDifferential_HighNoise asserts zero false positives on noisy pages
// while accurately detecting true SQL injection differences.
func TestBooleanDifferential_HighNoise(t *testing.T) {
	var requestCount int64

	// Mock server returning dynamic noisy timestamps and tokens on every request
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cnt := atomic.AddInt64(&requestCount, 1)
		q := r.URL.Query().Get("id")

		currentTime := time.Now().Format(time.RFC3339Nano)
		randomNonce := fmt.Sprintf("%032x", cnt*1234567)

		w.Header().Set("Content-Type", "text/html")

		// True condition: returns valid record with dynamic noise
		if q == "1" || strings.Contains(q, "' AND '1'='1") || strings.Contains(q, "AND 1=1") || strings.Contains(q, "OR 1=1") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html>
<body>
<div class="nonce">%s</div>
<div class="time">%s</div>
<div id="record">User Found: Administrator (ID: 1)</div>
</body></html>`, randomNonce, currentTime)
			return
		}

		// False condition: returns "No records found"
		if strings.Contains(q, "' AND '1'='2") || strings.Contains(q, "AND 1=2") || strings.Contains(q, "1=2") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html>
<body>
<div class="nonce">%s</div>
<div class="time">%s</div>
<div id="record">No records found.</div>
</body></html>`, randomNonce, currentTime)
			return
		}

		// Default fallback
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `<html><body><div class="nonce">%s</div><div>Default</div></body></html>`, randomNonce)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	req, err := http.NewRequest("GET", server.URL+"?id=1", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	analyzer := NewSQLiAnalyzer(server.Client(), pe)
	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest returned unexpected error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected SQLi finding on parameter 'id', but got 0 findings")
	}

	var confirmedBool *SQLiFinding
	for _, f := range findings {
		if f.Type == SQLiBooleanDifferential && f.Confidence == ConfidenceConfirmed {
			confirmedBool = &f
			break
		}
	}

	if confirmedBool == nil {
		t.Fatalf("Expected CONFIRMED Boolean Differential SQLi finding, got: %+v", findings)
	}

	if confirmedBool.TrueSimilarity < 0.88 {
		t.Fatalf("Expected TrueSimilarity >= 0.88 despite dynamic noise, got: %.3f", confirmedBool.TrueSimilarity)
	}
	if confirmedBool.ResponseDeltaRatio < 0.10 {
		t.Fatalf("Expected ResponseDeltaRatio >= 0.10, got: %.3f", confirmedBool.ResponseDeltaRatio)
	}
	if !confirmedBool.DynamicNoiseMasked {
		t.Fatalf("Expected DynamicNoiseMasked to be true")
	}
}

// TestBooleanDifferential_NegativeBaselineEquivalence asserts that an unexploitable endpoint
// with heavy random noise does NOT produce a false positive.
func TestBooleanDifferential_NegativeBaselineEquivalence(t *testing.T) {
	var requestCount int64

	// Secure endpoint: simply ignores SQL operators and returns static record with dynamic noise
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cnt := atomic.AddInt64(&requestCount, 1)
		currentTime := time.Now().Format(time.RFC3339Nano)
		randomNonce := fmt.Sprintf("%032x", cnt*987654)

		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Both true and false probes return exactly the same page (no differential)
		fmt.Fprintf(w, `<html>
<body>
<div class="nonce">%s</div>
<div class="time">%s</div>
<div id="content">Static Safe Documentation Page</div>
</body></html>`, randomNonce, currentTime)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	req, err := http.NewRequest("GET", server.URL+"?page=faq", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	analyzer := NewSQLiAnalyzer(server.Client(), pe)
	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest returned unexpected error: %v", err)
	}

	// Must have ZERO confirmed findings (zero false positives)
	for _, f := range findings {
		if f.Confidence == ConfidenceConfirmed {
			t.Fatalf("False positive detected on non-vulnerable endpoint: %+v", f)
		}
	}
}

// TestDBErrorMatcher_AllDialects asserts comprehensive database dialect syntax error identification
// across MySQL, PostgreSQL, MSSQL, Oracle, SQLite, HSQLDB/H2, and MongoDB.
func TestDBErrorMatcher_AllDialects(t *testing.T) {
	matcher := NewDBErrorMatcher()

	cases := []struct {
		Dialect string
		Body    string
	}{
		{"MySQL / MariaDB", "Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"},
		{"PostgreSQL", "org.postgresql.util.PSQLException: ERROR: syntax error at or near \"admin\""},
		{"Microsoft SQL Server", "com.microsoft.sqlserver.jdbc.SQLServerException: Unclosed quotation mark after the character string ''."},
		{"Oracle", "java.sql.SQLException: ORA-00933: SQL command not properly ended"},
		{"SQLite", "System.Data.SQLite.SQLiteException: SQL logic error: near \"'\": syntax error"},
		{"HSQLDB / H2", "org.hsqldb.HsqlException: Syntax error in SQL statement SELECT * FROM user_data WHERE userid=1'"},
		{"MongoDB / NoSQL", "MongoError: Cast to ObjectId failed for value \"admin'\" at path \"_id\""},
	}

	for _, c := range cases {
		dialect, snippet, found := matcher.Match(c.Body)
		if !found {
			t.Fatalf("Failed to match expected DB error for dialect %s. Body: %s", c.Dialect, c.Body)
		}
		if dialect != c.Dialect {
			t.Fatalf("Dialect mismatch: expected %s, got %s (snippet: %s)", c.Dialect, dialect, snippet)
		}
	}
}

// TestDBErrorMatcher_Generic500IsNotConfirmed asserts that a generic 500 error
// without database error signatures is NOT flagged as confirmed SQLi.
func TestDBErrorMatcher_Generic500IsNotConfirmed(t *testing.T) {
	matcher := NewDBErrorMatcher()

	genericBodies := []string{
		"HTTP 500 Internal Server Error",
		"java.lang.NullPointerException at com.example.Controller.doGet",
		"502 Bad Gateway - Nginx",
		"Internal Application Error: Something went wrong.",
	}

	for _, body := range genericBodies {
		_, _, found := matcher.Match(body)
		if found {
			t.Fatalf("Generic error body falsely identified as DB error: %s", body)
		}
		if !matcher.IsGenericFrameworkError(http.StatusInternalServerError, body) {
			t.Fatalf("Expected IsGenericFrameworkError to be true for generic 500: %s", body)
		}
	}
}

// TestTimeBasedLatencyProgression_LinearScaling verifies that time-based SQL injection is confirmed
// ONLY when response durations strictly scale linearly: 1s -> 3s -> 0s control ([L2.2]).
func TestTimeBasedLatencyProgression_LinearScaling(t *testing.T) {
	// Mock server that honors delay queries
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "SLEEP(1)") || strings.Contains(q, "1000") {
			time.Sleep(1000 * time.Millisecond)
		} else if strings.Contains(q, "SLEEP(3)") || strings.Contains(q, "3000") {
			time.Sleep(3000 * time.Millisecond)
		} else if strings.Contains(q, "SLEEP(0)") {
			// 0s control probe
			time.Sleep(10 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	req, err := http.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	analyzer := NewSQLiAnalyzer(server.Client(), pe)
	analyzer.Timeout = 8 * time.Second

	param := Parameter{
		Name:     "q",
		Path:     "query.q",
		Location: LocQuery,
		Value:    "test",
		Context:  ContextAlphanumeric,
	}

	baseReq, _ := pe.GenerateMutation(req, param, "test")
	baseResp, err := analyzer.executeRequest(baseReq)
	if err != nil {
		t.Fatalf("Failed to get baseline: %v", err)
	}

	findings, err := analyzer.AnalyzeTimeBased(req, param, baseResp)
	if err != nil {
		t.Fatalf("AnalyzeTimeBased returned error: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected confirmed time-based finding, got 0")
	}

	finding := findings[0]
	if finding.Type != SQLiTimeBased || finding.Confidence != ConfidenceConfirmed {
		t.Fatalf("Expected CONFIRMED TimeBased finding, got %+v", finding)
	}
	if !finding.TimeScalingVerified {
		t.Fatalf("Expected TimeScalingVerified to be true")
	}
}

// TestTimeBasedLatencyProgression_ConcurrencyFlukeRejection asserts that when a server suffers from
// CPU queuing / load where all requests take ~1.2 seconds, the sequential check REJECTS the fluke.
func TestTimeBasedLatencyProgression_ConcurrencyFlukeRejection(t *testing.T) {
	// Mock overloaded server: every request takes 1.2 seconds regardless of payload (concurrency queue)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"overloaded"}`)
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	req, err := http.NewRequest("GET", server.URL+"?q=load", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	analyzer := NewSQLiAnalyzer(server.Client(), pe)
	analyzer.Timeout = 8 * time.Second

	param := Parameter{
		Name:     "q",
		Path:     "query.q",
		Location: LocQuery,
		Value:    "load",
		Context:  ContextAlphanumeric,
	}

	baseReq, _ := pe.GenerateMutation(req, param, "load")
	baseResp, err := analyzer.executeRequest(baseReq)
	if err != nil {
		t.Fatalf("Failed to get baseline: %v", err)
	}

	findings, err := analyzer.AnalyzeTimeBased(req, param, baseResp)
	if err != nil {
		t.Fatalf("AnalyzeTimeBased returned error: %v", err)
	}

	// Must have 0 confirmed findings because T(3s) - T(1s) was ~0ms (non-linear queuing fluke)
	for _, f := range findings {
		if f.Confidence == ConfidenceConfirmed {
			t.Fatalf("Concurrency queuing fluke falsely confirmed as time-based SQLi: %+v", f)
		}
	}
}

// TestNonTargetPreservation verifies that generating SQLi mutations guarantees 100% preservation
// of all adjacent parameters and headers.
func TestNonTargetPreservation(t *testing.T) {
	pe := NewParameterExtractor()

	origReq, err := http.NewRequest("POST", "http://example.com/api/v1/transfer?auth=true&version=2", strings.NewReader(`{"sender":"alice","recipient":"bob","amount":100}`))
	if err != nil {
		t.Fatalf("Failed to build request: %v", err)
	}
	origReq.Header.Set("Content-Type", "application/json")
	origReq.Header.Set("X-Custom-Header", "preserve-this")

	params, err := pe.Extract(origReq)
	if err != nil {
		t.Fatalf("Failed to extract: %v", err)
	}

	// Target "sender" inside JSON
	var senderParam *Parameter
	for _, p := range params {
		if p.Name == "sender" {
			senderParam = &p
			break
		}
	}
	if senderParam == nil {
		t.Fatalf("Parameter 'sender' not found in extracted parameters")
	}

	mutatedReq, err := pe.GenerateMutation(origReq, *senderParam, "alice' OR 1=1-- ")
	if err != nil {
		t.Fatalf("Failed to mutate: %v", err)
	}

	// Check query preservation
	if mutatedReq.URL.Query().Get("auth") != "true" || mutatedReq.URL.Query().Get("version") != "2" {
		t.Fatalf("Query params corrupted after mutation: %s", mutatedReq.URL.RawQuery)
	}

	// Check header preservation
	if mutatedReq.Header.Get("X-Custom-Header") != "preserve-this" {
		t.Fatalf("Custom header lost after mutation")
	}

	// Check body preservation of non-target fields
	bodyBytes, _ := io.ReadAll(mutatedReq.Body)
	bodyStr := string(bodyBytes)
	if !strings.Contains(bodyStr, `"recipient":"bob"`) || !strings.Contains(bodyStr, `"amount":100`) {
		t.Fatalf("Non-target JSON fields corrupted: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `"alice' OR 1=1-- "`) {
		t.Fatalf("Target payload not injected: %s", bodyStr)
	}
}

// TestConcurrency_20Workers asserts thread-safety and zero data races under parallel analysis.
func TestConcurrency_20Workers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Echo: %s", r.URL.Query().Get("p"))
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSQLiAnalyzer(server.Client(), pe)

	var wg sync.WaitGroup
	workers := 20

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			reqURL := fmt.Sprintf("%s?p=worker_%d", server.URL, workerID)
			req, err := http.NewRequest("GET", reqURL, nil)
			if err != nil {
				t.Errorf("Worker %d failed to create request: %v", workerID, err)
				return
			}
			_, err = analyzer.AnalyzeRequest(req)
			if err != nil {
				t.Errorf("Worker %d AnalyzeRequest failed: %v", workerID, err)
			}
		}(i)
	}

	wg.Wait()
}

// TestTimeBasedLatencyProgression_20WorkerConcurrency evaluates the sequential mathematical progression
// (1s -> 3s -> 0s control) under active 20-worker concurrency load, ensuring that server-side CPU queuing
// is rejected as a fluke, while genuine commanded delays are accurately identified ([L2.2]).
func TestTimeBasedLatencyProgression_20WorkerConcurrency(t *testing.T) {
	var inFlight int64

	// Concurrency-sensitive test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&inFlight, 1)
		defer atomic.AddInt64(&inFlight, -1)

		q := r.URL.Query().Get("q")
		isVulnerable := r.URL.Query().Get("vulnerable") == "true"

		if isVulnerable {
			// Vulnerable branch: executes commanded delays
			if strings.Contains(q, "SLEEP(1)") || strings.Contains(q, "1000") {
				time.Sleep(1000 * time.Millisecond)
			} else if strings.Contains(q, "SLEEP(3)") || strings.Contains(q, "3000") {
				time.Sleep(3000 * time.Millisecond)
			} else if strings.Contains(q, "SLEEP(0)") {
				time.Sleep(15 * time.Millisecond)
			}
		} else {
			// Benign branch under 20-worker load: simulates thread contention / queuing delay
			// where requests experience non-linear delays (e.g. 1100ms flat delay)
			if q != "baseline" {
				time.Sleep(1100 * time.Millisecond)
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"ok","in_flight":%d}`, atomic.LoadInt64(&inFlight))
	}))
	defer server.Close()

	pe := NewParameterExtractor()
	analyzer := NewSQLiAnalyzer(server.Client(), pe)
	analyzer.Timeout = 10 * time.Second

	// 1. Launch 19 background worker routines to generate continuous concurrent load
	stopTraffic := make(chan struct{})
	var bgWg sync.WaitGroup
	var bgRequestsCompleted int64

	for i := 0; i < 19; i++ {
		bgWg.Add(1)
		go func(workerID int) {
			defer bgWg.Done()
			client := server.Client()
			for {
				select {
				case <-stopTraffic:
					return
				default:
					trafficURL := fmt.Sprintf("%s?traffic=worker_%d", server.URL, workerID)
					resp, err := client.Get(trafficURL)
					if err == nil {
						_ = resp.Body.Close()
						atomic.AddInt64(&bgRequestsCompleted, 1)
					}
					time.Sleep(10 * time.Millisecond)
				}
			}
		}(i)
	}

	// Allow background workers to spin up and create concurrency contention
	time.Sleep(100 * time.Millisecond)

	// 2. Worker 20: Test Scenario A - Benign parameter experiencing queuing contention
	// Must REJECT the non-linear latency spike as a concurrency fluke
	param := Parameter{
		Name:     "q",
		Path:     "query.q",
		Location: LocQuery,
		Value:    "benign_load",
		Context:  ContextAlphanumeric,
	}

	baseReq, err := http.NewRequest("GET", server.URL+"?q=baseline", nil)
	if err != nil {
		t.Fatalf("Failed to create base request: %v", err)
	}
	baseResp, err := analyzer.executeRequest(baseReq)
	if err != nil {
		t.Fatalf("Failed to execute baseline under concurrency: %v", err)
	}

	testReq, _ := http.NewRequest("GET", server.URL+"?q=benign_load", nil)
	startTiming := time.Now()
	flukeFindings, err := analyzer.AnalyzeTimeBased(testReq, param, baseResp)
	elapsedFlukeTest := time.Since(startTiming)
	if err != nil {
		t.Fatalf("AnalyzeTimeBased returned error: %v", err)
	}

	t.Logf("[20-Worker Concurrency] Benign Queuing Contention Test completed in %v, Findings count: %d", elapsedFlukeTest, len(flukeFindings))
	for _, f := range flukeFindings {
		if f.Confidence == ConfidenceConfirmed {
			t.Fatalf("FAIL: Concurrency queuing fluke falsely confirmed under 20-worker load: %+v", f)
		}
	}
	t.Log("[20-Worker Concurrency] Zero false-positive flukes confirmed under active concurrent load: PASS")

	// 3. Worker 20: Test Scenario B - Vulnerable parameter with commanded delays under concurrent load
	// Must CONFIRM the vulnerability via strict linear scaling
	vulnParam := Parameter{
		Name:     "q",
		Path:     "query.q",
		Location: LocQuery,
		Value:    "test",
		Context:  ContextAlphanumeric,
	}

	vulnBaseReq, _ := http.NewRequest("GET", server.URL+"?q=baseline&vulnerable=true", nil)
	vulnBaseResp, err := analyzer.executeRequest(vulnBaseReq)
	if err != nil {
		t.Fatalf("Failed to execute vuln baseline: %v", err)
	}

	vulnReq, _ := http.NewRequest("GET", server.URL+"?q=test&vulnerable=true", nil)
	startVulnTiming := time.Now()
	vulnFindings, err := analyzer.AnalyzeTimeBased(vulnReq, vulnParam, vulnBaseResp)
	elapsedVulnTest := time.Since(startVulnTiming)
	if err != nil {
		t.Fatalf("AnalyzeTimeBased vuln test returned error: %v", err)
	}

	// Stop background traffic
	close(stopTraffic)
	bgWg.Wait()

	t.Logf("[20-Worker Concurrency] Total background requests handled during test: %d", atomic.LoadInt64(&bgRequestsCompleted))
	t.Logf("[20-Worker Concurrency] Vulnerable linear delay test completed in %v, Findings: %d", elapsedVulnTest, len(vulnFindings))

	if len(vulnFindings) == 0 {
		t.Fatalf("FAIL: Expected confirmed time-based finding under 20-worker concurrency, got 0")
	}

	vulnFinding := vulnFindings[0]
	if vulnFinding.Confidence != ConfidenceConfirmed || !vulnFinding.TimeScalingVerified {
		t.Fatalf("FAIL: Finding not properly confirmed with TimeScalingVerified=true: %+v", vulnFinding)
	}
	t.Logf("[20-Worker Concurrency] Verified Finding: Evidence=%s", vulnFinding.Evidence)
}
