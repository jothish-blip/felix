package fuzzer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTraversal_POSIXPasswd_StandardTraversal verifies detection of unencoded POSIX traversal.
func TestTraversal_POSIXPasswd_StandardTraversal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fileParam := r.URL.Query().Get("file")
		if strings.Contains(fileParam, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Welcome to file viewer"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"?file=intro.txt", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	params, err := pe.Extract(req)
	if err != nil {
		t.Fatalf("Failed to extract parameters: %v", err)
	}

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmed bool
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && f.Type == TraversalPOSIX {
			confirmed = true
			if !strings.Contains(f.Evidence, "root:x:0:0:") {
				t.Errorf("Expected evidence to contain root:x:0:0:, got %q", f.Evidence)
			}
			t.Logf("Confirmed POSIX Traversal: Payload=%s, Evidence=%s", f.Payload, f.Evidence)
			break
		}
	}

	if !confirmed {
		t.Fatalf("Expected confirmed POSIX traversal finding, got %d findings", len(findings))
	}
}

// TestTraversal_POSIXPasswd_EncodedTraversal verifies detection of URL-encoded traversal probes.
func TestTraversal_POSIXPasswd_EncodedTraversal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server checks raw query string for decoded traversal and rejects, but decodes URL-encoding
		rawQuery := r.URL.RawQuery
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
		_, _ = w.Write([]byte("Default catalog view"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?page=catalog", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmedEncoded bool
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && f.Type == TraversalEncoded {
			confirmedEncoded = true
			t.Logf("Confirmed Encoded Traversal: Payload=%s, Evidence=%s", f.Payload, f.Evidence)
			break
		}
	}

	if !confirmedEncoded {
		t.Fatalf("Expected confirmed encoded traversal finding, got %d findings", len(findings))
	}
}

// TestTraversal_WindowsWinIni_BackslashTraversal verifies Windows-style backslash traversal.
func TestTraversal_WindowsWinIni_BackslashTraversal(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := r.URL.Query().Get("doc")
		if strings.Contains(strings.ToLower(doc), `windows\win.ini`) || strings.Contains(strings.ToLower(doc), `windows/win.ini`) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("; for 16-bit app support\r\n[fonts]\r\nArial=arial.ttf\r\n[extensions]\r\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Document viewer initial page"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?doc=readme.txt", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmedWindows bool
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && f.Type == TraversalWindows {
			confirmedWindows = true
			if !strings.Contains(f.Evidence, "[fonts]") && !strings.Contains(f.Evidence, "[extensions]") {
				t.Errorf("Expected evidence to contain [fonts] or [extensions], got %q", f.Evidence)
			}
			t.Logf("Confirmed Windows Traversal: Payload=%s, Evidence=%s", f.Payload, f.Evidence)
			break
		}
	}

	if !confirmedWindows {
		t.Fatalf("Expected confirmed Windows traversal finding, got %d findings", len(findings))
	}
}

// TestTraversal_CanaryToken_Proof verifies controlled canary token matching.
func TestTraversal_CanaryToken_Proof(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "felix_canary_proof.txt") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("FELIX_CANARY_TRAVERSAL_CONFIRMED_OK: Lab host verification passed"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Safe index page"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=index.html", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmedCanary bool
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && f.Type == TraversalCanary {
			confirmedCanary = true
			t.Logf("Confirmed Canary Traversal: Payload=%s, Evidence=%s", f.Payload, f.Evidence)
			break
		}
	}

	if !confirmedCanary {
		t.Fatalf("Expected confirmed canary traversal finding, got %d findings", len(findings))
	}
}

// TestTraversal_Defended_404NotFound_ZeroFalsePositives verifies 0 false positives on HTTP 404.
func TestTraversal_Defended_404NotFound_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("404 File Not Found"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=missing.txt", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on 404! Found confirmed traversal: %+v", f)
		}
	}
	t.Logf("Verified 0 false positives on HTTP 404 (PASS)")
}

// TestTraversal_Defended_403Forbidden_ZeroFalsePositives verifies 0 false positives on HTTP 403.
func TestTraversal_Defended_403Forbidden_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("Access Denied: Path traversal attempt blocked by security filter."))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?path=document.pdf", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on 403! Found confirmed traversal: %+v", f)
		}
	}
	t.Logf("Verified 0 false positives on HTTP 403 (PASS)")
}

// TestTraversal_Defended_400BadRequest_ZeroFalsePositives verifies 0 false positives on HTTP 400.
func TestTraversal_Defended_400BadRequest_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Illegal characters are not allowed in the query params"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?id=1", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on 400! Found confirmed traversal: %+v", f)
		}
	}
	t.Logf("Verified 0 false positives on HTTP 400 (PASS)")
}

// TestTraversal_Defended_500ErrorPage_ZeroFalsePositives verifies error pages mentioning paths do not confirm file reads.
func TestTraversal_Defended_500ErrorPage_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		file := r.URL.Query().Get("file")
		_, _ = w.Write([]byte(fmt.Sprintf("Internal Error: Failed to open file handle for: %s", file)))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=test.txt", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on 500 error page! Found confirmed traversal: %+v", f)
		}
	}
	t.Logf("Verified 0 false positives on 500 error page (PASS)")
}

// TestTraversal_ReflectedPayloadInHTML_ZeroFalsePositives verifies parameter reflection without file contents is rejected.
func TestTraversal_ReflectedPayloadInHTML_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		q := r.URL.Query().Get("search_file")
		_, _ = w.Write([]byte(fmt.Sprintf("<html><body><h1>Search Results for: %s</h1><p>No matching files found.</p></body></html>", q)))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?search_file=annual_report.pdf", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on reflected payload! Found confirmed traversal: %+v", f)
		}
	}
	t.Logf("Verified 0 false positives on reflected payload in HTML (PASS)")
}

// TestTraversal_BaselineExclusion verifies that markers already present in the baseline are ignored.
func TestTraversal_BaselineExclusion(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Baseline already has [fonts] section because it is a font configuration service
		_, _ = w.Write([]byte("<html><body><h1>Font Configuration</h1><pre>[fonts]\nVerdana=verdana.ttf</pre></body></html>"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?view=fonts", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == TraversalConfidenceConfirmed && f.SignatureMatched == "Windows win.ini" {
			t.Fatalf("False positive! Baseline signature was falsely confirmed: %+v", f)
		}
	}
	t.Logf("Verified baseline exclusion prevents false positives (PASS)")
}

// TestTraversal_CandidatePathDisclosure verifies stack trace / internal path disclosure classification.
func TestTraversal_CandidatePathDisclosure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("file")
		if strings.Contains(q, "..") {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("java.io.FileNotFoundException: C:\\SecurityLabs\\app\\uploads\\" + q + " (The system cannot find the path specified)"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("File viewer ready"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=doc.txt", nil)
	params, _ := pe.Extract(req)

	findings, err := analyzer.AnalyzeParameter(req, params[0])
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var candidateFound bool
	for _, f := range findings {
		if f.Confidence == TraversalConfidenceCandidate && strings.Contains(f.Evidence, "FileNotFoundException") {
			candidateFound = true
			t.Logf("Path disclosure classified as CANDIDATE: Evidence=%s", f.Evidence)
			break
		}
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("Path disclosure must not be marked CONFIRMED file read: %+v", f)
		}
	}

	if !candidateFound {
		t.Fatalf("Expected candidate path disclosure finding, got %d findings", len(findings))
	}
}

// TestTraversal_MultipleParameters_Isolation verifies mutation isolation across multiple parameters.
func TestTraversal_MultipleParameters_Isolation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		doc := q.Get("doc")
		user := q.Get("user")
		action := q.Get("action")

		// Assert unmutated non-target parameters are strictly preserved
		if user != "alice" || action != "view" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Corrupted non-target parameters"))
			return
		}

		if strings.Contains(doc, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Doc viewer ok"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?doc=notes.txt&user=alice&action=view", nil)
	params, _ := pe.Extract(req)

	var docParam, userParam Parameter
	for _, p := range params {
		if p.Name == "doc" {
			docParam = p
		} else if p.Name == "user" {
			userParam = p
		}
	}

	// 1. Analyze vulnerable doc parameter
	docFindings, err := analyzer.AnalyzeParameter(req, docParam)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed on doc: %v", err)
	}

	var docConfirmed bool
	for _, f := range docFindings {
		if f.Confidence == TraversalConfidenceConfirmed {
			docConfirmed = true
			break
		}
	}
	if !docConfirmed {
		t.Fatalf("Expected doc parameter to be confirmed vulnerable")
	}

	// 2. Analyze safe user parameter
	userFindings, err := analyzer.AnalyzeParameter(req, userParam)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed on user: %v", err)
	}
	for _, f := range userFindings {
		if f.Confidence == TraversalConfidenceConfirmed {
			t.Fatalf("False positive on safe parameter user: %+v", f)
		}
	}
	t.Logf("Multi-parameter isolation verified: doc confirmed, user produced 0 false positives (PASS)")
}

// TestTraversal_MalformedResponses_NoPanics verifies analyzer resilience on malformed and irregular responses.
func TestTraversal_MalformedResponses_NoPanics(t *testing.T) {
	testCases := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{"Empty_Body", http.StatusOK, []byte{}},
		{"Binary_Garbage", http.StatusOK, []byte{0x00, 0xFF, 0xFE, 0x12, 0x89, 0x50, 0x4E, 0x47}},
		{"Truncated_Headers", http.StatusBadGateway, []byte("502 Bad Gateway")},
		{"Large_Noise", http.StatusOK, []byte(strings.Repeat("RANDOM_DATA_BLOCK_", 5000))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.statusCode)
				_, _ = w.Write(tc.body)
			}))
			defer ts.Close()

			client := ts.Client()
			pe := NewParameterExtractor()
			analyzer := NewTraversalAnalyzer(client, pe)

			req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=test", nil)
			params, _ := pe.Extract(req)

			findings, err := analyzer.AnalyzeParameter(req, params[0])
			if err != nil {
				t.Fatalf("AnalyzeParameter failed unexpectedly: %v", err)
			}
			_ = findings
		})
	}
}

// TestTraversal_Concurrency_20Workers verifies high-concurrency race freedom.
func TestTraversal_Concurrency_20Workers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		file := r.URL.Query().Get("file")
		if strings.Contains(file, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Normal content"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?file=index.html", nil)
	params, _ := pe.Extract(req)

	var wg sync.WaitGroup
	errCh := make(chan error, 20)

	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			findings, err := analyzer.AnalyzeParameter(req, params[0])
			if err != nil {
				errCh <- fmt.Errorf("worker %d error: %w", workerID, err)
				return
			}
			hasConfirmed := false
			for _, f := range findings {
				if f.Confidence == TraversalConfidenceConfirmed {
					hasConfirmed = true
					break
				}
			}
			if !hasConfirmed {
				errCh <- fmt.Errorf("worker %d failed to confirm finding", workerID)
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatal(err)
	}
	t.Logf("20-worker concurrent path traversal analysis completed with 100%% deterministic confirmation across all workers")
}

// TestTraversal_ContextCancellation_Timeout verifies context cancellation handling.
func TestTraversal_ContextCancellation_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Delayed response"))
	}))
	defer ts.Close()

	client := ts.Client()
	pe := NewParameterExtractor()
	analyzer := NewTraversalAnalyzer(client, pe)
	analyzer.Timeout = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"?file=slow.txt", nil)
	params, _ := pe.Extract(req)

	// Should not hang and gracefully return error
	_, err := analyzer.AnalyzeParameter(req, params[0])
	if err == nil {
		t.Fatalf("Expected timeout / context cancellation error, got nil")
	}
	t.Logf("Context cancellation safely handled: %v", err)
}
