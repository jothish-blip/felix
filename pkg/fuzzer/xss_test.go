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

// 1. Reflected payload in HTML body context (unencoded -> CONFIRMED)
func TestXSS_ReflectedHTMLBody_Unencoded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><h1>Welcome</h1><div>User: %s</div></body></html>", q)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?user=alice", nil)
	param := Parameter{
		Name:     "user",
		Path:     "query.user",
		Location: LocQuery,
		Value:    "alice",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmed *XSSFinding
	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			confirmed = &f
			break
		}
	}

	if confirmed == nil {
		t.Fatalf("Expected CONFIRMED XSS finding for unencoded HTML body reflection, got 0 confirmed out of %d findings", len(findings))
	}

	if confirmed.Type != XSSTypeReflectedBody || confirmed.Context != XSSContextHTMLBody {
		t.Errorf("Unexpected finding classification: Type=%s, Context=%s", confirmed.Type, confirmed.Context)
	}
	if !confirmed.UnencodedReflected {
		t.Errorf("Expected UnencodedReflected=true")
	}
	t.Logf("Confirmed HTML Body XSS: Evidence=%s, Rationale=%s", confirmed.Evidence, confirmed.ExecutionRationale)
}

// 2. Reflected payload in HTML body context properly entity-encoded (defended -> NOT_EXPOSED)
func TestXSS_ReflectedHTMLBody_EntityEncoded(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		// Safely entity encode <, >, ", '
		safe := strings.ReplaceAll(q, "&", "&amp;")
		safe = strings.ReplaceAll(safe, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		safe = strings.ReplaceAll(safe, "\"", "&quot;")
		safe = strings.ReplaceAll(safe, "'", "&#39;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><h1>Welcome</h1><div>User: %s</div></body></html>", safe)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?user=alice", nil)
	param := Parameter{
		Name:     "user",
		Path:     "query.user",
		Location: LocQuery,
		Value:    "alice",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			t.Fatalf("FAIL: False positive! Entity-encoded reflection was incorrectly flagged as CONFIRMED: %+v", f)
		}
	}

	var defendedFound bool
	for _, f := range findings {
		if f.Confidence == XSSConfidenceNotExposed && f.EncodedReflected {
			defendedFound = true
			t.Logf("Correctly classified encoded reflection as NOT_EXPOSED: %s", f.ExecutionRationale)
			break
		}
	}
	if !defendedFound && len(findings) > 0 {
		t.Logf("Notice: findings count %d, none flagged as confirmed (PASS)", len(findings))
	}
}

// 3. Reflected payload inside HTML attribute (quote breakout -> CONFIRMED)
func TestXSS_ReflectedHTMLAttribute_DoubleQuoteBreakout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><form><input type="text" name="search" value="%s"></form></body></html>`, search)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?search=books", nil)
	param := Parameter{
		Name:     "search",
		Path:     "query.search",
		Location: LocQuery,
		Value:    "books",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmed *XSSFinding
	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed && (f.Context == XSSContextHTMLAttribute || f.Context == XSSContextHTMLBody) {
			confirmed = &f
			break
		}
	}

	if confirmed == nil {
		t.Fatalf("Expected CONFIRMED finding for attribute breakout, got 0 confirmed out of %d findings", len(findings))
	}
	t.Logf("Confirmed Attribute XSS: Evidence=%s, Rationale=%s", confirmed.Evidence, confirmed.ExecutionRationale)
}

// 4. Reflected payload inside HTML attribute with entity-encoded quotes (defended -> NOT_EXPOSED)
func TestXSS_ReflectedHTMLAttribute_EntityEncodedQuotes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		// Safely encode quotes
		safe := strings.ReplaceAll(search, "\"", "&quot;")
		safe = strings.ReplaceAll(safe, "'", "&#39;")
		safe = strings.ReplaceAll(safe, "<", "&lt;")
		safe = strings.ReplaceAll(safe, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><form><input type="text" name="search" value="%s"></form></body></html>`, safe)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?search=books", nil)
	param := Parameter{
		Name:     "search",
		Path:     "query.search",
		Location: LocQuery,
		Value:    "books",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			t.Fatalf("FAIL: Attribute with encoded quotes was incorrectly flagged as CONFIRMED: %+v", f)
		}
	}
	t.Log("Verified 0 false positives for attribute with encoded quotes")
}

// 5. Reflected payload inside JavaScript script tag (string literal breakout -> CONFIRMED)
func TestXSS_ReflectedScript_StringBreakout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><head><script>var userName = '%s'; console.log(userName);</script></head><body></body></html>`, name)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?name=alice", nil)
	param := Parameter{
		Name:     "name",
		Path:     "query.name",
		Location: LocQuery,
		Value:    "alice",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmed *XSSFinding
	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			confirmed = &f
			break
		}
	}

	if confirmed == nil {
		t.Fatalf("Expected CONFIRMED finding for JavaScript string breakout, got 0 confirmed out of %d findings", len(findings))
	}
	t.Logf("Confirmed Script Tag XSS: Evidence=%s, Rationale=%s", confirmed.Evidence, confirmed.ExecutionRationale)
}

// 6. Reflected payload inside script tag with backslash-escaped quotes (defended -> NOT_EXPOSED)
func TestXSS_ReflectedScript_BackslashEscaped(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		// Backslash-escape quotes and strip </script>
		safe := strings.ReplaceAll(name, `\`, `\\`)
		safe = strings.ReplaceAll(safe, `'`, `\'`)
		safe = strings.ReplaceAll(safe, `"`, `\"`)
		safe = strings.ReplaceAll(safe, `</script>`, `<\/script>`)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><head><script>var userName = '%s'; console.log(userName);</script></head><body></body></html>`, safe)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?name=alice", nil)
	param := Parameter{
		Name:     "name",
		Path:     "query.name",
		Location: LocQuery,
		Value:    "alice",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			t.Fatalf("FAIL: Safely escaped script reflection was incorrectly flagged as CONFIRMED: %+v", f)
		}
	}
	t.Log("Verified 0 false positives for backslash-escaped script reflection")
}

// 7. Reflected payload inside inert tags: <textarea> and <title> without breakout (defended -> NOT_EXPOSED)
func TestXSS_InertTag_TextareaAndTitle(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := r.URL.Query().Get("msg")
		// If payload closes textarea, simulate breakout defense by stripping </textarea>
		safe := strings.ReplaceAll(msg, "</textarea>", "")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><head><title>Search: %s</title></head><body><textarea name="comment">%s</textarea></body></html>`, safe, safe)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?msg=feedback", nil)
	param := Parameter{
		Name:     "msg",
		Path:     "query.msg",
		Location: LocQuery,
		Value:    "feedback",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			t.Fatalf("FAIL: Reflection inside <textarea> without breakout was incorrectly flagged as CONFIRMED: %+v", f)
		}
	}
	t.Log("Verified 0 false positives for inert <textarea> and <title> contexts")
}

// 8. Reflected payload inside HTML comment with breakout sequence (--> <felix_xss_probe>)
func TestXSS_HTMLComment_Breakout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		note := r.URL.Query().Get("note")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><!-- Developer Note: %s --><div>Content</div></body></html>`, note)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?note=internal", nil)
	param := Parameter{
		Name:     "note",
		Path:     "query.note",
		Location: LocQuery,
		Value:    "internal",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	var confirmed *XSSFinding
	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			confirmed = &f
			break
		}
	}

	if confirmed == nil {
		t.Fatalf("Expected CONFIRMED finding for comment breakout, got 0 confirmed out of %d findings", len(findings))
	}
	t.Logf("Confirmed Comment Breakout XSS: Evidence=%s, Rationale=%s", confirmed.Evidence, confirmed.ExecutionRationale)
}

// 9. Dynamic response noise and ambient mentions of XSS
func TestXSS_DynamicResponseNoise_ZeroFalsePositives(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Page contains ambient text with probe keywords and timestamps, but DOES NOT reflect parameter
		fmt.Fprintf(w, `<html><body>
			<div>Security notice: <felix_xss_probe> is a test keyword. Timestamp: %d</div>
			<div>Autofocus rules: onfocus="felix_xss_probe()" is prohibited.</div>
		</body></html>`, time.Now().UnixNano())
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?session_id=abc123xyz", nil)
	param := Parameter{
		Name:     "session_id",
		Path:     "query.session_id",
		Location: LocQuery,
		Value:    "abc123xyz",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	if len(findings) != 0 {
		t.Fatalf("FAIL: Expected 0 findings for unreflected parameter with ambient page noise, got %d: %+v", len(findings), findings)
	}
	t.Log("Verified 0 false positives on dynamic noisy pages with ambient probe keywords")
}

// 10. Malformed responses, HTTP errors, and non-panics
func TestXSS_MalformedResponses_NoPanics(t *testing.T) {
	scenarios := []struct {
		name       string
		statusCode int
		body       string
		cType      string
	}{
		{"Empty Body", 200, "", "text/html"},
		{"Truncated HTML Tag", 200, "<html><body><div <unclosed tag", "text/html"},
		{"Malformed JSON", 200, `{"broken": `, "application/json"},
		{"Binary Stream", 200, "\x00\x01\x02\xFF\xFE\xFD", "application/octet-stream"},
		{"Internal Server Error 500", 500, "500 Internal Error", "text/plain"},
		{"Not Found 404", 404, "404 Page Not Found", "text/html"},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", sc.cType)
				w.WriteHeader(sc.statusCode)
				w.Write([]byte(sc.body))
			}))
			defer ts.Close()

			pe := NewParameterExtractor()
			analyzer := NewXSSAnalyzer(ts.Client(), pe)
			req, _ := http.NewRequest(http.MethodGet, ts.URL+"?input=test", nil)
			param := Parameter{
				Name:     "input",
				Path:     "query.input",
				Location: LocQuery,
				Value:    "test",
				Context:  ContextAlphanumeric,
			}

			findings, err := analyzer.AnalyzeParameter(req, param)
			if err != nil && sc.statusCode == 200 && sc.name != "Malformed JSON" {
				t.Errorf("Unexpected error for %s: %v", sc.name, err)
			}
			_ = findings
		})
	}
}

// 11. Multi-parameter isolation and non-target parameter preservation
func TestXSS_MultipleParameters_Isolation(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		vuln := q.Get("vuln_param")
		safe := q.Get("safe_param")
		_ = q.Get("ignored_param")

		safeEncoded := strings.ReplaceAll(safe, "<", "&lt;")
		safeEncoded = strings.ReplaceAll(safeEncoded, ">", "&gt;")

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body>
			<div class="vuln">%s</div>
			<div class="safe">%s</div>
		</body></html>`, vuln, safeEncoded)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	analyzer := NewXSSAnalyzer(ts.Client(), pe)

	reqURL := fmt.Sprintf("%s?vuln_param=test1&safe_param=test2&ignored_param=test3", ts.URL)
	req, _ := http.NewRequest(http.MethodGet, reqURL, nil)

	findings, err := analyzer.AnalyzeRequest(req)
	if err != nil {
		t.Fatalf("AnalyzeRequest failed: %v", err)
	}

	var vulnConfirmedCount int
	var safeConfirmedCount int
	var ignoredConfirmedCount int

	for _, f := range findings {
		if f.Confidence == XSSConfidenceConfirmed {
			switch f.Parameter.Name {
			case "vuln_param":
				vulnConfirmedCount++
			case "safe_param":
				safeConfirmedCount++
			case "ignored_param":
				ignoredConfirmedCount++
			}
		}
	}

	if vulnConfirmedCount == 0 {
		t.Errorf("Expected vuln_param to have confirmed findings, got 0")
	}
	if safeConfirmedCount != 0 {
		t.Errorf("FAIL: safe_param had %d false positive confirmed findings", safeConfirmedCount)
	}
	if ignoredConfirmedCount != 0 {
		t.Errorf("FAIL: ignored_param had %d false positive confirmed findings", ignoredConfirmedCount)
	}
	t.Logf("Multi-parameter isolation verified: vuln confirmed=%d, safe confirmed=%d, ignored confirmed=%d",
		vulnConfirmedCount, safeConfirmedCount, ignoredConfirmedCount)
}

// 12. Concurrency, thread safety, and race verification
func TestXSS_Concurrency_20Workers(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><h1>Search: %s</h1></body></html>`, q)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	analyzer := NewXSSAnalyzer(ts.Client(), pe)

	workers := 20
	var wg sync.WaitGroup
	wg.Add(workers)

	results := make([]int, workers)

	for i := 0; i < workers; i++ {
		go func(workerID int) {
			defer wg.Done()
			reqURL := fmt.Sprintf("%s?q=worker_%d", ts.URL, workerID)
			req, _ := http.NewRequest(http.MethodGet, reqURL, nil)
			param := Parameter{
				Name:     "q",
				Path:     "query.q",
				Location: LocQuery,
				Value:    fmt.Sprintf("worker_%d", workerID),
				Context:  ContextAlphanumeric,
			}
			findings, err := analyzer.AnalyzeParameter(req, param)
			if err != nil {
				return
			}
			for _, f := range findings {
				if f.Confidence == XSSConfidenceConfirmed {
					results[workerID]++
				}
			}
		}(i)
	}

	wg.Wait()

	for i := 0; i < workers; i++ {
		if results[i] == 0 {
			t.Errorf("Worker %d failed to confirm XSS under concurrency", i)
		}
	}
	t.Logf("20-worker concurrent XSS analysis completed with 100%% deterministic confirmation across all workers")
}

// 13. Context cancellation and timeout handling
func TestXSS_ContextCancellation_Timeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Server intentionally hangs for 5 seconds
		time.Sleep(2 * time.Second)
		fmt.Fprintf(w, "<html><body>Delayed</body></html>")
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	client := ts.Client()
	analyzer := NewXSSAnalyzer(client, pe)
	analyzer.Timeout = 100 * time.Millisecond // Tight timeout

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?p=slow", nil)
	param := Parameter{
		Name:     "p",
		Path:     "query.p",
		Location: LocQuery,
		Value:    "slow",
		Context:  ContextAlphanumeric,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req = req.WithContext(ctx)

	findings, err := analyzer.AnalyzeParameter(req, param)
	// Must not hang, must return error or 0 findings safely
	if err == nil && len(findings) > 0 {
		t.Fatalf("Expected timeout error, got findings: %+v", findings)
	}
	t.Log("Context cancellation and request timeout safely handled")
}

// 14. Audit verification: Distinguish custom tag markup injection from executable script reflection
func TestXSS_Classification_CustomTag_Is_MarkupInjection_Not_ConfirmedJS(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("user")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body><div>Greeting: %s</div></body></html>", q)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	analyzer := NewXSSAnalyzer(ts.Client(), pe)
	// Specifically test custom tag injection alone
	analyzer.Probes = []XSSProbeDefinition{
		{
			Name:            "CUSTOM_TAG_ONLY",
			Context:         XSSContextHTMLBody,
			Payload:         "<felix_xss_probe>",
			BreakoutTag:     "felix_xss_probe",
			IsScriptPayload: false,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?user=test", nil)
	param := Parameter{
		Name:     "user",
		Path:     "query.user",
		Location: LocQuery,
		Value:    "test",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected at least 1 finding for custom tag reflection, got 0")
	}

	finding := findings[0]
	// Assert it does NOT claim confirmed JS execution
	if finding.Confidence == XSSConfidenceConfirmed {
		t.Fatalf("FAIL: Custom tag creation alone (<felix_xss_probe>) was falsely classified as CONFIRMED JavaScript execution")
	}
	if finding.Confidence != XSSConfidenceCandidate {
		t.Errorf("Expected Confidence=CANDIDATE, got %s", finding.Confidence)
	}
	if finding.Type != XSSTypeHTMLInjection {
		t.Errorf("Expected Type=HTML_INJECTION, got %s", finding.Type)
	}
	if finding.EvidenceModel != ModelMarkupInjection {
		t.Errorf("Expected EvidenceModel=MARKUP_INJECTION, got %s", finding.EvidenceModel)
	}
	t.Logf("PASS: Custom tag reflection correctly classified as HTML_INJECTION (CANDIDATE / MARKUP_INJECTION): %s", finding.ExecutionRationale)
}

// 15. Audit verification: Parser-visible structure vs browser runtime execution
func TestXSS_Classification_ParserVisibleStructure_NotBrowserRuntime(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<html><body><input value="%s"></body></html>`, q)
	}))
	defer ts.Close()

	pe := NewParameterExtractor()
	analyzer := NewXSSAnalyzer(ts.Client(), pe)
	analyzer.Probes = []XSSProbeDefinition{
		{
			Name:            "ATTR_EVENT_HANDLER",
			Context:         XSSContextHTMLAttribute,
			Payload:         `" autofocus onfocus="felix_xss_probe()`,
			BreakoutAttr:    "onfocus",
			IsScriptPayload: true,
		},
	}

	req, _ := http.NewRequest(http.MethodGet, ts.URL+"?q=test", nil)
	param := Parameter{
		Name:     "q",
		Path:     "query.q",
		Location: LocQuery,
		Value:    "test",
		Context:  ContextAlphanumeric,
	}

	findings, err := analyzer.AnalyzeParameter(req, param)
	if err != nil {
		t.Fatalf("AnalyzeParameter failed: %v", err)
	}

	if len(findings) == 0 {
		t.Fatalf("Expected event handler finding, got 0")
	}

	finding := findings[0]
	if finding.Confidence != XSSConfidenceConfirmed {
		t.Errorf("Expected Confidence=CONFIRMED, got %s", finding.Confidence)
	}
	if finding.EvidenceModel != ModelParserStructure {
		t.Errorf("Expected EvidenceModel=PARSER_STRUCTURE, got %s", finding.EvidenceModel)
	}
	t.Logf("PASS: Event-handler attribute breakout verified with EvidenceModel=PARSER_STRUCTURE: %s", finding.ExecutionRationale)
}
