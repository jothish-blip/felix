package webvuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"felix/pkg/report"
)

// 1. Test XSS: Positive and Negative controls
func TestWebVuln_XSS(t *testing.T) {
	// Vulnerable server reflecting raw unescaped input into HTML
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", q)
	}))
	defer vulnServer.Close()

	// Safe server HTML entity encoding input
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		escaped := strings.ReplaceAll(q, "<", "&lt;")
		escaped = strings.ReplaceAll(escaped, ">", "&gt;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", escaped)
	}))
	defer safeServer.Close()

	// JSON server reflecting input inside JSON data
	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"query":"%s","status":"ok"}`, q)
	}))
	defer jsonServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Unescaped HTML Reflection -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-xss-test",
		ExecutionID:  "exec-xss-test",
		BaseURL:      vulnServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/search", Parameters: []string{"q"}},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessXSS(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 {
		t.Fatalf("expected 1 verified XSS finding, got %d", covVuln.Verified)
	}
	if len(resultsVuln) == 0 || resultsVuln[0].VerificationState != StateVerified {
		t.Fatalf("expected result state VERIFIED, got %+v", resultsVuln)
	}
	if len(findingsVuln) != 1 || findingsVuln[0].Severity != report.SeverityHigh {
		t.Fatalf("expected 1 HIGH severity finding, got %+v", findingsVuln)
	}

	// Negative Control: Encoded Reflection -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-xss-safe",
		ExecutionID:  "exec-xss-safe",
		BaseURL:      safeServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/search", Parameters: []string{"q"}},
		},
	}
	resultsSafe, _, covSafe := engine.assessXSS(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 {
		t.Errorf("expected 0 verified XSS on safe server, got %d", covSafe.Verified)
	}
	if len(resultsSafe) == 0 || resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE state for entity encoded response, got %+v", resultsSafe)
	}

	// JSON Control: Reflection in JSON -> OBSERVED (not verified reflected XSS)
	actxJSON := &AssessmentContext{
		AssessmentID: "asm-xss-json",
		ExecutionID:  "exec-xss-json",
		BaseURL:      jsonServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/api/search", Parameters: []string{"q"}},
		},
	}
	resultsJSON, _, covJSON := engine.assessXSS(context.Background(), actxJSON, jsonServer.Client())
	if covJSON.Verified != 0 {
		t.Errorf("expected 0 verified XSS on JSON server, got %d", covJSON.Verified)
	}
	if len(resultsJSON) == 0 || resultsJSON[0].VerificationState != StateObserved {
		t.Errorf("expected OBSERVED state for JSON response, got %+v", resultsJSON)
	}
}

// 2. Test SQL Injection: Database error vs Generic 500 error vs Clean Baseline
func TestWebVuln_SQLi(t *testing.T) {
	// Vulnerable server returning database-specific syntax error on syntax disruption
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `SQLite3::SQLException: near "': syntax error`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id": %s, "name": "Item"}`, id)
	}))
	defer vulnServer.Close()

	// Server returning generic HTTP 500 error without any database syntax signature
	generic500Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `Internal Server Error: strconv.Atoi parsing error`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"id": %s}`, id)
	}))
	defer generic500Server.Close()

	// Safe parameterized server
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status": "ok"}`)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Database syntax disruption -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-sqli-vuln",
		ExecutionID:  "exec-sqli-vuln",
		BaseURL:      vulnServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/items", Parameters: []string{"id"}},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSQLi(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 {
		t.Fatalf("expected 1 verified SQLi finding, got %d", covVuln.Verified)
	}
	if len(resultsVuln) == 0 || resultsVuln[0].VerificationState != StateVerified {
		t.Fatalf("expected StateVerified, got %+v", resultsVuln)
	}
	if len(findingsVuln) != 1 || findingsVuln[0].Severity != report.SeverityCritical {
		t.Fatalf("expected CRITICAL severity finding, got %+v", findingsVuln)
	}

	// Negative Control: Generic 500 -> CANDIDATE (never verified without DB error)
	actxGen := &AssessmentContext{
		AssessmentID: "asm-sqli-gen",
		ExecutionID:  "exec-sqli-gen",
		BaseURL:      generic500Server.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/items", Parameters: []string{"id"}},
		},
	}
	resultsGen, findingsGen, covGen := engine.assessSQLi(context.Background(), actxGen, generic500Server.Client())
	if covGen.Verified != 0 {
		t.Errorf("generic 500 must NOT be marked verified, got %d verified", covGen.Verified)
	}
	if covGen.Candidates != 1 || len(resultsGen) == 0 || resultsGen[0].VerificationState != StateCandidate {
		t.Errorf("expected StateCandidate for generic 500, got %+v", resultsGen)
	}
	if len(findingsGen) != 0 {
		t.Errorf("generic 500 candidate should not produce verified finding, got %d", len(findingsGen))
	}

	// Clean Baseline Control: No disruption -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-sqli-safe",
		ExecutionID:  "exec-sqli-safe",
		BaseURL:      safeServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/items", Parameters: []string{"id"}},
		},
	}
	resultsSafe, _, covSafe := engine.assessSQLi(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 || len(resultsSafe) == 0 || resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE for safe server, got %+v", resultsSafe)
	}
}

// 3. Test NoSQL Injection: Differential query manipulation
func TestWebVuln_NoSQLi(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("user[$ne]") != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `[{"id":1,"user":"admin","role":"root"},{"id":2,"user":"jane","role":"editor"}]`)
			return
		}
		if q.Get("user[$eq]") != "" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `[]`)
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-nosqli",
		ExecutionID:  "exec-nosqli",
		BaseURL:      server.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/users", Parameters: []string{"user"}},
		},
	}

	results, findings, cov := engine.assessNoSQLi(context.Background(), actx, server.Client())
	if cov.Verified != 1 {
		t.Fatalf("expected 1 verified NoSQLi finding, got %d", cov.Verified)
	}
	if len(results) == 0 || results[0].VerificationState != StateVerified {
		t.Fatalf("expected StateVerified, got %+v", results)
	}
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

// 4. Test Server-Side Template Injection: Evaluated arithmetic vs Literal reflection
func TestWebVuln_SSTI(t *testing.T) {
	// Vulnerable SSTI server evaluating template arithmetic (491*13 -> 6383)
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if strings.Contains(name, "{{491*13}}") {
			fmt.Fprint(w, "Hello 6383!")
			return
		}
		fmt.Fprintf(w, "Hello %s!", name)
	}))
	defer vulnServer.Close()

	// Safe server reflecting the input literally
	literalServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		fmt.Fprintf(w, "Hello %s!", name)
	}))
	defer literalServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: Evaluated arithmetic proof -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-ssti-vuln",
		ExecutionID:  "exec-ssti-vuln",
		BaseURL:      vulnServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/greet", Parameters: []string{"name"}},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessSSTI(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 {
		t.Fatalf("expected 1 verified SSTI finding, got %d", covVuln.Verified)
	}
	if len(resultsVuln) == 0 || resultsVuln[0].VerificationState != StateVerified {
		t.Fatalf("expected StateVerified, got %+v", resultsVuln)
	}
	if len(findingsVuln) != 1 || findingsVuln[0].Severity != report.SeverityHigh {
		t.Fatalf("expected 1 HIGH finding, got %+v", findingsVuln)
	}

	// Negative Control: Literal expression reflection -> NOT_VULNERABLE
	actxLit := &AssessmentContext{
		AssessmentID: "asm-ssti-lit",
		ExecutionID:  "exec-ssti-lit",
		BaseURL:      literalServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/greet", Parameters: []string{"name"}},
		},
	}
	resultsLit, _, covLit := engine.assessSSTI(context.Background(), actxLit, literalServer.Client())
	if covLit.Verified != 0 {
		t.Errorf("literal reflection must NOT be marked verified, got %d verified", covLit.Verified)
	}
	for _, r := range resultsLit {
		if r.VerificationState == StateVerified {
			t.Errorf("found unexpected verified state on literal server: %+v", r)
		}
	}
}

// 5. Test Open Redirect: External Location vs Internal/Sanitized
func TestWebVuln_OpenRedirect(t *testing.T) {
	// Vulnerable redirect server reflecting untrusted destination in Location header
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		http.Redirect(w, r, next, http.StatusFound)
	}))
	defer vulnServer.Close()

	// Safe redirect server restricting to local paths
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Positive Control: 302 to external canary domain -> VERIFIED
	actxVuln := &AssessmentContext{
		AssessmentID: "asm-redir-vuln",
		ExecutionID:  "exec-redir-vuln",
		BaseURL:      vulnServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/login", Parameters: []string{"next"}},
		},
	}
	resultsVuln, findingsVuln, covVuln := engine.assessOpenRedirect(context.Background(), actxVuln, vulnServer.Client())
	if covVuln.Verified != 1 {
		t.Fatalf("expected 1 verified open redirect finding, got %d", covVuln.Verified)
	}
	if len(resultsVuln) == 0 || resultsVuln[0].VerificationState != StateVerified {
		t.Fatalf("expected StateVerified, got %+v", resultsVuln)
	}
	if len(findingsVuln) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findingsVuln))
	}

	// Negative Control: Relative path redirect -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-redir-safe",
		ExecutionID:  "exec-redir-safe",
		BaseURL:      safeServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/login", Parameters: []string{"next"}},
		},
	}
	resultsSafe, _, covSafe := engine.assessOpenRedirect(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 {
		t.Errorf("expected 0 verified on safe server, got %d", covSafe.Verified)
	}
	if len(resultsSafe) == 0 || resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %+v", resultsSafe)
	}
}

// 6. Test Information Disclosure: Exposed .env file and Stack Trace with Redaction
func TestWebVuln_InfoDisclosure_And_Redaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "DB_PASSWORD=super_secret_db_pass_1234\nSECRET_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_me\n")
			return
		}
		if r.URL.Query().Get("debug_probe") != "" {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, "Traceback (most recent call last):\n  File \"/app/server.py\", line 42, in handle\n    raise ValueError(\"invalid debug probe\")\n")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-infodisc",
		ExecutionID:  "exec-infodisc",
		BaseURL:      server.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/api/test"},
		},
	}

	results, findings, cov := engine.assessInfoDisclosure(context.Background(), actx, server.Client())
	if cov.Verified < 1 {
		t.Fatalf("expected at least 1 verified info disclosure finding, got %d", cov.Verified)
	}

	// Verify that secrets in results and findings are redacted
	for _, r := range results {
		if strings.Contains(r.EvidenceSummary, "super_secret_db_pass_1234") {
			t.Errorf("raw password leaked in evidence summary: %s", r.EvidenceSummary)
		}
		for k, v := range r.EvidenceDetails {
			if strings.Contains(v, "super_secret_db_pass_1234") {
				t.Errorf("raw password leaked in evidence details[%s]: %s", k, v)
			}
		}
	}
	for _, f := range findings {
		if strings.Contains(f.Evidence, "super_secret_db_pass_1234") {
			t.Errorf("raw password leaked in report finding evidence: %s", f.Evidence)
		}
	}
}

// 7. Test Security Misconfiguration: Directory listing and Debug Console
func TestWebVuln_SecurityMisconfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/static/" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><head><title>Index of /static/</title></head><body><h1>Index of /static/</h1><pre><a href=\"app.js\">app.js</a></pre></body></html>")
			return
		}
		if r.URL.Path == "/console" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><h1>Werkzeug // console</h1><div class=\"debugger\"></div></body></html>")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-misconfig",
		ExecutionID:  "exec-misconfig",
		BaseURL:      server.URL,
	}

	results, findings, cov := engine.assessMisconfiguration(context.Background(), actx, server.Client())
	if cov.Verified != 2 {
		t.Fatalf("expected 2 verified misconfiguration findings, got %d", cov.Verified)
	}
	if len(results) < 2 {
		t.Fatalf("expected at least 2 results, got %d", len(results))
	}
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
}

// 8. Test Scope & Redirect Enforcement
func TestWebVuln_ScopedRedirectEnforcement(t *testing.T) {
	// Destination server outside scope
	outServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Out of scope content")
	}))
	defer outServer.Close()

	// In-scope server redirecting to out-of-scope server
	inServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, outServer.URL, http.StatusFound)
	}))
	defer inServer.Close()

	engine := NewEngine(nil, DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-scope-redir",
		ExecutionID:  "exec-scope-redir",
		BaseURL:      inServer.URL,
		IsAllowed: func(u string) bool {
			return strings.HasPrefix(u, inServer.URL)
		},
		IsExcluded: func(u string) bool {
			return strings.Contains(u, "excluded")
		},
	}

	client := engine.scopedClient(actx)

	// In-scope redirect to out-of-scope destination should fail closed
	req, _ := http.NewRequest("GET", inServer.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatalf("expected redirect to out-of-scope URL to be blocked by client CheckRedirect")
	}
	if !strings.Contains(err.Error(), "out of authorized scope") {
		t.Errorf("expected out of authorized scope error, got %v", err)
	}
}

// 9. Test Synthetic Controls for Command Injection and Path Traversal
func TestWebVuln_SyntheticControls(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("cmd") == "flx_synthetic_sim" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "FLX_SYNTHETIC_CMDI_ACK")
			return
		}
		if q.Get("file") == "../../../../flx_canary_fixture" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "FLX_CANARY_TRAVERSAL_TOKEN_OK")
			return
		}
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())

	// Synthetic test context: SyntheticFixture = true
	actxSynthetic := &AssessmentContext{
		AssessmentID:     "asm-synth",
		ExecutionID:      "exec-synth",
		BaseURL:          server.URL,
		SyntheticFixture: true,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/run", Parameters: []string{"cmd"}},
			{Method: "GET", Path: "/view", Parameters: []string{"file"}},
		},
	}

	// 1. Synthetic CmdI
	_, findingsCmdi, covCmdi := engine.assessCmdi(context.Background(), actxSynthetic, server.Client())
	if covCmdi.Verified != 1 || len(findingsCmdi) != 1 {
		t.Errorf("expected 1 verified synthetic CmdI finding, got %d", covCmdi.Verified)
	}

	// 2. Synthetic Path Traversal
	_, findingsPath, covPath := engine.assessPathTraversal(context.Background(), actxSynthetic, server.Client())
	if covPath.Verified != 1 || len(findingsPath) != 1 {
		t.Errorf("expected 1 verified synthetic Path Traversal finding, got %d", covPath.Verified)
	}

	// Live test context: SyntheticFixture = false (Safety Enforcement: must NOT execute commands or dump files)
	actxLive := &AssessmentContext{
		AssessmentID:     "asm-live",
		ExecutionID:      "exec-live",
		BaseURL:          server.URL,
		SyntheticFixture: false,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/run", Parameters: []string{"cmd"}},
		},
	}
	resultsLiveCmdi, findingsLiveCmdi, covLiveCmdi := engine.assessCmdi(context.Background(), actxLive, server.Client())
	if covLiveCmdi.Verified != 0 {
		t.Errorf("live command injection must NEVER be marked verified without synthetic fixture, got %d", covLiveCmdi.Verified)
	}
	if len(resultsLiveCmdi) == 0 || resultsLiveCmdi[0].VerificationState != StateCandidate {
		t.Errorf("live command parameter must remain StateCandidate, got %+v", resultsLiveCmdi)
	}
	if len(findingsLiveCmdi) != 0 {
		t.Errorf("live command parameter must not produce verified finding, got %d", len(findingsLiveCmdi))
	}
}

// 10. Comprehensive Assess Pipeline Test across all 13 categories
func TestWebVuln_FullPipeline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, "<html><body>Felix Test Target Root</body></html>")
	}))
	defer server.Close()

	engine := NewEngine(server.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID: "asm-pipeline-test",
		ExecutionID:  "exec-pipeline-test",
		BaseURL:      server.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/", Parameters: []string{"q"}},
		},
	}

	results, findings, summary, err := engine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("Assess failed: %v", err)
	}
	if summary == nil {
		t.Fatalf("nil summary returned")
	}
	if summary.CategoriesCovered != 13 {
		t.Errorf("expected all 13 categories to be covered in summary, got %d", summary.CategoriesCovered)
	}
	if len(results) == 0 {
		t.Errorf("expected results to be populated")
	}
	t.Logf("Full pipeline completed with %d tests, %d findings across %d categories",
		summary.TotalTests, len(findings), summary.CategoriesCovered)
}
