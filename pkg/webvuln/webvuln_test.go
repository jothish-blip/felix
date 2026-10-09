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

// 1. Test XSS: Comprehensive verification hardening covering all 8 criteria
func TestWebVuln_XSS(t *testing.T) {
	// Server 1: Harmless text reflection (server strips HTML tags)
	textServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		stripped := strings.ReplaceAll(strings.ReplaceAll(q, "<", ""), ">", "")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", stripped)
	}))
	defer textServer.Close()

	// Server 2: HTML-entity-encoded reflection
	entityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		escaped := strings.ReplaceAll(strings.ReplaceAll(q, "<", "&lt;"), ">", "&gt;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", escaped)
	}))
	defer entityServer.Close()

	// Server 3: Inert custom HTML tag in HTML body
	inertServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><body>Search results for: %s</body></html>", q)
	}))
	defer inertServer.Close()

	// Server 4: A script element containing a harmless string
	stringScriptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><script>var query = \"%s\";</script></head><body>Search</body></html>", q)
	}))
	defer stringScriptServer.Close()

	// Server 5: A script element containing a harmless comment
	commentScriptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><script>// query parameter: %s\n</script></head><body>Search</body></html>", q)
	}))
	defer commentScriptServer.Close()

	// Server 6: Safely encoded values in a script-related context
	encodedScriptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		escaped := strings.ReplaceAll(strings.ReplaceAll(q, "<", "\\u003c"), ">", "\\u003e")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><script>var query = \"%s\";</script></head><body>Search</body></html>", escaped)
	}))
	defer encodedScriptServer.Close()

	// Server 7 & 8: Unsafe script interpretation fixture (unquoted/executable injection into script)
	unsafeScriptServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, "<html><head><script>var x = 1; %s;</script></head><body>Search</body></html>", q)
	}))
	defer unsafeScriptServer.Close()

	// JSON Server
	jsonServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"query":"%s","status":"ok"}`, q)
	}))
	defer jsonServer.Close()

	engine := NewEngine(entityServer.Client(), DefaultConfig())

	// 1. Harmless text reflection -> OBSERVED
	actxText := &AssessmentContext{
		AssessmentID:     "asm-xss-text",
		ExecutionID:      "exec-xss-text",
		BaseURL:          textServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsText, findingsText, covText := engine.assessXSS(context.Background(), actxText, textServer.Client())
	if covText.Verified != 0 || len(findingsText) != 0 {
		t.Errorf("harmless text must not be verified, got %d verified", covText.Verified)
	}
	if covText.Observations != 1 || len(resultsText) == 0 || resultsText[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved for text reflection, got %+v", resultsText)
	}

	// 2. HTML-entity-encoded reflection -> NOT_VULNERABLE
	actxEntity := &AssessmentContext{
		AssessmentID:     "asm-xss-entity",
		ExecutionID:      "exec-xss-entity",
		BaseURL:          entityServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsEntity, findingsEntity, covEntity := engine.assessXSS(context.Background(), actxEntity, entityServer.Client())
	if covEntity.Verified != 0 || len(findingsEntity) != 0 {
		t.Errorf("entity encoded must not be verified, got %d verified", covEntity.Verified)
	}
	if len(resultsEntity) == 0 || resultsEntity[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for entity encoded reflection, got %+v", resultsEntity)
	}

	// 3. Inert custom HTML elements on live target -> CANDIDATE
	actxInert := &AssessmentContext{
		AssessmentID:     "asm-xss-inert",
		ExecutionID:      "exec-xss-inert",
		BaseURL:          inertServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsInert, findingsInert, covInert := engine.assessXSS(context.Background(), actxInert, inertServer.Client())
	if covInert.Verified != 0 || len(findingsInert) != 0 {
		t.Errorf("inert custom tag must not be verified, got %d verified", covInert.Verified)
	}
	if covInert.Candidates != 1 || len(resultsInert) == 0 || resultsInert[0].VerificationState != StateCandidate {
		t.Errorf("expected StateCandidate for inert tag, got %+v", resultsInert)
	}
	if resultsInert[0].EvidenceDetails["limitation"] != "browser_dom_execution_not_invoked" {
		t.Errorf("expected limitation documented for inert tag, got %+v", resultsInert[0].EvidenceDetails)
	}

	// 4. A script element containing a harmless string -> OBSERVED (never verified)
	actxString := &AssessmentContext{
		AssessmentID:     "asm-xss-str",
		ExecutionID:      "exec-xss-str",
		BaseURL:          stringScriptServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsString, findingsString, covString := engine.assessXSS(context.Background(), actxString, stringScriptServer.Client())
	if covString.Verified != 0 || len(findingsString) != 0 {
		t.Errorf("harmless string in script must NOT be verified, got %d verified", covString.Verified)
	}
	if covString.Observations != 1 || len(resultsString) == 0 || resultsString[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved for string in script, got %+v", resultsString)
	}

	// 5. A script element containing a harmless comment -> OBSERVED (never verified)
	actxComment := &AssessmentContext{
		AssessmentID:     "asm-xss-comment",
		ExecutionID:      "exec-xss-comment",
		BaseURL:          commentScriptServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsComment, findingsComment, covComment := engine.assessXSS(context.Background(), actxComment, commentScriptServer.Client())
	if covComment.Verified != 0 || len(findingsComment) != 0 {
		t.Errorf("harmless comment in script must NOT be verified, got %d verified", covComment.Verified)
	}
	if covComment.Observations != 1 || len(resultsComment) == 0 || resultsComment[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved for comment in script, got %+v", resultsComment)
	}

	// 6. Safely encoded values in a script-related context -> NOT_VULNERABLE
	actxEncScript := &AssessmentContext{
		AssessmentID:     "asm-xss-enc-script",
		ExecutionID:      "exec-xss-enc-script",
		BaseURL:          encodedScriptServer.URL,
		SyntheticFixture: false,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsEncScript, findingsEncScript, covEncScript := engine.assessXSS(context.Background(), actxEncScript, encodedScriptServer.Client())
	if covEncScript.Verified != 0 || len(findingsEncScript) != 0 {
		t.Errorf("safely encoded in script context must NOT be verified, got %d verified", covEncScript.Verified)
	}
	if len(resultsEncScript) == 0 || resultsEncScript[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable for encoded script context, got %+v", resultsEncScript)
	}

	// 7. A synthetic fixture demonstrating genuinely unsafe interpretation -> VERIFIED
	actxSynthUnsafe := &AssessmentContext{
		AssessmentID:     "asm-xss-synth-unsafe",
		ExecutionID:      "exec-xss-synth-unsafe",
		BaseURL:          unsafeScriptServer.URL,
		SyntheticFixture: true,
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsSynthUnsafe, findingsSynthUnsafe, covSynthUnsafe := engine.assessXSS(context.Background(), actxSynthUnsafe, unsafeScriptServer.Client())
	if covSynthUnsafe.Verified != 1 || len(findingsSynthUnsafe) != 1 {
		t.Fatalf("expected 1 verified finding in synthetic unsafe fixture, got %d", covSynthUnsafe.Verified)
	}
	if len(resultsSynthUnsafe) == 0 || resultsSynthUnsafe[0].VerificationState != StateVerified {
		t.Fatalf("expected StateVerified for synthetic unsafe fixture, got %+v", resultsSynthUnsafe)
	}
	if findingsSynthUnsafe[0].Severity != report.SeverityHigh {
		t.Errorf("expected SeverityHigh, got %v", findingsSynthUnsafe[0].Severity)
	}

	// 8. Live-target findings remaining unverified when the available evidence is insufficient -> CANDIDATE with documented limitation
	actxLiveUnsafe := &AssessmentContext{
		AssessmentID:     "asm-xss-live-unsafe",
		ExecutionID:      "exec-xss-live-unsafe",
		BaseURL:          unsafeScriptServer.URL,
		SyntheticFixture: false, // LIVE TARGET
		Endpoints:        []TargetEndpoint{{Method: "GET", Path: "/search", Parameters: []string{"q"}}},
	}
	resultsLiveUnsafe, findingsLiveUnsafe, covLiveUnsafe := engine.assessXSS(context.Background(), actxLiveUnsafe, unsafeScriptServer.Client())
	if covLiveUnsafe.Verified != 0 || len(findingsLiveUnsafe) != 0 {
		t.Errorf("live target without browser execution must NEVER be marked verified, got %d verified", covLiveUnsafe.Verified)
	}
	if covLiveUnsafe.Candidates != 1 || len(resultsLiveUnsafe) == 0 || resultsLiveUnsafe[0].VerificationState != StateCandidate {
		t.Errorf("expected StateCandidate for live script reflection, got %+v", resultsLiveUnsafe)
	}
	if resultsLiveUnsafe[0].EvidenceDetails["limitation"] != "browser_dom_execution_not_invoked" {
		t.Errorf("expected browser_dom_execution_not_invoked limitation, got %+v", resultsLiveUnsafe[0].EvidenceDetails)
	}

	// JSON response control -> OBSERVED
	actxJSON := &AssessmentContext{
		AssessmentID: "asm-xss-json",
		ExecutionID:  "exec-xss-json",
		BaseURL:      jsonServer.URL,
		Endpoints:    []TargetEndpoint{{Method: "GET", Path: "/api/search", Parameters: []string{"q"}}},
	}
	resultsJSON, _, covJSON := engine.assessXSS(context.Background(), actxJSON, jsonServer.Client())
	if covJSON.Verified != 0 || len(resultsJSON) == 0 || resultsJSON[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved for JSON response, got %+v", resultsJSON)
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

// 5. Test Open Redirect: Dynamic Input-Controlled vs Static External vs Internal/Sanitized
func TestWebVuln_OpenRedirect(t *testing.T) {
	// Vulnerable redirect server dynamically reflecting untrusted destination in Location header
	vulnServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next := r.URL.Query().Get("next")
		if next == "" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Redirect(w, r, next, http.StatusFound)
	}))
	defer vulnServer.Close()

	// Static external redirect server (e.g. SSO login always goes to fixed external provider)
	staticServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://auth.company.example.com/sso", http.StatusFound)
	}))
	defer staticServer.Close()

	// Safe redirect server restricting to local paths
	safeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}))
	defer safeServer.Close()

	engine := NewEngine(vulnServer.Client(), DefaultConfig())

	// Test 1: Dynamic input-controlled redirect across paired differential canaries -> VERIFIED
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

	// Test 2: Static external redirect -> OBSERVED (never verified)
	actxStatic := &AssessmentContext{
		AssessmentID: "asm-redir-static",
		ExecutionID:  "exec-redir-static",
		BaseURL:      staticServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/login", Parameters: []string{"next"}},
		},
	}
	resultsStatic, findingsStatic, covStatic := engine.assessOpenRedirect(context.Background(), actxStatic, staticServer.Client())
	if covStatic.Verified != 0 {
		t.Errorf("static external redirect must NOT be marked verified, got %d verified", covStatic.Verified)
	}
	if covStatic.Observations != 1 || len(resultsStatic) == 0 || resultsStatic[0].VerificationState != StateObserved {
		t.Errorf("expected StateObserved for static external redirect, got %+v", resultsStatic)
	}
	if len(findingsStatic) != 0 {
		t.Errorf("static redirect must not produce findings, got %d", len(findingsStatic))
	}

	// Test 3: Relative path redirect -> NOT_VULNERABLE
	actxSafe := &AssessmentContext{
		AssessmentID: "asm-redir-safe",
		ExecutionID:  "exec-redir-safe",
		BaseURL:      safeServer.URL,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/login", Parameters: []string{"next"}},
		},
	}
	resultsSafe, findingsSafe, covSafe := engine.assessOpenRedirect(context.Background(), actxSafe, safeServer.Client())
	if covSafe.Verified != 0 {
		t.Errorf("expected 0 verified on safe server, got %d", covSafe.Verified)
	}
	if len(resultsSafe) == 0 || resultsSafe[0].VerificationState != StateNotVulnerable {
		t.Errorf("expected StateNotVulnerable, got %+v", resultsSafe)
	}
	if len(findingsSafe) != 0 {
		t.Errorf("safe server must not produce findings, got %d", len(findingsSafe))
	}
}

// 6. Test Information Disclosure: Live metadata-only HEAD vs Synthetic Fixture Redaction vs Stack Traces
func TestWebVuln_InfoDisclosure_And_Redaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			if r.Method == "HEAD" {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "DB_PASSWORD=super_secret_db_pass_1234\nSECRET_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.do_not_leak_me\n")
			return
		}
		if r.URL.Path == "/server-status" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Apache Server Status for example.com")
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

	// Control A: Live Target Check (SyntheticFixture = false)
	// Safety enforcement: Must NOT download or retain live /.env content; reports StateCandidate
	actxLive := &AssessmentContext{
		AssessmentID:     "asm-infodisc-live",
		ExecutionID:      "exec-infodisc-live",
		BaseURL:          server.URL,
		SyntheticFixture: false,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/api/test"},
		},
	}
	resultsLive, _, covLive := engine.assessInfoDisclosure(context.Background(), actxLive, server.Client())
	var envLiveResult *Result
	for i := range resultsLive {
		if strings.Contains(resultsLive[i].Endpoint, "/.env") {
			envLiveResult = &resultsLive[i]
			break
		}
	}
	if envLiveResult == nil {
		t.Fatalf("expected /.env result in live mode")
	}
	if envLiveResult.VerificationState != StateCandidate {
		t.Errorf("expected /.env on live target to be StateCandidate, got %v", envLiveResult.VerificationState)
	}
	if envLiveResult.EvidenceDetails["safety_policy"] != "metadata_only_check_zero_content_retained" {
		t.Errorf("expected metadata_only_check_zero_content_retained safety policy, got %v", envLiveResult.EvidenceDetails)
	}
	if strings.Contains(envLiveResult.EvidenceSummary, "super_secret_db_pass_1234") {
		t.Errorf("live target leaked secret in summary: %s", envLiveResult.EvidenceSummary)
	}
	if strings.Contains(fmt.Sprint(envLiveResult.EvidenceDetails), "super_secret_db_pass_1234") {
		t.Errorf("live target leaked secret in details: %+v", envLiveResult.EvidenceDetails)
	}
	if covLive.Candidates < 1 {
		t.Errorf("expected candidate count >= 1 in live mode, got %d", covLive.Candidates)
	}

	// Control B: Synthetic Fixture Check (SyntheticFixture = true)
	// Demonstrates detection and strict redaction
	actxSynth := &AssessmentContext{
		AssessmentID:     "asm-infodisc-synth",
		ExecutionID:      "exec-infodisc-synth",
		BaseURL:          server.URL,
		SyntheticFixture: true,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/api/test"},
		},
	}
	resultsSynth, findingsSynth, covSynth := engine.assessInfoDisclosure(context.Background(), actxSynth, server.Client())
	if covSynth.Verified < 1 {
		t.Fatalf("expected verified findings in synthetic mode, got %d", covSynth.Verified)
	}

	var envSynthResult *Result
	for i := range resultsSynth {
		if strings.Contains(resultsSynth[i].Endpoint, "/.env") {
			envSynthResult = &resultsSynth[i]
			break
		}
	}
	if envSynthResult == nil || envSynthResult.VerificationState != StateVerified {
		t.Fatalf("expected verified state for /.env in synthetic fixture mode, got %+v", envSynthResult)
	}

	// Assert that fixture secrets never leak into findings or evidence and are replaced by [REDACTED]
	for _, r := range resultsSynth {
		if strings.Contains(r.EvidenceSummary, "super_secret_db_pass_1234") {
			t.Errorf("raw password leaked in evidence summary: %s", r.EvidenceSummary)
		}
		for k, v := range r.EvidenceDetails {
			if strings.Contains(v, "super_secret_db_pass_1234") {
				t.Errorf("raw password leaked in evidence details[%s]: %s", k, v)
			}
		}
	}
	for _, f := range findingsSynth {
		if strings.Contains(f.Evidence, "super_secret_db_pass_1234") {
			t.Errorf("raw password leaked in report finding evidence: %s", f.Evidence)
		}
	}
	if !strings.Contains(envSynthResult.EvidenceDetails["snippet"], "[REDACTED]") {
		t.Errorf("expected [REDACTED] in snippet, got: %s", envSynthResult.EvidenceDetails["snippet"])
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
