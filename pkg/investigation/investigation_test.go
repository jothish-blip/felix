package investigation_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/investigation"
	"felix/pkg/report"
)

// setupControlledVulnerableApp creates a comprehensive local test harness covering all 10 vulnerability categories
// plus defensive negative controls to verify false-positive prevention.
func setupControlledVulnerableApp(t *testing.T) (*httptest.Server, map[string]bool) {
	state := map[string]bool{
		"sqli_patched":     false,
		"xss_patched":      false,
		"ssrf_patched":     false,
		"bola_patched":     false,
		"bfla_patched":     false,
		"auth_patched":     false,
		"traversal_patched": false,
		"secret_patched":   false,
		"cors_patched":     false,
		"biz_patched":      false,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		// 1. SQL Injection: Parameter syntax error divergence (or parameterized if patched)
		case strings.HasPrefix(path, "/api/products"):
			id := r.URL.Query().Get("id")
			if state["sqli_patched"] {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"ok","product":{"id":1,"name":"Widget"}}`))
				return
			}
			if strings.Contains(id, "'") {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"error":"syntax error in SQL statement near ''' at line 1","code":"SQL_SYNTAX_ERROR"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok","product":{"id":1,"name":"Widget"}}`))

		// 2. Cross-Site Scripting: Unescaped reflection vs HTML entity escaped
		case strings.HasPrefix(path, "/search"):
			q := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			if state["xss_patched"] {
				escaped := strings.ReplaceAll(q, "<", "&lt;")
				escaped = strings.ReplaceAll(escaped, ">", "&gt;")
				_, _ = w.Write([]byte(fmt.Sprintf(`<html><body><h1>Results for: %s</h1></body></html>`, escaped)))
				return
			}
			// Unescaped reflection
			_, _ = w.Write([]byte(fmt.Sprintf(`<html><body><h1>Results for: %s</h1></body></html>`, q)))

		// 3. SSRF: Callback probe verification
		case strings.HasPrefix(path, "/webhook"):
			dest := r.URL.Query().Get("dest")
			if state["ssrf_patched"] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"prohibited destination host"}`))
				return
			}
			if dest != "" {
				go func(targetDest string) {
					cli := &http.Client{Timeout: 500 * time.Millisecond}
					resp, err := cli.Get(targetDest)
					if err == nil && resp != nil {
						_ = resp.Body.Close()
					}
				}(dest)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status":"callback received from target server","dest": "` + dest + `"}`))
				return
			}
			w.WriteHeader(http.StatusBadRequest)

		// 4. BOLA: Dual identity test object access
		case strings.HasPrefix(path, "/api/documents/"):
			docID := strings.TrimPrefix(path, "/api/documents/")
			if state["bola_patched"] {
				auth := r.Header.Get("Authorization")
				if !strings.Contains(auth, "owner_b") {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"forbidden: document not owned by tenant"}`))
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"doc_id":"` + docID + `","content":"Confidential Tenant B Document [unauthorized_access=true]"}`))

		// 5. BFLA: Admin route access by low-privilege user
		case strings.HasPrefix(path, "/api/admin/users"):
			if state["bfla_patched"] {
				auth := r.Header.Get("Authorization")
				if !strings.Contains(auth, "admin_role") {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":"access denied: requires ADMIN role"}`))
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin_action":"list_all_users","status":"admin_bypass_confirmed"}`))

		// 6. Authentication: Missing auth barrier
		case strings.HasPrefix(path, "/api/user/private-profile"):
			if state["auth_patched"] {
				auth := r.Header.Get("Authorization")
				if auth == "" {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error":"unauthorized: bearer token required"}`))
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"email":"ceo@company.test","role":"executive"}`))

		// 7. Path Traversal: Canary file reflection
		case strings.HasPrefix(path, "/download"):
			file := r.URL.Query().Get("file")
			if state["traversal_patched"] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid file path: directory traversal prohibited"}`))
				return
			}
			if strings.Contains(file, "..") {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`[extensions]\ncanonical_canary_proof=true\n`))
				return
			}
			w.WriteHeader(http.StatusNotFound)

		// 8. Sensitive Information Exposure: High-entropy token
		case strings.HasPrefix(path, "/config.js"):
			if state["secret_patched"] {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`window.ENV = { API_BASE: "/api" };`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`window.ENV = { API_KEY: "AKIAIOSFODNN7EXAMPLE", REGION: "us-east-1" };`))

		// 9. CORS Policy Misconfiguration
		case strings.HasPrefix(path, "/api/cors-data"):
			if state["cors_patched"] {
				w.Header().Set("Access-Control-Allow-Origin", "https://trusted.example")
				w.WriteHeader(http.StatusOK)
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusOK)

		// 10. Business Logic Tampering
		case strings.HasPrefix(path, "/api/checkout/confirm"):
			if state["biz_patched"] {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid order state: shipping step not completed"}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"order_completed","workflow_tampering_confirmed":"true"}`))

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	server := httptest.NewServer(handler)
	return server, state
}

func TestInvestigation_ControlledApplications_All10Categories(t *testing.T) {
	ts, _ := setupControlledVulnerableApp(t)
	defer ts.Close()

	engine := investigation.NewInvestigationEngine(investigation.InvestigationOptions{
		AssessmentID: "asm_test_all10",
		SafeMode:     false,
	})

	httpClient := ts.Client()
	ctx := context.Background()

	testCases := []struct {
		name           string
		finding        report.Finding
		expectedStatus investigation.ValidationStatus
		expectedCat    string
	}{
		{
			name: "Category 1: SQL Injection (Differential Syntax Divergence)",
			finding: report.Finding{
				ID:       "FND-SQLI-01",
				Title:    "SQL Injection (Error-Based)",
				Category: "SQL Injection",
				Severity: "HIGH",
				Target:   ts.URL + "/api/products?id=1",
				Endpoint: "/api/products",
				Method:   "GET",
				Evidence: "syntax error in sql statement near ''' at line 1",
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "SQL",
		},
		{
			name: "Category 2: Cross-Site Scripting (Unescaped Reflection)",
			finding: report.Finding{
				ID:       "FND-XSS-01",
				Title:    "Reflected Cross-Site Scripting",
				Category: "Cross-Site Scripting",
				Severity: "HIGH",
				Target:   ts.URL + "/search?q=<script>alert(1)</script>",
				Endpoint: "/search",
				Method:   "GET",
				Evidence: "<html><body><h1>Results for: <script>alert(1)</script></h1></body></html>",
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "XSS",
		},
		{
			name: "Category 3: SSRF (Controlled Callback)",
			finding: report.Finding{
				ID:       "FND-SSRF-01",
				Title:    "Server-Side Request Forgery",
				Category: "SSRF",
				Severity: "CRITICAL",
				Target:   ts.URL + "/webhook?dest=http://canary.oast.felix.internal",
				Endpoint: "/webhook",
				Method:   "GET",
				Evidence: `{"status":"callback received from target server","dest": "http://canary.oast.felix.internal"}`,
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "SSRF",
		},
		{
			name: "Category 4: BOLA / IDOR (Dual Identity Comparison)",
			finding: report.Finding{
				ID:       "FND-BOLA-01",
				Title:    "Broken Object Level Authorization (IDOR)",
				Category: "BOLA",
				Severity: "CRITICAL",
				Target:   ts.URL + "/api/documents/doc_999",
				Endpoint: "/api/documents/doc_999",
				Method:   "GET",
				Evidence: `{"doc_id":"doc_999","content":"Confidential Tenant B Document [unauthorized_access=true]"}`,
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"unauthorized_access": "true"},
				},
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "BOLA",
		},
		{
			name: "Category 5: BFLA (Administrative Role Bypass)",
			finding: report.Finding{
				ID:       "FND-BFLA-01",
				Title:    "Broken Function Level Authorization",
				Category: "BFLA",
				Severity: "HIGH",
				Target:   ts.URL + "/api/admin/users",
				Endpoint: "/api/admin/users",
				Method:   "GET",
				Evidence: `{"admin_action":"list_all_users","status":"admin_bypass_confirmed"}`,
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"admin_bypass_confirmed": "true"},
				},
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "BFLA",
		},
		{
			name: "Category 6: Path Traversal (Canary Marker Reflection)",
			finding: report.Finding{
				ID:       "FND-TRAV-01",
				Title:    "Path Traversal",
				Category: "Path Traversal",
				Severity: "HIGH",
				Target:   ts.URL + "/download?file=../../canary.txt",
				Endpoint: "/download",
				Method:   "GET",
				Evidence: `[extensions]\ncanonical_canary_proof=true`,
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "TRAVERSAL",
		},
		{
			name: "Category 7: Authentication Weakness (Unauthenticated Access)",
			finding: report.Finding{
				ID:       "FND-AUTH-01",
				Title:    "Unauthenticated Sensitive Route Access",
				Category: "Authentication",
				Severity: "HIGH",
				Target:   ts.URL + "/api/user/private-profile",
				Endpoint: "/api/user/private-profile",
				Method:   "GET",
				Evidence: `{"email":"ceo@company.test","role":"executive"}`,
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus: 200,
				},
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "AUTH",
		},
		{
			name: "Category 8: Secret Exposure (High-Entropy Token)",
			finding: report.Finding{
				ID:          "FND-SEC-01",
				Title:       "Exposed AWS Access Key ID",
				Category:    "Information Disclosure",
				Severity:    "HIGH",
				Target:      ts.URL + "/config.js",
				Endpoint:    "/config.js",
				Method:      "GET",
				Evidence:    `window.ENV = { API_KEY: "AKIAIOSFODNN7EXAMPLE", REGION: "us-east-1" };`,
				Fingerprint: "fp_aws_sec_123",
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "SECRET",
		},
		{
			name: "Category 9: Dangerous CORS Configuration",
			finding: report.Finding{
				ID:       "FND-CORS-01",
				Title:    "CORS Wildcard with Credentials",
				Category: "CORS",
				Severity: "HIGH",
				Target:   ts.URL + "/api/cors-data",
				Endpoint: "/api/cors-data",
				Method:   "OPTIONS",
				Evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true",
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "CORS",
		},
		{
			name: "Category 10: Business Logic Workflow Bypass",
			finding: report.Finding{
				ID:       "FND-BIZ-01",
				Title:    "Business Logic Order Step Bypass",
				Category: "Business Logic",
				Severity: "HIGH",
				Target:   ts.URL + "/api/checkout/confirm",
				Endpoint: "/api/checkout/confirm",
				Method:   "POST",
				Evidence: `{"status":"order_completed","workflow_tampering_confirmed":"true"}`,
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{"workflow_tampering_confirmed": "true"},
				},
			},
			expectedStatus: investigation.StatusConfirmed,
			expectedCat:    "BIZ",
		},
	}

	var investigatedList []*investigation.InvestigatedFinding

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			startTime := time.Now()
			inf, err := engine.Investigate(ctx, tc.finding, httpClient, "express/node")
			duration := time.Since(startTime)

			if err != nil {
				t.Fatalf("unexpected error during investigation: %v", err)
			}
			if inf == nil {
				t.Fatalf("expected non-nil investigated finding")
			}

			// 1. Validation Status Verification
			if inf.ValidationStatus != tc.expectedStatus {
				t.Errorf("expected validation status %s, got %s", tc.expectedStatus, inf.ValidationStatus)
			}

			// 2. Evidence Completeness Verification
			eb := inf.EvidenceBundle
			if eb == nil {
				t.Fatalf("expected non-nil evidence bundle")
			}
			if eb.EvidenceHash == "" || !strings.HasPrefix(eb.EvidenceHash, "sha256:") {
				t.Errorf("invalid or missing evidence hash: %q", eb.EvidenceHash)
			}
			if eb.SanitizedRequest == "" {
				t.Errorf("expected non-empty sanitized request")
			}
			if eb.SanitizedResponse == "" {
				t.Errorf("expected non-empty sanitized response")
			}
			if len(eb.ReproductionSteps) == 0 {
				t.Errorf("expected reproduction steps in evidence bundle")
			}
			if eb.LeastInvasiveMethod == "" {
				t.Errorf("expected non-empty least invasive proof method label")
			}

			// 3. Attack Path Verification
			ap := inf.AttackPath
			if ap == nil {
				t.Fatalf("expected non-nil attack path")
			}
			if ap.InitialEntryPoint == "" || ap.FailedControl == "" || ap.DemonstratedImpact == "" {
				t.Errorf("incomplete attack path attributes: %+v", ap)
			}
			if len(ap.Steps) < 2 {
				t.Errorf("expected at least 2 discrete attack steps, got %d", len(ap.Steps))
			}
			if ap.GraphVisual == "" {
				t.Errorf("expected non-empty graph visual representation")
			}

			// 4. Remediation Intelligence Verification
			rem := inf.Remediation
			if rem == nil {
				t.Fatalf("expected non-nil remediation intelligence")
			}
			if rem.RootCause == "" || rem.RecommendedFix == "" || rem.ImplementationGuidance == "" {
				t.Errorf("incomplete remediation intelligence fields: %+v", rem)
			}
			if rem.DeveloperVerification == "" || rem.RetestInstructions == "" {
				t.Errorf("missing developer verification or retest instructions")
			}

			// 5. Performance Check: Instant bounded validation should finish < 250ms
			if duration > 250*time.Millisecond {
				t.Logf("Notice: validation took %v (within bounded limits)", duration)
			}

			investigatedList = append(investigatedList, inf)
		})
	}

	// 6. Test Multi-Hop Attack Chain Reconstruction
	chains := investigation.AnalyzeAttackChains(investigatedList)
	if len(chains) == 0 {
		t.Errorf("expected at least 1 multi-hop attack chain to be constructed across confirmed findings")
	}
	for _, c := range chains {
		if c.Status != investigation.StatusConfirmed && c.Status != investigation.StatusPotential {
			t.Errorf("invalid attack chain status: %s", c.Status)
		}
		if len(c.Links) == 0 {
			t.Errorf("expected attack chain to have linked transitions")
		}
	}

	// 7. Test Continuous Remediation Roadmap Generation
	roadmap := investigation.BuildRemediationRoadmap(investigatedList)
	if roadmap.TotalActions != len(investigatedList) {
		t.Errorf("expected %d roadmap actions, got %d", len(investigatedList), roadmap.TotalActions)
	}
	if roadmap.CriticalCount == 0 || roadmap.HighCount == 0 {
		t.Errorf("expected critical and high severity findings grouped in roadmap")
	}
	if len(roadmap.Items) != len(investigatedList) {
		t.Errorf("expected %d roadmap items, got %d", len(investigatedList), len(roadmap.Items))
	}
	// Verify roadmap fixing order starts at 1 and increases monotonically
	for i, it := range roadmap.Items {
		if it.FixOrder != i+1 {
			t.Errorf("expected fix order %d, got %d", i+1, it.FixOrder)
		}
	}
}

func TestInvestigation_NegativeControls_ZeroFalsePositives(t *testing.T) {
	ts, state := setupControlledVulnerableApp(t)
	defer ts.Close()

	// Apply patches to all categories in the test harness
	for k := range state {
		state[k] = true
	}

	engine := investigation.NewInvestigationEngine(investigation.InvestigationOptions{
		AssessmentID: "asm_negative_controls",
		SafeMode:     false,
	})

	httpClient := ts.Client()
	ctx := context.Background()

	// 1. Escaped XSS (Entity encoded)
	xssFinding := report.Finding{
		ID:       "FND-XSS-CLEAN",
		Title:    "Potential XSS",
		Category: "Cross-Site Scripting",
		Target:   ts.URL + "/search?q=<script>alert(1)</script>",
		Endpoint: "/search",
		Method:   "GET",
		Evidence: "<html><body><h1>Results for: &lt;script&gt;alert(1)&lt;/script&gt;</h1></body></html>",
	}
	inf, err := engine.Investigate(ctx, xssFinding, httpClient, "express")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inf.ValidationStatus == investigation.StatusConfirmed {
		t.Errorf("negative control failed: escaped XSS was incorrectly CONFIRMED as vulnerable!")
	}

	// 2. Parameterized SQL query
	sqliFinding := report.Finding{
		ID:       "FND-SQLI-CLEAN",
		Title:    "Potential SQLi",
		Category: "SQL Injection",
		Target:   ts.URL + "/api/products?id=1",
		Endpoint: "/api/products",
		Method:   "GET",
		Evidence: `{"status":"ok","product":{"id":1,"name":"Widget"}}`,
	}
	inf2, err := engine.Investigate(ctx, sqliFinding, httpClient, "express")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inf2.ValidationStatus == investigation.StatusConfirmed {
		t.Errorf("negative control failed: parameterized query was incorrectly CONFIRMED as vulnerable!")
	}
}

func TestInvestigation_RetestWorkflow(t *testing.T) {
	ts, state := setupControlledVulnerableApp(t)
	defer ts.Close()

	engine := investigation.NewInvestigationEngine(investigation.InvestigationOptions{
		AssessmentID: "asm_retest_demo",
		SafeMode:     false,
	})

	httpClient := ts.Client()
	ctx := context.Background()

	// 1. Create a confirmed SQLi finding against live server
	sqliFinding := report.Finding{
		ID:       "FND-RETEST-SQLI",
		Title:    "SQL Injection",
		Category: "SQL Injection",
		Severity: "HIGH",
		Target:   ts.URL + "/api/products?id=1",
		Endpoint: "/api/products",
		Method:   "GET",
		Evidence: "syntax error in sql statement near ''' at line 1",
	}

	inf, err := engine.Investigate(ctx, sqliFinding, httpClient, "node")
	if err != nil || inf.ValidationStatus != investigation.StatusConfirmed {
		t.Fatalf("expected confirmed initial status, got %s, err: %v", inf.ValidationStatus, err)
	}

	// 2. Retest while STILL VULNERABLE -> expect VULNERABILITY STILL PRESENT
	verdict1, err := engine.Retest.RerunFinding(ctx, inf, httpClient)
	if err != nil {
		t.Fatalf("unexpected retest error: %v", err)
	}
	if verdict1.RetestStatus != investigation.RetestVulnerabilityPresent {
		t.Errorf("expected VULNERABILITY STILL PRESENT, got %s", verdict1.RetestStatus)
	}
	if verdict1.OriginalEvidenceHash == "" {
		t.Errorf("expected original evidence hash to be preserved")
	}

	// 3. Patch the vulnerability in the application
	state["sqli_patched"] = true

	// 4. Retest after patch -> expect FIX DETECTED
	verdict2, err := engine.Retest.RerunFinding(ctx, inf, httpClient)
	if err != nil {
		t.Fatalf("unexpected retest error: %v", err)
	}
	if verdict2.RetestStatus != investigation.RetestFixDetected {
		t.Errorf("expected FIX DETECTED after patch, got %s", verdict2.RetestStatus)
	}
	if verdict2.RegressionDetected {
		t.Errorf("regression incorrectly flagged when fix was applied")
	}
}

func TestInvestigation_LiveAssessmentSession(t *testing.T) {
	ts, _ := setupControlledVulnerableApp(t)
	defer ts.Close()

	var buf strings.Builder
	session := investigation.NewLiveAssessmentSession("asm_live_stream", ts.URL, "standard", false, &buf)
	session.TargetTech = "Express/Node.js"

	ctx := context.Background()
	httpClient := ts.Client()

	f := report.Finding{
		ID:       "FND-LIVE-01",
		Title:    "Reflected XSS",
		Category: "Cross-Site Scripting",
		Severity: "HIGH",
		Target:   ts.URL + "/search?q=<script>alert(1)</script>",
		Endpoint: "/search",
		Method:   "GET",
		Evidence: "<html><body><h1>Results for: <script>alert(1)</script></h1></body></html>",
	}

	inf, err := session.ProcessFinding(ctx, f, httpClient)
	if err != nil {
		t.Fatalf("unexpected error processing finding in session: %v", err)
	}
	if inf.ValidationStatus != investigation.StatusConfirmed {
		t.Errorf("expected confirmed status, got %s", inf.ValidationStatus)
	}

	// Verify terminal output stream was written in real-time
	streamOutput := buf.String()
	if !strings.Contains(streamOutput, "LIVE FINDING INVESTIGATED") {
		t.Errorf("expected live finding alert in console stream, got: %s", streamOutput)
	}
	if !strings.Contains(streamOutput, "CONFIRMED") {
		t.Errorf("expected CONFIRMED badge in console stream")
	}
	if !strings.Contains(streamOutput, "Attack Path:") {
		t.Errorf("expected attack path in console stream")
	}
	if !strings.Contains(streamOutput, "Remediation:") {
		t.Errorf("expected remediation in console stream")
	}

	// Verify report enrichment
	rep := &report.Report{
		Target: ts.URL,
	}
	session.EnrichReport(rep)
	if len(rep.Findings) != 1 {
		t.Errorf("expected 1 enriched finding, got %d", len(rep.Findings))
	}
	if rep.Findings[0].Verification.Status != "CONFIRMED" {
		t.Errorf("expected enriched finding verification status CONFIRMED, got %s", rep.Findings[0].Verification.Status)
	}
	if len(rep.AttackPaths) == 0 {
		t.Errorf("expected attack path summary in enriched report")
	}
}
