package test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/report"
)

// TestReportingIntegrity_CanonicalCorrectness verifies that canonical findings across all severities,
// statuses, zero-finding states, missing optional fields, and Unicode payloads serialize and reconcile accurately.
func TestReportingIntegrity_CanonicalCorrectness(t *testing.T) {
	t.Run("Zero findings assessment is clean and consistent", func(t *testing.T) {
		rep := report.BuildReport("https://clean.example.com", nil)
		rep.CompletionStatus = "COMPLETED"

		if err := report.ValidateReportIntegrity(rep); err != nil {
			t.Fatalf("expected valid zero-finding report to pass integrity validation, got: %v", err)
		}
		if rep.Summary.TotalFindings != 0 || rep.Summary.CriticalCount != 0 || rep.Summary.HighCount != 0 ||
			rep.Summary.MediumCount != 0 || rep.Summary.LowCount != 0 || rep.Summary.InfoCount != 0 {
			t.Errorf("summary counts must all be 0 for zero-finding scan, got: %+v", rep.Summary)
		}
		if rep.RiskScore != 0 || rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("expected clean risk score 0 and level INFORMATIONAL, got: %d (%s)", rep.RiskScore, rep.RiskLevel)
		}
		if !rep.RiskScoreAvailable {
			t.Errorf("expected RiskScoreAvailable to be true for clean scan")
		}
	})

	t.Run("All severity tiers and status reconciliations", func(t *testing.T) {
		findings := []report.Finding{
			{
				ID:           "FND-CRIT-01",
				Title:        "Remote Code Execution",
				Severity:     report.SeverityCritical,
				Confidence:   report.ConfidenceHigh,
				Target:       "https://app.example.com",
				Endpoint:     "/api/exec",
				Status:       report.FindingStatusConfirmed,
				Verification: report.VerificationRecord{Status: report.VerificationVerified, Result: "CONFIRMED_VULN"},
				Category:     "rce",
				Score:        95,
			},
			{
				ID:           "FND-HIGH-01",
				Title:        "SQL Injection",
				Severity:     report.SeverityHigh,
				Confidence:   report.ConfidenceHigh,
				Target:       "https://app.example.com",
				Endpoint:     "/api/users",
				Status:       report.FindingStatusConfirmed,
				Verification: report.VerificationRecord{Status: report.VerificationVerified, Result: "CONFIRMED_VULN"},
				Category:     "sqli",
				Score:        85,
			},
			{
				ID:           "FND-MED-01",
				Title:        "Cross-Site Scripting (Reflected)",
				Severity:     report.SeverityMedium,
				Confidence:   report.ConfidenceMedium,
				Target:       "https://app.example.com",
				Endpoint:     "/search",
				Status:       report.FindingStatusSuspected,
				Verification: report.VerificationRecord{Status: report.VerificationDetected, Result: "SUSPECTED"},
				Category:     "xss",
				Score:        55,
			},
			{
				ID:           "FND-LOW-01",
				Title:        "Missing Security Header CSP",
				Severity:     report.SeverityLow,
				Confidence:   report.ConfidenceHigh,
				Target:       "https://app.example.com",
				Endpoint:     "/",
				Status:       report.FindingStatusConfirmed,
				Verification: report.VerificationRecord{Status: report.VerificationObserved, Result: "HEADER_ABSENT"},
				Category:     "missing-csp",
				Score:        25,
			},
			{
				ID:           "FND-INFO-01",
				Title:        "Swagger UI Documentation Exposed",
				Severity:     report.SeverityInfo,
				Confidence:   report.ConfidenceHigh,
				Target:       "https://app.example.com",
				Endpoint:     "/docs",
				Status:       report.FindingStatusConfirmed,
				Verification: report.VerificationRecord{Status: report.VerificationObserved, Result: "PUBLIC_DOCS"},
				Category:     "api-docs-exposure",
				Score:        10,
			},
		}

		rep := report.BuildReport("https://app.example.com", findings)
		rep.CompletionStatus = "COMPLETED"

		if err := report.ValidateReportIntegrity(rep); err != nil {
			t.Fatalf("expected report to pass integrity validation: %v", err)
		}
		if rep.Summary.TotalFindings != 5 {
			t.Errorf("expected 5 total findings, got: %d", rep.Summary.TotalFindings)
		}
		if rep.Summary.CriticalCount != 1 || rep.Summary.HighCount != 1 || rep.Summary.MediumCount != 1 ||
			rep.Summary.LowCount != 1 || rep.Summary.InfoCount != 1 {
			t.Errorf("severity breakdown count mismatch: %+v", rep.Summary)
		}
		if rep.RiskLevel != report.SeverityCritical {
			t.Errorf("expected CRITICAL risk level, got: %s", rep.RiskLevel)
		}
		if rep.RiskScore <= 0 {
			t.Errorf("expected positive risk score, got: %d", rep.RiskScore)
		}
	})

	t.Run("Missing optional values do not panic and serialize cleanly", func(t *testing.T) {
		bareFinding := report.Finding{
			ID:       "FND-BARE-01",
			Severity: report.SeverityMedium,
		}

		rep := report.BuildReport("https://app.example.com", []report.Finding{bareFinding})
		rep.CompletionStatus = "COMPLETED"

		// HTML generation
		htmlContent, err := report.GenerateHTML(rep)
		if err != nil {
			t.Fatalf("GenerateHTML failed on bare finding: %v", err)
		}
		if len(htmlContent) == 0 {
			t.Errorf("expected non-empty HTML output")
		}

		// JSON serialization
		jsonData, err := report.GenerateJSON(rep)
		if err != nil {
			t.Fatalf("GenerateJSON failed on bare finding: %v", err)
		}
		if len(jsonData) == 0 {
			t.Errorf("expected non-empty JSON output")
		}

		// SARIF generation & schema conformance
		sarifData, err := report.GenerateSARIF(rep)
		if err != nil {
			t.Fatalf("GenerateSARIF failed on bare finding: %v", err)
		}
		if err := report.ValidateSARIF(sarifData); err != nil {
			t.Fatalf("ValidateSARIF failed on bare finding SARIF: %v", err)
		}
	})

	t.Run("Unicode, Emojis, and Multi-line Text Fidelity", func(t *testing.T) {
		unicodeFinding := report.Finding{
			ID:          "FND-UNICODE-01",
			Title:       "Injection with Unicode & Emojis \u2705 \U0001F6E1 \u6F0F\u6D1E\u6D4B\u8BD5",
			Description: "Multi-line payload:\nLine 1: ' OR '1'='1\nLine 2: 日本語テキスト\r\nLine 3: 🔒 Protected resource",
			Evidence:    "Raw request with special chars: <>&\"' \n\t [REDACTED]",
			Remediation: "Use parameterized queries; verify encoding: UTF-8 standard \u2714",
			Severity:    report.SeverityHigh,
			Category:    "unicode-test",
			Target:      "https://app.example.com",
			Endpoint:    "/api/unicode?name=\u4F60\u597D",
		}

		rep := report.BuildReport("https://app.example.com", []report.Finding{unicodeFinding})
		rep.CompletionStatus = "COMPLETED"

		// JSON round-trip
		jsonData, err := report.GenerateJSON(rep)
		if err != nil {
			t.Fatalf("GenerateJSON failed: %v", err)
		}
		parsed, err := report.ParseReport(jsonData)
		if err != nil {
			t.Fatalf("ParseReport failed: %v", err)
		}
		if len(parsed.Findings) != 1 {
			t.Fatalf("expected 1 finding, got: %d", len(parsed.Findings))
		}
		if !strings.Contains(parsed.Findings[0].Title, "\u6F0F\u6D1E\u6D4B\u8BD5") {
			t.Errorf("expected Chinese characters preserved in title")
		}
		if !strings.Contains(parsed.Findings[0].Description, "\u65E5\u672C\u8A9E\u30C6\u30AD\u30B9\u30C8") {
			t.Errorf("expected Japanese characters preserved in description")
		}

		// HTML contains escaped representation
		htmlOut, err := report.GenerateHTML(rep)
		if err != nil {
			t.Fatalf("GenerateHTML failed: %v", err)
		}
		if !strings.Contains(htmlOut, "\u6F0F\u6D1E\u6D4B\u8BD5") {
			t.Errorf("expected Chinese characters in HTML output")
		}
		if strings.Contains(htmlOut, "&lt;>&amp;\"'") {
			t.Errorf("expected HTML escaping for raw chars")
		}

		// SARIF conformance
		sarifData, err := report.GenerateSARIF(rep)
		if err != nil {
			t.Fatalf("GenerateSARIF failed: %v", err)
		}
		if err := report.ValidateSARIF(sarifData); err != nil {
			t.Fatalf("ValidateSARIF failed for unicode finding: %v", err)
		}
	})

	t.Run("Inconclusive observations are never represented as verified vulnerabilities", func(t *testing.T) {
		inconclusiveFinding := report.Finding{
			ID:           "FND-INC-01",
			Title:        "SPA Login Fallback Shell",
			Severity:     report.SeverityInfo,
			Category:     "route-unverified",
			Target:       "https://app.example.com",
			Endpoint:     "/admin/dashboard",
			Status:       report.FindingStatusInconclusive,
			Verification: report.VerificationRecord{Status: report.VerificationObserved, Result: "HTML_SPA_LOGIN_SHELL"},
		}

		rep := report.BuildReport("https://app.example.com", []report.Finding{inconclusiveFinding})
		rep.CompletionStatus = "COMPLETED"

		if rep.Summary.VerifiedCount != 0 {
			t.Errorf("inconclusive observation must have VerifiedCount=0, got: %d", rep.Summary.VerifiedCount)
		}
		if rep.Summary.InconclusiveCount != 1 {
			t.Errorf("expected InconclusiveCount=1, got: %d", rep.Summary.InconclusiveCount)
		}
		if rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("inconclusive observation must not inflate risk: score=%d, level=%s", rep.RiskScore, rep.RiskLevel)
		}

		// In CommercialReport, inconclusive findings must not appear in VerifiedFindings
		cr := report.BuildCommercialReport(rep)
		if len(cr.VerifiedFindings) != 0 {
			t.Errorf("inconclusive finding must not appear in VerifiedFindings")
		}
		if len(cr.Observations) != 1 {
			t.Errorf("inconclusive finding must appear under Observations")
		}
	})

	t.Run("Failed and blocked assessments are clearly distinguishable with unavailable risk", func(t *testing.T) {
		blockedRep := report.BuildReport("https://blocked.example.com", nil)
		blockedRep.CompletionStatus = "BLOCKED"
		report.RecalculateReportRisk(&blockedRep)

		if blockedRep.CompletionStatus != "BLOCKED" {
			t.Errorf("expected BLOCKED status, got: %s", blockedRep.CompletionStatus)
		}
		if blockedRep.RiskLevel != "UNAVAILABLE" || blockedRep.RiskScore != 0 || blockedRep.RiskScoreAvailable {
			t.Errorf("blocked assessment must have UNAVAILABLE risk score: %+v", blockedRep)
		}
		if err := report.ValidateReportIntegrity(blockedRep); err != nil {
			t.Fatalf("blocked report failed integrity validation: %v", err)
		}

		failedRep := report.BuildReport("https://failed.example.com", nil)
		failedRep.CompletionStatus = "FAILED"
		report.RecalculateReportRisk(&failedRep)

		if failedRep.CompletionStatus != "FAILED" {
			t.Errorf("expected FAILED status, got: %s", failedRep.CompletionStatus)
		}
		if failedRep.RiskLevel != "UNAVAILABLE" || failedRep.RiskScore != 0 || failedRep.RiskScoreAvailable {
			t.Errorf("failed assessment must have UNAVAILABLE risk score: %+v", failedRep)
		}
		if err := report.ValidateReportIntegrity(failedRep); err != nil {
			t.Fatalf("failed report failed integrity validation: %v", err)
		}
	})
}

// TestReportingIntegrity_HTMLInjectionAndSecurity validates that all untrusted fields
// are safely contextually escaped and malicious script execution is impossible.
func TestReportingIntegrity_HTMLInjectionAndSecurity(t *testing.T) {
	hostileFinding := report.Finding{
		ID:          "FND-XSS-<script>alert(1)</script>",
		Title:       "SQL Injection\"><script>alert('title-xss')</script><b attr=\"",
		Description: "Hostile description with multiple breakouts: </div><script>alert('desc')</script><iframe src=\"javascript:alert(2)\">",
		Evidence:    "Hostile evidence: </pre><script>alert('ev')</script><a href=\"javascript:alert('link')\">clickme</a>",
		Remediation: "Hostile remediation: </span><script>alert('rem')</script>",
		Target:      "https://attacker.com\"><script>alert('target')</script>",
		Endpoint:    "/api/v1/test?param=\"><script>alert('endpoint')</script>",
		Method:      "GET<script>alert('method')</script>",
		Category:    "hostile-cat\"><script>alert('cat')</script>",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		RemediationAdvice: &report.RemediationAdvice{
			Summary:     "Advice summary <script>alert('summary')</script>",
			Steps:       []string{"Step 1 <script>alert('step')</script>"},
			References:  []string{"javascript:alert('ref')", "https://trusted.example.com/<script>alert(3)</script>"},
			CodeSnippet: "const x = '<script>alert(1)</script>';",
		},
		Verification: report.VerificationRecord{
			Status:          report.VerificationVerified,
			Result:          "Result <script>alert('res')</script>",
			SafeCurlCommand: "curl 'https://victim.com' -H 'X-Evil: <script>alert(1)</script>'",
		},
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Observation <script>alert('obs')</script>",
			Location:    "https://victim.com/loc\"><script>alert('loc')</script>",
			Details: map[string]string{
				"custom_key_<script>": "custom_val_<script>alert('val')</script>",
			},
		},
	}

	rep := report.BuildReport("https://attacker.com", []report.Finding{hostileFinding})
	rep.CompletionStatus = "COMPLETED"

	// 1. Standard HTML Report
	htmlContent, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	forbiddenPayloads := []string{
		"<script>alert('title-xss')</script>",
		"<script>alert('desc')</script>",
		"<script>alert('ev')</script>",
		"<script>alert('rem')</script>",
		"<script>alert('target')</script>",
		"<script>alert('endpoint')</script>",
		"<iframe src=\"javascript:alert(2)\">",
		"<a href=\"javascript:alert('link')\">",
	}

	for _, payload := range forbiddenPayloads {
		if strings.Contains(htmlContent, payload) {
			t.Errorf("HTML report contains unescaped hostile payload: %s", payload)
		}
	}

	if !strings.Contains(htmlContent, "&lt;script&gt;alert(&#39;title-xss&#39;)&lt;/script&gt;") {
		t.Errorf("expected contextual HTML escaping for title")
	}

	// 2. Commercial HTML Report
	cr := report.BuildCommercialReport(rep)
	commHTML, err := report.GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}

	for _, payload := range forbiddenPayloads {
		if strings.Contains(commHTML, payload) {
			t.Errorf("Commercial HTML report contains unescaped hostile payload: %s", payload)
		}
	}
}

// TestReportingIntegrity_SecretCanariesZeroLeakage verifies that all secret canaries across
// API keys, tokens, connection strings, headers, and query parameters are 100% scrubbed.
func TestReportingIntegrity_SecretCanariesZeroLeakage(t *testing.T) {
	const (
		canaryOpenAIKey   = "sk-proj-CANARY-OPENAI-KEY-998877665544332211"
		canaryBearerToken = "CANARY-BEARER-TOKEN-SECRET-VALUE-XYZ-12345"
		canaryDBPass      = "CANARY-DB-PASS-SECRET-PASSWORD-7788"
		canaryAWSAccess   = "AKIA-CANARY-ACCESS-KEY-1122"
		canaryStripeKey   = "sk_live_CANARY_STRIPE_LIVE_KEY_abcdef"
		canaryJWT         = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDQU5BUllfVVNFUiJ9.CANARY_SIGNATURE_SECRET"
		canaryHeaderAuth  = "CANARY-CUSTOM-AUTH-SECRET-XYZ-99"
		canaryQueryToken  = "CANARY-QUERY-PARAM-SECRET-TOKEN-55"
	)

	finding := report.Finding{
		ID:          "FND-SECRET-CANARY-01",
		Title:       fmt.Sprintf("Secret Exposure: %s", canaryOpenAIKey),
		Description: fmt.Sprintf("Hardcoded Bearer %s detected in bundle and DB uri postgres://admin:%s@db.internal:5432/app", canaryBearerToken, canaryDBPass),
		Evidence:    fmt.Sprintf("Authorization: Bearer %s\nAWS Key: %s\nStripe: %s\nJWT: %s", canaryHeaderAuth, canaryAWSAccess, canaryStripeKey, canaryJWT),
		Remediation: fmt.Sprintf("Rotate secret %s immediately and update config", canaryOpenAIKey),
		Target:      fmt.Sprintf("https://app.example.com/login?token=%s", canaryQueryToken),
		Endpoint:    fmt.Sprintf("https://api.example.com/v1/auth?api_key=%s", canaryOpenAIKey),
		Category:    "secrets-leak",
		Severity:    report.SeverityCritical,
		EvidenceDetails: report.EvidenceDetails{
			Observation: fmt.Sprintf("Authorization token: %s", canaryBearerToken),
			Location:    fmt.Sprintf("https://db.internal:5432/orders?password=%s", canaryDBPass),
			Details: map[string]string{
				"Authorization": fmt.Sprintf("Bearer %s", canaryBearerToken),
				"secret_token":  canaryHeaderAuth,
				"db_uri":        fmt.Sprintf("postgres://admin:%s@db.internal:5432/prod", canaryDBPass),
			},
		},
		Verification: report.VerificationRecord{
			Status:          report.VerificationVerified,
			Result:          fmt.Sprintf("Verified access using token: %s", canaryBearerToken),
			SafeCurlCommand: fmt.Sprintf("curl -H 'Authorization: Bearer %s' https://api.example.com", canaryBearerToken),
		},
	}

	rep := report.BuildReport("https://app.example.com", []report.Finding{finding})
	rep.CompletionStatus = "COMPLETED"

	allCanaries := []string{
		canaryOpenAIKey,
		canaryBearerToken,
		canaryDBPass,
		canaryAWSAccess,
		canaryStripeKey,
		canaryJWT,
		canaryHeaderAuth,
		canaryQueryToken,
	}

	// 1. JSON Report
	jsonData, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	jsonStr := string(jsonData)
	for _, canary := range allCanaries {
		if strings.Contains(jsonStr, canary) {
			t.Errorf("JSON report leaked canary: %s", canary)
		}
	}

	// 2. HTML Report
	htmlContent, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	for _, canary := range allCanaries {
		if strings.Contains(htmlContent, canary) {
			t.Errorf("HTML report leaked canary: %s", canary)
		}
	}

	// 3. SARIF Report
	sarifData, err := report.GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	sarifStr := string(sarifData)
	for _, canary := range allCanaries {
		if strings.Contains(sarifStr, canary) {
			t.Errorf("SARIF report leaked canary: %s", canary)
		}
	}
	if err := report.ValidateSARIF(sarifData); err != nil {
		t.Fatalf("SARIF failed schema validation: %v", err)
	}

	// 4. Commercial HTML Report
	cr := report.BuildCommercialReport(rep)
	commHTML, err := report.GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	for _, canary := range allCanaries {
		if strings.Contains(commHTML, canary) {
			t.Errorf("Commercial HTML report leaked canary: %s", canary)
		}
	}

	// 5. Commercial JSON Report
	commJSON, err := report.GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	commJSONStr := string(commJSON)
	for _, canary := range allCanaries {
		if strings.Contains(commJSONStr, canary) {
			t.Errorf("Commercial JSON report leaked canary: %s", canary)
		}
	}
}

// TestReportingIntegrity_FilesystemReliability tests the safe write, overwrite, and failure semantics
// across HTML, JSON, and SARIF exports.
func TestReportingIntegrity_FilesystemReliability(t *testing.T) {
	tmpDir := t.TempDir()

	f := report.Finding{
		ID:       "FND-FS-01",
		Title:    "File Reliability Verification",
		Severity: report.SeverityMedium,
		Target:   "https://fs.example.com",
		Endpoint: "/status",
	}
	rep := report.BuildReport("https://fs.example.com", []report.Finding{f})
	rep.CompletionStatus = "COMPLETED"

	t.Run("Valid exports create non-empty, parseable files", func(t *testing.T) {
		htmlPath := filepath.Join(tmpDir, "report.html")
		jsonPath := filepath.Join(tmpDir, "report.json")
		sarifPath := filepath.Join(tmpDir, "report.sarif")

		if err := report.WriteHTML(rep, htmlPath); err != nil {
			t.Fatalf("WriteHTML failed: %v", err)
		}
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			t.Fatalf("WriteJSON failed: %v", err)
		}
		if err := report.WriteSARIF(rep, sarifPath); err != nil {
			t.Fatalf("WriteSARIF failed: %v", err)
		}

		// Check non-empty
		fiH, err := os.Stat(htmlPath)
		if err != nil || fiH.Size() < 100 {
			t.Errorf("HTML file missing or unexpectedly small: %v", err)
		}

		fiJ, err := os.Stat(jsonPath)
		if err != nil || fiJ.Size() < 100 {
			t.Errorf("JSON file missing or unexpectedly small: %v", err)
		}

		fiS, err := os.Stat(sarifPath)
		if err != nil || fiS.Size() < 100 {
			t.Errorf("SARIF file missing or unexpectedly small: %v", err)
		}

		// Check parseability
		loadedRep, err := report.LoadReport(jsonPath)
		if err != nil {
			t.Fatalf("LoadReport failed on exported JSON: %v", err)
		}
		if len(loadedRep.Findings) != 1 {
			t.Errorf("expected 1 finding in loaded report, got: %d", len(loadedRep.Findings))
		}

		if err := report.ValidateSARIFFile(sarifPath); err != nil {
			t.Fatalf("ValidateSARIFFile failed on exported SARIF: %v", err)
		}
	})

	t.Run("Overwriting existing files is safe and replaces content", func(t *testing.T) {
		existingFile := filepath.Join(tmpDir, "pre_existing.json")
		if err := os.WriteFile(existingFile, []byte("original-valid-content"), 0600); err != nil {
			t.Fatalf("failed to create existing file: %v", err)
		}

		// Overwrite with valid report
		if err := report.WriteJSON(rep, existingFile); err != nil {
			t.Fatalf("WriteJSON failed to overwrite: %v", err)
		}

		data, err := os.ReadFile(existingFile)
		if err != nil {
			t.Fatalf("failed to read overwritten file: %v", err)
		}
		if !strings.Contains(string(data), "File Reliability Verification") {
			t.Errorf("overwritten file does not contain expected report content")
		}
	})

	t.Run("Missing parent directory returns error per contract", func(t *testing.T) {
		invalidPath := filepath.Join(tmpDir, "missing_subdir", "nested", "audit.html")
		err := report.WriteHTML(rep, invalidPath)
		if err == nil {
			t.Errorf("expected error when writing to nonexistent parent directory, got nil")
		}
	})

	t.Run("Empty or directory paths return error", func(t *testing.T) {
		if err := report.WriteHTML(rep, ""); err == nil {
			t.Errorf("expected error writing to empty path, got nil")
		}
		if err := report.WriteJSON(rep, "   "); err == nil {
			t.Errorf("expected error writing to whitespace path, got nil")
		}
		if err := report.WriteSARIF(rep, tmpDir); err == nil {
			t.Errorf("expected error writing to directory path, got nil")
		}
	})
}

// TestReportingIntegrity_CrossFormatParity ensures that HTML, JSON, and SARIF
// generated from the identical canonical assessment contain consistent counts, severities, and metadata.
func TestReportingIntegrity_CrossFormatParity(t *testing.T) {
	findings := []report.Finding{
		{
			ID:          "FND-PARITY-CRIT",
			Title:       "Privileged Cloud Access Key in Bundle",
			Severity:    report.SeverityCritical,
			Confidence:  report.ConfidenceHigh,
			Target:      "https://target.corp",
			Endpoint:    "/static/bundle.js",
			Category:    "cloud-keys",
			Fingerprint: "fp-cloud-key-01",
			Verification: report.VerificationRecord{Status: report.VerificationVerified, Result: "LIVE_KEY"},
		},
		{
			ID:          "FND-PARITY-HIGH",
			Title:       "BOLA Access to Account Details",
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
			Target:      "https://target.corp",
			Endpoint:    "/api/v1/accounts/202",
			Category:    "bola",
			Fingerprint: "fp-bola-02",
			Verification: report.VerificationRecord{Status: report.VerificationVerified, Result: "CROSS_TENANT_LEAK"},
		},
		{
			ID:          "FND-PARITY-MED",
			Title:       "CORS Origin Reflection",
			Severity:    report.SeverityMedium,
			Confidence:  report.ConfidenceMedium,
			Target:      "https://target.corp",
			Endpoint:    "/api/v1/feed",
			Category:    "cors",
			Fingerprint: "fp-cors-03",
			Verification: report.VerificationRecord{Status: report.VerificationDetected, Result: "SUSPECTED"},
		},
		{
			ID:          "FND-PARITY-LOW",
			Title:       "Missing Security Headers",
			Severity:    report.SeverityLow,
			Confidence:  report.ConfidenceHigh,
			Target:      "https://target.corp",
			Endpoint:    "/",
			Category:    "missing-headers",
			Fingerprint: "fp-headers-04",
			Verification: report.VerificationRecord{Status: report.VerificationObserved, Result: "ABSENT"},
		},
	}

	rep := report.BuildReport("https://target.corp", findings)
	rep.CompletionStatus = "COMPLETED"

	// 1. Generate JSON and parse
	jsonData, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	parsedJSON, err := report.ParseReport(jsonData)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	// 2. Generate SARIF and parse
	sarifData, err := report.GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	if err := report.ValidateSARIF(sarifData); err != nil {
		t.Fatalf("ValidateSARIF failed: %v", err)
	}

	var sarifLog report.SARIFLog
	if err := json.Unmarshal(sarifData, &sarifLog); err != nil {
		t.Fatalf("Unmarshal SARIF failed: %v", err)
	}

	// 3. Generate HTML
	htmlContent, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	// Parity Assertion 1: Total finding count
	if len(parsedJSON.Findings) != len(findings) {
		t.Errorf("JSON finding count mismatch: expected %d, got %d", len(findings), len(parsedJSON.Findings))
	}
	if len(sarifLog.Runs[0].Results) != len(findings) {
		t.Errorf("SARIF results count mismatch: expected %d, got %d", len(findings), len(sarifLog.Runs[0].Results))
	}

	// Parity Assertion 2: Severity distribution
	if rep.Summary.CriticalCount != parsedJSON.Summary.CriticalCount ||
		rep.Summary.HighCount != parsedJSON.Summary.HighCount ||
		rep.Summary.MediumCount != parsedJSON.Summary.MediumCount ||
		rep.Summary.LowCount != parsedJSON.Summary.LowCount {
		t.Errorf("JSON summary counts do not match canonical summary: %+v vs %+v", parsedJSON.Summary, rep.Summary)
	}

	// In SARIF: Critical and High -> "error", Medium -> "warning", Low -> "note"
	var sarifErrors, sarifWarnings, sarifNotes int
	for _, res := range sarifLog.Runs[0].Results {
		switch res.Level {
		case "error":
			sarifErrors++
		case "warning":
			sarifWarnings++
		case "note":
			sarifNotes++
		}
	}
	expectedErrors := rep.Summary.CriticalCount + rep.Summary.HighCount
	if sarifErrors != expectedErrors {
		t.Errorf("SARIF error level count mismatch: expected %d, got %d", expectedErrors, sarifErrors)
	}
	if sarifWarnings != rep.Summary.MediumCount {
		t.Errorf("SARIF warning level count mismatch: expected %d, got %d", rep.Summary.MediumCount, sarifWarnings)
	}
	if sarifNotes != rep.Summary.LowCount {
		t.Errorf("SARIF note level count mismatch: expected %d, got %d", rep.Summary.LowCount, sarifNotes)
	}

	// Parity Assertion 3: HTML includes all finding titles
	for _, f := range findings {
		if !strings.Contains(htmlContent, f.Title) {
			t.Errorf("HTML report missing finding title: %s", f.Title)
		}
	}

	// Parity Assertion 4: Execution successful flag in SARIF invocations
	if !sarifLog.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Errorf("expected ExecutionSuccessful to be true in SARIF invocations")
	}
}
