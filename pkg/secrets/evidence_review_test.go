package secrets_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/apk"
	"felix/pkg/assessment"
	"felix/pkg/notify"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// =============================================================================
// Comprehensive Synthetic Secret Markers for P11.7 Evidence Review
// =============================================================================

const (
	testSecretBearerToken     = "FELIX_TEST_SECRET_BEARER_8a7f2c1b9e0d4a3f"
	testSecretAPIKey          = "FELIX_TEST_SECRET_APIKEY_9c8b7a6d5e4f3a2b"
	testSecretPassword        = "FELIX_TEST_SECRET_PASS_P@ssw0rd123!"
	testSecretClientSecret    = "FELIX_TEST_SECRET_CLIENTSEC_4f3e2d1c0b9a8e7d"
	testSecretSessionCookie   = "FELIX_TEST_SECRET_SESSION_7e6d5c4b3a2f1e0d"
	testSecretCSRFToken       = "FELIX_TEST_SECRET_CSRF_1a2b3c4d5e6f7a8b"
	testSecretProxyAuth       = "Basic FELIX_TEST_SECRET_PROXYAUTH_dXNlcjpwYXNz"
	testSecretJWT             = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZFTElYX1RFU1RfU0VDUkVUX0pXVCIiLCJhZG1pbiI6dHJ1ZX0.4ad7vGqDvd1nJ8c7eFmFh1T7qW5h7tX9vC4rF0_adQs"
	testSecretAWSAccessKey    = "AKIAIOSFODNN7EXAMPLE"
	testSecretStripeKey       = "sk" + "_live_51FELIXTESTSECRET998877665544"
	testSecretGitHubToken     = "gh" + "p_FELIXTESTSECRET11223344556677889900"
	testSecretOpenAIKey       = "s" + "k-FELIXTESTSECRET11223344556677889900"
	testSecretPEMPrivateKey   = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0FELIXTESTSECRETEXAMPLEKEYDATA1234567890ABCDEF\nGHJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/==\n-----END RSA PRIVATE KEY-----"
	testSecretPEMTruncated    = "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIFELIXTESTSECRETECKEYDATA1234567890ABCDEFGHJKLMNOPQR"
	testSecretSSN             = "987-65-4321"
	testSecretCreditCard      = "4111 2222 3333 4444"
	testSecretURLUserPass     = "https://felix_admin:FELIX_TEST_SECRET_PASS_P@ssw0rd123!@internal.corp.local:8443/admin/api"
	testSecretURLQueryParam   = "https://internal.corp.local/v1/auth?token=FELIX_TEST_SECRET_PARAM_TOKEN&client_secret=FELIX_TEST_SECRET_PARAM_SEC&csrf=FELIX_TEST_SECRET_PARAM_CSRF&view=audit"
	testANSIEscapeSequence    = "\x1b[31;1mFELIX_TEST_SECRET_ANSI_INJECTION\x1b[0m\x1b]0;PwnedTitle\x07"
	testControlCharacters     = "HeaderValue\x00\x08\x0b\x0c\x1fSanitized"
)

// assertZeroSecretLeaks verifies that the output string contains zero occurrences
// of any synthetic secret markers, cleartext tokens, ANSI injection sequences, or control characters.
func assertZeroSecretLeaks(t *testing.T, output string, context string) {
	t.Helper()

	syntheticMarkers := []string{
		"FELIX_TEST_SECRET",
		testSecretBearerToken,
		testSecretAPIKey,
		testSecretPassword,
		testSecretClientSecret,
		testSecretSessionCookie,
		testSecretCSRFToken,
		"dXNlcjpwYXNz",
		testSecretAWSAccessKey,
		testSecretStripeKey,
		testSecretGitHubToken,
		testSecretOpenAIKey,
		"MIIEowIBAAKCAQEA0FELIXTESTSECRET",
		"MHcCAQEEIFELIXTESTSECRETECKEY",
		testSecretSSN,
		testSecretCreditCard,
	}

	for _, marker := range syntheticMarkers {
		if strings.Contains(output, marker) {
			// Find the line that leaked
			for _, line := range strings.Split(output, "\n") {
				if strings.Contains(line, marker) {
					t.Errorf("[%s] LEAKED LINE: %s", context, strings.TrimSpace(line))
				}
			}
			t.Fatalf("[%s] Leak detected! Output contains raw sensitive marker %q", context, marker)
		}
	}

	// Verify no raw unstripped ANSI sequences
	if strings.Contains(output, "\x1b[") || strings.Contains(output, "\x1b]") {
		t.Fatalf("[%s] ANSI terminal escape sequence detected in output: %s", context, truncateOutputForLog(output))
	}

	// Verify no raw ASCII control characters (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F, 0x7F)
	for i := 0; i < len(output); i++ {
		b := output[i]
		if (b < 32 && b != '\t' && b != '\n' && b != '\r') || b == 0x7f {
			t.Fatalf("[%s] Non-printable control character byte 0x%02x detected in output", context, b)
		}
	}
}

func truncateOutputForLog(s string) string {
	if len(s) > 300 {
		return s[:150] + " ... [TRUNCATED] ... " + s[len(s)-100:]
	}
	return s
}

// =============================================================================
// Category 1: Authorization and Proxy-Authorization Headers
// =============================================================================

func TestEvidenceReview_AuthorizationAndProxyHeaders(t *testing.T) {
	headers := http.Header{
		"Authorization":       []string{"Bearer " + testSecretBearerToken},
		"Proxy-Authorization": []string{testSecretProxyAuth},
		"X-Api-Key":           []string{testSecretAPIKey},
		"X-Session-ID":        []string{testSecretSessionCookie},
		"X-CSRF-Token":        []string{testSecretCSRFToken},
		"X-Custom-Secret":     []string{testSecretClientSecret},
		"Content-Type":        []string{"application/json"},
		"User-Agent":          []string{"Felix-Security/2.0"},
	}

	sanitized := secrets.SanitizeHeaders(headers)

	// Assert sensitive headers are redacted
	for _, sensitive := range []string{"Authorization", "Proxy-Authorization", "X-Api-Key", "X-Session-ID", "X-CSRF-Token", "X-Custom-Secret"} {
		if val, ok := sanitized[sensitive]; !ok || val != "[REDACTED]" {
			t.Errorf("Expected %s to be [REDACTED], got %q", sensitive, val)
		}
	}

	// Assert non-sensitive headers are preserved
	if sanitized["Content-Type"] != "application/json" {
		t.Errorf("Expected Content-Type to be preserved, got %q", sanitized["Content-Type"])
	}
	if sanitized["User-Agent"] != "Felix-Security/2.0" {
		t.Errorf("Expected User-Agent to be preserved, got %q", sanitized["User-Agent"])
	}

	rawJSON, _ := json.Marshal(sanitized)
	assertZeroSecretLeaks(t, string(rawJSON), "SanitizeHeaders")
}

// =============================================================================
// Category 2: Bearer Tokens, API Keys, Passwords, and Client Secrets
// =============================================================================

func TestEvidenceReview_BearerAndVendorTokens(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"BearerToken", "Request used Authorization: Bearer " + testSecretBearerToken + " to authenticate"},
		{"StripeLiveKey", "Leaked gateway credential: " + testSecretStripeKey + " in JavaScript"},
		{"GitHubPAT", "Found repo access token: " + testSecretGitHubToken + " in build log"},
		{"OpenAIKey", "Exposed LLM key: " + testSecretOpenAIKey + " in backend config"},
		{"AWSAccessKey", "Hardcoded cloud identity: " + testSecretAWSAccessKey + " in client bundle"},
		{"PasswordAssignment", "db_password: " + testSecretPassword},
		{"ClientSecretAssignment", `{"client_secret": "` + testSecretClientSecret + `"}`},
		{"ProsePassword", "Database connection established with password " + testSecretPassword + " on port 5432"},
		{"ProseFoundSecret", "Found secret " + testSecretClientSecret + " in environment dump"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redacted := secrets.RedactText(tc.input)
			assertZeroSecretLeaks(t, redacted, tc.name)

			// Verify idempotency
			secondPass := secrets.RedactText(redacted)
			if secondPass != redacted {
				t.Errorf("[%s] RedactText is not idempotent: first=%q second=%q", tc.name, redacted, secondPass)
			}
		})
	}
}

// =============================================================================
// Category 3: Cookies, Session Identifiers, and CSRF Tokens
// =============================================================================

func TestEvidenceReview_CookiesAndMultiCookieHeader(t *testing.T) {
	// Multi-cookie Request Header
	cookieReq := fmt.Sprintf("session_id=%s; csrf_token=%s; token=%s; theme=dark; lang=en",
		testSecretSessionCookie, testSecretCSRFToken, testSecretBearerToken)

	redactedCookie := secrets.RedactCookieHeader(cookieReq)
	assertZeroSecretLeaks(t, redactedCookie, "Multi-cookie Request Header")

	if !strings.Contains(redactedCookie, "session_id=[REDACTED]") {
		t.Errorf("Expected session_id=[REDACTED], got: %s", redactedCookie)
	}
	if !strings.Contains(redactedCookie, "csrf_token=[REDACTED]") {
		t.Errorf("Expected csrf_token=[REDACTED], got: %s", redactedCookie)
	}

	// Set-Cookie Response Header with Security Directives
	setCookieResp := fmt.Sprintf("auth_session=%s; Path=/app; Domain=corp.local; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Max-Age=3600; HttpOnly; Secure; SameSite=Strict",
		testSecretSessionCookie)

	redactedSetCookie := secrets.RedactCookieHeader(setCookieResp)
	assertZeroSecretLeaks(t, redactedSetCookie, "Set-Cookie Response Header")

	// Ensure all standard security attributes are preserved intact
	for _, attr := range []string{"Path=/app", "Domain=corp.local", "HttpOnly", "Secure", "SameSite=Strict"} {
		if !strings.Contains(redactedSetCookie, attr) {
			t.Errorf("Expected Set-Cookie security attribute %q to be preserved, got: %s", attr, redactedSetCookie)
		}
	}
}

// =============================================================================
// Category 4: JWTs and Cloud Identity Credentials
// =============================================================================

func TestEvidenceReview_JWTAndCloudCredentials(t *testing.T) {
	jwtInput := "Server verified token: " + testSecretJWT + " with issuer https://auth.corp.local"
	redactedJWT := secrets.RedactText(jwtInput)
	assertZeroSecretLeaks(t, redactedJWT, "JWT Redaction")

	if !strings.Contains(redactedJWT, "[REDACTED_JWT]") {
		t.Errorf("Expected [REDACTED_JWT] placeholder, got: %s", redactedJWT)
	}
	if !strings.Contains(redactedJWT, "https://auth.corp.local") {
		t.Errorf("Harmless issuer URL was improperly removed: %s", redactedJWT)
	}
}

// =============================================================================
// Category 5: Credential-Bearing URLs and Sensitive Query Parameters
// =============================================================================

func TestEvidenceReview_URLsAndConnectionStrings(t *testing.T) {
	// Embedded User:Password URL
	sanitizedUserPass := secrets.SanitizeURL(testSecretURLUserPass)
	assertZeroSecretLeaks(t, sanitizedUserPass, "SanitizeURL UserPass")
	if !strings.Contains(sanitizedUserPass, "internal.corp.local:8443/admin/api") {
		t.Errorf("URL host and path were improperly modified: %s", sanitizedUserPass)
	}

	// URL with sensitive and non-sensitive query parameters
	sanitizedQuery := secrets.SanitizeURL(testSecretURLQueryParam)
	assertZeroSecretLeaks(t, sanitizedQuery, "SanitizeURL QueryParams")
	if !strings.Contains(sanitizedQuery, "view=audit") {
		t.Errorf("Harmless non-sensitive query parameter 'view=audit' was lost: %s", sanitizedQuery)
	}
	if !strings.Contains(sanitizedQuery, "token=[REDACTED]") {
		t.Errorf("Expected token=[REDACTED], got: %s", sanitizedQuery)
	}
	if !strings.Contains(sanitizedQuery, "client_secret=[REDACTED]") {
		t.Errorf("Expected client_secret=[REDACTED], got: %s", sanitizedQuery)
	}

	// JDBC Connection String
	jdbcInput := "jdbc:postgresql://felix_db:FELIX_TEST_SECRET_DB_PASS@db.corp.local:5432/production?sslmode=verify-full&secret=FELIX_TEST_SECRET_DB_SEC"
	sanitizedJDBC := secrets.SanitizeURL(jdbcInput)
	assertZeroSecretLeaks(t, sanitizedJDBC, "SanitizeURL JDBC")
	if !strings.HasPrefix(sanitizedJDBC, "jdbc:") {
		t.Errorf("Expected jdbc: prefix to be preserved, got: %s", sanitizedJDBC)
	}
	if !strings.Contains(sanitizedJDBC, "sslmode=verify-full") {
		t.Errorf("Harmless sslmode query parameter was lost: %s", sanitizedJDBC)
	}
}

// =============================================================================
// Category 6: Sensitive JSON Keys and Deep Structures
// =============================================================================

func TestEvidenceReview_SensitiveJSONKeysAndStructures(t *testing.T) {
	data := map[string]any{
		"user": map[string]any{
			"username":      "security_analyst",
			"password":      testSecretPassword,
			"api_token":     testSecretAPIKey,
			"session_id":    testSecretSessionCookie,
			"csrf_token":    testSecretCSRFToken,
			"refresh_token": testSecretBearerToken,
			"profile": map[string]any{
				"full_name":     "Jane Doe",
				"ssn":           testSecretSSN,
				"credit_card":   testSecretCreditCard,
				"is_admin":      true,
				"client_secret": testSecretClientSecret,
			},
		},
		"endpoint": "/api/v2/users/me",
		"status":   "ACTIVE",
	}

	redactedMap := secrets.RedactMap(data)
	mapJSON, _ := json.Marshal(redactedMap)
	assertZeroSecretLeaks(t, string(mapJSON), "RedactMap")

	// Verify non-sensitive context is preserved
	userMap, ok := redactedMap["user"].(map[string]any)
	if !ok || userMap["username"] != "security_analyst" {
		t.Errorf("Expected username to be preserved, got: %v", userMap["username"])
	}

	// Test RedactJSON fail-closed handling on malformed JSON
	malformedInput := []byte(`{"access_token": "` + testSecretBearerToken + `", "status": `)
	redactedJSONBytes := secrets.RedactJSON(malformedInput)
	assertZeroSecretLeaks(t, string(redactedJSONBytes), "RedactJSON Malformed")
}

// =============================================================================
// Category 7: Private Keys and Multiline PEM Blocks
// =============================================================================

func TestEvidenceReview_PrivateKeysAndMultilinePEM(t *testing.T) {
	// Complete multiline PEM
	logWithKey := "Error occurred while loading private key:\n" + testSecretPEMPrivateKey + "\nSSL handshake terminated."
	redactedKey := secrets.RedactText(logWithKey)
	assertZeroSecretLeaks(t, redactedKey, "PEM Private Key Complete")
	if !strings.Contains(redactedKey, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("Expected [REDACTED_PRIVATE_KEY] placeholder, got: %s", redactedKey)
	}

	// Truncated/unclosed PEM block in error stream
	truncatedLog := "Truncated stack trace:\n" + testSecretPEMTruncated
	redactedTruncated := secrets.RedactText(truncatedLog)
	assertZeroSecretLeaks(t, redactedTruncated, "PEM Private Key Truncated")
	if !strings.Contains(redactedTruncated, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("Expected [REDACTED_PRIVATE_KEY] for truncated PEM, got: %s", redactedTruncated)
	}
}

// =============================================================================
// Category 8: SSN and Credit Card Numbers (PII)
// =============================================================================

func TestEvidenceReview_PII_SSNAndCreditCards(t *testing.T) {
	piiText := fmt.Sprintf("Customer profile contains SSN %s and Primary Card %s registered to account.",
		testSecretSSN, testSecretCreditCard)

	redactedPII := secrets.RedactText(piiText)
	assertZeroSecretLeaks(t, redactedPII, "PII SSN and Card")

	if !strings.Contains(redactedPII, "[REDACTED_SSN]") {
		t.Errorf("Expected [REDACTED_SSN], got: %s", redactedPII)
	}
	if !strings.Contains(redactedPII, "[REDACTED_CARD_NUMBER]") {
		t.Errorf("Expected [REDACTED_CARD_NUMBER], got: %s", redactedPII)
	}
	if !strings.Contains(redactedPII, "Customer profile contains") {
		t.Errorf("Harmless prose was stripped: %s", redactedPII)
	}
}

// =============================================================================
// Category 9: ANSI Escape Codes and Terminal Injection
// =============================================================================

func TestEvidenceReview_ANSIAndControlSequences(t *testing.T) {
	// 1. StripANSI standalone test
	cleanedANSI := secrets.StripANSI(testANSIEscapeSequence)
	if strings.Contains(cleanedANSI, "\x1b") {
		t.Errorf("ANSI escape bytes remained after StripANSI: %q", cleanedANSI)
	}
	if cleanedANSI != "FELIX_TEST_SECRET_ANSI_INJECTION" {
		t.Errorf("Unexpected output after StripANSI: %q", cleanedANSI)
	}

	// 2. SanitizeControlCharacters standalone test
	cleanedCtrl := secrets.SanitizeControlCharacters(testControlCharacters)
	if strings.Contains(cleanedCtrl, "\x00") || strings.Contains(cleanedCtrl, "\x08") {
		t.Errorf("Control characters remained after SanitizeControlCharacters: %q", cleanedCtrl)
	}
	if cleanedCtrl != "HeaderValueSanitized" {
		t.Errorf("Unexpected output after SanitizeControlCharacters: %q", cleanedCtrl)
	}

	// 3. Combined in RedactText
	mixedInput := fmt.Sprintf("\x1b[31;1mpassword=\"%s\"\x1b[0m\x00\x08", testSecretPassword)
	redactedMixed := secrets.RedactText(mixedInput)
	assertZeroSecretLeaks(t, redactedMixed, "RedactText with ANSI and Control Chars")
	if !strings.Contains(redactedMixed, `password="[REDACTED]"`) {
		t.Errorf("Expected password to be redacted after stripping ANSI, got: %s", redactedMixed)
	}
}

// =============================================================================
// Category 10: Callback Headers and OAST / Request Payloads
// =============================================================================

func TestEvidenceReview_CallbackHeadersAndPayloads(t *testing.T) {
	headers := map[string]string{
		"Authorization":   "Bearer " + testSecretBearerToken,
		"X-OAST-Token":    testSecretAPIKey,
		"X-Callback-Sig":  testSecretClientSecret,
		"Content-Type":    "application/x-www-form-urlencoded",
	}

	payload := "token=" + testSecretBearerToken + "&action=verify&pass=" + testSecretPassword
	summary := secrets.RedactRequestSummary("POST", "https://oast.corp.local/callback?token="+testSecretAPIKey, headers, payload)

	assertZeroSecretLeaks(t, summary, "RedactRequestSummary")
	if !strings.Contains(summary, "POST https://oast.corp.local/callback?token=[REDACTED]") {
		t.Errorf("Expected endpoint to be sanitized, got: %s", summary)
	}
	if !strings.Contains(summary, "Authorization: [REDACTED]") {
		t.Errorf("Expected Authorization: [REDACTED], got: %s", summary)
	}
	if !strings.Contains(summary, "Content-Type: application/x-www-form-urlencoded") {
		t.Errorf("Expected Content-Type to be preserved, got: %s", summary)
	}
}

// =============================================================================
// Category 11: SQLite Persistence Round-Trip (No Raw Secret Storage)
// =============================================================================

func TestEvidenceReview_PersistenceRoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence_review_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	clientID := "client-rev-01"
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Evidence Review Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asmID := "asm-rev-01"
	execID := "exec-rev-01"
	targetID := "tgt-rev-01"

	_ = store.CreateAssessment(&assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-REV-01",
		Name:           "Evidence Review Assessment",
		ClientID:       clientID,
		AssessmentType: "WEB_API",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://api.corp.local",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	})

	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	})

	rawFinding := report.Finding{
		ID:          "rev-find-001",
		RuleID:      "SEC-CREDS-01",
		Title:       "Sensitive Credential Exposure: password=" + testSecretPassword,
		Category:    "secrets",
		Severity:    report.SeverityCritical,
		Confidence:  report.ConfidenceHigh,
		Target:      testSecretURLUserPass,
		Endpoint:    testSecretURLQueryParam,
		Method:      "GET",
		Description: "Response contained client_secret=" + testSecretClientSecret + " and Bearer " + testSecretBearerToken,
		Evidence:    "Set-Cookie: session=" + testSecretSessionCookie + "; csrf=" + testSecretCSRFToken,
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Observation with api_key=" + testSecretAPIKey + " and JWT " + testSecretJWT,
			Location:    testSecretURLQueryParam,
			Details: map[string]string{
				"Authorization": "Bearer " + testSecretBearerToken,
				"error_log":     "database failure with password=" + testSecretPassword,
				"safe_context":  "transaction_id_12345",
			},
		},
		Verification: report.VerificationRecord{
			Status:          report.VerificationVerified,
			Result:          "Verified access using token: " + testSecretBearerToken,
			Rationale:       "Endpoint returned 200 with secret=" + testSecretClientSecret,
			SafeCurlCommand: "curl -H 'Authorization: Bearer " + testSecretBearerToken + "' https://api.corp.local/data",
			ReproductionSteps: []string{
				"Step 1: Authenticate with password=" + testSecretPassword,
				"Step 2: Obtain session=" + testSecretSessionCookie,
			},
		},
		Remediation: "Ensure password=" + testSecretPassword + " and key=" + testSecretAPIKey + " are removed.",
	}

	// 1. Construct AssessmentFinding via ToAssessmentFinding
	asmFinding := assessment.ToAssessmentFinding(asmID, execID, targetID, rawFinding)

	// Save to SQLite store
	if err := store.SaveFindings([]assessment.AssessmentFinding{asmFinding}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	// Retrieve from SQLite store
	retrieved, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(retrieved))
	}

	// Assert retrieved AssessmentFinding has zero secret leaks
	retrievedJSON, _ := json.Marshal(retrieved[0])
	assertZeroSecretLeaks(t, string(retrievedJSON), "SQLite Retrieved AssessmentFinding")

	// Convert back to report.Finding via ToReportFinding
	repFinding := assessment.ToReportFinding(retrieved[0])
	repFindingJSON, _ := json.Marshal(repFinding)
	assertZeroSecretLeaks(t, string(repFindingJSON), "ToReportFinding")

	// Verify non-sensitive context is preserved
	if repFinding.RuleID != "SEC-CREDS-01" {
		t.Errorf("Expected RuleID 'SEC-CREDS-01', got %q", repFinding.RuleID)
	}
	if repFinding.EvidenceDetails.Details["safe_context"] != "transaction_id_12345" {
		t.Errorf("Expected safe_context to be preserved, got %q", repFinding.EvidenceDetails.Details["safe_context"])
	}
}

// =============================================================================
// Category 12: Production Report Exports (JSON, HTML, Commercial, SARIF)
// =============================================================================

func TestEvidenceReview_ReportExports_ZeroLeaks(t *testing.T) {
	nowStr := time.Now().UTC().Format(time.RFC3339)

	testFinding := report.Finding{
		ID:          "leak-check-001",
		RuleID:      "SEC-EXP-001",
		Title:       "Sensitive Credential Exposure: password=" + testSecretPassword,
		Category:    "secrets",
		Severity:    report.SeverityCritical,
		Confidence:  report.ConfidenceHigh,
		Target:      testSecretURLUserPass,
		Endpoint:    testSecretURLQueryParam,
		Method:      "POST",
		Description: "Endpoint exposed Bearer " + testSecretBearerToken + " and Stripe key " + testSecretStripeKey,
		Evidence:    "Response included Set-Cookie: session=" + testSecretSessionCookie + "; csrf=" + testSecretCSRFToken,
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Observation: " + testSecretPEMPrivateKey + "\nSSN: " + testSecretSSN + "\nCard: " + testSecretCreditCard,
			Location:    testSecretURLQueryParam,
			Details: map[string]string{
				"Authorization": "Bearer " + testSecretBearerToken,
				"X-Api-Key":     testSecretAPIKey,
				"error_output":  "database error with password=" + testSecretPassword,
				"safe_metric":   "latency_ms=42",
			},
		},
		Verification: report.VerificationRecord{
			Status:          report.VerificationVerified,
			Result:          "Active session confirmed with token: " + testSecretBearerToken,
			Rationale:       "Payload contained client_secret=" + testSecretClientSecret,
			SafeCurlCommand: "curl -H 'Authorization: Bearer " + testSecretBearerToken + "' 'https://api.corp.local/v1/auth?token=" + testSecretAPIKey + "'",
			ReproductionSteps: []string{
				"1. Send request with password=" + testSecretPassword,
				"2. Verify callback receives token=" + testSecretBearerToken,
			},
		},
		Remediation: "Ensure secret=" + testSecretClientSecret + " is not committed or logged.",
	}

	testReport := report.Report{
		Version:          "2.0.0",
		Target:           testSecretURLUserPass,
		Targets:          []string{testSecretURLUserPass, testSecretURLQueryParam},
		Timestamp:        nowStr,
		Duration:         "1.5s",
		CompletionStatus: "COMPLETED",
		Findings:         []report.Finding{testFinding},
		TopPriorities:    []report.Finding{testFinding},
		SecurityStories: []report.SecurityStory{
			{
				ID:               "story-01",
				Title:            "Account Takeover via password=" + testSecretPassword,
				Summary:          "Attacker obtained bearer token " + testSecretBearerToken,
				Description:      "Compromised session=" + testSecretSessionCookie + " leading to full access.",
				InvestigateFirst: "Inspect credentials at " + testSecretURLQueryParam,
				Evidence:         []string{"Leaked token=" + testSecretBearerToken},
			},
		},
		AttackPaths: []report.AttackPathSummary{
			{
				Title:           "Attack Path via secret_key=" + testSecretClientSecret,
				RiskRationale:   "Exposed API key " + testSecretAPIKey + " permits unauthenticated access.",
				EntryPoint:      testSecretURLQueryParam,
				TargetAsset:     testSecretURLUserPass,
				PrimaryWeakness: "Credential Leak",
				TerminalImpact:  "Data Breach",
				Remediation:     "Revoke token=" + testSecretBearerToken,
				Transitions:     []string{"Step 1: Extract password=" + testSecretPassword},
			},
		},
		Metadata: map[string]any{
			"auth_token":   testSecretBearerToken,
			"safe_runtime": "go1.23.0",
			"error_detail": "Failed with password=" + testSecretPassword,
		},
	}

	// 1. Standard JSON Export
	jsonBytes, err := report.GenerateJSON(testReport)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	assertZeroSecretLeaks(t, string(jsonBytes), "GenerateJSON")
	if !strings.Contains(string(jsonBytes), "leak-check-001") {
		t.Errorf("Finding ID leak-check-001 was improperly stripped from JSON report")
	}

	// 2. Standard HTML Export
	htmlStr, err := report.GenerateHTML(testReport)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	assertZeroSecretLeaks(t, htmlStr, "GenerateHTML")
	if !strings.Contains(htmlStr, "leak-check-001") {
		t.Errorf("Finding ID leak-check-001 was improperly stripped from HTML report")
	}

	// 3. Commercial Report (JSON & HTML)
	commReport := report.BuildCommercialReport(testReport)

	commJSONBytes, err := report.GenerateCommercialJSON(commReport)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	assertZeroSecretLeaks(t, string(commJSONBytes), "GenerateCommercialJSON")
	if !strings.Contains(string(commJSONBytes), "leak-check-001") {
		t.Errorf("Finding ID leak-check-001 was improperly stripped from Commercial JSON report")
	}

	commHTMLStr, err := report.GenerateCommercialHTML(commReport)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	assertZeroSecretLeaks(t, commHTMLStr, "GenerateCommercialHTML")
	if !strings.Contains(commHTMLStr, "leak-check-001") {
		t.Errorf("Finding ID leak-check-001 was improperly stripped from Commercial HTML report")
	}

	// 4. SARIF Export
	sarifLog := report.BuildSARIFLog(testReport)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("Failed to marshal SARIF: %v", err)
	}
	assertZeroSecretLeaks(t, string(sarifBytes), "BuildSARIFLog")
	if !strings.Contains(string(sarifBytes), "leak-check-001") {
		t.Errorf("Finding ID leak-check-001 was improperly stripped from SARIF report")
	}
}

// =============================================================================
// Category 13: Webhook and Notification Payload Sanitization
// =============================================================================

func TestEvidenceReview_WebhookPayload_Redaction(t *testing.T) {
	metaMap := map[string]any{
		"auth_header":   "Bearer " + testSecretBearerToken,
		"api_key":       testSecretAPIKey,
		"client_secret": testSecretClientSecret,
		"password":      testSecretPassword,
		"safe_tenant":   "enterprise-tenant-123",
		"request_id":    "req-test-9999",
	}
	metaBytes, _ := json.Marshal(metaMap)

	notif := notify.Notification{
		ID:           "notif-test-001",
		EventType:    notify.EventSecurityFindingCritical,
		Severity:     notify.SeverityCritical,
		Title:        "Critical finding exposed password=" + testSecretPassword,
		Message:      "Verification succeeded with token: " + testSecretBearerToken + " on " + testSecretURLUserPass,
		TenantID:     "tenant-01",
		AssessmentID: "asm-01",
		PayloadJSON:  string(metaBytes),
		CreatedAt:    time.Now().UTC(),
	}

	payload := notif.ToWebhookPayload()
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Failed to marshal WebhookPayload: %v", err)
	}

	assertZeroSecretLeaks(t, string(payloadBytes), "ToWebhookPayload")

	// Ensure non-sensitive metadata is intact
	if payload.Metadata["safe_tenant"] != "enterprise-tenant-123" {
		t.Errorf("Expected safe_tenant preserved, got: %v", payload.Metadata["safe_tenant"])
	}
	if payload.Metadata["request_id"] != "req-test-9999" {
		t.Errorf("Expected request_id preserved, got: %v", payload.Metadata["request_id"])
	}
	// Ensure sensitive fields were redacted
	if payload.Metadata["api_key"] != "[REDACTED]" {
		t.Errorf("Expected api_key [REDACTED], got: %v", payload.Metadata["api_key"])
	}
}

// =============================================================================
// Category 14: Terminal Change Summary Format Sanitization
// =============================================================================

func TestEvidenceReview_ChangeSummaryTerminal_ZeroLeaks(t *testing.T) {
	now := time.Now().UTC()
	cs := report.ChangeSummary{
		AssessmentID:          "asm-base-01",
		ComparisonExecutionID: "exec-curr-01",
		BaselineExecutionID:   "exec-base-01",
		ComparisonTimestamp:   now,
		BaselineTimestamp:     &now,
		Headline:              "Audit diff revealed secret=" + testSecretClientSecret,
		Narrative: []string{
			"Comparison completed with credentials password=" + testSecretPassword,
			"Target URL: " + testSecretURLQueryParam,
		},
		ImportantChanges: []report.ChangeFindingItem{
			{
				FindingID:      "chg-find-001",
				Title:          "Leaked key=" + testSecretAPIKey,
				Severity:       "HIGH",
				TargetURL:      testSecretURLUserPass,
				Endpoint:       testSecretURLQueryParam,
				Classification: "NEW",
				Explanation:    "Found password=" + testSecretPassword + " with Bearer " + testSecretBearerToken,
			},
		},
	}

	text := cs.FormatText()
	assertZeroSecretLeaks(t, text, "ChangeSummary.FormatText")

	if !strings.Contains(text, "Leaked key=[REDACTED]") {
		t.Errorf("Sanitized title was missing from ChangeSummary text: %s", text)
	}
}

// =============================================================================
// Category 15: Mobile Audit HTML Report Format Sanitization
// =============================================================================

func TestEvidenceReview_MobileAuditHTML_ZeroLeaks(t *testing.T) {
	data := apk.MobileReportData{
		Title:            "Mobile Security Audit - " + testSecretURLUserPass,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ReportVersion:    "1.0.0",
		Status:           "COMPLETED",
		TotalFindings:    1,
		HighCount:        1,
		ExecutiveSummary: "Static analysis found credentials with password=" + testSecretPassword + " and key=" + testSecretAPIKey,
		APKFileName:      "target-mobile-app.apk",
		PackageName:      "com.corp.mobileapp",
		Findings: []apk.ReportFinding{
			{
				ID:             "mob-find-001",
				RuleID:         "APK-SECRET-01",
				Title:          "Embedded secret=" + testSecretClientSecret,
				Severity:       "HIGH",
				SeverityClass:  "high",
				Confidence:     "HIGH",
				AffectedTarget: testSecretURLQueryParam,
				Description:    "Exposed token: " + testSecretBearerToken,
				Evidence:       "Set-Cookie: auth=" + testSecretSessionCookie,
				Remediation:    "Revoke client_secret=" + testSecretClientSecret,
			},
		},
		Endpoints: []apk.ReportEndpoint{
			{
				NormalizedURL: testSecretURLQueryParam,
				HostIdentity:  "corp.local",
			},
		},
	}

	htmlBytes, err := apk.GenerateMobileAuditHTML(&data)
	if err != nil {
		t.Fatalf("GenerateMobileAuditHTML failed: %v", err)
	}

	assertZeroSecretLeaks(t, string(htmlBytes), "GenerateMobileAuditHTML")

	if !strings.Contains(string(htmlBytes), "mob-find-001") {
		t.Errorf("Finding ID mob-find-001 was improperly stripped from Mobile Audit HTML report")
	}
}

// =============================================================================
// Category 16: Direct SQLite Persistence Bypass Protection
// =============================================================================

func TestEvidenceReview_DirectStoreSave_BypassProtection(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "direct_store_bypass_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	clientID := "client-direct-01"
	_ = store.CreateClient(&assessment.Client{
		ID:        clientID,
		Name:      "Direct Bypass Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})

	asmID := "asm-direct-01"
	execID := "exec-direct-01"
	targetID := "tgt-direct-01"

	_ = store.CreateAssessment(&assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-DIR-01",
		Name:           "Direct Save Bypass Test",
		ClientID:       clientID,
		AssessmentType: "WEB_API",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	})

	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://api.corp.local",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	})

	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	})

	// Manually construct raw un-sanitized AssessmentFinding (bypassing ToAssessmentFinding)
	rawAF := assessment.AssessmentFinding{
		ID:                 "direct-find-001",
		AssessmentID:       asmID,
		ExecutionID:        execID,
		TargetID:           targetID,
		OriginalFindingID:  "direct-find-001",
		Title:              "Unsanitized Finding with password=" + testSecretPassword,
		Category:           "secrets",
		Severity:           report.SeverityCritical,
		Confidence:         report.ConfidenceHigh,
		VerificationStatus: report.VerificationVerified,
		TargetURL:          testSecretURLUserPass,
		Endpoint:           testSecretURLQueryParam,
		Method:             "POST",
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Raw token=" + testSecretBearerToken + " and key=" + testSecretAPIKey,
			Details: map[string]string{
				"Authorization": "Bearer " + testSecretBearerToken,
				"error_output":  "database error with password=" + testSecretPassword,
				"safe_item":     "item_999",
			},
		},
		VerificationRecord: report.VerificationRecord{
			Result:    "Verified access using token: " + testSecretBearerToken,
			Rationale: "Exposed client_secret=" + testSecretClientSecret,
		},
		Remediation: "Remove client_secret=" + testSecretClientSecret,
		CreatedAt:   time.Now().UTC(),
	}

	// Directly save to SQLiteStore
	if err := store.SaveFindings([]assessment.AssessmentFinding{rawAF}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	// Query back
	retrieved, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(retrieved))
	}

	// Security Invariant: Even if an un-sanitized finding was somehow persisted into SQLite,
	// converting it for report compilation via ToReportFinding or presenting it via
	// SanitizeAssessmentFinding (as done in Operator API) guarantees zero secret leaks before egress.
	sanitizedReportFinding := assessment.ToReportFinding(retrieved[0])
	repFindingJSON, _ := json.Marshal(sanitizedReportFinding)
	assertZeroSecretLeaks(t, string(repFindingJSON), "ToReportFinding Egress Protection")

	sanitizedAF := assessment.SanitizeAssessmentFinding(retrieved[0])
	afJSON, _ := json.Marshal(sanitizedAF)
	assertZeroSecretLeaks(t, string(afJSON), "SanitizeAssessmentFinding Egress Protection")

	// Ensure non-sensitive metadata is intact
	if sanitizedReportFinding.ID != "direct-find-001" {
		t.Errorf("Finding ID mismatch: got %q, want direct-find-001", sanitizedReportFinding.ID)
	}
	if sanitizedReportFinding.EvidenceDetails.Details["safe_item"] != "item_999" {
		t.Errorf("Safe context detail lost: got %q", sanitizedReportFinding.EvidenceDetails.Details["safe_item"])
	}
}
