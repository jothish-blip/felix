package secrets_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/verification"
)

// Synthetic test canaries. These values represent sensitive material during tests
// and must NEVER appear in any sanitized output, logs, or persisted records.
const (
	canarySecret01 = "FELIX_TEST_SECRET_CANARY_01"
	canaryToken02  = "FELIX_TEST_TOKEN_CANARY_02"
	canaryKey03    = "FELIX_TEST_KEY_CANARY_03"
	canaryPass04   = "FELIX_TEST_PASS_CANARY_04"
	canaryAuth05   = "FELIX_TEST_AUTH_CANARY_05"
)

var allCanaries = []string{
	canarySecret01,
	canaryToken02,
	canaryKey03,
	canaryPass04,
	canaryAuth05,
}

// assertNoCanaries performs an explicit negative leak assertion that none of the
// defined canary values appear anywhere within the provided text output.
func assertNoCanaries(t *testing.T, output string, desc string) {
	t.Helper()
	for _, c := range allCanaries {
		if strings.Contains(output, c) {
			t.Fatalf("LEAK DETECTED in %s: sensitive canary token %q found in sanitized output:\n%s", desc, c, output)
		}
	}
}

// =============================================================================
// 7.1 Core Text Tests
// =============================================================================

func TestRedactText_Passwords(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"password_equals", "password=" + canaryPass04},
		{"password_colon", "password: " + canaryPass04},
		{"passwd_equals", "passwd=" + canaryPass04},
		{"pwd_quotes", `pwd="` + canaryPass04 + `"`},
		{"client_secret_single_quotes", "client_secret: '" + canaryPass04 + "'"},
		{"db_password_backticks", "db_password: `" + canaryPass04 + "`"},
		{"aws_secret_key_assign", "aws_secret_access_key := " + canaryPass04},
		{"secret_hash_rocket", "secret => " + canaryPass04},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := secrets.RedactText(tc.input)
			assertNoCanaries(t, out, tc.name)
			if !strings.Contains(out, "[REDACTED") {
				t.Errorf("[%s] Expected redaction placeholder in output, got: %s", tc.name, out)
			}
		})
	}
}

func TestRedactText_BearerTokens(t *testing.T) {
	input := "Authorization: Bearer " + canaryToken02
	out := secrets.RedactText(input)
	assertNoCanaries(t, out, "Bearer token")
	if !strings.Contains(out, "Bearer [REDACTED]") {
		t.Errorf("Expected 'Bearer [REDACTED]', got: %s", out)
	}
}

func TestRedactText_JWT(t *testing.T) {
	// Realistic 3-segment base64url JWT structure containing canary token in payload
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkZFTElYX1RFU1RfVE9LRU5fQ0FOQVJZXzAyIn0.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
	input := "Found authorization token: " + jwt + " in response"
	out := secrets.RedactText(input)
	assertNoCanaries(t, out, "JWT token")
	if !strings.Contains(out, "[REDACTED_JWT]") {
		t.Errorf("Expected '[REDACTED_JWT]', got: %s", out)
	}
}

func TestRedactText_VendorAPIKeys(t *testing.T) {
	cases := []struct {
		vendor string
		key    string
	}{
		{"Stripe", "sk_live_" + canaryKey03 + "_9876543210"},
		{"GitHub", "ghp_" + canaryKey03 + "_1234567890"},
		{"Slack", "xoxb-123456789012-" + canaryKey03},
		{"OpenAI", "sk-proj-" + canaryKey03 + "_abcdefghij"},
	}

	for _, tc := range cases {
		t.Run(tc.vendor, func(t *testing.T) {
			input := fmt.Sprintf("API key for %s is %s.", tc.vendor, tc.key)
			out := secrets.RedactText(input)
			assertNoCanaries(t, out, tc.vendor+" API key")
			if !strings.Contains(out, "[REDACTED]") {
				t.Errorf("[%s] Expected '[REDACTED]' in output, got: %s", tc.vendor, out)
			}
		})
	}
}

func TestRedactText_AWSAccessKeys(t *testing.T) {
	input := "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=" + canarySecret01
	out := secrets.RedactText(input)
	assertNoCanaries(t, out, "AWS credentials")
	if !strings.Contains(out, "AKIA[REDACTED]") {
		t.Errorf("Expected 'AKIA[REDACTED]', got: %s", out)
	}
	if !strings.Contains(out, "aws_secret_access_key=[REDACTED]") {
		t.Errorf("Expected secret key redacted, got: %s", out)
	}
}

func TestRedactText_PEMPrivateKey_Complete(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0Y3FELIX_TEST_SECRET_CANARY_01\n" +
		"7i8u2F+example+key+material+canary+01234567890\n" +
		"-----END RSA PRIVATE KEY-----"
	input := "Server configuration leaked key:\n" + pem
	out := secrets.RedactText(input)
	assertNoCanaries(t, out, "Complete PEM block")
	if !strings.Contains(out, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("Expected '[REDACTED_PRIVATE_KEY]', got: %s", out)
	}
}

func TestRedactText_PEMPrivateKey_Truncated(t *testing.T) {
	pemTruncated := "-----BEGIN EC PRIVATE KEY-----\n" +
		"MHQCAQEEIFELIX_TEST_SECRET_CANARY_01"
	out := secrets.RedactText(pemTruncated)
	assertNoCanaries(t, out, "Truncated PEM block")
	if !strings.Contains(out, "[REDACTED_PRIVATE_KEY]") {
		t.Errorf("Expected truncated PEM to be replaced by '[REDACTED_PRIVATE_KEY]', got: %s", out)
	}
}

func TestRedactText_HarmlessProsePreserved(t *testing.T) {
	prose := []string{
		"Please reset your password on the account settings page.",
		"The authentication token architecture uses industry-standard OAuth2.",
		"The primary key column in the database table is id.",
		"The secret sauce of our scanning algorithm is deterministic analysis.",
		"Keyboard shortcuts and category filters are available in the UI.",
	}

	for _, p := range prose {
		out := secrets.RedactText(p)
		if out != p {
			t.Errorf("Harmless prose was improperly mutated:\nOriginal: %s\nResult:   %s", p, out)
		}
	}
}

func TestRedactText_EdgeCasesAndPerformance(t *testing.T) {
	// 1. Empty string
	if out := secrets.RedactText(""); out != "" {
		t.Errorf("Expected empty string, got %q", out)
	}

	// 2. Whitespace only
	ws := "   \t\r\n  "
	if out := secrets.RedactText(ws); out != ws {
		t.Errorf("Expected whitespace preserved, got %q", out)
	}

	// 3. Extremely large input (100 KB payload) with embedded canaries
	var sb strings.Builder
	for i := 0; i < 1000; i++ {
		sb.WriteString("Line of standard text containing normal words and data ")
		if i == 500 {
			sb.WriteString("api_key=" + canaryKey03 + " ")
		}
		if i == 750 {
			sb.WriteString("password: " + canaryPass04 + " ")
		}
	}
	largeInput := sb.String()

	start := time.Now()
	out := secrets.RedactText(largeInput)
	duration := time.Since(start)

	if duration > 2*time.Second {
		t.Errorf("Redaction took too long (%v) for 100KB input", duration)
	}
	assertNoCanaries(t, out, "Large 100KB payload")
}

// =============================================================================
// 7.2 HTTP Header Tests
// =============================================================================

func TestSanitizeHeaders_CredentialHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+canaryToken02)
	h.Set("Proxy-Authorization", "Basic "+canaryAuth05)
	h.Set("Cookie", "sessionid="+canarySecret01)
	h.Set("Set-Cookie", "sid="+canarySecret01+"; Path=/; Secure; HttpOnly")
	h.Set("X-API-Key", canaryKey03)
	h.Set("api-key", canaryKey03)
	h.Set("X-Auth-Token", canaryAuth05)
	h.Set("X-Session-ID", canarySecret01)

	// Harmless headers
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("User-Agent", "Felix/2.0")
	h.Set("Accept", "application/json")
	h.Set("Host", "api.example.com")
	h.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	sanitized := secrets.SanitizeHeaders(h)

	// Verify all credential headers redacted
	credentialKeys := []string{
		"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
		"X-API-Key", "api-key", "X-Auth-Token", "X-Session-ID",
	}
	for _, k := range credentialKeys {
		canon := http.CanonicalHeaderKey(k)
		val, exists := sanitized[canon]
		if !exists {
			t.Errorf("Header %q (%s) was dropped from output map", k, canon)
		}
		if val != "[REDACTED]" {
			t.Errorf("Header %q value was not redacted: got %q", canon, val)
		}
	}

	// Verify harmless headers preserved intact
	if sanitized["Content-Type"] != "application/json; charset=utf-8" {
		t.Errorf("Content-Type was modified: %s", sanitized["Content-Type"])
	}
	if sanitized["Sec-Websocket-Key"] != "dGhlIHNhbXBsZSBub25jZQ==" {
		t.Errorf("Sec-Websocket-Key was modified: %s", sanitized["Sec-Websocket-Key"])
	}

	// Assert no leaks in entire map
	for k, v := range sanitized {
		assertNoCanaries(t, v, "Header "+k)
	}
}

func TestRedactCookieHeader_AttributesPreserved(t *testing.T) {
	rawCookie := "session_token=" + canarySecret01 + "; Path=/api; Domain=example.com; Secure; HttpOnly; SameSite=Strict"
	redacted := secrets.RedactCookieHeader(rawCookie)

	assertNoCanaries(t, redacted, "Cookie header")
	if !strings.HasPrefix(redacted, "session_token=[REDACTED]") {
		t.Errorf("Expected cookie value to be redacted, got: %s", redacted)
	}
	if !strings.Contains(redacted, "Secure") || !strings.Contains(redacted, "HttpOnly") ||
		!strings.Contains(redacted, "SameSite=Strict") || !strings.Contains(redacted, "Path=/api") {
		t.Errorf("Security attributes were improperly removed: %s", redacted)
	}
}

// =============================================================================
// 7.3 URL and Connection String Tests
// =============================================================================

func TestSanitizeURL_EmbeddedCredentials(t *testing.T) {
	rawURL := "http://admin:" + canaryPass04 + "@example.com:8080/admin/dashboard"
	sanitized := secrets.SanitizeURL(rawURL)

	assertNoCanaries(t, sanitized, "Embedded URL credentials")
	if !strings.Contains(sanitized, "admin:[REDACTED]@example.com:8080/admin/dashboard") {
		t.Errorf("Expected admin:[REDACTED]@..., got: %s", sanitized)
	}
}

func TestSanitizeURL_ConnectionStrings(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected string
	}{
		{
			name:     "PostgreSQL",
			raw:      "postgres://felix_user:" + canaryPass04 + "@db.internal.net:5432/audit_db?sslmode=require",
			expected: "postgres://felix_user:[REDACTED]@db.internal.net:5432/audit_db?sslmode=require",
		},
		{
			name:     "MySQL",
			raw:      "mysql://root:" + canaryPass04 + "@127.0.0.1:3306/production",
			expected: "mysql://root:[REDACTED]@127.0.0.1:3306/production",
		},
		{
			name:     "Redis",
			raw:      "redis://:" + canaryPass04 + "@cache.internal:6379/0",
			expected: "redis://:[REDACTED]@cache.internal:6379/0",
		},
		{
			name:     "MongoDB",
			raw:      "mongodb://appuser:" + canaryPass04 + "@mongo.internal:27017/analytics",
			expected: "mongodb://appuser:[REDACTED]@mongo.internal:27017/analytics",
		},
		{
			name:     "JDBC PostgreSQL",
			raw:      "jdbc:postgresql://dbuser:" + canaryPass04 + "@dbhost:5432/appdb",
			expected: "jdbc:postgresql://dbuser:[REDACTED]@dbhost:5432/appdb",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := secrets.SanitizeURL(tc.raw)
			assertNoCanaries(t, out, tc.name)
			if out != tc.expected {
				t.Errorf("[%s] Expected %q, got %q", tc.name, tc.expected, out)
			}
		})
	}
}

func TestSanitizeURL_SensitiveAndNonSensitiveParams(t *testing.T) {
	// Sensitive query parameters
	rawSensitive := "https://example.com/api?token=" + canaryToken02 + "&secret=" + canarySecret01 + "&key=" + canaryKey03 + "&auth=" + canaryAuth05 + "&code=" + canaryPass04
	outSensitive := secrets.SanitizeURL(rawSensitive)
	assertNoCanaries(t, outSensitive, "Sensitive query parameters")
	if !strings.Contains(outSensitive, "token=[REDACTED]") || !strings.Contains(outSensitive, "secret=[REDACTED]") {
		t.Errorf("Expected query secrets to be redacted, got: %s", outSensitive)
	}

	// Non-sensitive query parameters preserved
	rawSafe := "https://example.com/search?q=test&page=2&limit=50&category=books"
	outSafe := secrets.SanitizeURL(rawSafe)
	if outSafe != rawSafe {
		t.Errorf("Safe URL query parameters were modified: expected %s, got %s", rawSafe, outSafe)
	}

	// Combined sensitive and non-sensitive
	rawMixed := "https://example.com/api/items?category=books&limit=10&api_key=" + canaryKey03 + "&page=1"
	outMixed := secrets.SanitizeURL(rawMixed)
	assertNoCanaries(t, outMixed, "Mixed URL parameters")
	if !strings.Contains(outMixed, "category=books") || !strings.Contains(outMixed, "limit=10") || !strings.Contains(outMixed, "page=1") {
		t.Errorf("Non-sensitive query params were lost in mixed URL: %s", outMixed)
	}
	if !strings.Contains(outMixed, "api_key=[REDACTED]") {
		t.Errorf("api_key was not redacted in mixed URL: %s", outMixed)
	}
}

// =============================================================================
// 7.4 Structured JSON and Nested Object Tests
// =============================================================================

func TestRedactJSON_StructuredData(t *testing.T) {
	inputJSON := `{
		"service": "billing",
		"password": "` + canaryPass04 + `",
		"config": {
			"db": {
				"database_url": "postgres://user:` + canaryPass04 + `@host/db",
				"secret_key": "` + canarySecret01 + `"
			},
			"apiTokens": [
				"` + canaryToken02 + `",
				"harmless_identifier_123"
			]
		},
		"metadata": {
			"Password": "` + canaryPass04 + `",
			"access_token": "` + canaryToken02 + `",
			"ACCESS-TOKEN": "` + canaryToken02 + `"
		}
	}`

	redactedBytes := secrets.RedactJSON([]byte(inputJSON))
	redactedStr := string(redactedBytes)

	assertNoCanaries(t, redactedStr, "Structured JSON")

	var parsed map[string]any
	if err := json.Unmarshal(redactedBytes, &parsed); err != nil {
		t.Fatalf("Redacted output is not valid JSON: %v", err)
	}

	if parsed["password"] != "[REDACTED]" {
		t.Errorf("Top-level password was not redacted: %v", parsed["password"])
	}
}

func TestRedactJSON_MalformedFallback(t *testing.T) {
	malformed := `{ malformed json: password="` + canaryPass04 + `" and token="` + canaryToken02 + `"`
	redactedBytes := secrets.RedactJSON([]byte(malformed))
	redactedStr := string(redactedBytes)

	assertNoCanaries(t, redactedStr, "Malformed JSON fallback")
	if !strings.Contains(redactedStr, "[REDACTED]") {
		t.Errorf("Expected fallback redaction on malformed JSON, got: %s", redactedStr)
	}
}

func TestRedactJSON_MalformedQuotedKeys_FailClosed(t *testing.T) {
	malformed := `{"password": "` + canaryPass04 + `", "api_key": "` + canaryKey03 + `", broken`
	redactedBytes := secrets.RedactJSON([]byte(malformed))
	redactedStr := string(redactedBytes)

	assertNoCanaries(t, redactedStr, "Malformed JSON with quoted keys")
}

func TestRedactJSON_Malformed_TruncatedValueAtEOF(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "TruncatedQuotedTokenAtEOF",
			input: `{"token": "` + canaryToken02,
		},
		{
			name:  "TruncatedQuotedPasswordAtEOF",
			input: `{"service": "auth", "password": "` + canaryPass04,
		},
		{
			name:  "TruncatedQuotedSecretAtEOF",
			input: `{"client_secret": "` + canarySecret01,
		},
		{
			name:  "TruncatedSingleQuotedAtEOF",
			input: `{'api_key': '` + canaryKey03,
		},
		{
			name:  "TruncatedColonSpaceAtEOF",
			input: `{"auth_token":   "` + canaryToken02,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := secrets.RedactJSON([]byte(tc.input))
			assertNoCanaries(t, string(out), tc.name)
		})
	}
}

func TestRedactJSON_Malformed_UnquotedAndCorrupted(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{
			name:  "UnquotedCanaryInMalformedObject",
			input: `{"password": ` + canaryPass04 + `, "admin": true, broken`,
		},
		{
			name:  "ControlCharsAndCorruptedBytes",
			input: `{"token": "\x00\xff` + canaryToken02 + `\x00", "broken`,
		},
		{
			name:  "UnclosedBraceWithNewline",
			input: "{\n  \"client_secret\": \"" + canarySecret01 + "\"\n  broken",
		},
		{
			name:  "MalformedArrayWithSensitiveKey",
			input: `[{"api_key": "` + canaryKey03 + `", "status": `,
		},
		{
			name:  "NestedMalformedStructure",
			input: `{"data": {"nested": {"access_token": "` + canaryToken02 + `", broken`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := secrets.RedactJSON([]byte(tc.input))
			assertNoCanaries(t, string(out), tc.name)
		})
	}
}

func TestRedactBody_Malformed_LengthBounded(t *testing.T) {
	// Verify that length bounding on malformed JSON truncates safely without leaking secrets or corrupting UTF-8
	malformedLong := `{"password": "` + canaryPass04 + `", "details": "` + strings.Repeat("text_data_", 20) + `" broken`
	bounded := secrets.RedactBody([]byte(malformedLong), 40)

	assertNoCanaries(t, bounded, "RedactBody malformed length bounded")
	if len(bounded) > 60 { // 40 + len(" ... [TRUNCATED]")
		t.Errorf("bounded output exceeded expected length: len=%d, text=%s", len(bounded), bounded)
	}
	if !strings.Contains(bounded, "[TRUNCATED]") {
		t.Errorf("expected [TRUNCATED] marker, got: %s", bounded)
	}
}

// =============================================================================
// 7.5 Production Integration Tests
// =============================================================================

func TestIntegration_SanitizeFinding(t *testing.T) {
	rawFinding := report.Finding{
		ID:          "find-001",
		Title:       "Information Disclosure: Leak of token=" + canaryToken02,
		Category:    "info-disclosure",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "http://admin:" + canaryPass04 + "@internal.example.com",
		Endpoint:    "https://api.example.com/v1/auth?token=" + canaryToken02,
		Method:      "GET",
		Description: "The server response contains password: " + canaryPass04 + " in error output.",
		Evidence:    "Response headers included Set-Cookie: session_id=" + canarySecret01,
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Leaked credentials in response body: secret_key=" + canarySecret01,
			Location:    "https://api.example.com/v1/login?sig=" + canaryKey03,
			Details: map[string]string{
				"Authorization": "Bearer " + canaryToken02,
				"error_detail":  "database error with password=" + canaryPass04,
				"debug_info":    "safe debug context information",
			},
		},
		Verification: report.VerificationRecord{
			Status:          report.VerificationVerified,
			Result:          "Verified access using token: " + canaryToken02,
			Rationale:       "Endpoint returned 200 with secret=" + canarySecret01,
			SafeCurlCommand: "curl -H 'Authorization: Bearer " + canaryToken02 + "' https://api.example.com/data",
			ReproductionSteps: []string{
				"Step 1: Authenticate with password=" + canaryPass04,
				"Step 2: Access endpoint with token=" + canaryToken02,
			},
		},
		Remediation: "Ensure password=" + canaryPass04 + " is never returned in HTTP responses.",
	}

	sanitizedFinding := report.SanitizeFinding(rawFinding)

	// Convert finding to JSON to assert no canary leaks in any field
	findingBytes, err := json.Marshal(sanitizedFinding)
	if err != nil {
		t.Fatalf("Failed to marshal sanitized finding: %v", err)
	}
	assertNoCanaries(t, string(findingBytes), "report.SanitizeFinding")

	// Verify assessment.ToAssessmentFinding also sanitizes all fields
	asmFinding := assessment.ToAssessmentFinding("asm-1", "exec-1", "tgt-1", rawFinding)
	asmBytes, err := json.Marshal(asmFinding)
	if err != nil {
		t.Fatalf("Failed to marshal assessment finding: %v", err)
	}
	assertNoCanaries(t, string(asmBytes), "assessment.ToAssessmentFinding")
}

func TestIntegration_SanitizeReport(t *testing.T) {
	rep := report.Report{
		Findings: []report.Finding{
			{
				ID:          "f-1",
				Title:       "API Key Exposure: api_key=" + canaryKey03,
				Description: "API key api_key=" + canaryKey03 + " exposed in scripts",
				Evidence:    "sk_live_" + canaryKey03 + "_9876543210",
			},
		},
		TopPriorities: []report.Finding{
			{
				ID:          "p-1",
				Title:       "Database Credential Leak: password=" + canaryPass04,
				Description: "postgres://user:" + canaryPass04 + "@db.net/app",
			},
		},
		SecurityStories: []report.SecurityStory{
			{
				ID:          "story-1",
				Title:       "Account Takeover via token=" + canaryToken02,
				Summary:     "Token token=" + canaryToken02 + " allowed lateral movement",
				Description: "Password password=" + canaryPass04 + " was reused across environments",
				Evidence:    []string{"Bearer " + canaryToken02},
			},
		},
		AttackPaths: []report.AttackPathSummary{
			{
				ID:            "path-1",
				Title:         "Attack Path with Secret secret=" + canarySecret01,
				RiskRationale: "Leaked secret secret=" + canarySecret01 + " enabled admin access",
				Transitions:   []string{"Step 1: Exploit token=" + canaryToken02},
			},
		},
	}

	sanitizedRep := report.SanitizeReport(rep)
	reportBytes, err := json.Marshal(sanitizedRep)
	if err != nil {
		t.Fatalf("Failed to marshal sanitized report: %v", err)
	}
	assertNoCanaries(t, string(reportBytes), "report.SanitizeReport")
}

func TestIntegration_CommercialReport(t *testing.T) {
	rep := report.Report{
		Findings: []report.Finding{
			{
				ID:          "cf-1",
				Title:       "Exposed Secret in JS: secret=" + canarySecret01,
				Category:    "secrets",
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceHigh,
				Endpoint:    "https://example.com/auth?token=" + canaryToken02,
				Description: "Client secret: " + canarySecret01 + " found in bundle",
				Evidence:    "var secret = \"" + canarySecret01 + "\";",
				Verification: report.VerificationRecord{
					Status:          report.VerificationVerified,
					Result:          "Secret verified active: secret=" + canarySecret01,
					SafeCurlCommand: "curl -H 'X-Key: " + canaryKey03 + "' https://example.com",
				},
			},
		},
	}

	cr := report.BuildCommercialReport(rep)
	crBytes, err := json.Marshal(cr)
	if err != nil {
		t.Fatalf("Failed to marshal CommercialReport: %v", err)
	}
	assertNoCanaries(t, string(crBytes), "BuildCommercialReport")
}

func TestIntegration_SQLitePersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_audit.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create SQLiteStore: %v", err)
	}
	defer store.Close()

	clientID := "client-test-01"
	client := &assessment.Client{
		ID:        clientID,
		Name:      "Test Client",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asmID := "asm-test-01"
	execID := "exec-test-01"
	targetID := "tgt-test-01"

	asm := &assessment.Assessment{
		ID:             asmID,
		Ref:            "ASM-TEST",
		Name:           "Test Audit",
		ClientID:       clientID,
		AssessmentType: "BLACK_BOX_WEB",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	target := &assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	rawFinding := report.Finding{
		ID:          "persist-001",
		Title:       "Credential exposure: password=" + canaryPass04,
		Category:    "secrets",
		Severity:    report.SeverityCritical,
		Confidence:  report.ConfidenceHigh,
		Endpoint:    "https://example.com/api?token=" + canaryToken02,
		Description: "Found secret_key=" + canarySecret01 + " in error stream",
		Evidence:    "Bearer " + canaryToken02,
		EvidenceDetails: report.EvidenceDetails{
			Observation: "Observation with password=" + canaryPass04,
			Details: map[string]string{
				"api_key": canaryKey03,
			},
		},
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "Result with auth=" + canaryAuth05,
		},
	}

	// Create AssessmentFinding which must sanitize at construction
	asmFinding := assessment.ToAssessmentFinding(asmID, execID, targetID, rawFinding)

	err = store.SaveFindings([]assessment.AssessmentFinding{asmFinding})
	if err != nil {
		t.Fatalf("Failed to save findings to SQLite: %v", err)
	}

	retrieved, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("Failed to retrieve findings from SQLite: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 finding in SQLite, found %d", len(retrieved))
	}

	retrievedBytes, err := json.Marshal(retrieved[0])
	if err != nil {
		t.Fatalf("Failed to marshal retrieved finding: %v", err)
	}
	assertNoCanaries(t, string(retrievedBytes), "SQLite persisted finding")
}

// =============================================================================
// 7.6 Production Output Coverage Tests (JSON, HTML, SARIF, Commercial, CLI/API, Ingestion)
// =============================================================================

func TestProductionOutput_HTMLReport_ZeroLeaks(t *testing.T) {
	rep := report.Report{
		Target: "https://admin:" + canaryPass04 + "@corp.internal",
		Findings: []report.Finding{
			{
				ID:          "find-html-01",
				Title:       "Token leak in title: token=" + canaryToken02,
				Description: "Password leaked: " + canaryPass04,
				Evidence:    "api_key=" + canaryKey03,
				Target:      "https://admin:" + canaryPass04 + "@corp.internal",
				Endpoint:    "https://api.corp.internal/v1?secret=" + canarySecret01,
				EvidenceDetails: report.EvidenceDetails{
					Observation: "Observation with " + canaryAuth05,
				},
			},
		},
		SecurityStories: []report.SecurityStory{
			{
				ID:       "story-html-01",
				Title:    "Story with secret=" + canarySecret01,
				Summary:  "Summary with token=" + canaryToken02,
				Evidence: []string{"Evidence with password=" + canaryPass04},
			},
		},
		AttackPaths: []report.AttackPathSummary{
			{
				ID:            "path-html-01",
				Title:         "Path with api_key=" + canaryKey03,
				RiskRationale: "Rationale with auth=" + canaryAuth05,
			},
		},
	}

	htmlStr, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	assertNoCanaries(t, htmlStr, "GenerateHTML output")

	tmpFile := filepath.Join(t.TempDir(), "report.html")
	if err := report.WriteHTML(rep, tmpFile); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	fileBytes, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read HTML report file: %v", err)
	}
	assertNoCanaries(t, string(fileBytes), "WriteHTML file output")
}

func TestProductionOutput_SARIFReport_ZeroLeaks(t *testing.T) {
	rep := report.Report{
		Target: "https://admin:" + canaryPass04 + "@corp.internal",
		Findings: []report.Finding{
			{
				ID:          "find-sarif-01",
				Title:       "Leaked token: token=" + canaryToken02,
				Description: "Leaked password: password=" + canaryPass04,
				Evidence:    "api_key=" + canaryKey03,
				Target:      "https://admin:" + canaryPass04 + "@corp.internal",
				Endpoint:    "https://api.corp.internal/v1?secret=" + canarySecret01,
				Verification: report.VerificationRecord{
					Status:          report.VerificationVerified,
					Result:          "Verified auth=" + canaryAuth05,
					SafeCurlCommand: "curl -H 'Authorization: Bearer " + canaryToken02 + "' https://example.com",
				},
			},
		},
	}

	sarifLog := report.BuildSARIFLog(rep)
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("Failed to marshal SARIF: %v", err)
	}
	assertNoCanaries(t, string(sarifBytes), "BuildSARIFLog output")

	tmpFile := filepath.Join(t.TempDir(), "audit.sarif")
	if err := report.WriteSARIF(rep, tmpFile); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	fileBytes, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read SARIF file: %v", err)
	}
	assertNoCanaries(t, string(fileBytes), "WriteSARIF file output")
}

func TestProductionOutput_CommercialJSONAndHTML_ZeroLeaks(t *testing.T) {
	rep := report.Report{
		Target: "https://admin:" + canaryPass04 + "@corp.internal",
		Findings: []report.Finding{
			{
				ID:          "find-comm-01",
				Title:       "Commercial finding: token=" + canaryToken02,
				Description: "Details with password=" + canaryPass04,
				Evidence:    "client_secret=" + canarySecret01,
				Endpoint:    "https://api.corp.internal/auth?api_key=" + canaryKey03,
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
					Result: "Verified with auth=" + canaryAuth05,
				},
			},
		},
	}

	cr := report.BuildCommercialReport(rep)

	jsonBytes, err := report.GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	assertNoCanaries(t, string(jsonBytes), "GenerateCommercialJSON output")

	htmlStr, err := report.GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	assertNoCanaries(t, htmlStr, "GenerateCommercialHTML output")
}

func TestProductionOutput_ParseReport_IngestionSanitization(t *testing.T) {
	rawJSON := []byte(`{
		"target": "https://admin:` + canaryPass04 + `@example.com",
		"findings": [
			{
				"id": "raw-01",
				"title": "Unsanitized title: token=` + canaryToken02 + `",
				"description": "Unsanitized desc: password=` + canaryPass04 + `",
				"evidence_summary": "api_key=` + canaryKey03 + `",
				"evidence": {
					"observation": "secret=` + canarySecret01 + `"
				},
				"endpoint": "https://example.com/api?secret=` + canarySecret01 + `"
			}
		]
	}`)

	parsed, err := report.ParseReport(rawJSON)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	marshaled, err := json.Marshal(parsed)
	if err != nil {
		t.Fatalf("Failed to marshal parsed report: %v", err)
	}
	assertNoCanaries(t, string(marshaled), "ParseReport ingestion sanitization")
}

func TestProductionOutput_VerificationSafeCurl_ZeroLeaks(t *testing.T) {
	rawFinding := report.Finding{
		ID:       "find-curl-01",
		Endpoint: "https://api.example.com/login?token=" + canaryToken02,
		Method:   "POST",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"Authorization": "Bearer " + canaryToken02,
				"X-Custom-Auth": canaryAuth05,
			},
		},
	}

	repro := verification.BuildReproductionContext(
		rawFinding,
		"https://admin:"+canaryPass04+"@api.example.com",
		"policy-01",
		report.VerificationVerified,
		"expected behavior",
		"observed with secret="+canarySecret01,
		[]string{"precondition with api_key=" + canaryKey03},
		nil,
	)

	assertNoCanaries(t, repro.SafeCurlCommand, "BuildReproductionContext SafeCurlCommand")
	for _, step := range repro.ReproductionSteps {
		assertNoCanaries(t, step, "BuildReproductionContext ReproductionSteps")
	}
}

// =============================================================================
// 7.7 Idempotence & Repeatability Tests
// =============================================================================

func TestIdempotence(t *testing.T) {
	sampleText := "Encountered password=" + canaryPass04 + " and token: Bearer " + canaryToken02
	pass1 := secrets.RedactText(sampleText)
	pass2 := secrets.RedactText(pass1)
	pass3 := secrets.RedactText(pass2)

	if pass1 != pass2 {
		t.Errorf("RedactText is not idempotent:\nPass 1: %s\nPass 2: %s", pass1, pass2)
	}
	if pass2 != pass3 {
		t.Errorf("RedactText is not repeatable across multiple passes")
	}

	// Verify that already redacted tokens are not mangled
	preRedacted := "Already redacted: [REDACTED], [REDACTED_JWT], [REDACTED_PRIVATE_KEY], AKIA[REDACTED]"
	outPre := secrets.RedactText(preRedacted)
	if outPre != preRedacted {
		t.Errorf("Pre-redacted tokens were mangled:\nBefore: %s\nAfter:  %s", preRedacted, outPre)
	}

	// URL idempotence
	sampleURL := "https://user:" + canaryPass04 + "@example.com/api?token=" + canaryToken02 + "&page=1"
	urlPass1 := secrets.SanitizeURL(sampleURL)
	urlPass2 := secrets.SanitizeURL(urlPass1)
	if urlPass1 != urlPass2 {
		t.Errorf("SanitizeURL is not idempotent:\nPass 1: %s\nPass 2: %s", urlPass1, urlPass2)
	}

	// Cookie idempotence
	sampleCookie := "session_id=" + canarySecret01 + "; Path=/; Secure; HttpOnly"
	cookiePass1 := secrets.RedactCookieHeader(sampleCookie)
	cookiePass2 := secrets.RedactCookieHeader(cookiePass1)
	if cookiePass1 != cookiePass2 {
		t.Errorf("RedactCookieHeader is not idempotent:\nPass 1: %s\nPass 2: %s", cookiePass1, cookiePass2)
	}
}

// =============================================================================
// 7.8 Safe Error Tests
// =============================================================================

func TestSanitizeError(t *testing.T) {
	// 1. Strips sensitive tokens and connection strings
	rawErr := errors.New("failed connection to postgres://appuser:" + canaryPass04 + "@db.internal:5432/app with token=" + canaryToken02)
	sanitizedMsg := secrets.SanitizeError(rawErr)

	assertNoCanaries(t, sanitizedMsg, "SanitizeError")
	if !strings.Contains(sanitizedMsg, "[REDACTED") {
		t.Errorf("Expected redacted credentials in error message, got: %s", sanitizedMsg)
	}

	// 2. Bounds error length
	longErr := errors.New(strings.Repeat("very long error message context ", 20))
	boundedMsg := secrets.SanitizeError(longErr)
	if len(boundedMsg) > 256 {
		t.Errorf("SanitizeError exceeded maximum bound of 256 chars (len=%d): %s", len(boundedMsg), boundedMsg)
	}
	if !strings.HasSuffix(boundedMsg, "...") {
		t.Errorf("Expected truncated error message to end with '...', got: %s", boundedMsg)
	}

	// 3. Nil error returns empty string
	if secrets.SanitizeError(nil) != "" {
		t.Errorf("Expected empty string for nil error, got: %s", secrets.SanitizeError(nil))
	}
}
