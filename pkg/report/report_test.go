package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/secrets"
)

// 1. Finding normalization
func TestFindingNormalization(t *testing.T) {
	raw := Finding{
		ID:          "RAW-1",
		Title:       "Test Finding",
		Category:    "cors_origin_reflection",
		Severity:    "high",
		Confidence:  "high",
		Target:      "https://example.com:443/",
		Endpoint:    "https://example.com:443/api/v1/users",
		Method:      "get",
		Description: "Raw description",
		Source:      "API",
	}

	norm := NormalizeFinding(raw)
	if norm.Target != "https://example.com" {
		t.Errorf("expected normalized target 'https://example.com', got %q", norm.Target)
	}
	if norm.Endpoint != "https://example.com/api/v1/users" {
		t.Errorf("expected normalized endpoint without port :443, got %q", norm.Endpoint)
	}
	if norm.Method != "GET" {
		t.Errorf("expected uppercase GET method, got %q", norm.Method)
	}
	if norm.Category != "cors-origin-reflection" {
		t.Errorf("expected kebab-case category, got %q", norm.Category)
	}
	if norm.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity, got %q", norm.Severity)
	}
	if norm.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %q", norm.Confidence)
	}
	if norm.Remediation == "" {
		t.Errorf("expected non-empty remediation guidance")
	}
}

// 2. URL normalization
func TestURLNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://EXAMPLE.COM:443/", "https://example.com"},
		{"http://EXAMPLE.COM:80/", "http://example.com"},
		{"https://example.com:8443/api", "https://example.com:8443/api"},
		{"https://example.com/api/", "https://example.com/api/"},
		{"https://example.com/api", "https://example.com/api"},
		{"https://example.com/api/v1?token=123", "https://example.com/api/v1?token=123"},
	}

	for _, tt := range tests {
		got := NormalizeURL(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeURL(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

// 3. Severity normalization
func TestSeverityNormalization(t *testing.T) {
	if NormalizeSeverity("crit") != SeverityCritical {
		t.Errorf("crit did not normalize to CRITICAL")
	}
	if NormalizeSeverity("moderate") != SeverityMedium {
		t.Errorf("moderate did not normalize to MEDIUM")
	}

	// Explainable mapping rules
	if MapSeverity("supabase-anon-key", "HIGH") != SeverityInfo {
		t.Errorf("supabase-anon-key should remain INFO regardless of raw tag")
	}
	if MapSeverity("missing-permissions-policy", "HIGH") != SeverityInfo {
		t.Errorf("missing-permissions-policy should be normalized to INFO")
	}
	if MapSeverity("supabase-service-key", "LOW") != SeverityCritical {
		t.Errorf("supabase-service-key must be CRITICAL")
	}
}

// 4. Confidence normalization
func TestConfidenceNormalization(t *testing.T) {
	if NormalizeConfidence("High") != ConfidenceHigh {
		t.Errorf("High did not map to HIGH")
	}
	if NormalizeConfidence("med") != ConfidenceMedium {
		t.Errorf("med did not map to MEDIUM")
	}
	if NormalizeConfidence("LOW") != ConfidenceLow {
		t.Errorf("LOW did not map to LOW")
	}
}

// 5. Deduplication
func TestDeduplication(t *testing.T) {
	f1 := Finding{
		Target:      "https://example.com",
		Category:    "missing-csp",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Evidence:    "Observation 1",
		Fingerprint: "fp-csp-1",
	}
	f2 := Finding{
		Target:      "https://example.com",
		Category:    "missing-csp",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Evidence:    "Observation 2",
		Fingerprint: "fp-csp-1",
	}

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(deduped))
	}
	if !strings.Contains(deduped[0].Evidence, "Observation 1") || !strings.Contains(deduped[0].Evidence, "Observation 2") {
		t.Errorf("merged evidence should contain both observations: %s", deduped[0].Evidence)
	}
}

// 6. Duplicate secret correlation
func TestDuplicateSecretCorrelation(t *testing.T) {
	sec1 := secrets.SecretFinding{
		Type:        secrets.SecretSupabaseServiceKey,
		Title:       "Supabase service_role Secret Key",
		Value:       "eyTestSecretToken",
		Redacted:    "eyTest********************.[REDACTED_SIG]",
		FileOrigin:  "https://example.com/app.js",
		LineNumber:  42,
		Severity:    secrets.SeverityCritical,
		Confidence:  secrets.ConfidenceHigh,
		Fingerprint: "sha-sb-service-1",
	}
	sec2 := secrets.SecretFinding{
		Type:        secrets.SecretSupabaseServiceKey,
		Title:       "Supabase service_role Secret Key",
		Value:       "eyTestSecretToken",
		Redacted:    "eyTest********************.[REDACTED_SIG]",
		FileOrigin:  "https://example.com/vendor.js",
		LineNumber:  108,
		Severity:    secrets.SeverityCritical,
		Confidence:  secrets.ConfidenceHigh,
		Fingerprint: "sha-sb-service-1",
	}

	f1 := FromSecretFinding("https://example.com", sec1)
	f2 := FromSecretFinding("https://example.com", sec2)

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected single deduplicated secret finding, got %d", len(deduped))
	}
	if !strings.Contains(deduped[0].Evidence, "app.js") || !strings.Contains(deduped[0].Evidence, "vendor.js") {
		t.Errorf("merged evidence missing references: %s", deduped[0].Evidence)
	}
}

// 7. Supabase credential + endpoint correlation
func TestSupabaseCredentialEndpointCorrelation(t *testing.T) {
	secFinding := Finding{
		ID:          "SEC-SB-1",
		Title:       "Supabase service_role Secret Key",
		Category:    "supabase-service-key",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/bundle.js",
		Method:      "GET",
		Source:      SourceSecrets,
		Fingerprint: "fp-sb-key",
	}
	cloudFinding := Finding{
		ID:          "CLD-SB-1",
		Title:       "Supabase Project Discovered",
		Category:    "supabase-project",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://xyz.supabase.co",
		Method:      "GET",
		Source:      SourceCloud,
		Fingerprint: "fp-sb-ep",
	}

	_, stories := Correlate("https://example.com", []Finding{secFinding, cloudFinding})
	if len(stories) == 0 {
		t.Fatalf("expected at least 1 correlated security story")
	}

	foundStory := false
	for _, s := range stories {
		if strings.Contains(s.Title, "Supabase") && s.Severity == SeverityCritical {
			foundStory = true
			if !strings.Contains(s.Description, "xyz.supabase.co") {
				t.Errorf("story description did not reference matching endpoint: %s", s.Description)
			}
		}
	}
	if !foundStory {
		t.Errorf("expected Supabase correlation story")
	}
}

// 8. Firebase endpoint correlation
func TestFirebaseEndpointCorrelation(t *testing.T) {
	fbFinding := Finding{
		ID:          "CLD-FB-1",
		Title:       "Public Firebase Realtime Database without Authentication",
		Category:    "firebase-open-database",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://app-db.firebaseio.com/.json",
		Method:      "GET",
		Source:      SourceCloud,
		Fingerprint: "fp-fb-open",
	}

	_, stories := Correlate("https://example.com", []Finding{fbFinding})
	if len(stories) == 0 {
		t.Fatalf("expected Firebase security story")
	}
	if !strings.Contains(stories[0].Title, "Firebase") {
		t.Errorf("story title should mention Firebase: %s", stories[0].Title)
	}
}

// 9. GraphQL endpoint + introspection correlation
func TestGraphQLIntrospectionCorrelation(t *testing.T) {
	gqlFinding := Finding{
		ID:          "API-GQL-1",
		Title:       "GraphQL Schema Introspection Enabled",
		Category:    "graphql-introspection",
		Severity:    SeverityMedium,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/graphql",
		Method:      "POST",
		Evidence:    "Introspection enabled: discovered 45 schema types",
		Source:      SourceAPI,
		Fingerprint: "fp-gql-1",
	}

	_, stories := Correlate("https://example.com", []Finding{gqlFinding})
	if len(stories) == 0 {
		t.Fatalf("expected GraphQL introspection story")
	}
	if !strings.Contains(stories[0].Title, "GraphQL") {
		t.Errorf("expected GraphQL story, got: %s", stories[0].Title)
	}
}

// 10. .env + secret correlation
func TestEnvSecretCorrelation(t *testing.T) {
	envFinding := Finding{
		ID:          "API-ENV-1",
		Title:       "Public exposure of sensitive /.env configuration file",
		Category:    "env-exposure",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Source:      SourceAPI,
		Fingerprint: "fp-env-1",
	}
	secFinding := Finding{
		ID:          "SEC-AWS-1",
		Title:       "AWS Access Key ID",
		Category:    "aws-access-key",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Source:      SourceSecrets,
		Fingerprint: "fp-sec-1",
	}

	_, stories := Correlate("https://example.com", []Finding{envFinding, secFinding})
	if len(stories) == 0 {
		t.Fatalf("expected .env + secret correlation story")
	}
	if stories[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity for .env with secret correlation, got %s", stories[0].Severity)
	}
}

// 11. CORS + API correlation
func TestCORSAPICorrelation(t *testing.T) {
	corsFinding := Finding{
		ID:          "API-CORS-1",
		Title:       "CORS arbitrary origin reflection with credentials",
		Category:    "cors-origin-reflection",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Source:      SourceAPI,
		Fingerprint: "fp-cors-1",
	}
	apiRoute := Finding{
		ID:          "API-ROUTE-1",
		Title:       "Referenced API Route",
		Category:    "api-endpoint",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/api/users",
		Method:      "GET",
		Source:      SourceAPI,
		Fingerprint: "fp-route-1",
	}

	_, stories := Correlate("https://example.com", []Finding{corsFinding, apiRoute})
	if len(stories) == 0 {
		t.Fatalf("expected CORS + API correlation story")
	}
	if !strings.Contains(stories[0].Title, "CORS") {
		t.Errorf("expected CORS story, got: %s", stories[0].Title)
	}
}

// 12. Risk scoring
func TestRiskScoring(t *testing.T) {
	critFinding := Finding{
		Severity:   SeverityCritical,
		Confidence: ConfidenceHigh,
		Category:   "supabase-service-key",
	}
	score, level := CalculateReportRisk([]Finding{critFinding}, nil)
	if score < 80 {
		t.Errorf("CRITICAL verified finding should yield score >= 80, got %d", score)
	}
	if level != "CRITICAL" {
		t.Errorf("expected CRITICAL risk level, got %s", level)
	}
}

// 13. Deterministic scoring
func TestDeterministicScoring(t *testing.T) {
	f1 := Finding{Severity: SeverityHigh, Confidence: ConfidenceHigh, Category: "env-exposure"}
	f2 := Finding{Severity: SeverityMedium, Confidence: ConfidenceHigh, Category: "graphql-introspection"}

	score1, _ := CalculateReportRisk([]Finding{f1, f2}, nil)
	score2, _ := CalculateReportRisk([]Finding{f1, f2}, nil)

	if score1 != score2 {
		t.Errorf("scores not deterministic: %d vs %d", score1, score2)
	}
}

// 14. Remediation generation
func TestRemediationGeneration(t *testing.T) {
	categories := []string{
		"supabase-service-key",
		"aws-access-key",
		"stripe-live-key",
		"firebase-open-database",
		"graphql-introspection",
		"cors-origin-reflection",
		"env-exposure",
		"missing-csp",
	}

	for _, c := range categories {
		rem := RemediationFor(c, "")
		if rem == "" || strings.Contains(rem, "Review the observed endpoint") {
			t.Errorf("expected specific remediation for category %q, got: %q", c, rem)
		}
	}
}

// 15. Prioritization
func TestPrioritization(t *testing.T) {
	fCrit := Finding{Severity: SeverityCritical, Confidence: ConfidenceHigh, Category: "a-crit", Endpoint: "https://example.com/a"}
	fHigh := Finding{Severity: SeverityHigh, Confidence: ConfidenceHigh, Category: "b-high", Endpoint: "https://example.com/b"}
	fLow := Finding{Severity: SeverityLow, Confidence: ConfidenceHigh, Category: "c-low", Endpoint: "https://example.com/c"}
	fInfo := Finding{Severity: SeverityInfo, Confidence: ConfidenceHigh, Category: "d-info", Endpoint: "https://example.com/d"}

	prioritized := Prioritize([]Finding{fLow, fInfo, fCrit, fHigh})
	if prioritized[0].Severity != SeverityCritical {
		t.Errorf("first prioritized item should be CRITICAL, got %s", prioritized[0].Severity)
	}
	if prioritized[1].Severity != SeverityHigh {
		t.Errorf("second prioritized item should be HIGH, got %s", prioritized[1].Severity)
	}
}

// 16. JSON export
func TestJSONExport(t *testing.T) {
	f := Finding{
		ID:          "TEST-1",
		Title:       "Test Finding",
		Category:    "test-cat",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/test",
		Evidence:    "password=SuperSecretPassword123",
	}
	rep := BuildReport("https://example.com", []Finding{f})

	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	if strings.Contains(string(jsonBytes), "SuperSecretPassword123") {
		t.Errorf("JSON report leaked raw password in evidence")
	}

	var parsed Report
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal generated JSON: %v", err)
	}
	if parsed.Target != "https://example.com" {
		t.Errorf("expected target 'https://example.com', got %s", parsed.Target)
	}
}

// 17. HTML export
func TestHTMLExport(t *testing.T) {
	f := Finding{
		ID:          "TEST-HTML",
		Title:       "Test HTML Finding",
		Category:    "test-category",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/app.js",
		Evidence:    "api_key: secret_token_xyz",
	}
	rep := BuildReport("https://example.com", []Finding{f})

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	if !strings.Contains(htmlStr, "FELIX SECURITY AUDIT REPORT") {
		t.Errorf("HTML missing header title")
	}
	if strings.Contains(htmlStr, "secret_token_xyz") {
		t.Errorf("HTML report leaked secret token in evidence")
	}
	if !strings.Contains(htmlStr, "CRITICAL") {
		t.Errorf("HTML report missing CRITICAL severity badge")
	}
}

// 18. Secret redaction
func TestSecretRedaction(t *testing.T) {
	rawEvidence := "token=ey12345678.ey87654321.abcdefgh and secret_key=sk_live_123456789"
	clean := SanitizeEvidence(rawEvidence)

	if strings.Contains(clean, "ey12345678") {
		t.Errorf("JWT token was not sanitized: %s", clean)
	}
	if strings.Contains(clean, "sk_live_123456789") {
		t.Errorf("Secret key was not sanitized: %s", clean)
	}
}

// 19. Stable report ordering
func TestStableReportOrdering(t *testing.T) {
	f1 := Finding{Category: "cat-b", Endpoint: "https://example.com/b", Severity: SeverityMedium, Confidence: ConfidenceHigh}
	f2 := Finding{Category: "cat-a", Endpoint: "https://example.com/a", Severity: SeverityMedium, Confidence: ConfidenceHigh}
	f3 := Finding{Category: "cat-c", Endpoint: "https://example.com/c", Severity: SeverityMedium, Confidence: ConfidenceHigh}

	p1 := Prioritize([]Finding{f1, f2, f3})
	p2 := Prioritize([]Finding{f3, f1, f2})

	for i := range p1 {
		if p1[i].Category != p2[i].Category {
			t.Errorf("ordering mismatch at index %d: %s vs %s", i, p1[i].Category, p2[i].Category)
		}
	}
}

// 20. Empty findings report
func TestEmptyFindingsReport(t *testing.T) {
	rep := BuildReport("https://example.com", nil)
	if rep.RiskScore != 0 {
		t.Errorf("expected 0 risk score for empty findings, got %d", rep.RiskScore)
	}
	if rep.RiskLevel != "INFORMATIONAL" {
		t.Errorf("expected INFORMATIONAL level, got %s", rep.RiskLevel)
	}
	if rep.Summary.TotalFindings != 0 {
		t.Errorf("expected 0 total findings, got %d", rep.Summary.TotalFindings)
	}

	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed on empty findings: %v", err)
	}
	if !strings.Contains(htmlStr, "No security findings") {
		t.Errorf("HTML should mention no findings detected")
	}
}

// 21. Multiple targets
func TestMultipleTargets(t *testing.T) {
	targets := []string{"https://site-a.com", "https://site-b.com"}
	fA := Finding{Target: targets[0], Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh}
	fB := Finding{Target: targets[1], Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh}

	rep := BuildMultiTargetReport(targets, []Finding{fA, fB})
	if len(rep.Targets) != 2 {
		t.Errorf("expected 2 targets, got %d", len(rep.Targets))
	}
	if rep.Summary.TotalFindings != 2 {
		t.Errorf("expected 2 findings across targets, got %d", rep.Summary.TotalFindings)
	}
}

// 22. Concurrent report generation
func TestConcurrentReportGeneration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-report-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	f := Finding{
		Title:      "Concurrent Probe",
		Category:   "missing-csp",
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Target:     "https://example.com",
		Endpoint:   "https://example.com",
	}

	var wg sync.WaitGroup
	workers := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			rep := BuildReport("https://example.com", []Finding{f})
			jsonPath := filepath.Join(tmpDir, fmt.Sprintf("report-%d.json", idx))
			htmlPath := filepath.Join(tmpDir, fmt.Sprintf("report-%d.html", idx))

			if err := WriteJSON(rep, jsonPath); err != nil {
				t.Errorf("WriteJSON failed in worker %d: %v", idx, err)
			}
			if err := WriteHTML(rep, htmlPath); err != nil {
				t.Errorf("WriteHTML failed in worker %d: %v", idx, err)
			}
		}(i)
	}

	wg.Wait()
}

// Additional test for unified model ingestion from all 3 engines
func TestUnifiedEngineIngestion(t *testing.T) {
	target := "https://example.com"

	secF := secrets.SecretFinding{
		Type:        secrets.SecretOpenAIKey,
		Title:       "OpenAI API Key Discovered",
		Value:       "sk-proj-1234567890abcdef1234567890abcdef",
		Redacted:    "sk-proj-********************cdef",
		FileOrigin:  "https://example.com/main.js",
		LineNumber:  25,
		Severity:    secrets.SeverityHigh,
		Confidence:  secrets.ConfidenceHigh,
		Fingerprint: "fp-openai-1",
	}
	cldF := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-anon-key",
		Endpoint:    "https://test.supabase.co",
		Description: "Supabase publishable anon key detected",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-sb-anon-1",
	}
	apiF := api.APIFinding{
		Category:    api.CategoryMissingCSP,
		Endpoint:    "https://example.com",
		Method:      "GET",
		Description: "Missing Content-Security-Policy",
		Severity:    api.SeverityLow,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-csp-1",
	}

	f1 := FromSecretFinding(target, secF)
	f2 := FromCloudFinding(target, cldF)
	f3 := FromAPIFinding(target, apiF)

	allFindings := []Finding{f1, f2, f3}
	rep := BuildReport(target, allFindings)

	if rep.Summary.TotalFindings != 3 {
		t.Errorf("expected 3 findings, got %d", rep.Summary.TotalFindings)
	}
	if rep.Summary.BySource[SourceSecrets] != 1 {
		t.Errorf("expected 1 secrets source finding, got %d", rep.Summary.BySource[SourceSecrets])
	}
	if rep.Summary.BySource[SourceCloud] != 1 {
		t.Errorf("expected 1 cloud source finding, got %d", rep.Summary.BySource[SourceCloud])
	}
	if rep.Summary.BySource[SourceAPI] != 1 {
		t.Errorf("expected 1 api source finding, got %d", rep.Summary.BySource[SourceAPI])
	}
}
