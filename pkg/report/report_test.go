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
	"felix/pkg/crawler"
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

// 19. Secret finding evidence survives normalization
func TestSecretEvidenceSurvivesNormalization(t *testing.T) {
	sec := secrets.SecretFinding{
		Type:        secrets.SecretHighEntropy,
		Title:       "High-Entropy Suspicious Secret String",
		Value:       "sb_p1234567890abcdef1234567890abcdef",
		Redacted:    "sb_p****************cdef",
		FileOrigin:  "https://example.com/chunk.js",
		LineNumber:  37,
		Severity:    secrets.SeverityLow,
		Confidence:  secrets.ConfidenceLow,
		Evidence:    "const token = 'sb_p****************cdef'",
		Fingerprint: "fp-entropy-1",
	}

	f := FromSecretFinding("https://example.com", sec)
	if f.EvidenceDetails.Observation == "" {
		t.Errorf("expected structured observation, got empty")
	}
	if f.EvidenceDetails.Location != "https://example.com/chunk.js:37" {
		t.Errorf("expected location 'https://example.com/chunk.js:37', got %q", f.EvidenceDetails.Location)
	}
	if f.EvidenceDetails.DetectionMethod != "shannon_entropy_heuristic" {
		t.Errorf("expected shannon_entropy_heuristic detection method, got %q", f.EvidenceDetails.DetectionMethod)
	}
	if f.Verification.Status != VerificationNotVerified {
		t.Errorf("expected NOT_VERIFIED status, got %q", f.Verification.Status)
	}
}

// 20. Secret redaction remains intact in structured evidence
func TestSecretRedactionIntact(t *testing.T) {
	sec := secrets.SecretFinding{
		Type:        secrets.SecretStripeLiveKey,
		Title:       "Stripe Live Secret Key Discovered",
		Value:       "sk_live_51Abcdef1234567890abcdef1234567890",
		Redacted:    "sk_live_********************7890",
		FileOrigin:  "https://example.com/api.js",
		LineNumber:  15,
		Severity:    secrets.SeverityCritical,
		Confidence:  secrets.ConfidenceHigh,
		Evidence:    "const key = 'sk_live_********************7890'",
		Fingerprint: "fp-stripe-1",
	}

	f := FromSecretFinding("https://example.com", sec)
	rep := BuildReport("https://example.com", []Finding{f})

	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON error: %v", err)
	}

	rawJSON := string(jsonBytes)
	if strings.Contains(rawJSON, "sk_live_51Abcdef1234567890abcdef1234567890") {
		t.Fatalf("CRITICAL LEAK: Raw unredacted secret found in JSON report!")
	}
	if !strings.Contains(rawJSON, "sk_live_********************7890") {
		t.Errorf("expected redacted token in JSON report")
	}
}

// 21. Line number and source asset information survives
func TestSecretLineNumberAndAssetSurvive(t *testing.T) {
	sec := secrets.SecretFinding{
		Type:        secrets.SecretGitHubToken,
		Title:       "GitHub Token Discovered",
		Value:       "ghp_123456789012345678901234567890123456",
		Redacted:    "ghp_********************3456",
		FileOrigin:  "https://example.com/bundle.js",
		LineNumber:  42,
		Severity:    secrets.SeverityHigh,
		Confidence:  secrets.ConfidenceHigh,
		Fingerprint: "fp-gh-42",
	}

	f := FromSecretFinding("https://example.com", sec)
	if f.EvidenceDetails.Details["line_number"] != "42" {
		t.Errorf("expected line_number 42 in details, got %q", f.EvidenceDetails.Details["line_number"])
	}
	if f.EvidenceDetails.Details["source_asset"] != "https://example.com/bundle.js" {
		t.Errorf("expected source_asset in details, got %q", f.EvidenceDetails.Details["source_asset"])
	}
}

// 22. Cloud provider evidence survives normalization
func TestCloudEvidenceSurvivesNormalization(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "Unauthorized Data Exposure",
		Endpoint:    "https://project.supabase.co/rest/v1/users",
		Description: "Public read access allowed on Supabase resource /users",
		Evidence:    "HTTP 200 OK. Returned 5 record(s). Observed fields: [email, id, name]",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-cld-data",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.EvidenceDetails.Observation != cld.Evidence {
		t.Errorf("cloud observation did not survive, got %q", f.EvidenceDetails.Observation)
	}
	if f.EvidenceDetails.Details["provider"] != "supabase" {
		t.Errorf("cloud provider details missing, got %v", f.EvidenceDetails.Details)
	}
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VERIFIED status for data exposure, got %s", f.Verification.Status)
	}
}

// 23. Cloud HTTP status survives
func TestCloudHTTPStatusSurvives(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "Anonymous Bucket Listing",
		Endpoint:    "https://s3.amazonaws.com/test-bucket",
		Description: "AWS S3 storage bucket permits anonymous object listing",
		Evidence:    "HTTP 200 OK. Public ListBucketResult observed (2450 bytes).",
		Severity:    cloud.SeverityMedium,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-s3-1",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.EvidenceDetails.HTTPStatus != 200 {
		t.Errorf("expected HTTP status 200, got %d", f.EvidenceDetails.HTTPStatus)
	}
	if f.EvidenceDetails.HTTPMethod != "GET" {
		t.Errorf("expected HTTPMethod GET, got %q", f.EvidenceDetails.HTTPMethod)
	}
}

// 24. API endpoint, method, and status survive
func TestAPIFindingEvidenceSurvives(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryGraphQLIntrospection,
		Endpoint:    "https://example.com/graphql",
		Method:      "GET",
		Description: "GraphQL endpoint has public introspection enabled",
		Evidence:    "HTTP 200 OK. Introspection query succeeded (24 types observed).",
		Severity:    api.SeverityLow,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-gql-1",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.EvidenceDetails.HTTPMethod != "GET" {
		t.Errorf("expected method GET, got %q", f.EvidenceDetails.HTTPMethod)
	}
	if f.EvidenceDetails.HTTPStatus != 200 {
		t.Errorf("expected status 200, got %d", f.EvidenceDetails.HTTPStatus)
	}
	if f.EvidenceDetails.DetectionMethod != "active_probe" {
		t.Errorf("expected detection method active_probe, got %q", f.EvidenceDetails.DetectionMethod)
	}
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VERIFIED status, got %q", f.Verification.Status)
	}
}

// 25. Verification status survives JSON serialization
func TestVerificationStatusSurvivesJSONSerialization(t *testing.T) {
	f := Finding{
		ID:          "TEST-VER",
		Title:       "Test Verification Finding",
		Category:    "cors-wildcard",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Description: "CORS policy permits wildcard origin",
		Verification: VerificationRecord{
			Status: VerificationObserved,
			Result: "Wildcard CORS origin observed on public endpoint.",
		},
	}

	rep := BuildReport("https://example.com", []Finding{f})
	data, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if len(parsed.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(parsed.Findings))
	}
	if parsed.Findings[0].Verification.Status != VerificationObserved {
		t.Errorf("expected verification status OBSERVED, got %s", parsed.Findings[0].Verification.Status)
	}
	if parsed.Findings[0].Verification.Result != "Wildcard CORS origin observed on public endpoint." {
		t.Errorf("verification result mismatch: %q", parsed.Findings[0].Verification.Result)
	}
}

// 26. Negative evidence survives serialization
func TestNegativeEvidenceSurvivesSerialization(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryCORSWildcard,
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Description: "CORS policy permits wildcard (*) origin",
		Evidence:    "Response returned Access-Control-Allow-Origin: *",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-cors-wildcard-1",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.EvidenceDetails.NegativeEvidence == "" {
		t.Fatalf("expected negative evidence for cors-wildcard, got empty")
	}

	rep := BuildReport("https://example.com", []Finding{f})
	data, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	neg := parsed.Findings[0].EvidenceDetails.NegativeEvidence
	if !strings.Contains(neg, "Access-Control-Allow-Credentials header was absent") {
		t.Errorf("expected negative evidence to survive serialization, got %q", neg)
	}
}

// 27. HTML report contains evidence and verification badges
func TestHTMLExportContainsEvidenceAndVerification(t *testing.T) {
	f := Finding{
		ID:          "TEST-HTML-EVID",
		Title:       "Test HTML Evidence",
		Category:    "missing-csp",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Description: "Missing Content-Security-Policy",
		Evidence:    "Response headers do not include Content-Security-Policy.",
		EvidenceDetails: EvidenceDetails{
			Observation:      "Response headers do not include Content-Security-Policy.",
			Location:         "https://example.com",
			DetectionMethod:  "header_inspection",
			NegativeEvidence: "No CSP header returned by web server.",
		},
		Verification: VerificationRecord{
			Status: VerificationVerified,
			Result: "Evaluated server response headers; missing-csp was confirmed.",
		},
	}

	rep := BuildReport("https://example.com", []Finding{f})
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	if !strings.Contains(htmlStr, "badge-VERIFIED") {
		t.Errorf("expected badge-VERIFIED in HTML report")
	}
	if !strings.Contains(htmlStr, "negative-evidence-box") {
		t.Errorf("expected negative-evidence-box in HTML report")
	}
	if !strings.Contains(htmlStr, "No CSP header returned by web server.") {
		t.Errorf("expected negative evidence text in HTML report")
	}
}

// 28. Existing minimal reports remain valid
func TestExistingReportsRemainValid(t *testing.T) {
	legacy := Finding{
		ID:          "LEGACY-1",
		Title:       "Legacy Finding",
		Category:    "missing-hsts",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Evidence:    "No HSTS header observed.",
	}

	norm := NormalizeFinding(legacy)
	if norm.EvidenceDetails.Observation != "No HSTS header observed." {
		t.Errorf("expected legacy evidence to populate EvidenceDetails.Observation, got %q", norm.EvidenceDetails.Observation)
	}
	if norm.Verification.Status == "" {
		t.Errorf("expected default verification status for legacy finding")
	}

	rep := BuildReport("https://example.com", []Finding{legacy})
	if rep.RiskScore == 0 {
		t.Errorf("expected non-zero risk score for legacy finding")
	}
}

// 29. Deterministic output remains deterministic
func TestDeterministicOutputRemainsDeterministic(t *testing.T) {
	f1 := Finding{
		ID:          "DET-1",
		Title:       "Finding 1",
		Category:    "cors-wildcard",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Evidence:    "Evidence 1",
	}
	f2 := Finding{
		ID:          "DET-2",
		Title:       "Finding 2",
		Category:    "missing-csp",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com",
		Method:      "GET",
		Evidence:    "Evidence 2",
	}

	rep1 := BuildReport("https://example.com", []Finding{f1, f2})
	rep2 := BuildReport("https://example.com", []Finding{f2, f1})

	// Override timestamp for strict comparison
	rep1.Timestamp = "2026-10-08T12:00:00Z"
	rep2.Timestamp = "2026-10-08T12:00:00Z"

	json1, err1 := GenerateJSON(rep1)
	json2, err2 := GenerateJSON(rep2)
	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateJSON failed: %v, %v", err1, err2)
	}

	if string(json1) != string(json2) {
		t.Errorf("expected deterministic JSON output regardless of input slice order.\nRun1:\n%s\nRun2:\n%s", string(json1), string(json2))
	}
}

// 30. Deduplication still works with differing evidence
func TestDeduplicationPreservesIdentityWithDifferingEvidence(t *testing.T) {
	f1 := Finding{
		Target:      "https://example.com",
		Category:    "cors-wildcard",
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Title:       "CORS Wildcard",
		Evidence:    "Observation from worker 1",
		EvidenceDetails: EvidenceDetails{
			Observation: "Observation from worker 1",
			Location:    "https://example.com/api",
		},
		Verification: VerificationRecord{
			Status: VerificationObserved,
		},
	}
	f2 := Finding{
		Target:      "https://example.com",
		Category:    "cors-wildcard",
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Title:       "CORS Wildcard",
		Evidence:    "Observation from worker 2",
		EvidenceDetails: EvidenceDetails{
			Observation: "Observation from worker 2",
			Location:    "https://example.com/api",
		},
		Verification: VerificationRecord{
			Status: VerificationVerified, // higher verification status
		},
	}

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected exactly 1 deduplicated finding despite differing evidence details, got %d", len(deduped))
	}

	merged := deduped[0]
	if !strings.Contains(merged.Evidence, "worker 1") || !strings.Contains(merged.Evidence, "worker 2") {
		t.Errorf("expected merged evidence to contain both observations, got: %s", merged.Evidence)
	}
	if merged.Verification.Status != VerificationVerified {
		t.Errorf("expected higher verification status VERIFIED to be retained, got %s", merged.Verification.Status)
	}
}

// 31. JS asset discovered -> OBSERVED
func TestMatrix1_JSAssetDiscovered_Observed(t *testing.T) {
	asset := crawler.Asset{
		URL:   "https://example.com/static/bundle.js",
		Type:  crawler.AssetJavaScript,
		Size:  10240,
	}

	f := FromCrawlerDiscovery("https://example.com", asset)
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
	if f.EvidenceDetails.DetectionStatus != "OBSERVED" {
		t.Errorf("expected detection status OBSERVED, got %s", f.EvidenceDetails.DetectionStatus)
	}
}

// 32. Source map discovered -> OBSERVED
func TestMatrix2_SourceMapDiscovered_Observed(t *testing.T) {
	asset := crawler.Asset{
		URL:         "https://example.com/static/bundle.js.map",
		Type:        crawler.AssetSourceMap,
		IsSourceMap: true,
		Size:        52400,
	}

	f, ok := FromCrawlerAsset("https://example.com", asset)
	if !ok {
		t.Fatalf("expected source map asset to produce finding")
	}
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity for source map discovery, got %s", f.Severity)
	}
	if !strings.Contains(f.Title, "Discovered") {
		t.Errorf("expected title to reflect discovery rather than vulnerability, got %q", f.Title)
	}
}

// 33. Entropy candidate -> DETECTED / NOT_VERIFIED
func TestMatrix3_EntropyCandidate_DetectedNotVerified(t *testing.T) {
	sec := secrets.SecretFinding{
		Type:        secrets.SecretHighEntropy,
		Title:       "High-Entropy Suspicious Secret String",
		Value:       "4fA8bC9dE0fG1hI2jK3lM4nO5pQ6rS7tU8vW9xY0z=",
		Redacted:    "4fA8****************xY0z=",
		FileOrigin:  "https://example.com/app.js",
		LineNumber:  24,
		Severity:    secrets.SeverityLow,
		Confidence:  secrets.ConfidenceLow,
		Evidence:    "const token = '4fA8****************xY0z='",
		Fingerprint: "fp-entropy-33",
	}

	f := FromSecretFinding("https://example.com", sec)
	if f.Verification.Status != VerificationNotVerified {
		t.Errorf("expected VerificationNotVerified, got %s", f.Verification.Status)
	}
	if f.Verification.DetectionStatus != "DETECTED" {
		t.Errorf("expected DetectionStatus DETECTED, got %s", f.Verification.DetectionStatus)
	}
	if f.EvidenceDetails.NegativeEvidence == "" {
		t.Errorf("expected negative evidence explaining live validity not tested")
	}
}

// 34. Known secret pattern -> DETECTED / NOT_VERIFIED
func TestMatrix4_KnownSecretPattern_DetectedNotVerified(t *testing.T) {
	sec := secrets.SecretFinding{
		Type:        secrets.SecretAWSAccessKey,
		Title:       "AWS Access Key ID Discovered",
		Value:       "AKIAIOSFODNN7EXAMPLE",
		Redacted:    "AKIA****************MPLE",
		FileOrigin:  "https://example.com/config.js",
		LineNumber:  12,
		Severity:    secrets.SeverityCritical,
		Confidence:  secrets.ConfidenceHigh,
		Evidence:    "const aws_key = 'AKIA****************MPLE'",
		Fingerprint: "fp-aws-34",
	}

	f := FromSecretFinding("https://example.com", sec)
	if f.Verification.Status != VerificationNotVerified {
		t.Errorf("expected VerificationNotVerified, got %s", f.Verification.Status)
	}
	if f.Verification.DetectionStatus != "DETECTED" {
		t.Errorf("expected DetectionStatus DETECTED, got %s", f.Verification.DetectionStatus)
	}
	// High confidence pattern must NOT be converted to VERIFIED without live probe
	if f.Confidence != ConfidenceHigh {
		t.Errorf("expected HIGH confidence, got %s", f.Confidence)
	}
}

// 35. Supabase provider detected -> OBSERVED
func TestMatrix5_SupabaseProviderDetected_Observed(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "provider-discovered",
		Endpoint:    "https://xyz.supabase.co",
		Description: "Discovered Supabase cloud provider infrastructure",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-sb-provider",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 36. Supabase endpoint discovered -> OBSERVED
func TestMatrix6_SupabaseEndpointDiscovered_Observed(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-endpoint-discovered",
		Endpoint:    "https://xyz.supabase.co/rest/v1/users",
		Description: "Discovered Supabase REST endpoint in client assets",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-sb-endpoint",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 37. Supabase endpoint returns 401 -> NOT_EXPOSED
func TestMatrix7_SupabaseEndpointReturns401_NotExposed(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-access-denied",
		Endpoint:    "https://xyz.supabase.co/rest/v1/private_table",
		Description: "Safe bounded GET returned HTTP 401 Unauthorized (RLS enforced)",
		Evidence:    "HTTP 401 Unauthorized. Access denied by Row Level Security.",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-sb-401",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity for denied access, got %s", f.Severity)
	}
	if !strings.Contains(f.EvidenceDetails.NegativeEvidence, "401") {
		t.Errorf("expected negative evidence citing HTTP 401, got %q", f.EvidenceDetails.NegativeEvidence)
	}
}

// 38. Supabase endpoint returns 403 -> NOT_EXPOSED
func TestMatrix8_SupabaseEndpointReturns403_NotExposed(t *testing.T) {
	cld := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-access-denied",
		Endpoint:    "https://xyz.supabase.co/rest/v1/admin_table",
		Description: "Safe bounded GET returned HTTP 403 Forbidden (RLS enforced)",
		Evidence:    "HTTP 403 Forbidden. Access denied by Row Level Security.",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-sb-403",
	}

	f := FromCloudFinding("https://example.com", cld)
	if f.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 39. GraphQL endpoint discovered -> OBSERVED
func TestMatrix9_GraphQLEndpointDiscovered_Observed(t *testing.T) {
	apiF := api.APIFinding{
		Category:    "graphql-endpoint-discovered",
		Endpoint:    "https://example.com/api/graphql",
		Method:      "GET",
		Description: "Discovered candidate GraphQL endpoint in assets",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-gql-discovered",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity for endpoint discovery, got %s", f.Severity)
	}
}

// 40. GraphQL introspection succeeds -> VERIFIED
func TestMatrix10_GraphQLIntrospectionSucceeds_Verified(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryGraphQLIntrospection,
		Endpoint:    "https://example.com/graphql",
		Method:      "GET",
		Description: "GraphQL endpoint has public introspection enabled",
		Evidence:    "HTTP 200 OK. Introspection query succeeded (32 types observed).",
		Severity:    api.SeverityLow,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-gql-success",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VerificationVerified, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityLow {
		t.Errorf("expected LOW severity (not critical), got %s", f.Severity)
	}
}

// 41. Wildcard CORS without credentials -> OBSERVED
func TestMatrix11_WildcardCORSWithoutCredentials_Observed(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryCORSWildcard,
		Endpoint:    "https://example.com/api/public",
		Method:      "GET",
		Description: "CORS policy permits wildcard (*) origin",
		Evidence:    "Response returned Access-Control-Allow-Origin: *",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-cors-wildcard-35",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
	if !strings.Contains(f.EvidenceDetails.NegativeEvidence, "Access-Control-Allow-Credentials header was absent") {
		t.Errorf("expected negative evidence confirming absence of credentials, got %q", f.EvidenceDetails.NegativeEvidence)
	}
}

// 42. Arbitrary-origin credentialed behavior -> VERIFIED
func TestMatrix12_ArbitraryOriginCredentialed_Verified(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryCORSOriginReflection,
		Endpoint:    "https://example.com/api/user",
		Method:      "GET",
		Description: "CORS configuration reflects arbitrary Origin with credentials allowed",
		Evidence:    "Supplied Origin: https://felix.invalid. Response returned Access-Control-Allow-Origin: https://felix.invalid, Access-Control-Allow-Credentials: true",
		Severity:    api.SeverityHigh,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-cors-creds-36",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VerificationVerified, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("expected HIGH severity for credentialed reflection, got %s", f.Severity)
	}
}

// 43. Sensitive endpoint 404 -> NOT_EXPOSED
func TestMatrix13_SensitiveEndpoint404_NotExposed(t *testing.T) {
	apiF := api.APIFinding{
		Category:    "sensitive-endpoint-protected",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Description: "Probe returned HTTP 404 Not Found",
		Evidence:    "HTTP 404 Not Found. Resource absent.",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-env-404",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 44. Sensitive endpoint 401 -> NOT_EXPOSED
func TestMatrix14_SensitiveEndpoint401_NotExposed(t *testing.T) {
	apiF := api.APIFinding{
		Category:    "sensitive-endpoint-protected",
		Endpoint:    "https://example.com/api/debug",
		Method:      "GET",
		Description: "Probe returned HTTP 401 Unauthorized",
		Evidence:    "HTTP 401 Unauthorized. Access denied.",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-debug-401",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 45. Sensitive endpoint 403 -> NOT_EXPOSED
func TestMatrix15_SensitiveEndpoint403_NotExposed(t *testing.T) {
	apiF := api.APIFinding{
		Category:    "sensitive-endpoint-protected",
		Endpoint:    "https://example.com/.git/HEAD",
		Method:      "GET",
		Description: "Probe returned HTTP 403 Forbidden",
		Evidence:    "HTTP 403 Forbidden. Access denied.",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-git-403",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationNotExposed {
		t.Errorf("expected VerificationNotExposed, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity, got %s", f.Severity)
	}
}

// 46. Sensitive endpoint 200 normal content -> VERIFIED response, no exposure
func TestMatrix16_SensitiveEndpoint200Normal_VerifiedNoExposure(t *testing.T) {
	apiF := api.APIFinding{
		Category:    "sensitive-endpoint-normal",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Description: "HTTP 200 OK returned generic HTML shell (no .env contents)",
		Evidence:    "HTTP 200 OK. Standard HTML document returned; no configuration variables.",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-env-spa-200",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VerificationVerified response, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected INFO severity for normal content, got %s", f.Severity)
	}
	if !strings.Contains(f.EvidenceDetails.NegativeEvidence, "normal content") {
		t.Errorf("expected negative evidence indicating normal response, got %q", f.EvidenceDetails.NegativeEvidence)
	}
}

// 47. Sensitive endpoint 200 sensitive content -> VERIFIED exposure
func TestMatrix17_SensitiveEndpoint200Sensitive_VerifiedExposure(t *testing.T) {
	apiF := api.APIFinding{
		Category:    api.CategoryEnvExposure,
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Description: "Public exposure of sensitive /.env configuration file",
		Evidence:    "HTTP 200 OK. Observed variable declarations: [DATABASE_URL, SECRET_KEY] (values redacted).",
		Severity:    api.SeverityCritical,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-env-leak-200",
	}

	f := FromAPIFinding("https://example.com", apiF)
	if f.Verification.Status != VerificationVerified {
		t.Errorf("expected VerificationVerified, got %s", f.Verification.Status)
	}
	if f.Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity, got %s", f.Severity)
	}
}

// 48. Weak observations -> NO false high-impact security story
func TestMatrix18_WeakObservations_NoFalseSecurityStory(t *testing.T) {
	target := "https://example.com"

	// Construct weak observations:
	// 1. Supabase publishable anon key (client config)
	cldAnon := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-anon-key",
		Endpoint:    "https://test.supabase.co",
		Description: "Supabase publishable anon key detected",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-anon-weak",
	}
	// 2. Discovered REST endpoint
	cldEP := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "supabase-endpoint-discovered",
		Endpoint:    "https://test.supabase.co/rest/v1/items",
		Description: "Discovered Supabase REST endpoint in client assets",
		Severity:    cloud.SeverityInfo,
		Confidence:  cloud.ConfidenceHigh,
		Fingerprint: "fp-ep-weak",
	}
	// 3. Discovered GraphQL endpoint
	apiGQL := api.APIFinding{
		Category:    "graphql-endpoint-discovered",
		Endpoint:    "https://example.com/graphql",
		Method:      "GET",
		Description: "Discovered GraphQL route in client assets",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-gql-weak",
	}
	// 4. Wildcard CORS
	apiCORS := api.APIFinding{
		Category:    api.CategoryCORSWildcard,
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Description: "CORS policy permits wildcard (*) origin",
		Evidence:    "Access-Control-Allow-Origin: *",
		Severity:    api.SeverityInfo,
		Confidence:  api.ConfidenceHigh,
		Fingerprint: "fp-cors-weak",
	}

	f1 := FromCloudFinding(target, cldAnon)
	f2 := FromCloudFinding(target, cldEP)
	f3 := FromAPIFinding(target, apiGQL)
	f4 := FromAPIFinding(target, apiCORS)

	rep := BuildReport(target, []Finding{f1, f2, f3, f4})

	// PROVE: Zero high-impact or critical security stories are formed from weak observations alone!
	for _, story := range rep.SecurityStories {
		if story.Severity == SeverityCritical || story.Severity == SeverityHigh {
			t.Errorf("UNSUPPORTED ESCALATION: Weak observations created high-impact story: %s (Severity: %s)",
				story.Title, story.Severity)
		}
	}

	// Overall risk score must remain strictly LOW or INFORMATIONAL (not inflated)
	if rep.RiskScore > 20 {
		t.Errorf("Risk score unfairly escalated for weak observations: %d/100", rep.RiskScore)
	}
	if rep.Summary.CriticalCount > 0 || rep.Summary.HighCount > 0 {
		t.Errorf("Weak observations must not produce CRITICAL or HIGH findings: Crit=%d, High=%d",
			rep.Summary.CriticalCount, rep.Summary.HighCount)
	}
}

// 26. Attack paths integration and sanitization
func TestReportIntegration_AttackPathsSerializationAndSanitization(t *testing.T) {
	target := "https://example.com"
	f := Finding{
		ID:         "FND-1",
		Title:      "Initial Finding",
		Category:   "bola",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Target:     target,
		Endpoint:   "https://example.com/api/v1/users/42",
		Method:     "GET",
	}

	rep := BuildReport(target, []Finding{f})

	path := AttackPathSummary{
		ID:                "PATH-001",
		Title:             "API Endpoint -> BOLA Customer Record Exposure",
		Status:            "VERIFIED",
		Confidence:        ConfidenceHigh,
		CombinedRiskLevel: SeverityCritical,
		CombinedRiskScore: 88,
		RiskRationale:     "Direct access to customer records via token=ey12345678.ey87654321.abcdefgh",
		EntryPoint:        "https://example.com/api/v1/users",
		TargetAsset:       "https://example.com",
		PrimaryWeakness:   "Broken Object-Level Authorization",
		TerminalImpact:    "password=SuperSecretPassword123 disclosed",
		Transitions: []string{
			"[CONFIRMED] Route -> BOLA: password=SuperSecretPassword123",
		},
		Assumptions: []string{
			"Endpoint reachable from public internet",
		},
		MissingEvidence: []string{},
		Remediation:     "Enforce tenant ownership check at the query layer",
		NodeIDs:         []string{"FND-1"},
		SyntheticFixture: true,
	}

	AttachAttackPaths(&rep, []AttackPathSummary{path})

	// Prove: Risk score was elevated from 88/CRITICAL attack path
	if rep.RiskScore != 88 || rep.RiskLevel != SeverityCritical {
		t.Errorf("expected report risk score 88 CRITICAL, got %d %s", rep.RiskScore, rep.RiskLevel)
	}

	// 1. JSON generation & sanitization test
	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)

	// Ensure sensitive tokens are redacted in attack path fields
	if strings.Contains(jsonStr, "SuperSecretPassword123") {
		t.Errorf("CRITICAL LEAK: Password in attack path was not sanitized: %s", jsonStr)
	}
	if strings.Contains(jsonStr, "ey12345678") {
		t.Errorf("CRITICAL LEAK: JWT token in attack path was not sanitized: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "PATH-001") {
		t.Errorf("JSON missing attack path ID")
	}

	// Parse back
	parsed, err := ParseReport(jsonBytes)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}
	if len(parsed.AttackPaths) != 1 {
		t.Fatalf("expected 1 attack path in parsed report, got %d", len(parsed.AttackPaths))
	}
	if parsed.AttackPaths[0].Status != "VERIFIED" {
		t.Errorf("expected VERIFIED status, got %s", parsed.AttackPaths[0].Status)
	}
	if !parsed.AttackPaths[0].SyntheticFixture {
		t.Errorf("expected SyntheticFixture to be true")
	}

	// 2. HTML generation test
	htmlStr, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if !strings.Contains(htmlStr, "Correlated Attack Paths") {
		t.Errorf("HTML report missing Correlated Attack Paths section")
	}
	if !strings.Contains(htmlStr, "API Endpoint -&gt; BOLA Customer Record Exposure") && !strings.Contains(htmlStr, "API Endpoint -> BOLA Customer Record Exposure") {
		t.Errorf("HTML report missing attack path title")
	}
	if !strings.Contains(htmlStr, "[SYNTHETIC FIXTURE]") {
		t.Errorf("HTML report missing [SYNTHETIC FIXTURE] badge")
	}
	if strings.Contains(htmlStr, "SuperSecretPassword123") {
		t.Errorf("CRITICAL LEAK: HTML report leaked raw password in attack path: %s", htmlStr)
	}
}
