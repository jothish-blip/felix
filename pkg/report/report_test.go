package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
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
		Severity:     SeverityCritical,
		Confidence:   ConfidenceHigh,
		Category:     "supabase-service-key",
		Verification: VerificationRecord{Status: VerificationVerified},
	}
	score, level := CalculateReportRisk([]Finding{critFinding}, nil)
	if score != 40 {
		t.Errorf("CRITICAL verified finding should yield genuine score 40 (no artificial 80 floor), got %d", score)
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

// -----------------------------------------------------------------------------
// Risk Score Integrity & Regression Suite across all 13 required scenarios
// -----------------------------------------------------------------------------
func TestCalculateReportRisk_RegressionIntegritySuite(t *testing.T) {
	// Scenario 1: Empty assessment -> score 0, INFORMATIONAL
	t.Run("1_EmptyAssessment", func(t *testing.T) {
		score, level := CalculateReportRisk(nil, nil)
		if score != 0 || level != "INFORMATIONAL" {
			t.Errorf("expected score 0 and level INFORMATIONAL, got (%d, %s)", score, level)
		}
	})

	// Scenario 2: Low-severity NOT_EXPOSED finding -> score 0; no escalation
	t.Run("2_LowNotExposedFinding", func(t *testing.T) {
		f := Finding{
			ID:           "N1",
			Category:     "endpoint-discovered",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationNotExposed},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 0 || level != "INFORMATIONAL" {
			t.Errorf("defended NOT_EXPOSED low finding caused leak/escalation: got (%d, %s)", score, level)
		}
	})

	// Scenario 3: One verified low hardening finding -> calculated weighted score 5, level LOW (no 20 floor)
	t.Run("3_OneVerifiedLowHardening", func(t *testing.T) {
		f := Finding{
			ID:           "L1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 5 || level != "LOW" {
			t.Errorf("expected genuine score 5 and level LOW (no artificial 20 floor), got (%d, %s)", score, level)
		}
	})

	// Scenario 4: Several low hardening findings -> diminishing returns and cap respected
	t.Run("4_SeveralLowHardeningFindings", func(t *testing.T) {
		findings := []Finding{
			{ID: "L1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "L2", Category: "missing-hsts", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "L3", Category: "missing-xfo", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
		}
		// 5*1.0 + 5*0.5 + 5*0.3 = 5 + 2.5 + 1.5 = 9.0
		score, level := CalculateReportRisk(findings, nil)
		if score != 9 || level != "LOW" {
			t.Errorf("expected score 9 (diminishing returns) and level LOW, got (%d, %s)", score, level)
		}
	})

	// Scenario 5: Passive informational observation -> weighting without artificial floor
	t.Run("5_PassiveInformationalObservation", func(t *testing.T) {
		f := Finding{
			ID:           "I1",
			Category:     "cors-wildcard",
			Severity:     SeverityInfo,
			Confidence:   ConfidenceHigh,
			Score:        1,
			Verification: VerificationRecord{Status: VerificationObserved},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 1 || level != "INFORMATIONAL" {
			t.Errorf("expected score 1 and level INFORMATIONAL, got (%d, %s)", score, level)
		}
	})

	// Scenario 6: One verified medium finding -> genuine score 12, level MEDIUM (no 40 floor)
	t.Run("6_OneVerifiedMediumFinding", func(t *testing.T) {
		f := Finding{
			ID:           "M1",
			Category:     "graphql-introspection",
			Severity:     SeverityMedium,
			Confidence:   ConfidenceHigh,
			Score:        12,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 12 || level != "MEDIUM" {
			t.Errorf("expected genuine score 12 (no 40 floor) and level MEDIUM, got (%d, %s)", score, level)
		}
	})

	// Scenario 7: One verified high finding -> genuine score 25, level HIGH (no 60 floor)
	t.Run("7_OneVerifiedHighFinding", func(t *testing.T) {
		f := Finding{
			ID:           "H1",
			Category:     "env-exposure",
			Severity:     SeverityHigh,
			Confidence:   ConfidenceHigh,
			Score:        25,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 25 || level != "HIGH" {
			t.Errorf("expected genuine score 25 (no 60 floor) and level HIGH, got (%d, %s)", score, level)
		}
	})

	// Scenario 8: One verified critical finding -> genuine score 40, level CRITICAL (no 80 floor)
	t.Run("8_OneVerifiedCriticalFinding", func(t *testing.T) {
		f := Finding{
			ID:           "C1",
			Category:     "supabase-service-key",
			Severity:     SeverityCritical,
			Confidence:   ConfidenceHigh,
			Score:        40,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 40 || level != "CRITICAL" {
			t.Errorf("expected genuine score 40 (no 80 floor) and level CRITICAL, got (%d, %s)", score, level)
		}
	})

	// Scenario 9: Story bonuses contribute to raw score according to existing cap
	t.Run("9_StoryBonusContribution", func(t *testing.T) {
		f := Finding{
			ID:           "M1",
			Category:     "graphql-introspection",
			Severity:     SeverityMedium,
			Confidence:   ConfidenceHigh,
			Score:        12,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		story := SecurityStory{
			ID:               "STORY-1",
			RiskContribution: 5,
		}
		// 12 + 5 = 17
		score, level := CalculateReportRisk([]Finding{f}, []SecurityStory{story})
		if score != 17 || level != "MEDIUM" {
			t.Errorf("expected score 17 and level MEDIUM, got (%d, %s)", score, level)
		}
	})

	// Scenario 10: Removing a finding cannot increase score
	t.Run("10_RemovingFindingMonotonicity", func(t *testing.T) {
		f1 := Finding{ID: "H1", Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh, Score: 25, Verification: VerificationRecord{Status: VerificationVerified}}
		f2 := Finding{ID: "L1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}}

		scoreBoth, _ := CalculateReportRisk([]Finding{f1, f2}, nil)
		scoreOnlyHigh, _ := CalculateReportRisk([]Finding{f1}, nil)
		scoreOnlyLow, _ := CalculateReportRisk([]Finding{f2}, nil)

		if scoreBoth < scoreOnlyHigh || scoreBoth < scoreOnlyLow {
			t.Errorf("removing a finding increased score: both=%d, onlyHigh=%d, onlyLow=%d",
				scoreBoth, scoreOnlyHigh, scoreOnlyLow)
		}
	})

	// Scenario 11: Reversing finding order produces identical score and level (Determinism)
	t.Run("11_OrderInvarianceDeterminism", func(t *testing.T) {
		f1 := Finding{ID: "L1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}}
		f2 := Finding{ID: "H1", Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh, Score: 25, Verification: VerificationRecord{Status: VerificationVerified}}

		scoreForward, levelForward := CalculateReportRisk([]Finding{f1, f2}, nil)
		scoreReverse, levelReverse := CalculateReportRisk([]Finding{f2, f1}, nil)

		if scoreForward != scoreReverse || levelForward != levelReverse {
			t.Errorf("ordering affected results: forward=(%d, %s), reverse=(%d, %s)",
				scoreForward, levelForward, scoreReverse, levelReverse)
		}
	})

	// Scenario 12: Risk level and numeric score are independently tested
	t.Run("12_IndependentScoreAndLevel", func(t *testing.T) {
		// Single low finding has raw score 5, but risk level is LOW (not INFORMATIONAL)
		f := Finding{
			ID:           "L1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 5 {
			t.Errorf("expected numerical score 5, got %d", score)
		}
		if level != "LOW" {
			t.Errorf("expected risk level LOW anchored by verified low severity, got %s", level)
		}
	})

	// Scenario 13: Mixed verified, observed, and NOT_EXPOSED findings
	t.Run("13_MixedFindingsExcludedCannotEscalate", func(t *testing.T) {
		findings := []Finding{
			{ID: "V1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "O1", Category: "metrics-exposure", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 2, Verification: VerificationRecord{Status: VerificationObserved}},
			{ID: "N1", Category: "sql-injection", Severity: SeverityCritical, Confidence: ConfidenceHigh, Score: 0, Verification: VerificationRecord{Status: VerificationNotExposed}},
		}
		score, level := CalculateReportRisk(findings, nil)
		// ExposureAccum: 2.0 (metrics-exposure), HardeningAccum: 5.0 (missing-csp) -> Total: 7
		// Anchor: LOW (from V1 missing-csp), N1 must NOT escalate to CRITICAL!
		if score != 7 {
			t.Errorf("expected score 7, got %d", score)
		}
		if level != "LOW" {
			t.Errorf("defended NOT_EXPOSED finding N1 escalated risk level to %s (expected LOW)", level)
		}
	})
}

// referenceFindingScore calculates an individual finding score independently from the mathematical spec.
func referenceFindingScore(f Finding) int {
	normVer := strings.ToUpper(strings.TrimSpace(string(f.Verification.Status)))
	detStatus := strings.ToUpper(strings.TrimSpace(f.EvidenceDetails.DetectionStatus))
	if normVer == "NOT_EXPOSED" || detStatus == "NOT_EXPOSED" {
		return 0
	}
	if f.EvidenceDetails.Details != nil {
		auth := strings.ToUpper(strings.TrimSpace(f.EvidenceDetails.Details["auth_state"]))
		if auth == "AUTH_REQUIRED" || auth == "FORBIDDEN" || auth == "NOT_FOUND" {
			return 0
		}
	}

	var base float64
	switch strings.ToUpper(strings.TrimSpace(string(f.Severity))) {
	case "CRITICAL":
		base = 40.0
	case "HIGH":
		base = 25.0
	case "MEDIUM":
		base = 12.0
	case "LOW":
		base = 5.0
	default:
		base = 1.0
	}

	cat := strings.ToLower(strings.TrimSpace(f.Category))
	if strings.Contains(cat, "service-key") || strings.Contains(cat, "service-role") ||
		strings.Contains(cat, "aws-secret") || strings.Contains(cat, "private-key") {
		if base+5.0 > 40.0 {
			base = 40.0
		} else {
			base += 5.0
		}
	}

	var confMult float64
	switch strings.ToUpper(strings.TrimSpace(string(f.Confidence))) {
	case "HIGH":
		confMult = 1.0
	case "MEDIUM":
		confMult = 0.75
	case "LOW":
		confMult = 0.5
	default:
		confMult = 0.75
	}

	verMult := 1.0
	if normVer != "" {
		switch normVer {
		case "VERIFIED":
			verMult = 1.0
		case "DETECTED":
			verMult = 0.8
		case "NOT_VERIFIED":
			verMult = 0.7
		case "OBSERVED":
			verMult = 0.3
		case "NOT_EXPOSED":
			verMult = 0.0
		default:
			verMult = 0.5
		}
	}

	score := int(math.Round(base * confMult * verMult))
	if score < 0 {
		return 0
	}
	if score > 40 {
		return 40
	}
	return score
}

func referenceIsHardeningCategory(cat string) bool {
	c := strings.ToLower(strings.TrimSpace(cat))
	return strings.HasPrefix(c, "missing-") ||
		strings.HasPrefix(c, "weak-") ||
		c == "cors-wildcard" ||
		c == "api-docs-exposure" ||
		strings.HasPrefix(c, "asset-") ||
		c == "source-map-discovered" ||
		c == "source-map-exposure"
}

func referenceSeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFORMATIONAL", "INFO":
		return 1
	default:
		return 0
	}
}

func referenceRiskBand(score int) string {
	switch {
	case score >= 80:
		return "CRITICAL"
	case score >= 60:
		return "HIGH"
	case score >= 40:
		return "MEDIUM"
	case score >= 20:
		return "LOW"
	default:
		return "INFORMATIONAL"
	}
}

// referenceRiskModel provides an independent, completely decoupled reference implementation of the mathematical formula
// directly from the engineering specification without calling any production risk functions or helpers.
func referenceRiskModel(findings []Finding, stories []SecurityStory) (int, string) {
	if len(findings) == 0 {
		return 0, "INFORMATIONAL"
	}

	var exposures []int
	var hardenings []int
	maxEligibleRank := 0
	maxEligibleSev := ""

	for _, f := range findings {
		normVer := strings.ToUpper(strings.TrimSpace(string(f.Verification.Status)))
		detStatus := strings.ToUpper(strings.TrimSpace(f.EvidenceDetails.DetectionStatus))
		if normVer == "NOT_EXPOSED" || detStatus == "NOT_EXPOSED" {
			continue
		}
		if f.EvidenceDetails.Details != nil {
			auth := strings.ToUpper(strings.TrimSpace(f.EvidenceDetails.Details["auth_state"]))
			if auth == "AUTH_REQUIRED" || auth == "FORBIDDEN" || auth == "NOT_FOUND" {
				continue
			}
		}

		s := f.Score
		if s <= 0 || s > 40 {
			s = referenceFindingScore(f)
		}
		if s <= 0 {
			continue
		}

		// Explicit evidence of verification is required to anchor categorical severity.
		isConfirmed := false
		if normVer != "" {
			isConfirmed = (normVer == "VERIFIED")
		} else if detStatus == "VERIFIED" {
			isConfirmed = true
		}

		if isConfirmed {
			sevUpper := strings.ToUpper(strings.TrimSpace(string(f.Severity)))
			rank := referenceSeverityRank(sevUpper)
			confUpper := strings.ToUpper(strings.TrimSpace(string(f.Confidence)))
			if confUpper != "LOW" && rank > maxEligibleRank {
				maxEligibleRank = rank
				maxEligibleSev = sevUpper
			}
		}

		if referenceIsHardeningCategory(f.Category) {
			hardenings = append(hardenings, s)
		} else {
			exposures = append(exposures, s)
		}
	}

	sort.Slice(exposures, func(i, j int) bool { return exposures[i] > exposures[j] })
	sort.Slice(hardenings, func(i, j int) bool { return hardenings[i] > hardenings[j] })

	weights := []float64{1.0, 0.5, 0.3, 0.2}
	var expAccum float64
	for i, s := range exposures {
		if i < len(weights) {
			expAccum += float64(s) * weights[i]
		} else {
			expAccum += float64(s) * 0.1
		}
	}

	var hardAccum float64
	for i, s := range hardenings {
		if i < len(weights) {
			hardAccum += float64(s) * weights[i]
		} else {
			hardAccum += float64(s) * 0.1
		}
	}
	if hardAccum > 20.0 {
		hardAccum = 20.0
	}

	seenStories := make(map[string]bool)
	var storyBonus float64
	for _, st := range stories {
		sid := strings.TrimSpace(st.ID)
		if sid != "" {
			if seenStories[sid] {
				continue
			}
			seenStories[sid] = true
		}
		c := st.RiskContribution
		if c < 0 {
			c = 0
		}
		storyBonus += float64(c)
	}
	if storyBonus > 15.0 {
		storyBonus = 15.0
	}

	total := int(math.Round(expAccum + hardAccum + storyBonus))
	if total > 100 {
		total = 100
	}
	if total < 0 {
		total = 0
	}

	bandLevel := referenceRiskBand(total)
	finalLevel := bandLevel
	if maxEligibleRank > 0 {
		anchorLevel := "INFORMATIONAL"
		switch maxEligibleSev {
		case "CRITICAL":
			anchorLevel = "CRITICAL"
		case "HIGH":
			anchorLevel = "HIGH"
		case "MEDIUM":
			anchorLevel = "MEDIUM"
		case "LOW":
			anchorLevel = "LOW"
		}
		if referenceSeverityRank(anchorLevel) > referenceSeverityRank(bandLevel) {
			finalLevel = anchorLevel
		}
	}

	return total, finalLevel
}

// TestCalculateReportRisk_ForensicAuditTestSuite executes the comprehensive test suite
// verifying every confirmed defect, property invariant, and mathematical boundary.
func TestCalculateReportRisk_ForensicAuditTestSuite(t *testing.T) {
	// Defect 1: Finding score bounded to 0-40 even if populated with 0-100 confidence score
	t.Run("Defect1_FindingScoreBoundedZeroToForty", func(t *testing.T) {
		f := Finding{
			ID:           "CONF-1",
			Category:     "supabase-service-key",
			Severity:     SeverityCritical,
			Confidence:   ConfidenceHigh,
			Score:        95, // Corrupted score from confidence percentage
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		// CalculateReportRisk must detect s > 40 and recompute via CalculateFindingScore (40)
		score, level := CalculateReportRisk([]Finding{f}, nil)
		if score != 40 || level != "CRITICAL" {
			t.Errorf("expected score 40 (clamped/recalculated from 95) and CRITICAL, got (%d, %s)", score, level)
		}
	})

	// Defect 2: Candidate attack path does NOT escalate assessment risk score or level
	t.Run("Defect2_CandidateAttackPathDoesNotEscalateAssessmentRisk", func(t *testing.T) {
		rep := BuildReport("https://example.com", nil)
		candidatePath := AttackPathSummary{
			ID:                "PATH-CAND-01",
			Title:             "Candidate Workflow Pivot",
			Status:            "CANDIDATE",
			Confidence:        ConfidenceHigh,
			CombinedRiskLevel: "CRITICAL",
			CombinedRiskScore: 85,
		}
		AttachAttackPaths(&rep, []AttackPathSummary{candidatePath})

		if rep.RiskScore != 0 || rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("candidate attack path escalated assessment risk! score=%d level=%s (expected 0, INFORMATIONAL)",
				rep.RiskScore, rep.RiskLevel)
		}
		if rep.CommercialReport.RiskOverview.RiskScore != 0 {
			t.Errorf("commercial report risk score escalated by candidate path: %d", rep.CommercialReport.RiskOverview.RiskScore)
		}
	})

	// Defect 3: RecalculateReportRisk preserves verified attack path escalation
	t.Run("Defect3_RecalculateReportRiskPreservesVerifiedAttackPathEscalation", func(t *testing.T) {
		f := Finding{
			ID:           "F1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		rep := BuildReport("https://example.com", []Finding{f})
		verifiedPath := AttackPathSummary{
			ID:                "PATH-VER-01",
			Title:             "Verified Multi-Step Compromise",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskLevel: "CRITICAL",
			CombinedRiskScore: 88,
		}
		AttachAttackPaths(&rep, []AttackPathSummary{verifiedPath})

		if rep.RiskScore != 88 || rep.RiskLevel != "CRITICAL" {
			t.Fatalf("expected score 88 CRITICAL after attach, got (%d, %s)", rep.RiskScore, rep.RiskLevel)
		}

		// Recompute via canonical RecalculateReportRisk
		RecalculateReportRisk(&rep)
		if rep.RiskScore != 88 || rep.RiskLevel != "CRITICAL" {
			t.Errorf("RecalculateReportRisk wiped out verified attack path score! Got (%d, %s)",
				rep.RiskScore, rep.RiskLevel)
		}
	})

	// Defect 4: Security story with 0 risk contribution contributes 0, not 5
	t.Run("Defect4_ZeroRiskSecurityStoryContributesZeroNotFive", func(t *testing.T) {
		f := Finding{
			ID:           "F1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		storyZero := SecurityStory{
			ID:               "STORY-ZERO",
			RiskContribution: 0,
		}
		score, level := CalculateReportRisk([]Finding{f}, []SecurityStory{storyZero})
		if score != 5 || level != "LOW" {
			t.Errorf("zero-risk story inflated score to %d (expected 5), level %s", score, level)
		}
	})

	// Defect 5: Duplicate security story IDs do not double-count bonuses
	t.Run("Defect5_DuplicateSecurityStoryIDsDeduplicated", func(t *testing.T) {
		f := Finding{
			ID:           "F1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		story1 := SecurityStory{ID: "STORY-DUP-1", RiskContribution: 5}
		story2 := SecurityStory{ID: "STORY-DUP-1", RiskContribution: 5} // Duplicate ID

		score, _ := CalculateReportRisk([]Finding{f}, []SecurityStory{story1, story2})
		// 5 (finding) + 5 (unique story) = 10. Must NOT be 15!
		if score != 10 {
			t.Errorf("duplicate story ID double-counted: expected 10, got %d", score)
		}
	})

	// Defect 6: Unverified candidate (DETECTED / NOT_VERIFIED) cannot anchor severity to CRITICAL
	t.Run("Defect6_UnverifiedCandidateDetectedCannotAnchorSeverityToCritical", func(t *testing.T) {
		fDetected := Finding{
			ID:           "CAND-1",
			Category:     "aws-secret",
			Severity:     SeverityCritical,
			Confidence:   ConfidenceHigh,
			Score:        0,
			Verification: VerificationRecord{Status: VerificationDetected},
		}
		// CalculateFindingScore: 40 * 1.0 * 0.8 = 32
		// ScoreBand(32) = LOW (20-39). Because status is DETECTED, it must NOT anchor to CRITICAL!
		score, level := CalculateReportRisk([]Finding{fDetected}, nil)
		if score != 32 {
			t.Errorf("expected genuine candidate score 32, got %d", score)
		}
		if level != "LOW" {
			t.Errorf("unverified candidate DETECTED finding anchored risk level to %s (expected LOW)", level)
		}
	})

	// Property: Recalculation idempotence across 5 sequential cycles
	t.Run("Property_RecalculationIdempotence", func(t *testing.T) {
		findings := []Finding{
			{ID: "F1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "F2", Category: "metrics-exposure", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 2, Verification: VerificationRecord{Status: VerificationObserved}},
		}
		stories := []SecurityStory{
			{ID: "S1", RiskContribution: 3},
		}
		rep := BuildReport("https://example.com", findings)
		AttachSecurityStories(&rep, stories)

		initialScore := rep.RiskScore
		initialLevel := rep.RiskLevel

		for cycle := 1; cycle <= 5; cycle++ {
			RecalculateReportRisk(&rep)
			if rep.RiskScore != initialScore || rep.RiskLevel != initialLevel {
				t.Fatalf("idempotence violated on cycle %d: (%d, %s) vs initial (%d, %s)",
					cycle, rep.RiskScore, rep.RiskLevel, initialScore, initialLevel)
			}
			if rep.CommercialReport.RiskOverview.RiskScore != initialScore {
				t.Fatalf("commercial report risk score mutated on cycle %d: %d",
					cycle, rep.CommercialReport.RiskOverview.RiskScore)
			}
		}
	})

	// Property: Independent Reference Model Agreement across diverse synthetic cases
	t.Run("Property_IndependentReferenceModelAgreement", func(t *testing.T) {
		testCases := []struct {
			name     string
			findings []Finding
			stories  []SecurityStory
		}{
			{name: "Empty"},
			{
				name: "SingleHardening",
				findings: []Finding{
					{ID: "H1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Verification: VerificationRecord{Status: VerificationVerified}},
				},
			},
			{
				name: "MultiExposureMixed",
				findings: []Finding{
					{ID: "E1", Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "E2", Category: "graphql-introspection", Severity: SeverityMedium, Confidence: ConfidenceHigh, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "N1", Category: "sql-injection", Severity: SeverityCritical, Confidence: ConfidenceHigh, Verification: VerificationRecord{Status: VerificationNotExposed}},
				},
				stories: []SecurityStory{
					{ID: "S1", RiskContribution: 7},
				},
			},
			{
				name: "CapsBoundaryExceeded",
				findings: []Finding{
					{ID: "H1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H2", Category: "missing-hsts", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H3", Category: "missing-xfo", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H4", Category: "missing-xxp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H5", Category: "missing-cto", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
					{ID: "H6", Category: "missing-rp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
				},
				stories: []SecurityStory{
					{ID: "S1", RiskContribution: 10},
					{ID: "S2", RiskContribution: 10}, // Total 20 -> must cap at 15
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				prodScore, prodLevel := CalculateReportRisk(tc.findings, tc.stories)
				refScore, refLevel := referenceRiskModel(tc.findings, tc.stories)
				if prodScore != refScore || prodLevel != refLevel {
					t.Errorf("%s mismatch: production=(%d, %s) vs reference=(%d, %s)",
						tc.name, prodScore, prodLevel, refScore, refLevel)
				}
			})
		}
	})

	// Property: Monotonicity on finding removal
	t.Run("Property_MonotonicityOnFindingRemoval", func(t *testing.T) {
		fHigh := Finding{ID: "H", Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh, Score: 25, Verification: VerificationRecord{Status: VerificationVerified}}
		fMed := Finding{ID: "M", Category: "graphql-introspection", Severity: SeverityMedium, Confidence: ConfidenceHigh, Score: 12, Verification: VerificationRecord{Status: VerificationVerified}}
		fLow := Finding{ID: "L", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}}

		fullScore, _ := CalculateReportRisk([]Finding{fHigh, fMed, fLow}, nil)
		removedLow, _ := CalculateReportRisk([]Finding{fHigh, fMed}, nil)
		removedMed, _ := CalculateReportRisk([]Finding{fHigh, fLow}, nil)
		removedHigh, _ := CalculateReportRisk([]Finding{fMed, fLow}, nil)

		if removedLow > fullScore || removedMed > fullScore || removedHigh > fullScore {
			t.Errorf("removing a finding increased score: full=%d, -low=%d, -med=%d, -high=%d",
				fullScore, removedLow, removedMed, removedHigh)
		}
	})

	// Property: Order invariance across permutations
	t.Run("Property_OrderInvariancePermutations", func(t *testing.T) {
		findings := []Finding{
			{ID: "1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "2", Category: "env-exposure", Severity: SeverityHigh, Confidence: ConfidenceHigh, Score: 25, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "3", Category: "metrics-exposure", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 2, Verification: VerificationRecord{Status: VerificationObserved}},
		}
		baseScore, baseLevel := CalculateReportRisk(findings, nil)

		// Permutation 1: reverse
		p1 := []Finding{findings[2], findings[1], findings[0]}
		s1, l1 := CalculateReportRisk(p1, nil)

		// Permutation 2: mid-first
		p2 := []Finding{findings[1], findings[0], findings[2]}
		s2, l2 := CalculateReportRisk(p2, nil)

		if s1 != baseScore || l1 != baseLevel || s2 != baseScore || l2 != baseLevel {
			t.Errorf("order invariance failed: base=(%d, %s), p1=(%d, %s), p2=(%d, %s)",
				baseScore, baseLevel, s1, l1, s2, l2)
		}
	})

	// Property: Neutrality of NOT_EXPOSED findings
	t.Run("Property_NeutralityOfNotExposedFindings", func(t *testing.T) {
		baseline := []Finding{
			{ID: "1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
		}
		baseScore, baseLevel := CalculateReportRisk(baseline, nil)

		withNotExposed := append(baseline, Finding{
			ID:           "2",
			Category:     "sql-injection",
			Severity:     SeverityCritical,
			Confidence:   ConfidenceHigh,
			Score:        0,
			Verification: VerificationRecord{Status: VerificationNotExposed},
		})
		newScore, newLevel := CalculateReportRisk(withNotExposed, nil)

		if newScore != baseScore || newLevel != baseLevel {
			t.Errorf("NOT_EXPOSED finding altered result: before=(%d, %s), after=(%d, %s)",
				baseScore, baseLevel, newScore, newLevel)
		}
	})

	// Property: Boundary scores and caps
	t.Run("Property_BoundaryScoresAndCaps", func(t *testing.T) {
		// Test score band boundaries
		if RiskLevelBand(19) != "INFORMATIONAL" {
			t.Errorf("expected 19 -> INFORMATIONAL, got %s", RiskLevelBand(19))
		}
		if RiskLevelBand(20) != "LOW" {
			t.Errorf("expected 20 -> LOW, got %s", RiskLevelBand(20))
		}
		if RiskLevelBand(39) != "LOW" {
			t.Errorf("expected 39 -> LOW, got %s", RiskLevelBand(39))
		}
		if RiskLevelBand(40) != "MEDIUM" {
			t.Errorf("expected 40 -> MEDIUM, got %s", RiskLevelBand(40))
		}
		if RiskLevelBand(59) != "MEDIUM" {
			t.Errorf("expected 59 -> MEDIUM, got %s", RiskLevelBand(59))
		}
		if RiskLevelBand(60) != "HIGH" {
			t.Errorf("expected 60 -> HIGH, got %s", RiskLevelBand(60))
		}
		if RiskLevelBand(79) != "HIGH" {
			t.Errorf("expected 79 -> HIGH, got %s", RiskLevelBand(79))
		}
		if RiskLevelBand(80) != "CRITICAL" {
			t.Errorf("expected 80 -> CRITICAL, got %s", RiskLevelBand(80))
		}
	})

	// Property: All outputs reconciliation (In-memory, JSON, HTML, Commercial Report)
	t.Run("Property_AllOutputsReconciliation", func(t *testing.T) {
		findings := []Finding{
			{ID: "L1", Category: "missing-csp", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 5, Verification: VerificationRecord{Status: VerificationVerified}},
			{ID: "O1", Category: "metrics-exposure", Severity: SeverityLow, Confidence: ConfidenceHigh, Score: 2, Verification: VerificationRecord{Status: VerificationObserved}},
		}
		stories := []SecurityStory{
			{ID: "S1", Title: "Operational Telemetry", RiskContribution: 1},
		}
		rep := BuildReport("https://example.com", findings)
		AttachSecurityStories(&rep, stories)

		// 1. In-memory report
		expectedScore := 8 // 2.0 (metrics) + 5.0 (csp) + 1.0 (story) = 8
		expectedLevel := "LOW" // Anchored by verified missing-csp
		if rep.RiskScore != expectedScore || rep.RiskLevel != expectedLevel {
			t.Fatalf("in-memory mismatch: expected (%d, %s), got (%d, %s)",
				expectedScore, expectedLevel, rep.RiskScore, rep.RiskLevel)
		}

		// 2. Commercial Report structures
		cr := rep.CommercialReport
		if cr == nil {
			t.Fatalf("CommercialReport is nil")
		}
		if cr.RiskOverview.RiskScore != expectedScore || cr.RiskOverview.RiskLevel != expectedLevel {
			t.Errorf("RiskOverview mismatch: (%d, %s) vs expected (%d, %s)",
				cr.RiskOverview.RiskScore, cr.RiskOverview.RiskLevel, expectedScore, expectedLevel)
		}
		if cr.ExecutiveSummary.RiskScore != expectedScore || cr.ExecutiveSummary.RiskLevel != expectedLevel {
			t.Errorf("ExecutiveSummary mismatch: (%d, %s) vs expected (%d, %s)",
				cr.ExecutiveSummary.RiskScore, cr.ExecutiveSummary.RiskLevel, expectedScore, expectedLevel)
		}

		// 3. JSON round-trip
		jsonBytes, err := GenerateJSON(rep)
		if err != nil {
			t.Fatalf("GenerateJSON failed: %v", err)
		}
		parsedRep, err := ParseReport(jsonBytes)
		if err != nil {
			t.Fatalf("ParseReport failed: %v", err)
		}
		if parsedRep.RiskScore != expectedScore || parsedRep.RiskLevel != expectedLevel {
			t.Errorf("Parsed JSON mismatch: (%d, %s) vs expected (%d, %s)",
				parsedRep.RiskScore, parsedRep.RiskLevel, expectedScore, expectedLevel)
		}
		if parsedRep.CommercialReport == nil || parsedRep.CommercialReport.RiskOverview.RiskScore != expectedScore {
			t.Errorf("Parsed JSON CommercialReport RiskOverview score mismatch")
		}

		// 4. HTML document inspection
		htmlStr, err := GenerateHTML(rep)
		if err != nil {
			t.Fatalf("GenerateHTML failed: %v", err)
		}
		scoreMarker := fmt.Sprintf(`<div class="score-val color-LOW">%d</div>`, expectedScore)
		if !strings.Contains(htmlStr, scoreMarker) {
			t.Errorf("HTML missing expected score marker: %s", scoreMarker)
		}
	})
}

// TestSeverityAnchor_ExplicitVerificationPolicy verifies that unverified candidates
// (empty status, DETECTED, NOT_VERIFIED, OBSERVED, NOT_EXPOSED) cannot anchor severity,
// and only explicit verified evidence or the documented legacy fallback can anchor severity.
func TestSeverityAnchor_ExplicitVerificationPolicy(t *testing.T) {
	testCases := []struct {
		name            string
		verStatus       VerificationStatus
		detectionStatus string
		expectedLevel   string // Score is 20 -> base band is "LOW"
		shouldAnchor    bool
	}{
		{
			name:            "EmptyStatus_MissingDetectionStatus",
			verStatus:       "",
			detectionStatus: "",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "EmptyStatus_DetectedDetectionStatus",
			verStatus:       "",
			detectionStatus: "DETECTED",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "EmptyStatus_NotVerifiedDetectionStatus",
			verStatus:       "",
			detectionStatus: "NOT_VERIFIED",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "EmptyStatus_ObservedDetectionStatus",
			verStatus:       "",
			detectionStatus: "OBSERVED",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "EmptyStatus_NotExposedDetectionStatus",
			verStatus:       "",
			detectionStatus: "NOT_EXPOSED",
			expectedLevel:   "INFORMATIONAL", // Contributes 0 score
			shouldAnchor:    false,
		},
		{
			name:            "EmptyStatus_VerifiedDetectionStatus_LegacyFallback",
			verStatus:       "",
			detectionStatus: "VERIFIED",
			expectedLevel:   "CRITICAL", // Legacy schema fallback anchors
			shouldAnchor:    true,
		},
		{
			name:            "ExplicitVerifiedStatus",
			verStatus:       VerificationVerified,
			detectionStatus: "DETECTED", // Canonical status takes precedence
			expectedLevel:   "CRITICAL",
			shouldAnchor:    true,
		},
		{
			name:            "ExplicitDetectedStatus_OverridesLegacyVerified",
			verStatus:       VerificationDetected,
			detectionStatus: "VERIFIED", // Canonical status DETECTED takes precedence over legacy
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "ExplicitNotVerifiedStatus_OverridesLegacyVerified",
			verStatus:       VerificationNotVerified,
			detectionStatus: "VERIFIED",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "ExplicitObservedStatus_OverridesLegacyVerified",
			verStatus:       VerificationObserved,
			detectionStatus: "VERIFIED",
			expectedLevel:   "LOW",
			shouldAnchor:    false,
		},
		{
			name:            "ExplicitNotExposedStatus_OverridesLegacyVerified",
			verStatus:       VerificationNotExposed,
			detectionStatus: "VERIFIED",
			expectedLevel:   "INFORMATIONAL",
			shouldAnchor:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			f := Finding{
				ID:         "TEST-" + tc.name,
				Category:   "env-exposure",
				Severity:   SeverityCritical,
				Confidence: ConfidenceHigh,
				Score:      20, // Low band score (20-34)
				Verification: VerificationRecord{
					Status: tc.verStatus,
				},
				EvidenceDetails: EvidenceDetails{
					DetectionStatus: tc.detectionStatus,
				},
			}

			score, level := CalculateReportRisk([]Finding{f}, nil)
			if tc.verStatus == VerificationNotExposed || tc.detectionStatus == "NOT_EXPOSED" {
				if score != 0 {
					t.Errorf("NOT_EXPOSED finding produced score %d (expected 0)", score)
				}
			}
			if level != tc.expectedLevel {
				t.Errorf("%s: risk level %s does not match expected %s (shouldAnchor=%v)",
					tc.name, level, tc.expectedLevel, tc.shouldAnchor)
			}
		})
	}
}

// TestAttackPath_MalformedScoresAndCategoriesSafelyNormalized verifies that attack path scores
// entering RecalculateReportRisk are safely clamped to [0, 100], and malformed or inflated categories
// cannot escalate report risk beyond what the verified score justifies.
func TestAttackPath_MalformedScoresAndCategoriesSafelyNormalized(t *testing.T) {
	t.Run("ScoreExceedingCeilingClampedTo100", func(t *testing.T) {
		rep := BuildReport("https://example.com", nil)
		path := AttackPathSummary{
			ID:                "AP-EXCEED",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: 150, // Malformed score > 100
			CombinedRiskLevel: "CRITICAL",
		}
		AttachAttackPaths(&rep, []AttackPathSummary{path})

		if rep.RiskScore != 100 {
			t.Errorf("expected score clamped to 100, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "CRITICAL" {
			t.Errorf("expected level CRITICAL, got %s", rep.RiskLevel)
		}
		if rep.CommercialReport.RiskOverview.RiskScore != 100 {
			t.Errorf("commercial report risk score not clamped: %d", rep.CommercialReport.RiskOverview.RiskScore)
		}
	})

	t.Run("NegativeScoreClampedToZero", func(t *testing.T) {
		rep := BuildReport("https://example.com", nil)
		path := AttackPathSummary{
			ID:                "AP-NEG",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: -50, // Malformed negative score
			CombinedRiskLevel: "CRITICAL",
		}
		AttachAttackPaths(&rep, []AttackPathSummary{path})

		if rep.RiskScore != 0 {
			t.Errorf("expected score 0, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("expected level INFORMATIONAL, got %s", rep.RiskLevel)
		}
	})

	t.Run("InflatedCategoryClampedToScoreBand", func(t *testing.T) {
		// A verified path has score 25 (which is LOW: 20-39), but claims CRITICAL in saved data.
		// RecalculateReportRisk must NOT allow this path to inflate the assessment to CRITICAL.
		rep := BuildReport("https://example.com", nil)
		path := AttackPathSummary{
			ID:                "AP-INFLATED",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: 25,         // Low band (20-39)
			CombinedRiskLevel: "CRITICAL", // Tampered/inflated category
		}
		AttachAttackPaths(&rep, []AttackPathSummary{path})

		if rep.RiskScore != 25 {
			t.Errorf("expected score 25, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "LOW" {
			t.Errorf("inflated category not clamped to score band! Got %s (expected LOW)", rep.RiskLevel)
		}
		if rep.CommercialReport.RiskOverview.RiskLevel != "LOW" {
			t.Errorf("commercial report risk level inflated: %s", rep.CommercialReport.RiskOverview.RiskLevel)
		}
	})

	t.Run("OmittedCategorySafelyDerivedFromScoreBand", func(t *testing.T) {
		rep := BuildReport("https://example.com", nil)
		path := AttackPathSummary{
			ID:                "AP-NO-CAT",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: 65, // HIGH band (60-79)
			CombinedRiskLevel: "", // Omitted
		}
		AttachAttackPaths(&rep, []AttackPathSummary{path})

		if rep.RiskScore != 65 {
			t.Errorf("expected score 65, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "HIGH" {
			t.Errorf("expected level HIGH derived from score band, got %s", rep.RiskLevel)
		}
	})

	t.Run("UnverifiedStatusContributesZeroEscalation", func(t *testing.T) {
		f := Finding{
			ID:           "F1",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Score:        5,
			Verification: VerificationRecord{Status: VerificationVerified},
		}
		rep := BuildReport("https://example.com", []Finding{f})
		candidatePath := AttackPathSummary{
			ID:                "AP-CAND",
			Status:            "CANDIDATE",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: 90,
			CombinedRiskLevel: "CRITICAL",
		}
		AttachAttackPaths(&rep, []AttackPathSummary{candidatePath})

		if rep.RiskScore != 5 || rep.RiskLevel != "LOW" {
			t.Errorf("unverified candidate path escalated assessment risk: (%d, %s)", rep.RiskScore, rep.RiskLevel)
		}
	})

	t.Run("LowConfidenceVerifiedPathContributesZeroEscalation", func(t *testing.T) {
		rep := BuildReport("https://example.com", nil)
		lowConfPath := AttackPathSummary{
			ID:                "AP-LOWCONF",
			Status:            "VERIFIED",
			Confidence:        ConfidenceLow,
			CombinedRiskScore: 90,
			CombinedRiskLevel: "CRITICAL",
		}
		AttachAttackPaths(&rep, []AttackPathSummary{lowConfPath})

		if rep.RiskScore != 0 || rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("low confidence path escalated assessment risk: (%d, %s)", rep.RiskScore, rep.RiskLevel)
		}
	})
}

// TestDeduplication_IdenticalFindingsDoNotInflateScore verifies that duplicate findings
// are merged into a canonical entry without inflating the overall assessment risk score.
func TestDeduplication_IdenticalFindingsDoNotInflateScore(t *testing.T) {
	t.Run("IdenticalFindingsMergedAndScoreCountedOnce", func(t *testing.T) {
		fp := ComputeFingerprint("https://example.com", "missing-csp", "/index.html", "GET", "")
		baseFinding := Finding{
			ID:          "F-CSP",
			Title:       "Missing Content Security Policy",
			Category:    "missing-csp",
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Target:      "https://example.com",
			Endpoint:    "/index.html",
			Method:      "GET",
			Fingerprint: fp,
			Score:       5,
			Verification: VerificationRecord{
				Status: VerificationVerified,
				Result: "Verified header missing",
			},
			Evidence: "CSP header is not set",
		}

		// Create 5 identical findings
		findings := make([]Finding, 5)
		for i := 0; i < 5; i++ {
			findings[i] = baseFinding
		}

		deduped := DeduplicateFindings(findings)
		if len(deduped) != 1 {
			t.Fatalf("expected 5 duplicate findings to be merged into 1, got %d", len(deduped))
		}

		// When built into report, score must be 5 (not 5 * 5 = 25 or diminished 5+2.5+1.5... = 10)
		rep := BuildReport("https://example.com", findings)
		if rep.RiskScore != 5 {
			t.Errorf("duplicate findings inflated report score: expected 5, got %d", rep.RiskScore)
		}
		if len(rep.Findings) != 1 {
			t.Errorf("expected 1 finding in built report, got %d", len(rep.Findings))
		}
	})

	t.Run("EvidenceMergingAndPrecedence", func(t *testing.T) {
		fp := ComputeFingerprint("https://example.com", "env-exposure", "/.env", "GET", "")
		f1 := Finding{
			Target:      "https://example.com",
			Category:    "env-exposure",
			Endpoint:    "/.env",
			Method:      "GET",
			Fingerprint: fp,
			Severity:    SeverityMedium,
			Confidence:  ConfidenceMedium,
			Verification: VerificationRecord{Status: VerificationDetected},
			Evidence:    "Found DB_PASSWORD",
		}
		f2 := Finding{
			Target:      "https://example.com",
			Category:    "env-exposure",
			Endpoint:    "/.env",
			Method:      "GET",
			Fingerprint: fp,
			Severity:    SeverityHigh,
			Confidence:  ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationVerified},
			Evidence:    "Found AWS_SECRET_ACCESS_KEY",
		}

		deduped := DeduplicateFindings([]Finding{f1, f2})
		if len(deduped) != 1 {
			t.Fatalf("expected 1 merged finding, got %d", len(deduped))
		}
		res := deduped[0]
		// Retained highest severity (HIGH)
		if res.Severity != SeverityHigh {
			t.Errorf("expected highest severity HIGH, got %s", res.Severity)
		}
		// Retained highest verification status (VERIFIED)
		if res.Verification.Status != VerificationVerified {
			t.Errorf("expected highest verification status VERIFIED, got %s", res.Verification.Status)
		}
		// Merged evidence strings
		if !strings.Contains(res.Evidence, "DB_PASSWORD") || !strings.Contains(res.Evidence, "AWS_SECRET_ACCESS_KEY") {
			t.Errorf("evidence not merged properly: %s", res.Evidence)
		}
	})
}

// TestConsistency_ScanTimeAndReportTimeScoringIdentical verifies that scan-time calculations
// and report-time deserialization and recomputation produce identical risk scores, risk levels,
// and commercial presentation fields across the complete data lifecycle.
func TestConsistency_ScanTimeAndReportTimeScoringIdentical(t *testing.T) {
	findings := []Finding{
		{
			ID:          "F-ENV",
			Title:       "Environment Variable Exposure",
			Category:    "env-exposure",
			Severity:    SeverityHigh,
			Confidence:  ConfidenceHigh,
			Target:      "https://target.com",
			Endpoint:    "/.env",
			Method:      "GET",
			Fingerprint: "fp-env-01",
			Score:       25,
			Verification: VerificationRecord{
				Status: VerificationVerified,
				Result: "Confirmed active credentials in response",
			},
		},
		{
			ID:          "F-CSP",
			Title:       "Missing Content Security Policy",
			Category:    "missing-csp",
			Severity:    SeverityLow,
			Confidence:  ConfidenceHigh,
			Target:      "https://target.com",
			Endpoint:    "/",
			Method:      "GET",
			Fingerprint: "fp-csp-01",
			Score:       5,
			Verification: VerificationRecord{
				Status: VerificationVerified,
				Result: "Confirmed CSP header absent",
			},
		},
	}

	stories := []SecurityStory{
		{
			ID:               "STORY-CRED-LEAK",
			Title:            "Credential Leak Pipeline",
			RiskContribution: 5,
		},
	}

	attackPaths := []AttackPathSummary{
		{
			ID:                "AP-01",
			Title:             "Direct Credential Extraction",
			Status:            "VERIFIED",
			Confidence:        ConfidenceHigh,
			CombinedRiskScore: 45,
			CombinedRiskLevel: "MEDIUM",
		},
	}

	// 1. Build initial scan-time report
	rep := BuildReport("https://target.com", findings)
	AttachSecurityStories(&rep, stories)
	AttachAttackPaths(&rep, attackPaths)

	scanTimeScore := rep.RiskScore
	scanTimeLevel := rep.RiskLevel
	scanTimeOverviewScore := rep.CommercialReport.RiskOverview.RiskScore
	scanTimeOverviewLevel := rep.CommercialReport.RiskOverview.RiskLevel
	scanTimeExecScore := rep.CommercialReport.ExecutiveSummary.RiskScore
	scanTimeExecLevel := rep.CommercialReport.ExecutiveSummary.RiskLevel

	// 2. Serialize to JSON
	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}

	// 3. Deserialize and recompute via RecalculateReportRisk
	deserialized, err := ParseReport(jsonBytes)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}
	RecalculateReportRisk(&deserialized)

	// 4. Verify all fields match 100%
	if deserialized.RiskScore != scanTimeScore {
		t.Errorf("RiskScore mismatch: scan-time=%d vs recalculated=%d", scanTimeScore, deserialized.RiskScore)
	}
	if deserialized.RiskLevel != scanTimeLevel {
		t.Errorf("RiskLevel mismatch: scan-time=%s vs recalculated=%s", scanTimeLevel, deserialized.RiskLevel)
	}
	if deserialized.CommercialReport == nil {
		t.Fatalf("CommercialReport is nil on deserialized report")
	}
	if deserialized.CommercialReport.RiskOverview.RiskScore != scanTimeOverviewScore {
		t.Errorf("RiskOverview.RiskScore mismatch: %d vs %d", scanTimeOverviewScore, deserialized.CommercialReport.RiskOverview.RiskScore)
	}
	if deserialized.CommercialReport.RiskOverview.RiskLevel != scanTimeOverviewLevel {
		t.Errorf("RiskOverview.RiskLevel mismatch: %s vs %s", scanTimeOverviewLevel, deserialized.CommercialReport.RiskOverview.RiskLevel)
	}
	if deserialized.CommercialReport.ExecutiveSummary.RiskScore != scanTimeExecScore {
		t.Errorf("ExecutiveSummary.RiskScore mismatch: %d vs %d", scanTimeExecScore, deserialized.CommercialReport.ExecutiveSummary.RiskScore)
	}
	if deserialized.CommercialReport.ExecutiveSummary.RiskLevel != scanTimeExecLevel {
		t.Errorf("ExecutiveSummary.RiskLevel mismatch: %s vs %s", scanTimeExecLevel, deserialized.CommercialReport.ExecutiveSummary.RiskLevel)
	}

	// 5. Test idempotence across repeated recalculations
	for cycle := 1; cycle <= 3; cycle++ {
		RecalculateReportRisk(&deserialized)
		if deserialized.RiskScore != scanTimeScore || deserialized.RiskLevel != scanTimeLevel {
			t.Fatalf("recalculation idempotence failed on cycle %d: (%d, %s)",
				cycle, deserialized.RiskScore, deserialized.RiskLevel)
		}
	}
}
