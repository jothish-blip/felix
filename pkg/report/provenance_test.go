package report

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/secrets"
)

// 1. Evidence provenance construction and metadata validation
func TestEvidenceProvenance_ConstructionAndValidation(t *testing.T) {
	prov := NewEvidenceProvenance(
		SourceAPI,
		"API-REST-AUTH",
		"fnd_1234567890abcdef",
		"ast_abcdef123456",
		"http_response",
		"https://api.example.com/v1/users",
		"active_probe",
		"HTTP 200 OK with unauthorized user profile",
	)

	if err := ValidateEvidenceProvenance(prov); err != nil {
		t.Fatalf("ValidateEvidenceProvenance failed: %v", err)
	}

	if !strings.HasPrefix(prov.EvidenceID, "ev_") {
		t.Errorf("expected EvidenceID to start with 'ev_', got: %s", prov.EvidenceID)
	}
	if prov.SourceEngine != SourceAPI {
		t.Errorf("expected SourceEngine %s, got: %s", SourceAPI, prov.SourceEngine)
	}
	if prov.RuleID != "API-REST-AUTH" {
		t.Errorf("expected RuleID API-REST-AUTH, got: %s", prov.RuleID)
	}
	if prov.FindingID != "fnd_1234567890abcdef" {
		t.Errorf("expected FindingID fnd_1234567890abcdef, got: %s", prov.FindingID)
	}
	if prov.AssetID != "ast_abcdef123456" {
		t.Errorf("expected AssetID ast_abcdef123456, got: %s", prov.AssetID)
	}
	if !strings.HasPrefix(prov.ContentDigest, "sha256:") {
		t.Errorf("expected ContentDigest with sha256: prefix, got: %s", prov.ContentDigest)
	}
}

// 2. Safe Content Digest strictly hashes sanitized evidence to prevent secret leakage via digests
func TestEvidenceProvenance_SafeContentDigestOverSanitizedContent(t *testing.T) {
	rawSecretEvidence := "Authorization: Bearer secret_super_token_1234567890 and password=super_secret_pass"
	sanitizedEvidence := secrets.RedactText(rawSecretEvidence)

	digest := ComputeContentDigest(rawSecretEvidence)
	sanitizedDigest := ComputeContentDigest(sanitizedEvidence)

	// Digest of raw secret evidence MUST match digest of already sanitized evidence
	if digest != sanitizedDigest {
		t.Errorf("ComputeContentDigest did not sanitize raw evidence before hashing: got %s vs %s", digest, sanitizedDigest)
	}

	// Raw secret MUST NOT be contained in the digest
	if strings.Contains(digest, "secret_super_token") || strings.Contains(digest, "super_secret_pass") {
		t.Errorf("digest leaked raw secret: %s", digest)
	}
}

// 3. Engine adapters attach structured provenance metadata
func TestEvidenceProvenance_EngineAdapters(t *testing.T) {
	target := "https://example.com"

	// Secrets Engine adapter
	secFinding := secrets.SecretFinding{
		Type:        secrets.SecretStripeLiveKey,
		Title:       "Exposed Stripe API Key",
		FileOrigin:  "https://example.com/assets/app.js",
		LineNumber:  42,
		Redacted:    "sk_live_[REDACTED]",
		Evidence:    "const key = '" + "sk_live_" + "1234567890abcdef';",
		Fingerprint: "fp-sec-123",
		Severity:    secrets.SeverityCritical,
		Confidence:  secrets.ConfidenceHigh,
	}
	rfSec := FromSecretFinding(target, secFinding)
	if rfSec.Provenance == nil {
		t.Fatal("expected FromSecretFinding to attach Provenance")
	}
	if rfSec.Provenance.SourceEngine != SourceSecrets {
		t.Errorf("expected SourceSecrets, got: %s", rfSec.Provenance.SourceEngine)
	}
	if rfSec.Provenance.EvidenceType != "secret_pattern" {
		t.Errorf("expected secret_pattern, got: %s", rfSec.Provenance.EvidenceType)
	}
	if rfSec.EvidenceDetails.Provenance == nil {
		t.Fatal("expected EvidenceDetails.Provenance to be populated")
	}

	// Cloud Engine adapter
	cldFinding := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "unauthorized-data-exposure",
		Endpoint:    "https://xyz.supabase.co/rest/v1/users",
		Description: "Unauthenticated table read returned records",
		Evidence:    "[{\"id\": 1, \"name\": \"admin\"}]",
		Fingerprint: "fp-cld-123",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
	}
	rfCld := FromCloudFinding(target, cldFinding)
	if rfCld.Provenance == nil {
		t.Fatal("expected FromCloudFinding to attach Provenance")
	}
	if rfCld.Provenance.SourceEngine != SourceCloud {
		t.Errorf("expected SourceCloud, got: %s", rfCld.Provenance.SourceEngine)
	}
	if rfCld.Provenance.EvidenceType != "cloud_resource" {
		t.Errorf("expected cloud_resource, got: %s", rfCld.Provenance.EvidenceType)
	}

	// API Engine adapter
	apiFinding := api.APIFinding{
		Category:    "cors-origin-reflection",
		Endpoint:    "https://example.com/api/v1/profile",
		Method:      "GET",
		Description: "Reflected origin with Access-Control-Allow-Credentials",
		Evidence:    "Access-Control-Allow-Origin: evil.com",
		Fingerprint: "fp-api-123",
		Severity:    api.SeverityHigh,
		Confidence:  api.ConfidenceHigh,
	}
	rfAPI := FromAPIFinding(target, apiFinding)
	if rfAPI.Provenance == nil {
		t.Fatal("expected FromAPIFinding to attach Provenance")
	}
	if rfAPI.Provenance.SourceEngine != SourceAPI {
		t.Errorf("expected SourceAPI, got: %s", rfAPI.Provenance.SourceEngine)
	}
	if rfAPI.Provenance.EvidenceType != "http_response" {
		t.Errorf("expected http_response, got: %s", rfAPI.Provenance.EvidenceType)
	}

	// Crawler Engine adapter (source map)
	crwAsset := crawler.Asset{
		URL:         "https://example.com/bundle.js.map",
		Type:        crawler.AssetSourceMap,
		Size:        10240,
		IsSourceMap: true,
	}
	rfCrw, ok := FromCrawlerAsset(target, crwAsset)
	if !ok {
		t.Fatal("expected FromCrawlerAsset to return finding for source map")
	}
	if rfCrw.Provenance == nil {
		t.Fatal("expected FromCrawlerAsset to attach Provenance")
	}
	if rfCrw.Provenance.SourceEngine != SourceCrawler {
		t.Errorf("expected SourceCrawler, got: %s", rfCrw.Provenance.SourceEngine)
	}
	if rfCrw.Provenance.EvidenceType != "client_asset" {
		t.Errorf("expected client_asset, got: %s", rfCrw.Provenance.EvidenceType)
	}
}

// 4. ResolveAssetIDs propagates resolved AssetID to Provenance
func TestEvidenceProvenance_AssetIDPropagation(t *testing.T) {
	inv := &discovery.Inventory{
		Assets: []discovery.Asset{
			{
				ID:          "ast_endpoint_999",
				Type:        discovery.AssetTypeEndpoint,
				CanonicalID: "https://example.com/api/users",
				Endpoint: &discovery.EndpointDetails{
					URL:  "https://example.com/api/users",
					Path: "/api/users",
				},
			},
		},
	}

	f := Finding{
		ID:       "fnd_test_01",
		RuleID:   "API-TEST",
		Target:   "https://example.com",
		Endpoint: "https://example.com/api/users",
		Method:   "GET",
		Category: "api-test",
		Source:   SourceAPI,
	}
	f = NormalizeFinding(f)
	if f.Provenance.AssetID != "" {
		t.Fatalf("expected empty initial AssetID, got: %s", f.Provenance.AssetID)
	}

	f.ResolveAssetIDs(inv)

	if f.PrimaryAssetID != "ast_endpoint_999" {
		t.Fatalf("expected PrimaryAssetID ast_endpoint_999, got: %s", f.PrimaryAssetID)
	}
	if f.Provenance.AssetID != "ast_endpoint_999" {
		t.Errorf("expected Provenance.AssetID to be updated to ast_endpoint_999, got: %s", f.Provenance.AssetID)
	}
	if f.EvidenceDetails.Provenance.AssetID != "ast_endpoint_999" {
		t.Errorf("expected EvidenceDetails.Provenance.AssetID to be updated to ast_endpoint_999, got: %s", f.EvidenceDetails.Provenance.AssetID)
	}
}

// 5. Deduplication merges provenance context without losing provenance identity
func TestEvidenceProvenance_Deduplication(t *testing.T) {
	f1 := Finding{
		ID:       "FND-DEDUP-01",
		RuleID:   "API-CORS",
		Title:    "CORS Issue",
		Category: "cors-wildcard",
		Severity: SeverityInfo,
		Target:   "https://example.com",
		Endpoint: "https://example.com/api/v1",
		Method:   "GET",
		Evidence: "Origin 1 observed",
		Provenance: &EvidenceProvenance{
			EvidenceID:   "ev_first",
			SourceEngine: SourceAPI,
			RuleID:       "API-CORS",
			FindingID:    "FND-DEDUP-01",
			AssetID:      "ast_111",
		},
	}

	f2 := Finding{
		ID:       "FND-DEDUP-01",
		RuleID:   "API-CORS",
		Title:    "CORS Issue",
		Category: "cors-wildcard",
		Severity: SeverityInfo,
		Target:   "https://example.com",
		Endpoint: "https://example.com/api/v1",
		Method:   "GET",
		Evidence: "Origin 2 observed",
		Provenance: &EvidenceProvenance{
			EvidenceID:          "ev_second",
			SourceEngine:        SourceAPI,
			RuleID:              "API-CORS",
			FindingID:           "FND-DEDUP-01",
			VerificationContext: "curl -H 'Origin: test.com' https://example.com/api/v1",
		},
	}

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected 1 finding after dedup, got %d", len(deduped))
	}

	merged := deduped[0]
	if merged.Provenance == nil {
		t.Fatal("expected merged finding to retain Provenance")
	}
	if merged.Provenance.AssetID != "ast_111" {
		t.Errorf("expected merged Provenance.AssetID to retain ast_111, got: %s", merged.Provenance.AssetID)
	}
	if merged.Provenance.VerificationContext != "curl -H 'Origin: test.com' https://example.com/api/v1" {
		t.Errorf("expected merged Provenance to contain VerificationContext, got: %s", merged.Provenance.VerificationContext)
	}
}

// 6. Comprehensive redaction across sensitive types in report outputs (JSON, SARIF)
func TestEvidenceProvenance_RedactionInOutputs(t *testing.T) {
	rawSecretURL := "https://admin:super_secret_pass@example.com/api?token=" + "sk_live_" + "1234567890abcdef&ssn=123-45-6789&key=my_api_key&page=1"
	f := Finding{
		ID:       "fnd_sensitive_leak_test",
		RuleID:   "SEC-PATTERN",
		Title:    "Found password=topsecret123 in URL",
		Category: "secret-leak",
		Severity: SeverityCritical,
		Target:   rawSecretURL,
		Endpoint: rawSecretURL,
		Method:   "GET",
		Evidence: "Authorization: Bearer secret_jwt_token_here with SSN 987-65-4321 and db_password=dbsecret",
		Provenance: &EvidenceProvenance{
			EvidenceID:          "ev_test_sensitive",
			SourceEngine:        SourceAPI,
			Location:            rawSecretURL,
			VerificationContext: "Database URL: postgres://user:pgpassword@localhost:5432/app",
		},
		EvidenceDetails: EvidenceDetails{
			Observation: "redis://:redissecret@localhost:6379",
			Location:    rawSecretURL,
			Details: map[string]string{
				"password":    "plaintext_leak",
				"api_key":     "super_api_key",
				"safe_metric": "count=42",
			},
		},
	}

	sanitized := SanitizeFinding(f)

	// Verify URL UserInfo and Query Params redaction
	if strings.Contains(sanitized.Target, "super_secret_pass") {
		t.Errorf("Target leaked password in userinfo: %s", sanitized.Target)
	}
	if strings.Contains(sanitized.Target, "sk_live_1234567890abcdef") {
		t.Errorf("Target leaked token in query: %s", sanitized.Target)
	}
	if strings.Contains(sanitized.Target, "123-45-6789") {
		t.Errorf("Target leaked SSN in query: %s", sanitized.Target)
	}
	if strings.Contains(sanitized.Target, "my_api_key") {
		t.Errorf("Target leaked key in query: %s", sanitized.Target)
	}
	if !strings.Contains(sanitized.Target, "page=1") {
		t.Errorf("Target unexpectedly stripped safe parameter page=1: %s", sanitized.Target)
	}

	// Verify Provenance location and verification context redaction
	if strings.Contains(sanitized.Provenance.Location, "super_secret_pass") {
		t.Errorf("Provenance.Location leaked userinfo password: %s", sanitized.Provenance.Location)
	}
	if strings.Contains(sanitized.Provenance.VerificationContext, "pgpassword") {
		t.Errorf("Provenance.VerificationContext leaked postgres password: %s", sanitized.Provenance.VerificationContext)
	}

	// Verify Evidence Details map redaction
	if sanitized.EvidenceDetails.Details["password"] != "[REDACTED]" {
		t.Errorf("EvidenceDetails.Details[password] was not redacted: %s", sanitized.EvidenceDetails.Details["password"])
	}
	if sanitized.EvidenceDetails.Details["api_key"] != "[REDACTED]" {
		t.Errorf("EvidenceDetails.Details[api_key] was not redacted: %s", sanitized.EvidenceDetails.Details["api_key"])
	}
	if sanitized.EvidenceDetails.Details["safe_metric"] != "count=42" {
		t.Errorf("EvidenceDetails.Details[safe_metric] was corrupted: %s", sanitized.EvidenceDetails.Details["safe_metric"])
	}

	// Verify JSON serialization round-trip
	rep := Report{
		Version:   "2.0.0",
		Target:    "https://example.com",
		Timestamp: "2026-10-15T12:00:00Z",
		Findings:  []Finding{sanitized},
	}
	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)
	for _, secretToken := range []string{"super_secret_pass", "sk_live_1234567890abcdef", "123-45-6789", "987-65-4321", "topsecret123", "redissecret", "pgpassword", "plaintext_leak", "super_api_key"} {
		if strings.Contains(jsonStr, secretToken) {
			t.Errorf("GenerateJSON leaked secret token %q in serialized JSON: %s", secretToken, jsonStr)
		}
	}

	// Verify SARIF output serialization
	sarifLog, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("Marshal SARIF failed: %v", err)
	}
	sarifStr := string(sarifBytes)
	for _, secretToken := range []string{"super_secret_pass", "sk_live_1234567890abcdef", "123-45-6789", "987-65-4321", "topsecret123", "redissecret", "pgpassword", "plaintext_leak", "super_api_key"} {
		if strings.Contains(sarifStr, secretToken) {
			t.Errorf("GenerateSARIF leaked secret token %q in serialized SARIF: %s", secretToken, sarifStr)
		}
	}
}

// 7. Error sanitization and wrapping
func TestEvidenceProvenance_ErrorRedaction(t *testing.T) {
	rawErr := errors.New("connection failed to postgres://app_user:db_secret_pass_999@db.internal:5432/main with token=tok_abc123")
	wrapped := secrets.WrapSanitizedError(rawErr)
	if wrapped == nil {
		t.Fatal("expected non-nil wrapped error")
	}
	errMsg := wrapped.Error()
	if strings.Contains(errMsg, "db_secret_pass_999") {
		t.Errorf("WrapSanitizedError leaked password: %s", errMsg)
	}
	if strings.Contains(errMsg, "tok_abc123") {
		t.Errorf("WrapSanitizedError leaked token: %s", errMsg)
	}
}
