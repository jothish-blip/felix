package test

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"felix/pkg/correlation"
	"felix/pkg/discovery"
	"felix/pkg/report"
)

// =============================================================================
// PHASE 6.2: FINDING & ASSET CORRELATION — COMPREHENSIVE REGRESSION SUITE
// Deterministic Relationships, Asset Identity & Evidence-Based Grouping
// 28 Strict Verification Categories
// =============================================================================

func helperMakeFinding(id, title, category, severity, confidence string, status report.VerificationStatus, target, endpoint, method string) report.Finding {
	f := report.Finding{
		ID:         id,
		Title:      title,
		Category:   category,
		Severity:   severity,
		Confidence: confidence,
		Target:     target,
		Endpoint:   endpoint,
		Method:     method,
		Verification: report.VerificationRecord{
			Status: status,
		},
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"route": endpoint,
			},
		},
	}
	f.Score = report.CalculateFindingScore(f)
	return f
}

// -----------------------------------------------------------------------------
// Category 1: Scheme Lowercasing & Default Port Stripping
// -----------------------------------------------------------------------------
func TestCorrelation_Category01_SchemeAndDefaultPort(t *testing.T) {
	cases := []struct {
		rawURL         string
		expectedOrigin string
		expectedPath   string
	}{
		{"http://example.com:80/api/users", "http://example.com", "/api/users"},
		{"HTTP://EXAMPLE.COM:80/api/users", "http://example.com", "/api/users"},
		{"https://example.com:443/api/users", "https://example.com", "/api/users"},
		{"HTTPS://Example.Com:443/api/users", "https://example.com", "/api/users"},
		{"https://example.com:8443/api/users", "https://example.com:8443", "/api/users"},
		{"http://example.com:8080/api/users", "http://example.com:8080", "/api/users"},
		{"https://example.com./api/users", "https://example.com", "/api/users"},
	}

	for _, tc := range cases {
		canon, err := correlation.CanonicalizeURL(tc.rawURL)
		if err != nil {
			t.Fatalf("CanonicalizeURL(%q) failed: %v", tc.rawURL, err)
		}
		if canon.Origin != tc.expectedOrigin {
			t.Errorf("CanonicalizeURL(%q).Origin = %q, expected %q", tc.rawURL, canon.Origin, tc.expectedOrigin)
		}
		if canon.Path != tc.expectedPath {
			t.Errorf("CanonicalizeURL(%q).Path = %q, expected %q", tc.rawURL, canon.Path, tc.expectedPath)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 2: Relative Path Traversals, Duplicate Slashes & Non-Root Trailing Slashes
// -----------------------------------------------------------------------------
func TestCorrelation_Category02_PathCleaning(t *testing.T) {
	cases := []struct {
		rawURL       string
		expectedPath string
	}{
		{"https://example.com/a/b/../c/./d", "/a/c/d"},
		{"https://example.com//multiple///slashes//here", "/multiple/slashes/here"},
		{"https://example.com/api/v1/users/", "/api/v1/users/"},
		{"https://example.com/api/v1/users", "/api/v1/users"},
		{"https://example.com/", "/"},
		{"https://example.com", "/"},
	}

	for _, tc := range cases {
		canon, err := correlation.CanonicalizeURL(tc.rawURL)
		if err != nil {
			t.Fatalf("CanonicalizeURL(%q) failed: %v", tc.rawURL, err)
		}
		if canon.Path != tc.expectedPath {
			t.Errorf("CanonicalizeURL(%q).Path = %q, expected %q", tc.rawURL, canon.Path, tc.expectedPath)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 3: Sensitive Query Parameter Redaction & Deterministic Sorting
// -----------------------------------------------------------------------------
func TestCorrelation_Category03_QueryRedactionAndSorting(t *testing.T) {
	raw := "https://example.com/api?z=last&token=SECRET_JWT_123&a=first&api_key=SECRET_KEY_456&sig=SIGNATURE#frag-to-drop"
	canon, err := correlation.CanonicalizeURL(raw)
	if err != nil {
		t.Fatalf("CanonicalizeURL failed: %v", err)
	}

	if strings.Contains(canon.Endpoint, "SECRET_JWT_123") {
		t.Errorf("sensitive token parameter value was not redacted: %s", canon.Endpoint)
	}
	if strings.Contains(canon.Endpoint, "SECRET_KEY_456") {
		t.Errorf("sensitive api_key parameter value was not redacted: %s", canon.Endpoint)
	}
	if strings.Contains(canon.Endpoint, "#frag-to-drop") {
		t.Errorf("fragment was not stripped: %s", canon.Endpoint)
	}

	expectedDisplayQuery := "a=first&api_key=REDACTED&sig=REDACTED&token=REDACTED&z=last"
	if canon.DisplayQuery != expectedDisplayQuery {
		t.Errorf("expected sorted and display-redacted query %q, got %q", expectedDisplayQuery, canon.DisplayQuery)
	}

	if strings.Contains(canon.Query, "SECRET_JWT_123") || strings.Contains(canon.Query, "SECRET_KEY_456") {
		t.Errorf("raw secret leaked in canon.Query: %s", canon.Query)
	}
	if !strings.Contains(canon.Query, "token=REDACTED_") || !strings.Contains(canon.Query, "api_key=REDACTED_") {
		t.Errorf("expected token hash in canon.Query, got %s", canon.Query)
	}
}

// -----------------------------------------------------------------------------
// Category 4: Cloud Storage Asset Identification (S3, GCS, Azure Blob)
// -----------------------------------------------------------------------------
func TestCorrelation_Category04_CloudStorageAssets(t *testing.T) {
	fS3 := helperMakeFinding("S3-01", "Open AWS S3 Bucket", "s3-bucket-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://finance-data-bucket/export.csv", "s3://finance-data-bucket/export.csv", "GET")
	assetS3, assocS3 := correlation.ResolveFindingAsset(fS3, nil)
	if assetS3.Type != discovery.AssetTypeStorage || assetS3.CanonicalKey != "storage:aws_s3:finance-data-bucket" {
		t.Errorf("unexpected S3 asset: %+v", assetS3)
	}
	if !assocS3.IsExact || assocS3.Basis != "CLOUD_STORAGE_RESOURCE" {
		t.Errorf("unexpected S3 association: %+v", assocS3)
	}

	fGCS := helperMakeFinding("GCS-01", "Public GCP Storage Bucket", "gcs-public-access", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "gs://gcp-backup-archive/db.dump", "gs://gcp-backup-archive/db.dump", "GET")
	assetGCS, assocGCS := correlation.ResolveFindingAsset(fGCS, nil)
	if assetGCS.Type != discovery.AssetTypeStorage || assetGCS.CanonicalKey != "storage:gcp_storage:gcp-backup-archive" {
		t.Errorf("unexpected GCS asset: %+v", assetGCS)
	}
	if !assocGCS.IsExact {
		t.Errorf("GCS association should be exact")
	}

	fAzure := helperMakeFinding("AZ-01", "Public Azure Blob Container", "azure-blob-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://mycorp.blob.core.windows.net/public-docs/file.pdf", "https://mycorp.blob.core.windows.net/public-docs/file.pdf", "GET")
	assetAzure, assocAzure := correlation.ResolveFindingAsset(fAzure, nil)
	if assetAzure.Type != discovery.AssetTypeStorage || !strings.Contains(assetAzure.CanonicalKey, "azure_blob") {
		t.Errorf("unexpected Azure asset: %+v", assetAzure)
	}
	if !assocAzure.IsExact {
		t.Errorf("Azure association should be exact")
	}
}

// -----------------------------------------------------------------------------
// Category 5: Cloud Database Asset Identification (Supabase, Firebase, Relational)
// -----------------------------------------------------------------------------
func TestCorrelation_Category05_CloudDatabaseAssets(t *testing.T) {
	fSupa := helperMakeFinding("DB-01", "Supabase Anon Key Exposure", "supabase-exposure", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://xyzprojectid.supabase.co/rest/v1/records", "https://xyzprojectid.supabase.co/rest/v1/records", "GET")
	assetSupa, assocSupa := correlation.ResolveFindingAsset(fSupa, nil)
	if assetSupa.Type != discovery.AssetTypeDatabase || assetSupa.CanonicalKey != "database:supabase_postgres:xyzprojectid" {
		t.Errorf("unexpected Supabase asset: %+v", assetSupa)
	}
	if !assocSupa.IsExact || assocSupa.Confidence != report.ConfidenceHigh {
		t.Errorf("unexpected Supabase association: %+v", assocSupa)
	}

	fFire := helperMakeFinding("DB-02", "Firebase Open Realtime Database", "firebase-open-db", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://my-app-db.firebaseio.com/users.json", "https://my-app-db.firebaseio.com/users.json", "GET")
	assetFire, assocFire := correlation.ResolveFindingAsset(fFire, nil)
	if assetFire.Type != discovery.AssetTypeDatabase || assetFire.CanonicalKey != "database:firebase_rtdb:my-app-db" {
		t.Errorf("unexpected Firebase asset: %+v", assetFire)
	}
	if !assocFire.IsExact {
		t.Errorf("Firebase association should be exact")
	}
}

// -----------------------------------------------------------------------------
// Category 6: Mobile APK Asset Identification
// -----------------------------------------------------------------------------
func TestCorrelation_Category06_MobileAPKAsset(t *testing.T) {
	fAPK := helperMakeFinding("APK-01", "Hardcoded API Token in Android Manifest", "apk-credential-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "", "", "")
	fAPK.Source = "apk"
	fAPK.EvidenceDetails.Details["package_name"] = "com.felix.mobile.banking"

	assetAPK, assocAPK := correlation.ResolveFindingAsset(fAPK, nil)
	if assetAPK.Type != discovery.AssetTypeAPK || assetAPK.CanonicalKey != "apk:com.felix.mobile.banking" {
		t.Errorf("unexpected APK asset: %+v", assetAPK)
	}
	if !assocAPK.IsExact || assocAPK.Basis != "APK_PACKAGE" {
		t.Errorf("unexpected APK association: %+v", assocAPK)
	}
}

// -----------------------------------------------------------------------------
// Category 7: Unresolvable & Malformed Endpoint Fallbacks
// -----------------------------------------------------------------------------
func TestCorrelation_Category07_UnresolvableAndMalformedFallback(t *testing.T) {
	fEmpty := helperMakeFinding("UNRES-01", "Empty Finding", "general", report.SeverityLow, report.ConfidenceLow, report.VerificationDetected, "", "", "")
	assetEmpty, assocEmpty := correlation.ResolveFindingAsset(fEmpty, nil)
	if assetEmpty.CanonicalKey != "unresolved" || assocEmpty.IsExact {
		t.Errorf("unresolvable empty finding should produce unresolved asset with IsExact=false: %+v", assetEmpty)
	}
	if assocEmpty.Confidence != report.ConfidenceLow {
		t.Errorf("expected LOW confidence for unresolvable finding")
	}

	fMalformed := helperMakeFinding("MAL-01", "Malformed URL", "general", report.SeverityLow, report.ConfidenceLow, report.VerificationDetected, "http://[invalid-ipv6-bracket", "", "")
	assetMal, assocMal := correlation.ResolveFindingAsset(fMalformed, nil)
	if !strings.HasPrefix(assetMal.CanonicalKey, "malformed") || assocMal.IsExact {
		t.Errorf("malformed URL should produce malformed asset with IsExact=false: %+v", assetMal)
	}
}

// -----------------------------------------------------------------------------
// Category 8: SAME_ENDPOINT Exact Matching
// -----------------------------------------------------------------------------
func TestCorrelation_Category08_SameEndpoint(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("F1", "Missing CSP Header", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	f2 := helperMakeFinding("F2", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	f3 := helperMakeFinding("F3", "CSRF on Create", "csrf", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "POST")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2, f3})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundSameEndpoint := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORSameEndpoint {
			foundSameEndpoint = true
			if r.Type != correlation.RelSameEndpoint {
				t.Errorf("expected SAME_ENDPOINT relationship type, got %s", r.Type)
			}
			if !r.IsExact || r.ValidationStatus != correlation.ValidationConfirmed {
				t.Errorf("expected confirmed exact SAME_ENDPOINT: %+v", r)
			}
			if (r.SourceFindingID == "F1" && r.TargetFindingID == "F3") || (r.SourceFindingID == "F2" && r.TargetFindingID == "F3") {
				t.Errorf("GET and POST must NOT match as SAME_ENDPOINT")
			}
		}
	}
	if !foundSameEndpoint {
		t.Errorf("expected SAME_ENDPOINT relationship between F1 and F2")
	}
}

// -----------------------------------------------------------------------------
// Category 9: SAME_ASSET Resolution
// -----------------------------------------------------------------------------
func TestCorrelation_Category09_SameAsset(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	// Two findings on different endpoints of the same origin application
	f1 := helperMakeFinding("FA1", "Favicon Route", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/favicon.ico", "GET")
	f2 := helperMakeFinding("FA2", "Account Settings SQLi", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/settings/account", "POST")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if len(paths) != 0 {
		t.Errorf("co-located findings on same asset must NOT generate attack paths: got %d", len(paths))
	}

	foundSameAsset := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORSameAsset {
			foundSameAsset = true
			if r.Type != correlation.RelSameAsset {
				t.Errorf("expected SAME_ASSET, got %s", r.Type)
			}
			if !r.IsExact || r.ValidationStatus != correlation.ValidationConfirmed {
				t.Errorf("expected confirmed exact SAME_ASSET relationship: %+v", r)
			}
		}
	}
	if !foundSameAsset {
		t.Errorf("expected SAME_ASSET relationship between FA1 and FA2")
	}
}

// -----------------------------------------------------------------------------
// Category 10: SHARED_COMPONENT Recognition
// -----------------------------------------------------------------------------
func TestCorrelation_Category10_SharedComponent(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("SC1", "SQL Injection in User Service", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://svc-a.example.com", "https://svc-a.example.com/users", "GET")
	f1.EvidenceDetails.Details["database"] = "aurora-pg-cluster-prod"

	f2 := helperMakeFinding("SC2", "Blind SQLi in Billing Service", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://svc-b.example.com", "https://svc-b.example.com/invoices", "GET")
	f2.EvidenceDetails.Details["database"] = "aurora-pg-cluster-prod"

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundSharedComp := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORSharedComp {
			foundSharedComp = true
			if r.Type != correlation.RelSharedComponent {
				t.Errorf("expected SHARED_COMPONENT, got %s", r.Type)
			}
			if !strings.Contains(r.Explanation, "aurora-pg-cluster-prod") {
				t.Errorf("expected explanation to mention shared database, got: %s", r.Explanation)
			}
		}
	}
	if !foundSharedComp {
		t.Errorf("expected SHARED_COMPONENT relationship between SC1 and SC2")
	}
}

// -----------------------------------------------------------------------------
// Category 11: RELATED_EVIDENCE Recognition
// -----------------------------------------------------------------------------
func TestCorrelation_Category11_RelatedEvidence(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("RE1", "IDOR on User Profile", "idor", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/profile", "GET")
	f1.EvidenceDetails.Details["parameters"] = "account_uuid,filter"

	f2 := helperMakeFinding("RE2", "BOLA on Payment Methods", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/wallet", "GET")
	f2.EvidenceDetails.Details["parameters"] = "account_uuid,currency"

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundRelatedEv := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORRelatedEv {
			foundRelatedEv = true
			if r.Type != correlation.RelRelatedEvidence {
				t.Errorf("expected RELATED_EVIDENCE, got %s", r.Type)
			}
			if !strings.Contains(r.Explanation, "account_uuid") {
				t.Errorf("expected explanation to mention shared parameter, got: %s", r.Explanation)
			}
		}
	}
	if !foundRelatedEv {
		t.Errorf("expected RELATED_EVIDENCE relationship between RE1 and RE2")
	}
}

// -----------------------------------------------------------------------------
// Category 12: POSSIBLE_RELATIONSHIP (Inconclusive Heuristic Infrastructure Association)
// -----------------------------------------------------------------------------
func TestCorrelation_Category12_PossibleRelationship(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	// Same host across different schemes
	fHTTP := helperMakeFinding("P-HTTP", "Cleartext HTTP Login", "cleartext-auth", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "http://secure.example.com", "http://secure.example.com/login", "GET")
	fHTTPS := helperMakeFinding("P-HTTPS", "HTTPS Dashboard XSS", "xss", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://secure.example.com", "https://secure.example.com/dashboard", "GET")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{fHTTP, fHTTPS})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundPossible := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORPossible {
			foundPossible = true
			if r.Type != correlation.RelPossibleRelationship {
				t.Errorf("expected POSSIBLE_RELATIONSHIP, got %s", r.Type)
			}
			if r.ValidationStatus != correlation.ValidationInconclusive {
				t.Errorf("POSSIBLE_RELATIONSHIP must be INCONCLUSIVE, got %s", r.ValidationStatus)
			}
			if r.Confidence != report.ConfidenceLow {
				t.Errorf("POSSIBLE_RELATIONSHIP confidence must be LOW, got %s", r.Confidence)
			}
			if r.IsExact {
				t.Errorf("POSSIBLE_RELATIONSHIP IsExact must be false")
			}
			if r.InconclusiveReason == "" {
				t.Errorf("POSSIBLE_RELATIONSHIP must have non-empty InconclusiveReason")
			}
		}
	}
	if !foundPossible {
		t.Errorf("expected POSSIBLE_RELATIONSHIP for different schemes on same hostname")
	}
}

// -----------------------------------------------------------------------------
// Category 13: Unrelated Findings Negative Test (Zero Relationships Fabricated)
// -----------------------------------------------------------------------------
func TestCorrelation_Category13_UnrelatedFindingsNegative(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	fA := helperMakeFinding("NEG1", "Alpha Finding", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://alpha.example.com", "https://alpha.example.com/test", "GET")
	fB := helperMakeFinding("NEG2", "Beta Finding", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://beta.unrelated-domain.org", "https://beta.unrelated-domain.org/query", "GET")

	summary, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{fA, fB})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if len(rels) != 0 {
		t.Errorf("expected 0 relationships between unrelated domains, got %d", len(rels))
	}
	if len(paths) != 0 {
		t.Errorf("expected 0 paths between unrelated domains, got %d", len(paths))
	}
	if summary.CandidateRelationships != 0 || summary.ConfirmedRelationships != 0 {
		t.Errorf("expected 0 relationships in summary, got cand=%d conf=%d",
			summary.CandidateRelationships, summary.ConfirmedRelationships)
	}
}

// -----------------------------------------------------------------------------
// Category 14: Hardened COR-09 Common Root Cause
// -----------------------------------------------------------------------------
func TestCorrelation_Category14_HardenedCOR09(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	// Positive: Same endpoint AND same hardening defect
	fHdr1 := helperMakeFinding("H1", "Missing X-Frame-Options", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/auth", "POST")
	fHdr2 := helperMakeFinding("H2", "Missing Strict-Transport-Security", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/auth", "POST")

	// Negative 1: Same category, but DIFFERENT endpoint
	fHdrDiffEP := helperMakeFinding("H3", "Missing CSP", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/other", "POST")

	// Negative 2: Same endpoint, but completely DIFFERENT defect
	fSqliSameEP := helperMakeFinding("S1", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/auth", "POST")

	_, paths, rels, err := engine.Correlate(context.Background(), []report.Finding{fHdr1, fHdr2, fHdrDiffEP, fSqliSameEP})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundCOR09 := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCOR09 {
			foundCOR09 = true
			if (r.SourceFindingID == "H1" && r.TargetFindingID == "H3") || (r.SourceFindingID == "H2" && r.TargetFindingID == "H3") {
				t.Errorf("negative test failed: different endpoints must NOT match COR-09")
			}
			if r.SourceFindingID == "S1" || r.TargetFindingID == "S1" {
				t.Errorf("negative test failed: SQLi must NOT match COR-09 with missing headers")
			}
		}
	}
	if !foundCOR09 {
		t.Errorf("expected positive COR-09 between H1 and H2")
	}

	// Verify no attack path contains COR-09
	for _, p := range paths {
		for _, e := range p.Edges {
			if e.RuleCode == correlation.RuleCOR09 {
				t.Errorf("COR-09 edge must NEVER be present in an attack path")
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 15: Symmetric Rule Canonical Pair Ordering
// -----------------------------------------------------------------------------
func TestCorrelation_Category15_SymmetricPairCanonicalOrdering(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	fA := helperMakeFinding("FA", "Missing X-Content-Type-Options", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api", "GET")
	fB := helperMakeFinding("FB", "Missing HSTS", "missing-headers", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api", "GET")

	_, _, relsForward, err1 := engine.Correlate(context.Background(), []report.Finding{fA, fB})
	_, _, relsReverse, err2 := engine.Correlate(context.Background(), []report.Finding{fB, fA})
	if err1 != nil || err2 != nil {
		t.Fatalf("Correlate errors: %v, %v", err1, err2)
	}

	if len(relsForward) != len(relsReverse) {
		t.Fatalf("expected equal relationship counts: forward=%d, reverse=%d", len(relsForward), len(relsReverse))
	}

	for i := range relsForward {
		rf := relsForward[i]
		rr := relsReverse[i]
		if rf.ID != rr.ID || rf.SourceFindingID != rr.SourceFindingID || rf.TargetFindingID != rr.TargetFindingID {
			t.Errorf("symmetric relationship mismatch at [%d]: forward=(%s, %s->%s), reverse=(%s, %s->%s)",
				i, rf.ID, rf.SourceFindingID, rf.TargetFindingID, rr.ID, rr.SourceFindingID, rr.TargetFindingID)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 16: Correlation Run Idempotency
// -----------------------------------------------------------------------------
func TestCorrelation_Category16_RunIdempotency(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("IDEMP1", "Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/items", "GET")
	f2 := helperMakeFinding("IDEMP2", "SQLi", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/items", "GET")

	s1, p1, r1, _ := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	s2, p2, r2, _ := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	s3, p3, r3, _ := engine.Correlate(context.Background(), []report.Finding{f1, f2})

	if s1.CandidateRelationships != s2.CandidateRelationships || s2.CandidateRelationships != s3.CandidateRelationships {
		t.Errorf("non-idempotent CandidateRelationships: %d, %d, %d", s1.CandidateRelationships, s2.CandidateRelationships, s3.CandidateRelationships)
	}
	if len(p1) != len(p2) || len(p2) != len(p3) {
		t.Errorf("non-idempotent path lengths: %d, %d, %d", len(p1), len(p2), len(p3))
	}
	if len(r1) != len(r2) || len(r2) != len(r3) {
		t.Errorf("non-idempotent relationship lengths: %d, %d, %d", len(r1), len(r2), len(r3))
	}
}

// -----------------------------------------------------------------------------
// Category 17: Input Order Invariance Across Shuffled Findings
// -----------------------------------------------------------------------------
func TestCorrelation_Category17_InputOrderInvariance(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	fA := helperMakeFinding("A1", "Entry Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user", "GET")
	fB := helperMakeFinding("B2", "BOLA on User", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user", "GET")
	fC := helperMakeFinding("C3", "PII Data Leak", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/user", "GET")
	fC.EvidenceDetails.Details["sensitive_data"] = "true"

	order1 := []report.Finding{fA, fB, fC}
	order2 := []report.Finding{fC, fA, fB}
	order3 := []report.Finding{fB, fC, fA}

	s1, p1, r1, _ := engine.Correlate(context.Background(), order1)
	s2, p2, r2, _ := engine.Correlate(context.Background(), order2)
	s3, p3, r3, _ := engine.Correlate(context.Background(), order3)

	if len(p1) != len(p2) || len(p2) != len(p3) {
		t.Fatalf("path count variation under permutation: %d, %d, %d", len(p1), len(p2), len(p3))
	}
	if len(r1) != len(r2) || len(r2) != len(r3) {
		t.Fatalf("relationship count variation under permutation: %d, %d, %d", len(r1), len(r2), len(r3))
	}
	if !reflect.DeepEqual(s1.AffectedAssets, s2.AffectedAssets) || !reflect.DeepEqual(s2.AffectedAssets, s3.AffectedAssets) {
		t.Errorf("affected assets variation under permutation: %+v, %+v, %+v", s1.AffectedAssets, s2.AffectedAssets, s3.AffectedAssets)
	}
}

// -----------------------------------------------------------------------------
// Category 18: Structural Relations Never Appear in Attack Paths
// -----------------------------------------------------------------------------
func TestCorrelation_Category18_StructuralRelationsNeverInAttackPaths(t *testing.T) {
	structuralTypes := []correlation.RelationshipType{
		correlation.RelSameAsset,
		correlation.RelSameEndpoint,
		correlation.RelSharedComponent,
		correlation.RelRelatedEvidence,
		correlation.RelPossibleRelationship,
		correlation.RelSharesRootCause,
		correlation.RelRelatedTo,
	}

	for _, st := range structuralTypes {
		if st.IsSequenceType() {
			t.Errorf("critical failure: structural type %s must return IsSequenceType() == false", st)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 19: Preserves Phase 6.1 Finding Scores and Verification Statuses
// -----------------------------------------------------------------------------
func TestCorrelation_Category19_ScoreAndStatusPreservation(t *testing.T) {
	f := helperMakeFinding("PRESERVE-01", "Hardcoded Cloud Key", "hardcoded-service-secret", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/config", "GET")
	originalScore := f.Score
	originalStatus := f.Verification.Status

	norm := correlation.NormalizeFinding(f)
	if norm.Score != originalScore {
		t.Errorf("normalized score changed: was %d, got %d", originalScore, norm.Score)
	}
	if norm.VerificationStatus != originalStatus {
		t.Errorf("normalized verification status changed: was %s, got %s", originalStatus, norm.VerificationStatus)
	}
}

// -----------------------------------------------------------------------------
// Category 20: Sensitive Query Parameter Redaction in Explanations & Evidence
// -----------------------------------------------------------------------------
func TestCorrelation_Category20_SensitiveTokenRedactionInEvidence(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("SEC1", "Leak 1", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api?jwt=SECRET_TOKEN_XYZ", "GET")
	f2 := helperMakeFinding("SEC2", "Leak 2", "sensitive-data-exposure", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api?jwt=SECRET_TOKEN_XYZ", "GET")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	for _, r := range rels {
		if strings.Contains(r.Explanation, "SECRET_TOKEN_XYZ") {
			t.Errorf("relationship explanation contains unredacted secret: %s", r.Explanation)
		}
		for _, ref := range r.EvidenceReferences {
			if strings.Contains(ref, "SECRET_TOKEN_XYZ") {
				t.Errorf("evidence reference contains unredacted secret: %s", ref)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 21: Evidence References Point to Valid Sanitized Resources
// -----------------------------------------------------------------------------
func TestCorrelation_Category21_EvidenceReferencesSanitized(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("EV1", "Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/items", "GET")
	f2 := helperMakeFinding("EV2", "SQLi", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/items", "GET")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	for _, r := range rels {
		if len(r.EvidenceReferences) == 0 {
			t.Errorf("relationship %s has empty EvidenceReferences", r.ID)
		}
		for _, ref := range r.EvidenceReferences {
			if ref == "" {
				t.Errorf("relationship %s contains empty evidence reference", r.ID)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 22: Inconclusive Reason Populated for Possible Relationships
// -----------------------------------------------------------------------------
func TestCorrelation_Category22_InconclusiveReasonPopulated(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("IP1", "Host 1 Service", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://svc1.example.com", "https://svc1.example.com/test", "GET")
	f1.EvidenceDetails.Details["ip"] = "203.0.113.50"

	f2 := helperMakeFinding("IP2", "Host 2 Service", "discovery", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://svc2.other.org", "https://svc2.other.org/test", "GET")
	f2.EvidenceDetails.Details["ip"] = "203.0.113.50"

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	foundPossible := false
	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORPossible {
			foundPossible = true
			if r.InconclusiveReason == "" {
				t.Errorf("POSSIBLE_RELATIONSHIP must provide explanatory InconclusiveReason")
			}
		}
	}
	if !foundPossible {
		t.Errorf("expected POSSIBLE_RELATIONSHIP for matching IP")
	}
}

// -----------------------------------------------------------------------------
// Category 23: Accurate Confidence Levels Across Relationships
// -----------------------------------------------------------------------------
func TestCorrelation_Category23_ConfidenceLevelsAccurate(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("CONF1", "Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api", "GET")
	f2 := helperMakeFinding("CONF2", "Route Duplicate", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api", "GET")

	_, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	for _, r := range rels {
		if r.RuleCode == correlation.RuleCORSameEndpoint {
			if r.Confidence != report.ConfidenceHigh {
				t.Errorf("SAME_ENDPOINT should have HIGH confidence, got %s", r.Confidence)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 24: RuleCatalog Metadata Complete for All 15 Rules
// -----------------------------------------------------------------------------
func TestCorrelation_Category24_RuleCatalogMetadataComplete(t *testing.T) {
	allRules := correlation.AllRules()
	if len(allRules) != 15 {
		t.Fatalf("expected 15 rules in AllRules(), got %d", len(allRules))
	}

	for _, code := range allRules {
		meta, exists := correlation.RuleCatalog[code]
		if !exists {
			t.Errorf("rule %s missing from RuleCatalog", code)
			continue
		}
		if meta.Code != code {
			t.Errorf("rule code mismatch: %s vs %s", meta.Code, code)
		}
		if meta.Name == "" {
			t.Errorf("rule %s has empty Name", code)
		}
		if meta.Description == "" {
			t.Errorf("rule %s has empty Description", code)
		}
		if meta.EdgeType == "" {
			t.Errorf("rule %s has empty EdgeType", code)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 25: Multi-Target Assessment with Mixed Asset Types
// -----------------------------------------------------------------------------
func TestCorrelation_Category25_MultiTargetMixedAssets(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	fWeb := helperMakeFinding("MIX-WEB", "API Endpoint Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/auth", "POST")
	fS3 := helperMakeFinding("MIX-S3", "Open S3 Bucket", "s3-bucket-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://corp-backups/dump.tar.gz", "s3://corp-backups/dump.tar.gz", "GET")
	fDB := helperMakeFinding("MIX-DB", "Exposed Supabase Database", "supabase-exposure", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://proja.supabase.co/rest/v1/data", "https://proja.supabase.co/rest/v1/data", "GET")
	fAPK := helperMakeFinding("MIX-APK", "APK Hardcoded Token", "apk-credential-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "", "", "")
	fAPK.Source = "apk"
	fAPK.EvidenceDetails.Details["package_name"] = "com.corp.mobile"

	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{fWeb, fS3, fDB, fAPK})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if summary.TotalFindings != 4 {
		t.Errorf("expected 4 findings, got %d", summary.TotalFindings)
	}
	if len(summary.AssetAssociations) != 4 {
		t.Errorf("expected 4 asset associations, got %d", len(summary.AssetAssociations))
	}

	assetTypesFound := make(map[discovery.AssetType]bool)
	for _, a := range summary.AssetAssociations {
		assetTypesFound[a.AssetType] = true
	}

	if !assetTypesFound[discovery.AssetTypeEndpoint] {
		t.Errorf("missing Endpoint asset type in associations")
	}
	if !assetTypesFound[discovery.AssetTypeStorage] {
		t.Errorf("missing Storage asset type in associations")
	}
	if !assetTypesFound[discovery.AssetTypeDatabase] {
		t.Errorf("missing Database asset type in associations")
	}
	if !assetTypesFound[discovery.AssetTypeAPK] {
		t.Errorf("missing APK asset type in associations")
	}
}

// -----------------------------------------------------------------------------
// Category 26: Summary AssetAssociations and Relationships Populated
// -----------------------------------------------------------------------------
func TestCorrelation_Category26_SummaryAssetAssociationsPopulated(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("S-A1", "Route A", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/a", "GET")
	f2 := helperMakeFinding("S-A2", "Route B", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/b", "GET")

	summary, _, rels, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if len(summary.AssetAssociations) == 0 {
		t.Errorf("summary.AssetAssociations must not be empty")
	}
	if len(summary.Relationships) != len(rels) {
		t.Errorf("summary.Relationships (%d) does not match returned rels (%d)", len(summary.Relationships), len(rels))
	}
}

// -----------------------------------------------------------------------------
// Category 27: AffectedAssets Complete, Deduplicated and Sorted
// -----------------------------------------------------------------------------
func TestCorrelation_Category27_AffectedAssetsCompleteAndSorted(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("AF1", "Route A", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/a", "GET")
	f2 := helperMakeFinding("AF2", "Route B", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/b", "GET")

	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if len(summary.AffectedAssets) == 0 {
		t.Fatalf("summary.AffectedAssets must not be empty")
	}

	// Verify deduplication
	seen := make(map[string]bool)
	for _, a := range summary.AffectedAssets {
		if seen[a] {
			t.Errorf("duplicate asset key in AffectedAssets: %s", a)
		}
		seen[a] = true
	}

	// Verify sorting
	if !sort.StringsAreSorted(summary.AffectedAssets) {
		t.Errorf("AffectedAssets is not sorted lexicographically: %+v", summary.AffectedAssets)
	}
}

// -----------------------------------------------------------------------------
// Category 28: CLI Summary Output Formatting & Coverage Reporting
// -----------------------------------------------------------------------------
func TestCorrelation_Category28_CLISummaryFormatting(t *testing.T) {
	engine := correlation.NewEngine(correlation.DefaultConfig())

	f1 := helperMakeFinding("CLI1", "Route", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/test", "GET")
	f2 := helperMakeFinding("CLI2", "SQLi", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/test", "GET")

	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{f1, f2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	if summary.RuleStats == nil {
		t.Fatalf("summary.RuleStats must not be nil")
	}

	for _, code := range correlation.AllRules() {
		st, ok := summary.RuleStats[string(code)]
		if !ok {
			t.Errorf("missing coverage stat for rule %s", code)
		}
		if st.Code != code {
			t.Errorf("stat code mismatch: %s vs %s", st.Code, code)
		}
	}
}

// -----------------------------------------------------------------------------
// Final Asset Identity Audit Tests
// -----------------------------------------------------------------------------

func TestAudit_EncodedSlashSeparators(t *testing.T) {
	u1 := "https://api.example.com/items/a%2Fb"
	u2 := "https://api.example.com/items/a/b"

	c1, err1 := correlation.CanonicalizeURL(u1)
	c2, err2 := correlation.CanonicalizeURL(u2)

	if err1 != nil || err2 != nil {
		t.Fatalf("CanonicalizeURL failed: %v, %v", err1, err2)
	}

	if c1.Path == c2.Path {
		t.Fatalf("Encoded slash %%2F was collapsed into a directory separator: %s == %s", c1.Path, c2.Path)
	}

	if !strings.Contains(c1.Path, "%2F") {
		t.Errorf("Expected canonical path to preserve %%2F, got %s", c1.Path)
	}

	if c1.RawURL != u1 {
		t.Errorf("Expected RawURL to preserve provenance %q, got %q", u1, c1.RawURL)
	}
}

func TestAudit_QuerySecretSeparationAndCollisionPrevention(t *testing.T) {
	// Two findings with different secret tokens at the same route
	fAlice := helperMakeFinding("F_ALICE", "Token Leak", "token-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/data?token=AliceSecret123&env=prod", "GET")
	fBob := helperMakeFinding("F_BOB", "Token Leak", "token-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/data?token=BobSecret456&env=prod", "GET")

	// 1. Neither secret must leak in DisplayEndpoint or Evidence
	cA, _ := correlation.CanonicalizeURL(fAlice.Endpoint)
	cB, _ := correlation.CanonicalizeURL(fBob.Endpoint)

	if strings.Contains(cA.DisplayEndpoint, "AliceSecret123") || strings.Contains(cB.DisplayEndpoint, "BobSecret456") {
		t.Fatalf("Secrets leaked in DisplayEndpoint: A=%s, B=%s", cA.DisplayEndpoint, cB.DisplayEndpoint)
	}

	// 2. Both display endpoints show REDACTED
	if !strings.Contains(cA.DisplayEndpoint, "token=REDACTED") || !strings.Contains(cB.DisplayEndpoint, "token=REDACTED") {
		t.Fatalf("DisplayEndpoint did not redact tokens to REDACTED: A=%s, B=%s", cA.DisplayEndpoint, cB.DisplayEndpoint)
	}

	// 3. But their internal canonical endpoints must NOT collide
	if cA.Endpoint == cB.Endpoint {
		t.Fatalf("Distinct sensitive query tokens collapsed into identical canonical endpoint: %s", cA.Endpoint)
	}

	// 4. Running correlation must NOT report SAME_ENDPOINT between Alice and Bob
	engine := correlation.NewEngine(correlation.DefaultConfig())
	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{fAlice, fBob})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	for _, rel := range summary.Relationships {
		if rel.Type == correlation.RelSameEndpoint {
			t.Errorf("Distinct token endpoints should not match as SAME_ENDPOINT: %+v", rel)
		}
	}

	// 5. Conversely, identical tokens across two findings MUST match as SAME_ENDPOINT
	fAliceDup := helperMakeFinding("F_ALICE_2", "SQLi", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/data?env=prod&token=AliceSecret123", "GET")
	summaryMatch, _, _, errMatch := engine.Correlate(context.Background(), []report.Finding{fAlice, fAliceDup})
	if errMatch != nil {
		t.Fatalf("Correlate failed: %v", errMatch)
	}

	foundExactMatch := false
	for _, rel := range summaryMatch.Relationships {
		if rel.Type == correlation.RelSameEndpoint {
			foundExactMatch = true
			if strings.Contains(rel.Explanation, "AliceSecret123") {
				t.Errorf("Secret token leaked in relationship explanation: %s", rel.Explanation)
			}
			for _, ref := range rel.EvidenceReferences {
				if strings.Contains(ref, "AliceSecret123") {
					t.Errorf("Secret token leaked in evidence reference: %s", ref)
				}
			}
		}
	}
	if !foundExactMatch {
		t.Errorf("Identical tokens failed to correlate as SAME_ENDPOINT")
	}
}

func TestAudit_EmptyAndDuplicateFindingIDs(t *testing.T) {
	// Finding with empty ID and duplicate long-prefix IDs
	fEmpty := helperMakeFinding("", "Empty ID Finding", "auth-bypass", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/auth/login", "POST")
	fLong1 := helperMakeFinding("FINDING-VERY-LONG-COMMON-PREFIX-001", "BOLA 1", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/users/1", "GET")
	fLong2 := helperMakeFinding("FINDING-VERY-LONG-COMMON-PREFIX-002", "PII 1", "pii-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/users/1", "GET")
	fDup := helperMakeFinding("FINDING-VERY-LONG-COMMON-PREFIX-001", "BOLA Duplicate", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/users/1", "GET")

	normList := correlation.NormalizeFindings([]report.Finding{fEmpty, fLong1, fLong2, fDup})

	if len(normList) != 4 {
		t.Fatalf("Expected 4 normalized findings, got %d", len(normList))
	}

	seenIDs := make(map[string]bool)
	for i, nf := range normList {
		if strings.TrimSpace(nf.ID) == "" {
			t.Errorf("Normalized finding %d has empty ID", i)
		}
		if seenIDs[nf.ID] {
			t.Errorf("Collision detected for normalized finding ID %q", nf.ID)
		}
		seenIDs[nf.ID] = true
	}

	engine := correlation.NewEngine(correlation.DefaultConfig())
	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{fLong1, fLong2})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	seenRelIDs := make(map[string]bool)
	for _, rel := range summary.Relationships {
		if seenRelIDs[rel.ID] {
			t.Errorf("Duplicate relationship ID detected: %s", rel.ID)
		}
		seenRelIDs[rel.ID] = true
		// Verify no truncated single-character artifact
		if strings.Contains(rel.ID, "--") {
			t.Errorf("Relationship ID contains empty or malformed segment: %s", rel.ID)
		}
	}
}

func TestAudit_MultiTenantIsolationBoundaries(t *testing.T) {
	// Tenant A vs Tenant B on the same multi-tenant endpoint
	fTenantA := helperMakeFinding("T_A_01", "Auth Flaw Tenant A", "auth-bypass", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shared.example.com", "https://shared.example.com/api/v1/accounts", "GET")
	fTenantA.EvidenceDetails.Details = map[string]string{
		"tenant_id": "tenant-alpha",
	}

	fTenantB := helperMakeFinding("T_B_01", "Auth Flaw Tenant B", "auth-bypass", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shared.example.com", "https://shared.example.com/api/v1/accounts", "GET")
	fTenantB.EvidenceDetails.Details = map[string]string{
		"tenant_id": "tenant-beta",
	}

	// 1. Asset identities must be distinct
	assetA, assocA := correlation.ResolveFindingAsset(fTenantA, nil)
	assetB, assocB := correlation.ResolveFindingAsset(fTenantB, nil)

	if assetA.ID == assetB.ID {
		t.Fatalf("Multi-tenant boundary failed: identical asset IDs for different tenants (%s == %s)", assetA.ID, assetB.ID)
	}
	if assetA.TenantID != "tenant-alpha" || assetB.TenantID != "tenant-beta" {
		t.Errorf("TenantID was not preserved on asset: A=%s, B=%s", assetA.TenantID, assetB.TenantID)
	}
	if assocA.CanonicalKey == assocB.CanonicalKey {
		t.Errorf("Canonical keys must not collide across tenants: %s", assocA.CanonicalKey)
	}

	// 2. Correlation must NOT mark SAME_ENDPOINT or SAME_ASSET across distinct tenants
	engine := correlation.NewEngine(correlation.DefaultConfig())
	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{fTenantA, fTenantB})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	hasPossibleRel := false
	for _, rel := range summary.Relationships {
		if rel.Type == correlation.RelSameEndpoint {
			t.Errorf("Cross-tenant findings must not match as SAME_ENDPOINT: %+v", rel)
		}
		if rel.Type == correlation.RelSameAsset {
			t.Errorf("Cross-tenant findings must not match as SAME_ASSET: %+v", rel)
		}
		if rel.Type == correlation.RelPossibleRelationship {
			hasPossibleRel = true
			if !strings.Contains(rel.Explanation, "distinct tenant boundaries") {
				t.Errorf("Expected tenant boundary explanation, got: %s", rel.Explanation)
			}
		}
	}

	if !hasPossibleRel {
		t.Errorf("Expected POSSIBLE_RELATIONSHIP noting shared host across distinct tenant boundaries")
	}

	// 3. Multi-tenant Cloud Storage buckets with identical names
	fBucketA := helperMakeFinding("B_A", "Bucket A", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://exports", "s3://exports", "GET")
	fBucketA.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "exports",
		"tenant_id":      "tenant-alpha",
	}

	fBucketB := helperMakeFinding("B_B", "Bucket B", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://exports", "s3://exports", "GET")
	fBucketB.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "exports",
		"tenant_id":      "tenant-beta",
	}

	assetBA, _ := correlation.ResolveFindingAsset(fBucketA, nil)
	assetBB, _ := correlation.ResolveFindingAsset(fBucketB, nil)

	if assetBA.ID == assetBB.ID {
		t.Fatalf("Bucket assets collapsed across tenant boundaries: %s == %s", assetBA.ID, assetBB.ID)
	}
	if !strings.Contains(assetBA.CanonicalKey, "tenant-alpha") || !strings.Contains(assetBB.CanonicalKey, "tenant-beta") {
		t.Errorf("Bucket canonical keys lack tenant qualification: BA=%s, BB=%s", assetBA.CanonicalKey, assetBB.CanonicalKey)
	}
}

// -----------------------------------------------------------------------------
// Category 29 (Audit): Account ID Isolation Boundaries & Relationship ID Uniqueness
// -----------------------------------------------------------------------------
func TestAudit_AccountIDIsolationBoundaries(t *testing.T) {
	// 1. Direct account_id boundary isolation on identical endpoint
	fAcctA := helperMakeFinding("ACCT_A_01", "BFLA Account Alpha", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shared.example.com", "https://shared.example.com/api/v1/orders", "GET")
	fAcctA.EvidenceDetails.Details = map[string]string{
		"account_id": "acct-111",
	}

	fAcctB := helperMakeFinding("ACCT_B_01", "BFLA Account Beta", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://shared.example.com", "https://shared.example.com/api/v1/orders", "GET")
	fAcctB.EvidenceDetails.Details = map[string]string{
		"account_id": "acct-222",
	}

	assetA, assocA := correlation.ResolveFindingAsset(fAcctA, nil)
	assetB, assocB := correlation.ResolveFindingAsset(fAcctB, nil)

	if assetA.ID == assetB.ID {
		t.Fatalf("Account boundary failed: identical asset IDs for different accounts (%s == %s)", assetA.ID, assetB.ID)
	}
	if assetA.AccountID != "acct-111" || assetB.AccountID != "acct-222" {
		t.Errorf("AccountID was not preserved on asset: A=%s, B=%s", assetA.AccountID, assetB.AccountID)
	}
	if assocA.CanonicalKey == assocB.CanonicalKey {
		t.Errorf("Canonical keys must not collide across accounts: %s", assocA.CanonicalKey)
	}

	engine := correlation.NewEngine(correlation.DefaultConfig())
	summary, _, _, err := engine.Correlate(context.Background(), []report.Finding{fAcctA, fAcctB})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	hasPossibleRel := false
	for _, rel := range summary.Relationships {
		if rel.Type == correlation.RelSameEndpoint {
			t.Errorf("Cross-account findings must not match as SAME_ENDPOINT: %+v", rel)
		}
		if rel.Type == correlation.RelSameAsset {
			t.Errorf("Cross-account findings must not match as SAME_ASSET: %+v", rel)
		}
		if rel.Type == correlation.RelPossibleRelationship {
			hasPossibleRel = true
			if !strings.Contains(rel.Explanation, "distinct account boundaries") {
				t.Errorf("Expected account boundary explanation, got: %s", rel.Explanation)
			}
		}
	}
	if !hasPossibleRel {
		t.Errorf("Expected POSSIBLE_RELATIONSHIP noting shared host across distinct account boundaries")
	}

	// 2. Dual-boundary isolation: same tenant_id, distinct account_id
	fDualA := helperMakeFinding("DUAL_A_01", "Flaw 1", "idor", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/v1/users", "GET")
	fDualA.EvidenceDetails.Details = map[string]string{
		"tenant_id":  "tenant-omega",
		"account_id": "acct-primary",
	}

	fDualB := helperMakeFinding("DUAL_B_01", "Flaw 2", "idor", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/v1/users", "GET")
	fDualB.EvidenceDetails.Details = map[string]string{
		"tenant_id":  "tenant-omega",
		"account_id": "acct-secondary",
	}

	assetDA, assocDA := correlation.ResolveFindingAsset(fDualA, nil)
	assetDB, assocDB := correlation.ResolveFindingAsset(fDualB, nil)

	if assetDA.ID == assetDB.ID {
		t.Fatalf("Dual-boundary failed: identical asset IDs for different accounts under same tenant (%s == %s)", assetDA.ID, assetDB.ID)
	}
	if assocDA.CanonicalKey == assocDB.CanonicalKey {
		t.Errorf("Canonical keys must not collide for different accounts under same tenant: %s", assocDA.CanonicalKey)
	}

	summaryDual, _, _, err := engine.Correlate(context.Background(), []report.Finding{fDualA, fDualB})
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}
	for _, rel := range summaryDual.Relationships {
		if rel.Type == correlation.RelSameEndpoint {
			t.Errorf("Dual-boundary findings with conflicting account_id must not match as SAME_ENDPOINT: %+v", rel)
		}
		if rel.Type == correlation.RelSameAsset {
			t.Errorf("Dual-boundary findings with conflicting account_id must not match as SAME_ASSET: %+v", rel)
		}
	}

	// 3. Multi-account Cloud Storage buckets
	fStorageA := helperMakeFinding("S_A", "Bucket Prod", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://backups", "s3://backups", "GET")
	fStorageA.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "backups",
		"account_id":     "acct-prod",
	}

	fStorageB := helperMakeFinding("S_B", "Bucket Dev", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://backups", "s3://backups", "GET")
	fStorageB.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "backups",
		"account_id":     "acct-dev",
	}

	assetSA, _ := correlation.ResolveFindingAsset(fStorageA, nil)
	assetSB, _ := correlation.ResolveFindingAsset(fStorageB, nil)

	if assetSA.ID == assetSB.ID {
		t.Fatalf("Bucket assets collapsed across account boundaries: %s == %s", assetSA.ID, assetSB.ID)
	}
	if !strings.Contains(assetSA.CanonicalKey, "acct-prod") || !strings.Contains(assetSB.CanonicalKey, "acct-dev") {
		t.Errorf("Bucket canonical keys lack account qualification: SA=%s, SB=%s", assetSA.CanonicalKey, assetSB.CanonicalKey)
	}

	// 4. Strict relationship ID uniqueness verification across multiple relationships
	seenIDs := make(map[string]bool)
	for _, r := range summaryDual.Relationships {
		if seenIDs[r.ID] {
			t.Errorf("Duplicate relationship ID detected: %s", r.ID)
		}
		seenIDs[r.ID] = true
	}
}
