package report

import (
	"strings"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/discovery"
)

func TestFindingIdentity_DeterministicAndStable(t *testing.T) {
	target := "https://app.example.com"
	ruleID := "SEC-JWT-SECRET"
	category := "jwt-secret-key"
	endpoint := "https://app.example.com/api/v1/auth"
	method := "POST"
	key := "candidate-secret-token"

	id1 := ComputeStableFindingID(target, ruleID, category, endpoint, method, key)
	id2 := ComputeStableFindingID(target, ruleID, category, endpoint, method, key)

	if id1 == "" {
		t.Fatalf("expected non-empty finding ID")
	}
	if !strings.HasPrefix(id1, "fnd_") {
		t.Errorf("expected finding ID prefix 'fnd_', got %s", id1)
	}
	if id1 != id2 {
		t.Errorf("finding ID is non-deterministic: id1=%s, id2=%s", id1, id2)
	}

	// Distinct issue separation: endpoint change
	idEndpointDiff := ComputeStableFindingID(target, ruleID, category, "https://app.example.com/api/v1/profile", method, key)
	if id1 == idEndpointDiff {
		t.Errorf("expected different finding IDs for different endpoints")
	}

	// Distinct issue separation: method change
	idMethodDiff := ComputeStableFindingID(target, ruleID, category, endpoint, "GET", key)
	if id1 == idMethodDiff {
		t.Errorf("expected different finding IDs for different methods")
	}

	// Distinct issue separation: rule change
	idRuleDiff := ComputeStableFindingID(target, "SEC-AWS-KEY", category, endpoint, method, key)
	if id1 == idRuleDiff {
		t.Errorf("expected different finding IDs for different rules")
	}

	// Whitespace and case normalization stability
	idNormalized := ComputeStableFindingID("  HTTPS://app.example.com/  ", "sec-jwt-secret ", " JWT-SECRET-KEY ", "https://app.example.com/api/v1/auth", "post", "candidate-secret-token")
	if id1 != idNormalized {
		t.Errorf("expected case/whitespace normalization to produce identical ID: got %s, want %s", idNormalized, id1)
	}
}

func TestFindingStatus_ModelAndPrecedence(t *testing.T) {
	statuses := []FindingStatus{
		FindingStatusConfirmed,
		FindingStatusSuspected,
		FindingStatusInconclusive,
		FindingStatusNotTested,
		FindingStatusError,
	}

	for _, s := range statuses {
		norm := NormalizeFindingStatus(s)
		if norm != s {
			t.Errorf("NormalizeFindingStatus(%s) = %s, want %s", s, norm, s)
		}
	}

	// Case insensitivity & fallback
	if NormalizeFindingStatus("confirmed") != FindingStatusConfirmed {
		t.Errorf("expected case-insensitive normalization")
	}
	if NormalizeFindingStatus("UNKNOWN_INVALID_STATUS") != FindingStatusInconclusive {
		t.Errorf("expected safe fallback to INCONCLUSIVE for invalid status")
	}
	if NormalizeFindingStatus("UNKNOWN_INVALID_STATUS") == FindingStatusSuspected {
		t.Errorf("CRITICAL DEFECT: invalid status must never silently become SUSPECTED")
	}

	// Precedence order: CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR
	if FindingStatusRank(FindingStatusConfirmed) <= FindingStatusRank(FindingStatusSuspected) {
		t.Errorf("CONFIRMED should rank higher than SUSPECTED")
	}
	if FindingStatusRank(FindingStatusSuspected) <= FindingStatusRank(FindingStatusInconclusive) {
		t.Errorf("SUSPECTED should rank higher than INCONCLUSIVE")
	}
	if FindingStatusRank(FindingStatusInconclusive) <= FindingStatusRank(FindingStatusNotTested) {
		t.Errorf("INCONCLUSIVE should rank higher than NOT_TESTED")
	}
	if FindingStatusRank(FindingStatusNotTested) <= FindingStatusRank(FindingStatusError) {
		t.Errorf("NOT_TESTED should rank higher than ERROR")
	}

	// Bidirectional mapping between VerificationStatus and FindingStatus
	if FindingStatusFromVerification(VerificationVerified) != FindingStatusConfirmed {
		t.Errorf("expected VERIFIED -> CONFIRMED")
	}
	if FindingStatusFromVerification(VerificationNotExposed) != FindingStatusInconclusive {
		t.Errorf("expected NOT_EXPOSED -> INCONCLUSIVE")
	}
	if VerificationFromFindingStatus(FindingStatusConfirmed) != VerificationVerified {
		t.Errorf("expected CONFIRMED -> VERIFIED")
	}
	if VerificationFromFindingStatus(FindingStatusInconclusive) != VerificationNotExposed {
		t.Errorf("expected INCONCLUSIVE -> NOT_EXPOSED")
	}
}

func TestFinding_AssetLinkageAndResolution(t *testing.T) {
	inv := discovery.NewInventory()

	// 1. Create root app asset
	appAsset := discovery.NewApplicationAsset("asm-1", "exec-1", "tgt-1", "https://app.example.com", discovery.ApplicationDetails{
		AppType: "web",
		RootURL: "https://app.example.com",
	})
	appID := inv.AddAsset(appAsset)

	// 2. Create endpoint asset
	epAsset := discovery.NewEndpointAsset("asm-1", "exec-1", "tgt-1", "POST", "https://app.example.com/api/v1/auth", discovery.EndpointDetails{
		URL:        "https://app.example.com/api/v1/auth",
		Path:       "/api/v1/auth",
		HTTPMethod: "POST",
	})
	epID := inv.AddAsset(epAsset)

	// 3. Create storage asset
	stAsset := discovery.NewStorageAsset("asm-1", "exec-1", "tgt-1", "aws", "s3://company-prod-backups", discovery.StorageDetails{
		BucketName: "company-prod-backups",
		Provider:   "aws",
	})
	stID := inv.AddAsset(stAsset)

	// Finding matching endpoint
	f1 := Finding{
		ID:          "f-1",
		Category:    "missing-hsts",
		Severity:    SeverityLow,
		Confidence:  ConfidenceHigh,
		Target:      "https://app.example.com",
		Endpoint:    "https://app.example.com/api/v1/auth",
		Method:      "POST",
		Description: "Missing HSTS header",
	}
	f1.ResolveAssetIDs(inv)

	if f1.PrimaryAssetID != epID {
		t.Errorf("expected primary asset ID %s, got %s", epID, f1.PrimaryAssetID)
	}
	hasApp := false
	for _, id := range f1.AffectedAssetIDs {
		if id == appID {
			hasApp = true
			break
		}
	}
	if !hasApp {
		t.Errorf("expected affected asset IDs to include application %s, got %+v", appID, f1.AffectedAssetIDs)
	}

	// Validate affected assets against inventory
	if err := ValidateAffectedAssets(f1, inv); err != nil {
		t.Errorf("ValidateAffectedAssets failed on valid assets: %v", err)
	}

	// Finding matching storage
	f2 := Finding{
		ID:          "f-2",
		Category:    "s3-public-listing",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceHigh,
		Target:      "https://app.example.com",
		Endpoint:    "s3://company-prod-backups",
		Method:      "GET",
		Description: "Open S3 bucket listing",
	}
	f2.ResolveAssetIDs(inv)
	if f2.PrimaryAssetID != stID {
		t.Errorf("expected primary asset ID %s for storage finding, got %s", stID, f2.PrimaryAssetID)
	}

	// Dangling asset validation error
	fDangling := Finding{
		PrimaryAssetID:   "ast_non_existent",
		AffectedAssetIDs: []string{epID, "ast_ghost_asset"},
	}
	if err := ValidateAffectedAssets(fDangling, inv); err == nil {
		t.Errorf("expected error for dangling asset reference, got nil")
	}
}

func TestFinding_ValidationFunction(t *testing.T) {
	validFinding := Finding{
		ID:               "fnd_0123456789abcdef01234567",
		RuleID:           "SEC-API-KEY",
		Status:           FindingStatusConfirmed,
		Category:         "api-key",
		Severity:         SeverityHigh,
		Confidence:       ConfidenceHigh,
		Target:           "https://target.com",
		Endpoint:         "https://target.com/api",
		Method:           "GET",
		PrimaryAssetID:   "ast_1111",
		AffectedAssetIDs: []string{"ast_1111", "ast_2222"},
	}

	if err := ValidateFinding(validFinding); err != nil {
		t.Errorf("expected valid finding to pass validation: %v", err)
	}

	// Missing ID
	fNoID := validFinding
	fNoID.ID = ""
	if err := ValidateFinding(fNoID); err == nil {
		t.Errorf("expected error for empty ID")
	}

	// Missing Category
	fNoCat := validFinding
	fNoCat.Category = ""
	if err := ValidateFinding(fNoCat); err == nil {
		t.Errorf("expected error for empty Category")
	}

	// Duplicate affected assets
	fDupAssets := validFinding
	fDupAssets.AffectedAssetIDs = []string{"ast_1111", "ast_1111"}
	if err := ValidateFinding(fDupAssets); err == nil {
		t.Errorf("expected error for duplicate affected assets")
	}
}

func TestFinding_DeduplicationMerging(t *testing.T) {
	fp := ComputeFingerprint("https://app.example.com", "cors-wildcard", "https://app.example.com/api", "GET", "key-1")

	f1 := Finding{
		ID:               "fnd-1",
		Title:            "CORS Wildcard Initial Observation",
		Category:         "cors-wildcard",
		Severity:         SeverityInfo,
		Confidence:       ConfidenceMedium,
		Status:           FindingStatusSuspected,
		Target:           "https://app.example.com",
		Endpoint:         "https://app.example.com/api",
		Method:           "GET",
		Fingerprint:      fp,
		PrimaryAssetID:   "ast_1111",
		AffectedAssetIDs: []string{"ast_1111"},
		RemediationAdvice: &RemediationAdvice{
			Summary:    "Configure CORS properly",
			Steps:      []string{"Review AllowedOrigins"},
			References: []string{"https://owasp.org/cors"},
		},
	}

	f2 := Finding{
		ID:               "fnd-2",
		Title:            "CORS Wildcard Verified Probe",
		Category:         "cors-wildcard",
		Severity:         SeverityLow,
		Confidence:       ConfidenceHigh,
		Status:           FindingStatusConfirmed,
		Target:           "https://app.example.com",
		Endpoint:         "https://app.example.com/api",
		Method:           "GET",
		Fingerprint:      fp,
		AffectedAssetIDs: []string{"ast_2222"},
		Verification: VerificationRecord{
			Status: VerificationVerified,
			Result: "Active wildcard verified on GET /api",
		},
		RemediationAdvice: &RemediationAdvice{
			Summary:    "Configure CORS properly",
			Steps:      []string{"Restrict origins to trusted domains"},
			References: []string{"https://developer.mozilla.org/cors"},
		},
	}

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(deduped))
	}

	merged := deduped[0]
	// Highest status retained
	if merged.Status != FindingStatusConfirmed {
		t.Errorf("expected status CONFIRMED, got %s", merged.Status)
	}
	// Highest confidence retained
	if merged.Confidence != ConfidenceHigh {
		t.Errorf("expected confidence HIGH, got %s", merged.Confidence)
	}
	// Highest verification status retained
	if merged.Verification.Status != VerificationVerified {
		t.Errorf("expected verification status VERIFIED, got %s", merged.Verification.Status)
	}
	// Asset IDs merged and sorted
	if len(merged.AffectedAssetIDs) != 2 || merged.AffectedAssetIDs[0] != "ast_1111" || merged.AffectedAssetIDs[1] != "ast_2222" {
		t.Errorf("expected affected assets [ast_1111, ast_2222], got %+v", merged.AffectedAssetIDs)
	}
	// Primary asset ID preserved
	if merged.PrimaryAssetID != "ast_1111" {
		t.Errorf("expected primary asset ID ast_1111, got %s", merged.PrimaryAssetID)
	}
	// RemediationAdvice steps and references merged
	if merged.RemediationAdvice == nil {
		t.Fatalf("expected non-nil RemediationAdvice")
	}
	if len(merged.RemediationAdvice.Steps) != 2 {
		t.Errorf("expected 2 merged remediation steps, got %d", len(merged.RemediationAdvice.Steps))
	}
	if len(merged.RemediationAdvice.References) != 2 {
		t.Errorf("expected 2 merged remediation references, got %d", len(merged.RemediationAdvice.References))
	}
}

func TestFinding_SanitizeRedactsRemediationAdvice(t *testing.T) {
	secretVal := "ghp_" + "CANARY_SECRET_TOKEN_ABCD1234EFGH"
	f := Finding{
		ID:          "fnd_test",
		Category:    "github-token",
		Target:      "https://app.example.com",
		Endpoint:    "https://app.example.com/api",
		Method:      "GET",
		Remediation: "Rotate " + secretVal,
		RemediationAdvice: &RemediationAdvice{
			Summary:     "Compromised secret: " + secretVal,
			Steps:       []string{"Revoke " + secretVal + " immediately"},
			References:  []string{"https://github.com/settings/tokens?auth=" + secretVal},
			CodeSnippet: "const token = \"" + secretVal + "\";",
		},
	}

	sanitized := SanitizeFinding(f)
	if strings.Contains(sanitized.Remediation, secretVal) {
		t.Errorf("unredacted secret found in Remediation string")
	}
	if sanitized.RemediationAdvice == nil {
		t.Fatalf("expected non-nil sanitized RemediationAdvice")
	}
	if strings.Contains(sanitized.RemediationAdvice.Summary, secretVal) {
		t.Errorf("unredacted secret in RemediationAdvice.Summary")
	}
	for _, s := range sanitized.RemediationAdvice.Steps {
		if strings.Contains(s, secretVal) {
			t.Errorf("unredacted secret in RemediationAdvice.Steps")
		}
	}
	for _, r := range sanitized.RemediationAdvice.References {
		if strings.Contains(r, secretVal) {
			t.Errorf("unredacted secret in RemediationAdvice.References")
		}
	}
	if strings.Contains(sanitized.RemediationAdvice.CodeSnippet, secretVal) {
		t.Errorf("unredacted secret in RemediationAdvice.CodeSnippet")
	}
}

func TestFinding_UnknownSeverityAndConfidence(t *testing.T) {
	f := Finding{
		ID:         "fnd-unknown",
		Category:   "custom-probe",
		Severity:   SeverityUnknown,
		Confidence: ConfidenceUnknown,
		Target:     "https://example.com",
		Endpoint:   "https://example.com/probe",
		Method:     "GET",
	}

	norm := NormalizeFinding(f)
	if norm.Severity != SeverityUnknown {
		t.Errorf("expected Severity UNKNOWN, got %s", norm.Severity)
	}
	if norm.Confidence != ConfidenceUnknown {
		t.Errorf("expected Confidence UNKNOWN, got %s", norm.Confidence)
	}
	if err := ValidateFinding(norm); err != nil {
		t.Errorf("expected UNKNOWN severity and confidence to be valid: %v", err)
	}
}

func TestConnectionIndicatorFinding_NonConflationClassification(t *testing.T) {
	cf := cloud.CloudFinding{
		Provider:         cloud.Provider("postgresql"),
		Category:         "Connection Indicator: postgresql",
		Endpoint:         "postgres.internal:5432",
		Description:      "Detected postgresql connection_string in config.yml. Service connectivity, authentication validity, and resource exposure remain unverified.",
		Evidence:         "Matched postgresql indicator in config.yml (line 12): postgres://user:[REDACTED]@postgres.internal:5432/app",
		Severity:         cloud.SeverityMedium,
		Confidence:       cloud.ConfidenceHigh,
		Fingerprint:      "cld-ind-fingerprint-test",
		NegativeEvidence: "Static analysis only. Zero active network connections or DNS queries were made. Service reachability, credential validity, and resource exposure remain unverified.",
		Details: map[string]string{
			"indicator_type":      "CONNECTION_STRING",
			"technology":          "postgresql",
			"family":              "direct_database",
			"analysis_method":     "STATIC_ANALYSIS",
			"verification_status": "UNVERIFIED",
		},
	}

	finding := FromCloudFinding("https://target.com", cf)

	if finding.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected AnalysisMethodStatic for connection indicator, got %s", finding.AnalysisMethod)
	}
	if finding.Status != FindingStatusSuspected {
		t.Errorf("expected FindingStatusSuspected for connection indicator, got %s", finding.Status)
	}
	if finding.Verification.Status == VerificationVerified {
		t.Errorf("indicator finding must never be VerificationVerified")
	}
	if finding.EvidenceDetails.HTTPStatus != 0 {
		t.Errorf("expected HTTPStatus=0 for static indicator, got %d", finding.EvidenceDetails.HTTPStatus)
	}
	if !strings.Contains(finding.EvidenceDetails.NegativeEvidence, "Zero active network connections") {
		t.Errorf("expected NegativeEvidence in EvidenceDetails to state zero network connections: %s", finding.EvidenceDetails.NegativeEvidence)
	}
}

func TestCorrelate_ConnectionIndicatorWithDiscoveredService(t *testing.T) {
	target := "https://target.com"

	indFinding := Finding{
		ID:         "FND-IND-01",
		RuleID:     "CLD-POSTGRESQL-CONNECTION-INDICATOR",
		Title:      "Connection Indicator (postgresql) with Credentials",
		Category:   "Connection Indicator (postgresql) with Credentials",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Endpoint:   "postgres.internal:5432",
		EvidenceDetails: EvidenceDetails{
			Details: map[string]string{
				"technology":      "postgresql",
				"has_credentials": "true",
			},
		},
	}

	discFinding := Finding{
		ID:         "FND-DISC-01",
		RuleID:     "CLD-POSTGRESQL-DISCOVERY",
		Title:      "Discovered postgresql service (direct_database)",
		Category:   "Service Discovery: postgresql",
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Endpoint:   "postgres.internal:5432",
		EvidenceDetails: EvidenceDetails{
			Details: map[string]string{
				"technology": "postgresql",
			},
		},
	}

	findings, stories := Correlate(target, []Finding{indFinding, discFinding})
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings returned, got %d", len(findings))
	}
	if len(stories) != 1 {
		t.Fatalf("expected 1 correlated security story, got %d", len(stories))
	}

	story := stories[0]
	// Invariant: Indicator correlation must NOT incorrectly upgrade confidence (remains MEDIUM)
	if story.Confidence != ConfidenceMedium {
		t.Errorf("expected story Confidence to be %s (not upgraded), got %s", ConfidenceMedium, story.Confidence)
	}
	if story.Severity != SeverityHigh {
		t.Errorf("expected story Severity to be %s, got %s", SeverityHigh, story.Severity)
	}
	if len(story.RelatedIDs) != 2 {
		t.Errorf("expected 2 related IDs in story, got %d", len(story.RelatedIDs))
	}
	if !strings.Contains(story.Description, "remain unverified") {
		t.Errorf("expected story Description to state that connectivity and credential validity remain unverified: %s", story.Description)
	}
}

func TestFromAPIFinding_DjangoAndFastAPI(t *testing.T) {
	target := "https://app.example.com"

	cases := []struct {
		apiFinding      api.APIFinding
		expectedRule    string
		expectedStatus  FindingStatus
		expectedVer     VerificationStatus
		expectedSev     string
		expectedRemSub  string
	}{
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryDjangoDebugMode,
				Endpoint:    "https://app.example.com/admin/login/",
				Method:      "GET",
				Description: "Django technical 500 debug page exposed (DEBUG=True confirmed)",
				Severity:    api.SeverityHigh,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryDjangoDebugMode, "https://app.example.com/admin/login/", "GET"),
			},
			expectedRule:   "API-DJANGO-DEBUG-MODE",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationVerified,
			expectedSev:    SeverityHigh,
			expectedRemSub: "DEBUG = False",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryDjangoDebugMode,
				Endpoint:    "https://app.example.com/api/crash",
				Method:      "GET",
				Description: "Django framework exception traceback and internal path disclosure (suspected debug mode)",
				Severity:    api.SeverityMedium,
				Confidence:  api.ConfidenceMedium,
				Fingerprint: api.GenerateFingerprint(api.CategoryDjangoDebugMode, "https://app.example.com/api/crash", "GET"),
			},
			expectedRule:   "API-DJANGO-DEBUG-MODE",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityMedium,
			expectedRemSub: "DEBUG = False",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryDjangoURLConfDisclosure,
				Endpoint:    "https://app.example.com/_felix_django_404_probe",
				Method:      "GET",
				Description: "Django technical 404 page exposed application URLconf routing patterns",
				Severity:    api.SeverityMedium,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryDjangoURLConfDisclosure, "https://app.example.com/_felix_django_404_probe", "GET"),
			},
			expectedRule:   "API-DJANGO-URLCONF-DISCLOSURE",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationVerified,
			expectedSev:    SeverityMedium,
			expectedRemSub: "URLconf",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryDjangoBrowsableAPI,
				Endpoint:    "https://app.example.com/api/",
				Method:      "GET",
				Description: "Django REST Framework browsable API exposed publicly",
				Severity:    api.SeverityLow,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryDjangoBrowsableAPI, "https://app.example.com/api/", "GET"),
			},
			expectedRule:   "API-DJANGO-BROWSABLE-API",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityLow,
			expectedRemSub: "BrowsableAPIRenderer",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryFastAPIDocs,
				Endpoint:    "https://app.example.com/docs",
				Method:      "GET",
				Description: "Publicly accessible FastAPI interactive documentation (/docs)",
				Severity:    api.SeverityInfo,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryFastAPIDocs, "https://app.example.com/docs", "GET"),
			},
			expectedRule:   "API-FASTAPI-DOCS-EXPOSURE",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityInfo,
			expectedRemSub: "docs_url=None",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryFastAPISensitivePaths,
				Endpoint:    "https://app.example.com/openapi.json",
				Method:      "GET",
				Description: "FastAPI OpenAPI schema contains internal or administrative route definitions (route visibility observation)",
				Severity:    api.SeverityInfo,
				Confidence:  api.ConfidenceLow,
				Fingerprint: api.GenerateFingerprint(api.CategoryFastAPISensitivePaths, "https://app.example.com/openapi.json", "GET"),
			},
			expectedRule:   "API-FASTAPI-SENSITIVE-PATHS",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityInfo,
			expectedRemSub: "include_in_schema=False",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryFastAPISensitiveSchema,
				Endpoint:    "https://app.example.com/openapi.json",
				Method:      "GET",
				Description: "FastAPI OpenAPI schema contains embedded credentials or sensitive defaults",
				Severity:    api.SeverityHigh,
				Confidence:  api.ConfidenceMedium,
				Fingerprint: api.GenerateFingerprint(api.CategoryFastAPISensitiveSchema, "https://app.example.com/openapi.json", "GET"),
			},
			expectedRule:   "API-FASTAPI-SENSITIVE-SCHEMA",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationVerified,
			expectedSev:    SeverityHigh,
			expectedRemSub: "Remove sensitive credentials",
		},
	}

	for _, tc := range cases {
		f := FromAPIFinding(target, tc.apiFinding)

		if f.RuleID != tc.expectedRule {
			t.Errorf("category %s: expected RuleID %s, got %s", tc.apiFinding.Category, tc.expectedRule, f.RuleID)
		}
		if f.Status != tc.expectedStatus {
			t.Errorf("category %s: expected Status %s, got %s", tc.apiFinding.Category, tc.expectedStatus, f.Status)
		}
		if f.Verification.Status != tc.expectedVer {
			t.Errorf("category %s: expected Verification.Status %s, got %s", tc.apiFinding.Category, tc.expectedVer, f.Verification.Status)
		}
		if f.Severity != tc.expectedSev {
			t.Errorf("category %s: expected Severity %s, got %s", tc.apiFinding.Category, tc.expectedSev, f.Severity)
		}

		rem := RemediationFor(tc.apiFinding.Category, f.Title)
		if !strings.Contains(rem, tc.expectedRemSub) {
			t.Errorf("category %s: expected remediation to contain %q, got: %s", tc.apiFinding.Category, tc.expectedRemSub, rem)
		}
	}
}

func TestFromAPIFinding_Laravel(t *testing.T) {
	target := "https://app.example.com"

	cases := []struct {
		apiFinding     api.APIFinding
		expectedRule   string
		expectedStatus FindingStatus
		expectedVer    VerificationStatus
		expectedSev    string
		expectedRemSub string
	}{
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryLaravelIgnitionDebug,
				Endpoint:    "https://app.example.com/_felix_ignition_probe",
				Method:      "GET",
				Description: "Laravel Ignition debug page exposed (APP_DEBUG=true confirmed)",
				Severity:    api.SeverityHigh,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryLaravelIgnitionDebug, "https://app.example.com/_felix_ignition_probe", "GET"),
			},
			expectedRule:   "API-LARAVEL-IGNITION-DEBUG",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationVerified,
			expectedSev:    SeverityHigh,
			expectedRemSub: "APP_DEBUG=false",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryLaravelIgnitionDebug,
				Endpoint:    "https://app.example.com/api/error",
				Method:      "GET",
				Description: "Laravel framework exception traceback observed (suspected debug mode)",
				Severity:    api.SeverityMedium,
				Confidence:  api.ConfidenceMedium,
				Fingerprint: api.GenerateFingerprint(api.CategoryLaravelIgnitionDebug, "https://app.example.com/api/error", "GET"),
			},
			expectedRule:   "API-LARAVEL-IGNITION-DEBUG",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityMedium,
			expectedRemSub: "APP_DEBUG=false",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryLaravelTelescopeProtected,
				Endpoint:    "https://app.example.com/telescope",
				Method:      "GET",
				Description: "Laravel Telescope monitoring dashboard access restricted",
				Severity:    api.SeverityInfo,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryLaravelTelescopeProtected, "https://app.example.com/telescope", "GET"),
			},
			expectedRule:   "API-LARAVEL-TELESCOPE-RESTRICTED",
			expectedStatus: FindingStatusInconclusive,
			expectedVer:    VerificationNotExposed,
			expectedSev:    SeverityInfo,
			expectedRemSub: "Telescope::auth",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryLaravelTelescopeExposed,
				Endpoint:    "https://app.example.com/telescope",
				Method:      "GET",
				Description: "Laravel Telescope monitoring dashboard reachable (interface shell)",
				Severity:    api.SeverityInfo,
				Confidence:  api.ConfidenceMedium,
				Fingerprint: api.GenerateFingerprint(api.CategoryLaravelTelescopeExposed, "https://app.example.com/telescope", "GET"),
			},
			expectedRule:   "API-LARAVEL-TELESCOPE-EXPOSURE",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationObserved,
			expectedSev:    SeverityInfo,
			expectedRemSub: "Telescope::auth",
		},
		{
			apiFinding: api.APIFinding{
				Category:    api.CategoryLaravelTelescopeData,
				Endpoint:    "https://app.example.com/telescope/telescope-api/requests",
				Method:      "GET",
				Description: "Laravel Telescope unauthenticated monitoring telemetry disclosure",
				Severity:    api.SeverityHigh,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: api.GenerateFingerprint(api.CategoryLaravelTelescopeData, "https://app.example.com/telescope/telescope-api/requests", "GET"),
			},
			expectedRule:   "API-LARAVEL-TELESCOPE-SENSITIVE-DATA",
			expectedStatus: FindingStatusConfirmed,
			expectedVer:    VerificationVerified,
			expectedSev:    SeverityHigh,
			expectedRemSub: "Telescope::auth",
		},
	}

	for _, tc := range cases {
		f := FromAPIFinding(target, tc.apiFinding)

		if f.RuleID != tc.expectedRule {
			t.Errorf("category %s: expected RuleID %s, got %s", tc.apiFinding.Category, tc.expectedRule, f.RuleID)
		}
		if f.Status != tc.expectedStatus {
			t.Errorf("category %s: expected Status %s, got %s", tc.apiFinding.Category, tc.expectedStatus, f.Status)
		}
		if f.Verification.Status != tc.expectedVer {
			t.Errorf("category %s: expected Verification.Status %s, got %s", tc.apiFinding.Category, tc.expectedVer, f.Verification.Status)
		}
		if f.Severity != tc.expectedSev {
			t.Errorf("category %s: expected Severity %s, got %s", tc.apiFinding.Category, tc.expectedSev, f.Severity)
		}

		rem := RemediationFor(tc.apiFinding.Category, f.Title)
		if !strings.Contains(rem, tc.expectedRemSub) {
			t.Errorf("category %s: expected remediation to contain %q, got: %s", tc.apiFinding.Category, tc.expectedRemSub, rem)
		}
	}
}
