package report

import (
	"strings"
	"testing"

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
