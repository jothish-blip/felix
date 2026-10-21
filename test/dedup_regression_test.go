package test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
)

// =============================================================================
// PHASE 6.4: FINDING DEDUPLICATION — COMPREHENSIVE REGRESSION SUITE
// Production-Oriented Verification Across 16 Rigorous Categories
// =============================================================================

func helperMakeDedupFinding(id, title, category, severity, confidence string, status report.VerificationStatus, target, endpoint, method string) report.Finding {
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
			Observation: "Initial detector observation",
			Details: map[string]string{
				"route": endpoint,
			},
		},
		Timestamp: time.Now().UTC(),
	}
	f.Score = report.CalculateFindingScore(f)
	expl := report.ExplainFindingScore(f)
	f.ScoreExplanation = &expl
	f.Fingerprint = correlation.ComputeStableFingerprint(f)
	return f
}

// -----------------------------------------------------------------------------
// Category 1: Identical Validated Fingerprints Consolidation
// -----------------------------------------------------------------------------
func TestDedup_Category01_IdenticalFingerprintConsolidation(t *testing.T) {
	f1 := helperMakeDedupFinding("fnd_dup_1", "SQL Injection on user_id", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	f1.EvidenceDetails.Details["parameter"] = "user_id"
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_dup_2", "SQL Injection on user_id", "sqli", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	f2.EvidenceDetails.Details["parameter"] = "user_id"
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	f3 := helperMakeDedupFinding("fnd_dup_3", "SQL Injection on user_id", "sqli", report.SeverityMedium, report.ConfidenceLow, report.VerificationNotVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	f3.EvidenceDetails.Details["parameter"] = "user_id"
	f3.Fingerprint = correlation.ComputeStableFingerprint(f3)

	if f1.Fingerprint != f2.Fingerprint || f2.Fingerprint != f3.Fingerprint {
		t.Fatalf("Test setup failure: fingerprints must match: fp1=%s, fp2=%s, fp3=%s", f1.Fingerprint, f2.Fingerprint, f3.Fingerprint)
	}

	res := correlation.DeduplicateFindings([]report.Finding{f1, f2, f3})
	if len(res) != 1 {
		t.Fatalf("Expected 3 duplicate findings to consolidate into 1 canonical finding, got %d", len(res))
	}

	canon := res[0]
	if canon.ID != f1.ID {
		t.Errorf("Expected canonical finding ID to be %s (VERIFIED authoritative), got %s", f1.ID, canon.ID)
	}
	if canon.Verification.Status != report.VerificationVerified {
		t.Errorf("Expected canonical verification status %s, got %s", report.VerificationVerified, canon.Verification.Status)
	}

	dupIDs := canon.EvidenceDetails.Details["duplicate_finding_ids"]
	if !strings.Contains(dupIDs, "fnd_dup_2") || !strings.Contains(dupIDs, "fnd_dup_3") {
		t.Errorf("Expected duplicate IDs to record merged findings, got: %s", dupIDs)
	}
	if canon.EvidenceDetails.Details["duplicate_count"] != "2" {
		t.Errorf("Expected duplicate_count to be 2, got %s", canon.EvidenceDetails.Details["duplicate_count"])
	}
}

// -----------------------------------------------------------------------------
// Category 2: Input-Order Independence
// -----------------------------------------------------------------------------
func TestDedup_Category02_InputOrderIndependence(t *testing.T) {
	f1 := helperMakeDedupFinding("fnd_ord_1", "BOLA on user profile", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/profiles", "GET")
	f1.EvidenceDetails.Details["parameter"] = "id"
	f1.EvidenceDetails.Observation = "Observation from Scanner 1"
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_ord_2", "BOLA on user profile", "bola", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/profiles", "GET")
	f2.EvidenceDetails.Details["parameter"] = "id"
	f2.EvidenceDetails.Observation = "Observation from Scanner 2"
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	f3 := helperMakeDedupFinding("fnd_ord_3", "BOLA on user profile", "bola", report.SeverityMedium, report.ConfidenceLow, report.VerificationObserved, "https://api.example.com", "https://api.example.com/v1/profiles", "GET")
	f3.EvidenceDetails.Details["parameter"] = "id"
	f3.EvidenceDetails.Observation = "Observation from Scanner 3"
	f3.Fingerprint = correlation.ComputeStableFingerprint(f3)

	permutations := [][]report.Finding{
		{f1, f2, f3},
		{f1, f3, f2},
		{f2, f1, f3},
		{f2, f3, f1},
		{f3, f1, f2},
		{f3, f2, f1},
	}

	var baseRes []report.Finding
	for i, perm := range permutations {
		out := correlation.DeduplicateFindings(perm)
		if len(out) != 1 {
			t.Fatalf("Permutation %d: expected 1 finding, got %d", i, len(out))
		}
		if i == 0 {
			baseRes = out
		} else {
			if out[0].ID != baseRes[0].ID {
				t.Errorf("Permutation %d ID mismatch: expected %s, got %s", i, baseRes[0].ID, out[0].ID)
			}
			if out[0].Score != baseRes[0].Score {
				t.Errorf("Permutation %d Score mismatch: expected %d, got %d", i, baseRes[0].Score, out[0].Score)
			}
			if out[0].EvidenceDetails.Observation != baseRes[0].EvidenceDetails.Observation {
				t.Errorf("Permutation %d Observation mismatch:\nExpected: %q\nGot:      %q", i, baseRes[0].EvidenceDetails.Observation, out[0].EvidenceDetails.Observation)
			}
			if out[0].EvidenceDetails.Details["duplicate_finding_ids"] != baseRes[0].EvidenceDetails.Details["duplicate_finding_ids"] {
				t.Errorf("Permutation %d duplicate_finding_ids mismatch: %s vs %s", i, baseRes[0].EvidenceDetails.Details["duplicate_finding_ids"], out[0].EvidenceDetails.Details["duplicate_finding_ids"])
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 3: Idempotency
// -----------------------------------------------------------------------------
func TestDedup_Category03_Idempotency(t *testing.T) {
	f1 := helperMakeDedupFinding("fnd_idemp_1", "IDOR in Billing", "idor", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/billing", "GET")
	f1.EvidenceDetails.Details["parameter"] = "account_id"
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_idemp_2", "IDOR in Billing", "idor", report.SeverityHigh, report.ConfidenceHigh, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/billing", "GET")
	f2.EvidenceDetails.Details["parameter"] = "account_id"
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	firstPass := correlation.DeduplicateFindings([]report.Finding{f1, f2})
	if len(firstPass) != 1 {
		t.Fatalf("First pass: expected 1 finding, got %d", len(firstPass))
	}

	secondPass := correlation.DeduplicateFindings(firstPass)
	if len(secondPass) != 1 {
		t.Fatalf("Second pass: expected 1 finding, got %d", len(secondPass))
	}

	if !reflect.DeepEqual(firstPass[0], secondPass[0]) {
		t.Errorf("Idempotency violation: second pass modified canonical finding:\nPass 1: %+v\nPass 2: %+v", firstPass[0], secondPass[0])
	}
}

// -----------------------------------------------------------------------------
// Category 4: Differentiation of Different Vulnerabilities on Same Endpoint
// -----------------------------------------------------------------------------
func TestDedup_Category04_DifferentVulnerabilitiesSameEndpoint(t *testing.T) {
	endpoint := "https://api.example.com/v1/search"
	target := "https://api.example.com"

	fSQLi := helperMakeDedupFinding("fnd_diff_sqli", "SQL Injection in Search", "sqli", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fSQLi.EvidenceDetails.Details["parameter"] = "q"
	fSQLi.Fingerprint = correlation.ComputeStableFingerprint(fSQLi)

	fXSS := helperMakeDedupFinding("fnd_diff_xss", "Reflected XSS in Search", "xss", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fXSS.EvidenceDetails.Details["parameter"] = "q"
	fXSS.Fingerprint = correlation.ComputeStableFingerprint(fXSS)

	fBOLA := helperMakeDedupFinding("fnd_diff_bola", "BOLA in Search", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fBOLA.EvidenceDetails.Details["parameter"] = "user_id"
	fBOLA.Fingerprint = correlation.ComputeStableFingerprint(fBOLA)

	fSSRF := helperMakeDedupFinding("fnd_diff_ssrf", "SSRF in Search", "ssrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fSSRF.EvidenceDetails.Details["parameter"] = "callback"
	fSSRF.Fingerprint = correlation.ComputeStableFingerprint(fSSRF)

	all := []report.Finding{fSQLi, fXSS, fBOLA, fSSRF}
	res := correlation.DeduplicateFindings(all)

	if len(res) != 4 {
		t.Fatalf("Expected all 4 distinct vulnerability types on same endpoint to remain separate, got %d", len(res))
	}

	seenIDs := make(map[string]bool)
	for _, f := range res {
		seenIDs[f.ID] = true
	}
	for _, f := range all {
		if !seenIDs[f.ID] {
			t.Errorf("Missing distinct finding %s after deduplication", f.ID)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 5: Differentiation of Different Endpoints and Resources
// -----------------------------------------------------------------------------
func TestDedup_Category05_DifferentEndpointsSameVuln(t *testing.T) {
	target := "https://api.example.com"

	fUsers := helperMakeDedupFinding("fnd_ep_users", "SQL Injection on id", "sqli", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, target, "https://api.example.com/v1/users", "GET")
	fUsers.EvidenceDetails.Details["parameter"] = "id"
	fUsers.Fingerprint = correlation.ComputeStableFingerprint(fUsers)

	fOrders := helperMakeDedupFinding("fnd_ep_orders", "SQL Injection on id", "sqli", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, target, "https://api.example.com/v1/orders", "GET")
	fOrders.EvidenceDetails.Details["parameter"] = "id"
	fOrders.Fingerprint = correlation.ComputeStableFingerprint(fOrders)

	fProducts := helperMakeDedupFinding("fnd_ep_products", "SQL Injection on id", "sqli", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, target, "https://api.example.com/v1/products", "GET")
	fProducts.EvidenceDetails.Details["parameter"] = "id"
	fProducts.Fingerprint = correlation.ComputeStableFingerprint(fProducts)

	res := correlation.DeduplicateFindings([]report.Finding{fUsers, fOrders, fProducts})
	if len(res) != 3 {
		t.Fatalf("Expected 3 different endpoints with same vuln type to remain distinct, got %d", len(res))
	}
}

// -----------------------------------------------------------------------------
// Category 6: Tenant and Account Boundary Isolation
// -----------------------------------------------------------------------------
func TestDedup_Category06_TenantBoundaryIsolation(t *testing.T) {
	target := "https://api.example.com"
	endpoint := "https://api.example.com/v1/data"

	fTenantA := helperMakeDedupFinding("fnd_tenant_a", "Sensitive Data Exposure", "info_leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fTenantA.EvidenceDetails.Details["tenant_id"] = "tenant_alpha"
	fTenantA.Fingerprint = correlation.ComputeStableFingerprint(fTenantA)

	fTenantB := helperMakeDedupFinding("fnd_tenant_b", "Sensitive Data Exposure", "info_leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fTenantB.EvidenceDetails.Details["tenant_id"] = "tenant_beta"
	fTenantB.Fingerprint = correlation.ComputeStableFingerprint(fTenantB)

	fAccountA := helperMakeDedupFinding("fnd_acct_a", "Sensitive Data Exposure", "info_leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fAccountA.EvidenceDetails.Details["account_id"] = "acct_1001"
	fAccountA.Fingerprint = correlation.ComputeStableFingerprint(fAccountA)

	fAccountB := helperMakeDedupFinding("fnd_acct_b", "Sensitive Data Exposure", "info_leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	fAccountB.EvidenceDetails.Details["account_id"] = "acct_2002"
	fAccountB.Fingerprint = correlation.ComputeStableFingerprint(fAccountB)

	res := correlation.DeduplicateFindings([]report.Finding{fTenantA, fTenantB, fAccountA, fAccountB})
	if len(res) != 4 {
		t.Fatalf("Security failure: cross-tenant / cross-account findings must NEVER be consolidated! Expected 4, got %d", len(res))
	}
}

// -----------------------------------------------------------------------------
// Category 7: Invalid, Legacy, or Cross-Copied Fingerprint Neutralization
// -----------------------------------------------------------------------------
func TestDedup_Category07_FingerprintNeutralization(t *testing.T) {
	// Finding A on /v1/users
	fA := helperMakeDedupFinding("fnd_leg_a", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	fA.EvidenceDetails.Details["parameter"] = "user_id"
	fA.Fingerprint = correlation.ComputeStableFingerprint(fA)

	// Finding B on /v1/admin, but someone cross-copied fA's fingerprint onto fB!
	fB := helperMakeDedupFinding("fnd_leg_b", "Command Injection", "cmdi", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/admin", "POST")
	fB.Fingerprint = fA.Fingerprint // Malicious or corrupted copy

	// Finding C with legacy/malformed fingerprint string
	fC := helperMakeDedupFinding("fnd_leg_c", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/reports", "GET")
	fC.Fingerprint = "legacy_fp_12345"

	res := correlation.DeduplicateFindings([]report.Finding{fA, fB, fC})
	if len(res) != 3 {
		t.Fatalf("Expected invalid and cross-copied fingerprints to be validated/recomputed and kept distinct, got %d", len(res))
	}

	for _, f := range res {
		if len(f.Fingerprint) != 64 || !correlation.IsValidFingerprint(f, f.Fingerprint) {
			t.Errorf("Finding %s did not have validated v2 fingerprint after dedup: %s", f.ID, f.Fingerprint)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 8: Ambiguous and Incomplete Findings Isolation
// -----------------------------------------------------------------------------
func TestDedup_Category08_AmbiguousFindingsIsolation(t *testing.T) {
	// Ambiguous finding without clean endpoint or target
	fAmb1 := report.Finding{
		ID:          "fnd_amb_1",
		Title:       "Suspected Anomaly",
		Category:    "anomaly",
		Severity:    report.SeverityLow,
		Confidence:  report.ConfidenceLow,
		Target:      "",
		Endpoint:    "",
		Fingerprint: "",
	}
	fAmb1.Score = report.CalculateFindingScore(fAmb1)

	fAmb2 := report.Finding{
		ID:          "fnd_amb_2",
		Title:       "Suspected Anomaly",
		Category:    "anomaly",
		Severity:    report.SeverityLow,
		Confidence:  report.ConfidenceLow,
		Target:      "",
		Endpoint:    "",
		Fingerprint: "",
	}
	fAmb2.Score = report.CalculateFindingScore(fAmb2)

	res := correlation.DeduplicateFindings([]report.Finding{fAmb1, fAmb2})
	if len(res) != 2 {
		t.Fatalf("Ambiguous findings missing essential identity attributes must never be merged. Expected 2, got %d", len(res))
	}
}

// -----------------------------------------------------------------------------
// Category 9: Evidence and Provenance Preservation
// -----------------------------------------------------------------------------
func TestDedup_Category09_EvidenceAndProvenancePreservation(t *testing.T) {
	target := "https://api.example.com"
	endpoint := "https://api.example.com/v1/items"

	earlyTime := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	lateTime := time.Date(2026, 10, 10, 15, 30, 0, 0, time.UTC)

	// F1: Verified with curl command and reproduction steps
	f1 := helperMakeDedupFinding("fnd_ev_1", "Path Traversal", "traversal", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	f1.EvidenceDetails.Details["parameter"] = "filepath"
	f1.EvidenceDetails.Details["os_type"] = "linux"
	f1.EvidenceDetails.Observation = "Observed /etc/passwd contents in response"
	f1.EvidenceDetails.Location = "query:filepath"
	f1.Verification.SafeCurlCommand = "curl -X GET 'https://api.example.com/v1/items?filepath=../../../../etc/passwd'"
	f1.Verification.ReproductionSteps = []string{"1. Send GET request with traversal payload.", "2. Observe passwd file."}
	f1.Timestamp = earlyTime
	f1.AffectedAssetIDs = []string{"asset_item_service"}
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	// F2: Detected duplicate with additional observation and asset
	f2 := helperMakeDedupFinding("fnd_ev_2", "Path Traversal", "traversal", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, target, endpoint, "GET")
	f2.EvidenceDetails.Details["parameter"] = "filepath"
	f2.EvidenceDetails.Details["backend"] = "nginx"
	f2.EvidenceDetails.Observation = "Backend returned status 200 with root entry"
	f2.EvidenceDetails.Location = "header:x-forwarded-host"
	f2.Timestamp = lateTime
	f2.AffectedAssetIDs = []string{"asset_item_service", "asset_storage_backend"}
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	res := correlation.DeduplicateFindings([]report.Finding{f1, f2})
	if len(res) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(res))
	}

	canon := res[0]
	// Verify observations aggregated
	if !strings.Contains(canon.EvidenceDetails.Observation, "Observed /etc/passwd contents") ||
		!strings.Contains(canon.EvidenceDetails.Observation, "Backend returned status 200") {
		t.Errorf("Observations were not merged properly: %s", canon.EvidenceDetails.Observation)
	}

	// Verify curl command and reproduction steps preserved
	if canon.Verification.SafeCurlCommand != f1.Verification.SafeCurlCommand {
		t.Errorf("Curl command was lost or corrupted: %s", canon.Verification.SafeCurlCommand)
	}
	if len(canon.Verification.ReproductionSteps) < 2 {
		t.Errorf("Reproduction steps lost: %+v", canon.Verification.ReproductionSteps)
	}

	// Verify details merged
	if canon.EvidenceDetails.Details["os_type"] != "linux" || canon.EvidenceDetails.Details["backend"] != "nginx" {
		t.Errorf("Details map was not merged cleanly: %+v", canon.EvidenceDetails.Details)
	}

	// Verify locations merged
	if !strings.Contains(canon.EvidenceDetails.Location, "query:filepath") || !strings.Contains(canon.EvidenceDetails.Location, "header:x-forwarded-host") {
		t.Errorf("Locations not unioned properly: %s", canon.EvidenceDetails.Location)
	}

	// Verify affected asset IDs unioned
	assets := strings.Join(canon.AffectedAssetIDs, ",")
	if !strings.Contains(assets, "asset_item_service") || !strings.Contains(assets, "asset_storage_backend") {
		t.Errorf("Affected assets not unioned properly: %+v", canon.AffectedAssetIDs)
	}

	// Verify earliest timestamp preserved
	if !canon.Timestamp.Equal(earlyTime) {
		t.Errorf("Expected earliest timestamp %v, got %v", earlyTime, canon.Timestamp)
	}
}

// -----------------------------------------------------------------------------
// Category 10: Conflicting Verification States & Risk Score Reconciliation
// -----------------------------------------------------------------------------
func TestDedup_Category10_VerificationPrecedenceAndRiskReconciliation(t *testing.T) {
	target := "https://api.example.com"
	endpoint := "https://api.example.com/v1/auth"

	// Weak candidate finding
	fWeak := helperMakeDedupFinding("fnd_conf_weak", "Weak Auth Token", "auth", report.SeverityLow, report.ConfidenceLow, report.VerificationNotVerified, target, endpoint, "POST")
	fWeak.EvidenceDetails.Details["parameter"] = "token"
	fWeak.Fingerprint = correlation.ComputeStableFingerprint(fWeak)

	// Authoritative verified finding
	fStrong := helperMakeDedupFinding("fnd_conf_strong", "Weak Auth Token", "auth", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "POST")
	fStrong.EvidenceDetails.Details["parameter"] = "token"
	fStrong.Fingerprint = correlation.ComputeStableFingerprint(fStrong)

	res := correlation.DeduplicateFindings([]report.Finding{fWeak, fStrong})
	if len(res) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(res))
	}

	canon := res[0]
	if canon.ID != fStrong.ID {
		t.Errorf("Expected canonical finding to be %s (VERIFIED), got %s", fStrong.ID, canon.ID)
	}
	if canon.Verification.Status != report.VerificationVerified {
		t.Errorf("Expected canonical status VERIFIED, got %s", canon.Verification.Status)
	}

	// Ensure score matches authoritative calculation
	expectedScore := report.CalculateFindingScore(canon)
	if canon.Score != expectedScore {
		t.Errorf("Reconciled score mismatch: expected %d, got %d", expectedScore, canon.Score)
	}
	if canon.ScoreExplanation == nil || canon.ScoreExplanation.Score != canon.Score {
		t.Errorf("Score explanation out of sync with final score: explanation=%v, score=%d", canon.ScoreExplanation, canon.Score)
	}
}

// -----------------------------------------------------------------------------
// Category 11: Traceability of Merged IDs and Source References
// -----------------------------------------------------------------------------
func TestDedup_Category11_TraceabilityAndDuplicateMap(t *testing.T) {
	target := "https://api.example.com"
	endpoint := "https://api.example.com/v1/docs"

	f1 := helperMakeDedupFinding("fnd_tr_1", "Directory Listing", "info_leak", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, target, endpoint, "GET")
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_tr_2", "Directory Listing", "info_leak", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, target, endpoint, "GET")
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	f3 := helperMakeDedupFinding("fnd_tr_3", "Directory Listing", "info_leak", report.SeverityLow, report.ConfidenceLow, report.VerificationObserved, target, endpoint, "GET")
	f3.Fingerprint = correlation.ComputeStableFingerprint(f3)

	dedup := correlation.NewDeduplicator(nil)
	res := dedup.Deduplicate([]report.Finding{f1, f2, f3})

	if res.DeduplicatedCount != 1 || res.TotalInputCount != 3 {
		t.Fatalf("Expected 3 inputs to produce 1 canonical, got %d canonicals from %d inputs", res.DeduplicatedCount, res.TotalInputCount)
	}

	// Verify duplicate map
	if res.DuplicateMap["fnd_tr_2"] != "fnd_tr_1" {
		t.Errorf("Expected duplicate map for fnd_tr_2 to be fnd_tr_1, got %s", res.DuplicateMap["fnd_tr_2"])
	}
	if res.DuplicateMap["fnd_tr_3"] != "fnd_tr_1" {
		t.Errorf("Expected duplicate map for fnd_tr_3 to be fnd_tr_1, got %s", res.DuplicateMap["fnd_tr_3"])
	}

	// Verify canonical finding details
	canon := res.CanonicalFindings[0]
	dupIDs := canon.EvidenceDetails.Details["duplicate_finding_ids"]
	if !strings.Contains(dupIDs, "fnd_tr_2") || !strings.Contains(dupIDs, "fnd_tr_3") {
		t.Errorf("duplicate_finding_ids did not contain both merged IDs: %s", dupIDs)
	}
}

// -----------------------------------------------------------------------------
// Category 12: Assessment Lifecycle and Cross-Assessment Compatibility
// -----------------------------------------------------------------------------
func TestDedup_Category12_CrossAssessmentLifecycleCompatibility(t *testing.T) {
	// Baseline assessment findings (Run 1)
	fBase1 := helperMakeDedupFinding("fnd_base_1", "CSRF on Payment", "csrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/pay", "POST")
	fBase1.Fingerprint = correlation.ComputeStableFingerprint(fBase1)

	fBase2 := helperMakeDedupFinding("fnd_base_2", "Open Redirect", "redirect", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/login", "GET")
	fBase2.Fingerprint = correlation.ComputeStableFingerprint(fBase2)

	// Current assessment findings before dedup (Run 2 has duplicates of fBase1)
	fCurr1A := helperMakeDedupFinding("fnd_curr_1a", "CSRF on Payment", "csrf", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/pay", "POST")
	fCurr1A.Fingerprint = correlation.ComputeStableFingerprint(fCurr1A)

	fCurr1B := helperMakeDedupFinding("fnd_curr_1b", "CSRF on Payment", "csrf", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/pay", "POST")
	fCurr1B.Fingerprint = correlation.ComputeStableFingerprint(fCurr1B)

	// Deduplicate current run
	currentDeduped := correlation.DeduplicateFindings([]report.Finding{fCurr1A, fCurr1B})
	if len(currentDeduped) != 1 {
		t.Fatalf("Expected current run to deduplicate to 1 finding, got %d", len(currentDeduped))
	}

	// Convert to AssessmentFinding format
	baselineAF := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding("asm_1", "exec_1", "tgt_1", fBase1),
		assessment.ToAssessmentFinding("asm_1", "exec_1", "tgt_1", fBase2),
	}
	currentAF := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding("asm_1", "exec_2", "tgt_1", currentDeduped[0]),
	}

	// Compare assessments
	comparison := assessment.CompareAssessmentFindings(baselineAF, currentAF)
	if comparison.RecurringCount != 1 {
		t.Errorf("Expected 1 recurring finding, got %d", comparison.RecurringCount)
	}
	if comparison.ResolvedCount != 1 {
		t.Errorf("Expected 1 resolved finding, got %d", comparison.ResolvedCount)
	}
	if comparison.NewCount != 0 {
		t.Errorf("Expected 0 new findings, got %d", comparison.NewCount)
	}
}

// -----------------------------------------------------------------------------
// Category 13: Controller and Persistence Integration
// -----------------------------------------------------------------------------
func TestDedup_Category13_ControllerAndPersistenceIntegration(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "felix-dedup-store-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	dbPath := filepath.Join(tempDir, "felix_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to create assessment store: %v", err)
	}
	defer store.Close()

	clientID := "cli_dedup_01"
	assessmentID := "asm_dedup_test"
	execID := "exec_dedup_001"
	targetID := "tgt_001"

	// 1. Create client
	client := &assessment.Client{ID: clientID, Name: "Dedup Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// 2. Create assessment record
	asm := &assessment.Assessment{
		ID:             assessmentID,
		Ref:            "ASM-2026-DEDUP",
		ClientID:       clientID,
		Name:           "Dedup Test",
		ScopeMode:      "same-origin",
		AssessmentType: "API_AUDIT",
		Status:         assessment.StatusDraft,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("Failed to create assessment: %v", err)
	}

	// 3. Create target
	target := &assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("Failed to add target: %v", err)
	}

	// 4. Create execution
	exec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("Failed to create execution: %v", err)
	}

	// Simulate 2 duplicate findings
	f1 := helperMakeDedupFinding("fnd_store_1", "Header Injection", "crlf", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/redir", "GET")
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_store_2", "Header Injection", "crlf", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/redir", "GET")
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	// Deduplicate via assessment helper
	rawAFs := []assessment.AssessmentFinding{
		assessment.ToAssessmentFinding(assessmentID, execID, targetID, f1),
		assessment.ToAssessmentFinding(assessmentID, execID, targetID, f2),
	}

	dedupedAFs := assessment.DeduplicateAssessmentFindings(rawAFs)
	if len(dedupedAFs) != 1 {
		t.Fatalf("Expected DeduplicateAssessmentFindings to reduce 2 duplicates to 1, got %d", len(dedupedAFs))
	}

	// Persist
	if err := store.SaveFindings(dedupedAFs); err != nil {
		t.Fatalf("Failed to persist deduplicated findings to SQLite: %v", err)
	}

	// Retrieve
	loaded, err := store.GetFindings(assessmentID, execID)
	if err != nil {
		t.Fatalf("Failed to load findings from SQLite: %v", err)
	}
	if len(loaded) != 1 {
		t.Fatalf("Expected exactly 1 finding stored in SQLite, got %d", len(loaded))
	}
}

// -----------------------------------------------------------------------------
// Category 14: Relationship Remapping and Attack Path Integrity
// -----------------------------------------------------------------------------
func TestDedup_Category14_RelationshipAndAttackPathRemapping(t *testing.T) {
	// Original findings:
	// A1 and A2 are duplicates (A1 is canonical)
	// B1 and B2 are duplicates (B1 is canonical)
	dupMap := map[string]string{
		"fnd_A2": "fnd_A1",
		"fnd_B2": "fnd_B1",
	}

	relationships := []correlation.Relationship{
		{
			ID:              "rel_1",
			SourceFindingID: "fnd_A1",
			TargetFindingID: "fnd_B1",
			Type:            correlation.RelEnables,
		},
		{
			// Duplicate edge from A2 to B2
			ID:              "rel_2",
			SourceFindingID: "fnd_A2",
			TargetFindingID: "fnd_B2",
			Type:            correlation.RelEnables,
		},
		{
			// Self-loop edge between A1 and A2
			ID:              "rel_3",
			SourceFindingID: "fnd_A1",
			TargetFindingID: "fnd_A2",
			Type:            correlation.RelSharesRootCause,
		},
	}

	remapped := correlation.RemapRelationships(relationships, dupMap)

	// Self-loop rel_3 must be dropped, and duplicate rel_2 must be merged into rel_1
	if len(remapped) != 1 {
		t.Fatalf("Expected 1 remapped unique relationship without self-loops or duplicate edges, got %d", len(remapped))
	}
	if remapped[0].SourceFindingID != "fnd_A1" || remapped[0].TargetFindingID != "fnd_B1" {
		t.Errorf("Remapped relationship endpoints incorrect: %s -> %s", remapped[0].SourceFindingID, remapped[0].TargetFindingID)
	}

	// Test Attack Paths
	paths := []correlation.AttackPath{
		{
			ID:      "path_1",
			NodeIDs: []string{"fnd_A1", "fnd_A2", "fnd_B2"},
			Edges: []correlation.Relationship{
				{SourceFindingID: "fnd_A1", TargetFindingID: "fnd_A2"},
				{SourceFindingID: "fnd_A2", TargetFindingID: "fnd_B2"},
			},
		},
	}

	remappedPaths := correlation.RemapAttackPaths(paths, dupMap)
	if len(remappedPaths) != 1 {
		t.Fatalf("Expected 1 remapped path, got %d", len(remappedPaths))
	}

	p := remappedPaths[0]
	// NodeIDs should collapse duplicate A2 and remap B2: ["fnd_A1", "fnd_B1"]
	if len(p.NodeIDs) != 2 || p.NodeIDs[0] != "fnd_A1" || p.NodeIDs[1] != "fnd_B1" {
		t.Errorf("Unexpected remapped NodeIDs: %+v", p.NodeIDs)
	}
	// Self-loop edge A1 -> A1 should be dropped; edge A1 -> B1 retained
	if len(p.Edges) != 1 || p.Edges[0].SourceFindingID != "fnd_A1" || p.Edges[0].TargetFindingID != "fnd_B1" {
		t.Errorf("Unexpected remapped Edges: %+v", p.Edges)
	}
}

// -----------------------------------------------------------------------------
// Category 15: High-Iteration Determinism (1,000 Iterations)
// -----------------------------------------------------------------------------
func TestDedup_Category15_HighIterationDeterminism(t *testing.T) {
	// Build a complex dataset with 3 distinct groups of duplicates and 2 unique findings
	target := "https://api.example.com"

	// Group 1: 4 duplicates of Auth Bypass
	var grp1 []report.Finding
	for i := 1; i <= 4; i++ {
		status := report.VerificationNotVerified
		if i == 1 {
			status = report.VerificationVerified
		} else if i == 2 {
			status = report.VerificationDetected
		}
		f := helperMakeDedupFinding(fmt.Sprintf("fnd_g1_%d", i), "Auth Bypass", "auth", report.SeverityCritical, report.ConfidenceHigh, status, target, "https://api.example.com/v1/admin/login", "POST")
		f.EvidenceDetails.Details["parameter"] = "token"
		f.Fingerprint = correlation.ComputeStableFingerprint(f)
		grp1 = append(grp1, f)
	}

	// Group 2: 3 duplicates of SSRF
	var grp2 []report.Finding
	for i := 1; i <= 3; i++ {
		status := report.VerificationDetected
		if i == 3 {
			status = report.VerificationVerified
		}
		f := helperMakeDedupFinding(fmt.Sprintf("fnd_g2_%d", i), "SSRF in Webhook", "ssrf", report.SeverityHigh, report.ConfidenceHigh, status, target, "https://api.example.com/v1/webhook", "POST")
		f.EvidenceDetails.Details["parameter"] = "url"
		f.Fingerprint = correlation.ComputeStableFingerprint(f)
		grp2 = append(grp2, f)
	}

	// Unique findings
	fUniq1 := helperMakeDedupFinding("fnd_uniq_1", "Info Leak in Robots", "info_leak", report.SeverityLow, report.ConfidenceHigh, report.VerificationVerified, target, "https://api.example.com/robots.txt", "GET")
	fUniq1.Fingerprint = correlation.ComputeStableFingerprint(fUniq1)

	fUniq2 := helperMakeDedupFinding("fnd_uniq_2", "CORS Misconfig", "cors", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, target, "https://api.example.com/api/data", "OPTIONS")
	fUniq2.Fingerprint = correlation.ComputeStableFingerprint(fUniq2)

	combined := append([]report.Finding{}, grp1...)
	combined = append(combined, grp2...)
	combined = append(combined, fUniq1, fUniq2)

	// Baseline run
	baseOut := correlation.DeduplicateFindings(combined)
	if len(baseOut) != 4 {
		t.Fatalf("Expected 4 canonical findings (2 grouped + 2 unique), got %d", len(baseOut))
	}

	// Sort base output by ID for consistent comparison
	sort.Slice(baseOut, func(i, j int) bool { return baseOut[i].ID < baseOut[j].ID })

	r := rand.New(rand.NewSource(42))
	const iterations = 1000

	for iter := 0; iter < iterations; iter++ {
		shuffled := make([]report.Finding, len(combined))
		copy(shuffled, combined)
		r.Shuffle(len(shuffled), func(i, j int) {
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		})

		iterOut := correlation.DeduplicateFindings(shuffled)
		if len(iterOut) != 4 {
			t.Fatalf("Iteration %d: expected 4 findings, got %d", iter, len(iterOut))
		}

		sort.Slice(iterOut, func(i, j int) bool { return iterOut[i].ID < iterOut[j].ID })

		for i := range baseOut {
			if iterOut[i].ID != baseOut[i].ID {
				t.Fatalf("Iteration %d: finding %d ID mismatch: expected %s, got %s", iter, i, baseOut[i].ID, iterOut[i].ID)
			}
			if iterOut[i].Score != baseOut[i].Score {
				t.Fatalf("Iteration %d: finding %s score mismatch: expected %d, got %d", iter, baseOut[i].ID, baseOut[i].Score, iterOut[i].Score)
			}
			if iterOut[i].EvidenceDetails.Observation != baseOut[i].EvidenceDetails.Observation {
				t.Fatalf("Iteration %d: finding %s observation mismatch", iter, baseOut[i].ID)
			}
		}
	}
}

// -----------------------------------------------------------------------------
// Category 16: Comprehensive Edge Cases
// -----------------------------------------------------------------------------
func TestDedup_Category16_EdgeCases(t *testing.T) {
	// Case 1: Nil and empty inputs
	var nilSlice []report.Finding
	if res := correlation.DeduplicateFindings(nilSlice); len(res) != 0 {
		t.Errorf("Expected 0 findings for nil input, got %d", len(res))
	}
	emptySlice := []report.Finding{}
	if res := correlation.DeduplicateFindings(emptySlice); len(res) != 0 {
		t.Errorf("Expected 0 findings for empty slice, got %d", len(res))
	}

	// Case 2: Single finding
	fSingle := helperMakeDedupFinding("fnd_single", "Single Finding", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/test", "GET")
	singleRes := correlation.DeduplicateFindings([]report.Finding{fSingle})
	if len(singleRes) != 1 || singleRes[0].ID != fSingle.ID {
		t.Errorf("Single finding failed dedup passthrough")
	}

	// Case 3: Large duplicate group (50 duplicates)
	const count = 50
	var largeGroup []report.Finding
	for i := 1; i <= count; i++ {
		status := report.VerificationNotVerified
		if i == 25 {
			status = report.VerificationVerified // Middle element is authoritative
		}
		f := helperMakeDedupFinding(fmt.Sprintf("fnd_large_%03d", i), "Massive Duplicate", "xss", report.SeverityMedium, report.ConfidenceHigh, status, "https://api.example.com", "https://api.example.com/v1/echo", "GET")
		f.EvidenceDetails.Details["parameter"] = "msg"
		f.Fingerprint = correlation.ComputeStableFingerprint(f)
		largeGroup = append(largeGroup, f)
	}

	largeRes := correlation.DeduplicateFindings(largeGroup)
	if len(largeRes) != 1 {
		t.Fatalf("Expected 50 duplicates to consolidate to 1, got %d", len(largeRes))
	}
	if largeRes[0].ID != "fnd_large_025" {
		t.Errorf("Expected canonical finding to be authoritative fnd_large_025, got %s", largeRes[0].ID)
	}
	if largeRes[0].EvidenceDetails.Details["duplicate_count"] != "49" {
		t.Errorf("Expected duplicate_count 49, got %s", largeRes[0].EvidenceDetails.Details["duplicate_count"])
	}

	// Case 4: Finding with nil maps or empty slices
	fNilMaps := report.Finding{
		ID:          "fnd_nil_maps",
		Title:       "Finding with Nil Maps",
		Category:    "sqli",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://api.example.com",
		Endpoint:    "https://api.example.com/v1/nil",
		Method:      "GET",
		Fingerprint: "",
	}
	fNilMaps.Score = report.CalculateFindingScore(fNilMaps)
	fNilMaps.Fingerprint = correlation.ComputeStableFingerprint(fNilMaps)

	nilMapsRes := correlation.DeduplicateFindings([]report.Finding{fNilMaps, fNilMaps})
	if len(nilMapsRes) != 1 {
		t.Fatalf("Expected duplicate with nil maps to consolidate to 1 without panic, got %d", len(nilMapsRes))
	}
}

// -----------------------------------------------------------------------------
// Category 17: Verification Pipeline Precedence & Post-Verification Consolidation
// -----------------------------------------------------------------------------
func TestDedup_Category17_VerificationPipelinePostVerificationConsolidation(t *testing.T) {
	// Detector A discovers candidate finding without active probe
	candA := helperMakeDedupFinding("fnd_det_a", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	candA.AnalysisMethod = report.AnalysisMethodStatic
	candA.Evidence = "Static regex match on query parameter"
	candA.EvidenceDetails.Observation = "Parameter 'id' appears unsanitized in static source"
	candA.Score = report.CalculateFindingScore(candA)
	candA.Fingerprint = correlation.ComputeStableFingerprint(candA)

	// Detector B discovers candidate finding with safe active verification probe
	candB := helperMakeDedupFinding("fnd_det_b", "SQL Injection", "sqli", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	candB.AnalysisMethod = report.AnalysisMethodActive
	candB.Evidence = "Time-based boolean probe confirmed database sleep of 5 seconds"
	candB.EvidenceDetails.Observation = "Empirical active probe delay matched database sleep"
	candB.EvidenceDetails.HTTPStatus = 200
	candB.EvidenceDetails.HTTPMethod = "GET"
	candB.EvidenceDetails.Details["payload"] = "1' AND SLEEP(5)--"
	candB.Verification.SafeCurlCommand = "curl -i -s 'https://api.example.com/v1/users?id=1%27+AND+SLEEP(5)--'"
	candB.Verification.ReproductionSteps = []string{
		"Send baseline request: observe 200ms latency",
		"Send probe request: observe 5200ms latency",
	}
	candB.Score = report.CalculateFindingScore(candB)
	candB.Fingerprint = correlation.ComputeStableFingerprint(candB)

	// Verify both have matching fingerprint
	if candA.Fingerprint != candB.Fingerprint {
		t.Fatalf("Expected both detectors to produce identical fingerprint, got %s vs %s", candA.Fingerprint, candB.Fingerprint)
	}

	// Post-verification deduplication: candB (VERIFIED) must win canonical authority over candA (DETECTED)
	// even if candA is presented first in input slice.
	input := []report.Finding{candA, candB}
	res := correlation.DeduplicateFindings(input)
	if len(res) != 1 {
		t.Fatalf("Expected 2 candidate findings to consolidate to 1, got %d", len(res))
	}

	canonical := res[0]
	if canonical.ID != "fnd_det_b" {
		t.Errorf("Expected canonical representative to be verified finding fnd_det_b, got %s", canonical.ID)
	}
	if canonical.Verification.Status != report.VerificationVerified {
		t.Errorf("Expected canonical verification status VERIFIED, got %s", canonical.Verification.Status)
	}
	if canonical.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("Expected canonical analysis method ACTIVE_VERIFICATION, got %s", canonical.AnalysisMethod)
	}
	if canonical.Verification.SafeCurlCommand == "" {
		t.Errorf("Expected canonical safe curl command to be preserved")
	}
	if len(canonical.Verification.ReproductionSteps) == 0 {
		t.Errorf("Expected canonical reproduction steps to be preserved")
	}
	if !strings.Contains(canonical.Evidence, "Static regex match") || !strings.Contains(canonical.Evidence, "Time-based boolean probe") {
		t.Errorf("Expected canonical evidence to aggregate both detector observations, got %s", canonical.Evidence)
	}

	// Score formula must match verified score exactly (confidence 1.0, verification 1.0)
	if canonical.ScoreExplanation == nil {
		t.Fatalf("Expected non-nil ScoreExplanation")
	}
	if canonical.ScoreExplanation.Score != canonical.Score {
		t.Errorf("Score explanation score (%d) does not match finding score (%d)", canonical.ScoreExplanation.Score, canonical.Score)
	}
	if canonical.ScoreExplanation.VerificationStatus != string(report.VerificationVerified) {
		t.Errorf("Score explanation verification status mismatch: %s", canonical.ScoreExplanation.VerificationStatus)
	}
}

// -----------------------------------------------------------------------------
// Category 18: Multi-Target Association and Evidence Provenance Preservation
// -----------------------------------------------------------------------------
func TestDedup_Category18_MultiTargetAssociationAndProvenancePreservation(t *testing.T) {
	assessmentID := "asm_multi_tgt"
	execID := "exec_multi_001"
	target1 := "tgt_frontend_001"
	target2 := "tgt_api_gateway_002"

	f1 := helperMakeDedupFinding("fnd_tgt1", "Open Redirect", "redirect", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "https://example.com", "https://example.com/oauth/callback", "GET")
	f1.Provenance = &report.EvidenceProvenance{
		EvidenceID:          "ev_001_frontend",
		SourceEngine:        "crawler",
		AssetID:             "asset_fe_01",
		VerificationContext: "direct_probe",
	}
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_tgt2", "Open Redirect", "redirect", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://example.com", "https://example.com/oauth/callback", "GET")
	f2.Provenance = &report.EvidenceProvenance{
		EvidenceID:          "ev_002_gateway",
		SourceEngine:        "apisec",
		AssetID:             "asset_gw_02",
		VerificationContext: "spec_analysis",
	}
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	af1 := assessment.ToAssessmentFinding(assessmentID, execID, target1, f1)
	af2 := assessment.ToAssessmentFinding(assessmentID, execID, target2, f2)

	afs := []assessment.AssessmentFinding{af1, af2}
	dedupedAFs := assessment.DeduplicateAssessmentFindings(afs)

	if len(dedupedAFs) != 1 {
		t.Fatalf("Expected 2 findings across different targets to consolidate to 1, got %d", len(dedupedAFs))
	}

	canonAF := dedupedAFs[0]
	// Primary target must be retained
	if canonAF.TargetID != target1 {
		t.Errorf("Expected primary TargetID %s, got %s", target1, canonAF.TargetID)
	}

	// Associated targets must preserve both target IDs
	assocTargets := canonAF.EvidenceDetails.Details["associated_target_ids"]
	if !strings.Contains(assocTargets, target1) || !strings.Contains(assocTargets, target2) {
		t.Errorf("Expected associated_target_ids to contain both %s and %s, got %s", target1, target2, assocTargets)
	}
	if canonAF.EvidenceDetails.Details["target_id_count"] != "2" {
		t.Errorf("Expected target_id_count 2, got %s", canonAF.EvidenceDetails.Details["target_id_count"])
	}

	// Provenance IDs must be merged and tracked
	mergedEvIDs := canonAF.EvidenceDetails.Details["merged_evidence_ids"]
	if !strings.Contains(mergedEvIDs, "ev_001_frontend") || !strings.Contains(mergedEvIDs, "ev_002_gateway") {
		t.Errorf("Expected merged_evidence_ids to contain both ev_001_frontend and ev_002_gateway, got %s", mergedEvIDs)
	}
}

// -----------------------------------------------------------------------------
// Category 19: Boolean Detail Flags and Discrete Payload Merging
// -----------------------------------------------------------------------------
func TestDedup_Category19_BooleanDetailFlagsAndPayloadMerging(t *testing.T) {
	f1 := helperMakeDedupFinding("fnd_bool_1", "Auth Bypass", "auth", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/admin", "POST")
	f1.EvidenceDetails.Details["unauth_bypass_tested"] = "true"
	f1.EvidenceDetails.Details["cross_tenant"] = "false"
	f1.EvidenceDetails.Details["payload"] = "X-Admin-Role: superadmin"
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_bool_2", "Auth Bypass", "auth", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin", "POST")
	f2.EvidenceDetails.Details["unauth_bypass_tested"] = "false"
	f2.EvidenceDetails.Details["cross_tenant"] = "true"
	f2.EvidenceDetails.Details["payload"] = "X-Tenant-Override: tenant-999"
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	res := correlation.DeduplicateFindings([]report.Finding{f1, f2})
	if len(res) != 1 {
		t.Fatalf("Expected 2 findings to consolidate to 1, got %d", len(res))
	}

	canon := res[0]
	// Boolean flags must preserve "true" if either candidate proved the condition
	if canon.EvidenceDetails.Details["unauth_bypass_tested"] != "true" {
		t.Errorf("Expected unauth_bypass_tested='true', got %s", canon.EvidenceDetails.Details["unauth_bypass_tested"])
	}
	if canon.EvidenceDetails.Details["cross_tenant"] != "true" {
		t.Errorf("Expected cross_tenant='true', got %s", canon.EvidenceDetails.Details["cross_tenant"])
	}

	// Primary payload should remain canonical's payload, alternative recorded in additional_payloads
	if canon.EvidenceDetails.Details["payload"] != "X-Admin-Role: superadmin" {
		t.Errorf("Expected primary payload 'X-Admin-Role: superadmin', got %s", canon.EvidenceDetails.Details["payload"])
	}
	if !strings.Contains(canon.EvidenceDetails.Details["additional_payloads"], "X-Tenant-Override: tenant-999") {
		t.Errorf("Expected additional_payloads to contain secondary payload, got %s", canon.EvidenceDetails.Details["additional_payloads"])
	}
}

// -----------------------------------------------------------------------------
// Category 20: Hardened Fallback Deduplicator Tenant Boundary & Ranking
// -----------------------------------------------------------------------------
func TestDedup_Category20_HardenedFallbackDeduplicator(t *testing.T) {
	// Directly test legacyDeduplicateFindings via pkg/report fallback semantics
	fTenantA := helperMakeDedupFinding("fnd_tenant_a", "IDOR", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/tenant/data", "GET")
	fTenantA.EvidenceDetails.Details["tenant_id"] = "tenant-alpha"
	fTenantA.Fingerprint = "fp_fixed_idor_001"

	fTenantB := helperMakeDedupFinding("fnd_tenant_b", "IDOR", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/tenant/data", "GET")
	fTenantB.EvidenceDetails.Details["tenant_id"] = "tenant-beta"
	fTenantB.Fingerprint = "fp_fixed_idor_001"

	// Same tenant duplicate
	fTenantA2 := helperMakeDedupFinding("fnd_tenant_a2", "IDOR", "bola", report.SeverityHigh, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/tenant/data", "GET")
	fTenantA2.EvidenceDetails.Details["tenant_id"] = "tenant-alpha"
	fTenantA2.Fingerprint = "fp_fixed_idor_001"

	input := []report.Finding{fTenantA, fTenantB, fTenantA2}

	// Test fallback deduplication logic directly
	res := report.DeduplicateFindings(input)

	// Tenant A and Tenant B must NEVER merge, while Tenant A's 2 findings must consolidate
	if len(res) != 2 {
		t.Fatalf("Expected 2 tenant-isolated findings, got %d", len(res))
	}

	tenantsSeen := make(map[string]bool)
	for _, f := range res {
		tid := f.EvidenceDetails.Details["tenant_id"]
		tenantsSeen[tid] = true
		if tid == "tenant-alpha" {
			if f.EvidenceDetails.Details["duplicate_count"] != "1" {
				t.Errorf("Expected tenant-alpha finding to have duplicate_count=1, got %s", f.EvidenceDetails.Details["duplicate_count"])
			}
			if f.ID != "fnd_tenant_a" {
				t.Errorf("Expected canonical finding for tenant-alpha to be fnd_tenant_a, got %s", f.ID)
			}
		}
	}

	if !tenantsSeen["tenant-alpha"] || !tenantsSeen["tenant-beta"] {
		t.Errorf("Expected both tenant-alpha and tenant-beta to be represented separately")
	}
}

// -----------------------------------------------------------------------------
// Category 21: Contradiction and Dispute Handling
// -----------------------------------------------------------------------------
func TestDedup_Category21_ContradictionAndDisputeHandling(t *testing.T) {
	// Case 1: Unauthenticated Bypass (HTTP 200) vs Authentication Required Claim
	fBypass := helperMakeDedupFinding("fnd_bypass", "Unauthenticated Admin API Bypass", "auth", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/api/v1/admin/users", "GET")
	fBypass.EvidenceDetails.HTTPStatus = 200
	fBypass.EvidenceDetails.Details["auth_required"] = "false"
	fBypass.EvidenceDetails.Details["unauth_bypass_tested"] = "true"
	fBypass.Fingerprint = correlation.ComputeStableFingerprint(fBypass)

	fClaim := helperMakeDedupFinding("fnd_claim", "Admin API Exposed", "auth", report.SeverityLow, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/api/v1/admin/users", "GET")
	fClaim.EvidenceDetails.HTTPStatus = 401
	fClaim.EvidenceDetails.Details["auth_required"] = "true"
	fClaim.EvidenceDetails.Details["unauth_bypass_tested"] = "false"
	fClaim.Fingerprint = correlation.ComputeStableFingerprint(fClaim)

	deduped := correlation.DeduplicateFindings([]report.Finding{fBypass, fClaim})
	if len(deduped) != 1 {
		t.Fatalf("Expected 2 duplicate findings to merge into 1 canonical finding, got %d", len(deduped))
	}
	canon := deduped[0]

	// Must NOT report auth_required='true' when bypass succeeded with HTTP 200
	if canon.EvidenceDetails.Details["auth_required"] == "true" {
		t.Fatalf("CRITICAL SECURITY DEFECT: auth_required was set to 'true' despite proven unauthenticated bypass!")
	}
	if canon.EvidenceDetails.Details["disputed_auth_required"] != "true" {
		t.Errorf("Expected disputed_auth_required='true', got %s", canon.EvidenceDetails.Details["disputed_auth_required"])
	}
	if !strings.Contains(canon.EvidenceDetails.Details["auth_required_contradiction"], "unauthenticated access succeeded") {
		t.Errorf("Expected auth_required_contradiction explanation, got %s", canon.EvidenceDetails.Details["auth_required_contradiction"])
	}
	if !strings.Contains(canon.EvidenceDetails.Details["alternative_http_statuses"], "401") {
		t.Errorf("Expected alternative_http_statuses to record 401, got %s", canon.EvidenceDetails.Details["alternative_http_statuses"])
	}

	// Case 2: Cross-Tenant Data Disclosure vs Isolation Verified
	fLeak := helperMakeDedupFinding("fnd_leak", "Cross-Tenant BOLA", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/tenant/doc", "GET")
	fLeak.EvidenceDetails.Details["cross_tenant"] = "true"
	fLeak.EvidenceDetails.Details["cross_tenant_data_confirmed"] = "true"
	fLeak.Fingerprint = correlation.ComputeStableFingerprint(fLeak)

	fIso := helperMakeDedupFinding("fnd_iso", "Cross-Tenant BOLA", "bola", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/tenant/doc", "GET")
	fIso.EvidenceDetails.Details["isolation_verified"] = "true"
	fIso.Fingerprint = correlation.ComputeStableFingerprint(fIso)

	dedupedLeak := correlation.DeduplicateFindings([]report.Finding{fLeak, fIso})
	if len(dedupedLeak) != 1 {
		t.Fatalf("Expected leak and isolation findings to merge, got %d", len(dedupedLeak))
	}
	canonLeak := dedupedLeak[0]
	if canonLeak.EvidenceDetails.Details["isolation_verified"] == "true" {
		t.Fatalf("CRITICAL DEFECT: isolation_verified was preserved despite verified cross-tenant leak!")
	}
	if canonLeak.EvidenceDetails.Details["disputed_tenant_isolation"] != "true" {
		t.Errorf("Expected disputed_tenant_isolation='true', got %s", canonLeak.EvidenceDetails.Details["disputed_tenant_isolation"])
	}
	if !strings.Contains(canonLeak.EvidenceDetails.Details["observation_conflict"], "cross-tenant disclosure observed") {
		t.Errorf("Expected observation_conflict note, got %s", canonLeak.EvidenceDetails.Details["observation_conflict"])
	}

	// Case 3: Output encoding reflection divergence between unverified detectors
	fRefl1 := helperMakeDedupFinding("fnd_refl1", "XSS Reflection", "xss", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://app.example.com", "https://app.example.com/search", "GET")
	fRefl1.EvidenceDetails.Details["unescaped_reflection"] = "true"
	fRefl1.Fingerprint = correlation.ComputeStableFingerprint(fRefl1)

	fRefl2 := helperMakeDedupFinding("fnd_refl2", "XSS Reflection", "xss", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://app.example.com", "https://app.example.com/search", "GET")
	fRefl2.EvidenceDetails.Details["unescaped_reflection"] = "false"
	fRefl2.Fingerprint = correlation.ComputeStableFingerprint(fRefl2)

	dedupedRefl := correlation.DeduplicateFindings([]report.Finding{fRefl1, fRefl2})
	canonRefl := dedupedRefl[0]
	if canonRefl.EvidenceDetails.Details["disputed_unescaped_reflection"] != "true" {
		t.Errorf("Expected disputed_unescaped_reflection='true' when detectors disagree without verified proof")
	}
}

// -----------------------------------------------------------------------------
// Category 22: Multi-Target Cross-Assessment Lifecycle Comparison
// -----------------------------------------------------------------------------
func TestDedup_Category22_MultiTargetCrossAssessmentLifecycleComparison(t *testing.T) {
	// Baseline finding affects two targets: app.corp.local and admin.corp.local
	targetA := "https://app.corp.local"
	targetB := "https://admin.corp.local"

	baseFinding := helperMakeDedupFinding("fnd_base_multi", "Shared Config Flaw", "config", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/v1/config", "GET")
	baseFinding.PrimaryAssetID = "asset_shared_service"
	baseFinding.EvidenceDetails.Details["associated_targets"] = fmt.Sprintf("%s, %s", targetB, targetA)
	baseFinding.EvidenceDetails.Details["associated_target_ids"] = "tgt_admin_02,tgt_app_01"
	baseFinding.Fingerprint = correlation.ComputeStableFingerprint(baseFinding)

	// Sub-test 1: Current assessment ONLY scopes Target A.
	// The finding was not detected on Target A, but Target B was not tested.
	// It MUST be classified as UNASSESSED, NOT RESOLVED!
	optsOnlyA := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{targetA},
	}
	cmp1 := correlation.CompareFindingsWithOptions([]report.Finding{baseFinding}, nil, optsOnlyA)
	if cmp1.UnassessedCount != 1 {
		t.Fatalf("CRITICAL DEFECT: Expected 1 UNASSESSED finding when secondary target %s was out of scope, got %d unassessed and %d resolved",
			targetB, cmp1.UnassessedCount, cmp1.ResolvedCount)
	}
	if cmp1.ResolvedCount != 0 {
		t.Fatalf("CRITICAL DEFECT: Multi-target finding was falsely marked RESOLVED when target %s was unscoped!", targetB)
	}
	if len(cmp1.Items) != 1 || cmp1.Items[0].LifecycleStatus != correlation.LifecycleUnassessed {
		t.Fatalf("Expected comparison item status UNASSESSED, got %+v", cmp1.Items[0])
	}
	if !strings.Contains(cmp1.Items[0].Explanation, targetB) {
		t.Errorf("Expected explanation to name the unscoped target %s, got: %s", targetB, cmp1.Items[0].Explanation)
	}

	// Sub-test 2: Current assessment scopes BOTH targets, finding is patched on both.
	// It MUST be classified as RESOLVED!
	optsBoth := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{targetA, targetB},
	}
	cmp2 := correlation.CompareFindingsWithOptions([]report.Finding{baseFinding}, nil, optsBoth)
	if cmp2.ResolvedCount != 1 {
		t.Fatalf("Expected finding to be marked RESOLVED when all affected targets were evaluated and finding was absent, got %d", cmp2.ResolvedCount)
	}
	if cmp2.UnassessedCount != 0 {
		t.Errorf("Expected 0 unassessed findings, got %d", cmp2.UnassessedCount)
	}
	if cmp2.Items[0].LifecycleStatus != correlation.LifecycleResolved {
		t.Errorf("Expected RESOLVED status, got %s", cmp2.Items[0].LifecycleStatus)
	}

	// Sub-test 3: Current assessment scopes BOTH targets, finding was patched on Target A but still detected on Target B.
	// It MUST be classified as RECURRING with target footprint shift documented!
	curFindingTargetB := helperMakeDedupFinding("fnd_cur_b", "Shared Config Flaw", "config", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, targetB, targetB+"/v1/config", "GET")
	curFindingTargetB.PrimaryAssetID = "asset_shared_service"
	curFindingTargetB.Fingerprint = correlation.ComputeStableFingerprint(curFindingTargetB)

	cmp3 := correlation.CompareFindingsWithOptions([]report.Finding{baseFinding}, []report.Finding{curFindingTargetB}, optsBoth)
	if cmp3.RecurringCount != 1 {
		t.Fatalf("Expected finding to be classified as RECURRING, got %d", cmp3.RecurringCount)
	}
	item := cmp3.Items[0]
	if item.LifecycleStatus != correlation.LifecycleRecurring {
		t.Errorf("Expected RECURRING status, got %s", item.LifecycleStatus)
	}
	if !strings.Contains(item.Explanation, "target footprint shifted") {
		t.Errorf("Expected recurring explanation to document target footprint shift, got: %s", item.Explanation)
	}
	if !strings.Contains(item.Explanation, targetA) || !strings.Contains(item.Explanation, targetB) {
		t.Errorf("Expected explanation to document previous and current footprints, got: %s", item.Explanation)
	}
}

// -----------------------------------------------------------------------------
// Category 23: Complete Round-Trip Persistence and Model Conversion Fidelity
// -----------------------------------------------------------------------------
func TestDedup_Category23_CompleteRoundTripPersistenceFidelity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "dedup_roundtrip_*")
	if err != nil {
		t.Fatalf("MkdirTemp failed: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_roundtrip.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed: %v", err)
	}
	defer store.Close()

	// Setup client, assessment, and targets
	cli := &assessment.Client{ID: "cli_rt_01", Name: "Roundtrip Test Client"}
	if err := store.CreateClient(cli); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	asm := &assessment.Assessment{
		ID:       "asm_rt_01",
		ClientID: cli.ID,
		Name:     "Roundtrip Dedup Assessment",
		Status:   assessment.StatusCompleted,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	execID := "exec_rt_001"
	execRec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().Add(-10 * time.Minute),
	}
	if err := store.CreateExecution(execRec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	target1 := &assessment.AssessmentTarget{
		ID:           "tgt_portal_01",
		AssessmentID: asm.ID,
		TargetURL:    "https://portal.example.com",
		ScopeStatus:  "APPROVED",
	}
	target2 := &assessment.AssessmentTarget{
		ID:           "tgt_api_02",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target1); err != nil {
		t.Fatalf("AddTarget 1 failed: %v", err)
	}
	if err := store.AddTarget(target2); err != nil {
		t.Fatalf("AddTarget 2 failed: %v", err)
	}

	// Create 2 findings on distinct targets sharing an underlying infrastructure asset
	f1 := helperMakeDedupFinding("fnd_portal_1", "Information Disclosure", "info", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, target1.TargetURL, target1.TargetURL+"/debug/pprof", "GET")
	f1.PrimaryAssetID = "ast_shared_pprof"
	f1.Provenance = &report.EvidenceProvenance{
		EvidenceID:   "ev_portal_100",
		SourceEngine: "crawler",
		AssetID:      "ast_shared_pprof",
	}
	f1.EvidenceDetails.Details["payload"] = "mode=profile"
	f1.Fingerprint = correlation.ComputeStableFingerprint(f1)

	f2 := helperMakeDedupFinding("fnd_api_2", "Information Disclosure", "info", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, target2.TargetURL, target2.TargetURL+"/debug/pprof", "GET")
	f2.PrimaryAssetID = "ast_shared_pprof"
	f2.Provenance = &report.EvidenceProvenance{
		EvidenceID:   "ev_api_200",
		SourceEngine: "apisec",
		AssetID:      "ast_shared_pprof",
	}
	f2.EvidenceDetails.Details["payload"] = "mode=heap"
	f2.Fingerprint = correlation.ComputeStableFingerprint(f2)

	af1 := assessment.ToAssessmentFinding(asm.ID, execID, target1.ID, f1)
	af2 := assessment.ToAssessmentFinding(asm.ID, execID, target2.ID, f2)

	// Deduplicate assessment findings
	dedupedAFs := assessment.DeduplicateAssessmentFindings([]assessment.AssessmentFinding{af1, af2})
	if len(dedupedAFs) != 1 {
		t.Fatalf("Expected 2 findings across targets to deduplicate to 1, got %d", len(dedupedAFs))
	}

	// Save to SQLite
	if err := store.SaveFindings(dedupedAFs); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	// Retrieve from SQLite
	retrievedAFs, err := store.GetFindings(asm.ID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(retrievedAFs) != 1 {
		t.Fatalf("Expected 1 finding from SQLite, got %d", len(retrievedAFs))
	}

	rAF := retrievedAFs[0]

	// Verify multi-target association survived SQLite round-trip
	assocIDs := rAF.EvidenceDetails.Details["associated_target_ids"]
	if !strings.Contains(assocIDs, target1.ID) || !strings.Contains(assocIDs, target2.ID) {
		t.Errorf("Expected associated_target_ids in SQLite to contain %s and %s, got %s", target1.ID, target2.ID, assocIDs)
	}
	if rAF.EvidenceDetails.Details["target_id_count"] != "2" {
		t.Errorf("Expected target_id_count=2, got %s", rAF.EvidenceDetails.Details["target_id_count"])
	}

	assocTargets := rAF.EvidenceDetails.Details["associated_targets"]
	if !strings.Contains(assocTargets, target1.TargetURL) || !strings.Contains(assocTargets, target2.TargetURL) {
		t.Errorf("Expected associated_targets to contain %s and %s, got %s", target1.TargetURL, target2.TargetURL, assocTargets)
	}

	// Verify merged evidence IDs survived
	mergedEv := rAF.EvidenceDetails.Details["merged_evidence_ids"]
	if !strings.Contains(mergedEv, "ev_portal_100") || !strings.Contains(mergedEv, "ev_api_200") {
		t.Errorf("Expected merged_evidence_ids to contain ev_portal_100 and ev_api_200, got %s", mergedEv)
	}

	// Verify alternative payload survived
	if !strings.Contains(rAF.EvidenceDetails.Details["additional_payloads"], "mode=heap") {
		t.Errorf("Expected additional_payloads to contain mode=heap, got %s", rAF.EvidenceDetails.Details["additional_payloads"])
	}

	// Convert back to report.Finding and verify lossless representation
	rf := assessment.ToReportFinding(rAF)
	if rf.Target == "" || rf.Endpoint == "" {
		t.Errorf("Target or Endpoint was dropped in ToReportFinding")
	}
	if rf.EvidenceDetails.Details["associated_target_ids"] != assocIDs {
		t.Errorf("associated_target_ids lost in ToReportFinding conversion")
	}
	if rf.EvidenceDetails.Details["associated_targets"] != assocTargets {
		t.Errorf("associated_targets lost in ToReportFinding conversion")
	}

	// Verify risk score calculation is consistent
	score := report.CalculateFindingScore(rf)
	if score <= 0 || score > 40 {
		t.Errorf("Finding score %d out of valid [1, 40] range", score)
	}
	expl := report.ExplainFindingScore(rf)
	if expl.Score != score {
		t.Errorf("Score explanation score %d does not match calculated score %d", expl.Score, score)
	}
}

// -----------------------------------------------------------------------------
// Category 24: HTTP 200 Alone Cannot Establish Authentication Bypass
// -----------------------------------------------------------------------------
func TestDedup_Category24_HTTP200AloneCannotEstablishAuthBypass(t *testing.T) {
	// Case 1: HTTP 200 on an endpoint without bypass context or affirmative leak
	fAdmin1 := helperMakeDedupFinding("fnd_adm_1", "Admin Management Interface", "admin", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin", "GET")
	fAdmin1.EvidenceDetails.HTTPStatus = 200
	fAdmin1.EvidenceDetails.Details["auth_required"] = "true"
	fAdmin1.Fingerprint = correlation.ComputeStableFingerprint(fAdmin1)

	fAdmin2 := helperMakeDedupFinding("fnd_adm_2", "Admin Management Interface", "admin", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin", "GET")
	fAdmin2.EvidenceDetails.HTTPStatus = 200
	fAdmin2.EvidenceDetails.Details["auth_required"] = "true"
	fAdmin2.Fingerprint = correlation.ComputeStableFingerprint(fAdmin2)

	deduped := correlation.DeduplicateFindings([]report.Finding{fAdmin1, fAdmin2})
	if len(deduped) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(deduped))
	}
	if deduped[0].EvidenceDetails.Details["auth_required"] != "true" {
		t.Fatalf("CRITICAL SECURITY DEFECT: auth_required revoked on ordinary HTTP 200 without bypass!")
	}
	if deduped[0].EvidenceDetails.Details["disputed_auth_required"] == "true" {
		t.Fatalf("disputed_auth_required should NOT be set when both agreed auth_required=true on HTTP 200")
	}

	// Case 2: Cross-finding contamination guard:
	// Finding A has HTTP 200 on a normal probe. Finding B attempted bypass but got 401.
	// Neither finding demonstrated bypass; B's bypass claim must NOT combine with A's 200!
	fNorm := helperMakeDedupFinding("fnd_norm", "Admin Portal Endpoint", "auth", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin/settings", "GET")
	fNorm.EvidenceDetails.HTTPStatus = 200
	fNorm.EvidenceDetails.Details["auth_required"] = "true"
	fNorm.Fingerprint = correlation.ComputeStableFingerprint(fNorm)

	fProbe401 := helperMakeDedupFinding("fnd_probe401", "Unauthenticated Bypass Probe", "auth", report.SeverityLow, report.ConfidenceLow, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin/settings", "GET")
	fProbe401.EvidenceDetails.HTTPStatus = 401
	fProbe401.Evidence = "HTTP 401 Unauthorized returned on unauthenticated request"
	fProbe401.EvidenceDetails.Details["auth_required"] = "true"
	fProbe401.Fingerprint = correlation.ComputeStableFingerprint(fProbe401)

	dedupedCross := correlation.DeduplicateFindings([]report.Finding{fNorm, fProbe401})
	if len(dedupedCross) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(dedupedCross))
	}
	if dedupedCross[0].EvidenceDetails.Details["auth_required"] != "true" {
		t.Fatalf("CRITICAL SECURITY DEFECT: cross-finding contamination revoked auth_required!")
	}

	// Case 3: Empty evidence guard:
	// Finding has Title "Unauthenticated Bypass", HTTPStatus = 200, but empty evidence and detected status
	fEmptyEv := helperMakeDedupFinding("fnd_empty_ev", "Unauthenticated Access Bypass", "auth", report.SeverityMedium, report.ConfidenceLow, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin/data", "GET")
	fEmptyEv.Evidence = ""
	fEmptyEv.EvidenceDetails.Observation = ""
	fEmptyEv.EvidenceDetails.HTTPStatus = 200
	fEmptyEv.EvidenceDetails.Details["auth_required"] = "true"
	fEmptyEv.Fingerprint = correlation.ComputeStableFingerprint(fEmptyEv)

	fAuthEnf := helperMakeDedupFinding("fnd_enf", "Admin Data Route", "auth", report.SeverityMedium, report.ConfidenceMedium, report.VerificationDetected, "https://api.example.com", "https://api.example.com/admin/data", "GET")
	fAuthEnf.EvidenceDetails.HTTPStatus = 403
	fAuthEnf.EvidenceDetails.Details["auth_required"] = "true"
	fAuthEnf.Fingerprint = correlation.ComputeStableFingerprint(fAuthEnf)

	dedupedEmpty := correlation.DeduplicateFindings([]report.Finding{fEmptyEv, fAuthEnf})
	if len(dedupedEmpty) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(dedupedEmpty))
	}
	if dedupedEmpty[0].EvidenceDetails.Details["auth_required"] != "true" {
		t.Fatalf("HTTP 200 without affirmative evidence revoked auth_required!")
	}

	// Case 4: Affirmative demonstrated bypass:
	// Finding has Title "Unauthenticated Bypass", HTTPStatus = 200, affirmative evidence, and verified status
	fProvenBypass := helperMakeDedupFinding("fnd_proven", "Unauthenticated Bypass Succeeded", "auth", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/admin/data", "GET")
	fProvenBypass.Evidence = "Disclosed sensitive records with HTTP 200 without authentication"
	fProvenBypass.EvidenceDetails.Observation = "Disclosed sensitive records with HTTP 200 without authentication"
	fProvenBypass.EvidenceDetails.HTTPStatus = 200
	fProvenBypass.EvidenceDetails.Details["auth_required"] = "false"
	fProvenBypass.Fingerprint = correlation.ComputeStableFingerprint(fProvenBypass)

	dedupedProven := correlation.DeduplicateFindings([]report.Finding{fProvenBypass, fAuthEnf})
	if len(dedupedProven) != 1 {
		t.Fatalf("Expected 1 canonical finding, got %d", len(dedupedProven))
	}
	if dedupedProven[0].EvidenceDetails.Details["auth_required"] == "true" {
		t.Fatalf("Proven unauthenticated bypass failed to dispute auth_required!")
	}
	if dedupedProven[0].EvidenceDetails.Details["disputed_auth_required"] != "true" {
		t.Errorf("Expected disputed_auth_required=true on proven bypass")
	}
}

// -----------------------------------------------------------------------------
// Category 25: Multi-Target Rescan Partial Mitigation (Remains on A, Absent on B)
// -----------------------------------------------------------------------------
func TestDedup_Category25_MultiTargetRescanPartialMitigation(t *testing.T) {
	targetA := "https://app-a.example.com"
	targetB := "https://app-b.example.com"

	// Baseline finding affects both Target A and Target B
	fBase := helperMakeDedupFinding("fnd_base_ab", "Sensitive Header Exposure", "headers", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/api/v1/status", "GET")
	fBase.EvidenceDetails.Details["associated_targets"] = targetA + ", " + targetB
	fBase.Fingerprint = correlation.ComputeStableFingerprint(fBase)

	// In current assessment, both targets A and B are adequately rescanned.
	// The vulnerability is still detected on Target A, but is absent on Target B.
	fCurA := helperMakeDedupFinding("fnd_cur_a", "Sensitive Header Exposure", "headers", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, targetA, targetA+"/api/v1/status", "GET")
	fCurA.EvidenceDetails.Details["associated_targets"] = targetA
	fCurA.Fingerprint = correlation.ComputeStableFingerprint(fCurA)

	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{targetA, targetB},
	}

	comp := correlation.CompareFindingsWithOptions([]report.Finding{fBase}, []report.Finding{fCurA}, opts)

	// Target A must NOT be marked resolved! Finding remains recurring
	if comp.ResolvedCount != 0 {
		t.Fatalf("Target A finding was incorrectly marked resolved! ResolvedCount=%d", comp.ResolvedCount)
	}
	if comp.RecurringCount != 1 {
		t.Fatalf("Expected RecurringCount=1, got %d", comp.RecurringCount)
	}
	if len(comp.Items) != 1 {
		t.Fatalf("Expected 1 comparison item, got %d", len(comp.Items))
	}

	item := comp.Items[0]
	if item.LifecycleStatus != correlation.LifecycleRecurring {
		t.Errorf("Expected LifecycleRecurring, got %s", item.LifecycleStatus)
	}

	// Footprint shift must be recorded in the explanation
	if !strings.Contains(item.Explanation, "target footprint shifted") {
		t.Errorf("Expected explanation to document target footprint shift, got %q", item.Explanation)
	}
	if !strings.Contains(item.Explanation, targetA) || !strings.Contains(item.Explanation, targetB) {
		t.Errorf("Explanation missing target references: %q", item.Explanation)
	}
}
