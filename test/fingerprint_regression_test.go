package test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/correlation"
	"felix/pkg/report"
)

// =============================================================================
// PHASE 6.3: STABLE FINDING FINGERPRINTS — COMPREHENSIVE REGRESSION SUITE
// Reliable Cross-Assessment Identity System & Lifecycle Tracking
// 16 Strict Verification Categories
// =============================================================================

func helperMakeFPFinding(id, title, category, severity, confidence string, status report.VerificationStatus, target, endpoint, method string) report.Finding {
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
		Timestamp: time.Now().UTC(),
	}
	f.Score = report.CalculateFindingScore(f)
	return f
}

// -----------------------------------------------------------------------------
// Category 1: Stability Across Assessment Metadata & Timestamps
// -----------------------------------------------------------------------------
func TestFingerprint_Category01_MetadataAndTimestampInvariance(t *testing.T) {
	// Finding from Assessment 1 (Run 1 on Monday)
	fRun1 := helperMakeFPFinding("fnd_001_run1", "BOLA on User API", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	fRun1.EvidenceDetails.Details["parameter"] = "user_id"
	fRun1.Timestamp = time.Date(2026, 10, 1, 10, 0, 0, 0, time.UTC)

	// Finding from Assessment 2 (Run 2 on Friday): Different Finding ID, Timestamp, Target ID
	fRun2 := helperMakeFPFinding("fnd_999_run2", "BOLA on User API", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	fRun2.EvidenceDetails.Details["parameter"] = "user_id"
	fRun2.Timestamp = time.Date(2026, 10, 15, 14, 30, 0, 0, time.UTC)

	fp1 := correlation.ComputeStableFingerprint(fRun1)
	fp2 := correlation.ComputeStableFingerprint(fRun2)

	if fp1 == "" || fp2 == "" {
		t.Fatalf("Expected non-empty fingerprints, got fp1=%q, fp2=%q", fp1, fp2)
	}
	if len(fp1) != 64 || len(fp2) != 64 {
		t.Fatalf("Expected 64-char SHA-256 hex digests, got len=%d and len=%d", len(fp1), len(fp2))
	}
	if fp1 != fp2 {
		t.Errorf("Fingerprints must be invariant across assessment runs: %s != %s", fp1, fp2)
	}
}

// -----------------------------------------------------------------------------
// Category 2: Stability Across Verification State Transitions
// -----------------------------------------------------------------------------
func TestFingerprint_Category02_VerificationStateInvariance(t *testing.T) {
	// Run 1: Suspected candidate finding
	fSuspected := helperMakeFPFinding("f1", "SQL Injection Candidate", "sql-injection", report.SeverityHigh, report.ConfidenceLow, report.VerificationDetected, "https://api.example.com", "https://api.example.com/v1/search", "POST")
	fSuspected.Status = report.FindingStatusSuspected
	fSuspected.EvidenceDetails.Details["parameter"] = "query"

	// Run 2: Actively confirmed finding
	fConfirmed := helperMakeFPFinding("f2", "SQL Injection Candidate", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/search", "POST")
	fConfirmed.Status = report.FindingStatusConfirmed
	fConfirmed.EvidenceDetails.Details["parameter"] = "query"

	fpSuspected := correlation.ComputeStableFingerprint(fSuspected)
	fpConfirmed := correlation.ComputeStableFingerprint(fConfirmed)

	if fpSuspected != fpConfirmed {
		t.Errorf("Verification transition must not alter finding fingerprint: suspected=%s, confirmed=%s", fpSuspected, fpConfirmed)
	}
}

// -----------------------------------------------------------------------------
// Category 3: Stability Across Score & Confidence Adjustments
// -----------------------------------------------------------------------------
func TestFingerprint_Category03_ScoreAndConfidenceInvariance(t *testing.T) {
	fInitial := helperMakeFPFinding("f1", "Missing CSP", "missing-csp", report.SeverityLow, report.ConfidenceMedium, report.VerificationObserved, "https://example.com", "https://example.com/", "GET")
	fInitial.Score = 10

	fAdjusted := helperMakeFPFinding("f2", "Missing CSP", "missing-csp", report.SeverityLow, report.ConfidenceHigh, report.VerificationObserved, "https://example.com", "https://example.com/", "GET")
	fAdjusted.Score = 15

	fpInit := correlation.ComputeStableFingerprint(fInitial)
	fpAdj := correlation.ComputeStableFingerprint(fAdjusted)

	if fpInit != fpAdj {
		t.Errorf("Score or confidence changes must not alter finding fingerprint: %s != %s", fpInit, fpAdj)
	}
}

// -----------------------------------------------------------------------------
// Category 4: Stability Across Title Rewording & Prose Variations
// -----------------------------------------------------------------------------
func TestFingerprint_Category04_TitleAndProseInvariance(t *testing.T) {
	fProse1 := helperMakeFPFinding("f1", "Potential Broken Object Level Authorization (BOLA)", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/api/accounts", "GET")
	fProse1.Description = "Detailed description version 1 with analysis."
	fProse1.EvidenceDetails.Details["parameter"] = "account_id"

	fProse2 := helperMakeFPFinding("f2", "BOLA Authorization Flaw Confirmed", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/api/accounts", "GET")
	fProse2.Description = "Reworded description version 2 with updated remediation."
	fProse2.EvidenceDetails.Details["parameter"] = "account_id"

	fp1 := correlation.ComputeStableFingerprint(fProse1)
	fp2 := correlation.ComputeStableFingerprint(fProse2)

	if fp1 != fp2 {
		t.Errorf("Prose edits and title variations must not alter finding fingerprint: %s != %s", fp1, fp2)
	}
}

// -----------------------------------------------------------------------------
// Category 5: Stability Across Incidental Evidence & Query Ordering
// -----------------------------------------------------------------------------
func TestFingerprint_Category05_IncidentalEvidenceOrdering(t *testing.T) {
	// URL with query keys in different order: ?b=val2&a=val1 vs ?a=val1&b=val2
	fOrder1 := helperMakeFPFinding("f1", "API Endpoint", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/items?b=2&a=1", "GET")
	fOrder2 := helperMakeFPFinding("f2", "API Endpoint", "api-route", report.SeverityInfo, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/items?a=1&b=2", "GET")

	fp1 := correlation.ComputeStableFingerprint(fOrder1)
	fp2 := correlation.ComputeStableFingerprint(fOrder2)

	if fp1 != fp2 {
		t.Errorf("Query parameter ordering differences must normalize to identical fingerprint: %s != %s", fp1, fp2)
	}
}

// -----------------------------------------------------------------------------
// Category 6: HTTP / API Vulnerability Differentiation by Parameter & Method
// -----------------------------------------------------------------------------
func TestFingerprint_Category06_HTTPParameterAndMethodDifferentiation(t *testing.T) {
	// Same endpoint, different vulnerable parameters
	fParamA := helperMakeFPFinding("f1", "SQLi on User", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/search", "POST")
	fParamA.EvidenceDetails.Details["parameter"] = "username"

	fParamB := helperMakeFPFinding("f2", "SQLi on Org", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/search", "POST")
	fParamB.EvidenceDetails.Details["parameter"] = "organization"

	fpA := correlation.ComputeStableFingerprint(fParamA)
	fpB := correlation.ComputeStableFingerprint(fParamB)

	if fpA == fpB {
		t.Errorf("Different vulnerable parameters must produce distinct fingerprints: %s == %s", fpA, fpB)
	}

	// Same endpoint, different HTTP methods
	fMethodGet := helperMakeFPFinding("f3", "Method Access", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/admin/users", "GET")
	fMethodPost := helperMakeFPFinding("f4", "Method Access", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/admin/users", "POST")

	fpGet := correlation.ComputeStableFingerprint(fMethodGet)
	fpPost := correlation.ComputeStableFingerprint(fMethodPost)

	if fpGet == fpPost {
		t.Errorf("Different HTTP methods must produce distinct fingerprints: %s == %s", fpGet, fpPost)
	}
}

// -----------------------------------------------------------------------------
// Category 7: Configuration & Security-Hardening Differentiation
// -----------------------------------------------------------------------------
func TestFingerprint_Category07_HardeningRuleDifferentiation(t *testing.T) {
	// Missing CSP vs Missing HSTS vs Missing X-Frame-Options on the exact same endpoint
	fCSP := helperMakeFPFinding("f1", "Missing CSP", "missing-security-header", report.SeverityLow, report.ConfidenceHigh, report.VerificationObserved, "https://example.com", "https://example.com/", "GET")
	fCSP.EvidenceDetails.Details["header"] = "content-security-policy"

	fHSTS := helperMakeFPFinding("f2", "Missing HSTS", "missing-security-header", report.SeverityMedium, report.ConfidenceHigh, report.VerificationObserved, "https://example.com", "https://example.com/", "GET")
	fHSTS.EvidenceDetails.Details["header"] = "strict-transport-security"

	fXFO := helperMakeFPFinding("f3", "Missing XFO", "missing-security-header", report.SeverityLow, report.ConfidenceHigh, report.VerificationObserved, "https://example.com", "https://example.com/", "GET")
	fXFO.EvidenceDetails.Details["header"] = "x-frame-options"

	fpCSP := correlation.ComputeStableFingerprint(fCSP)
	fpHSTS := correlation.ComputeStableFingerprint(fHSTS)
	fpXFO := correlation.ComputeStableFingerprint(fXFO)

	if fpCSP == fpHSTS || fpCSP == fpXFO || fpHSTS == fpXFO {
		t.Errorf("Distinct security headers on the same endpoint must produce distinct fingerprints: CSP=%s, HSTS=%s, XFO=%s", fpCSP, fpHSTS, fpXFO)
	}
}

// -----------------------------------------------------------------------------
// Category 8: Cloud Resource Misconfigurations & Resource Separation
// -----------------------------------------------------------------------------
func TestFingerprint_Category08_CloudResourceDifferentiation(t *testing.T) {
	// Same bucket, different misconfigurations (Public Read vs Missing Encryption)
	fBucketRead := helperMakeFPFinding("f1", "S3 Public Read", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://corp-backups", "s3://corp-backups", "GET")
	fBucketRead.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "corp-backups",
		"permission":     "public_read",
	}

	fBucketEncrypt := helperMakeFPFinding("f2", "S3 Missing Encryption", "s3-leak", report.SeverityMedium, report.ConfidenceHigh, report.VerificationVerified, "s3://corp-backups", "s3://corp-backups", "GET")
	fBucketEncrypt.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "corp-backups",
		"permission":     "unencrypted_storage",
	}

	fpRead := correlation.ComputeStableFingerprint(fBucketRead)
	fpEncrypt := correlation.ComputeStableFingerprint(fBucketEncrypt)

	if fpRead == fpEncrypt {
		t.Errorf("Different cloud misconfigurations on same bucket must produce distinct fingerprints: %s == %s", fpRead, fpEncrypt)
	}

	// Different buckets with same misconfiguration
	fOtherBucket := helperMakeFPFinding("f3", "S3 Public Read", "s3-leak", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "s3://public-assets", "s3://public-assets", "GET")
	fOtherBucket.EvidenceDetails.Details = map[string]string{
		"cloud_provider": "aws_s3",
		"bucket":         "public-assets",
		"permission":     "public_read",
	}

	fpOther := correlation.ComputeStableFingerprint(fOtherBucket)
	if fpRead == fpOther {
		t.Errorf("Different buckets must produce distinct fingerprints: %s == %s", fpRead, fpOther)
	}
}

// -----------------------------------------------------------------------------
// Category 9: Multi-Tenant and Multi-Account Isolation Boundaries
// -----------------------------------------------------------------------------
func TestFingerprint_Category09_TenantAndAccountIsolationBoundaries(t *testing.T) {
	// Same host and endpoint across Tenant A vs Tenant B
	fTenantA := helperMakeFPFinding("f1", "BOLA", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://saas.app.com", "https://saas.app.com/api/v1/data", "GET")
	fTenantA.EvidenceDetails.Details["tenant_id"] = "tenant-alpha"

	fTenantB := helperMakeFPFinding("f2", "BOLA", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://saas.app.com", "https://saas.app.com/api/v1/data", "GET")
	fTenantB.EvidenceDetails.Details["tenant_id"] = "tenant-beta"

	fpA := correlation.ComputeStableFingerprint(fTenantA)
	fpB := correlation.ComputeStableFingerprint(fTenantB)

	if fpA == fpB {
		t.Errorf("Cross-tenant findings must never collide in fingerprint: %s == %s", fpA, fpB)
	}

	// Same tenant, distinct Account IDs
	fAcct1 := helperMakeFPFinding("f3", "IAM Flaw", "iam-escalation", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://saas.app.com", "https://saas.app.com/api/v1/data", "GET")
	fAcct1.EvidenceDetails.Details["tenant_id"] = "tenant-alpha"
	fAcct1.EvidenceDetails.Details["account_id"] = "acct-prod"

	fAcct2 := helperMakeFPFinding("f4", "IAM Flaw", "iam-escalation", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://saas.app.com", "https://saas.app.com/api/v1/data", "GET")
	fAcct2.EvidenceDetails.Details["tenant_id"] = "tenant-alpha"
	fAcct2.EvidenceDetails.Details["account_id"] = "acct-dev"

	fpAcct1 := correlation.ComputeStableFingerprint(fAcct1)
	fpAcct2 := correlation.ComputeStableFingerprint(fAcct2)

	if fpAcct1 == fpAcct2 {
		t.Errorf("Cross-account findings must never collide in fingerprint: %s == %s", fpAcct1, fpAcct2)
	}
}

// -----------------------------------------------------------------------------
// Category 10: Mobile Application (APK) Differentiation
// -----------------------------------------------------------------------------
func TestFingerprint_Category10_MobileAPKDifferentiation(t *testing.T) {
	// Different exported activities in the same mobile package
	fActA := helperMakeFPFinding("f1", "Exported Activity 1", "apk-exported-activity", report.SeverityMedium, report.ConfidenceHigh, report.VerificationObserved, "apk://com.bank.app", "apk://com.bank.app", "GET")
	fActA.Source = "apk"
	fActA.EvidenceDetails.Details = map[string]string{
		"package_name": "com.bank.app",
		"component":    "com.bank.app.PaymentActivity",
	}

	fActB := helperMakeFPFinding("f2", "Exported Activity 2", "apk-exported-activity", report.SeverityMedium, report.ConfidenceHigh, report.VerificationObserved, "apk://com.bank.app", "apk://com.bank.app", "GET")
	fActB.Source = "apk"
	fActB.EvidenceDetails.Details = map[string]string{
		"package_name": "com.bank.app",
		"component":    "com.bank.app.SettingsActivity",
	}

	fpActA := correlation.ComputeStableFingerprint(fActA)
	fpActB := correlation.ComputeStableFingerprint(fActB)

	if fpActA == fpActB {
		t.Errorf("Different mobile components must produce distinct fingerprints: %s == %s", fpActA, fpActB)
	}
}

// -----------------------------------------------------------------------------
// Category 11: Secrets Detection Differentiation & Line-Number Invariance
// -----------------------------------------------------------------------------
func TestFingerprint_Category11_SecretsDifferentiationAndLineInvariance(t *testing.T) {
	// Same secret issue at line 14 vs line 88 (line shift due to code edits)
	fSecLine14 := helperMakeFPFinding("f1", "AWS Key Exposed", "hardcoded-secret", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://repo.corp.local", "/src/auth.js:14", "GET")
	fSecLine14.Source = report.SourceSecrets
	fSecLine14.EvidenceDetails.Details = map[string]string{
		"file_path":     "/src/auth.js",
		"secret_type":   "aws_access_key",
		"variable_name": "AWS_SECRET_ACCESS_KEY",
	}

	fSecLine88 := helperMakeFPFinding("f2", "AWS Key Exposed", "hardcoded-secret", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://repo.corp.local", "/src/auth.js:88", "GET")
	fSecLine88.Source = report.SourceSecrets
	fSecLine88.EvidenceDetails.Details = map[string]string{
		"file_path":     "/src/auth.js",
		"secret_type":   "aws_access_key",
		"variable_name": "AWS_SECRET_ACCESS_KEY",
	}

	fp14 := correlation.ComputeStableFingerprint(fSecLine14)
	fp88 := correlation.ComputeStableFingerprint(fSecLine88)

	if fp14 != fp88 {
		t.Errorf("Line number shift must NOT alter secret finding fingerprint: %s != %s", fp14, fp88)
	}

	// Different secret type in the same file
	fStripe := helperMakeFPFinding("f3", "Stripe Key Exposed", "hardcoded-secret", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://repo.corp.local", "/src/auth.js:40", "GET")
	fStripe.Source = report.SourceSecrets
	fStripe.EvidenceDetails.Details = map[string]string{
		"file_path":     "/src/auth.js",
		"secret_type":   "stripe_api_key",
		"variable_name": "STRIPE_SECRET_KEY",
	}

	fpStripe := correlation.ComputeStableFingerprint(fStripe)
	if fp14 == fpStripe {
		t.Errorf("Different secret types in the same file must produce distinct fingerprints: %s == %s", fp14, fpStripe)
	}
}

// -----------------------------------------------------------------------------
// Category 12: Incomplete & Ambiguous Findings Conservatism
// -----------------------------------------------------------------------------
func TestFingerprint_Category12_IncompleteEvidenceConservatism(t *testing.T) {
	// Two distinct incomplete findings with missing target and endpoint
	fAmb1 := report.Finding{
		ID:       "fnd_amb_01",
		Title:    "Ambiguous Finding One",
		Category: "generic-vulnerability",
	}

	fAmb2 := report.Finding{
		ID:       "fnd_amb_02",
		Title:    "Ambiguous Finding Two",
		Category: "generic-vulnerability",
	}

	details1 := correlation.ComputeFingerprintDetails(fAmb1, nil)
	details2 := correlation.ComputeFingerprintDetails(fAmb2, nil)

	if !details1.IsAmbiguous || !details2.IsAmbiguous {
		t.Errorf("Expected findings with missing target/endpoint to be marked ambiguous")
	}
	if details1.Value == details2.Value {
		t.Errorf("Conservative fallback violated: separate ambiguous findings must not merge into identical fingerprint (%s == %s)", details1.Value, details2.Value)
	}
}

// -----------------------------------------------------------------------------
// Category 13: Secret Protection in Canonical Keys & Explanations
// -----------------------------------------------------------------------------
func TestFingerprint_Category13_SecretProtectionInExplanations(t *testing.T) {
	rawSecret := "AKIAIOSFODNN7EXAMPLE_SECRET"
	sensitiveURL := fmt.Sprintf("https://api.example.com/callback?token=%s&auth=supersecret123", rawSecret)

	fWithSecret := helperMakeFPFinding("f1", "Leaked Token", "api-route", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", sensitiveURL, "GET")
	fWithSecret.EvidenceDetails.Details["parameter"] = "token"

	details := correlation.ComputeFingerprintDetails(fWithSecret, nil)

	// Ensure raw sensitive query values NEVER appear in the canonical payload or explanation
	if strings.Contains(details.CanonicalPayload, rawSecret) {
		t.Errorf("Raw secret token leaked in canonical payload: %s", details.CanonicalPayload)
	}
	if strings.Contains(details.CanonicalPayload, "supersecret123") {
		t.Errorf("Sensitive parameter value leaked in canonical payload: %s", details.CanonicalPayload)
	}
}

// -----------------------------------------------------------------------------
// Category 14: Cross-Assessment Finding Lifecycle Tracking
// -----------------------------------------------------------------------------
func TestFingerprint_Category14_LifecycleTrackingComparison(t *testing.T) {
	// Baseline assessment findings (Run 1)
	fRecurringBase := helperMakeFPFinding("f1_base", "BOLA on User API", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	fRecurringBase.EvidenceDetails.Details["parameter"] = "id"

	fResolvedBase := helperMakeFPFinding("f2_base", "Missing CSP", "missing-csp", report.SeverityLow, report.ConfidenceHigh, report.VerificationObserved, "https://api.example.com", "https://api.example.com/", "GET")
	fResolvedBase.EvidenceDetails.Details["header"] = "content-security-policy"

	baseline := []report.Finding{fRecurringBase, fResolvedBase}

	// Current assessment findings (Run 2)
	fRecurringCur := helperMakeFPFinding("f1_cur", "BOLA on User API (Verified)", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/users", "GET")
	fRecurringCur.EvidenceDetails.Details["parameter"] = "id"

	fNewCur := helperMakeFPFinding("f3_cur", "SQLi in Orders", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.example.com", "https://api.example.com/v1/orders", "POST")
	fNewCur.EvidenceDetails.Details["parameter"] = "order_id"

	current := []report.Finding{fRecurringCur, fNewCur}

	diff := correlation.CompareFindings(baseline, current)

	if diff.BaselineCount != 2 {
		t.Errorf("Expected 2 baseline findings, got %d", diff.BaselineCount)
	}
	if diff.CurrentCount != 2 {
		t.Errorf("Expected 2 current findings, got %d", diff.CurrentCount)
	}
	if diff.RecurringCount != 1 {
		t.Errorf("Expected 1 recurring finding, got %d", diff.RecurringCount)
	}
	if diff.NewCount != 1 {
		t.Errorf("Expected 1 new finding, got %d", diff.NewCount)
	}
	if diff.ResolvedCount != 1 {
		t.Errorf("Expected 1 resolved finding, got %d", diff.ResolvedCount)
	}

	// Verify lifecycle statuses in items
	statusMap := make(map[correlation.FindingLifecycleStatus]int)
	for _, item := range diff.Items {
		statusMap[item.LifecycleStatus]++
	}
	if statusMap[correlation.LifecycleRecurring] != 1 {
		t.Errorf("Expected 1 RECURRING item, got %d", statusMap[correlation.LifecycleRecurring])
	}
	if statusMap[correlation.LifecycleNew] != 1 {
		t.Errorf("Expected 1 NEW item, got %d", statusMap[correlation.LifecycleNew])
	}
	if statusMap[correlation.LifecycleResolved] != 1 {
		t.Errorf("Expected 1 RESOLVED item, got %d", statusMap[correlation.LifecycleResolved])
	}
}

// -----------------------------------------------------------------------------
// Category 15: SQLite Store Cross-Assessment Persistence & CompareExecutions
// -----------------------------------------------------------------------------
func TestFingerprint_Category15_StoreCompareExecutionsIntegration(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_fp_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("Failed to initialize SQLite store: %v", err)
	}
	defer store.Close()

	asmID := "asm-lifecycle-test"
	exec1ID := "exec-run-001"
	exec2ID := "exec-run-002"
	targetID := "tgt-001"
	clientID := "client-001"

	// 1. Setup Client
	client := &assessment.Client{ID: clientID, Name: "Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// 2. Setup Assessment
	asm := &assessment.Assessment{ID: asmID, ClientID: clientID, Name: "Fingerprint Lifecycle Test", Status: assessment.StatusRunning}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	// 3. Setup Target
	target := &assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://api.corp.local",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	exec1 := &assessment.AssessmentExecution{ID: exec1ID, AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	if err := store.CreateExecution(exec1); err != nil {
		t.Fatalf("CreateExecution 1 failed: %v", err)
	}

	exec2 := &assessment.AssessmentExecution{ID: exec2ID, AssessmentID: asmID, Status: assessment.StatusCompleted, StartedAt: time.Now().UTC()}
	if err := store.CreateExecution(exec2); err != nil {
		t.Fatalf("CreateExecution 2 failed: %v", err)
	}

	// Execution 1 Findings: Finding A + Finding B
	fA := helperMakeFPFinding("f_A", "Auth Flaw", "auth-bypass", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/auth", "POST")
	fB := helperMakeFPFinding("f_B", "CORS Wildcard", "cors-wildcard", report.SeverityMedium, report.ConfidenceHigh, report.VerificationObserved, "https://api.corp.local", "https://api.corp.local/api", "GET")

	afA1 := assessment.ToAssessmentFinding(asmID, exec1ID, targetID, fA)
	afB1 := assessment.ToAssessmentFinding(asmID, exec1ID, targetID, fB)
	if err := store.SaveFindings([]assessment.AssessmentFinding{afA1, afB1}); err != nil {
		t.Fatalf("SaveFindings Exec 1 failed: %v", err)
	}

	// Execution 2 Findings: Finding A (recurring) + Finding C (new) -> Finding B is resolved
	fC := helperMakeFPFinding("f_C", "BOLA on Invoices", "bola", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/invoices", "GET")
	fC.EvidenceDetails.Details["parameter"] = "inv_id"

	afA2 := assessment.ToAssessmentFinding(asmID, exec2ID, targetID, fA)
	afC2 := assessment.ToAssessmentFinding(asmID, exec2ID, targetID, fC)
	if err := store.SaveFindings([]assessment.AssessmentFinding{afA2, afC2}); err != nil {
		t.Fatalf("SaveFindings Exec 2 failed: %v", err)
	}

	// Query Store.CompareExecutions
	diff, err := store.CompareExecutions(asmID, exec1ID, exec2ID)
	if err != nil {
		t.Fatalf("CompareExecutions failed: %v", err)
	}

	if diff.RecurringCount != 1 {
		t.Errorf("Expected 1 recurring finding in SQLite store comparison, got %d", diff.RecurringCount)
	}
	if diff.NewCount != 1 {
		t.Errorf("Expected 1 new finding in SQLite store comparison, got %d", diff.NewCount)
	}
	if diff.ResolvedCount != 1 {
		t.Errorf("Expected 1 resolved finding in SQLite store comparison, got %d", diff.ResolvedCount)
	}
}

// -----------------------------------------------------------------------------
// Category 16: Determinism & Idempotency Across 1,000 Iterations
// -----------------------------------------------------------------------------
func TestFingerprint_Category16_DeterminismAcross1000Runs(t *testing.T) {
	f := helperMakeFPFinding("f_det", "BFLA Admin Access", "bfla", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.example.com", "https://app.example.com/api/v1/admin/users", "POST")
	f.EvidenceDetails.Details["parameter"] = "role"

	baselineFP := correlation.ComputeStableFingerprint(f)

	for i := 0; i < 1000; i++ {
		fp := correlation.ComputeStableFingerprint(f)
		if fp != baselineFP {
			t.Fatalf("Non-deterministic fingerprint detected on iteration %d: %s != %s", i, fp, baselineFP)
		}
	}
}

// -----------------------------------------------------------------------------
// Category 17: Delimiter Collision Immunity & Canonical Payload Integrity
// -----------------------------------------------------------------------------
func TestFingerprint_Category17_DelimiterCollisionImmunity(t *testing.T) {
	// Pair with shifted delimiter in asset/endpoint vs vulnerability keys
	f1 := helperMakeFPFinding("f1", "SQLi", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local:8080", "https://api.corp.local:8080/v1/auth", "POST")
	f1.RuleID = "RULE:C"

	f2 := helperMakeFPFinding("f2", "SQLi", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/auth", "POST")
	f2.RuleID = "RULE:C:EXTRA"

	d1 := correlation.ComputeFingerprintDetails(f1, nil)
	d2 := correlation.ComputeFingerprintDetails(f2, nil)

	if d1.CanonicalPayload == d2.CanonicalPayload {
		t.Fatalf("CRITICAL DEFECT: Pre-hash canonical payload collision due to delimiter leakage:\nPayload 1: %s\nPayload 2: %s", d1.CanonicalPayload, d2.CanonicalPayload)
	}
	if d1.Value == d2.Value {
		t.Fatalf("CRITICAL DEFECT: Fingerprint hash collision between distinct finding tuples: %s", d1.Value)
	}
}

// -----------------------------------------------------------------------------
// Category 18: Fingerprint Trust, Invalidation & Cross-Finding Copy Immunity
// -----------------------------------------------------------------------------
func TestFingerprint_Category18_CrossFindingCopyImmunity(t *testing.T) {
	// Finding A: SQL Injection on /api/login
	fA := helperMakeFPFinding("fA", "SQL Injection", "sql-injection", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://app.corp.local", "https://app.corp.local/api/login", "POST")
	fA.EvidenceDetails.Details["parameter"] = "username"
	fpA := correlation.ComputeStableFingerprint(fA)
	fA.Fingerprint = fpA

	// Finding B: BOLA on /api/users
	fB := helperMakeFPFinding("fB", "BOLA on Users", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://app.corp.local", "https://app.corp.local/api/users", "GET")
	fB.EvidenceDetails.Details["parameter"] = "id"

	// Maliciously or accidentally copy Finding A's fingerprint onto Finding B
	fB.Fingerprint = fpA

	// 1. IsValidFingerprint must detect that fpA is invalid/mismatched for Finding B
	if correlation.IsValidFingerprint(fB, fB.Fingerprint) {
		t.Fatalf("CRITICAL DEFECT: IsValidFingerprint accepted a copied/mismatched fingerprint!")
	}

	// 2. EnsureFindingFingerprint must neutralize the copied fingerprint
	fBCopy := fB
	correlation.EnsureFindingFingerprint(&fBCopy, correlation.TrustPolicyRecomputeIfLegacy)
	if fBCopy.Fingerprint == fpA {
		t.Fatalf("CRITICAL DEFECT: EnsureFindingFingerprint preserved a copied/mismatched fingerprint!")
	}
	if !correlation.IsValidFingerprint(fBCopy, fBCopy.Fingerprint) {
		t.Fatalf("EnsureFindingFingerprint failed to compute a valid fingerprint!")
	}

	// 3. Cross-assessment comparison must NOT conflate Finding A and Finding B
	cmp := correlation.CompareFindings([]report.Finding{fA}, []report.Finding{fB})
	if cmp.RecurringCount != 0 {
		t.Errorf("CRITICAL DEFECT: Copied fingerprint caused distinct findings to be marked RECURRING! got %d", cmp.RecurringCount)
	}
	if cmp.NewCount != 1 {
		t.Errorf("Expected 1 NEW finding, got %d", cmp.NewCount)
	}
}

// -----------------------------------------------------------------------------
// Category 19: Execution Failure & Cancellation Resolution Safeguard
// -----------------------------------------------------------------------------
func TestFingerprint_Category19_ExecutionFailureResolutionSafeguard(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-fp-fail-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "fail_test.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to create sqlite store: %v", err)
	}
	defer store.Close()

	asmID := "asm_fail_test"
	clientID := "cli_fail_test"
	targetID := "tgt_fail_test"
	exec1ID := "exec_success"
	exec2ID := "exec_crashed"

	_ = store.CreateClient(&assessment.Client{ID: clientID, Name: "Test Client"})
	_ = store.CreateAssessment(&assessment.Assessment{ID: asmID, ClientID: clientID, Name: "Fail Test", Status: assessment.StatusRunning})
	_ = store.AddTarget(&assessment.AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://api.corp.local",
		TargetType:   assessment.TargetWebsite,
		ScopeStatus:  "APPROVED",
	})

	// Execution 1: Completed scan with 2 critical findings
	now := time.Now().UTC()
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           exec1ID,
		AssessmentID: asmID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
	})
	f1 := helperMakeFPFinding("f1", "SQLi", "sql-injection", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/auth", "POST")
	f2 := helperMakeFPFinding("f2", "BOLA", "bola", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/items", "GET")
	af1 := assessment.ToAssessmentFinding(asmID, exec1ID, targetID, f1)
	af2 := assessment.ToAssessmentFinding(asmID, exec1ID, targetID, f2)
	_ = store.SaveFindings([]assessment.AssessmentFinding{af1, af2})

	// Execution 2: Crashed/Failed scan (0 findings produced because the scanner died)
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           exec2ID,
		AssessmentID: asmID,
		Status:       assessment.StatusFailed,
		StartedAt:    now.Add(1 * time.Hour),
		ErrorMessage: "scanner crashed due to network timeout",
	})

	// Compare executions: Baseline=exec1, Current=exec2 (Failed)
	cmp, err := store.CompareExecutions(asmID, exec1ID, exec2ID)
	if err != nil {
		t.Fatalf("CompareExecutions failed: %v", err)
	}

	// CRITICAL SAFETY CHECK: The failed scan must NEVER mark previous findings as resolved!
	if cmp.ResolvedCount != 0 {
		t.Fatalf("CRITICAL SECURITY DEFECT: Failed execution marked %d findings as RESOLVED!", cmp.ResolvedCount)
	}
	if cmp.UnassessedCount != 2 {
		t.Errorf("Expected 2 UNASSESSED findings for failed run, got %d", cmp.UnassessedCount)
	}
}

// -----------------------------------------------------------------------------
// Category 20: Target Scope Boundary Resolution Safeguard
// -----------------------------------------------------------------------------
func TestFingerprint_Category20_TargetScopeBoundaryResolutionSafeguard(t *testing.T) {
	// Baseline findings: one on api.corp.local, one on payments.corp.local
	fAPI := helperMakeFPFinding("f_api", "BOLA on API", "bola", report.SeverityHigh, report.ConfidenceHigh, report.VerificationVerified, "https://api.corp.local", "https://api.corp.local/users", "GET")
	fPay := helperMakeFPFinding("f_pay", "CSRF on Payments", "csrf", report.SeverityCritical, report.ConfidenceHigh, report.VerificationVerified, "https://payments.corp.local", "https://payments.corp.local/transfer", "POST")

	baseline := []report.Finding{fAPI, fPay}

	// Current run: Only scanned https://api.corp.local (payments was not in scope at all!)
	// Current found 0 vulnerabilities on https://api.corp.local (api issue was resolved).
	current := []report.Finding{}

	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://api.corp.local"},
	}

	cmp := correlation.CompareFindingsWithOptions(baseline, current, opts)

	// API finding was in scope and not found -> RESOLVED (1)
	if cmp.ResolvedCount != 1 {
		t.Errorf("Expected 1 resolved finding for in-scope target, got %d", cmp.ResolvedCount)
	}

	// Payments finding was NOT in scope -> UNASSESSED (1)
	if cmp.UnassessedCount != 1 {
		t.Errorf("Expected 1 unassessed finding for out-of-scope target, got %d", cmp.UnassessedCount)
	}

	// Verify items
	for _, item := range cmp.Items {
		if strings.Contains(item.TargetEndpoint, "payments.corp.local") {
			if item.LifecycleStatus != correlation.LifecycleUnassessed {
				t.Fatalf("CRITICAL DEFECT: Out-of-scope target was marked %s instead of UNASSESSED!", item.LifecycleStatus)
			}
		}
		if strings.Contains(item.TargetEndpoint, "api.corp.local") {
			if item.LifecycleStatus != correlation.LifecycleResolved {
				t.Fatalf("In-scope target was marked %s instead of RESOLVED!", item.LifecycleStatus)
			}
		}
	}
}
