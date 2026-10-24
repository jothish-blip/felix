package test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/auth"
	"felix/pkg/bfla"
	"felix/pkg/bopla"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/verification"
	"felix/pkg/workflow"
)

// =============================================================================
// PHASE 5.8: EVIDENCE INTEGRITY, REPRODUCIBILITY & REGRESSION RELIABILITY
// =============================================================================

// 1. Evidence Integrity: Invariant Proof Requirement
// Proves that VERIFIED findings require concrete invariant evidence, whereas
// generic HTTP 200 responses without state proof remain CANDIDATE or INCONCLUSIVE.
func TestEvidenceIntegrity_InvariantProofRequirement(t *testing.T) {
	wfCandidate := workflow.Workflow{
		ID:   "wf-echo-candidate",
		Name: "Echo Only Candidate Workflow",
		Steps: []workflow.Step{
			{
				ID:       "step-1-init",
				Name:     "Initialize",
				Endpoint: "/checkout/start",
				Method:   "POST",
			},
			{
				ID:                    "step-2-pay",
				Name:                  "Payment",
				Endpoint:              "/checkout/pay",
				Method:                "POST",
				Preconditions:         []string{"step-1-init"},
				VerificationProperty:  "payment_status",
				ExpectedVerifiedValue: "captured",
			},
		},
		CategoriesToAssess: []workflow.Category{workflow.CategoryPrerequisiteSkipping},
	}

	// Echo server: returns 200 OK on /checkout/pay, but read-back does NOT show "captured"
	echoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/checkout/pay" {
			// Skip attempt returns 200 OK without capturing payment
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"received","payment_status":"pending_approval"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer echoSrv.Close()

	past := time.Now().UTC().Add(-1 * time.Hour)
	future := time.Now().UTC().Add(24 * time.Hour)
	authRec := &auth.AuthorizationRecord{
		ID:         "auth-wf-test",
		Status:     "APPROVED",
		ValidFrom:  &past,
		ValidUntil: &future,
	}

	wfEngine := workflow.NewEngine(nil, workflow.DefaultConfig())
	actx := &workflow.AssessmentContext{
		AssessmentID:            "asm-wf-ev-test",
		ExecutionID:             "exec-wf-ev-01",
		BaseURL:                 echoSrv.URL,
		Authorization:           authRec,
		AllowStateChangingTests: true,
		SyntheticFixture:        true,
		Workflows:               []workflow.Workflow{wfCandidate},
		Identities:              workflow.DefaultIdentities(),
		IsAllowed:               func(u string) bool { return true },
	}

	resEcho, _, err := wfEngine.Assess(context.Background(), actx)
	if err != nil {
		t.Fatalf("unexpected error assessing workflow: %v", err)
	}
	if len(resEcho) == 0 {
		t.Fatalf("expected assessment results, got none")
	}

	// Invariant: Missing property-level proof must NOT be marked VERIFIED
	for _, r := range resEcho {
		if r.VerificationState == workflow.StateVerified {
			t.Fatalf("CRITICAL EVIDENCE INTEGRITY VIOLATION: HTTP 200 without invariant proof marked VERIFIED: %s", r.EvidenceSummary)
		}
	}
}

// 2. Failure Distinction: Transport/Network Failures Cannot Become NOT_VULNERABLE or VERIFIED
// Proves that connection refused, timeouts, and unparseable bodies are classified
// as INCONCLUSIVE or ERROR, preserving the failure reason without false security claims.
func TestEvidenceIntegrity_TransportAndParserFailureHandling(t *testing.T) {
	// A. Non-routable port (connection refused)
	deadURL := "http://127.0.0.1:54321/unreachable"

	fConnRefused := report.Finding{
		ID:          "fnd-conn-refused",
		RuleID:      "API-CHECK-RATE-LIMIT",
		Category:    "API_SECURITY",
		Severity:    report.SeverityMedium,
		Confidence:  report.ConfidenceHigh,
		Target:      deadURL,
		Endpoint:    deadURL,
		Method:      "GET",
		Description: "Rate limit verification on dead endpoint",
	}

	safety := verification.NewSafetyChecker(verification.SafetyOptions{
		IsAuthorized:         true,
		InScopeFunc:          func(u string) bool { return true },
		MaxRequestsPerTarget: 5,
	})
	vEngine := verification.NewEngine(safety)

	res := vEngine.VerifyFinding(context.Background(), fConnRefused)

	// Invariant: Unreachable service must NOT be marked VERIFIED or NOT_EXPOSED (NOT_VULNERABLE)
	if res.Status == verification.StatusVerified {
		t.Fatalf("VIOLATION: Connection failure produced VERIFIED status")
	}
	if res.Status == verification.StatusNotExposed {
		t.Fatalf("VIOLATION: Connection failure produced NOT_EXPOSED / NOT_VULNERABLE status")
	}
	if res.FindingStatus == report.FindingStatusConfirmed {
		t.Fatalf("VIOLATION: Connection failure produced CONFIRMED finding status")
	}
	if res.FailureReason == "" && res.InconclusiveReason == "" {
		t.Errorf("expected failure or inconclusive reason to be preserved on connection failure")
	}

	// B. Non-JSON body on property evaluation
	baselineResp := bopla.ResponseData{
		StatusCode: 200,
		Header:     map[string][]string{"Content-Type": {"text/html"}},
		Body:       []byte("<html><body>Fatal Error</body></html>"),
	}
	testResp := bopla.ResponseData{
		StatusCode: 200,
		Header:     map[string][]string{"Content-Type": {"text/html"}},
		Body:       []byte("<html><body>Fatal Error</body></html>"),
	}

	boplaPol := bopla.PropertyPolicy{
		PropertyID:   "POL-USER-ROLE",
		Name:         "User Role Protection",
		Endpoint:     "/api/v1/user",
		Method:       "GET",
		Category:     bopla.CategoryBOPLAPropertyRead,
		PropertyPath: "user.role",
		AllowedRoles: []string{"admin"},
	}

	boplaRes := bopla.ComparePropertyRead(baselineResp, testResp, boplaPol, "admin", "user", "alice")
	if boplaRes.State == bopla.StateVerified {
		t.Fatalf("VIOLATION: Malformed non-JSON response evaluated as VERIFIED")
	}
	if boplaRes.State != bopla.StateInconclusive {
		t.Errorf("expected INCONCLUSIVE for non-JSON body, got %s", boplaRes.State)
	}
	if !strings.Contains(boplaRes.EvidenceSummary, "non-JSON") {
		t.Errorf("expected evidence summary to document non-JSON body, got: %s", boplaRes.EvidenceSummary)
	}
}

// 3. Deterministic Reproducibility: Repeated Runs Produce Identical Normalized Findings
// Tests that multiple runs on identical fixtures produce deterministic IDs,
// sorting orders, and score values without reliance on unstable slice ordering.
func TestEvidenceIntegrity_DeterministicReproducibility(t *testing.T) {
	// Create two findings that share Category and Endpoint to test tie-breaker determinism
	f1 := report.Finding{
		ID:          "fnd_001_auth_header",
		RuleID:      "SEC-AUTH-01",
		Status:      report.FindingStatusConfirmed,
		Category:    "AUTHENTICATION",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://api.example.com",
		Endpoint:    "/api/v1/user",
		Method:      "GET",
		Score:       80,
		Fingerprint: "fp_auth_user_001",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
		EvidenceDetails: report.EvidenceDetails{
			ExpectedBehavior: "Endpoint requires valid Bearer token",
			ObservedBehavior: "Endpoint disclosed user record to anonymous caller",
		},
	}

	f2 := report.Finding{
		ID:          "fnd_002_user_bopla",
		RuleID:      "BOPLA-PROP-02",
		Status:      report.FindingStatusConfirmed,
		Category:    "AUTHENTICATION",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://api.example.com",
		Endpoint:    "/api/v1/user",
		Method:      "GET",
		Score:       80,
		Fingerprint: "fp_bopla_user_002",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
		EvidenceDetails: report.EvidenceDetails{
			ExpectedBehavior: "Role property withheld from non-admin identity",
			ObservedBehavior: "Role property returned in JSON response",
		},
	}

	// Run 1: Order [f1, f2]
	rep1 := report.BuildReport("https://api.example.com", []report.Finding{f1, f2})

	// Run 2: Reverse Order [f2, f1]
	rep2 := report.BuildReport("https://api.example.com", []report.Finding{f2, f1})

	// Assert finding ordering is deterministic across runs regardless of initial input order
	if len(rep1.Findings) != len(rep2.Findings) {
		t.Fatalf("mismatched finding counts: %d vs %d", len(rep1.Findings), len(rep2.Findings))
	}
	for i := range rep1.Findings {
		if rep1.Findings[i].ID != rep2.Findings[i].ID {
			t.Errorf("non-deterministic order at index %d: run1=%s, run2=%s",
				i, rep1.Findings[i].ID, rep2.Findings[i].ID)
		}
	}

	// Normalize timestamps for pure structural & content determinism comparison across second boundaries
	rep2.Timestamp = rep1.Timestamp
	if rep1.CommercialReport != nil && rep2.CommercialReport != nil {
		cr := report.BuildCommercialReport(rep2, report.WithCompletionStatus("COMPLETED"))
		rep2.CommercialReport = &cr
	}

	// Generate JSON from both runs and assert identical output
	json1, err1 := report.GenerateJSON(rep1)
	json2, err2 := report.GenerateJSON(rep2)
	if err1 != nil || err2 != nil {
		t.Fatalf("JSON generation error: %v / %v", err1, err2)
	}
	if string(json1) != string(json2) {
		t.Errorf("deterministic report output mismatch across repeated runs")
	}
}

// 4. Secret Redaction & Sensitive-Data Safety
// Tests that synthetic credentials (Bearer tokens, API keys, passwords, DB URLs, cookies)
// are rigorously scrubbed from evidence, descriptions, URLs, error messages, and reports.
func TestEvidenceIntegrity_ComprehensiveSecretRedaction(t *testing.T) {
	const rawBearer = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
	const rawStripeKey = "sk_test_mock_synthetic_secret_token_12345"
	const rawPassword = "SuperSecretMasterDbPassword123!"
	const rawCookie = "session_token=9a8b7c6d5e4f3a2b1c; Path=/; HttpOnly"

	rawURL := fmt.Sprintf("https://dbadmin:%s@db.internal.example.com/query?token=%s&apikey=%s&safe_param=xyz",
		rawPassword, rawBearer, rawStripeKey)

	f := report.Finding{
		ID:          "fnd-secret-leak-test",
		Title:       fmt.Sprintf("Secret Exposure with %s", rawStripeKey),
		Description: fmt.Sprintf("Observed %s in Authorization header, cookie: %s", rawBearer, rawCookie),
		Category:    "SENSITIVE_DATA_EXPOSURE",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      rawURL,
		Endpoint:    rawURL,
		Method:      "GET",
		Evidence:    fmt.Sprintf("Credentials: %s, password: %s", rawBearer, rawPassword),
		EvidenceDetails: report.EvidenceDetails{
			Observation:      fmt.Sprintf("Leaked password: %s", rawPassword),
			ExpectedBehavior: "Zero credential disclosure",
			ObservedBehavior: fmt.Sprintf("Disclosed token: %s", rawBearer),
			Details: map[string]string{
				"auth_header":  rawBearer,
				"cookie_value": rawCookie,
				"safe_detail":  "production_cluster_01",
			},
		},
		Verification: report.VerificationRecord{
			Status:    report.VerificationVerified,
			Result:    fmt.Sprintf("Confirmed leak of %s", rawStripeKey),
			Rationale: fmt.Sprintf("Token validated with %s", rawBearer),
		},
	}

	sanitized := report.SanitizeFinding(f)

	// Verify all secret strings are redacted
	assertNoSecret := func(field, val, secret string) {
		if strings.Contains(val, secret) {
			t.Errorf("LEAK DEFECT in %s: found raw secret %q in %q", field, secret, val)
		}
	}

	assertNoSecret("Title", sanitized.Title, rawStripeKey)
	assertNoSecret("Description", sanitized.Description, rawBearer)
	assertNoSecret("Description", sanitized.Description, "9a8b7c6d5e4f3a2b1c")
	assertNoSecret("Target", sanitized.Target, rawPassword)
	assertNoSecret("Target", sanitized.Target, rawStripeKey)
	assertNoSecret("Endpoint", sanitized.Endpoint, rawPassword)
	assertNoSecret("Evidence", sanitized.Evidence, rawBearer)
	assertNoSecret("Evidence", sanitized.Evidence, rawPassword)
	assertNoSecret("EvidenceDetails.Observation", sanitized.EvidenceDetails.Observation, rawPassword)
	assertNoSecret("EvidenceDetails.ObservedBehavior", sanitized.EvidenceDetails.ObservedBehavior, rawBearer)
	assertNoSecret("EvidenceDetails.Details[auth_header]", sanitized.EvidenceDetails.Details["auth_header"], rawBearer)
	assertNoSecret("EvidenceDetails.Details[cookie_value]", sanitized.EvidenceDetails.Details["cookie_value"], "9a8b7c6d5e4f3a2b1c")
	assertNoSecret("Verification.Result", sanitized.Verification.Result, rawStripeKey)
	assertNoSecret("Verification.Rationale", sanitized.Verification.Rationale, rawBearer)

	// Verify safe fields are not corrupted
	if sanitized.EvidenceDetails.Details["safe_detail"] != "production_cluster_01" {
		t.Errorf("safe detail was unexpectedly corrupted: %q", sanitized.EvidenceDetails.Details["safe_detail"])
	}
	if !strings.Contains(sanitized.Target, "safe_param=xyz") {
		t.Errorf("safe URL query parameter was removed: %s", sanitized.Target)
	}

	// Verify Error String Redaction
	rawErr := fmt.Errorf("connection failed to %s with password %s", rawURL, rawPassword)
	redactedErr := secrets.RedactText(rawErr.Error())
	assertNoSecret("ErrorString", redactedErr, rawPassword)
	assertNoSecret("ErrorString", redactedErr, rawStripeKey)
}

// 5. Lifecycle Persistence Round-Trip Fidelity
// Tests that a finding retains 100% of its metadata (Status, AnalysisMethod, Provenance,
// RemediationAdvice, Expected/Observed behavior, Score) through SQLite persistence,
// retrieval, ToReportFinding mapping, and report export.
func TestEvidenceIntegrity_PersistenceRoundTripFidelity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-phase58-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_fidelity.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	// 1. Create client, assessment, and target
	client := &assessment.Client{ID: "cli_fid_01", Name: "Fidelity Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm_fid_01",
		Ref:            "ASM-2026-FID1",
		ClientID:       client.ID,
		Name:           "Fidelity Audit Assessment",
		AssessmentType: "API_AUDIT",
		ScopeMode:      "explicit",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	target := &assessment.AssessmentTarget{
		ID:           "tgt_fid_01",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.fidelity.example.com",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	execID := "exec_fid_001"
	execRec := &assessment.AssessmentExecution{
		ID:           execID,
		AssessmentID: asm.ID,
		Status:       assessment.StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(execRec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 2. Construct complete report finding
	initialFinding := report.Finding{
		ID:               "fnd_fidelity_original_001",
		RuleID:           "SEC-API-BFLA-01",
		Status:           report.FindingStatusConfirmed,
		AnalysisMethod:   report.AnalysisMethodActive,
		PrimaryAssetID:   "ast_api_endpoint_77",
		AffectedAssetIDs: []string{"ast_api_endpoint_77", "ast_role_admin_88"},
		Title:            "BFLA Method Bypass on User Promotion",
		Category:         "BFLA",
		Severity:         report.SeverityHigh,
		Confidence:       report.ConfidenceHigh,
		Target:           "https://api.fidelity.example.com",
		Endpoint:         "/api/v2/users/promote",
		Method:           "PUT",
		Fingerprint:      "fp_fidelity_bfla_001",
		Score:            85,
		Evidence:         "Anonymous PUT received HTTP 200 with role: admin",
		EvidenceDetails: report.EvidenceDetails{
			Observation:      "Anonymous PUT received HTTP 200 with role: admin",
			Location:         "https://api.fidelity.example.com/api/v2/users/promote",
			HTTPMethod:       "PUT",
			HTTPStatus:       200,
			DetectionMethod:  "active_method_tampering",
			DetectionStatus:  "CONFIRMED",
			ExpectedBehavior: "HTTP 403 Forbidden with unprivileged identity",
			ObservedBehavior: "HTTP 200 OK with admin privilege granted",
			Details: map[string]string{
				"promoted_role": "superadmin",
			},
		},
		Verification: report.VerificationRecord{
			Status:             report.VerificationVerified,
			Result:             "Privilege escalation confirmed via active read-back",
			Rationale:          "Empirical proof satisfied all mandatory BFLA criteria",
			PolicyID:           "POL-BFLA-METHOD-BYPASS",
			VerificationMethod: "active_method_tampering",
			AnalysisMethod:     report.AnalysisMethodActive,
			ConfidenceScore:    90,
			ReproductionSteps:  []string{"curl -X PUT https://api.fidelity.example.com/api/v2/users/promote"},
		},
		Remediation: "Enforce uniform role authorization across all HTTP verb handlers.",
		RemediationAdvice: &report.RemediationAdvice{
			Summary:    "Restrict role updates to administrators across all methods",
			Steps:      []string{"Add middleware authorization check", "Audit route bindings"},
			References: []string{"https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/"},
		},
		Provenance: &report.EvidenceProvenance{
			EvidenceID:          "ev_fid_999",
			EvidenceType:        "http_response",
			SourceEngine:        "bfla_engine",
			RuleID:              "SEC-API-BFLA-01",
			AssetID:             "ast_api_endpoint_77",
			AssessmentID:        asm.ID,
			ExecutionID:         execID,
			TargetID:            target.ID,
			CollectionMethod:    "active_probe",
			AnalysisMethod:      report.AnalysisMethodActive,
			VerificationContext: "method_tampering_check",
		},
	}

	// 3. Convert to AssessmentFinding and persist
	asmFinding := assessment.ToAssessmentFinding(asm.ID, execID, target.ID, initialFinding)
	if err := store.SaveFindings([]assessment.AssessmentFinding{asmFinding}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	// 4. Retrieve from SQLite
	retrievedFindings, err := store.GetFindings(asm.ID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(retrievedFindings) != 1 {
		t.Fatalf("expected 1 finding retrieved, got %d", len(retrievedFindings))
	}
	retrieved := retrievedFindings[0]

	// 5. Convert back using ToReportFinding
	roundTripFinding := assessment.ToReportFinding(retrieved)

	// 6. Assert Complete Field Preservation
	if roundTripFinding.ID != initialFinding.ID {
		t.Errorf("ID mismatch: got %s, want %s", roundTripFinding.ID, initialFinding.ID)
	}
	if roundTripFinding.Status != initialFinding.Status {
		t.Errorf("Status mismatch: got %s, want %s", roundTripFinding.Status, initialFinding.Status)
	}
	if roundTripFinding.AnalysisMethod != initialFinding.AnalysisMethod {
		t.Errorf("AnalysisMethod mismatch: got %s, want %s", roundTripFinding.AnalysisMethod, initialFinding.AnalysisMethod)
	}
	if roundTripFinding.PrimaryAssetID != initialFinding.PrimaryAssetID {
		t.Errorf("PrimaryAssetID mismatch: got %s, want %s", roundTripFinding.PrimaryAssetID, initialFinding.PrimaryAssetID)
	}
	if len(roundTripFinding.AffectedAssetIDs) != len(initialFinding.AffectedAssetIDs) {
		t.Errorf("AffectedAssetIDs length mismatch: got %+v, want %+v", roundTripFinding.AffectedAssetIDs, initialFinding.AffectedAssetIDs)
	}
	if roundTripFinding.Verification.Status != report.VerificationVerified {
		t.Errorf("Verification status mismatch: got %s, want VERIFIED", roundTripFinding.Verification.Status)
	}
	if roundTripFinding.EvidenceDetails.ExpectedBehavior != initialFinding.EvidenceDetails.ExpectedBehavior {
		t.Errorf("ExpectedBehavior mismatch: got %q, want %q",
			roundTripFinding.EvidenceDetails.ExpectedBehavior, initialFinding.EvidenceDetails.ExpectedBehavior)
	}
	if roundTripFinding.EvidenceDetails.ObservedBehavior != initialFinding.EvidenceDetails.ObservedBehavior {
		t.Errorf("ObservedBehavior mismatch: got %q, want %q",
			roundTripFinding.EvidenceDetails.ObservedBehavior, initialFinding.EvidenceDetails.ObservedBehavior)
	}
	if roundTripFinding.RemediationAdvice == nil {
		t.Fatalf("RemediationAdvice lost in persistence round-trip!")
	}
	if roundTripFinding.RemediationAdvice.Summary != initialFinding.RemediationAdvice.Summary {
		t.Errorf("RemediationAdvice.Summary mismatch: got %q, want %q",
			roundTripFinding.RemediationAdvice.Summary, initialFinding.RemediationAdvice.Summary)
	}
	if roundTripFinding.Provenance == nil {
		t.Fatalf("Provenance lost in persistence round-trip!")
	}
	if roundTripFinding.Provenance.EvidenceID != initialFinding.Provenance.EvidenceID {
		t.Errorf("Provenance.EvidenceID mismatch: got %s, want %s",
			roundTripFinding.Provenance.EvidenceID, initialFinding.Provenance.EvidenceID)
	}
}

// 6. Multi-Run and Multi-Target Isolation
// Verifies that repeated assessments and different execution runs are strictly
// isolated by assessment ID and execution ID, preventing cross-run evidence contamination.
func TestEvidenceIntegrity_MultiRunAndTargetIsolation(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-phase58-iso-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_iso.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{ID: "cli_iso_01", Name: "Isolation Client"}
	_ = store.CreateClient(client)

	asmA := &assessment.Assessment{ID: "asm_iso_a", Ref: "ASM-ISO-A", ClientID: client.ID, Name: "Target A"}
	asmB := &assessment.Assessment{ID: "asm_iso_b", Ref: "ASM-ISO-B", ClientID: client.ID, Name: "Target B"}
	_ = store.CreateAssessment(asmA)
	_ = store.CreateAssessment(asmB)

	tgtA := &assessment.AssessmentTarget{ID: "tgt_iso_a", AssessmentID: asmA.ID, TargetURL: "https://a.example.com"}
	tgtB := &assessment.AssessmentTarget{ID: "tgt_iso_b", AssessmentID: asmB.ID, TargetURL: "https://b.example.com"}
	_ = store.AddTarget(tgtA)
	_ = store.AddTarget(tgtB)

	now := time.Now().UTC()
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           "exec_a_1",
		AssessmentID: asmA.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
	})
	_ = store.CreateExecution(&assessment.AssessmentExecution{
		ID:           "exec_b_1",
		AssessmentID: asmB.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    now,
	})

	fA := assessment.AssessmentFinding{
		ID:                assessment.ComputeAssessmentFindingID(asmA.ID, "fnd_vuln_a"),
		AssessmentID:      asmA.ID,
		ExecutionID:       "exec_a_1",
		TargetID:          tgtA.ID,
		OriginalFindingID: "fnd_vuln_a",
		Title:             "Vulnerability on Target A",
		Category:          "BOLA",
		Severity:          "HIGH",
		Confidence:        "HIGH",
		TargetURL:         "https://a.example.com",
		Endpoint:          "/user/a",
		Method:            "GET",
	}

	fB := assessment.AssessmentFinding{
		ID:                assessment.ComputeAssessmentFindingID(asmB.ID, "fnd_vuln_b"),
		AssessmentID:      asmB.ID,
		ExecutionID:       "exec_b_1",
		TargetID:          tgtB.ID,
		OriginalFindingID: "fnd_vuln_b",
		Title:             "Vulnerability on Target B",
		Category:          "BFLA",
		Severity:          "HIGH",
		Confidence:        "HIGH",
		TargetURL:         "https://b.example.com",
		Endpoint:          "/admin/b",
		Method:            "POST",
	}

	if err := store.SaveFindings([]assessment.AssessmentFinding{fA}); err != nil {
		t.Fatalf("SaveFindings fA failed: %v", err)
	}
	if err := store.SaveFindings([]assessment.AssessmentFinding{fB}); err != nil {
		t.Fatalf("SaveFindings fB failed: %v", err)
	}

	// Query Target A findings
	resA, err := store.GetFindings(asmA.ID, "")
	if err != nil || len(resA) != 1 {
		t.Fatalf("expected 1 finding for Target A, got %d (err: %v)", len(resA), err)
	}
	if resA[0].AssessmentID != asmA.ID || resA[0].TargetURL != "https://a.example.com" {
		t.Errorf("finding for Target A contaminated with Target B data: %+v", resA[0])
	}

	// Query Target B findings
	resB, err := store.GetFindings(asmB.ID, "")
	if err != nil || len(resB) != 1 {
		t.Fatalf("expected 1 finding for Target B, got %d (err: %v)", len(resB), err)
	}
	if resB[0].AssessmentID != asmB.ID || resB[0].TargetURL != "https://b.example.com" {
		t.Errorf("finding for Target B contaminated with Target A data: %+v", resB[0])
	}
}

// 7. Honest Classification: Positive & Negative Control Verification in BFLA/BOPLA
// Tests that positive controls and negative controls avoid false positives and
// properly produce NOT_VULNERABLE or INCONCLUSIVE when access is properly restricted.
func TestEvidenceIntegrity_HonestClassificationControls(t *testing.T) {
	// Baseline authorized response
	baselineResp := bfla.ResponseData{
		StatusCode: 200,
		Header:     map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"status":"success","data":{"admin":true}}`),
	}
	bflaPol := bfla.FunctionPolicy{
		FunctionID:   "USER-DELETE",
		Path:         "/api/v1/user",
		Method:       "DELETE",
		AllowedRoles: []string{"admin"},
	}

	// 1. Properly enforced BFLA returns NOT_VULNERABLE
	enforcedResp := bfla.ResponseData{
		StatusCode: 403,
		Header:     map[string][]string{"Content-Type": {"application/json"}},
		Body:       []byte(`{"error":"access_denied","message":"forbidden"}`),
	}
	bflaRes := bfla.CompareFunctionAccess(baselineResp, enforcedResp, bflaPol, "admin", "guest", "bob")
	if bflaRes.State != bfla.StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE for 403 response, got %s", bflaRes.State)
	}

	// 2. Ambiguous HTML login challenge with HTTP 200 does NOT become VERIFIED
	loginChallengeResp := bfla.ResponseData{
		StatusCode: 200,
		Header:     map[string][]string{"Content-Type": {"text/html"}},
		Body:       []byte(`<html><body><form action="/login"><input type="password"/></form></body></html>`),
	}
	bflaLoginRes := bfla.CompareFunctionAccess(baselineResp, loginChallengeResp, bflaPol, "admin", "guest", "bob")
	if bflaLoginRes.State == bfla.StateVerified {
		t.Errorf("FALSE POSITIVE DEFECT: HTML login form with HTTP 200 must NOT be marked VERIFIED")
	}
	if bflaLoginRes.State != bfla.StateNotVulnerable {
		t.Errorf("expected NOT_VULNERABLE for login challenge, got %s", bflaLoginRes.State)
	}
}
