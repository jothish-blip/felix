package assessment

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"felix/pkg/report"
	"felix/pkg/verification"
)

func TestStore_AnalysisMethodAndHonestStatusPersistence(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_analysis_method.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	defer store.Close()

	asmID := "asm-" + uuid.New().String()
	execID := "exec-" + uuid.New().String()
	targetID := "tgt-" + uuid.New().String()

	clientID := uuid.New().String()
	client := &Client{
		ID:   clientID,
		Name: "Test Client",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &Assessment{
		ID:        asmID,
		Ref:       "ASM-2026-TEST",
		ClientID:  clientID,
		Name:      "Analysis Method Test Project",
		Status:    StatusDraft,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	target := &AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	findings := []AssessmentFinding{
		{
			ID:                 "fnd_static_suspected",
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  "FND-01",
			RuleID:             "SEC-JWT",
			Status:             report.FindingStatusSuspected,
			AnalysisMethod:     report.AnalysisMethodStatic,
			Title:              "Suspected Hardcoded Secret",
			Category:           "SECRETS",
			Severity:           report.SeverityHigh,
			Confidence:         report.ConfidenceHigh,
			VerificationStatus: report.VerificationNotVerified,
			TargetURL:          "https://example.com",
			Endpoint:           "https://example.com/bundle.js",
			Method:             "GET",
			Score:              75,
			EvidenceDetails: report.EvidenceDetails{
				Observation:     "Pattern match for JWT",
				DetectionMethod: "static_pattern_analysis",
			},
			VerificationRecord: report.VerificationRecord{
				Status:         report.VerificationNotVerified,
				AnalysisMethod: report.AnalysisMethodStatic,
				Result:         "Live test avoided for safety",
			},
		},
		{
			ID:                 "fnd_active_confirmed",
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  "FND-02",
			RuleID:             "API-ENV",
			Status:             report.FindingStatusConfirmed,
			AnalysisMethod:     report.AnalysisMethodActive,
			Title:              "Active Env File Exposure",
			Category:           "EXPOSURE",
			Severity:           report.SeverityCritical,
			Confidence:         report.ConfidenceHigh,
			VerificationStatus: report.VerificationVerified,
			TargetURL:          "https://example.com",
			Endpoint:           "https://example.com/.env",
			Method:             "GET",
			Score:              95,
			EvidenceDetails: report.EvidenceDetails{
				Observation:     "Unauthenticated 200 with credentials",
				DetectionMethod: "active_probe",
			},
			VerificationRecord: report.VerificationRecord{
				Status:         report.VerificationVerified,
				AnalysisMethod: report.AnalysisMethodActive,
				Result:         "Verified through active HTTP probe",
			},
		},
		{
			ID:                 "fnd_not_tested_blocked",
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  "FND-03",
			RuleID:             "API-BOLA",
			Status:             report.FindingStatusNotTested,
			AnalysisMethod:     report.AnalysisMethodStatic,
			Title:              "Candidate Outside Scope",
			Category:           "BOLA",
			Severity:           report.SeverityMedium,
			Confidence:         report.ConfidenceHigh,
			VerificationStatus: report.VerificationNotVerified,
			TargetURL:          "https://thirdparty.org",
			Endpoint:           "https://thirdparty.org/api/data",
			Method:             "GET",
			Score:              50,
			EvidenceDetails: report.EvidenceDetails{
				Observation:     "Candidate endpoint observed in script",
				DetectionMethod: "static_analysis",
			},
			VerificationRecord: report.VerificationRecord{
				Status:         report.VerificationNotVerified,
				AnalysisMethod: report.AnalysisMethodStatic,
				Result:         "Blocked by safety controls",
			},
		},
		{
			ID:                 "fnd_error",
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  "FND-04",
			RuleID:             "API-PROBE",
			Status:             report.FindingStatusError,
			AnalysisMethod:     report.AnalysisMethodActive,
			Title:              "Verification Probe Execution Error",
			Category:           "API",
			Severity:           report.SeverityMedium,
			Confidence:         report.ConfidenceMedium,
			VerificationStatus: report.VerificationNotVerified,
			TargetURL:          "https://example.com",
			Endpoint:           "https://example.com/api/test",
			Method:             "POST",
			Score:              40,
			EvidenceDetails: report.EvidenceDetails{
				Observation:     "Request timed out",
				DetectionMethod: "active_probe",
			},
			VerificationRecord: report.VerificationRecord{
				Status:         report.VerificationNotVerified,
				AnalysisMethod: report.AnalysisMethodActive,
				Result:         "Connection timeout during probe",
			},
		},
	}

	if err := store.SaveFindings(findings); err != nil {
		t.Fatalf("failed to save findings: %v", err)
	}

	fetched, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("failed to get findings: %v", err)
	}
	if len(fetched) != 4 {
		t.Fatalf("expected 4 findings, got %d", len(fetched))
	}

	fetchedMap := make(map[string]AssessmentFinding)
	for _, f := range fetched {
		fetchedMap[f.ID] = f
	}

	// 1. Check static suspected finding
	f1 := fetchedMap["fnd_static_suspected"]
	if f1.Status != report.FindingStatusSuspected {
		t.Errorf("f1 status mismatch: got %s, want SUSPECTED", f1.Status)
	}
	if f1.AnalysisMethod != report.AnalysisMethodStatic {
		t.Errorf("f1 analysis_method mismatch: got %s, want STATIC_ANALYSIS", f1.AnalysisMethod)
	}

	// 2. Check active confirmed finding
	f2 := fetchedMap["fnd_active_confirmed"]
	if f2.Status != report.FindingStatusConfirmed {
		t.Errorf("f2 status mismatch: got %s, want CONFIRMED", f2.Status)
	}
	if f2.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("f2 analysis_method mismatch: got %s, want ACTIVE_VERIFICATION", f2.AnalysisMethod)
	}

	// 3. Check not tested blocked finding
	f3 := fetchedMap["fnd_not_tested_blocked"]
	if f3.Status != report.FindingStatusNotTested {
		t.Errorf("f3 status mismatch: got %s, want NOT_TESTED", f3.Status)
	}
	if f3.AnalysisMethod != report.AnalysisMethodStatic {
		t.Errorf("f3 analysis_method mismatch: got %s, want STATIC_ANALYSIS", f3.AnalysisMethod)
	}

	// 4. Check error finding
	f4 := fetchedMap["fnd_error"]
	if f4.Status != report.FindingStatusError {
		t.Errorf("f4 status mismatch: got %s, want ERROR", f4.Status)
	}
	if f4.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("f4 analysis_method mismatch: got %s, want ACTIVE_VERIFICATION", f4.AnalysisMethod)
	}
}

func TestController_ScopeEnforcementOnActiveVerification(t *testing.T) {
	ctx := context.Background()

	// Assessment scope: example.com allowed, forbidden.org and admin excluded
	scopeRules := []ScopeRule{
		{RuleType: "HOSTNAME", Pattern: "example.com"},
	}
	exclusions := []Exclusion{
		{ExclusionType: "HOSTNAME", Pattern: "forbidden.org"},
		{ExclusionType: "PATH_PREFIX", Pattern: "/admin/restricted"},
	}
	scopeVal := NewScopeValidator("same-origin", []string{"https://example.com"}, scopeRules, exclusions)

	safetyChecker := verification.NewSafetyChecker(verification.SafetyOptions{
		IsAuthorized:       true,
		AllowStateChanging: false,
		InScopeFunc: func(rawURL string) bool {
			return scopeVal.IsAllowed(rawURL)
		},
		IsExcludedFunc: func(rawURL string) bool {
			excluded, _ := scopeVal.IsExcluded(rawURL)
			return excluded
		},
	})
	engine := verification.NewEngine(safetyChecker)

	candidateFindings := []report.Finding{
		// 1. Allowed in-scope endpoint
		{
			ID:          "FND-IN-SCOPE",
			RuleID:      "API-ENV",
			Title:       "Exposed Environment File",
			Category:    "EXPOSURE",
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
			Target:      "https://example.com",
			Endpoint:    "https://example.com/.env",
			Method:      "GET",
			Evidence:    "DB_PASSWORD=Secret123",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		// 2. Excluded path endpoint
		{
			ID:             "FND-EXCLUDED",
			RuleID:         "API-ADMIN",
			Title:          "Admin Panel Candidate",
			Category:       "EXPOSURE",
			Severity:       report.SeverityHigh,
			Confidence:     report.ConfidenceHigh,
			AnalysisMethod: report.AnalysisMethodStatic,
			Target:         "https://example.com",
			Endpoint:       "https://example.com/admin/restricted/config",
			Method:         "GET",
		},
		// 3. Out of scope host endpoint
		{
			ID:             "FND-OUT-OF-SCOPE",
			RuleID:         "API-EXTERNAL",
			Title:          "Third Party Exposure",
			Category:       "EXPOSURE",
			Severity:       report.SeverityHigh,
			Confidence:     report.ConfidenceHigh,
			AnalysisMethod: report.AnalysisMethodStatic,
			Target:         "https://thirdparty.org",
			Endpoint:       "https://thirdparty.org/.env",
			Method:         "GET",
		},
	}

	results, _ := engine.VerifyFindings(ctx, candidateFindings)
	updated := verification.ApplyVerificationToFindings(candidateFindings, results)

	updatedMap := make(map[string]report.Finding)
	for _, f := range updated {
		updatedMap[f.ID] = f
	}

	// 1. In-scope finding: actively verified -> CONFIRMED + ACTIVE_VERIFICATION
	inScope := updatedMap["FND-IN-SCOPE"]
	if inScope.Status != report.FindingStatusConfirmed {
		t.Errorf("in-scope finding expected CONFIRMED, got %s", inScope.Status)
	}
	if inScope.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("in-scope finding expected ACTIVE_VERIFICATION, got %s", inScope.AnalysisMethod)
	}

	// 2. Excluded finding: blocked by scope -> NOT_TESTED, confidence preserved
	excluded := updatedMap["FND-EXCLUDED"]
	if excluded.Status != report.FindingStatusNotTested {
		t.Errorf("excluded finding expected NOT_TESTED, got %s", excluded.Status)
	}
	if excluded.Confidence != report.ConfidenceHigh {
		t.Errorf("excluded finding confidence should remain HIGH, got %s", excluded.Confidence)
	}

	// 3. Out of scope finding: blocked by scope -> NOT_TESTED, confidence preserved
	outOfScope := updatedMap["FND-OUT-OF-SCOPE"]
	if outOfScope.Status != report.FindingStatusNotTested {
		t.Errorf("out-of-scope finding expected NOT_TESTED, got %s", outOfScope.Status)
	}
	if outOfScope.Confidence != report.ConfidenceHigh {
		t.Errorf("out-of-scope finding confidence should remain HIGH, got %s", outOfScope.Confidence)
	}
}

func TestToAssessmentFinding_CrossEngineNormalization(t *testing.T) {
	asmID := "asm-test-norm"
	execID := "exec-test-norm"
	tgtID := "tgt-test-norm"

	// Finding from sessionsec without explicit AnalysisMethod or Status
	rawSession := report.Finding{
		ID:       "fnd-session-01",
		Title:    "Weak Session Entropy",
		Category: "SESSION_SECURITY",
		Source:   "session_identity_engine",
		Target:   "https://example.com",
		Endpoint: "https://example.com/api/session",
		Method:   "GET",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	af := ToAssessmentFinding(asmID, execID, tgtID, rawSession)
	if af.Status != report.FindingStatusConfirmed {
		t.Errorf("expected Status CONFIRMED, got %s", af.Status)
	}
	if af.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected AnalysisMethod ACTIVE_VERIFICATION, got %s", af.AnalysisMethod)
	}

	// Finding from businesslogic without explicit AnalysisMethod or Status
	rawBiz := report.Finding{
		ID:       "fnd-biz-01",
		Title:    "Workflow Replay Flaw",
		Category: "BUSINESS_LOGIC",
		Source:   "business_logic_security_engine",
		Target:   "https://example.com",
		Endpoint: "https://example.com/checkout",
		Method:   "POST",
		Verification: report.VerificationRecord{
			Status: report.VerificationDetected,
		},
	}

	afBiz := ToAssessmentFinding(asmID, execID, tgtID, rawBiz)
	if afBiz.Status != report.FindingStatusSuspected {
		t.Errorf("expected Status SUSPECTED, got %s", afBiz.Status)
	}
	if afBiz.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected AnalysisMethod ACTIVE_VERIFICATION, got %s", afBiz.AnalysisMethod)
	}
}
