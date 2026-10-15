package verification

import (
	"context"
	"strings"
	"testing"
	"time"

	"felix/pkg/report"
)

func TestActiveVerification_ConfirmedSucceeds(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	// Direct empirical evidence: sensitive env file with keys
	f := report.Finding{
		ID:          "FND-ACTIVE-01",
		RuleID:      "API-ENV-EXPOSURE",
		Title:       "Public Environment Configuration File",
		Category:    "EXPOSURE",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Description: "Sensitive .env file is publicly accessible",
		Evidence:    "DB_PASSWORD=Secret123\nAWS_SECRET=xyz789",
		EvidenceDetails: report.EvidenceDetails{
			Observation:     "Unauthenticated GET to /.env returned HTTP 200 with credentials",
			Location:        "https://example.com/.env",
			HTTPMethod:      "GET",
			HTTPStatus:      200,
			DetectionMethod: "active_probe",
		},
		Source: report.SourceAPI,
	}

	res := engine.VerifyFinding(ctx, f)
	if res.Status != StatusVerified {
		t.Fatalf("expected StatusVerified, got %s", res.Status)
	}
	if res.FindingStatus != report.FindingStatusConfirmed {
		t.Errorf("expected FindingStatusConfirmed on VerificationResult, got %s", res.FindingStatus)
	}
	if res.AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected AnalysisMethodActive, got %s", res.AnalysisMethod)
	}

	updated := ApplyVerificationToFindings([]report.Finding{f}, []VerificationResult{res})
	if len(updated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(updated))
	}
	if updated[0].Status != report.FindingStatusConfirmed {
		t.Errorf("expected finding status CONFIRMED, got %s", updated[0].Status)
	}
	if updated[0].AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected finding AnalysisMethod ACTIVE_VERIFICATION, got %s", updated[0].AnalysisMethod)
	}
	if updated[0].Verification.Status != report.VerificationVerified {
		t.Errorf("expected verification status VERIFIED, got %s", updated[0].Verification.Status)
	}
}

func TestActiveVerification_InconclusiveAccessDenied(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	f := report.Finding{
		ID:          "FND-ACTIVE-02",
		RuleID:      "AUTH-ADMIN-EXPOSURE",
		Title:       "Public Unauthenticated Access on Admin Settings",
		Category:    "AUTH",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      "https://example.com",
		Endpoint:    "https://example.com/admin/settings",
		Method:      "GET",
		Description: "Admin settings tested for unauthenticated exposure",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus:       401,
			Observation:      "Access denied by authentication",
			NegativeEvidence: "Direct unauthenticated probe to /admin/settings returned HTTP 401 Unauthorized",
			Details: map[string]string{
				"negative_proof":  "true",
				"caller_identity": "anonymous",
			},
		},
		Source: report.SourceAPI,
	}

	res := engine.VerifyFinding(ctx, f)
	if res.Status != StatusNotExposed {
		t.Fatalf("expected StatusNotExposed, got %s", res.Status)
	}
	if res.FindingStatus != report.FindingStatusInconclusive {
		t.Errorf("expected FindingStatusInconclusive on VerificationResult, got %s", res.FindingStatus)
	}

	updated := ApplyVerificationToFindings([]report.Finding{f}, []VerificationResult{res})
	if len(updated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(updated))
	}
	if updated[0].Status != report.FindingStatusInconclusive {
		t.Errorf("expected finding status INCONCLUSIVE, got %s", updated[0].Status)
	}
	if updated[0].AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected finding AnalysisMethod ACTIVE_VERIFICATION, got %s", updated[0].AnalysisMethod)
	}
	if updated[0].Verification.Status != report.VerificationNotExposed {
		t.Errorf("expected verification status NOT_EXPOSED, got %s", updated[0].Verification.Status)
	}
}

func TestActiveVerification_NotTestedSafetyBlock(t *testing.T) {
	ctx := context.Background()
	// Unauthorized checker: all active probes must be blocked
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: false,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	f := report.Finding{
		ID:             "FND-ACTIVE-03",
		RuleID:         "API-BOLA",
		Title:          "BOLA Exposure Candidate",
		Category:       "BOLA",
		Severity:       report.SeverityHigh,
		Confidence:     report.ConfidenceHigh, // High detection confidence
		AnalysisMethod: report.AnalysisMethodStatic,
		Target:         "https://example.com",
		Endpoint:       "https://example.com/api/users/2",
		Method:         "GET",
		Source:         report.SourceAPI,
	}

	res := engine.VerifyFinding(ctx, f)
	if res.SafetyDecision != DecisionBlocked {
		t.Fatalf("expected DecisionBlocked, got %s", res.SafetyDecision)
	}
	if res.FindingStatus != report.FindingStatusNotTested {
		t.Errorf("expected FindingStatusNotTested, got %s", res.FindingStatus)
	}

	updated := ApplyVerificationToFindings([]report.Finding{f}, []VerificationResult{res})
	if len(updated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(updated))
	}
	if updated[0].Status != report.FindingStatusNotTested {
		t.Errorf("expected finding status NOT_TESTED, got %s", updated[0].Status)
	}
	// Detection confidence MUST NOT be downgraded upon verification block
	if updated[0].Confidence != report.ConfidenceHigh {
		t.Errorf("expected finding confidence to remain HIGH, got %s", updated[0].Confidence)
	}
}

func TestActiveVerification_ExecutionError(t *testing.T) {
	f := report.Finding{
		ID:             "FND-ERR-01",
		RuleID:         "RULE-TIMEOUT",
		Title:          "Vulnerability Check Error",
		Category:       "API",
		Severity:       report.SeverityMedium,
		Confidence:     report.ConfidenceMedium,
		Target:         "https://example.com",
		Endpoint:       "https://example.com/api/test",
		Method:         "GET",
		AnalysisMethod: report.AnalysisMethodActive,
	}

	// Simulated runtime execution failure during active check
	res := VerificationResult{
		FindingID:           f.ID,
		TargetURL:           f.Target,
		Endpoint:            f.Endpoint,
		Status:              StatusNotVerified,
		Attempted:           true,
		FailureReason:       "dial tcp 192.0.2.1:443: i/o timeout during payload transmission",
		VerificationMethod:  "active_probe",
		OverallConfidence:   report.ConfidenceMedium,
		DetectionConfidence: report.ConfidenceMedium,
	}

	updated := ApplyVerificationToFindings([]report.Finding{f}, []VerificationResult{res})
	if len(updated) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(updated))
	}
	if updated[0].Status != report.FindingStatusError {
		t.Errorf("expected finding status ERROR on execution failure, got %s", updated[0].Status)
	}
	if updated[0].AnalysisMethod != report.AnalysisMethodActive {
		t.Errorf("expected AnalysisMethod ACTIVE_VERIFICATION, got %s", updated[0].AnalysisMethod)
	}
	if !strings.Contains(updated[0].Verification.Result, "i/o timeout") {
		t.Errorf("expected verification result to capture failure reason, got %s", updated[0].Verification.Result)
	}
}

func TestVerification_ConfidenceIndependence(t *testing.T) {
	ctx := context.Background()

	// 1. High confidence static secret finding: live verification skipped for safety
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	fSecret := report.Finding{
		ID:             "FND-CONF-01",
		RuleID:         "SEC-AWS-KEY",
		Title:          "AWS Access Key Detected in Client Asset",
		Category:       "SECRETS",
		Severity:       report.SeverityHigh,
		Confidence:     report.ConfidenceHigh, // Certain pattern match
		AnalysisMethod: report.AnalysisMethodStatic,
		Target:         "https://example.com",
		Endpoint:       "https://example.com/assets/app.js",
		Source:         report.SourceSecrets,
		Evidence:       "AKIAIOSFODNN7EXAMPLE",
		Verification:   report.VerificationRecord{Status: report.VerificationNotVerified},
	}

	resSecret := engine.VerifyFinding(ctx, fSecret)
	updatedSecret := ApplyVerificationToFindings([]report.Finding{fSecret}, []VerificationResult{resSecret})
	if len(updatedSecret) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(updatedSecret))
	}

	// Status is NOT_TESTED (live credential testing skipped for safety)
	if updatedSecret[0].Status != report.FindingStatusNotTested {
		t.Errorf("expected finding status NOT_TESTED for skipped live check, got %s", updatedSecret[0].Status)
	}
	// High confidence in the indicator presence is preserved
	if updatedSecret[0].Confidence != report.ConfidenceHigh {
		t.Errorf("expected indicator confidence to remain HIGH, got %s", updatedSecret[0].Confidence)
	}

	// 2. Medium confidence finding confirmed via active probe
	fPartial := report.Finding{
		ID:          "FND-CONF-02",
		RuleID:      "API-ENV",
		Title:       "Exposed Configuration File",
		Category:    "EXPOSURE",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceMedium, // Partial heuristic
		Target:      "https://example.com",
		Endpoint:    "https://example.com/.env",
		Method:      "GET",
		Description: "Sensitive .env file is accessible",
		Evidence:    "DB_PASSWORD=Secret123",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 200,
		},
		Source: report.SourceAPI,
	}

	resPartial := engine.VerifyFinding(ctx, fPartial)
	if resPartial.Status != StatusVerified {
		t.Fatalf("expected StatusVerified, got %s", resPartial.Status)
	}
	updatedPartial := ApplyVerificationToFindings([]report.Finding{fPartial}, []VerificationResult{resPartial})
	if updatedPartial[0].Status != report.FindingStatusConfirmed {
		t.Errorf("expected finding status CONFIRMED, got %s", updatedPartial[0].Status)
	}
}

func TestVerification_ScopeEnforcementIntegration(t *testing.T) {
	ctx := context.Background()

	// Scope validator logic: allow example.com, exclude forbidden.org and *.internal
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc: func(url string) bool {
			return strings.Contains(url, "example.com")
		},
		IsExcludedFunc: func(url string) bool {
			return strings.Contains(url, "forbidden.org") || strings.Contains(url, "internal")
		},
	})
	engine := NewEngine(checker)

	// Target 1: Out of scope target
	fOutOfScope := report.Finding{
		ID:       "FND-SCOPE-01",
		RuleID:   "API-TEST",
		Title:    "Out of Scope Target Probe",
		Category: "EXPOSURE",
		Target:   "https://thirdparty.net",
		Endpoint: "https://thirdparty.net/.env",
	}

	res1 := engine.VerifyFinding(ctx, fOutOfScope)
	if res1.SafetyDecision != DecisionBlocked {
		t.Errorf("expected DecisionBlocked for out-of-scope URL, got %s", res1.SafetyDecision)
	}
	if !strings.Contains(res1.BlockReason, "outside authorized") {
		t.Errorf("expected out-of-scope block reason, got %s", res1.BlockReason)
	}

	// Target 2: Explicitly excluded hostname
	fExcluded := report.Finding{
		ID:       "FND-SCOPE-02",
		RuleID:   "API-TEST",
		Title:    "Excluded Target Probe",
		Category: "EXPOSURE",
		Target:   "https://forbidden.org",
		Endpoint: "https://forbidden.org/admin",
	}

	res2 := engine.VerifyFinding(ctx, fExcluded)
	if res2.SafetyDecision != DecisionBlocked {
		t.Errorf("expected DecisionBlocked for excluded target, got %s", res2.SafetyDecision)
	}

	// Target 3: Allowed in-scope target
	fAllowed := report.Finding{
		ID:       "FND-SCOPE-03",
		RuleID:   "API-TEST",
		Title:    "Allowed In-Scope Probe",
		Category: "EXPOSURE",
		Target:   "https://example.com",
		Endpoint: "https://example.com/.env",
		Evidence: "DB_PASSWORD=Secret123",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 200,
		},
	}

	res3 := engine.VerifyFinding(ctx, fAllowed)
	if res3.SafetyDecision != DecisionAllowed {
		t.Errorf("expected DecisionAllowed for in-scope target, got %s (block reason: %s)", res3.SafetyDecision, res3.BlockReason)
	}
	if res3.Status != StatusVerified {
		t.Errorf("expected StatusVerified for valid in-scope check, got %s", res3.Status)
	}
}

// Ensure unused import time doesn't cause compilation issues if removed
var _ = time.Now
