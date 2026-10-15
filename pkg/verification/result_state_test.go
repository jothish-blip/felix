package verification

import (
	"context"
	"errors"
	"testing"

	"felix/pkg/report"
)

type dummyErrorPolicy struct {
	id string
}

func (p *dummyErrorPolicy) ID() string                      { return p.id }
func (p *dummyErrorPolicy) Version() string                 { return "1.0.0" }
func (p *dummyErrorPolicy) Name() string                    { return "Dummy Error Policy" }
func (p *dummyErrorPolicy) Description() string             { return "Tests error handling" }
func (p *dummyErrorPolicy) AppliesTo(f report.Finding) bool { return true }
func (p *dummyErrorPolicy) Verify(ctx context.Context, f report.Finding, safety *SafetyChecker) (VerificationResult, error) {
	return VerificationResult{}, errors.New("simulated network connection reset by peer")
}

func TestVerificationEngine_HonestResultStateMapping(t *testing.T) {
	safety := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		InScopeFunc:          func(s string) bool { return true },
		MaxRequestsPerTarget: 50,
	})
	engine := NewEngine(safety)
	ctx := context.Background()

	// 1. Confirmed outcome: Public .env exposure with live content verified
	fEnv := report.Finding{
		ID:             "FND-03",
		Title:          "Public Environment File (.env)",
		Category:       "EXPOSURE",
		Target:         "https://example.com",
		Endpoint:       "https://example.com/.env",
		Evidence:       "DB_PASSWORD=SuperSecretPass123\nAWS_SECRET=secret456",
		Confidence:     report.ConfidenceHigh,
		Severity:       report.SeverityCritical,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 200,
		},
	}

	resEnv := engine.VerifyFinding(ctx, fEnv)
	if resEnv.FindingStatus != report.FindingStatusConfirmed {
		t.Errorf("expected FindingStatusConfirmed for verified env file, got %s", resEnv.FindingStatus)
	}

	// 2. Inconclusive outcome: Specifically tested unauthenticated bypass disproved (NOT_EXPOSED)
	fProtected := report.Finding{
		ID:             "FND-04",
		Title:          "Unauthenticated Access Bypass on Admin Endpoint",
		Category:       "AUTH",
		Target:         "https://example.com",
		Endpoint:       "https://example.com/admin/settings",
		Confidence:     report.ConfidenceHigh,
		Severity:       report.SeverityHigh,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus:       401,
			Observation:      "Access denied by authentication",
			NegativeEvidence: "Direct unauthenticated request to /admin/settings returned HTTP 401 Unauthorized",
			Details: map[string]string{
				"unauth_bypass_tested": "true",
				"caller_identity":      "anonymous",
			},
		},
	}

	resProtected := engine.VerifyFinding(ctx, fProtected)
	if resProtected.FindingStatus != report.FindingStatusInconclusive {
		t.Errorf("expected FindingStatusInconclusive for protected outcome, got %s", resProtected.FindingStatus)
	}

	// 3. Not Tested outcome: Blocked by safety checker
	strictSafety := NewSafetyChecker(SafetyOptions{
		IsAuthorized: false,
	})
	strictEngine := NewEngine(strictSafety)

	fInternal := report.Finding{
		ID:             "FND-SSRF-INTERNAL",
		Category:       "ssrf",
		Target:         "http://169.254.169.254",
		Endpoint:       "http://169.254.169.254/latest/meta-data/",
		Method:         "GET",
		Confidence:     report.ConfidenceHigh,
		Severity:       report.SeverityCritical,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
	}

	resBlocked := strictEngine.VerifyFinding(ctx, fInternal)
	if resBlocked.FindingStatus != report.FindingStatusNotTested {
		t.Errorf("expected FindingStatusNotTested for safety-blocked probe, got %s", resBlocked.FindingStatus)
	}

	// 4. Error outcome: Execution failure fail-safe
	errorRegistry := NewDefaultRegistry()
	errorRegistry.Register(&dummyErrorPolicy{id: "POL-ERR-01"})
	engineWithError := &Engine{
		registry: errorRegistry,
		safety:   safety,
		version:  "2.0.0",
	}

	fError := report.Finding{
		ID:             "FND-ERR-01",
		Category:       "unknown-error-cat",
		Target:         "https://example.com",
		Endpoint:       "https://example.com/err",
		Method:         "GET",
		Confidence:     report.ConfidenceMedium,
		Severity:       report.SeverityMedium,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
	}

	resErr := engineWithError.VerifyFinding(ctx, fError)
	if resErr.FailureReason == "" {
		t.Errorf("expected failure reason on error result")
	}

	updated := ApplyVerificationToFindings([]report.Finding{fError}, []VerificationResult{resErr})
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated finding")
	}
	if updated[0].Status != report.FindingStatusError {
		t.Errorf("expected FindingStatusError on failure, got %s", updated[0].Status)
	}
}

func TestVerificationEngine_SkippedChecksCannotBecomeConfirmed(t *testing.T) {
	strictSafety := NewSafetyChecker(SafetyOptions{
		IsAuthorized: false,
	})
	engine := NewEngine(strictSafety)
	ctx := context.Background()

	// Prohibited AWS metadata destination
	fMetadata := report.Finding{
		ID:             "FND-METADATA",
		Category:       "cloud-metadata",
		Target:         "http://169.254.169.254",
		Endpoint:       "http://169.254.169.254/latest/meta-data/",
		Method:         "GET",
		Confidence:     report.ConfidenceHigh,
		Severity:       report.SeverityCritical,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
	}

	res := engine.VerifyFinding(ctx, fMetadata)
	if res.FindingStatus == report.FindingStatusConfirmed {
		t.Fatalf("CRITICAL DEFECT: blocked check was marked as CONFIRMED")
	}
	if res.FindingStatus != report.FindingStatusNotTested {
		t.Errorf("expected FindingStatusNotTested for blocked metadata check, got %s", res.FindingStatus)
	}

	updated := ApplyVerificationToFindings([]report.Finding{fMetadata}, []VerificationResult{res})
	if updated[0].Status == report.FindingStatusConfirmed {
		t.Fatalf("CRITICAL DEFECT: ApplyVerificationToFindings marked blocked check as CONFIRMED")
	}
	if updated[0].Status != report.FindingStatusNotTested {
		t.Errorf("expected finding status NOT_TESTED, got %s", updated[0].Status)
	}
}

func TestVerificationEngine_ErrorsCannotBecomeNegative(t *testing.T) {
	safety := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		MaxRequestsPerTarget: 50,
	})
	errorRegistry := NewDefaultRegistry()
	errorRegistry.Register(&dummyErrorPolicy{id: "POL-ERR-NET"})
	engineWithError := &Engine{
		registry: errorRegistry,
		safety:   safety,
		version:  "2.0.0",
	}

	f := report.Finding{
		ID:             "FND-NET-TIMEOUT",
		Category:       "timeout-cat",
		Target:         "https://example.com",
		Endpoint:       "https://example.com/hang",
		Method:         "GET",
		Confidence:     report.ConfidenceHigh,
		Severity:       report.SeverityHigh,
		Status:         report.FindingStatusSuspected,
		AnalysisMethod: report.AnalysisMethodStatic,
	}

	res := engineWithError.VerifyFinding(context.Background(), f)
	if res.Status == StatusNotExposed {
		t.Fatalf("CRITICAL DEFECT: network error was classified as NOT_EXPOSED (false negative)")
	}
	if res.Status == StatusVerified {
		t.Fatalf("CRITICAL DEFECT: network error was classified as VERIFIED")
	}
	if res.FindingStatus != report.FindingStatusError {
		t.Errorf("expected FindingStatusError directly on VerificationResult, got %s", res.FindingStatus)
	}

	updated := ApplyVerificationToFindings([]report.Finding{f}, []VerificationResult{res})
	if updated[0].Status != report.FindingStatusError {
		t.Errorf("expected finding status ERROR, got %s", updated[0].Status)
	}
	if updated[0].Status == report.FindingStatusConfirmed || updated[0].Status == report.FindingStatusSuspected {
		t.Errorf("CRITICAL DEFECT: execution error was promoted to a security vulnerability")
	}
}
