package verification

import (
	"context"
	"strings"
	"testing"

	"felix/pkg/report"
)

func TestVerification_StatusCorrectnessAllFiveStatuses(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	tests := []struct {
		name           string
		finding        report.Finding
		expectedStatus report.VerificationStatus
	}{
		{
			name: "Observed: Discovered web asset without vulnerability claim",
			finding: report.Finding{
				ID:       "FND-01",
				Title:    "Endpoint Discovered",
				Category: "RECON",
				Target:   "https://example.com",
				Endpoint: "https://example.com/api/v1/health",
				Source:   report.SourceCrawler,
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus: 200,
				},
			},
			expectedStatus: StatusObserved,
		},
		{
			name: "Not Verified: Secret pattern in client code (live test avoided for safety)",
			finding: report.Finding{
				ID:         "FND-02",
				Title:      "AWS Access Key ID Detected",
				Category:   "SECRETS",
				Confidence: report.ConfidenceHigh,
				Target:     "https://example.com",
				Endpoint:   "https://example.com/main.js",
				Source:     report.SourceSecrets,
				Evidence:   "AKIAIOSFODNN7EXAMPLE",
			},
			expectedStatus: StatusNotVerified,
		},
		{
			name: "Verified: Sensitive .env configuration exposure with live content",
			finding: report.Finding{
				ID:       "FND-03",
				Title:    "Public Environment File (.env)",
				Category: "EXPOSURE",
				Target:   "https://example.com",
				Endpoint: "https://example.com/.env",
				Evidence: "DB_PASSWORD=SuperSecretPass123\nAWS_SECRET=secret456",
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus: 200,
				},
			},
			expectedStatus: StatusVerified,
		},
		{
			name: "Not Exposed: Access denied by authorization boundary (HTTP 401)",
			finding: report.Finding{
				ID:       "FND-04",
				Title:    "Protected Admin Endpoint",
				Category: "AUTH",
				Target:   "https://example.com",
				Endpoint: "https://example.com/admin/settings",
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus:  401,
					Observation: "Access denied by authentication",
				},
			},
			expectedStatus: StatusNotExposed,
		},
		{
			name: "Detected -> Not Verified: BOLA claimed without differential tenant proof",
			finding: report.Finding{
				ID:         "FND-05",
				Title:      "BOLA Candidate",
				Category:   "BOLA",
				Confidence: report.ConfidenceHigh, // High detection confidence
				Target:     "https://example.com",
				Endpoint:   "https://example.com/api/users/1",
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus: 200, // Generic 200 alone without cross-tenant proof
				},
			},
			expectedStatus: StatusNotVerified,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := engine.VerifyFinding(ctx, tc.finding)
			if res.Status != tc.expectedStatus {
				t.Fatalf("expected status %s, got %s (failure: %s, inconclusive: %s)",
					tc.expectedStatus, res.Status, res.FailureReason, res.InconclusiveReason)
			}
		})
	}
}

func TestVerification_ProofRequirementsInvariants(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	t.Run("Detector match alone cannot produce VERIFIED", func(t *testing.T) {
		f := report.Finding{
			ID:         "FND-XSS-01",
			Title:      "Cross-Site Scripting (XSS)",
			Category:   "XSS",
			Confidence: report.ConfidenceHigh,
			Target:     "https://example.com",
			Endpoint:   "https://example.com/search?q=test",
			Evidence:   "Searched for: test", // Reflected string only, no unescaped context
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusVerified {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: reflection alone produced VERIFIED status!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})

	t.Run("Generic HTTP 200 cannot produce VERIFIED for BOLA", func(t *testing.T) {
		f := report.Finding{
			ID:         "FND-BOLA-01",
			Title:      "Broken Object Level Authorization",
			Category:   "BOLA",
			Confidence: report.ConfidenceHigh,
			Target:     "https://example.com",
			Endpoint:   "https://example.com/api/v1/orders/123",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200, // Just HTTP 200, no differential tenant comparison
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusVerified {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: generic HTTP 200 without comparative tenant proof produced VERIFIED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})

	t.Run("Generic 500 error alone cannot produce VERIFIED for SQLi", func(t *testing.T) {
		f := report.Finding{
			ID:         "FND-SQLI-01",
			Title:      "SQL Injection Candidate",
			Category:   "SQLI",
			Confidence: report.ConfidenceHigh,
			Target:     "https://example.com",
			Endpoint:   "https://example.com/api/users?id=1'",
			Evidence:   "Internal Server Error (500)", // Generic 500, no SQL syntax error
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 500,
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusVerified {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: generic 500 error produced VERIFIED SQLi!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})

	t.Run("Missing cloud credentials cannot produce NOT_EXPOSED", func(t *testing.T) {
		f := report.Finding{
			ID:          "FND-CLOUD-01",
			Title:       "AWS S3 Bucket Permissions",
			Category:    "CLOUD_STORAGE",
			Target:      "https://example.com",
			Endpoint:    "s3://example-bucket",
			Description: "Audit check inconclusive due to missing permissions",
			Evidence:    "missing permissions to describe bucket",
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: missing cloud permissions produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})
}

func TestVerification_SafetyControlsEnforcement(t *testing.T) {
	ctx := context.Background()

	t.Run("Unauthorized assessment blocks verification and produces NOT_VERIFIED", func(t *testing.T) {
		checker := NewSafetyChecker(SafetyOptions{
			IsAuthorized: false, // Unauthorized!
			InScopeFunc:  func(s string) bool { return true },
		})
		engine := NewEngine(checker)

		f := report.Finding{
			ID:       "FND-AUTHZ-01",
			Title:    "Unauthorized Probe Test",
			Category: "BOLA",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/v1/secret",
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("CRITICAL SAFETY VIOLATION: blocked check converted to NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
		if res.SafetyDecision != DecisionBlocked {
			t.Fatalf("expected safety decision BLOCKED, got %s", res.SafetyDecision)
		}
		if !strings.Contains(res.BlockReason, "authorization is missing") {
			t.Fatalf("expected authorization block reason, got %s", res.BlockReason)
		}
	})

	t.Run("Out of scope target blocks verification and produces NOT_VERIFIED", func(t *testing.T) {
		checker := NewSafetyChecker(SafetyOptions{
			IsAuthorized: true,
			InScopeFunc:  func(url string) bool { return strings.Contains(url, "example.com") },
			IsExcludedFunc: func(url string) bool { return strings.Contains(url, "forbidden.org") },
		})
		engine := NewEngine(checker)

		f := report.Finding{
			ID:       "FND-SCOPE-01",
			Title:    "External Endpoint Probe",
			Category: "BOLA",
			Target:   "https://forbidden.org",
			Endpoint: "https://forbidden.org/api/data",
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("CRITICAL: out-of-scope check produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
		if res.SafetyDecision != DecisionBlocked {
			t.Fatalf("expected BLOCKED, got %s", res.SafetyDecision)
		}
	})

	t.Run("State-changing actions blocked by default non-destructive policy", func(t *testing.T) {
		checker := NewSafetyChecker(SafetyOptions{
			IsAuthorized:       true,
			InScopeFunc:        func(s string) bool { return true },
			AllowStateChanging: false, // Default: non-destructive
		})
		engine := NewEngine(checker)

		f := report.Finding{
			ID:       "FND-BIZ-01",
			Title:    "Order Payment Step Skip",
			Category: "WORKFLOW",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/checkout/complete",
			Method:   "POST",
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED for state-changing check, got %s", res.Status)
		}
		if res.SafetyDecision != DecisionBlocked {
			t.Fatalf("expected BLOCKED, got %s", res.SafetyDecision)
		}
		if !strings.Contains(res.BlockReason, "non-destructive") {
			t.Fatalf("expected non-destructive reason, got %s", res.BlockReason)
		}
	})
}

func TestVerification_ConfidenceModelSeparation(t *testing.T) {
	// 1. High detection confidence but no verification evidence
	res1 := ComputeConfidence(
		report.ConfidenceHigh,
		ConfidenceNone,
		StatusNotVerified,
		false,
		false,
		false,
	)
	if res1.OverallConfidence == ConfidenceHigh {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: high detection confidence alone produced high overall confidence!")
	}
	if res1.Score > 60 {
		t.Fatalf("expected score capped at 55 for NOT_VERIFIED, got %d", res1.Score)
	}

	// 2. High detection and high verification confidence with mandatory criteria passed
	res2 := ComputeConfidence(
		report.ConfidenceHigh,
		ConfidenceHigh,
		StatusVerified,
		false,
		false,
		true,
	)
	if res2.OverallConfidence != ConfidenceHigh {
		t.Fatalf("expected high overall confidence for verified finding, got %s", res2.OverallConfidence)
	}
	if res2.Score < 80 {
		t.Fatalf("expected verified score >= 80, got %d", res2.Score)
	}

	// 3. Contradiction reduces confidence
	res3 := ComputeConfidence(
		report.ConfidenceHigh,
		ConfidenceHigh,
		StatusVerified,
		true, // Contradiction present!
		false,
		true,
	)
	if res3.Score > 50 {
		t.Fatalf("expected contradiction penalty reducing score, got %d", res3.Score)
	}
	if !strings.Contains(res3.Rationale, "PENALTY") {
		t.Fatalf("expected contradiction penalty in rationale: %s", res3.Rationale)
	}
}

func TestVerification_ReproductionAndSecretRedaction(t *testing.T) {
	f := report.Finding{
		ID:       "FND-REPRO-01",
		Title:    "Exposed API Endpoint with Key",
		Category: "API_SECURITY",
		Target:   "https://api.example.com",
		Endpoint: "https://api.example.com/v1/users?token=supersecret12345",
		Method:   "GET",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 200,
			Details: map[string]string{
				"Authorization": "Bearer supersecretjwttoken",
				"X-API-Key":     "secretkey999",
			},
		},
	}

	repro := BuildReproductionContext(
		f,
		"https://api.example.com",
		"POL-APISEC-01",
		StatusVerified,
		"HTTP 401 Unauthorized",
		"HTTP 200 OK",
		[]string{"API reachability"},
		nil,
	)

	// Check safe curl command
	curl := repro.SafeCurlCommand
	if strings.Contains(curl, "supersecretjwttoken") {
		t.Fatalf("CRITICAL LEAK: unredacted JWT token in safe curl command: %s", curl)
	}
	if strings.Contains(curl, "secretkey999") {
		t.Fatalf("CRITICAL LEAK: unredacted secret key in safe curl command: %s", curl)
	}
	if !strings.Contains(curl, "[REDACTED]") {
		t.Fatalf("expected [REDACTED] in safe curl command: %s", curl)
	}
	if len(repro.ReproductionSteps) < 4 {
		t.Fatalf("expected structured reproduction steps, got %d", len(repro.ReproductionSteps))
	}
}

func TestVerification_SummaryAndRateCalculations(t *testing.T) {
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	findings := []report.Finding{
		{
			ID:       "F-1",
			Title:    "Public .env",
			Category: "EXPOSURE",
			Target:   "https://example.com",
			Endpoint: "https://example.com/.env",
			Evidence: "SECRET=123",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		},
		{
			ID:       "F-2",
			Title:    "Secret in JS",
			Category: "SECRETS",
			Target:   "https://example.com",
			Endpoint: "https://example.com/main.js",
			Source:   report.SourceSecrets,
			Evidence: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			ID:       "F-3",
			Title:    "Admin Route 401",
			Category: "AUTH",
			Target:   "https://example.com",
			Endpoint: "https://example.com/admin",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 401,
			},
		},
	}

	results, summary := engine.VerifyFindings(context.Background(), findings)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if summary.TotalFindings != 3 {
		t.Fatalf("expected TotalFindings=3, got %d", summary.TotalFindings)
	}
	if summary.VerifiedCount != 1 {
		t.Fatalf("expected VerifiedCount=1, got %d", summary.VerifiedCount)
	}
	if summary.NotVerifiedCount != 1 {
		t.Fatalf("expected NotVerifiedCount=1, got %d", summary.NotVerifiedCount)
	}
	if summary.NotExposedCount != 1 {
		t.Fatalf("expected NotExposedCount=1, got %d", summary.NotExposedCount)
	}
	if summary.VerificationRateTotal <= 0 {
		t.Fatalf("expected positive VerificationRateTotal, got %f", summary.VerificationRateTotal)
	}
}
