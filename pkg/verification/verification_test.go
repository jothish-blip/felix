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
			name: "Not Exposed: Specifically tested unauthenticated bypass disproved with negative evidence",
			finding: report.Finding{
				ID:       "FND-04",
				Title:    "Unauthenticated Access Bypass on Admin Endpoint",
				Category: "AUTH",
				Target:   "https://example.com",
				Endpoint: "https://example.com/admin/settings",
				EvidenceDetails: report.EvidenceDetails{
					HTTPStatus:       401,
					Observation:      "Access denied by authentication",
					NegativeEvidence: "Direct unauthenticated request to /admin/settings returned HTTP 401 Unauthorized",
					Details: map[string]string{
						"unauth_bypass_tested": "true",
						"caller_identity":      "anonymous",
					},
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
			Title:    "Unauthenticated Access Bypass on Admin Endpoint",
			Category: "AUTH",
			Target:   "https://example.com",
			Endpoint: "https://example.com/admin",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       401,
				NegativeEvidence: "Direct unauthenticated request to /admin returned HTTP 401 Unauthorized",
				Details: map[string]string{
					"unauth_bypass_tested": "true",
					"caller_identity":      "anonymous",
				},
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

func TestVerification_ClaimSpecificNegativeProofRegressions(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	// 1. A generic 401 does not automatically produce NOT_EXPOSED
	t.Run("1. Generic 401 does not produce NOT_EXPOSED", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-401-01",
			Title:    "Discovered Protected Route",
			Category: "DISCOVERY",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/admin",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 401, // Generic 401 without specific tested negative claim
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: generic 401 produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}

		// Also test under AUTH category
		fAuth := report.Finding{
			ID:       "REG-401-02",
			Title:    "Authentication Endpoint Observed",
			Category: "AUTH",
			Target:   "https://example.com",
			Endpoint: "https://example.com/login",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 401, // Generic 401 without unauth-bypass claim or negative evidence
			},
		}
		resAuth := engine.VerifyFinding(ctx, fAuth)
		if resAuth.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: generic 401 in AUTH produced NOT_EXPOSED!")
		}
		if resAuth.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", resAuth.Status)
		}
	})

	// 2. A generic 403 does not automatically produce NOT_EXPOSED
	t.Run("2. Generic 403 does not produce NOT_EXPOSED", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-403-01",
			Title:    "Restricted Resource",
			Category: "DISCOVERY",
			Target:   "https://example.com",
			Endpoint: "https://example.com/internal",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 403,
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: generic 403 produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}

		// In BOLA category without comparative evidence:
		fAuthz := report.Finding{
			ID:       "REG-403-02",
			Title:    "BOLA Candidate Resource",
			Category: "BOLA",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/v1/orders/99",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 403, // Generic 403 without comparative tenant evidence
			},
		}
		resAuthz := engine.VerifyFinding(ctx, fAuthz)
		if resAuthz.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: generic 403 in BOLA produced NOT_EXPOSED!")
		}
		if resAuthz.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", resAuthz.Status)
		}
	})

	// 3. A 404 does not automatically disprove a vulnerability
	t.Run("3. HTTP 404 does not automatically disprove a vulnerability", func(t *testing.T) {
		fTraversal := report.Finding{
			ID:       "REG-404-01",
			Title:    "Directory Traversal Probe",
			Category: "TRAVERSAL",
			Target:   "https://example.com",
			Endpoint: "https://example.com/files?path=../../etc/passwd",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 404, // 404 Not Found
			},
		}
		res := engine.VerifyFinding(ctx, fTraversal)
		if res.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: 404 produced NOT_EXPOSED on web vulnerability!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}

		// Also on discovery exposure
		fExposure := report.Finding{
			ID:       "REG-404-02",
			Title:    "Public .env Config Claim",
			Category: "EXPOSURE",
			Target:   "https://example.com",
			Endpoint: "https://example.com/.env",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 404,
			},
		}
		resExposure := engine.VerifyFinding(ctx, fExposure)
		if resExposure.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: 404 produced NOT_EXPOSED on configuration exposure claim!")
		}
		if resExposure.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", resExposure.Status)
		}
	})

	// 4. A cloud storage access-denied response cannot establish that the entire resource is secure
	t.Run("4. Cloud access-denied cannot establish entire resource is secure", func(t *testing.T) {
		// Generic 403 without specific anonymous bucket listing verification
		fGenericCloud := report.Finding{
			ID:       "REG-CLOUD-01",
			Title:    "Cloud IAM Policy Inspection",
			Category: "CLOUD_STORAGE",
			Target:   "https://example.com",
			Endpoint: "https://mybucket.s3.amazonaws.com/private/file.txt",
			Evidence: "AccessDenied (HTTP 403)",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 403,
			},
		}
		res := engine.VerifyFinding(ctx, fGenericCloud)
		if res.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: generic cloud access-denied produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}

		// Even when claim-specific anonymous listing IS verified as denied:
		fSpecificBucket := report.Finding{
			ID:       "REG-CLOUD-02",
			Title:    "Anonymous Public Bucket Listing",
			Category: "CLOUD_STORAGE",
			Target:   "https://example.com",
			Endpoint: "https://mybucket.s3.amazonaws.com/?list-type=2",
			Evidence: "AccessDenied",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       403,
				NegativeEvidence: "Anonymous GET / returned 403 AccessDenied",
				Details: map[string]string{
					"access_denied_confirmed": "true",
				},
			},
		}
		resSpecific := engine.VerifyFinding(ctx, fSpecificBucket)
		if resSpecific.Status != StatusNotExposed {
			t.Fatalf("expected NOT_EXPOSED for properly scoped bucket listing claim, got %s", resSpecific.Status)
		}
		// Invariant: MUST record limitations stating whole bucket/account is not proven secure
		if len(resSpecific.Limitations) == 0 {
			t.Fatalf("expected limitations explaining narrow scope of cloud negative proof")
		}
		limitationFound := false
		for _, lim := range resSpecific.Limitations {
			if strings.Contains(strings.ToLower(lim), "strictly limited") || strings.Contains(strings.ToLower(lim), "other bucket permissions") {
				limitationFound = true
				break
			}
		}
		if !limitationFound {
			t.Fatalf("expected limitation stating cloud verification is strictly limited to tested request: %v", resSpecific.Limitations)
		}
	})

	// 5. Missing comparative authorization evidence results in NOT_VERIFIED
	t.Run("5. Missing comparative authorization evidence results in NOT_VERIFIED", func(t *testing.T) {
		fMissingBaseline := report.Finding{
			ID:       "REG-BOLA-01",
			Title:    "Broken Object Level Authorization",
			Category: "BOLA",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/v1/documents/456",
			Evidence: `{"doc_id": 456}`,
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
				Details: map[string]string{
					"resource_id": "456",
					// Missing owner_identity and baseline_accessible!
					"caller_identity": "attacker_user",
				},
			},
		}
		res := engine.VerifyFinding(ctx, fMissingBaseline)
		if res.Status == StatusVerified {
			t.Fatalf("VIOLATION: missing comparative evidence produced VERIFIED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
		if !strings.Contains(res.FailureReason, "Missing comparative") {
			t.Fatalf("expected failure reason mentioning comparative evidence, got %s", res.FailureReason)
		}
	})

	// 6. A properly scoped negative verification can still return NOT_EXPOSED when its required criteria pass
	t.Run("6. Properly scoped negative verification returns NOT_EXPOSED", func(t *testing.T) {
		fAuth := report.Finding{
			ID:       "REG-SCOPED-01",
			Title:    "Unauthenticated Access Bypass on Internal API",
			Category: "AUTH",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/internal/metrics",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       401,
				Observation:      "Authentication barrier enforced",
				NegativeEvidence: "Anonymous request denied: HTTP 401 Unauthorized",
				Details: map[string]string{
					"unauth_bypass_tested": "true",
					"caller_identity":      "anonymous",
				},
			},
		}
		resAuth := engine.VerifyFinding(ctx, fAuth)
		if resAuth.Status != StatusNotExposed {
			t.Fatalf("expected NOT_EXPOSED for scoped negative auth check, got %s", resAuth.Status)
		}

		// Also properly scoped comparative BOLA negative verification
		fAuthz := report.Finding{
			ID:       "REG-SCOPED-02",
			Title:    "BOLA / Cross-Tenant Access Attempt",
			Category: "BOLA",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/v1/invoices/inv-001",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       403,
				NegativeEvidence: "Tenant B denied access to Tenant A's invoice: HTTP 403 Forbidden",
				Details: map[string]string{
					"resource_id":           "inv-001",
					"owner_identity":        "tenant_a",
					"baseline_accessible":   "true",
					"unauthorized_identity": "tenant_b",
					"isolation_verified":    "true",
				},
			},
		}
		resAuthz := engine.VerifyFinding(ctx, fAuthz)
		if resAuthz.Status != StatusNotExposed {
			t.Fatalf("expected NOT_EXPOSED for comparative negative BOLA check, got %s", resAuthz.Status)
		}
	})

	// 7. Contradictory evidence without conclusive negative proof results in NOT_VERIFIED
	t.Run("7. Contradictory evidence without conclusive negative proof produces NOT_VERIFIED", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-CONTRA-01",
			Title:    "Publicly Accessible Configuration",
			Category: "EXPOSURE",
			Target:   "https://example.com",
			Endpoint: "https://example.com/config.json",
			Evidence: "Claimed exposed",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:  404, // Contradicts claim of exposure
				Observation: "Endpoint returned 404 Not Found",
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusNotExposed {
			t.Fatalf("VIOLATION: contradictory evidence alone produced NOT_EXPOSED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})

	// 8. Only evidence satisfying all mandatory criteria can produce VERIFIED
	t.Run("8. Only evidence satisfying all mandatory criteria produces VERIFIED", func(t *testing.T) {
		// Finding claiming BOLA where resource leak is unconfirmed
		f := report.Finding{
			ID:       "REG-MAND-01",
			Title:    "BOLA with Incomplete Criteria",
			Category: "BOLA",
			Target:   "https://example.com",
			Endpoint: "https://example.com/api/v1/users/10",
			Evidence: "", // Empty evidence!
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
				Details: map[string]string{
					"resource_id":           "10",
					"owner_identity":        "user_1",
					"baseline_accessible":   "true",
					"unauthorized_identity": "user_2",
					// "cross_tenant_data_confirmed" is missing!
				},
			},
		}
		res := engine.VerifyFinding(ctx, f)
		if res.Status == StatusVerified {
			t.Fatalf("CRITICAL INVARIANT VIOLATION: incomplete mandatory criteria produced VERIFIED!")
		}
		if res.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED, got %s", res.Status)
		}
	})

	// 9. Confidence penalties alone cannot change the verification status
	t.Run("9. Confidence penalties alone cannot change verification status", func(t *testing.T) {
		// Test ComputeConfidence directly: contradiction penalty halves score but does not change status
		confRes := ComputeConfidence(
			report.ConfidenceHigh,
			ConfidenceLow,
			StatusNotVerified,
			true, // Contradiction!
			false,
			false,
		)
		if confRes.Score >= 50 {
			t.Fatalf("expected penalized score < 50, got %d", confRes.Score)
		}
		if confRes.OverallConfidence != ConfidenceLow {
			t.Fatalf("expected overall confidence LOW due to penalty, got %s", confRes.OverallConfidence)
		}
		// The status supplied to ComputeConfidence was StatusNotVerified; score penalty did not force NOT_EXPOSED or VERIFIED
	})

	// 10. Existing synthetic-fixture labels, evidence provenance, and scope enforcement remain intact
	t.Run("10. Synthetic fixture labels, provenance, and scope enforcement intact", func(t *testing.T) {
		// Scope block
		checkerScoped := NewSafetyChecker(SafetyOptions{
			IsAuthorized: true,
			InScopeFunc:  func(u string) bool { return strings.Contains(u, "allowed.com") },
		})
		engineScoped := NewEngine(checkerScoped)
		fOutOfScope := report.Finding{
			ID:       "REG-SCOPE-01",
			Title:    "Out of Scope Endpoint",
			Category: "AUTH",
			Target:   "https://forbidden.org",
			Endpoint: "https://forbidden.org/api",
		}
		resScope := engineScoped.VerifyFinding(ctx, fOutOfScope)
		if resScope.SafetyDecision != DecisionBlocked {
			t.Fatalf("expected BLOCKED, got %s", resScope.SafetyDecision)
		}
		if resScope.Status != StatusNotVerified {
			t.Fatalf("expected NOT_VERIFIED for scope-blocked finding, got %s", resScope.Status)
		}

		// Synthetic fixture marker
		fSynthetic := report.Finding{
			ID:       "REG-SYNTH-01",
			Title:    "Synthetic Test Finding",
			Category: "EXPOSURE",
			Target:   "https://allowed.com",
			Endpoint: "https://allowed.com/.env",
			Evidence: "[SYNTHETIC FIXTURE] DB_PASS=test",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
			Verification: report.VerificationRecord{
				SyntheticFixture: true,
			},
		}
		resSynth := engineScoped.VerifyFinding(ctx, fSynthetic)
		if !resSynth.SyntheticFixture {
			t.Fatalf("expected SyntheticFixture=true on verification result")
		}
		if !strings.Contains(resSynth.ConfidenceRationale, "[SYNTHETIC FIXTURE") {
			t.Fatalf("expected [SYNTHETIC FIXTURE] in confidence rationale: %s", resSynth.ConfidenceRationale)
		}
	})
}

func TestVerification_Regression_FrameworkObservationAndHTTPCookie(t *testing.T) {
	ctx := context.Background()
	engine := NewEngine(NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	}))

	// 1. Node runtime exposure via 404 probe response
	fNode := report.Finding{
		ID:       "REG-NODE-404",
		Title:    "Node.js Express framework identified via HTTP response header",
		Category: "node-runtime-exposure",
		Target:   "http://127.0.0.1:4000",
		Endpoint: "http://127.0.0.1:4000/_felix_node_probe",
		Evidence: "HTTP 404 on http://127.0.0.1:4000/_felix_node_probe returned X-Powered-By: Express header.",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 404,
		},
	}
	resNode := engine.VerifyFinding(ctx, fNode)
	if resNode.Status != StatusObserved {
		t.Errorf("expected StatusObserved for framework identification probe, got %s (must not be NOT_VERIFIED)", resNode.Status)
	}
	if resNode.Attempted {
		t.Errorf("expected Attempted=false for passive framework observation, got true")
	}
	if resNode.FailureReason != "" {
		t.Errorf("framework identification on 404 probe must not have failure reason, got %s", resNode.FailureReason)
	}

	// 2. Session cookie missing Secure flag on HTTP-only local target
	fCookie := report.Finding{
		ID:       "REG-COOKIE-HTTP",
		RuleID:   "AUTH-COOKIE-DEFECT",
		Title:    "Session Cookie Security Defect: connect.sid (Missing Secure flag (target served over unencrypted HTTP))",
		Category: "Authentication / Session Security",
		Target:   "http://127.0.0.1:4000",
		Endpoint: "/",
		Evidence: "Cookie name: connect.sid | Secure: false | HttpOnly: true | SameSite: ",
		EvidenceDetails: report.EvidenceDetails{
			HTTPStatus: 200,
			Details: map[string]string{
				"cookie_name": "connect.sid",
			},
		},
	}
	resCookie := engine.VerifyFinding(ctx, fCookie)
	if resCookie.Status != StatusObserved {
		t.Errorf("expected StatusObserved for cookie on unencrypted HTTP target, got %s (must not be NOT_VERIFIED or INCONCLUSIVE)", resCookie.Status)
	}
	if resCookie.Attempted {
		t.Errorf("expected Attempted=false for passive HTTP session cookie observation, got true")
	}
	if !strings.Contains(resCookie.ObservedBehavior, "unencrypted HTTP") {
		t.Errorf("expected unencrypted HTTP context in observed behavior, got: %s", resCookie.ObservedBehavior)
	}
}

func TestVerification_Regression_GraphQLIntrospection(t *testing.T) {
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)
	ctx := context.Background()

	// 1. Valid introspection evidence -> VERIFIED
	t.Run("ValidIntrospectionEvidence", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-1",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL endpoint has public introspection enabled",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "HTTP 200 OK. Introspection query succeeded (29 types observed; sensitive schema indicators: [CreateUser, UserInput, UserObject]). Full schema dump omitted.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusVerified {
			t.Fatalf("expected StatusVerified for successful GraphQL introspection, got %s", res.Status)
		}
		if !res.Attempted {
			t.Errorf("expected Attempted=true for active GraphQL introspection check")
		}
		if res.PolicyID != "POL-APISEC-01" {
			t.Errorf("expected policy POL-APISEC-01, got %s", res.PolicyID)
		}
		if res.VerificationMethod != "graphql_introspection_query" {
			t.Errorf("expected verification method 'graphql_introspection_query', got %s", res.VerificationMethod)
		}
	})

	// 2. HTTP 200 without successful introspection (e.g. SPA shell fallback) -> NOT_VERIFIED
	t.Run("HTTP200WithoutIntrospection_SPAShell", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-2A",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL endpoint has public introspection enabled",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "<!DOCTYPE html><html><head><title>App Shell</title></head><body><div id=\"root\"></div></body></html>",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotVerified {
			t.Fatalf("expected StatusNotVerified for SPA HTML fallback, got %s", res.Status)
		}
		if !res.Attempted {
			t.Errorf("expected Attempted=true for evaluated endpoint check")
		}
		if !strings.Contains(res.InconclusiveReason, "HTML document or SPA fallback shell") {
			t.Errorf("expected HTML shell explanation in InconclusiveReason, got %s", res.InconclusiveReason)
		}
	})

	// 2b. HTTP 200 without schema types (generic JSON) -> NOT_VERIFIED
	t.Run("HTTP200WithoutIntrospection_GenericJSON", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-2B",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL endpoint has public introspection enabled",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "{\"status\": \"ok\", \"service\": \"graphql-gateway\", \"version\": \"1.0.0\"}",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotVerified {
			t.Fatalf("expected StatusNotVerified for generic JSON 200 without schema, got %s", res.Status)
		}
		if !strings.Contains(res.InconclusiveReason, "lacks confirmed GraphQL schema types") {
			t.Errorf("expected missing schema types explanation, got %s", res.InconclusiveReason)
		}
	})

	// 3. Malformed or incomplete schema evidence (0 types observed) -> NOT_VERIFIED
	t.Run("MalformedOrIncompleteSchema_ZeroTypes", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-3",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL endpoint has public introspection enabled",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "HTTP 200 OK. Introspection query succeeded (0 types observed). Full schema dump omitted.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotVerified {
			t.Fatalf("expected StatusNotVerified for 0 types observed, got %s", res.Status)
		}
		if !strings.Contains(res.InconclusiveReason, "0 types") {
			t.Errorf("expected 0 types in InconclusiveReason, got %s", res.InconclusiveReason)
		}
	})

	// 4. Unrelated error pages and generic API responses -> NOT_VERIFIED
	t.Run("UnrelatedErrorPage_500InternalError", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-4",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL endpoint has public introspection enabled",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "{\"error\": \"Internal Server Error\", \"code\": 500}",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 500,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotVerified {
			t.Fatalf("expected StatusNotVerified for 500 error response, got %s", res.Status)
		}
		if !strings.Contains(res.InconclusiveReason, "inconclusive generic API response") {
			t.Errorf("expected generic API response rationale, got %s", res.InconclusiveReason)
		}
	})

	// 5. Negative controls where introspection is disabled or unavailable -> NOT_EXPOSED
	t.Run("NegativeControl_IntrospectionDenied403", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-5A",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL Introspection Denied",
			Category: "graphql-introspection-denied",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "{\"errors\":[{\"message\":\"GraphQL introspection is not allowed by GraphQL server.\"}]}",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 400,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotExposed {
			t.Fatalf("expected StatusNotExposed for disabled GraphQL introspection, got %s", res.Status)
		}
		if !res.Attempted {
			t.Errorf("expected Attempted=true for active barrier verification check")
		}
		if res.VerificationMethod != "graphql_introspection_barrier" {
			t.Errorf("expected method 'graphql_introspection_barrier', got %s", res.VerificationMethod)
		}
	})

	t.Run("NegativeControl_ForbiddenStatus403", func(t *testing.T) {
		f := report.Finding{
			ID:       "REG-GQL-5B",
			Source:   report.SourceAPI,
			RuleID:   "API-GRAPHQL-INTROSPECTION",
			Title:    "GraphQL Introspection",
			Category: "graphql-introspection",
			Target:   "http://127.0.0.1:5013",
			Endpoint: "http://127.0.0.1:5013/graphql",
			Method:   "GET",
			Evidence: "HTTP 403 Forbidden: Access to GraphQL introspection is restricted",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 403,
			},
		}

		res := engine.VerifyFinding(ctx, f)
		if res.Status != StatusNotExposed {
			t.Fatalf("expected StatusNotExposed for 403 forbidden introspection, got %s", res.Status)
		}
		if res.VerificationMethod != "graphql_introspection_barrier" {
			t.Errorf("expected method 'graphql_introspection_barrier', got %s", res.VerificationMethod)
		}
	})
}

// TestVerification_Regression_WebGoatSevenFindings verifies that WebGoat's 7 findings
// reconcile with 5 VERIFIED header findings and 2 NOT_EXPOSED defended route controls,
// proving AttemptedCount = 7, VerifiedCount = 5, NotExposedCount = 2, NotVerifiedCount = 0,
// and VerificationRateAttempted = 71.4%, without classifying defended controls as NOT_VERIFIED.
func TestVerification_Regression_WebGoatSevenFindings(t *testing.T) {
	ctx := context.Background()
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized: true,
		InScopeFunc:  func(s string) bool { return true },
	})
	engine := NewEngine(checker)

	target := "http://127.0.0.1:8080/WebGoat/login"
	findings := []report.Finding{
		{
			ID:       "API-ea50cdc6609b02b0",
			RuleID:   "API-MISSING-CSP",
			Title:    "Missing Content-Security-Policy (CSP) defense-in-depth header",
			Category: "missing-csp",
			Severity: report.SeverityLow,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: target,
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "Response headers do not include Content-Security-Policy.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
		},
		{
			ID:       "API-0dd48df4fb1bbd13",
			RuleID:   "API-MISSING-X-FRAME-OPTIONS",
			Title:    "Missing X-Frame-Options header (clickjacking protection)",
			Category: "missing-x-frame-options",
			Severity: report.SeverityLow,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: target,
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "Response headers do not include X-Frame-Options or CSP frame-ancestors directive.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
		},
		{
			ID:       "API-1695d04a8f808f33",
			RuleID:   "API-MISSING-PERMISSIONS-POLICY",
			Title:    "Missing Permissions-Policy header (browser feature gating)",
			Category: "missing-permissions-policy",
			Severity: report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: target,
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "Response headers do not include Permissions-Policy.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
		},
		{
			ID:       "API-69ae4973c13f6a16",
			RuleID:   "API-MISSING-REFERRER-POLICY",
			Title:    "Missing Referrer-Policy defense-in-depth header",
			Category: "missing-referrer-policy",
			Severity: report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: target,
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "Response headers do not include Referrer-Policy (browser default applies).",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
		},
		{
			ID:       "API-2cd8d2e571c1283f",
			RuleID:   "API-MISSING-X-CONTENT-TYPE-OPTIONS",
			Title:    "Missing or incomplete X-Content-Type-Options: nosniff header",
			Category: "missing-x-content-type-options",
			Severity: report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: target,
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "X-Content-Type-Options observed: \"absent\" (expected 'nosniff').",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:      200,
				DetectionMethod: "header_inspection",
			},
		},
		{
			ID:       "API-1957c2555281256f",
			RuleID:   "API-LARAVEL-TELESCOPE-RESTRICTED",
			Title:    "Laravel Telescope interface requires authentication (observed login redirect)",
			Category: "laravel-telescope-restricted",
			Severity: report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: "http://127.0.0.1:8080/WebGoat/login/telescope",
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "HTTP 302 redirect observed on http://127.0.0.1:8080/WebGoat/login/telescope to http://127.0.0.1:8080/WebGoat/login. Laravel Telescope dashboard route requires authentication.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       302,
				DetectionMethod:  "active_probe",
				NegativeEvidence: "Authentication redirect active on probed route; unauthenticated access to this endpoint is not permitted.",
			},
		},
		{
			ID:       "API-6c494905ee1f9ff2",
			RuleID:   "API-LARAVEL-TELESCOPE-RESTRICTED",
			Title:    "Laravel Telescope API requires authentication (observed login redirect)",
			Category: "laravel-telescope-restricted",
			Severity: report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Target:   target,
			Endpoint: "http://127.0.0.1:8080/WebGoat/login/telescope/telescope-api/requests",
			Method:   "GET",
			Source:   report.SourceAPI,
			Evidence: "HTTP 302 redirect observed on http://127.0.0.1:8080/WebGoat/login/telescope/telescope-api/requests to http://127.0.0.1:8080/WebGoat/login. Laravel Telescope API route requires authentication.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus:       302,
				DetectionMethod:  "active_probe",
				NegativeEvidence: "Authentication redirect active on probed route; unauthenticated access to this API endpoint is not permitted.",
			},
		},
	}

	results, summary := engine.VerifyFindings(ctx, findings)

	if len(results) != 7 {
		t.Fatalf("expected 7 verification results, got %d", len(results))
	}
	if summary.TotalFindings != 7 {
		t.Errorf("expected TotalFindings 7, got %d", summary.TotalFindings)
	}
	if summary.AttemptedCount != 7 {
		t.Errorf("expected AttemptedCount 7, got %d", summary.AttemptedCount)
	}
	if summary.VerifiedCount != 5 {
		t.Errorf("expected VerifiedCount 5, got %d", summary.VerifiedCount)
	}
	if summary.NotExposedCount != 2 {
		t.Errorf("expected NotExposedCount 2, got %d", summary.NotExposedCount)
	}
	if summary.NotVerifiedCount != 0 {
		t.Errorf("expected NotVerifiedCount 0, got %d", summary.NotVerifiedCount)
	}
	if summary.InconclusiveCount != 0 {
		t.Errorf("expected InconclusiveCount 0 in verification summary, got %d", summary.InconclusiveCount)
	}
	if summary.VerificationRateAttempted != 71.4 {
		t.Errorf("expected VerificationRateAttempted 71.4, got %.1f", summary.VerificationRateAttempted)
	}
	if summary.VerificationRateTotal != 71.4 {
		t.Errorf("expected VerificationRateTotal 71.4, got %.1f", summary.VerificationRateTotal)
	}

	// Verify both telescope findings individually
	resMap := make(map[string]VerificationResult)
	for _, r := range results {
		resMap[r.FindingID] = r
	}

	tel1 := resMap["API-1957c2555281256f"]
	if tel1.Status != StatusNotExposed {
		t.Errorf("expected tel1 StatusNotExposed, got %s", tel1.Status)
	}
	if !tel1.Attempted {
		t.Errorf("expected tel1 Attempted=true")
	}
	if tel1.VerificationMethod != "diagnostic_barrier_check" {
		t.Errorf("expected tel1 method 'diagnostic_barrier_check', got %s", tel1.VerificationMethod)
	}

	tel2 := resMap["API-6c494905ee1f9ff2"]
	if tel2.Status != StatusNotExposed {
		t.Errorf("expected tel2 StatusNotExposed, got %s", tel2.Status)
	}
	if !tel2.Attempted {
		t.Errorf("expected tel2 Attempted=true")
	}
	if tel2.VerificationMethod != "diagnostic_barrier_check" {
		t.Errorf("expected tel2 method 'diagnostic_barrier_check', got %s", tel2.VerificationMethod)
	}

	// Apply verification back to findings and verify report model status
	updated := ApplyVerificationToFindings(findings, results)
	repSummary := report.Summarize(updated)

	if repSummary.TotalFindings != 7 {
		t.Errorf("expected report TotalFindings 7, got %d", repSummary.TotalFindings)
	}
	if repSummary.VerifiedCount != 5 {
		t.Errorf("expected report VerifiedCount 5, got %d", repSummary.VerifiedCount)
	}
	if repSummary.NotExposedCount != 2 {
		t.Errorf("expected report NotExposedCount 2, got %d", repSummary.NotExposedCount)
	}
	if repSummary.NotVerifiedCount != 0 {
		t.Errorf("expected report NotVerifiedCount 0, got %d", repSummary.NotVerifiedCount)
	}
	if repSummary.AttemptedCount != 7 {
		t.Errorf("expected report AttemptedCount 7, got %d", repSummary.AttemptedCount)
	}
	if repSummary.ConfirmedCount != 5 {
		t.Errorf("expected report ConfirmedCount 5, got %d", repSummary.ConfirmedCount)
	}
	if repSummary.InconclusiveCount != 2 {
		t.Errorf("expected report InconclusiveCount 2, got %d", repSummary.InconclusiveCount)
	}
	if repSummary.VerificationRateAttempted != 71.4 {
		t.Errorf("expected report VerificationRateAttempted 71.4, got %.1f", repSummary.VerificationRateAttempted)
	}
	if repSummary.VerificationRateTotal != 71.4 {
		t.Errorf("expected report VerificationRateTotal 71.4, got %.1f", repSummary.VerificationRateTotal)
	}
}
