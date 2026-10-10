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
