package verification

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"felix/pkg/report"
)

// TestJuiceShop_InconclusiveResolutionRegression verifies that:
// 1. ENDPOINT-DISCOVERED findings with AUTH_REQUIRED are evaluated as NOT_EXPOSED (defended boundary).
// 2. ENDPOINT-DISCOVERED findings that are PUBLIC are evaluated as OBSERVED (asset inventory).
// 3. CORS-WILDCARD findings are evaluated as OBSERVED (informational header observation).
// 4. Passive evidence evaluations do not consume active probe quota in SafetyChecker.
// 5. Inconclusive probe failure count across the 23 Juice Shop findings resolves to ZERO.
func TestJuiceShop_InconclusiveResolutionRegression(t *testing.T) {
	checker := NewSafetyChecker(SafetyOptions{
		IsAuthorized:         true,
		MaxRequestsPerTarget: 20,
	})
	engine := NewEngine(checker)

	t.Run("EndpointDiscovered_AuthRequired_EvaluatesToNotExposed", func(t *testing.T) {
		f := report.Finding{
			ID:          "API-JS-AUTH",
			Category:    "endpoint-discovered",
			Title:       "Discovered API endpoint: /api/Addresss (AUTH_REQUIRED)",
			Endpoint:    "http://127.0.0.1:3000/api/Addresss",
			Target:      "http://127.0.0.1:3000",
			Method:      "GET",
			Severity:    report.SeverityInfo,
			Confidence:  report.ConfidenceMedium,
			Source:      report.SourceAPI,
			Evidence:    "Authentication challenge returned (HTTP 401); protected boundary active.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
				Details: map[string]string{
					"auth_state":   "AUTH_REQUIRED",
					"auth_context": "AUTH_REQUIRED",
				},
				NegativeEvidence: "Authentication or authorization barrier active (AUTH_REQUIRED); unauthenticated access not permitted.",
			},
		}

		res := engine.VerifyFinding(context.Background(), f)
		if res.Status != StatusNotExposed {
			t.Errorf("expected StatusNotExposed, got %s (inconclusive reason: %q)", res.Status, res.InconclusiveReason)
		}
		if res.InconclusiveReason != "" {
			t.Errorf("expected empty InconclusiveReason, got %q", res.InconclusiveReason)
		}
	})

	t.Run("EndpointDiscovered_Public_EvaluatesToObserved", func(t *testing.T) {
		f := report.Finding{
			ID:         "API-JS-PUB",
			Category:   "endpoint-discovered",
			Title:      "Discovered API endpoint: /api/Challenges (PUBLIC)",
			Endpoint:   "http://127.0.0.1:3000/api/Challenges",
			Target:     "http://127.0.0.1:3000",
			Method:     "GET",
			Severity:   report.SeverityInfo,
			Confidence: report.ConfidenceMedium,
			Source:     report.SourceAPI,
			Evidence:   "Endpoint responded with HTTP 200 OK without requiring authentication.",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
				Details: map[string]string{
					"auth_state": "PUBLIC",
				},
			},
		}

		res := engine.VerifyFinding(context.Background(), f)
		if res.Status != StatusObserved {
			t.Errorf("expected StatusObserved, got %s (inconclusive reason: %q)", res.Status, res.InconclusiveReason)
		}
		if res.InconclusiveReason != "" {
			t.Errorf("expected empty InconclusiveReason, got %q", res.InconclusiveReason)
		}
	})

	t.Run("CORSWildcard_EvaluatesToObserved", func(t *testing.T) {
		f := report.Finding{
			ID:         "API-JS-CORS",
			Category:   "cors-wildcard",
			Title:      "CORS policy permits wildcard (*) origin",
			Endpoint:   "http://127.0.0.1:3000/api/Challenges",
			Target:     "http://127.0.0.1:3000",
			Method:     "GET",
			Severity:   report.SeverityInfo,
			Confidence: report.ConfidenceHigh,
			Source:     report.SourceAPI,
			Evidence:   "Supplied Origin: https://felix.invalid. Response returned Access-Control-Allow-Origin: * (HTTP 200 GET).",
			EvidenceDetails: report.EvidenceDetails{
				HTTPStatus: 200,
				Details: map[string]string{
					"acao": "*",
				},
				NegativeEvidence: "Access-Control-Allow-Credentials header was absent. Credentialed cross-origin exposure was not demonstrated.",
			},
		}

		res := engine.VerifyFinding(context.Background(), f)
		if res.Status != StatusObserved {
			t.Errorf("expected StatusObserved, got %s (inconclusive reason: %q)", res.Status, res.InconclusiveReason)
		}
		if res.InconclusiveReason != "" {
			t.Errorf("expected empty InconclusiveReason, got %q", res.InconclusiveReason)
		}
	})

	t.Run("PassiveChecks_DoNotConsumeProbeQuota", func(t *testing.T) {
		sc := NewSafetyChecker(SafetyOptions{
			IsAuthorized:         true,
			MaxRequestsPerTarget: 5,
		})
		eng := NewEngine(sc)

		// Create 10 passive header findings for the same target
		var passiveFindings []report.Finding
		for i := 0; i < 10; i++ {
			passiveFindings = append(passiveFindings, report.Finding{
				ID:         "H-CSP",
				Category:   "missing-csp",
				Title:      "Missing Content-Security-Policy (CSP)",
				Endpoint:   "http://127.0.0.1:3000/",
				Target:     "http://127.0.0.1:3000",
				Severity:   report.SeverityLow,
				Confidence: report.ConfidenceHigh,
				Source:     report.SourceAPI,
				Evidence:   "Evaluated server HTTP response headers; confirmed absence of CSP header.",
			})
		}

		_, summary := eng.VerifyFindings(context.Background(), passiveFindings)
		if summary.BlockedCount != 0 {
			t.Errorf("expected 0 blocked findings from passive evaluation, got %d", summary.BlockedCount)
		}
		if summary.VerifiedCount != 10 {
			t.Errorf("expected 10 verified findings, got %d", summary.VerifiedCount)
		}
	})

	t.Run("JuiceShop23Findings_Reconciled_ZeroInconclusive_ZeroBlocked", func(t *testing.T) {
		// Load the real campaign 2 reconciled Juice Shop findings
		path := "../../reports/real_target_validation/campaign_2_reconciled/juice_shop_reconciled.json"
		data, err := os.ReadFile(path)
		if err != nil {
			t.Skipf("campaign 2 juice shop reconciled file not found: %v", err)
			return
		}

		var scanReport struct {
			Findings []report.Finding `json:"findings"`
		}
		if err := json.Unmarshal(data, &scanReport); err != nil {
			t.Fatalf("failed to unmarshal findings: %v", err)
		}

		if len(scanReport.Findings) != 23 {
			t.Fatalf("expected 23 findings in fixture, got %d", len(scanReport.Findings))
		}

		sc := NewSafetyChecker(SafetyOptions{
			IsAuthorized:         true,
			MaxRequestsPerTarget: 20, // Even with default 20, passive findings must not be blocked!
		})
		eng := NewEngine(sc)

		_, summary := eng.VerifyFindings(context.Background(), scanReport.Findings)

		if summary.InconclusiveCount != 0 {
			t.Errorf("expected 0 inconclusive findings across Juice Shop dataset, got %d", summary.InconclusiveCount)
		}
		if summary.BlockedCount != 0 {
			t.Errorf("expected 0 blocked findings across Juice Shop dataset, got %d", summary.BlockedCount)
		}
		if summary.VerifiedCount != 3 {
			t.Errorf("expected 3 verified findings (missing headers), got %d", summary.VerifiedCount)
		}
		if summary.NotExposedCount != 6 { // 6 defended endpoints requiring auth (5 + 1 previously blocked)
			t.Errorf("expected 6 defended (NotExposed) endpoints, got %d", summary.NotExposedCount)
		}
		if summary.ObservedCount != 14 { // 2 diagnostic (/metrics, /api-docs) + 4 CORS + 8 public endpoints
			t.Errorf("expected 14 observed findings, got %d", summary.ObservedCount)
		}
		if summary.ConclusiveRate != 100.0 {
			t.Errorf("expected 100.0%% conclusive rate, got %.1f%%", summary.ConclusiveRate)
		}
	})
}
