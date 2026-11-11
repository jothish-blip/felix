package investigation_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"felix/pkg/investigation"
	"felix/pkg/report"
)

func TestPhase4Investigation_BOPLARoutingAndRemediation(t *testing.T) {
	prover := investigation.NewSafeProver("asm-phase4-inv", false)

	f := report.Finding{
		ID:       "BOPLA-test-1",
		Category: "API3:2023 - BOPLA",
		Title:    "[BOPLA-MASS-ASSIGNMENT] Unauthorized modification of profile.role",
		Severity: "High",
		Method:   "PUT",
		Target:   "http://127.0.0.1:8080/api/profile",
		Endpoint: "/api/profile",
		Evidence: "Property role was persisted to admin as verified via independent GET read-back",
		EvidenceDetails: report.EvidenceDetails{
			Details: map[string]string{
				"authz_engine_verified": "true",
				"property_path":         "role",
				"verification_state":    "VERIFIED",
				"required_role":         "admin",
				"accessor_alias":        "USER_A",
				"accessor_role":         "user",
				"expected_access":       "IMMUTABLE",
			},
		},
	}

	bundle, status, proofSummary, err := prover.ExecuteBoundedProof(context.Background(), f, http.DefaultClient)
	if err != nil {
		t.Fatalf("ExecuteBoundedProof failed: %v", err)
	}
	if status != investigation.StatusConfirmed {
		t.Fatalf("expected confirmed status for pre-verified BOPLA finding, got %s", status)
	}
	if bundle == nil || bundle.LeastInvasiveMethod != "ISOLATED_PROPERTY_DIFFERENTIAL" {
		t.Fatalf("expected ISOLATED_PROPERTY_DIFFERENTIAL proof method, got %+v", bundle)
	}
	if bundle.ModuleID != "bopla" || proofSummary == "" || strings.Contains(strings.ToUpper(bundle.TestIdentifier), "LOGIN") {
		t.Fatalf("expected BOPLA proof bundle (not auth login probe), got id=%q summary=%q", bundle.TestIdentifier, proofSummary)
	}

	rem := investigation.GenerateRemediationIntelligence(f, "")
	if !strings.Contains(strings.ToLower(rem.RootCause), "properties") && !strings.Contains(strings.ToLower(rem.RootCause), "allowlist") {
		t.Fatalf("expected BOPLA-specific remediation root cause, got %q", rem.RootCause)
	}
	if rem.CodeSnippet == "" {
		t.Fatal("expected BOPLA remediation code snippet")
	}
}
