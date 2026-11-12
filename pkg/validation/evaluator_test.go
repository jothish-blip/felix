package validation

import (
	"testing"
	"time"

	"felix/pkg/investigation"
	"felix/pkg/report"
)

func TestPhase8_AuthorizationGate_WindowAndExclusions(t *testing.T) {
	start := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	end := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	contract := AuthorizationContract{
		AuthorizingParty:  "Owner Security Team",
		AuthorizationRef:  "AUTH-2026-08",
		Confirmed:         true,
		AuthorizedTargets: []string{"https://app.authorized.example"},
		ExcludedPaths:     []string{"/admin/delete", "/billing/charge"},
		WindowStart:       start,
		WindowEnd:         end,
	}

	if err := ValidateAuthorizationGate(contract, "https://app.authorized.example/api/v1/items", start.Add(30*time.Minute)); err != nil {
		t.Fatalf("expected valid target within window to pass gate: %v", err)
	}
	if err := ValidateAuthorizationGate(contract, "https://app.authorized.example/admin/delete/users", start.Add(30*time.Minute)); err == nil {
		t.Fatalf("expected excluded path to be refused")
	}
	if err := ValidateAuthorizationGate(contract, "https://other.public.example/", start.Add(30*time.Minute)); err == nil {
		t.Fatalf("expected out-of-scope public domain to be refused")
	}
	if err := ValidateAuthorizationGate(contract, "https://app.authorized.example/", start.Add(-1*time.Minute)); err == nil {
		t.Fatalf("expected pre-window timestamp to be refused")
	}
	if err := ValidateAuthorizationGate(contract, "https://app.authorized.example/", end.Add(1*time.Minute)); err == nil {
		t.Fatalf("expected post-window timestamp to be refused")
	}

	unconfirmed := contract
	unconfirmed.Confirmed = false
	if err := ValidateAuthorizationGate(unconfirmed, "https://app.authorized.example/", start.Add(10*time.Minute)); err == nil {
		t.Fatalf("expected unconfirmed contract to be refused")
	}
}

func TestPhase8_EvaluateAccuracy_StrictNineStates_And_NoInconclusiveAsTN(t *testing.T) {
	establishedAt := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	executedAt := time.Date(2026, 11, 12, 10, 30, 0, 0, time.UTC)

	reg := &GroundTruthRegistry{
		RegistryID:         "gt-reg-01",
		Application:        "DeployedDemo",
		TargetOrigin:       "https://app.authorized.example",
		EstablishedAt:      establishedAt,
		EstablishedBy:      "Independent Reviewer",
		ProvenanceNote:     "Derived from source code prior to FELIX execution",
		DerivedFromScanner: false,
		Entries: []GroundTruthEntry{
			{
				ID:              "GT-TP-BOLA",
				EndpointPattern: "/api/orders/{id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  GTVulnerable,
				InScope:         true,
				Description:     "Cross-user order read",
			},
			{
				ID:              "GT-CANDIDATE-NOT-TP",
				EndpointPattern: "/api/profile/{id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  GTVulnerable,
				InScope:         true,
				Description:     "Candidate-only finding must remain FN under strict verified TP accounting",
			},
			{
				ID:              "GT-FN-SQLI",
				EndpointPattern: "/api/search",
				Method:          "GET",
				VulnClass:       "SQLI",
				ExpectedStatus:  GTVulnerable,
				InScope:         true,
				Description:     "Missed SQLi",
			},
			{
				ID:              "GT-TN-BOLA",
				EndpointPattern: "/api/users/{id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  GTNegativeControl,
				InScope:         true,
				Description:     "Protected user endpoint tested deterministically",
			},
			{
				ID:              "GT-INCONCLUSIVE-BOLA",
				EndpointPattern: "/api/invoices/{id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  GTNegativeControl,
				InScope:         true,
				Description:     "Inconclusive negative control must never count as TN",
			},
			{
				ID:              "GT-NOTTESTED-NEG",
				EndpointPattern: "/api/webhooks/{id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  GTNegativeControl,
				InScope:         true,
				Description:     "Untested negative control must remain NOT_TESTED",
			},
			{
				ID:              "GT-FP-NEG",
				EndpointPattern: "/api/catalog",
				Method:          "GET",
				VulnClass:       "BFLA",
				ExpectedStatus:  GTNegativeControl,
				InScope:         true,
				Description:     "Public endpoint falsely flagged as BFLA",
			},
			{
				ID:              "GT-NOTCONFIG",
				EndpointPattern: "/api/admin/audit",
				Method:          "GET",
				VulnClass:       "BFLA",
				ExpectedStatus:  GTVulnerable,
				InScope:         true,
				RequiresConfig:  "MULTI_ROLE",
				Description:     "Requires multi-role config if absent",
			},
			{
				ID:              "GT-SAFE-EXCL",
				EndpointPattern: "/api/reset",
				Method:          "POST",
				VulnClass:       "BFLA",
				ExpectedStatus:  GTVulnerable,
				InScope:         true,
				SafetyExcluded:  true,
				Description:     "Safety-excluded destructive check",
			},
			{
				ID:              "GT-OOS",
				EndpointPattern: "/thirdparty/widget",
				Method:          "GET",
				VulnClass:       "XSS",
				ExpectedStatus:  GTOutOfScope,
				InScope:         false,
				Description:     "Out of scope route",
			},
		},
	}

	gtHash, err := CanonicalGroundTruthSHA256(reg)
	if err != nil {
		t.Fatalf("hash gt: %v", err)
	}

	manifest := &CampaignManifest{
		ManifestID:              "camp-01",
		TargetName:              "DeployedDemo",
		TargetURL:               "https://app.authorized.example",
		Environment:             "DEPLOYED_AUTHORIZED",
		GroundTruthRegistryID:   reg.RegistryID,
		GroundTruthSHA256:       gtHash,
		GroundTruthRegisteredAt: establishedAt,
		BlindExecution:          true,
		Profile:                 "full",
		RolesConfigured:         []string{"user_a"}, // intentionally single-role so GT-NOTCONFIG -> NOT_CONFIGURED
		ExecutedAt:              executedAt,
		Authorization: AuthorizationContract{
			AuthorizingParty:  "App Owner",
			AuthorizationRef:  "AUTH-01",
			Confirmed:         true,
			AuthorizedTargets: []string{"https://app.authorized.example"},
			WindowStart:       establishedAt,
			WindowEnd:         executedAt.Add(time.Hour),
		},
	}

	rep := &report.Report{
		Target: "https://app.authorized.example",
		Summary: report.Summary{
			TotalFindings: 4,
		},
		Findings: []report.Finding{
			{
				ID:       "RECON-INFO-01",
				Category: "Attack Surface Discovery",
				Title:    "Discovered 12 attack surface endpoints on app.authorized.example",
				Severity: "INFO",
				Method:   "GET",
				Endpoint: "/",
				Verification: report.VerificationRecord{
					Status: report.VerificationNotVerified,
				},
			},
			{
				ID:       "F-BOLA-1",
				Category: "API1:2023",
				Title:    "[BOLA-USER-READ] Unauthorized Cross-User Object Read",
				Severity: "HIGH",
				Method:   "GET",
				Endpoint: "/api/orders/{id}",
				Evidence: "user_a read order #42 belonging to user_b (token=[REDACTED])",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
			{
				ID:       "F-BOLA-CAND",
				Category: "API1:2023",
				Title:    "[BOLA-CANDIDATE] Candidate on /api/profile/{id}",
				Severity: "MEDIUM",
				Method:   "GET",
				Endpoint: "/api/profile/{id}",
				Verification: report.VerificationRecord{
					Status: report.VerificationDetected, // Must NOT promote candidate to TP
				},
			},
			{
				ID:       "F-BFLA-FP",
				Category: "API5:2023",
				Title:    "[BFLA-ADMIN-ENDPOINT] False candidate on /api/catalog",
				Severity: "MEDIUM",
				Method:   "GET",
				Endpoint: "/api/catalog",
				Verification: report.VerificationRecord{
					Status: report.VerificationDetected,
				},
			},
		},
	}

	authz := &report.AuthorizationReportSummary{
		CoverageItems: []report.AuthzItemCoverageEntry{
			{Engine: "BOLA", Item: "/api/users/{id}", Outcome: "NOT_VULNERABLE"},
			{Engine: "BOLA", Item: "/api/invoices/{id}", Outcome: "INCONCLUSIVE"},
		},
	}

	retestVerdicts := []*investigation.RetestVerdict{
		{FindingID: "F-BOLA-1", RetestStatus: investigation.RetestFixDetected},
		{FindingID: "F-INCONC", RetestStatus: investigation.RetestInconclusive},
	}
	retestExpected := []RetestExpectedItem{
		{FindingID: "F-BOLA-1", GroundTruthID: "GT-TP-BOLA", ExpectedAction: "FIXED"},
		{FindingID: "F-INCONC", ExpectedAction: "FIXED"},
	}

	eval, err := EvaluateAccuracy(reg, rep, authz, retestVerdicts, retestExpected, manifest, executedAt.Add(5*time.Minute))
	if err != nil {
		t.Fatalf("EvaluateAccuracy failed: %v", err)
	}

	if !eval.BlindExecutionVerified || !eval.ManifestIntegrityOK {
		t.Fatalf("expected blind integrity verified, got blind=%v manifest=%v notes=%v", eval.BlindExecutionVerified, eval.ManifestIntegrityOK, eval.BlindnessNotes)
	}
	if eval.UniversalAccuracyClaimed {
		t.Fatalf("UniversalAccuracyClaimed must always remain false")
	}
	if !eval.RedactionAudit.Clean {
		t.Fatalf("expected redacted report to pass redaction audit, leaks=%v", eval.RedactionAudit.LeakLocations)
	}
	if !eval.ReportSummaryConsistent {
		t.Fatalf("expected summary consistency true (4 == 4)")
	}

	// Verify exact 9-state accounting:
	// Positives executable in-scope: GT-TP-BOLA (TP), GT-CANDIDATE-NOT-TP (FN + CandidateOnlyMatches=1), GT-FN-SQLI (FN) -> TP=1, FN=2
	// Negatives: GT-TN-BOLA (TN=1), GT-INCONCLUSIVE-BOLA (Inconclusive=1, NOT TN!), GT-NOTTESTED-NEG (NotTested=1, NOT TN!), GT-FP-NEG (FP=1)
	// Excluded/Unconfigured: GT-NOTCONFIG (NotConfigured=1), GT-SAFE-EXCL (SafetyExcluded=1), GT-OOS (OutOfScope=1)
	// Discovery obs ignored = 1
	c := eval.Counts
	if c.TP != 1 || c.FP != 1 || c.FN != 2 || c.TN != 1 || c.Inconclusive != 1 || c.NotTested != 1 ||
		c.NotConfigured != 1 || c.SafetyExcluded != 1 || c.OutOfScope != 1 || c.CandidateOnlyMatches != 1 ||
		c.DiscoveryObservationsIgnored != 1 {
		t.Fatalf("unexpected counts breakdown: %+v", c)
	}

	if !eval.Precision.Valid || eval.Precision.Value != 0.5 || !eval.Precision.CI95.Valid {
		t.Fatalf("expected precision=0.5 (1/2) with valid Wilson CI, got %+v", eval.Precision)
	}
	if !eval.Recall.Valid || eval.Recall.Denominator != 3 {
		t.Fatalf("expected recall denominator=3 (1/3), got %+v", eval.Recall)
	}
	if !eval.Specificity.Valid || eval.Specificity.Value != 0.5 {
		t.Fatalf("expected specificity=0.5 (1/2, excluding INCONCLUSIVE and NOT_TESTED from TN), got %+v", eval.Specificity)
	}
	// ExecutionCoverage over 6 in-scope executable items (TP=1, FN=2, TN=1, Inconclusive=1, NotTested=1) -> evaluated=5/6
	if !eval.ExecutionCoverage.Valid || eval.ExecutionCoverage.Numerator != 5 || eval.ExecutionCoverage.Denominator != 6 {
		t.Fatalf("expected execution coverage 5/6 separate from recall 1/3, got %+v", eval.ExecutionCoverage)
	}
	if eval.RetestAccuracy == nil || eval.RetestAccuracy.CorrectFixed != 1 || eval.RetestAccuracy.InconclusiveCount != 1 {
		t.Fatalf("expected retest accuracy 1 fixed + 1 inconclusive, got %+v", eval.RetestAccuracy)
	}
}

func TestPhase8_DenominatorZero_TamperedGT_And_SecretLeakDetection(t *testing.T) {
	reg := &GroundTruthRegistry{
		RegistryID:         "gt-zero",
		Application:        "EmptyScopeApp",
		TargetOrigin:       "https://empty.authorized.example",
		EstablishedAt:      time.Now().UTC(),
		DerivedFromScanner: true, // invalid! derived from scanner
		Entries: []GroundTruthEntry{
			{
				ID:             "OOS-ONLY",
				EndpointPattern: "/x",
				VulnClass:      "XSS",
				ExpectedStatus: GTOutOfScope,
				InScope:        false,
			},
		},
	}

	rep := &report.Report{
		Findings: []report.Finding{
			{
				ID:       "LEAK-1",
				Category: "Attack Surface Discovery",
				Title:    "Info",
				Evidence: "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
		},
	}

	eval, err := EvaluateAccuracy(reg, rep, nil, nil, nil, nil, time.Now().UTC())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if eval.BlindExecutionVerified {
		t.Fatalf("expected derived_from_scanner=true to fail blind verification")
	}
	if eval.Precision.Valid || eval.Recall.Valid || eval.Specificity.Valid || eval.F1Score.Valid {
		t.Fatalf("expected invalid denominators when TP/FP/FN/TN are all 0: P=%v R=%v S=%v F1=%v",
			eval.Precision.Valid, eval.Recall.Valid, eval.Specificity.Valid, eval.F1Score.Valid)
	}
	if eval.RedactionAudit.Clean || len(eval.RedactionAudit.LeakLocations) == 0 {
		t.Fatalf("expected unredacted JWT in report finding to fail redaction audit")
	}
}

func TestPhase9_Evaluator_ValidationGuards_And_NoUnverifiedCorroboration(t *testing.T) {
	now := time.Date(2026, 11, 12, 11, 0, 0, 0, time.UTC)

	// 1. Duplicate GT ID rejected
	dupReg := &GroundTruthRegistry{
		RegistryID: "dup",
		Entries: []GroundTruthEntry{
			{ID: "E1", EndpointPattern: "/a", VulnClass: "BOLA", ExpectedStatus: GTVulnerable, InScope: true},
			{ID: "E1", EndpointPattern: "/b", VulnClass: "BOLA", ExpectedStatus: GTVulnerable, InScope: true},
		},
	}
	if _, err := EvaluateAccuracy(dupReg, &report.Report{}, nil, nil, nil, nil, now); err == nil {
		t.Errorf("expected duplicate GT entry ID to be rejected")
	}

	// 2. Invalid ExpectedStatus rejected
	badStatusReg := &GroundTruthRegistry{
		RegistryID: "bad-status",
		Entries: []GroundTruthEntry{
			{ID: "E1", EndpointPattern: "/a", VulnClass: "BOLA", ExpectedStatus: "MAYBE", InScope: true},
		},
	}
	if _, err := EvaluateAccuracy(badStatusReg, &report.Report{}, nil, nil, nil, nil, now); err == nil {
		t.Errorf("expected invalid ExpectedStatus to be rejected")
	}

	// 3. Invalid RetestExpectedAction rejected
	validReg := &GroundTruthRegistry{
		RegistryID: "valid",
		Entries: []GroundTruthEntry{
			{ID: "GT-1", EndpointPattern: "/api/orders/{id}", VulnClass: "BOLA", ExpectedStatus: GTVulnerable, InScope: true},
			{ID: "GT-HDR", EndpointPattern: "/", VulnClass: "SECURITY_HEADERS", ExpectedStatus: GTNegativeControl, InScope: true},
		},
	}
	if _, err := EvaluateAccuracy(validReg, &report.Report{}, nil, nil, []RetestExpectedItem{{FindingID: "F1", ExpectedAction: "MAYBE_FIXED"}}, nil, now); err == nil {
		t.Errorf("expected invalid Retest ExpectedAction to be rejected")
	}

	// 4. Unverified finding matching a verified GT entry must NOT get OutcomeTP as corroborating evidence,
	//    and SECURITY_HEADERS negative control with only DISCOVERY_OBSERVATION on custom profile must remain NOT_TESTED.
	customManifest := &CampaignManifest{
		ManifestID: "m-custom",
		Profile:    "custom",
	}
	rep := &report.Report{
		Findings: []report.Finding{
			{
				ID:       "RECON-1",
				Category: "Attack Surface Discovery",
				Title:    "Discovered endpoints",
				Endpoint: "/",
			},
			{
				ID:       "F-VER",
				Category: "API1:2023",
				Title:    "[BOLA] Verified order read",
				Endpoint: "/api/orders/1",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
			{
				ID:       "F-UNVER",
				Category: "API1:2023",
				Title:    "[BOLA] Unverified order candidate",
				Endpoint: "/api/orders/2",
				Verification: report.VerificationRecord{
					Status: report.VerificationDetected,
				},
			},
		},
	}
	rep.Summary.TotalFindings = len(rep.Findings)

	eval, err := EvaluateAccuracy(validReg, rep, nil, nil, nil, customManifest, now)
	if err != nil {
		t.Fatalf("unexpected EvaluateAccuracy error: %v", err)
	}
	if eval.Counts.TN != 0 || eval.Counts.NotTested != 1 {
		t.Errorf("expected SECURITY_HEADERS with custom profile + DISCOVERY_OBSERVATION only to be NOT_TESTED (TN=0, NotTested=1), got TN=%d NotTested=%d", eval.Counts.TN, eval.Counts.NotTested)
	}
	for _, item := range eval.EvidenceComparison {
		if item.FindingID == "F-UNVER" && item.Outcome == OutcomeTP {
			t.Errorf("unverified candidate F-UNVER must NEVER be recorded as OutcomeTP in EvidenceComparison")
		}
	}
}
