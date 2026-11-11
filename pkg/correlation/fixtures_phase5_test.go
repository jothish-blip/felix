package correlation

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"felix/pkg/auth"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Fixture A — Valid Credential -> Identity Verification -> BOLA Object Access
func TestPhase5_FixtureA_ValidCredentialToBOLA(t *testing.T) {
	const rawSecret = "tok_live_userb_phase5_987654321"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/config.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`window.CFG = { token: "` + rawSecret + `" };`))
		case "/api/me":
			if authHdr != "Bearer "+rawSecret {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"identity":"user_b","role":"USER"}`))
		case "/api/orders/101":
			if authHdr != "Bearer "+rawSecret {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"order_id":101,"owner":"user_a","secret_note":"UserA confidential order #101"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	findings := []report.Finding{
		{
			ID:         "F-A-CRED",
			Title:      "Exposed Bearer API Token in Client Bundle",
			Category:   "secrets-exposure",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     ts.URL + "/config.js",
			Endpoint:   ts.URL + "/config.js",
			Method:     http.MethodGet,
			Evidence:   "Exposed high-entropy secret token observed in client bundle (" + secrets.CredentialFingerprint(rawSecret) + ")",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "Secret pattern verified in /config.js",
			},
			EvidenceDetails: report.EvidenceDetails{
				Observation: "Client JS exposes bearer credential",
				Location:    ts.URL + "/config.js",
				Details: map[string]string{
					"token_type":        "bearer",
					"intended_identity": "USER_B",
					"auth_check_url":    ts.URL + "/api/me",
				},
			},
		},
		{
			ID:         "F-A-BOLA",
			Title:      "BOLA Unauthorized Cross-Tenant Order Read",
			Category:   "bola",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     ts.URL + "/api/orders/101",
			Endpoint:   ts.URL + "/api/orders/101",
			Method:     http.MethodGet,
			Evidence:   "USER_B retrieved USER_A order record 101 without authorization check",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "Cross-tenant BOLA access confirmed",
			},
			EvidenceDetails: report.EvidenceDetails{
				Observation:      "Foreign user order returned HTTP 200",
				ExpectedBehavior: "HTTP 403 Forbidden for non-owner USER_B",
				ObservedBehavior: "HTTP 200 returned owner user_a record to USER_B",
				Location:         ts.URL + "/api/orders/101",
				Details: map[string]string{
					"auth_required":   "true",
					"owner_identity":  "USER_A",
					"expected_marker": "UserA confidential order #101",
				},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, err := engine.Correlate(context.Background(), findings)
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}
	if len(paths) == 0 {
		t.Fatalf("expected candidate credential->BOLA path from Correlate")
	}
	// Prior to Phase 5 validation, engine alone MUST NOT mark the multi-step path CONFIRMED/VERIFIED
	for _, p := range paths {
		if IsConfirmedStatus(p.Status) {
			t.Fatalf("static correlation alone must not mark path CONFIRMED/VERIFIED (got %s)", p.Status)
		}
	}

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:           ts.URL,
		BaseClient:          ts.Client(),
		AllowLoopback:       true,
		RawCredentialTokens: map[string]string{"F-A-CRED": rawSecret},
	})
	valPaths, valRels, valSum := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)
	if len(valPaths) != 1 {
		t.Fatalf("expected 1 validated path, got %d", len(valPaths))
	}

	vp := valPaths[0]
	if vp.Status != PathConfirmed {
		t.Fatalf("expected Status CONFIRMED, got %s (rationale: %s)", vp.Status, vp.ConfidenceRationale)
	}
	if vp.ReachabilityStatus != ReachabilityReachable {
		t.Errorf("expected ReachabilityStatus REACHABLE, got %s", vp.ReachabilityStatus)
	}
	if vp.VerifiedTransitions != 1 || vp.UnverifiedTransitions != 0 {
		t.Errorf("expected 1 verified / 0 unverified transitions, got %d/%d", vp.VerifiedTransitions, vp.UnverifiedTransitions)
	}
	if len(vp.CredentialValidations) != 1 {
		t.Fatalf("expected 1 CredentialVerificationResult, got %d", len(vp.CredentialValidations))
	}
	cv := vp.CredentialValidations[0]
	if cv.Status != CredVerified || cv.ObservedIdentity != "USER_B" || !cv.IdentityMatched {
		t.Errorf("unexpected credential validation: %+v", cv)
	}
	if !strings.HasPrefix(cv.TokenFingerprint, "sha256:") {
		t.Errorf("expected sha256 fingerprint on credential validation, got %q", cv.TokenFingerprint)
	}
	if len(vp.StepVerifications) != 2 {
		t.Fatalf("expected 2 StepVerifications (entry + hop), got %d", len(vp.StepVerifications))
	}
	hop := vp.StepVerifications[1]
	if hop.EntryCondition == "" || hop.RequiredIdentity == "" || hop.RequiredPermissions == "" ||
		hop.TargetResource == "" || hop.ExpectedResult == "" || hop.ObservedResult == "" ||
		len(hop.EvidenceRefs) == 0 || hop.NextStepReachable != ReachabilityReachable {
		t.Errorf("step verification missing required 8 Phase 5 properties: %+v", hop)
	}

	// Verify NO raw secret leaks anywhere in validated path, relationships, or JSON serialization
	rawBytes, _ := json.Marshal(struct {
		Paths   []AttackPath   `json:"paths"`
		Rels    []Relationship `json:"rels"`
		Summary *Summary       `json:"summary"`
	}{valPaths, valRels, valSum})
	if strings.Contains(string(rawBytes), rawSecret) {
		t.Fatalf("CRITICAL: raw secret %q leaked into serialized validation output!", rawSecret)
	}
}

// Fixture B — Documentation/Placeholder Credential (AKIAIOSFODNN7EXAMPLE) Rejected as INVALID
func TestPhase5_FixtureB_PlaceholderCredentialInvalid(t *testing.T) {
	const awsExample = "AKIAIOSFODNN7EXAMPLE"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"identity":"admin","order":"secret"}`))
	}))
	defer ts.Close()

	findings := []report.Finding{
		{
			ID:         "F-B-PH",
			Title:      "Exposed AWS Access Key Pattern in Docs JS",
			Category:   "secrets-exposure",
			Severity:   report.SeverityMedium,
			Confidence: report.ConfidenceMedium,
			Target:     ts.URL + "/docs/example.js",
			Endpoint:   ts.URL + "/docs/example.js",
			Method:     http.MethodGet,
			Evidence:   `const exampleKey = "` + awsExample + `";`,
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"auth_check_url": ts.URL + "/api/me",
				},
			},
		},
		{
			ID:         "F-B-BOLA",
			Title:      "BOLA Account Data Endpoint",
			Category:   "bola",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     ts.URL + "/api/accounts/2",
			Endpoint:   ts.URL + "/api/accounts/2",
			Method:     http.MethodGet,
			Evidence:   "Cross-tenant read observed",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{"auth_required": "true"},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, err := engine.Correlate(context.Background(), findings)
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:           ts.URL,
		BaseClient:          ts.Client(),
		AllowLoopback:       true,
		RawCredentialTokens: map[string]string{"F-B-PH": awsExample},
	})
	valPaths, valRels, valSum := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)

	if len(valPaths) != 0 {
		t.Fatalf("placeholder credential MUST NOT produce any validated/retained attack path; got %d path(s): %+v", len(valPaths), valPaths)
	}
	if valSum.ConfirmedPaths != 0 {
		t.Errorf("expected 0 ConfirmedPaths, got %d", valSum.ConfirmedPaths)
	}
	foundInvalidRel := false
	for _, r := range valRels {
		if r.SourceFindingID == "F-B-PH" && r.ValidationStatus == ValidationInvalid {
			foundInvalidRel = true
		}
	}
	if !foundInvalidRel {
		t.Errorf("expected explicit INVALID relationship classification for placeholder key %s", awsExample)
	}
}

// Fixture C — Two Genuine Unrelated Vulnerabilities Must NOT Be Joined Into an Attack Path
func TestPhase5_FixtureC_UnrelatedVulnsDisconnected(t *testing.T) {
	findings := []report.Finding{
		{
			ID:         "F-C-XSS",
			Title:      "Reflected XSS on Search Widget",
			Category:   "xss",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     "http://127.0.0.1:18080/search?q=test",
			Endpoint:   "http://127.0.0.1:18080/search",
			Method:     http.MethodGet,
			Evidence:   "Reflected unescaped script tag in search body",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
		},
		{
			ID:         "F-C-COOKIE",
			Title:      "Cookie Missing SameSite Flag on Analytics Path",
			Category:   "cookie-security",
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceHigh,
			Target:     "http://127.0.0.1:18080/analytics/ping",
			Endpoint:   "http://127.0.0.1:18080/analytics/ping",
			Method:     http.MethodGet,
			Evidence:   "Set-Cookie: _ga=1; Path=/",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, err := engine.Correlate(context.Background(), findings)
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	validator := NewPhase5Validator(ValidationOptions{TargetURL: "http://127.0.0.1:18080"})
	valPaths, _, valSum := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)

	if len(valPaths) != 0 {
		t.Fatalf("unrelated findings on same host MUST NOT generate any attack path; got %d paths: %+v", len(valPaths), valPaths)
	}
	if valSum.TotalFindings != 2 {
		t.Errorf("expected 2 preserved individual findings, got %d", valSum.TotalFindings)
	}

	// Also verify report.EnrichAttackPathGraph does not synthesize arbitrary connections
	emptyPath := report.AttackPathSummary{ID: "EMPTY-UNRELATED"}
	report.EnrichAttackPathGraph(&emptyPath, findings)
	if len(emptyPath.GraphNodes) != 0 || len(emptyPath.NodeIDs) != 0 {
		t.Errorf("EnrichAttackPathGraph MUST NOT auto-link unrelated findings into arbitrary nodes/edges")
	}
}

// Fixture D — Broken Transition (HTTP 403 / 302 -> /login) Classified NOT_REACHABLE
func TestPhase5_FixtureD_BrokenTransitionNotReachable(t *testing.T) {
	const rawSecret = "tok_live_userb_restricted_555666777"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/me":
			if r.Header.Get("Authorization") == "Bearer "+rawSecret {
				_, _ = w.Write([]byte(`{"identity":"user_b","role":"USER"}`))
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		case "/api/admin/export":
			// Transition is BLOCKED by RBAC!
			http.Error(w, `{"error":"forbidden: admin role required"}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	findings := []report.Finding{
		{
			ID:       "F-D-CRED",
			Title:    "Exposed Session Token",
			Category: "secrets-exposure",
			Severity: report.SeverityHigh,
			Target:   ts.URL + "/bundle.js",
			Endpoint: ts.URL + "/bundle.js",
			Method:   http.MethodGet,
			Evidence: "Credential token disclosed in client script",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"token_type":        "bearer",
					"intended_identity": "USER_B",
					"auth_check_url":    ts.URL + "/api/me",
				},
			},
		},
		{
			ID:       "F-D-BFLA",
			Title:    "Suspected BFLA Admin Export Endpoint",
			Category: "bfla",
			Severity: report.SeverityHigh,
			Target:   ts.URL + "/api/admin/export",
			Endpoint: ts.URL + "/api/admin/export",
			Method:   http.MethodGet,
			Evidence: "Admin export route discovered during crawl",
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{"auth_required": "true"},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, _ := engine.Correlate(context.Background(), findings)

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:           ts.URL,
		BaseClient:          ts.Client(),
		AllowLoopback:       true,
		RawCredentialTokens: map[string]string{"F-D-CRED": rawSecret},
	})
	valPaths, _, _ := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)
	if len(valPaths) != 1 {
		t.Fatalf("expected 1 evaluated path with NOT_REACHABLE status, got %d", len(valPaths))
	}
	vp := valPaths[0]
	if vp.Status != PathNotReachable {
		t.Errorf("expected Status NOT_REACHABLE, got %s", vp.Status)
	}
	if vp.ReachabilityStatus != ReachabilityNotReachable {
		t.Errorf("expected ReachabilityStatus NOT_REACHABLE, got %s", vp.ReachabilityStatus)
	}
	if len(vp.StepVerifications) < 2 || vp.StepVerifications[1].NextStepReachable != ReachabilityNotReachable {
		t.Errorf("expected step 1 NextStepReachable=NOT_REACHABLE, got %+v", vp.StepVerifications)
	}
}

// Fixture E — Identity Mismatch Rejected (Claimed ADMIN vs Observed USER_A, and UserA != Admin on isolated transport)
func TestPhase5_FixtureE_IdentityMismatch(t *testing.T) {
	const userAToken = "tok_live_usera_identity_mismatch_111"
	const adminToken = "tok_live_admin_real_999"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/me":
			if authHdr == "Bearer "+userAToken {
				_, _ = w.Write([]byte(`{"identity":"user_a","role":"standard_user"}`))
				return
			}
			if authHdr == "Bearer "+adminToken {
				_, _ = w.Write([]byte(`{"identity":"admin","role":"admin"}`))
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		case "/api/admin/audit":
			if authHdr == "Bearer "+adminToken {
				_, _ = w.Write([]byte(`{"audit_log":["entry1","entry2"]}`))
				return
			}
			http.Error(w, `{"error":"forbidden: admin only"}`, http.StatusForbidden)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()

	// E1: Leaked credential resolves to USER_A while finding claims intended_identity=ADMIN
	findings := []report.Finding{
		{
			ID:       "F-E-CRED",
			Title:    "Leaked Token Claimed as Admin Key",
			Category: "secrets-exposure",
			Severity: report.SeverityHigh,
			Target:   ts.URL + "/env.js",
			Endpoint: ts.URL + "/env.js",
			Method:   http.MethodGet,
			Evidence: "Claimed admin credential observed",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"token_type":        "bearer",
					"intended_identity": "ADMIN",
					"auth_check_url":    ts.URL + "/api/me",
				},
			},
		},
		{
			ID:       "F-E-ADMIN",
			Title:    "Admin Audit Function Access",
			Category: "bfla",
			Severity: report.SeverityHigh,
			Target:   ts.URL + "/api/admin/audit",
			Endpoint: ts.URL + "/api/admin/audit",
			Method:   http.MethodGet,
			Evidence: "Admin endpoint reference",
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{"auth_required": "true"},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, _ := engine.Correlate(context.Background(), findings)

	// Wire real Phase 2 IdentityManager verifying strict isolation between USER_A and ADMIN
	mgr, err := auth.NewIdentityManager(auth.IdentityManagerOptions{
		TargetURL:     ts.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewIdentityManager failed: %v", err)
	}
	mgr.SetBearerToken(auth.IdentityUserA, auth.RoleVictim, userAToken)
	mgr.SetBearerToken(auth.IdentityAdmin, auth.RoleAdmin, adminToken)

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:           ts.URL,
		IdentityManager:     mgr,
		AllowLoopback:       true,
		RawCredentialTokens: map[string]string{"F-E-CRED": userAToken},
	})
	valPaths, valRels, _ := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)

	if len(valPaths) != 0 {
		t.Fatalf("identity-mismatched credential MUST NOT yield valid attack path; got %d (status=%s rationale=%s creds=%+v rels=%+v)",
			len(valPaths), valPaths[0].Status, valPaths[0].ConfidenceRationale, valPaths[0].CredentialValidations, valRels)
	}
	matchedMismatch := false
	for _, r := range valRels {
		if r.CredentialValidation != nil && !r.CredentialValidation.IdentityMatched && r.CredentialValidation.Status == CredInvalid {
			matchedMismatch = true
		}
	}
	if !matchedMismatch {
		t.Errorf("expected CredentialValidation with Status=INVALID and IdentityMatched=false")
	}

	// E2: Multi-identity isolation via real AuthenticatedTransport: edge claims identity USER_A -> target admin route rejects USER_A (403)
	edgeReqAdmin := AttackPath{
		ID:      "PATH-E2-IDENTITY-ISO",
		Title:   "User A Attempting Admin-Only Transition",
		NodeIDs: []string{"F-E2-SRC", "F-E2-DST"},
		Nodes: NormalizeFindings([]report.Finding{
			{
				ID: "F-E2-SRC", Title: "User A Authenticated Session", Category: "auth-bypass", Severity: report.SeverityMedium,
				Target: ts.URL + "/api/me", Endpoint: ts.URL + "/api/me", Method: http.MethodGet, Evidence: "User A session confirmed",
				Verification:    report.VerificationRecord{Status: report.VerificationVerified},
				EvidenceDetails: report.EvidenceDetails{Details: map[string]string{"identity": "USER_A"}},
			},
			{
				ID: "F-E2-DST", Title: "Admin Audit Endpoint", Category: "bfla", Severity: report.SeverityHigh,
				Target: ts.URL + "/api/admin/audit", Endpoint: ts.URL + "/api/admin/audit", Method: http.MethodGet, Evidence: "Admin endpoint target",
				Verification:    report.VerificationRecord{Status: report.VerificationDetected},
				EvidenceDetails: report.EvidenceDetails{Details: map[string]string{"required_identity": "ADMIN", "accessor_identity": "USER_A"}},
			},
		}),
		Edges: []Relationship{{
			ID: "REL-E2", SourceFindingID: "F-E2-SRC", TargetFindingID: "F-E2-DST",
			SourceTitle: "User A Authenticated Session", TargetTitle: "Admin Audit Endpoint",
			Type: RelPrivEscRestricted, RuleCode: RuleCOR05, ValidationStatus: ValidationCandidate,
			IdentityContext: "USER_A", EvidenceReferences: []string{"ev-e2-1"},
		}},
	}
	e2Paths, _, _ := validator.ValidateAttackPaths(context.Background(), nil, []AttackPath{edgeReqAdmin}, edgeReqAdmin.Edges, &Summary{})
	if len(e2Paths) != 1 || e2Paths[0].Status != PathNotReachable {
		t.Fatalf("expected isolated USER_A probe against admin endpoint to fail with NOT_REACHABLE, got %+v", e2Paths)
	}
}

// Fixture F — Missing Supporting Evidence Cannot Confirm Path
func TestPhase5_FixtureF_MissingEvidenceCannotConfirm(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user":"bob","account_id":42,"balance":500}`))
	}))
	defer ts.Close()

	f1 := NormalizeFindings([]report.Finding{{
		ID:       "F-F-1",
		Title:    "JWT Weakness",
		Category: "auth-bypass",
		Severity: report.SeverityHigh,
		Target:   ts.URL + "/login",
		Endpoint: ts.URL + "/login",
		Method:   http.MethodGet,
		// Intentionally EMPTY Evidence and unverified
		Verification: report.VerificationRecord{Status: report.VerificationDetected},
	}})[0]
	f2 := NormalizeFindings([]report.Finding{{
		ID:       "F-F-2",
		Title:    "BOLA User Record",
		Category: "bola",
		Severity: report.SeverityHigh,
		Target:   ts.URL + "/api/users/42",
		Endpoint: ts.URL + "/api/users/42",
		Method:   http.MethodGet,
		// Intentionally EMPTY Evidence and unverified
		Verification: report.VerificationRecord{Status: report.VerificationDetected},
	}})[0]

	path := AttackPath{
		ID:      "PATH-MISSING-EV",
		Title:   "Missing Evidence Chain",
		NodeIDs: []string{f1.ID, f2.ID},
		Nodes:   []NormalizedFinding{f1, f2},
		Edges: []Relationship{{
			ID:                 "REL-MISSING-EV",
			SourceFindingID:    f1.ID,
			TargetFindingID:    f2.ID,
			SourceTitle:        f1.Title,
			TargetTitle:        f2.Title,
			Type:               RelEnables,
			RuleCode:           RuleCOR02,
			ValidationStatus:   ValidationCandidate,
			EvidenceReferences: nil, // Intentionally missing
		}},
		Status: PathCandidate,
	}

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:     ts.URL,
		BaseClient:    ts.Client(),
		AllowLoopback: true,
	})
	valPaths, _, _ := validator.ValidateAttackPaths(context.Background(), nil, []AttackPath{path}, path.Edges, &Summary{})
	if len(valPaths) != 1 {
		t.Fatalf("expected 1 path result, got %d", len(valPaths))
	}
	vp := valPaths[0]
	if IsConfirmedStatus(vp.Status) {
		t.Fatalf("missing finding/edge evidence MUST NOT allow CONFIRMED status, got %s", vp.Status)
	}
	if vp.StepVerifications[1].ValidationStatus == ValidationConfirmed {
		t.Errorf("expected step 1 not to be CONFIRMED when finding & edge evidence refs are absent")
	}
}

// Fixture G — False Impact HTTP 200 Rejected (Login HTML, Stub JSON {}, {"status":"ok"}, Missing Victim Data)
func TestPhase5_FixtureG_FalseImpactHTTP200Rejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login-200":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><h1>Sign In</h1><form><input type="password"/></form></body></html>`))
		case "/stub-ok":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		case "/empty-obj":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		case "/no-marker":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"info":"public catalog item"}`))
		}
	}))
	defer ts.Close()

	subcases := []struct {
		name     string
		endpoint string
		details  map[string]string
	}{
		{"HTML_Login_HTTP_200", "/login-200", map[string]string{}},
		{"Generic_Status_OK_200", "/stub-ok", map[string]string{}},
		{"Empty_JSON_200", "/empty-obj", map[string]string{}},
		{"Missing_Victim_Marker_200", "/no-marker", map[string]string{"expected_marker": "UserA_Secret_SSN"}},
	}

	for _, sc := range subcases {
		t.Run(sc.name, func(t *testing.T) {
			fSrc := NormalizeFindings([]report.Finding{{
				ID:       "F-G-SRC",
				Title:    "Auth Entrypoint",
				Category: "auth-bypass",
				Severity: report.SeverityHigh,
				Target:   ts.URL + "/entry",
				Endpoint: ts.URL + "/entry",
				Evidence: "Entry probe verified",
				Verification: report.VerificationRecord{Status: report.VerificationVerified},
			}})[0]
			fDst := NormalizeFindings([]report.Finding{{
				ID:       "F-G-DST",
				Title:    "Suspected BOLA Resource",
				Category: "bola",
				Severity: report.SeverityHigh,
				Target:   ts.URL + sc.endpoint,
				Endpoint: ts.URL + sc.endpoint,
				Method:   http.MethodGet,
				Evidence: "Observed HTTP 200 on endpoint",
				Verification: report.VerificationRecord{Status: report.VerificationVerified},
				EvidenceDetails: report.EvidenceDetails{
					Details: sc.details,
				},
			}})[0]

			edge := Relationship{
				ID:                 "REL-G",
				SourceFindingID:    fSrc.ID,
				TargetFindingID:    fDst.ID,
				SourceTitle:        fSrc.Title,
				TargetTitle:        fDst.Title,
				Type:               RelBACCrossTenant,
				RuleCode:           RuleCOR02,
				ValidationStatus:   ValidationCandidate,
				EvidenceReferences: []string{"ev-g-1"},
			}
			p := AttackPath{
				ID:      "PATH-G-" + sc.name,
				Title:   "False Impact Trap",
				NodeIDs: []string{fSrc.ID, fDst.ID},
				Nodes:   []NormalizedFinding{fSrc, fDst},
				Edges:   []Relationship{edge},
				Status:  PathCandidate,
			}

			validator := NewPhase5Validator(ValidationOptions{
				TargetURL:     ts.URL,
				BaseClient:    ts.Client(),
				AllowLoopback: true,
			})
			valPaths, _, _ := validator.ValidateAttackPaths(context.Background(), nil, []AttackPath{p}, []Relationship{edge}, &Summary{})
			if len(valPaths) != 1 {
				t.Fatalf("expected 1 path outcome, got %d", len(valPaths))
			}
			vp := valPaths[0]
			if IsConfirmedStatus(vp.Status) || vp.Status == PathHighConfidence {
				t.Fatalf("soft-200 / false impact HTTP 200 (%s) MUST NOT confirm path, got %s", sc.name, vp.Status)
			}
			if vp.StepVerifications[1].ImpactVerified {
				t.Errorf("expected ImpactVerified=false on %s", sc.name)
			}
		})
	}
}

// Fixture H — Graph Integrity (Reject Cycles, Duplicate Edges, Self-Loops, Missing/Invalid References)
func TestPhase5_FixtureH_GraphIntegrity(t *testing.T) {
	nA := NormalizedFinding{ID: "N-A", Title: "Node A", Category: "auth", Endpoint: "/a"}
	nB := NormalizedFinding{ID: "N-B", Title: "Node B", Category: "bola", Endpoint: "/b"}

	// 1. Cycle detection in NewAttackGraph + Phase5Validator
	cyclicRels := []Relationship{
		{ID: "E-AB", SourceFindingID: "N-A", TargetFindingID: "N-B", Type: RelEnables, RuleCode: RuleCOR02, ValidationStatus: ValidationCandidate, EvidenceReferences: []string{"ev1"}},
		{ID: "E-BA", SourceFindingID: "N-B", TargetFindingID: "N-A", Type: RelEnables, RuleCode: RuleCOR05, ValidationStatus: ValidationCandidate, EvidenceReferences: []string{"ev2"}},
	}
	g := NewAttackGraph([]NormalizedFinding{nA, nB}, cyclicRels)
	if !g.Validation.HasCycle || g.Validation.IsValid {
		t.Errorf("expected NewAttackGraph to flag cycle cleanly, got %+v", g.Validation)
	}

	validator := NewPhase5Validator(ValidationOptions{TargetURL: "http://127.0.0.1:8080"})
	cyclicPath := AttackPath{
		ID:      "PATH-CYCLE",
		NodeIDs: []string{"N-A", "N-B", "N-A"},
		Nodes:   []NormalizedFinding{nA, nB},
		Edges:   cyclicRels,
	}
	valPaths, _, _ := validator.ValidateAttackPaths(context.Background(), nil, []AttackPath{cyclicPath}, cyclicRels, &Summary{})
	if len(valPaths) != 0 {
		t.Errorf("expected cyclic path to be rejected by Phase5Validator, got %d paths", len(valPaths))
	}

	// 2. Self-loop + duplicate + invalid edge + missing node ID rejection
	badRels := []Relationship{
		{ID: "E-SELF", SourceFindingID: "N-A", TargetFindingID: "N-A", Type: RelEnables, RuleCode: RuleCOR02},
		{ID: "E-MISS", SourceFindingID: "N-A", TargetFindingID: "N-UNKNOWN", Type: RelEnables, RuleCode: RuleCOR02},
		{ID: "E-INV", SourceFindingID: "N-A", TargetFindingID: "N-B", Type: RelCredEnablesAccess, RuleCode: RuleCORCredPivot, ValidationStatus: ValidationInvalid},
	}
	g2 := NewAttackGraph([]NormalizedFinding{nA, nB}, badRels)
	if len(g2.Edges) != 0 || len(g2.Validation.Errors) < 3 {
		t.Errorf("expected self-loop, missing target, and INVALID edges to be rejected; edges=%d errors=%v", len(g2.Edges), g2.Validation.Errors)
	}
}

// Fixture I — Partial Path Honesty (2 Verified Transitions + 1 Unverified Transition -> HIGH_CONFIDENCE, NEVER CONFIRMED)
func TestPhase5_FixtureI_PartialPathHonesty(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/session":
			_, _ = w.Write([]byte(`{"session_token":"ephemeral_session_ok","role":"user_b"}`))
		case "/api/users/user_a/profile":
			_, _ = w.Write([]byte(`{"user":"user_a","email":"alice@corp.test","ssn_last4":"4321"}`))
		case "/api/admin/rotate":
			_, _ = w.Write([]byte(`{"rotated":true}`))
		}
	}))
	defer ts.Close()

	findings := []report.Finding{
		{
			ID: "F-I-0", Title: "Public Onboarding Route", Category: "exposure", Severity: report.SeverityMedium,
			Target: ts.URL + "/onboard", Endpoint: ts.URL + "/onboard", Method: http.MethodGet,
			Evidence: "Public entrypoint confirmed", Verification: report.VerificationRecord{Status: report.VerificationVerified},
		},
		{
			ID: "F-I-1", Title: "Broken Session Issuance", Category: "auth-bypass", Severity: report.SeverityHigh,
			Target: ts.URL + "/api/session", Endpoint: ts.URL + "/api/session", Method: http.MethodGet,
			Evidence: "Session issued without verification", Verification: report.VerificationRecord{Status: report.VerificationVerified},
			EvidenceDetails: report.EvidenceDetails{Details: map[string]string{"expected_marker": "ephemeral_session_ok"}},
		},
		{
			ID: "F-I-2", Title: "BOLA Profile Disclosure", Category: "bola", Severity: report.SeverityHigh,
			Target: ts.URL + "/api/users/user_a/profile", Endpoint: ts.URL + "/api/users/user_a/profile", Method: http.MethodGet,
			Evidence: "Cross-tenant profile exposure", Verification: report.VerificationRecord{Status: report.VerificationVerified},
			EvidenceDetails: report.EvidenceDetails{Details: map[string]string{"expected_marker": "alice@corp.test"}},
		},
		{
			ID: "F-I-3", Title: "Admin Key Rotation State Mutation", Category: "bfla", Severity: report.SeverityCritical,
			Target: ts.URL + "/api/admin/rotate", Endpoint: ts.URL + "/api/admin/rotate", Method: http.MethodPost,
			Evidence: "Admin state-changing route inferred from OpenAPI spec", Verification: report.VerificationRecord{Status: report.VerificationDetected},
			// State-changing POST without AllowStateChanging will safely remain NOT_TESTED!
		},
	}

	norm := NormalizeFindings(findings)
	edges := []Relationship{
		{
			ID: "E-I-1", SourceFindingID: "F-I-0", TargetFindingID: "F-I-1",
			SourceTitle: norm[0].Title, TargetTitle: norm[1].Title,
			Type: RelReaches, RuleCode: RuleCOR01, ValidationStatus: ValidationCandidate,
			EvidenceReferences: []string{"ev-i-01"},
		},
		{
			ID: "E-I-2", SourceFindingID: "F-I-1", TargetFindingID: "F-I-2",
			SourceTitle: norm[1].Title, TargetTitle: norm[2].Title,
			Type: RelBACCrossTenant, RuleCode: RuleCOR02, ValidationStatus: ValidationCandidate,
			EvidenceReferences: []string{"ev-i-12"},
		},
		{
			ID: "E-I-3", SourceFindingID: "F-I-2", TargetFindingID: "F-I-3",
			SourceTitle: norm[2].Title, TargetTitle: norm[3].Title,
			Type: RelPrivEscRestricted, RuleCode: RuleCOR05, ValidationStatus: ValidationCandidate,
			EvidenceReferences: []string{"ev-i-23"},
		},
	}
	partialPath := AttackPath{
		ID:      "PATH-PARTIAL-I",
		Title:   "3-Transition Partial Validation Chain",
		NodeIDs: []string{"F-I-0", "F-I-1", "F-I-2", "F-I-3"},
		Nodes:   norm,
		Edges:   edges,
		Status:  PathCandidate,
	}

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:          ts.URL,
		BaseClient:         ts.Client(),
		AllowLoopback:      true,
		AllowStateChanging: false, // Step 3 POST /api/admin/rotate MUST stay non-destructive NOT_TESTED
	})
	valPaths, _, valSum := validator.ValidateAttackPaths(context.Background(), findings, []AttackPath{partialPath}, edges, &Summary{})
	if len(valPaths) != 1 {
		t.Fatalf("expected 1 path, got %d", len(valPaths))
	}
	vp := valPaths[0]
	if IsConfirmedStatus(vp.Status) {
		t.Fatalf("CRITICAL: partial path (2 verified + 1 unverified) MUST NOT be promoted to CONFIRMED; got %s", vp.Status)
	}
	if vp.Status != PathHighConfidence {
		t.Errorf("expected Status HIGH_CONFIDENCE for 2 verified + 1 unverified partial path, got %s (rationale: %s)", vp.Status, vp.ConfidenceRationale)
	}
	if vp.VerifiedTransitions != 2 || vp.UnverifiedTransitions != 1 {
		t.Errorf("expected VerifiedTransitions=2, UnverifiedTransitions=1, got %d/%d", vp.VerifiedTransitions, vp.UnverifiedTransitions)
	}
	if vp.UnverifiedImpact == "" || len(vp.Limitations) == 0 {
		t.Errorf("expected UnverifiedImpact and Limitations to document unverified 3rd step; got unverified=%q limits=%v", vp.UnverifiedImpact, vp.Limitations)
	}
	if valSum.ConfirmedPaths != 0 || valSum.HighConfidencePaths != 1 {
		t.Errorf("expected summary ConfirmedPaths=0, HighConfidencePaths=1; got %+v", valSum)
	}
}

// Fixture J — Negative Secure Controls (Proper Authz + Proper Ownership -> Zero Confirmed Attack Paths)
func TestPhase5_FixtureJ_NegativeSecureControls(t *testing.T) {
	const userBToken = "tok_secure_userb_000"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/api/orders/101":
			// Enforces strict ownership: USER_B cannot access USER_A object -> 403
			http.Error(w, `{"error":"forbidden: resource belongs to another user"}`, http.StatusForbidden)
		case "/api/admin/users":
			// Enforces strict admin RBAC -> 403
			http.Error(w, `{"error":"forbidden: admin role required"}`, http.StatusForbidden)
		case "/api/me":
			if authHdr == "Bearer "+userBToken {
				_, _ = w.Write([]byte(`{"identity":"user_b"}`))
				return
			}
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		}
	}))
	defer ts.Close()

	mgr, err := auth.NewIdentityManager(auth.IdentityManagerOptions{
		TargetURL:     ts.URL,
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("NewIdentityManager failed: %v", err)
	}
	mgr.SetBearerToken(auth.IdentityUserB, auth.RoleAttacker, userBToken)

	// Hardened target observations (secure cookie / defended probes -> zero exploitable vuln findings)
	findings := []report.Finding{
		{
			ID: "F-J-SAFE-1", Title: "HTTP Strict-Transport-Security Header Check", Category: "security-headers",
			Severity: report.SeverityInfo, Target: ts.URL + "/", Endpoint: ts.URL + "/",
			Verification: report.VerificationRecord{Status: report.VerificationNotExposed},
		},
		{
			ID: "F-J-SAFE-2", Title: "Order Endpoint Access Control Check", Category: "bola",
			Severity: report.SeverityInfo, Target: ts.URL + "/api/orders/101", Endpoint: ts.URL + "/api/orders/101",
			Method:   http.MethodGet,
			Evidence: "Access properly denied with HTTP 403 for non-owner USER_B",
			Verification: report.VerificationRecord{Status: report.VerificationNotExposed},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{"auth_required": "true", "accessor_identity": "USER_B"},
			},
		},
	}

	cfg := DefaultConfig()
	cfg.RequireValidatedTransitions = true
	engine := NewEngine(cfg)
	sum, paths, rels, _ := engine.Correlate(context.Background(), findings)

	validator := NewPhase5Validator(ValidationOptions{
		TargetURL:       ts.URL,
		IdentityManager: mgr,
		AllowLoopback:   true,
	})
	valPaths, _, valSum := validator.ValidateAttackPaths(context.Background(), findings, paths, rels, sum)

	if len(valPaths) != 0 {
		t.Fatalf("negative secure controls MUST yield 0 attack paths, got %d: %+v", len(valPaths), valPaths)
	}
	if valSum.ConfirmedPaths != 0 || valSum.ConfirmedRelationships != 0 {
		t.Errorf("expected 0 ConfirmedPaths and 0 ConfirmedRelationships, got %d/%d", valSum.ConfirmedPaths, valSum.ConfirmedRelationships)
	}
}
