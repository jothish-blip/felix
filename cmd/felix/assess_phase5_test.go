package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/investigation"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

func TestAssessPhase5_EndToEnd_ReportsConsistencyAndZeroSecretLeak(t *testing.T) {
	const rawSecret = "tok_e2e_phase5_secret_xyz987654321"
	const awsPlaceholder = "AKIAIOSFODNN7EXAMPLE"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHdr := strings.TrimSpace(r.Header.Get("Authorization"))
		switch r.URL.Path {
		case "/config.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`window.APP_CFG = { bearer: "` + rawSecret + `" };`))
		case "/docs.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`const key = "` + awsPlaceholder + `";`))
		case "/api/me":
			if authHdr != "Bearer "+rawSecret {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"identity":"user_b","role":"user"}`))
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

	liveSession := investigation.NewLiveAssessmentSession("asm-phase5-e2e", ts.URL, "standard", false, nil)
	liveSession.Quiet = true

	rawFindings := []report.Finding{
		{
			ID:         "F-E2E-CRED",
			Title:      "Exposed Live Bearer Token in /config.js",
			Category:   "secrets-exposure",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     ts.URL + "/config.js",
			Endpoint:   ts.URL + "/config.js",
			Method:     http.MethodGet,
			Evidence:   "Authorization: Bearer " + rawSecret,
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "Secret observed in /config.js",
			},
			EvidenceDetails: report.EvidenceDetails{
				Observation: "Cleartext token Bearer " + rawSecret,
				Location:    ts.URL + "/config.js",
				Details: map[string]string{
					"token_type":        "bearer",
					"intended_identity": "USER_B",
					"auth_check_url":    ts.URL + "/api/me",
					"candidate_token":   rawSecret,
				},
			},
		},
		{
			ID:         "F-E2E-BOLA",
			Title:      "BOLA Cross-Tenant Order Disclosure",
			Category:   "bola",
			Severity:   report.SeverityHigh,
			Confidence: report.ConfidenceHigh,
			Target:     ts.URL + "/api/orders/101",
			Endpoint:   ts.URL + "/api/orders/101",
			Method:     http.MethodGet,
			Evidence:   "USER_B accessed USER_A confidential order #101",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "BOLA verified",
			},
			EvidenceDetails: report.EvidenceDetails{
				Observation:      "Returned owner user_a record to user_b",
				ExpectedBehavior: "HTTP 403 Forbidden for non-owner USER_B",
				ObservedBehavior: "HTTP 200 returned user_a order payload",
				Location:         ts.URL + "/api/orders/101",
				Details: map[string]string{
					"auth_required":       "true",
					"authz_engine_verified": "true",
					"verification_state":    "VERIFIED",
					"owner_identity":        "USER_A",
					"owner_alias":           "USER_A",
					"accessor_identity":     "USER_B",
					"accessor_alias":        "USER_B",
					"accessor_role":         "user",
					"object_id":             "101",
					"expected_marker":       "UserA confidential order #101",
				},
			},
		},
		{
			ID:         "F-E2E-PH",
			Title:      "Documentation Placeholder AWS Key",
			Category:   "secrets-exposure",
			Severity:   report.SeverityLow,
			Confidence: report.ConfidenceLow,
			Target:     ts.URL + "/docs.js",
			Endpoint:   ts.URL + "/docs.js",
			Method:     http.MethodGet,
			Evidence:   `const key = "` + awsPlaceholder + `";`,
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"is_placeholder":    "true",
					"credential_status": "INVALID",
				},
			},
		},
	}

	var investigatedInput []report.Finding
	for _, f := range rawFindings {
		inf, err := liveSession.ProcessFinding(context.Background(), f, ts.Client())
		if err != nil {
			t.Fatalf("ProcessFinding failed for %s: %v", f.ID, err)
		}
		investigatedInput = append(investigatedInput, inf.Finding)
	}

	rtCtx := &AssessmentRuntimeContext{
		TargetURL: ts.URL,
		Client:    ts.Client(),
		Opts: AssessOptions{
			AllowLoopback: true,
		},
	}

	rep := report.BuildReport(ts.URL, investigatedInput)
	liveSession.EnrichReport(&rep)
	phase5Out := runPhase5AttackPathPipeline(context.Background(), rtCtx, investigatedInput, &rep)
	cleanInvestigated := sanitizeInvestigatedSlice(liveSession.GetFindings())
	rep.Metadata["attack_chains"] = phase5Out.ValidatedChains
	rep.Metadata["investigated_findings"] = cleanInvestigated
	rep = report.SanitizeReport(rep)

	// 1. Validate summary & validated path outcome
	if rep.Summary.ConfirmedAttackPaths != 1 {
		t.Fatalf("expected ConfirmedAttackPaths=1, got %+v (paths=%+v)", rep.Summary, rep.AttackPaths)
	}
	if len(rep.AttackPaths) != 1 {
		t.Fatalf("expected exactly 1 validated attack path (placeholder rejected), got %d: %+v", len(rep.AttackPaths), rep.AttackPaths)
	}
	ap := rep.AttackPaths[0]
	if ap.Status != "CONFIRMED" || ap.ReachabilityStatus != "REACHABLE" {
		t.Errorf("expected CONFIRMED / REACHABLE attack path, got status=%s reachability=%s", ap.Status, ap.ReachabilityStatus)
	}
	if len(ap.StepVerifications) != 2 || len(ap.CredentialValidations) != 1 {
		t.Errorf("expected 2 step verifications and 1 credential validation, got steps=%d creds=%d",
			len(ap.StepVerifications), len(ap.CredentialValidations))
	}
	if ap.CredentialValidations[0].TokenFingerprint != secrets.CredentialFingerprint(rawSecret) {
		t.Errorf("expected credential fingerprint %q, got %q", secrets.CredentialFingerprint(rawSecret), ap.CredentialValidations[0].TokenFingerprint)
	}

	// 2. Generate JSON, Standard HTML, Commercial HTML, attack_chains.json, and investigated_findings.json
	jsonBytes, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	stdHTML, err := report.GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	commRep := report.BuildCommercialReport(rep)
	commHTML, err := report.GenerateCommercialHTML(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	chainsBytes, err := json.MarshalIndent(phase5Out.ValidatedChains, "", "  ")
	if err != nil {
		t.Fatalf("marshal attack_chains failed: %v", err)
	}
	invBytes, err := json.MarshalIndent(cleanInvestigated, "", "  ")
	if err != nil {
		t.Fatalf("marshal investigated_findings failed: %v", err)
	}

	// 3. Cross-format consistency checks (JSON / Standard HTML / Commercial HTML / attack_chains.json)
	if len(phase5Out.ValidatedChains) != 1 || phase5Out.ValidatedChains[0].Status != investigation.StatusConfirmed {
		t.Errorf("attack_chains mismatch with rep.AttackPaths: %+v", phase5Out.ValidatedChains)
	}
	for _, artifact := range []struct {
		name string
		body string
	}{
		{"JSON", string(jsonBytes)},
		{"StandardHTML", stdHTML},
		{"CommercialHTML", commHTML},
	} {
		if !strings.Contains(artifact.body, ap.ID) {
			t.Errorf("%s missing validated path ID %s", artifact.name, ap.ID)
		}
		if !strings.Contains(artifact.body, "CONFIRMED") {
			t.Errorf("%s missing CONFIRMED status", artifact.name)
		}
		if !strings.Contains(artifact.body, ap.CredentialValidations[0].TokenFingerprint) {
			t.Errorf("%s missing safe credential fingerprint %s", artifact.name, ap.CredentialValidations[0].TokenFingerprint)
		}
		if !strings.Contains(artifact.body, "USER_B") {
			t.Errorf("%s missing verified USER_B identity context", artifact.name)
		}
	}

	// 4. Zero Secret Leakage check across EVERY artifact!
	for _, artifact := range []struct {
		name string
		body string
	}{
		{"JSON", string(jsonBytes)},
		{"StandardHTML", stdHTML},
		{"CommercialHTML", commHTML},
		{"attack_chains.json", string(chainsBytes)},
		{"investigated_findings.json", string(invBytes)},
	} {
		if strings.Contains(artifact.body, rawSecret) {
			t.Fatalf("SECURITY FAILURE: raw bearer token %q leaked into %s!", rawSecret, artifact.name)
		}
	}
}

func TestAssessPhase5_CLI_PlaceholderAndNegativeControl(t *testing.T) {
	// Fixture 1: Server exposing only docs/placeholder AWS key in config.js
	phServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><script src="/config.js"></script><body>Docs Portal</body></html>`))
		case "/config.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`window.DOCS = { exampleAccessKey: "AKIAIOSFODNN7EXAMPLE" };`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer phServer.Close()

	outDir1 := filepath.Join(t.TempDir(), "ph_out")
	_, _, _ = captureStdoutStderr(func() int {
		return runAssess([]string{
			"--target", phServer.URL,
			"--profile", "quick",
			"--output", outDir1,
			"--allow-loopback",
			"--auth-confirm",
			"--authorizing-party", "FELIX Phase 5 Test Suite",
			"--report-format", "all",
		})
	})

	repBytes1, err := os.ReadFile(filepath.Join(outDir1, "assessment_report.json"))
	if err != nil {
		t.Fatalf("expected assessment_report.json in %s: %v", outDir1, err)
	}
	var parsed1 report.Report
	if err := json.Unmarshal(repBytes1, &parsed1); err != nil {
		t.Fatalf("invalid JSON in assessment_report.json: %v", err)
	}
	if parsed1.Summary.ConfirmedAttackPaths != 0 {
		t.Errorf("placeholder-only fixture MUST have confirmed_attack_paths=0, got %d", parsed1.Summary.ConfirmedAttackPaths)
	}
	if _, statErr := os.Stat(filepath.Join(outDir1, "assessment_report.html")); statErr != nil {
		t.Errorf("expected assessment_report.html generated: %v", statErr)
	}
	chainBytes1, err := os.ReadFile(filepath.Join(outDir1, "attack_chains.json"))
	if err != nil {
		t.Fatalf("expected attack_chains.json generated: %v", err)
	}
	var chains1 []investigation.AttackChain
	if err := json.Unmarshal(chainBytes1, &chains1); err != nil {
		t.Fatalf("invalid attack_chains.json: %v", err)
	}
	for _, ch := range chains1 {
		if ch.Status == investigation.StatusConfirmed {
			t.Errorf("placeholder fixture MUST NOT yield CONFIRMED chain in attack_chains.json: %+v", ch)
		}
	}

	// Fixture 2: Hardened negative control (strict security headers, 403 on protected paths, no leaks)
	negServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body><h1>Hardened Service</h1></body></html>`))
			return
		}
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer negServer.Close()

	outDir2 := filepath.Join(t.TempDir(), "neg_out")
	code2, _, _ := captureStdoutStderr(func() int {
		return runAssess([]string{
			"--target", negServer.URL,
			"--profile", "quick",
			"--output", outDir2,
			"--allow-loopback",
			"--auth-confirm",
			"--authorizing-party", "FELIX Phase 5 Test Suite",
			"--report-format", "all",
		})
	})
	if code2 != 0 && code2 != 1 {
		t.Fatalf("unexpected CLI exit code on negative control: %d", code2)
	}

	repBytes2, err := os.ReadFile(filepath.Join(outDir2, "assessment_report.json"))
	if err != nil {
		t.Fatalf("expected assessment_report.json in %s: %v", outDir2, err)
	}
	var parsed2 report.Report
	if err := json.Unmarshal(repBytes2, &parsed2); err != nil {
		t.Fatalf("invalid JSON in negative control report: %v", err)
	}
	if len(parsed2.AttackPaths) != 0 || parsed2.Summary.ConfirmedAttackPaths != 0 {
		t.Errorf("negative control MUST produce zero attack paths; got len=%d confirmed=%d",
			len(parsed2.AttackPaths), parsed2.Summary.ConfirmedAttackPaths)
	}
}
