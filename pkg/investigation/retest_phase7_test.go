package investigation_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"felix/pkg/investigation"
	"felix/pkg/report"
)

func TestPhase7_RetestNeverClaimsFixOnUntestedOrPotential(t *testing.T) {
	prover := investigation.NewSafeProver("asm_phase7_retest", false)
	retest := investigation.NewRetestEngine(prover)

	// Uncovered category -> UNTESTED_CATEGORY_PROCEDURE / StatusNotTested must yield INCONCLUSIVE, never FIX DETECTED
	untested := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "FND-UNTESTED-1",
			Title:    "Rate Limiting Missing on Login",
			Category: "API4 Unrestricted Resource Consumption",
			Severity: "Medium",
			Target:   "http://127.0.0.1:1/login",
			Endpoint: "/login",
			Method:   "POST",
		},
		ValidationStatus: investigation.StatusPotential,
	}

	verdict, err := retest.RerunFinding(context.Background(), untested, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if verdict.RetestStatus == investigation.RetestFixDetected {
		t.Fatalf("untested category must NEVER return FIX DETECTED, got %s (%s)", verdict.RetestStatus, verdict.Explanation)
	}
	if verdict.RetestStatus != investigation.RetestInconclusive {
		t.Fatalf("expected RetestInconclusive for untested finding, got %s", verdict.RetestStatus)
	}
}

func TestPhase7_SafeCurlResolvesSubpathTargetCleanly(t *testing.T) {
	prover := investigation.NewSafeProver("asm_phase7_curl", false)
	f := report.Finding{
		ID:       "FND-URL-1",
		Title:    "Rate Limiting Missing",
		Category: "API4 Unrestricted Resource Consumption",
		Severity: "Medium",
		Target:   "http://127.0.0.1:5000/ui/",
		Endpoint: "/users/v1",
		Method:   "GET",
	}

	bundle, _, _, err := prover.ExecuteBoundedProof(context.Background(), f, nil)
	if err != nil {
		t.Fatalf("ExecuteBoundedProof failed: %v", err)
	}
	if !strings.Contains(bundle.SafeCurlCommand, "http://127.0.0.1:5000/users/v1") {
		t.Fatalf("expected SafeCurlCommand to target resolved http://127.0.0.1:5000/users/v1, got %q", bundle.SafeCurlCommand)
	}
	if strings.Contains(bundle.SafeCurlCommand, "/ui/users/v1") {
		t.Fatalf("SafeCurlCommand duplicated subpath /ui/ prefix: %q", bundle.SafeCurlCommand)
	}
}

func TestPhase7_RetestLiveProvers_CMDI_Headers_Info_Authz(t *testing.T) {
	var fixed atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/ping":
			if !fixed.Load() {
				cmd := r.URL.Query().Get("host")
				if strings.Contains(cmd, "printf felixcmdi%s 7319") {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"output":"felixcmdi7319"}`))
					return
				}
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"output":"safe: " ` + r.URL.Query().Get("host") + `}`))

		case r.URL.Path == "/":
			if fixed.Load() {
				w.Header().Set("Content-Security-Policy", "default-src 'self'")
				w.Header().Set("X-Content-Type-Options", "nosniff")
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`ok`))

		case r.URL.Path == "/.env" || strings.HasPrefix(r.URL.Path, "/felix-nonexistent-soft404"):
			// Always returns SPA catch-all HTML -> should never be confirmed as exposed .env
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`<!doctype html><html><app-root></app-root></html>`))

		case r.URL.Path == "/users/v1/user1":
			if r.Header.Get("Authorization") != "Bearer token_user_b" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if fixed.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"username":"user1","email":"u1@example.local"}`))

		case r.URL.Path == "/users/v1/_debug":
			if r.Header.Get("Authorization") != "Bearer token_user_b" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			if fixed.Load() {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin_debug":true}`))

		case r.URL.Path == "/api/profile":
			if r.Header.Get("Authorization") != "Bearer token_user_b" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusOK)
			if fixed.Load() {
				_, _ = w.Write([]byte(`{"username":"user_b"}`))
			} else {
				_, _ = w.Write([]byte(`{"username":"user_b","passwordHash":"secret_hash"}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	retest := investigation.NewRetestEngine(investigation.NewSafeProver("asm_retest_live", false))
	client := srv.Client()
	ctx := context.Background()

	// 1. CMDI vulnerable -> patched
	cmdiFinding := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "FND-CMDI-1",
			Title:    "Command Injection in ping",
			Category: "Command Injection",
			Severity: "CRITICAL",
			Target:   srv.URL + "/ping?host=127.0.0.1",
			Endpoint: "/ping?host=127.0.0.1",
			Method:   "GET",
		},
		ValidationStatus: investigation.StatusConfirmed,
	}
	if v, err := retest.RerunFinding(ctx, cmdiFinding, client); err != nil || v.RetestStatus != investigation.RetestVulnerabilityPresent {
		t.Fatalf("CMDI vulnerable retest expected VULNERABILITY STILL PRESENT, got %v (err=%v)", v.RetestStatus, err)
	}

	// 2. CSP header missing -> patched
	hdrFinding := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "HDR-CSP-1",
			Title:    "Missing Content-Security-Policy (CSP)",
			Category: "Missing Security Header",
			Severity: "MEDIUM",
			Target:   srv.URL,
			Endpoint: "/",
			Method:   "GET",
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{"header": "Content-Security-Policy"},
			},
		},
		ValidationStatus: investigation.StatusConfirmed,
	}
	if v, err := retest.RerunFinding(ctx, hdrFinding, client); err != nil || v.RetestStatus != investigation.RetestVulnerabilityPresent {
		t.Fatalf("CSP missing retest expected VULNERABILITY STILL PRESENT, got %v (err=%v)", v.RetestStatus, err)
	}

	// 3. Soft-404 .env -> NOT exposed
	envFinding := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "INFO-ENV-1",
			Title:    "Exposed Environment File (.env)",
			Category: "Information Disclosure",
			Severity: "HIGH",
			Target:   srv.URL,
			Endpoint: "/.env",
			Method:   "GET",
		},
		ValidationStatus: investigation.StatusConfirmed,
	}
	if v, err := retest.RerunFinding(ctx, envFinding, client); err != nil || v.RetestStatus != investigation.RetestFixDetected {
		t.Fatalf(".env SPA catch-all should resolve to FIX DETECTED (not exposed), got %v (%s)", v.RetestStatus, v.Explanation)
	}

	// 4. BOLA missing accessor token -> must fail closed INCONCLUSIVE (never false FIX DETECTED)
	bolaNoTok := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "BOLA-NO-TOK",
			Title:    "BOLA User Profile",
			Category: "BOLA",
			Severity: "CRITICAL",
			Target:   srv.URL,
			Endpoint: "/users/v1/user1",
			Method:   "GET",
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"authz_engine_verified": "true",
					"accessor_token":        "[REDACTED]",
					"object_id":             "user1",
				},
			},
		},
		ValidationStatus: investigation.StatusConfirmed,
	}
	if v, err := retest.RerunFinding(ctx, bolaNoTok, client); err != nil || v.RetestStatus != investigation.RetestInconclusive {
		t.Fatalf("BOLA without accessor token expected INCONCLUSIVE (fail-closed), got %v (%s)", v.RetestStatus, v.Explanation)
	}

	// 5. BOLA, BFLA, BOPLA with valid accessor token while vulnerable -> VULNERABILITY STILL PRESENT
	bolaWithTok := *bolaNoTok
	bolaWithTok.Finding.ID = "BOLA-WITH-TOK"
	bolaWithTok.Finding.EvidenceDetails = report.EvidenceDetails{
		Details: map[string]string{
			"authz_engine_verified": "true",
			"accessor_token":        "Bearer token_user_b",
			"object_id":             "user1",
		},
	}
	bflaFinding := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "BFLA-1",
			Title:    "BFLA Admin Debug",
			Category: "BFLA",
			Severity: "CRITICAL",
			Target:   srv.URL,
			Endpoint: "/users/v1/_debug",
			Method:   "GET",
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"authz_engine_verified": "true",
					"accessor_token":        "Bearer token_user_b",
				},
			},
		},
		ValidationStatus: investigation.StatusConfirmed,
	}
	boplaFinding := &investigation.InvestigatedFinding{
		Finding: report.Finding{
			ID:       "BOPLA-1",
			Title:    "BOPLA Excessive Data Exposure (passwordHash)",
			Category: "BOPLA",
			Severity: "HIGH",
			Target:   srv.URL,
			Endpoint: "/api/profile",
			Method:   "GET",
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"authz_engine_verified": "true",
					"accessor_token":        "Bearer token_user_b",
					"property_path":         "passwordHash",
				},
			},
		},
		ValidationStatus: investigation.StatusConfirmed,
	}

	for name, inf := range map[string]*investigation.InvestigatedFinding{
		"BOLA":  &bolaWithTok,
		"BFLA":  bflaFinding,
		"BOPLA": boplaFinding,
	} {
		v, vErr := retest.RerunFinding(ctx, inf, client)
		if vErr != nil || v.RetestStatus != investigation.RetestVulnerabilityPresent {
			t.Fatalf("%s vulnerable retest expected VULNERABILITY STILL PRESENT, got %v (err=%v, %s)", name, v.RetestStatus, vErr, v.Explanation)
		}
	}

	// Flip target to fixed and confirm all 5 return FIX DETECTED
	fixed.Store(true)
	for name, inf := range map[string]*investigation.InvestigatedFinding{
		"CMDI":  cmdiFinding,
		"CSP":   hdrFinding,
		"BOLA":  &bolaWithTok,
		"BFLA":  bflaFinding,
		"BOPLA": boplaFinding,
	} {
		v, vErr := retest.RerunFinding(ctx, inf, client)
		if vErr != nil || v.RetestStatus != investigation.RetestFixDetected {
			t.Fatalf("%s patched retest expected FIX DETECTED, got %v (err=%v, %s)", name, v.RetestStatus, vErr, v.Explanation)
		}
	}
}
