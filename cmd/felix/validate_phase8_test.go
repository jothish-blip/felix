package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/report"
	"felix/pkg/validation"
)

func TestPhase8_AuthorizationGate_RefusesExpiredWindowAndOutOfScope_ZeroRequests(t *testing.T) {
	var reqCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	now := time.Now().UTC()

	cases := []struct {
		name     string
		contract validation.AuthorizationContract
	}{
		{
			name: "unconfirmed manifest",
			contract: validation.AuthorizationContract{
				AuthorizingParty:  "Owner",
				AuthorizationRef:  "REF-1",
				Confirmed:         false,
				AuthorizedTargets: []string{srv.URL},
				WindowStart:       now.Add(-time.Hour),
				WindowEnd:         now.Add(time.Hour),
			},
		},
		{
			name: "expired testing window",
			contract: validation.AuthorizationContract{
				AuthorizingParty:  "Owner",
				AuthorizationRef:  "REF-2",
				Confirmed:         true,
				AuthorizedTargets: []string{srv.URL},
				WindowStart:       now.Add(-2 * time.Hour),
				WindowEnd:         now.Add(-1 * time.Minute),
			},
		},
		{
			name: "target outside authorized origin",
			contract: validation.AuthorizationContract{
				AuthorizingParty:  "Owner",
				AuthorizationRef:  "REF-3",
				Confirmed:         true,
				AuthorizedTargets: []string{"https://different-host.example"},
				WindowStart:       now.Add(-time.Hour),
				WindowEnd:         now.Add(time.Hour),
			},
		},
	}

	for i, tc := range cases {
		manifestPath := filepath.Join(tmp, fmt.Sprintf("auth_%d.json", i))
		b, _ := json.MarshalIndent(tc.contract, "", "  ")
		_ = os.WriteFile(manifestPath, b, 0644)

		outDir := filepath.Join(tmp, fmt.Sprintf("out_%d", i))
		code := runAssess([]string{
			"--target", srv.URL,
			"--profile", "quick",
			"--output", outDir,
			"--allow-loopback",
			"--scope-manifest", manifestPath,
		})
		if code != 2 {
			t.Fatalf("%s: expected exit code 2, got %d", tc.name, code)
		}
	}

	if got := atomic.LoadInt32(&reqCount); got != 0 {
		t.Fatalf("expected 0 HTTP requests on authorization/window refusals, got %d", got)
	}
}

func TestPhase8_ExcludedPathsNeverTouchedDuringAssessAndRetest(t *testing.T) {
	var mu sync.Mutex
	visited := make([]string, 0)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		visited = append(visited, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><body>
				<a href="/excluded/danger">Danger</a>
				<a href="/logout">Logout</a>
				<a href="/api/ping">Ping</a>
			</body></html>`))
		case "/api/ping":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	outDir := filepath.Join(tmp, "assess_out")
	code := runAssess([]string{
		"--target", srv.URL,
		"--profile", "standard",
		"--output", outDir,
		"--allow-loopback",
		"--auth-confirm",
		"--authorizing-party", "Phase8-UnitTest",
		"--exclude-paths", "/excluded,/logout",
		"--crawl-max-pages", "20",
		"--crawl-max-requests", "40",
	})
	if code == 2 {
		t.Fatalf("runAssess returned config error code 2")
	}

	// Build a synthetic baseline report referencing /excluded/danger to prove runRetest also honors --exclude-paths
	retestInput := filepath.Join(tmp, "baseline_retest.json")
	rep := report.Report{
		Target: srv.URL,
		Findings: []report.Finding{
			{
				ID:       "HDR-EXCL-TEST",
				Category: "Missing Security Header",
				Title:    "Missing Content-Security-Policy (CSP)",
				Severity: "MEDIUM",
				Target:   srv.URL,
				Endpoint: "/excluded/danger",
				Method:   "GET",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
		},
	}
	rb, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.WriteFile(retestInput, rb, 0644)

	retestOut := filepath.Join(tmp, "retest_out")
	_ = runAssess([]string{
		"--target", srv.URL,
		"--retest", retestInput,
		"--output", retestOut,
		"--allow-loopback",
		"--auth-confirm",
		"--authorizing-party", "Phase8-UnitTest",
		"--exclude-paths", "/excluded,/logout",
	})

	mu.Lock()
	defer mu.Unlock()
	for _, p := range visited {
		if strings.HasPrefix(p, "/excluded") || strings.HasPrefix(p, "/logout") {
			t.Fatalf("excluded path %q was requested despite --exclude-paths enforcement", p)
		}
	}
}

func TestPhase8_BlindValidationReadiness_EndToEndHarness(t *testing.T) {
	var resetHits int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Deliberately set nosniff and X-Frame-Options (negative controls), omit CSP (positive control).
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")

		switch r.URL.Path {
		case "/admin/reset":
			atomic.AddInt32(&resetHits, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"reset":true}`))
		case "/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><script src="/app.js"></script></head><body><h1>Demo</h1><a href="/admin/reset">Reset</a></body></html>`))
		case "/app.js":
			w.Header().Set("Content-Type", "application/javascript")
			_, _ = w.Write([]byte(`fetch("/api/health");`))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"openapi":"3.0.0",
				"info":{"title":"BlindReadinessApp","version":"1.0"},
				"paths":{
					"/api/items/{item_id}":{"get":{"parameters":[{"name":"item_id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
					"/api/secure/{secure_id}":{"get":{"parameters":[{"name":"secure_id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"}}}},
					"/api/items":{"get":{"responses":{"200":{"description":"list"}}}},
					"/api/me":{"get":{"responses":{"200":{"description":"me"}}}},
					"/api/health":{"get":{"responses":{"200":{"description":"ok"}}}}
				}
			}`))
		case "/api/me":
			w.Header().Set("Content-Type", "application/json")
			auth := r.Header.Get("Authorization")
			switch auth {
			case "Bearer token-user-a":
				_, _ = w.Write([]byte(`{"username":"alice","id":"user-a"}`))
			case "Bearer token-user-b":
				_, _ = w.Write([]byte(`{"username":"bob","id":"user-b"}`))
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/api/items":
			w.Header().Set("Content-Type", "application/json")
			switch r.Header.Get("Authorization") {
			case "Bearer token-user-a":
				_, _ = w.Write([]byte(`[{"item_id":"item-alice-1","owner":"alice","secret":"alpha-note"}]`))
			case "Bearer token-user-b":
				_, _ = w.Write([]byte(`[{"item_id":"item-bob-1","owner":"bob","secret":"beta-note"}]`))
			default:
				w.WriteHeader(http.StatusUnauthorized)
			}
		case "/api/items/item-alice-1", "/api/items/item-bob-1":
			// Vulnerable BOLA: any authenticated user can read any item
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "item-alice-1") {
				_, _ = w.Write([]byte(`{"item_id":"item-alice-1","owner":"alice","secret":"alpha-note"}`))
			} else {
				_, _ = w.Write([]byte(`{"item_id":"item-bob-1","owner":"bob","secret":"beta-note"}`))
			}
		case "/api/secure/sec-alice-1":
			if r.Header.Get("Authorization") != "Bearer token-user-a" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"secure_id":"sec-alice-1","owner":"alice"}`))
		case "/api/health":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"healthy","info":"root service alive"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	tmp := t.TempDir()
	gtTime := time.Now().UTC().Add(-5 * time.Minute)
	reg := validation.GroundTruthRegistry{
		RegistryID:         "gt-ephemeral-p8",
		Application:        "BlindReadinessApp",
		Version:            "1.0",
		TargetOrigin:       srv.URL,
		EstablishedAt:      gtTime,
		EstablishedBy:      "Phase8-Harnesses",
		ProvenanceNote:     "Derived independently from mock handler specification before running FELIX",
		DerivedFromScanner: false,
		Entries: []validation.GroundTruthEntry{
			{
				ID:              "GT-BOLA-ITEMS",
				EndpointPattern: "/api/items/{item_id}",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  validation.GTVulnerable,
				InScope:         true,
				RequiresConfig:  "MULTI_ROLE",
				Description:     "Cross-user BOLA on /api/items/{item_id}",
			},
			{
				ID:              "GT-HDR-CSP",
				EndpointPattern: "/",
				Method:          "GET",
				VulnClass:       "SECURITY_HEADERS",
				ExpectedStatus:  validation.GTVulnerable,
				InScope:         true,
				Matcher:         validation.MatcherRule{TitleContains: []string{"Content-Security-Policy"}},
				Description:     "CSP header omitted",
			},
			{
				ID:              "GT-HDR-NOSNIFF-NC",
				EndpointPattern: "/",
				Method:          "GET",
				VulnClass:       "SECURITY_HEADERS",
				ExpectedStatus:  validation.GTNegativeControl,
				InScope:         true,
				Matcher:         validation.MatcherRule{TitleContains: []string{"X-Content-Type-Options"}},
				Description:     "nosniff present",
			},
			{
				ID:              "GT-EXCL-RESET",
				EndpointPattern: "/admin/reset",
				Method:          "POST",
				VulnClass:       "BFLA",
				ExpectedStatus:  validation.GTExcludedScope,
				InScope:         false,
				Description:     "Explicitly excluded reset endpoint",
			},
		},
	}

	gtPath := filepath.Join(tmp, "ground_truth.json")
	gtBytes, _ := json.MarshalIndent(reg, "", "  ")
	_ = os.WriteFile(gtPath, gtBytes, 0644)

	gtHash, err := validation.CanonicalGroundTruthSHA256(&reg)
	if err != nil {
		t.Fatalf("hash gt: %v", err)
	}

	rolesPath := filepath.Join(tmp, "roles.json")
	_ = os.WriteFile(rolesPath, []byte(`{"user_a":"Bearer token-user-a","user_b":"Bearer token-user-b"}`), 0644)

	execTime := time.Now().UTC()
	manifest := validation.CampaignManifest{
		ManifestID:              "p8-ephemeral-camp-1",
		TargetName:              "BlindReadinessApp",
		TargetURL:               srv.URL,
		Environment:             "EPHEMERAL_HARNESS",
		GroundTruthRegistryID:   reg.RegistryID,
		GroundTruthSHA256:       gtHash,
		GroundTruthRegisteredAt: gtTime,
		BlindExecution:          true,
		Profile:                 "full",
		RolesConfigured:         []string{"user_a", "user_b"},
		ExecutedAt:              execTime,
		Authorization: validation.AuthorizationContract{
			AuthorizingParty:  "Phase8-Test-Owner",
			AuthorizationRef:  "P8-HARNESS-01",
			Confirmed:         true,
			AuthorizedTargets: []string{srv.URL},
			ExcludedPaths:     []string{"/admin/reset"},
			WindowStart:       execTime.Add(-15 * time.Minute),
			WindowEnd:         execTime.Add(15 * time.Minute),
		},
	}
	manifestPath := filepath.Join(tmp, "manifest.json")
	mBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(manifestPath, mBytes, 0644)

	// Step 1: Verify CLI auth gate check
	if code := runValidate([]string{"verify-auth", "--manifest", manifestPath, "--target", srv.URL}); code != 0 {
		t.Fatalf("verify-auth failed with code %d", code)
	}

	// Step 2: Execute blind assessment strictly from base target + manifest + roles (zero GT passed to scanner)
	outDir := filepath.Join(tmp, "blind_run")
	code := runAssess([]string{
		"--target", srv.URL,
		"--profile", "full",
		"--output", outDir,
		"--roles-config", rolesPath,
		"--scope-manifest", manifestPath,
		"--allow-loopback",
		"--crawl-max-pages", "20",
		"--crawl-max-requests", "40",
	})
	if code == 2 {
		t.Fatalf("blind runAssess exited with error 2")
	}

	if hits := atomic.LoadInt32(&resetHits); hits != 0 {
		t.Fatalf("excluded endpoint /admin/reset was hit %d times", hits)
	}

	// Step 3: Execute multi-role retest (verifies --roles-config + --scope-manifest works in runRetest)
	retestOut := filepath.Join(tmp, "retest_run")
	_ = runAssess([]string{
		"--target", srv.URL,
		"--retest", filepath.Join(outDir, "assessment_report.json"),
		"--output", retestOut,
		"--roles-config", rolesPath,
		"--scope-manifest", manifestPath,
		"--allow-loopback",
	})

	retestBytes, err := os.ReadFile(filepath.Join(retestOut, "retest_report.json"))
	if err != nil {
		t.Fatalf("failed reading retest_report.json: %v", err)
	}
	var rr struct {
		FixedCount        int `json:"fixed_count"`
		StillPresentCount int `json:"still_present_count"`
		InconclusiveCount int `json:"inconclusive_count"`
	}
	if err := json.Unmarshal(retestBytes, &rr); err != nil {
		t.Fatalf("failed parsing retest_report.json: %v", err)
	}
	if rr.FixedCount != 0 || rr.StillPresentCount != 3 {
		t.Fatalf("expected fixed_count=0 and still_present_count=3 on unpatched server, got fixed=%d still_present=%d inconclusive=%d", rr.FixedCount, rr.StillPresentCount, rr.InconclusiveCount)
	}

	// Step 4: Evaluate blind outputs against hash-locked ground truth
	evalOut := filepath.Join(tmp, "accuracy_eval.json")
	evalCode := runValidate([]string{
		"evaluate",
		"--ground-truth", gtPath,
		"--report", filepath.Join(outDir, "assessment_report.json"),
		"--authz", filepath.Join(outDir, "authorization_summary.json"),
		"--retest", filepath.Join(retestOut, "retest_report.json"),
		"--manifest", manifestPath,
		"--output", evalOut,
	})
	if evalCode != 0 {
		t.Fatalf("felix validate evaluate failed with code %d", evalCode)
	}

	evalBytes, err := os.ReadFile(evalOut)
	if err != nil {
		t.Fatalf("failed reading accuracy_eval.json: %v", err)
	}
	var eval validation.AccuracyEvaluationReport
	if err := json.Unmarshal(evalBytes, &eval); err != nil {
		t.Fatalf("failed parsing accuracy_eval.json: %v", err)
	}
	if !eval.BlindExecutionVerified || !eval.ManifestIntegrityOK {
		t.Fatalf("expected blind execution verified, notes=%v", eval.BlindnessNotes)
	}
	if !eval.RedactionAudit.Clean {
		t.Fatalf("expected clean redaction audit, leaks=%v", eval.RedactionAudit.LeakLocations)
	}
	if !eval.ReportSummaryConsistent {
		t.Fatalf("expected report summary parity (%d == %d)", eval.SummaryTotalReported, eval.FindingsCountReported)
	}
	if eval.UniversalAccuracyClaimed {
		t.Fatalf("expected UniversalAccuracyClaimed=false")
	}
	if eval.Counts.TP != 2 || eval.Counts.FP != 0 || eval.Counts.FN != 0 || eval.Counts.TN != 1 {
		t.Fatalf("expected TP=2 FP=0 FN=0 TN=1, got counts=%+v", eval.Counts)
	}
	if eval.Counts.OutOfScope != 1 {
		t.Fatalf("expected 1 OutOfScope (/admin/reset), got %d", eval.Counts.OutOfScope)
	}
}
