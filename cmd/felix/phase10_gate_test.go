package main

import (
	"archive/zip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/validation"
)

func TestPhase10_ValidateVerifyAuth_PlaceholderAndGroundTruthLock(t *testing.T) {
	// 1. Existing Phase 8 placeholder templates must fail closed.
	cmTemplate := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "campaign_manifest_template.json")
	if code := runValidateVerifyAuth([]string{"--manifest", cmTemplate, "--target", "https://staging.example-authorized-app.internal"}); code == 0 {
		t.Fatalf("expected placeholder campaign manifest template to fail verify-auth, got exit 0")
	}

	acTemplate := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "authorization_contract_template.json")
	if code := runValidateVerifyAuth([]string{"--manifest", acTemplate, "--target", "https://staging.example-authorized-app.internal"}); code == 0 {
		t.Fatalf("expected placeholder authorization contract template to fail verify-auth, got exit 0")
	}

	tmp := t.TempDir()
	now := time.Now().UTC()

	reg := validation.GroundTruthRegistry{
		RegistryID:         "gt-phase10-test",
		Application:        "SampleApp",
		TargetOrigin:       "https://staging.example.internal",
		EstablishedAt:      now.Add(-time.Hour),
		EstablishedBy:      "Owner Security",
		ProvenanceNote:     "Independent pre-scan audit",
		DerivedFromScanner: false,
		Entries: []validation.GroundTruthEntry{
			{
				ID:              "GT-01",
				EndpointPattern: "/api/orders/1",
				Method:          "GET",
				VulnClass:       "BOLA",
				ExpectedStatus:  validation.GTVulnerable,
				InScope:         true,
				Description:     "Sample vulnerable endpoint",
			},
		},
	}
	gtBytes, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("marshal ground truth: %v", err)
	}
	gtPath := filepath.Join(tmp, "ground_truth.json")
	if err := os.WriteFile(gtPath, gtBytes, 0600); err != nil {
		t.Fatalf("write ground truth: %v", err)
	}

	validHash, err := validation.CanonicalGroundTruthSHA256(&reg)
	if err != nil {
		t.Fatalf("hash ground truth: %v", err)
	}

	// 2. Confirmed CampaignManifest with placeholder ground_truth_sha256 must fail.
	badManifest := validation.CampaignManifest{
		ManifestID:        "cmp-bad-hash",
		TargetName:        "SampleApp",
		TargetURL:         "https://staging.example.internal",
		GroundTruthSHA256: "<REQUIRED_PRE_SCAN_GT_SHA256>",
		BlindExecution:    true,
		ExecutedAt:        now,
		Authorization: validation.AuthorizationContract{
			AuthorizingParty:  "Owner Security",
			AuthorizationRef:  "SOW-100",
			Confirmed:         true,
			AuthorizedTargets: []string{"https://staging.example.internal"},
			WindowStart:       now.Add(-time.Hour),
			WindowEnd:         now.Add(time.Hour),
		},
	}
	badManifestBytes, _ := json.Marshal(badManifest)
	badManifestPath := filepath.Join(tmp, "bad_manifest.json")
	if err := os.WriteFile(badManifestPath, badManifestBytes, 0600); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	if code := runValidateVerifyAuth([]string{"--manifest", badManifestPath}); code == 0 {
		t.Fatalf("expected CampaignManifest with placeholder ground_truth_sha256 to fail verify-auth, got exit 0")
	}

	// 3. Mismatched --ground-truth digest must fail.
	mismatchManifest := badManifest
	mismatchManifest.GroundTruthSHA256 = "sha256:" + string(make([]byte, 0)) + "0000000000000000000000000000000000000000000000000000000000000000"
	mismatchBytes, _ := json.Marshal(mismatchManifest)
	mismatchPath := filepath.Join(tmp, "mismatch_manifest.json")
	if err := os.WriteFile(mismatchPath, mismatchBytes, 0600); err != nil {
		t.Fatalf("write mismatch manifest: %v", err)
	}
	if code := runValidateVerifyAuth([]string{"--manifest", mismatchPath, "--ground-truth", gtPath}); code == 0 {
		t.Fatalf("expected mismatched ground-truth SHA-256 to fail verify-auth, got exit 0")
	}

	// 4. Ground truth marked derived_from_scanner=true must fail even if digest matches.
	taintedReg := reg
	taintedReg.DerivedFromScanner = true
	taintedHash, _ := validation.CanonicalGroundTruthSHA256(&taintedReg)
	taintedManifest := badManifest
	taintedManifest.GroundTruthSHA256 = taintedHash
	taintedGTPath := filepath.Join(tmp, "tainted_gt.json")
	taintedGTBytes, _ := json.Marshal(taintedReg)
	_ = os.WriteFile(taintedGTPath, taintedGTBytes, 0600)
	taintedManifestPath := filepath.Join(tmp, "tainted_manifest.json")
	taintedManifestBytes, _ := json.Marshal(taintedManifest)
	_ = os.WriteFile(taintedManifestPath, taintedManifestBytes, 0600)
	if code := runValidateVerifyAuth([]string{"--manifest", taintedManifestPath, "--ground-truth", taintedGTPath}); code == 0 {
		t.Fatalf("expected derived_from_scanner=true ground truth to fail verify-auth, got exit 0")
	}

	// 5. Valid confirmed CampaignManifest + pre-locked independent ground truth passes.
	goodManifest := badManifest
	goodManifest.GroundTruthSHA256 = validHash
	goodBytes, _ := json.Marshal(goodManifest)
	goodPath := filepath.Join(tmp, "good_manifest.json")
	if err := os.WriteFile(goodPath, goodBytes, 0600); err != nil {
		t.Fatalf("write good manifest: %v", err)
	}
	if code := runValidateVerifyAuth([]string{"--manifest", goodPath, "--ground-truth", gtPath}); code != 0 {
		t.Fatalf("expected valid confirmed manifest + locked ground truth to pass verify-auth, got exit %d", code)
	}
}

func TestPhase10_CLIEntrypoints_RefuseInvalidScopeManifest_ZeroRequests(t *testing.T) {
	var reqCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	now := time.Now().UTC()

	unconfirmedManifest := validation.CampaignManifest{
		ManifestID:        "cmp-unconfirmed",
		TargetName:        "LocalMock",
		TargetURL:         srv.URL,
		GroundTruthSHA256: "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		Authorization: validation.AuthorizationContract{
			AuthorizingParty:  "Owner",
			AuthorizationRef:  "REF-UNCONFIRMED",
			Confirmed:         false,
			AuthorizedTargets: []string{srv.URL},
			WindowStart:       now.Add(-time.Hour),
			WindowEnd:         now.Add(time.Hour),
		},
	}
	unconfirmedPath := filepath.Join(tmp, "unconfirmed.json")
	ub, _ := json.Marshal(unconfirmedManifest)
	if err := os.WriteFile(unconfirmedPath, ub, 0600); err != nil {
		t.Fatalf("write unconfirmed manifest: %v", err)
	}

	excludedContract := validation.AuthorizationContract{
		AuthorizingParty:  "Owner",
		AuthorizationRef:  "REF-EXCLUDED",
		Confirmed:         true,
		AuthorizedTargets: []string{srv.URL},
		ExcludedPaths:     []string{"/admin"},
		WindowStart:       now.Add(-time.Hour),
		WindowEnd:         now.Add(time.Hour),
	}
	excludedPath := filepath.Join(tmp, "excluded.json")
	eb, _ := json.Marshal(excludedContract)
	if err := os.WriteFile(excludedPath, eb, 0600); err != nil {
		t.Fatalf("write excluded contract: %v", err)
	}

	// Ensure loopback testing is permitted so only the authorization gate decides.
	t.Setenv("FELIX_ALLOW_LOOPBACK", "true")

	// 1. Direct module commands (e.g. bola / web) must refuse unconfirmed & excluded manifests with 0 requests.
	if code := runDirectModule("bola", func([]string) int {
		t.Fatalf("runner must not be called when authorization gate refuses")
		return 0
	}, []string{"--target", srv.URL, "--scope-manifest", unconfirmedPath}); code != 2 {
		t.Fatalf("expected runDirectModule(unconfirmed) exit 2, got %d", code)
	}
	if code := runDirectModule("web", func([]string) int {
		t.Fatalf("runner must not be called when target path is excluded in manifest")
		return 0
	}, []string{"--target", srv.URL + "/admin/users", "--scope-manifest", excludedPath}); code != 2 {
		t.Fatalf("expected runDirectModule(excluded) exit 2, got %d", code)
	}

	// 2. scan command must refuse invalid/excluded --scope-manifest with 0 requests.
	if code := runScan([]string{"--quiet", "--allow-loopback", "--scope-manifest", unconfirmedPath, srv.URL}); code != 2 {
		t.Fatalf("expected runScan(unconfirmed) exit 2, got %d", code)
	}
	if code := runScan([]string{"--quiet", "--allow-loopback", "--scope-manifest", excludedPath, srv.URL + "/admin/panel"}); code != 2 {
		t.Fatalf("expected runScan(excluded) exit 2, got %d", code)
	}

	// 3. recon command must refuse invalid/excluded --scope-manifest with 0 requests.
	if code := runRecon([]string{"--allow-loopback", "--scope-manifest", unconfirmedPath, "--target", srv.URL}); code != 2 {
		t.Fatalf("expected runRecon(unconfirmed) exit 2, got %d", code)
	}
	if code := runRecon([]string{"--allow-loopback", "--scope-manifest", excludedPath, "--target", srv.URL + "/admin"}); code != 2 {
		t.Fatalf("expected runRecon(excluded) exit 2, got %d", code)
	}

	// 4. secrets command URL fetch must refuse invalid/excluded --scope-manifest with 0 requests.
	if code := runSecrets([]string{"--allow-loopback", "--scope-manifest", unconfirmedPath, "--url", srv.URL}); code != 2 {
		t.Fatalf("expected runSecrets(unconfirmed) exit 2, got %d", code)
	}
	if code := runSecrets([]string{"--allow-loopback", "--scope-manifest", excludedPath, "--url", srv.URL + "/admin/keys"}); code != 2 {
		t.Fatalf("expected runSecrets(excluded) exit 2, got %d", code)
	}

	if hits := atomic.LoadInt32(&reqCount); hits != 0 {
		t.Fatalf("authorization gate violation: server received %d HTTP requests, expected 0", hits)
	}
}

func TestPhase10A_AllAdditionalNetworkEntrypoints_RefuseUnauthorizedManifest_ZeroRequests(t *testing.T) {
	var reqCount int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&reqCount, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmp := t.TempDir()
	now := time.Now().UTC()

	unconfirmedManifest := validation.CampaignManifest{
		ManifestID:        "cmp-p10a-unconfirmed",
		TargetName:        "LocalMock",
		TargetURL:         srv.URL,
		GroundTruthSHA256: "sha256:2222222222222222222222222222222222222222222222222222222222222222",
		Authorization: validation.AuthorizationContract{
			AuthorizingParty:  "Owner",
			AuthorizationRef:  "REF-P10A-1",
			Confirmed:         false,
			AuthorizedTargets: []string{srv.URL},
			WindowStart:       now.Add(-time.Hour),
			WindowEnd:         now.Add(time.Hour),
		},
	}
	unconfirmedPath := filepath.Join(tmp, "unconfirmed.json")
	ub, _ := json.Marshal(unconfirmedManifest)
	_ = os.WriteFile(unconfirmedPath, ub, 0600)

	excludedContract := validation.AuthorizationContract{
		AuthorizingParty:  "Owner",
		AuthorizationRef:  "REF-P10A-2",
		Confirmed:         true,
		AuthorizedTargets: []string{srv.URL},
		ExcludedPaths:     []string{"/admin"},
		WindowStart:       now.Add(-time.Hour),
		WindowEnd:         now.Add(time.Hour),
	}
	excludedPath := filepath.Join(tmp, "excluded.json")
	eb, _ := json.Marshal(excludedContract)
	_ = os.WriteFile(excludedPath, eb, 0600)

	t.Setenv("FELIX_ALLOW_LOOPBACK", "true")

	// 1. felix ci run --scope-manifest must refuse unconfirmed & excluded manifests with 0 requests.
	ciOut := filepath.Join(tmp, "ci_out")
	if code := runCI([]string{"run", "--target", srv.URL, "--allow-loopback", "--output-dir", ciOut, "--scope-manifest", unconfirmedPath}); code != 2 {
		t.Fatalf("expected runCI(unconfirmed) exit 2, got %d", code)
	}
	if code := runCI([]string{"run", "--target", srv.URL + "/admin/Panel", "--allow-loopback", "--output-dir", ciOut, "--scope-manifest", excludedPath}); code != 2 {
		t.Fatalf("expected runCI(excluded) exit 2, got %d", code)
	}

	// 2. felix cve template run --scope-manifest must refuse unconfirmed & excluded manifests with 0 requests.
	if code := runCVETemplateRun([]string{"--target", srv.URL, "--allow-loopback", "--scope-manifest", unconfirmedPath}); code != 2 {
		t.Fatalf("expected runCVETemplateRun(unconfirmed) exit 2, got %d", code)
	}
	if code := runCVETemplateRun([]string{"--target", srv.URL + "/admin/check", "--allow-loopback", "--scope-manifest", excludedPath}); code != 2 {
		t.Fatalf("expected runCVETemplateRun(excluded) exit 2, got %d", code)
	}

	// 3. felix apk --assess --scope-manifest must refuse unconfirmed & excluded manifests with 0 requests.
	dummyAPK := filepath.Join(tmp, "dummy.apk")
	if f, err := os.Create(dummyAPK); err == nil {
		zw := zip.NewWriter(f)
		w, _ := zw.Create("AndroidManifest.xml")
		_, _ = w.Write([]byte("manifest"))
		_ = zw.Close()
		_ = f.Close()
	}
	if code := runAPK([]string{"--assess", "--target", srv.URL, "--allow-loopback", "--scope-manifest", unconfirmedPath, dummyAPK}); code != 2 {
		t.Fatalf("expected runAPK(unconfirmed) exit 2, got %d", code)
	}
	if code := runAPK([]string{"--assess", "--target", srv.URL + "/admin/api", "--allow-loopback", "--scope-manifest", excludedPath, dummyAPK}); code != 2 {
		t.Fatalf("expected runAPK(excluded) exit 2, got %d", code)
	}

	// 3b. Every runDirectModule surface must refuse invalid manifests with 0 requests.
	for _, mod := range []string{"web", "api", "auth", "authz", "bola", "bfla", "bopla", "cloud"} {
		if code := runDirectModule(mod, func([]string) int {
			t.Fatalf("direct runner %s must not run when gate refuses", mod)
			return 0
		}, []string{"--target", srv.URL, "--scope-manifest", unconfirmedPath}); code != 2 {
			t.Fatalf("expected direct module %s (unconfirmed) exit 2, got %d", mod, code)
		}
	}

	// 4. felix monitor snapshot --scope-manifest must refuse unconfirmed manifest.
	profPath := filepath.Join(tmp, "felix.target.yml")
	_ = os.WriteFile(profPath, []byte("version: 1\ntarget:\n  name: mock\n  base_urls:\n    - "+srv.URL+"\n"), 0600)
	if code := runMonitorSnapshot([]string{"--profile", profPath, "--state-dir", filepath.Join(tmp, "mon"), "--scope-manifest", unconfirmedPath}); code != 2 {
		t.Fatalf("expected runMonitorSnapshot(unconfirmed) exit 2, got %d", code)
	}

	// 5. felix assess --retest --scope-manifest must refuse unconfirmed manifest before requests.
	dummyRep := filepath.Join(tmp, "rep.json")
	_ = os.WriteFile(dummyRep, []byte(`{"version":"1.0.0","target":"`+srv.URL+`","findings":[]}`), 0600)
	if code := runAssess([]string{"--retest", dummyRep, "--target", srv.URL, "--allow-loopback", "--scope-manifest", unconfirmedPath, "--output", filepath.Join(tmp, "retest_out")}); code != 2 {
		t.Fatalf("expected runAssess(--retest, unconfirmed) exit 2, got %d", code)
	}

	// 6. felix validate pilot-readiness against template manifests must fail closed (exit 2).
	cmTemplate := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "campaign_manifest_template.json")
	gtTemplate := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "ground_truth_registry_template.json")
	if code := runValidatePilotReadiness([]string{"--manifest", cmTemplate, "--ground-truth", gtTemplate, "--output-dir", filepath.Join(tmp, "ready_out")}); code != 2 {
		t.Fatalf("expected runValidatePilotReadiness(template) exit 2, got %d", code)
	}

	if hits := atomic.LoadInt32(&reqCount); hits != 0 {
		t.Fatalf("authorization gate violation: server received %d HTTP requests, expected 0", hits)
	}
}

