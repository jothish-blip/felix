package validation

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPhase10A_PilotReadiness_StatesAndPlaceholders(t *testing.T) {
	tmp := t.TempDir()
	now := time.Date(2026, 11, 12, 18, 0, 0, 0, time.UTC)

	binPath := filepath.Join(tmp, "felix_dummy.exe")
	if err := os.WriteFile(binPath, []byte("PE-DUMMY-BINARY"), 0600); err != nil {
		t.Fatalf("write dummy bin: %v", err)
	}
	outDir := filepath.Join(tmp, "out")
	browserFalse := false
	browserTrue := true

	// 1. Missing all campaign files -> BLOCKED with explicit MISSING checks
	missingRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:       binPath,
		OutputDir:        outDir,
		BrowserAvailable: &browserFalse,
		Now:              now,
	})
	if missingRep.OverallStatus != ReadinessBlocked || missingRep.ExternalRequestsSent != 0 {
		t.Fatalf("expected BLOCKED with 0 requests when files missing, got status=%s reqs=%d", missingRep.OverallStatus, missingRep.ExternalRequestsSent)
	}
	findCheck := func(rep PilotReadinessReport, id string) ReadinessCheck {
		for _, c := range rep.Checks {
			if c.ID == id {
				return c
			}
		}
		t.Fatalf("missing check %s", id)
		return ReadinessCheck{}
	}
	if st := findCheck(missingRep, "authorization_contract").Status; st != ReadinessMissing {
		t.Fatalf("expected authorization_contract MISSING, got %s", st)
	}
	if st := findCheck(missingRep, "oast_configuration").Status; st != ReadinessNotConfigured {
		t.Fatalf("expected oast_configuration NOT_CONFIGURED, got %s", st)
	}

	// 2. Placeholder Phase 8 templates -> never READY
	templateManifest := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "campaign_manifest_template.json")
	templateGT := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "ground_truth_registry_template.json")
	templateRetest := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "retest_expected_template.json")
	templateRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:         binPath,
		ManifestPath:       templateManifest,
		GroundTruthPath:    templateGT,
		RetestExpectedPath: templateRetest,
		OutputDir:          outDir,
		BrowserAvailable:   &browserFalse,
		Now:                now,
	})
	if templateRep.OverallStatus != ReadinessBlocked || templateRep.PilotExecutionStatus != ReadinessBlocked {
		t.Fatalf("templates must stay BLOCKED, got overall=%s pilot=%s", templateRep.OverallStatus, templateRep.PilotExecutionStatus)
	}
	if st := findCheck(templateRep, "authorization_contract").Status; st != ReadinessInvalid {
		t.Fatalf("expected template authorization_contract INVALID, got %s", st)
	}
	if st := findCheck(templateRep, "retest_prerequisites").Status; st != ReadinessInvalid {
		t.Fatalf("expected template retest_prerequisites INVALID, got %s", st)
	}

	// 3. Expired authorization window -> EXPIRED
	reg := GroundTruthRegistry{
		RegistryID:         "gt-pilot-01",
		Application:        "PilotTargetApp",
		TargetOrigin:       "https://staging.pilot-app.test",
		EstablishedAt:      now.Add(-2 * time.Hour),
		EstablishedBy:      "Independent Reviewer",
		ProvenanceNote:     "OpenAPI + source code manual audit",
		DerivedFromScanner: false,
		Entries: []GroundTruthEntry{
			{
				ID:                 "GT-BOLA-1",
				EndpointPattern:    "/api/orders/{id}",
				Method:             "GET",
				VulnClass:          "BOLA",
				ExpectedStatus:     GTVulnerable,
				RequiredIdentities: []string{"user_a", "user_b"},
				RequiresConfig:     "MULTI_ROLE",
				InScope:            true,
				Description:        "Cross-tenant order read",
			},
			{
				ID:             "GT-HDR-NEG",
				EndpointPattern: "/health",
				Method:         "GET",
				VulnClass:      "SECURITY_HEADERS",
				ExpectedStatus: GTNegativeControl,
				InScope:        true,
				Description:    "Negative control",
			},
		},
	}
	gtBytes, _ := json.Marshal(reg)
	gtPath := filepath.Join(tmp, "gt.json")
	_ = os.WriteFile(gtPath, gtBytes, 0600)
	gtHash, err := CanonicalGroundTruthSHA256(&reg)
	if err != nil {
		t.Fatalf("hash gt: %v", err)
	}

	rolesPath := filepath.Join(tmp, "roles.json")
	_ = os.WriteFile(rolesPath, []byte(`{"user_a":"tok_a","user_b":"tok_b"}`), 0600)
	retestPath := filepath.Join(tmp, "retest.json")
	_ = os.WriteFile(retestPath, []byte(`[{"finding_id":"F-1","ground_truth_id":"GT-BOLA-1","expected_action":"FIXED"}]`), 0600)

	expiredManifest := CampaignManifest{
		ManifestID:        "cmp-pilot-01",
		TargetName:        "PilotTargetApp",
		TargetURL:         "https://staging.pilot-app.test",
		Environment:       "DEPLOYED_AUTHORIZED",
		GroundTruthSHA256: gtHash,
		BlindExecution:    true,
		Authorization: AuthorizationContract{
			AuthorizingParty:  "Pilot App Owner LLC",
			SignedBy:          "CISO Jane Doe",
			AuthorizationRef:  "SOW-2026-10A",
			Confirmed:         true,
			AuthorizedTargets: []string{"https://staging.pilot-app.test"},
			ExcludedPaths:     []string{"/admin/reset"},
			WindowStart:       now.Add(-4 * time.Hour),
			WindowEnd:         now.Add(-1 * time.Hour),
		},
	}
	expBytes, _ := json.Marshal(expiredManifest)
	expPath := filepath.Join(tmp, "expired_manifest.json")
	_ = os.WriteFile(expPath, expBytes, 0600)

	expRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:         binPath,
		ManifestPath:       expPath,
		GroundTruthPath:    gtPath,
		RolesConfigPath:    rolesPath,
		RetestExpectedPath: retestPath,
		OutputDir:          outDir,
		BrowserAvailable:   &browserTrue,
		Now:                now,
	})
	if expRep.OverallStatus != ReadinessExpired {
		t.Fatalf("expected OverallStatus=EXPIRED for expired window, got %s (reasons=%v)", expRep.OverallStatus, expRep.BlockingReasons)
	}
	if st := findCheck(expRep, "authorization_contract").Status; st != ReadinessExpired {
		t.Fatalf("expected check 3 EXPIRED, got %s", st)
	}

	// 4. Valid active window -> PilotExecutionStatus READY while PublicReleaseStatus stays BLOCKED
	validManifest := expiredManifest
	validManifest.Authorization.WindowStart = now.Add(-1 * time.Hour)
	validManifest.Authorization.WindowEnd = now.Add(2 * time.Hour)
	valBytes, _ := json.Marshal(validManifest)
	valPath := filepath.Join(tmp, "valid_manifest.json")
	_ = os.WriteFile(valPath, valBytes, 0600)

	readyRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:         binPath,
		ManifestPath:       valPath,
		GroundTruthPath:    gtPath,
		RolesConfigPath:    rolesPath,
		RetestExpectedPath: retestPath,
		OutputDir:          outDir,
		BrowserAvailable:   &browserTrue,
		Now:                now,
	})
	if readyRep.PilotExecutionStatus != ReadinessReady || readyRep.OverallStatus != ReadinessReady {
		t.Fatalf("expected PilotExecutionStatus & OverallStatus READY, got pilot=%s overall=%s reasons=%v",
			readyRep.PilotExecutionStatus, readyRep.OverallStatus, readyRep.BlockingReasons)
	}
	if readyRep.PublicReleaseStatus != ReadinessBlocked {
		t.Fatalf("expected PublicReleaseStatus BLOCKED while signing/CI blockers open, got %s", readyRep.PublicReleaseStatus)
	}
	if st := findCheck(readyRep, "release_and_ci_blockers").Status; st != ReadinessBlocked {
		t.Fatalf("expected check 16 BLOCKED, got %s", st)
	}

	// 5. Required OAST / BROWSER_DOM missing -> NOT_CONFIGURED blocks pilot execution
	oastReg := reg
	oastReg.Entries[0].RequiresConfig = "OAST"
	oastBytes, _ := json.Marshal(oastReg)
	oastGTPath := filepath.Join(tmp, "oast_gt.json")
	_ = os.WriteFile(oastGTPath, oastBytes, 0600)
	oastHash, _ := CanonicalGroundTruthSHA256(&oastReg)
	oastManifest := validManifest
	oastManifest.GroundTruthSHA256 = oastHash
	oastManPath := filepath.Join(tmp, "oast_man.json")
	oastManBytes, _ := json.Marshal(oastManifest)
	_ = os.WriteFile(oastManPath, oastManBytes, 0600)

	oastRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:         binPath,
		ManifestPath:       oastManPath,
		GroundTruthPath:    oastGTPath,
		RolesConfigPath:    rolesPath,
		RetestExpectedPath: retestPath,
		OutputDir:          outDir,
		BrowserAvailable:   &browserTrue,
		Now:                now,
	})
	if findCheck(oastRep, "oast_configuration").Status != ReadinessNotConfigured || oastRep.OverallStatus != ReadinessBlocked {
		t.Fatalf("expected OAST NOT_CONFIGURED blocking pilot execution, got check=%s overall=%s",
			findCheck(oastRep, "oast_configuration").Status, oastRep.OverallStatus)
	}

	// 6. Placeholder credentials file -> identity_configuration INVALID and secret-free
	placeholderRoles := filepath.Join("..", "..", "test", "evidence", "phase8", "realworld_readiness", "roles_config_template.json")
	phRep := EvaluatePilotReadiness(PilotReadinessOptions{
		BinaryPath:         binPath,
		ManifestPath:       valPath,
		GroundTruthPath:    gtPath,
		RolesConfigPath:    placeholderRoles,
		RetestExpectedPath: retestPath,
		OutputDir:          outDir,
		BrowserAvailable:   &browserTrue,
		Now:                now,
	})
	if st := findCheck(phRep, "identity_configuration").Status; st != ReadinessInvalid {
		t.Fatalf("expected placeholder roles_config_template.json to return INVALID, got %s", st)
	}
	if phRep.OverallStatus != ReadinessBlocked {
		t.Fatalf("expected OverallStatus BLOCKED on placeholder credentials, got %s", phRep.OverallStatus)
	}
}
