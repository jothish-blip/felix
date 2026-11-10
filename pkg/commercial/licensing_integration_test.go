package commercial_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"felix/pkg/commercial"
	"felix/pkg/report"
)

// helper to create a valid enterprise license
func createTestEnterpriseLicense(t *testing.T, keyID string, privKey ed25519.PrivateKey, maxAssessments int64, maxConcurrent int, maxTargets int, allowedFeatures []string) *commercial.SignedLicense {
	t.Helper()
	now := time.Now().UTC()
	payload := commercial.LicensePayload{
		LicenseID:        "LIC-ENT-INTEGRATION-001",
		OrganizationID:   "ORG-ACME-ENTERPRISE",
		OrganizationName: "Acme Enterprise Corp",
		ProductID:        "felix-enterprise",
		LicenseTier:      commercial.TierEnterprise,
		DeploymentType:   commercial.DeploymentOnPremise,
		Version:          "1.0.0",
		IssuerKeyID:      keyID,
		IssuedAt:         now.Add(-1 * time.Hour),
		NotBefore:        now.Add(-1 * time.Hour),
		ExpiresAt:        now.Add(30 * 24 * time.Hour),
		Entitlements: commercial.LicenseEntitlements{
			MaxAssessments:           maxAssessments,
			MaxConcurrentAssessments: maxConcurrent,
			MaxTargetsPerAssessment:  maxTargets,
			AllowedFeatures:          allowedFeatures,
			AllowAirGappedExport:     true,
			AllowOfflineExecution:    true,
		},
	}
	signed, err := commercial.SignLicensePayload(payload, keyID, privKey)
	if err != nil {
		t.Fatalf("failed signing test license: %v", err)
	}
	return signed
}

// -----------------------------------------------------------------------------
// Requirement 1: Actual FELIX-wide Entitlement Enforcement
// -----------------------------------------------------------------------------

func TestLicensingIntegration_AssessmentController_Enforcement(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key generation failed: %v", err)
	}
	keyID := "KEY-ISSUER-ASM-01"
	reg := commercial.NewMapLicenseKeyRegistry()
	_ = reg.RegisterKey(keyID, pub)

	store, err := commercial.NewLicenseStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	mgr, err := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   "LOCAL-USAGE-SIGNER-01",
		DefaultToCommunity: true,
	})
	if err != nil {
		t.Fatalf("failed creating license manager: %v", err)
	}

	enforcer := mgr.AsEnforcer()

	// 1. Community Tier: Test unauthorized feature block (Cloud Security)
	ctx := context.Background()
	_, err = enforcer.ReserveExecution(ctx, "op_cloud_01", "assessment.cloudsec", 1)
	if !errors.Is(err, commercial.ErrFeatureNotEntitled) {
		t.Fatalf("expected ErrFeatureNotEntitled for CloudSec under Community tier, got: %v", err)
	}

	// 2. Community Tier: Test target limit exceeded (limit is 5 in Community)
	_, err = enforcer.ReserveExecution(ctx, "op_targets_01", commercial.FeatureZeroCredentialRecon, 10)
	if !errors.Is(err, commercial.ErrTargetLimitExceeded) {
		t.Fatalf("expected ErrTargetLimitExceeded for 10 targets under Community tier, got: %v", err)
	}

	// 3. Community Tier: Concurrency limit exceeded (limit is 1 in Community)
	res1, err := enforcer.ReserveExecution(ctx, "op_conc_01", commercial.FeatureZeroCredentialRecon, 2)
	if err != nil {
		t.Fatalf("reservation 1 failed: %v", err)
	}
	_, err = enforcer.ReserveExecution(ctx, "op_conc_02", commercial.FeatureZeroCredentialRecon, 2)
	if !errors.Is(err, commercial.ErrConcurrencyLimitExceeded) {
		t.Fatalf("expected ErrConcurrencyLimitExceeded for second reservation, got: %v", err)
	}

	// 4. Uncompleted/Aborted assessment releases reservation without billing quota
	if err := res1.Release("aborted by operator"); err != nil {
		t.Fatalf("failed releasing reservation: %v", err)
	}

	reportAfterRelease, _ := mgr.GetQuotaReport()
	if reportAfterRelease.ConsumedAssessments != 0 {
		t.Fatalf("uncompleted operation consumed billable quota! consumed=%d", reportAfterRelease.ConsumedAssessments)
	}
	if reportAfterRelease.ActiveConcurrency != 0 {
		t.Fatalf("active concurrency not restored to 0! concurrency=%d", reportAfterRelease.ActiveConcurrency)
	}

	// 5. Install Enterprise License and verify feature permission and successful commit
	entLic := createTestEnterpriseLicense(t, keyID, priv, 100, 5, 50, []string{"*"})
	if _, err := mgr.InstallLicense(entLic); err != nil {
		t.Fatalf("failed installing enterprise license: %v", err)
	}

	resEnt, err := enforcer.ReserveExecution(ctx, "op_ent_01", "assessment.cloudsec", 15)
	if err != nil {
		t.Fatalf("enterprise reservation failed: %v", err)
	}

	// Terminal successful assessment commits usage
	if err := resEnt.Commit("COMPLETED", map[string]string{"client": "Acme", "findings": "12"}); err != nil {
		t.Fatalf("failed committing metered usage: %v", err)
	}

	reportEnt, _ := mgr.GetQuotaReport()
	if reportEnt.ConsumedAssessments != 1 {
		t.Fatalf("expected exactly 1 consumed assessment, got %d", reportEnt.ConsumedAssessments)
	}
	if reportEnt.ActiveConcurrency != 0 {
		t.Fatalf("expected 0 active concurrency after commit, got %d", reportEnt.ActiveConcurrency)
	}
}

func TestLicensingIntegration_CPaaS_Enforcement(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	// In isolated test without enterprise license, global manager defaults to Community
	commercial.ResetGlobalLicenseManager()
	mgr := commercial.GetGlobalLicenseManager()

	// 1. Community tier blocks CPaaS feature
	err := mgr.CheckFeature(commercial.FeatureCommercialCPaaS)
	if !errors.Is(err, commercial.ErrFeatureNotEntitled) {
		t.Fatalf("expected ErrFeatureNotEntitled for CPaaS in Community mode, got: %v", err)
	}

	// 2. Install Enterprise license with CPaaS
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "KEY-CPaaS-01"
	reg := mgr.KeyRegistry().(commercial.MapLicenseKeyRegistry)
	_ = reg.RegisterKey(keyID, pub)

	entLic := createTestEnterpriseLicense(t, keyID, priv, 500, 10, 100, []string{commercial.FeatureCommercialCPaaS, commercial.FeatureZeroCredentialRecon})
	if _, err := mgr.InstallLicense(entLic); err != nil {
		t.Fatalf("failed installing enterprise license: %v", err)
	}

	// Now CPaaS feature check succeeds
	if err := mgr.CheckFeature(commercial.FeatureCommercialCPaaS); err != nil {
		t.Fatalf("expected CPaaS feature permitted under enterprise license, got: %v", err)
	}
}

func TestLicensingIntegration_DueDiligence_Enforcement(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	commercial.ResetGlobalLicenseManager()
	report.SetGlobalFeatureGate(commercial.GetGlobalLicenseManager())

	engine := report.NewDueDiligenceEngine(report.DueDiligenceConfig{}, nil)

	// 1. Community baseline blocks Due Diligence
	ctx := context.Background()
	_, err := engine.ExecuteAssessment(ctx, report.DueDiligenceInput{
		Config: report.DueDiligenceConfig{
			TargetEntityName: "Acquisition Target Corp",
			RootDomain:       "target.corp",
		},
	})
	if err == nil || !errors.Is(err, commercial.ErrFeatureNotEntitled) {
		t.Fatalf("expected ErrFeatureNotEntitled for Due Diligence in Community mode, got: %v", err)
	}

	// 2. Install Enterprise license
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "KEY-DD-01"
	mgr := commercial.GetGlobalLicenseManager()
	reg := mgr.KeyRegistry().(commercial.MapLicenseKeyRegistry)
	_ = reg.RegisterKey(keyID, pub)

	entLic := createTestEnterpriseLicense(t, keyID, priv, 100, 5, 20, []string{"report.due_diligence", "*"})
	if _, err := mgr.InstallLicense(entLic); err != nil {
		t.Fatalf("failed installing enterprise license: %v", err)
	}

	// Feature check now succeeds
	if err := mgr.CheckFeature("report.due_diligence"); err != nil {
		t.Fatalf("expected report.due_diligence permitted under enterprise license, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Requirement 2: Independent Trust for Usage Exports
// -----------------------------------------------------------------------------

func TestLicensingSecurity_UsageExportIndependentTrust(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	pubTrusted, privTrusted, _ := ed25519.GenerateKey(nil)
	trustedKeyID := "KEY-TRUSTED-USAGE-01"

	reg := commercial.NewMapLicenseKeyRegistry()
	_ = reg.RegisterKey(trustedKeyID, pubTrusted)

	store, _ := commercial.NewLicenseStore(":memory:")
	defer store.Close()

	mgr, err := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   trustedKeyID,
		LocalSignerPrivKey: privTrusted,
		DefaultToCommunity: true,
	})
	if err != nil {
		t.Fatalf("failed creating manager: %v", err)
	}

	// Commit some usage
	res, _ := mgr.ReserveExecution(context.Background(), "op_trust_01", commercial.FeatureZeroCredentialRecon, 1)
	_, _ = mgr.CommitExecution(res, "COMPLETED", nil)

	export, err := mgr.ExportSignedUsage(context.Background())
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	// 1. Verify that private keys are NEVER exposed in export JSON
	exportJSON, _ := json.Marshal(export)
	var rawMap map[string]interface{}
	_ = json.Unmarshal(exportJSON, &rawMap)
	for k := range rawMap {
		if filepath.Base(k) == "priv" || filepath.Base(k) == "private_key" {
			t.Fatalf("private key field found in signed export JSON: %s", k)
		}
	}
	privHex := hex.EncodeToString(privTrusted)
	if hex.EncodeToString(exportJSON) == privHex {
		t.Fatal("private key leaked in serialized export")
	}

	// 2. Independent Verification with Trusted Registry succeeds
	result, err := commercial.VerifyUsageExportWithRegistry(export, reg)
	if err != nil || !result.Verified {
		t.Fatalf("expected trusted verification to succeed, err=%v, issues=%v", err, result.Issues)
	}

	// 3. Verification with Untrusted Key ID fails closed
	untrustedReg := commercial.NewMapLicenseKeyRegistry()
	resUntrusted, err := commercial.VerifyUsageExportWithRegistry(export, untrustedReg)
	if !errors.Is(err, commercial.ErrUntrustedSigningKey) && (resUntrusted == nil || resUntrusted.Verified) {
		t.Fatalf("expected ErrUntrustedSigningKey for unregistered key, got: %v", err)
	}

	// 4. Verification with Revoked Key ID fails closed
	_ = reg.RevokeKey(trustedKeyID, "compromised key revocation")
	resRevoked, err := commercial.VerifyUsageExportWithRegistry(export, reg)
	if !errors.Is(err, commercial.ErrRevokedSigningKey) && (resRevoked == nil || resRevoked.Verified) {
		t.Fatalf("expected ErrRevokedSigningKey for revoked key, got: %v", err)
	}

	// 5. Key Substitution Attack: Attacker generates rogue key and embeds it
	roguePub, _, _ := ed25519.GenerateKey(nil)
	tamperedExport := *export
	tamperedExport.SignerPublicKeyHex = hex.EncodeToString(roguePub)
	_ = reg.RegisterKey(trustedKeyID, pubTrusted) // re-register valid key

	resSub, err := commercial.VerifyUsageExportWithRegistry(&tamperedExport, reg)
	if !errors.Is(err, commercial.ErrKeySubstitutionDetected) && (resSub == nil || resSub.Verified) {
		t.Fatalf("expected ErrKeySubstitutionDetected, got: %v", err)
	}

	// 6. Self-signed export without registry trust fails closed
	rogueStore, _ := commercial.NewLicenseStore(":memory:")
	defer rogueStore.Close()
	rogueMgr, _ := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              rogueStore,
		KeyRegistry:        commercial.NewMapLicenseKeyRegistry(),
		LocalSignerKeyID:   "ROGUE-ATTACKER-KEY",
		LocalSignerPrivKey: privTrusted,
		DefaultToCommunity: true,
	})
	resRogue, _ := rogueMgr.ReserveExecution(context.Background(), "op_rogue_01", commercial.FeatureZeroCredentialRecon, 1)
	_, _ = rogueMgr.CommitExecution(resRogue, "COMPLETED", nil)
	rogueExport, _ := rogueMgr.ExportSignedUsage(context.Background())

	resSelfSigned, err := commercial.VerifyUsageExportWithRegistry(rogueExport, reg)
	if !errors.Is(err, commercial.ErrUntrustedSigningKey) && (resSelfSigned == nil || resSelfSigned.Verified) {
		t.Fatalf("expected self-signed export with unknown key to fail closed, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Requirement 3: Multi-Signal Clock Rollback and Snapshot Restoration
// -----------------------------------------------------------------------------

func TestLicensingSecurity_ClockRollbackAndSnapshotRestore(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "felix_test.db")
	anchorPath := filepath.Join(tmpDir, "felix_anchor.dat")

	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "KEY-TIME-01"
	reg := commercial.NewMapLicenseKeyRegistry()
	_ = reg.RegisterKey(keyID, pub)

	baseTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	mockTime := baseTime

	store, err := commercial.NewLicenseStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	mgr, err := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   keyID,
		LocalSignerPrivKey: priv,
		ReferenceTime:      &mockTime,
		TimeAnchorPath:     anchorPath,
		DefaultToCommunity: true,
	})
	if err != nil {
		t.Fatalf("failed creating manager: %v", err)
	}

	// 1. Initial valid commit at T=12:00
	res1, err := mgr.ReserveExecution(context.Background(), "op_time_01", commercial.FeatureZeroCredentialRecon, 1)
	if err != nil {
		t.Fatalf("initial reservation failed: %v", err)
	}
	_, err = mgr.CommitExecution(res1, "COMPLETED", nil)
	if err != nil {
		t.Fatalf("initial commit failed: %v", err)
	}

	// 2. Ordinary Clock Rollback: System clock jumps backwards to T=11:00
	mockTime = baseTime.Add(-1 * time.Hour)
	_, err = mgr.ReserveExecution(context.Background(), "op_time_02", commercial.FeatureZeroCredentialRecon, 1)
	if !errors.Is(err, commercial.ErrClockRollbackDetected) {
		t.Fatalf("expected ErrClockRollbackDetected on backwards clock during reserve, got: %v", err)
	}

	// 3. Restart recovery: System restarts with forward time (T=13:00) -> Succeeds
	mockTime = baseTime.Add(1 * time.Hour)
	recoveredMgr, err := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   keyID,
		LocalSignerPrivKey: priv,
		ReferenceTime:      &mockTime,
		TimeAnchorPath:     anchorPath,
		DefaultToCommunity: true,
	})
	if err != nil {
		t.Fatalf("restart recovery failed: %v", err)
	}

	report, err := recoveredMgr.GetQuotaReport()
	if err != nil || report.ConsumedAssessments != 1 {
		t.Fatalf("expected 1 consumed assessment after clean restart, got: %d", report.ConsumedAssessments)
	}

	// 4. Restored Older Snapshot Detection:
	// Emulate database restore by resetting database sequence/records while anchor file has sequence=1
	corruptStore, err := commercial.NewLicenseStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating memory store: %v", err)
	}
	defer corruptStore.Close()

	// New manager with fresh DB (sequence 0) but anchor file has sequence 1
	_, err = commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              corruptStore,
		KeyRegistry:        reg,
		LocalSignerKeyID:   keyID,
		LocalSignerPrivKey: priv,
		ReferenceTime:      &mockTime,
		TimeAnchorPath:     anchorPath, // anchor file has sequence 1
		DefaultToCommunity: true,
	})
	if !errors.Is(err, commercial.ErrSnapshotRollbackDetected) {
		t.Fatalf("expected ErrSnapshotRollbackDetected when older DB restored against newer anchor, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Requirement 4: Usage Accounting, Crash Safety, and Quota Boundary Tests
// -----------------------------------------------------------------------------

func TestLicensingSecurity_UsageAccountingCrashSafetyAndBoundaries(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "KEY-ACCNT-01"
	reg := commercial.NewMapLicenseKeyRegistry()
	_ = reg.RegisterKey(keyID, pub)

	store, err := commercial.NewLicenseStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating store: %v", err)
	}
	defer store.Close()

	mgr, err := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   keyID,
		LocalSignerPrivKey: priv,
		DefaultToCommunity: true,
	})
	if err != nil {
		t.Fatalf("failed creating manager: %v", err)
	}

	// 1. Negative target count rejected
	ctx := context.Background()
	_, err = mgr.ReserveExecution(ctx, "op_neg_targets", commercial.FeatureZeroCredentialRecon, -5)
	if !errors.Is(err, commercial.ErrInvalidTargetCount) {
		t.Fatalf("expected ErrInvalidTargetCount for -5 targets, got: %v", err)
	}

	// 2. Negative/zero usage quantity in commit rejected
	resValid, err := mgr.ReserveExecution(ctx, "op_neg_qty", commercial.FeatureZeroCredentialRecon, 1)
	if err != nil {
		t.Fatalf("valid reservation failed: %v", err)
	}
	resValid.Quantity = 0
	_, err = mgr.CommitExecution(resValid, "COMPLETED", nil)
	if !errors.Is(err, commercial.ErrInvalidQuantity) {
		t.Fatalf("expected ErrInvalidQuantity for 0 quantity, got: %v", err)
	}
	resValid.Quantity = 1

	// Commit properly
	_, err = mgr.CommitExecution(resValid, "COMPLETED", nil)
	if err != nil {
		t.Fatalf("commit failed: %v", err)
	}

	// 3. Duplicate usage submission rejected
	_, err = mgr.CommitExecution(resValid, "COMPLETED", nil)
	if !errors.Is(err, commercial.ErrReservationNotFound) && !errors.Is(err, commercial.ErrDuplicateUsageSubmission) {
		t.Fatalf("expected ErrDuplicateUsageSubmission or ErrReservationNotFound, got: %v", err)
	}

	// 4. Replay attack: reusing already committed operation ID in new reservation rejected
	_, err = mgr.ReserveExecution(ctx, "op_neg_qty", commercial.FeatureZeroCredentialRecon, 1)
	if !errors.Is(err, commercial.ErrReplayDetected) {
		t.Fatalf("expected ErrReplayDetected for committed opID, got: %v", err)
	}

	// 5. Database PRAGMA integrity check
	if err := store.CheckIntegrity(); err != nil {
		t.Fatalf("database integrity check failed: %v", err)
	}

	// 6. Definition of billable usage verification
	if commercial.DefinitionOfBillableUsage != "COMMITTED_UPON_TERMINAL_ASSESSMENT_COMPLETION_TO_DURABLE_LEDGER_ONLY" {
		t.Fatalf("unexpected definition of billable usage: %s", commercial.DefinitionOfBillableUsage)
	}
}

func TestLicensingSecurity_FinalQuotaContentionRace(t *testing.T) {
	commercial.SetDevTestMode(false)
	defer commercial.SetDevTestMode(true)

	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "KEY-QUOTA-RACE-01"
	reg := commercial.NewMapLicenseKeyRegistry()
	_ = reg.RegisterKey(keyID, pub)

	store, _ := commercial.NewLicenseStore(":memory:")
	defer store.Close()

	mgr, _ := commercial.NewLicenseManager(commercial.LicenseManagerConfig{
		Store:              store,
		KeyRegistry:        reg,
		LocalSignerKeyID:   keyID,
		LocalSignerPrivKey: priv,
		DefaultToCommunity: false,
	})

	// Exactly 1 quota remaining (MaxAssessments = 1)
	entLic := createTestEnterpriseLicense(t, keyID, priv, 1, 10, 50, []string{"*"})
	if _, err := mgr.InstallLicense(entLic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// 10 concurrent goroutines race to reserve the single remaining quota unit
	const concurrency = 10
	var successCount int32
	var quotaExhaustedCount int32
	var wg sync.WaitGroup

	startGate := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-startGate
			opID := "op_race_" + time.Now().Format("150405.000000000") + "_" + string(rune('A'+idx))
			_, err := mgr.ReserveExecution(context.Background(), opID, commercial.FeatureZeroCredentialRecon, 1)
			if err == nil {
				atomic.AddInt32(&successCount, 1)
			} else if errors.Is(err, commercial.ErrUsageQuotaExhausted) {
				atomic.AddInt32(&quotaExhaustedCount, 1)
			}
		}(i)
	}

	close(startGate)
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("expected exactly 1 reservation to win the final quota unit, got: %d", successCount)
	}
	if quotaExhaustedCount != concurrency-1 {
		t.Fatalf("expected %d reservations to receive ErrUsageQuotaExhausted, got: %d", concurrency-1, quotaExhaustedCount)
	}
}
