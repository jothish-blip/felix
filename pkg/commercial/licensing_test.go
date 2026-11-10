package commercial

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// helper to generate an Ed25519 keypair
func generateTestKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed generating test ed25519 key: %v", err)
	}
	return pub, priv
}

// helper to setup an in-memory LicenseManager with trusted keys
func setupTestManager(t *testing.T, opts ...func(*LicenseManagerConfig, *MapLicenseKeyRegistry)) (*LicenseManager, *MapLicenseKeyRegistry, ed25519.PrivateKey) {
	t.Helper()
	reg := make(MapLicenseKeyRegistry)
	localPub, localPriv := generateTestKeyPair(t)

	cfg := LicenseManagerConfig{
		KeyRegistry:        reg,
		LocalSignerKeyID:   "KEY-LOCAL-AGENT-TEST",
		LocalSignerPrivKey: localPriv,
		DefaultToCommunity: true,
	}

	for _, opt := range opts {
		opt(&cfg, &reg)
	}

	if cfg.Store == nil {
		store, err := NewLicenseStore(":memory:")
		if err != nil {
			t.Fatalf("failed initializing test license store: %v", err)
		}
		cfg.Store = store
		t.Cleanup(func() { _ = store.Close() })
	}

	_ = localPub
	mgr, err := NewLicenseManager(cfg)
	if err != nil {
		t.Fatalf("failed creating test license manager: %v", err)
	}
	return mgr, &reg, localPriv
}

// helper to create a valid test enterprise license
func createTestLicense(t *testing.T, keyID string, priv ed25519.PrivateKey, tier LicenseTier, maxAssessments int64, maxConcurrent int) *SignedLicense {
	t.Helper()
	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID:        "LIC-2026-ACME-ENTERPRISE-001",
		OrganizationID:   "ORG-ACME-CORP",
		OrganizationName: "Acme Enterprise Corporation",
		ProductID:        "FELIX-SECURITY-SUITE",
		LicenseTier:      tier,
		DeploymentType:   DeploymentAirGapped,
		Version:          "1.0.0",
		IssuerKeyID:      keyID,
		IssuedAt:         now.Add(-10 * time.Minute),
		NotBefore:        now.Add(-5 * time.Minute),
		ExpiresAt:        now.Add(90 * 24 * time.Hour),
		Entitlements: LicenseEntitlements{
			MaxAssessments:             maxAssessments,
			MaxConcurrentAssessments:   maxConcurrent,
			MaxTargetsPerAssessment:    100,
			MaxHistoricalRetentionDays: 365,
			AllowedFeatures: []string{
				FeatureCPaaS,
				FeatureDrift,
				FeatureDueDiligence,
				FeatureExecutiveDossier,
				FeatureComplianceVanta,
				FeatureComplianceDrata,
				FeatureAttestationExport,
				FeatureAirGappedExport,
				FeatureZeroCredentialRecon,
			},
			AllowedProfiles:          []string{"standard", "aggressive", "compliance", "due_diligence"},
			AllowAirGappedExport:     true,
			AllowOfflineExecution:    true,
			AllowCustomCronSchedules: true,
		},
		ContractMetadata: map[string]string{
			"contract_id": "CNT-2026-ACME-091",
			"po_number":   "PO-9912041",
		},
	}

	signed, err := SignLicensePayload(payload, keyID, priv)
	if err != nil {
		t.Fatalf("failed signing test license: %v", err)
	}
	return signed
}

// -----------------------------------------------------------------------------
// Test Group 1: Cryptography, Key Registries & Signatures
// -----------------------------------------------------------------------------

func TestLicensing_01_ValidEd25519SignatureVerification(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-CENTRAL-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{
			KeyID:     keyID,
			PublicKey: issuerPub,
			Authority: "FELIX Enterprise Licensing Authority",
		}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 1000, 8)
	valResult, err := mgr.VerifyLicense(lic)
	if err != nil {
		t.Fatalf("expected valid license verification, got: %v", err)
	}

	if !valResult.Valid || !valResult.SignerVerified {
		t.Errorf("expected validation success and signer verified")
	}
	if valResult.Tier != TierEnterprise {
		t.Errorf("expected TierEnterprise, got %s", valResult.Tier)
	}
	if valResult.DaysRemaining <= 0 {
		t.Errorf("expected positive days remaining, got %d", valResult.DaysRemaining)
	}

	// Install and verify active
	installedResult, err := mgr.InstallLicense(lic)
	if err != nil {
		t.Fatalf("failed installing valid license: %v", err)
	}
	if installedResult.LicenseID != lic.Payload.LicenseID {
		t.Errorf("license ID mismatch: %s != %s", installedResult.LicenseID, lic.Payload.LicenseID)
	}

	active, err := mgr.GetActiveLicense()
	if err != nil {
		t.Fatalf("failed retrieving active license: %v", err)
	}
	if active.Payload.LicenseID != lic.Payload.LicenseID {
		t.Errorf("active license mismatch")
	}
}

func TestLicensing_02_TamperedLicensePayloadRejected(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-CENTRAL-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{
			KeyID:     keyID,
			PublicKey: issuerPub,
			Authority: "FELIX Authority",
		}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierProfessional, 50, 2)

	// Tamper with payload: adversary attempts to elevate max assessments from 50 to 50000
	tampered := *lic
	tampered.Payload.Entitlements.MaxAssessments = 50000

	_, err := mgr.VerifyLicense(&tampered)
	if err == nil {
		t.Fatalf("expected verification failure on tampered license payload, got nil")
	}
	if !errors.Is(err, ErrInvalidLicenseSignature) {
		t.Errorf("expected ErrInvalidLicenseSignature, got: %v", err)
	}
}

func TestLicensing_03_UntrustedSigningKeyFailsClosed(t *testing.T) {
	// Adversary generates their own key pair
	adversaryPub, adversaryPriv := generateTestKeyPair(t)
	adversaryKeyID := "KEY-ROGUE-ADVERSARY"

	// Manager does NOT have adversaryKeyID in its trusted registry
	mgr, _, _ := setupTestManager(t)

	// Adversary signs a legitimate-looking Enterprise license
	lic := createTestLicense(t, adversaryKeyID, adversaryPriv, TierEnterprise, 100000, 32)
	_ = adversaryPub

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected verification failure for untrusted signing key, got nil")
	}
	if !errors.Is(err, ErrUntrustedSigningKey) {
		t.Errorf("expected ErrUntrustedSigningKey, got: %v", err)
	}
}

func TestLicensing_04_RevokedSigningKeyFailsClosed(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-COMPROMISED-01"
	revokedAt := time.Now().UTC().Add(-24 * time.Hour)

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{
			KeyID:            keyID,
			PublicKey:        issuerPub,
			Authority:        "FELIX Authority",
			Revoked:          true,
			RevokedAt:        &revokedAt,
			RevocationReason: "Key superseded after planned rotation",
		}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected verification failure for revoked key, got nil")
	}
	if !errors.Is(err, ErrRevokedSigningKey) {
		t.Errorf("expected ErrRevokedSigningKey, got: %v", err)
	}
}

func TestLicensing_05_InvalidOrCorruptedSignatureFails(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{
			KeyID:     keyID,
			PublicKey: issuerPub,
		}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)
	// Corrupt signature hex
	lic.SignatureHex = strings.Replace(lic.SignatureHex, "a", "b", 1)

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected failure on corrupted signature, got nil")
	}
	if !errors.Is(err, ErrInvalidLicenseSignature) {
		t.Errorf("expected ErrInvalidLicenseSignature, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test Group 2: Expiry, Validity Windows & Clock Rollback
// -----------------------------------------------------------------------------

func TestLicensing_06_ExpiredLicenseRejected(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)

	// Set clock 100 days into the future (past 90-day expiry)
	futureClock := time.Now().UTC().Add(100 * 24 * time.Hour)
	mgr.SetReferenceTime(&futureClock)

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected failure for expired license, got nil")
	}
	if !errors.Is(err, ErrLicenseExpired) {
		t.Errorf("expected ErrLicenseExpired, got: %v", err)
	}
}

func TestLicensing_07_NotYetValidLicenseRejected(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	now := time.Now().UTC()
	payload := LicensePayload{
		LicenseID:      "LIC-FUTURE-01",
		OrganizationID: "ORG-FUTURE",
		LicenseTier:    TierEnterprise,
		DeploymentType: DeploymentOnPremise,
		IssuerKeyID:    keyID,
		IssuedAt:       now,
		NotBefore:      now.Add(48 * time.Hour), // Starts in 2 days
		ExpiresAt:      now.Add(365 * 24 * time.Hour),
		Entitlements: LicenseEntitlements{
			MaxAssessments: 100,
		},
	}
	lic, _ := SignLicensePayload(payload, keyID, issuerPriv)

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected failure for not-yet-valid license, got nil")
	}
	if !errors.Is(err, ErrLicenseNotYetValid) {
		t.Errorf("expected ErrLicenseNotYetValid, got: %v", err)
	}
}

func TestLicensing_08_ClockRollbackDetection(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Adversary rolls system clock backward prior to license issuance timestamp
	pastClock := lic.Payload.IssuedAt.Add(-2 * time.Hour)
	mgr.SetReferenceTime(&pastClock)

	_, err := mgr.VerifyLicense(lic)
	if err == nil {
		t.Fatalf("expected clock rollback rejection, got nil")
	}
	if !errors.Is(err, ErrClockRollbackDetected) {
		t.Errorf("expected ErrClockRollbackDetected, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test Group 3: Entitlement Gates & Feature Restrictions
// -----------------------------------------------------------------------------

func TestLicensing_09_CommunityTierFeatureRestrictions(t *testing.T) {
	// Default community mode without installed commercial license
	mgr, _, _ := setupTestManager(t)

	// Basic recon feature allowed in Community
	if err := mgr.CheckFeature(FeatureZeroCredentialRecon); err != nil {
		t.Errorf("expected zero credential recon permitted in Community, got: %v", err)
	}

	// Enterprise features strictly blocked in Community
	enterpriseFeatures := []string{
		FeatureCPaaS,
		FeatureDrift,
		FeatureDueDiligence,
		FeatureExecutiveDossier,
		FeatureComplianceVanta,
		FeatureComplianceDrata,
		FeatureAirGappedExport,
	}

	for _, feat := range enterpriseFeatures {
		err := mgr.CheckFeature(feat)
		if err == nil {
			t.Errorf("expected feature %s to be denied in Community tier, got nil", feat)
		}
		if !errors.Is(err, ErrFeatureNotEntitled) {
			t.Errorf("expected ErrFeatureNotEntitled for %s, got: %v", feat, err)
		}
	}
}

func TestLicensing_10_EnterpriseFeatureEntitlementSuccess(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 1000, 8)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	allowedFeatures := []string{
		FeatureCPaaS,
		FeatureDrift,
		FeatureDueDiligence,
		FeatureExecutiveDossier,
		FeatureComplianceVanta,
		FeatureComplianceDrata,
		FeatureAirGappedExport,
		FeatureZeroCredentialRecon,
	}

	for _, feat := range allowedFeatures {
		if err := mgr.CheckFeature(feat); err != nil {
			t.Errorf("expected feature %s to be allowed in Enterprise, got: %v", feat, err)
		}
	}

	// Unlisted feature denied
	if err := mgr.CheckFeature("unlicensed.experimental.feature"); err == nil {
		t.Errorf("expected unlicensed feature to be denied")
	}
}

func TestLicensing_11_TargetCountLimitsEnforced(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	// License limits targets to 10 per assessment
	lic := createTestLicense(t, keyID, issuerPriv, TierProfessional, 100, 2)
	lic.Payload.Entitlements.MaxTargetsPerAssessment = 10
	reSigned, _ := SignLicensePayload(lic.Payload, keyID, issuerPriv)

	if _, err := mgr.InstallLicense(reSigned); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// 5 targets: OK
	res, err := mgr.ReserveExecution(context.Background(), "OP-TGT-01", FeatureCPaaS, 5)
	if err != nil {
		t.Fatalf("expected 5 targets allowed, got: %v", err)
	}
	_ = mgr.ReleaseExecution(res, "test")

	// 15 targets: Exceeds 10 limit
	_, err = mgr.ReserveExecution(context.Background(), "OP-TGT-02", FeatureCPaaS, 15)
	if err == nil {
		t.Fatalf("expected error for 15 targets (limit 10), got nil")
	}
	if !errors.Is(err, ErrTargetLimitExceeded) {
		t.Errorf("expected ErrTargetLimitExceeded, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// Test Group 4: Concurrency & Metered Usage Accounting
// -----------------------------------------------------------------------------

func TestLicensing_12_ConcurrencyLimitPreventsBypass(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	// Max concurrent limit = 2
	lic := createTestLicense(t, keyID, issuerPriv, TierProfessional, 100, 2)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Slot 1
	res1, err := mgr.ReserveExecution(context.Background(), "OP-CONCUR-01", FeatureCPaaS, 1)
	if err != nil {
		t.Fatalf("slot 1 failed: %v", err)
	}

	// Slot 2
	res2, err := mgr.ReserveExecution(context.Background(), "OP-CONCUR-02", FeatureCPaaS, 1)
	if err != nil {
		t.Fatalf("slot 2 failed: %v", err)
	}

	// Slot 3 (must fail with ErrConcurrencyLimitExceeded)
	_, err = mgr.ReserveExecution(context.Background(), "OP-CONCUR-03", FeatureCPaaS, 1)
	if err == nil {
		t.Fatalf("expected slot 3 rejection, got nil")
	}
	if !errors.Is(err, ErrConcurrencyLimitExceeded) {
		t.Errorf("expected ErrConcurrencyLimitExceeded, got: %v", err)
	}

	// Release Slot 1 -> Slot 3 can now proceed
	if err := mgr.ReleaseExecution(res1, "completed"); err != nil {
		t.Fatalf("failed releasing slot 1: %v", err)
	}

	res3, err := mgr.ReserveExecution(context.Background(), "OP-CONCUR-03", FeatureCPaaS, 1)
	if err != nil {
		t.Fatalf("slot 3 should succeed after slot 1 release, got: %v", err)
	}

	_ = mgr.ReleaseExecution(res2, "done")
	_ = mgr.ReleaseExecution(res3, "done")
}

func TestLicensing_13_QuotaExhaustionEnforcement(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	// Quota: exactly 3 assessments allowed
	lic := createTestLicense(t, keyID, issuerPriv, TierProfessional, 3, 4)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	for i := 1; i <= 3; i++ {
		res, err := mgr.ReserveExecution(context.Background(), fmt.Sprintf("OP-%d", i), FeatureCPaaS, 1)
		if err != nil {
			t.Fatalf("assessment %d reservation failed: %v", i, err)
		}
		_, err = mgr.CommitExecution(res, "COMPLETED", nil)
		if err != nil {
			t.Fatalf("assessment %d commit failed: %v", i, err)
		}
	}

	// Attempt assessment 4 -> Must fail closed with ErrUsageQuotaExhausted
	_, err := mgr.ReserveExecution(context.Background(), "OP-4", FeatureCPaaS, 1)
	if err == nil {
		t.Fatalf("expected quota exhausted error, got nil")
	}
	if !errors.Is(err, ErrUsageQuotaExhausted) {
		t.Errorf("expected ErrUsageQuotaExhausted, got: %v", err)
	}

	// Verify quota report
	report, err := mgr.GetQuotaReport()
	if err != nil {
		t.Fatalf("failed getting quota report: %v", err)
	}
	if report.ConsumedAssessments != 3 {
		t.Errorf("expected consumed 3, got %d", report.ConsumedAssessments)
	}
	if report.RemainingAssessments != 0 {
		t.Errorf("expected remaining 0, got %d", report.RemainingAssessments)
	}
}

func TestLicensing_14_FailedOperationDoesNotConsumeQuota(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierProfessional, 5, 2)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Reserve execution
	res, err := mgr.ReserveExecution(context.Background(), "OP-FAIL-01", FeatureCPaaS, 1)
	if err != nil {
		t.Fatalf("reservation failed: %v", err)
	}

	// Preflight guardrail fails or host is unreachable -> Operation is RELEASED, not committed
	if err := mgr.ReleaseExecution(res, "PREFLIGHT_GUARDRAIL_REJECTED"); err != nil {
		t.Fatalf("release failed: %v", err)
	}

	// Assert consumed quota remains 0 and full remaining balance is intact
	report, err := mgr.GetQuotaReport()
	if err != nil {
		t.Fatalf("failed getting quota report: %v", err)
	}
	if report.ConsumedAssessments != 0 {
		t.Errorf("expected 0 consumed assessments after release, got %d", report.ConsumedAssessments)
	}
	if report.RemainingAssessments != 5 {
		t.Errorf("expected 5 remaining assessments, got %d", report.RemainingAssessments)
	}
	if report.ActiveConcurrency != 0 {
		t.Errorf("expected 0 active concurrency, got %d", report.ActiveConcurrency)
	}
}

// -----------------------------------------------------------------------------
// Test Group 5: Hash Chain Integrity & Signed Usage Records
// -----------------------------------------------------------------------------

func TestLicensing_15_UsageRecordHashChainContinuous(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, localPriv := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Commit 5 sequential assessments
	var committedRecords []*UsageRecord
	for i := 1; i <= 5; i++ {
		res, err := mgr.ReserveExecution(context.Background(), fmt.Sprintf("OP-CHAIN-%d", i), FeatureCPaaS, 1)
		if err != nil {
			t.Fatalf("failed reservation: %v", err)
		}
		rec, err := mgr.CommitExecution(res, "COMPLETED", map[string]string{"target": fmt.Sprintf("https://target-%d.com", i)})
		if err != nil {
			t.Fatalf("failed commit: %v", err)
		}
		committedRecords = append(committedRecords, rec)
	}

	// Verify sequence continuity and hash chaining
	for i, r := range committedRecords {
		if r.SequenceNumber != int64(i+1) {
			t.Errorf("expected sequence %d, got %d", i+1, r.SequenceNumber)
		}
		if i == 0 {
			if r.PreviousRecordDigest != GenesisHash {
				t.Errorf("genesis previous digest mismatch: %s", r.PreviousRecordDigest)
			}
		} else {
			if r.PreviousRecordDigest != committedRecords[i-1].RecordDigest {
				t.Errorf("chain breakage at %d: previous %s != prior digest %s", i+1, r.PreviousRecordDigest, committedRecords[i-1].RecordDigest)
			}
		}

		// Verify individual Ed25519 signature
		canonBytes, digestHex, err := ComputeUsageRecordDigest(*r)
		if err != nil || digestHex != r.RecordDigest {
			t.Errorf("record digest recomputation mismatch: %v", err)
		}
		sigBytes, _ := hex.DecodeString(r.SignatureHex)
		localPub := localPriv.Public().(ed25519.PublicKey)
		if !ed25519.Verify(localPub, canonBytes, sigBytes) {
			t.Errorf("record %d signature verification failed", r.SequenceNumber)
		}
	}
}

func TestLicensing_16_TamperedUsageRecordDetected(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, localPriv := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)
	_ = mgr.store.SaveInstalledLicense(lic, true)
	mgr.activeLicense = lic

	// Commit 3 assessments
	for i := 1; i <= 3; i++ {
		res, _ := mgr.ReserveExecution(context.Background(), fmt.Sprintf("OP-%d", i), FeatureCPaaS, 1)
		_, _ = mgr.CommitExecution(res, "COMPLETED", nil)
	}

	// Export usage
	export, err := mgr.ExportSignedUsage(context.Background())
	if err != nil {
		t.Fatalf("failed exporting usage: %v", err)
	}

	localPub := localPriv.Public().(ed25519.PublicKey)

	// Baseline export verifies cleanly
	baseResult, err := VerifyUsageExport(export, localPub)
	if err != nil || !baseResult.Verified {
		t.Fatalf("expected baseline export verification to succeed: %v, issues: %v", err, baseResult.Issues)
	}

	// Adversary tampers with Record 2 quantity (from 1 to 0 or 10)
	tamperedExport := *export
	tamperedExport.Records = make([]UsageRecord, len(export.Records))
	copy(tamperedExport.Records, export.Records)
	tamperedExport.Records[1].Quantity = 99 // Tamper

	tamperResult, err := VerifyUsageExport(&tamperedExport, localPub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tamperResult.Verified {
		t.Fatalf("expected tampered usage export verification to fail, but it passed")
	}
	if tamperResult.ChainContinuous {
		t.Errorf("expected chain continuity to fail on tampered record")
	}
}

func TestLicensing_17_MissingRecordInSequenceDetected(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, localPriv := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100, 4)
	_ = mgr.store.SaveInstalledLicense(lic, true)
	mgr.activeLicense = lic

	for i := 1; i <= 4; i++ {
		res, _ := mgr.ReserveExecution(context.Background(), fmt.Sprintf("OP-%d", i), FeatureCPaaS, 1)
		_, _ = mgr.CommitExecution(res, "COMPLETED", nil)
	}

	export, _ := mgr.ExportSignedUsage(context.Background())
	localPub := localPriv.Public().(ed25519.PublicKey)

	// Adversary removes Record 2 (sequence gap: 1, 3, 4)
	deletedExport := *export
	deletedExport.Records = []UsageRecord{export.Records[0], export.Records[2], export.Records[3]}

	delResult, err := VerifyUsageExport(&deletedExport, localPub)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if delResult.Verified {
		t.Fatalf("expected verification failure on missing sequence record")
	}
	if delResult.ChainContinuous {
		t.Errorf("expected chain discontinuous on omitted record")
	}
}

// -----------------------------------------------------------------------------
// Test Group 6: Air-Gapped & Offline Export Workflows
// -----------------------------------------------------------------------------

func TestLicensing_18_AirGappedExportAndIndependentVerification(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, localPriv := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	// Air-gapped enterprise tier license
	lic := createTestLicense(t, keyID, issuerPriv, TierAirGappedEnterprise, -1, 16)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Record 10 assessments offline
	for i := 1; i <= 10; i++ {
		res, err := mgr.ReserveExecution(context.Background(), fmt.Sprintf("OFFLINE-OP-%d", i), FeatureCPaaS, 1)
		if err != nil {
			t.Fatalf("reservation %d failed: %v", i, err)
		}
		_, err = mgr.CommitExecution(res, "COMPLETED", map[string]string{"lab": "airgap-lab"})
		if err != nil {
			t.Fatalf("commit %d failed: %v", i, err)
		}
	}

	// Export signed audit bundle
	export, err := mgr.ExportSignedUsage(context.Background())
	if err != nil {
		t.Fatalf("failed exporting signed usage: %v", err)
	}

	if export.TotalRecords != 10 {
		t.Errorf("expected 10 records, got %d", export.TotalRecords)
	}
	if export.TotalQuantityConsumed != 10 {
		t.Errorf("expected 10 total quantity, got %d", export.TotalQuantityConsumed)
	}

	// Verify completely offline using trusted public key
	localPub := localPriv.Public().(ed25519.PublicKey)
	auditRegistry := MapLicenseKeyRegistry{
		export.SignerKeyID: TrustedLicenseKey{KeyID: export.SignerKeyID, PublicKey: localPub},
	}
	auditResult, err := VerifyUsageExport(export, auditRegistry)
	if err != nil {
		t.Fatalf("audit verification returned error: %v", err)
	}
	if !auditResult.Verified {
		t.Fatalf("audit verification failed: issues=%v", auditResult.Issues)
	}
	if !auditResult.ChainContinuous || !auditResult.ExportSignatureValid || !auditResult.RecordSignaturesValid {
		t.Errorf("audit integrity flags incomplete: %+v", auditResult)
	}
}

// -----------------------------------------------------------------------------
// Test Group 7: Restart Recovery & Persistent State
// -----------------------------------------------------------------------------

func TestLicensing_19_RestartRecoveryRestoresExactQuotaAndState(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "felix_licensing.db")

	store1, err := NewLicenseStore(dbPath)
	if err != nil {
		t.Fatalf("failed initializing store: %v", err)
	}

	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"
	reg := MapLicenseKeyRegistry{
		keyID: TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub},
	}
	localPub, localPriv := generateTestKeyPair(t)

	mgr1, err := NewLicenseManager(LicenseManagerConfig{
		Store:              store1,
		KeyRegistry:        reg,
		LocalSignerKeyID:   "KEY-LOCAL-AGENT",
		LocalSignerPrivKey: localPriv,
	})
	if err != nil {
		t.Fatalf("failed creating manager 1: %v", err)
	}

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 50, 4)
	if _, err := mgr1.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Commit 7 assessments
	for i := 1; i <= 7; i++ {
		res, _ := mgr1.ReserveExecution(context.Background(), fmt.Sprintf("RESTART-OP-%d", i), FeatureCPaaS, 1)
		_, _ = mgr1.CommitExecution(res, "COMPLETED", nil)
	}

	// Close store 1 (simulate process exit / reboot)
	_ = store1.Close()

	// Reopen store in new process session
	store2, err := NewLicenseStore(dbPath)
	if err != nil {
		t.Fatalf("failed reopening store: %v", err)
	}
	defer store2.Close()

	mgr2, err := NewLicenseManager(LicenseManagerConfig{
		Store:              store2,
		KeyRegistry:        reg,
		LocalSignerKeyID:   "KEY-LOCAL-AGENT",
		LocalSignerPrivKey: localPriv,
	})
	if err != nil {
		t.Fatalf("failed initializing manager 2: %v", err)
	}

	// Verify exact state recovery
	report, err := mgr2.GetQuotaReport()
	if err != nil {
		t.Fatalf("failed getting quota report: %v", err)
	}

	if report.ConsumedAssessments != 7 {
		t.Errorf("expected 7 consumed assessments after restart, got %d", report.ConsumedAssessments)
	}
	if report.RemainingAssessments != 43 { // 50 - 7 = 43
		t.Errorf("expected 43 remaining assessments after restart, got %d", report.RemainingAssessments)
	}

	// Verify that the next committed record continues sequence 8 and links to sequence 7 digest
	res8, err := mgr2.ReserveExecution(context.Background(), "RESTART-OP-8", FeatureCPaaS, 1)
	if err != nil {
		t.Fatalf("reservation 8 failed: %v", err)
	}
	rec8, err := mgr2.CommitExecution(res8, "COMPLETED", nil)
	if err != nil {
		t.Fatalf("commit 8 failed: %v", err)
	}

	if rec8.SequenceNumber != 8 {
		t.Errorf("expected sequence number 8 after restart, got %d", rec8.SequenceNumber)
	}

	// Verify full export chain
	export, err := mgr2.ExportSignedUsage(context.Background())
	if err != nil {
		t.Fatalf("failed exporting usage: %v", err)
	}
	if export.TotalRecords != 8 {
		t.Errorf("expected 8 records in export, got %d", export.TotalRecords)
	}

	audit, err := VerifyUsageExport(export, localPub)
	if err != nil || !audit.Verified {
		t.Fatalf("export verification failed after restart: %v, issues: %v", err, audit.Issues)
	}
}

// -----------------------------------------------------------------------------
// Test Group 8: High Concurrency Race Safety & Double-Spend Defense
// -----------------------------------------------------------------------------

func TestLicensing_20_HighConcurrencyContention(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, _ := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	// Max assessments: 20. Max concurrency: 4.
	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 20, 4)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// Launch 50 concurrent goroutines attempting reservations
	var wg sync.WaitGroup
	var successfulCommits int64
	var concurrencyRejected int64
	var quotaRejected int64

	numGoroutines := 50
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			opID := fmt.Sprintf("PARALLEL-OP-%d", id)
			res, err := mgr.ReserveExecution(context.Background(), opID, FeatureCPaaS, 1)
			if err != nil {
				if errors.Is(err, ErrConcurrencyLimitExceeded) {
					concurrencyRejected++
				} else if errors.Is(err, ErrUsageQuotaExhausted) {
					quotaRejected++
				}
				return
			}

			// Simulate work
			time.Sleep(2 * time.Millisecond)

			if _, err := mgr.CommitExecution(res, "COMPLETED", nil); err == nil {
				successfulCommits++
			}
		}(i)
	}

	wg.Wait()

	report, err := mgr.GetQuotaReport()
	if err != nil {
		t.Fatalf("failed getting quota: %v", err)
	}

	// Strict invariants:
	// 1. Consumed assessments can NEVER exceed maxAssessments (20)
	if report.ConsumedAssessments > 20 {
		t.Fatalf("CRITICAL: Consumed assessments %d exceeded max limit 20", report.ConsumedAssessments)
	}
	// 2. Active concurrency must return to 0 after all operations complete
	if report.ActiveConcurrency != 0 {
		t.Errorf("expected active concurrency 0 after test, got %d", report.ActiveConcurrency)
	}
	// 3. Exact match between report consumed and successful commits
	if report.ConsumedAssessments != successfulCommits {
		t.Errorf("mismatch: report consumed %d != successful commits %d", report.ConsumedAssessments, successfulCommits)
	}
}

// -----------------------------------------------------------------------------
// Test Group 9: Performance Benchmarking
// -----------------------------------------------------------------------------

func TestLicensing_21_PerformanceBenchmarks(t *testing.T) {
	issuerPub, issuerPriv := generateTestKeyPair(t)
	keyID := "KEY-AUTH-01"

	mgr, _, localPriv := setupTestManager(t, func(c *LicenseManagerConfig, r *MapLicenseKeyRegistry) {
		(*r)[keyID] = TrustedLicenseKey{KeyID: keyID, PublicKey: issuerPub}
	})

	lic := createTestLicense(t, keyID, issuerPriv, TierEnterprise, 100000, 32)
	if _, err := mgr.InstallLicense(lic); err != nil {
		t.Fatalf("failed installing license: %v", err)
	}

	// 1. Benchmark License Verification Overhead
	const verifyIterations = 500
	startVerify := time.Now()
	for i := 0; i < verifyIterations; i++ {
		if _, err := mgr.VerifyLicense(lic); err != nil {
			t.Fatalf("verification failed at iteration %d: %v", i, err)
		}
	}
	verifyDuration := time.Since(startVerify)
	avgVerifyMicros := float64(verifyDuration.Microseconds()) / float64(verifyIterations)
	t.Logf("[Benchmark] License Verification: %.2f µs/op (Total: %v for %d ops)", avgVerifyMicros, verifyDuration, verifyIterations)

	if avgVerifyMicros > 2000.0 { // Must be sub-2ms
		t.Errorf("license verification overhead too high: %.2f µs", avgVerifyMicros)
	}

	// 2. Benchmark Usage Accounting & Commit Overhead
	const commitIterations = 100
	startCommit := time.Now()
	for i := 0; i < commitIterations; i++ {
		res, err := mgr.ReserveExecution(context.Background(), fmt.Sprintf("BENCH-OP-%d", i), FeatureCPaaS, 1)
		if err != nil {
			t.Fatalf("reservation failed: %v", err)
		}
		if _, err := mgr.CommitExecution(res, "COMPLETED", nil); err != nil {
			t.Fatalf("commit failed: %v", err)
		}
	}
	commitDuration := time.Since(startCommit)
	avgCommitMicros := float64(commitDuration.Microseconds()) / float64(commitIterations)
	t.Logf("[Benchmark] Metered Usage Commit (ACID + Ed25519): %.2f µs/op (Total: %v for %d ops)", avgCommitMicros, commitDuration, commitIterations)

	// 3. Benchmark Export Verification Overhead
	export, err := mgr.ExportSignedUsage(context.Background())
	if err != nil {
		t.Fatalf("failed exporting: %v", err)
	}
	localPub := localPriv.Public().(ed25519.PublicKey)

	startExportVerify := time.Now()
	auditRegistry := MapLicenseKeyRegistry{
		export.SignerKeyID: TrustedLicenseKey{KeyID: export.SignerKeyID, PublicKey: localPub},
	}
	audit, err := VerifyUsageExport(export, auditRegistry)
	exportVerifyDuration := time.Since(startExportVerify)
	if err != nil || !audit.Verified {
		t.Fatalf("export verification failed: %v", err)
	}
	t.Logf("[Benchmark] Export Audit Verification (100 records): %v", exportVerifyDuration)
}
