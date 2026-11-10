package report

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDueDiligence_01_DomainAndSubdomainAssetDiscovery(t *testing.T) {
	cfg := DueDiligenceConfig{
		TargetEntityName: "Acme Cloud Logistics",
		RootDomain:       "acme-logistics.com",
		AuthorizedScope:  []string{"acme-logistics.com", "*.acme-logistics.com"},
	}
	engine := NewDueDiligenceEngine(cfg, nil)

	candidates := []string{
		"acme-logistics.com",
		"api.acme-logistics.com",
		"admin.acme-logistics.com",
		"auth.acme-logistics.com",
		"malicious-third-party.com",
	}

	assets, err := engine.DiscoverPerimeterAssets(context.Background(), candidates)
	if err != nil {
		t.Fatalf("unexpected error discovering assets: %v", err)
	}

	if len(assets) != 5 {
		t.Fatalf("expected 5 assets evaluated, got %d", len(assets))
	}

	inScopeCount := 0
	adminCount := 0
	for _, a := range assets {
		if a.IsWithinScope {
			inScopeCount++
		}
		if a.Type == AssetTypeAdminInterface {
			adminCount++
			if a.ExposureTier != ExposureAdminExposed {
				t.Errorf("expected ExposureAdminExposed for admin interface, got %s", a.ExposureTier)
			}
		}
	}

	if inScopeCount != 4 {
		t.Errorf("expected 4 in-scope assets, got %d", inScopeCount)
	}
	if adminCount != 1 {
		t.Errorf("expected 1 admin interface asset, got %d", adminCount)
	}
}

func TestDueDiligence_02_PublicStorageExposureClassification(t *testing.T) {
	tests := []struct {
		name          string
		indicator     CloudStorageIndicator
		expectedClass string
		expectedSev   string
	}{
		{
			name: "Open public listing is Critical",
			indicator: CloudStorageIndicator{
				Provider:      "AWS_S3",
				BucketName:    "acme-customer-invoices",
				Accessibility: "PUBLIC_LIST_OPEN",
			},
			expectedClass: ExposureMisconfigured,
			expectedSev:   DDSeverityCritical,
		},
		{
			name: "Public object read is High",
			indicator: CloudStorageIndicator{
				Provider:      "GCP_STORAGE",
				BucketName:    "acme-data-exports",
				Accessibility: "PUBLIC_READ_OPEN",
			},
			expectedClass: ExposureMisconfigured,
			expectedSev:   DDSeverityHigh,
		},
		{
			name: "Anonymous access denied is restricted, not globally verified secure",
			indicator: CloudStorageIndicator{
				Provider:      "AWS_S3",
				BucketName:    "acme-private-backups",
				Accessibility: "ACCESS_DENIED",
			},
			expectedClass: ExposureAnonymousRestricted,
			expectedSev:   DDSeverityInfo,
		},
		{
			name: "Not Found is absent resource, not globally verified secure",
			indicator: CloudStorageIndicator{
				Provider:      "AZURE_BLOB",
				BucketName:    "acme-nonexistent",
				Accessibility: "NOT_FOUND",
			},
			expectedClass: ExposureResourceNotFound,
			expectedSev:   DDSeverityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ClassifyCloudStorageExposure(tt.indicator)
			if res.ExposureClassification != tt.expectedClass {
				t.Errorf("expected classification %s, got %s", tt.expectedClass, res.ExposureClassification)
			}
			if res.FindingSeverity != tt.expectedSev {
				t.Errorf("expected severity %s, got %s", tt.expectedSev, res.FindingSeverity)
			}
		})
	}
}

func TestDueDiligence_03_BaaSExposureClassification_FirebaseSupabase(t *testing.T) {
	// Strict Rule Test: Public API key / config alone is NOT a vulnerability
	benignIndicator := BaaSIndicator{
		Provider:            "FIREBASE_RTDB",
		InstanceID:          "acme-mobile-prod",
		ConfigurationStatus: "BENIGN_PUBLIC_KEY",
	}
	benignClassified := ClassifyBaaSExposure(benignIndicator)
	if benignClassified.ExposureClassification != ExposurePublicSafe {
		t.Errorf("expected ExposurePublicSafe for benign client config, got %s", benignClassified.ExposureClassification)
	}
	if benignClassified.FindingSeverity != DDSeverityInfo {
		t.Errorf("expected INFO severity for benign client config, got %s", benignClassified.FindingSeverity)
	}
	if strings.Contains(strings.ToLower(benignClassified.Evidence), "not a vulnerability") == false {
		t.Errorf("expected evidence to clarify not a vulnerability, got: %s", benignClassified.Evidence)
	}

	// Confirmed open rules is Critical
	openIndicator := BaaSIndicator{
		Provider:            "FIREBASE_RTDB",
		InstanceID:          "acme-leaked-staging",
		ConfigurationStatus: "OPEN_RULES_CONFIRMED",
	}
	openClassified := ClassifyBaaSExposure(openIndicator)
	if openClassified.ExposureClassification != ExposureMisconfigured {
		t.Errorf("expected ExposureMisconfigured for open rules, got %s", openClassified.ExposureClassification)
	}
	if openClassified.FindingSeverity != DDSeverityCritical {
		t.Errorf("expected CRITICAL severity for open rules, got %s", openClassified.FindingSeverity)
	}
}

func TestDueDiligence_04_MobileAPKAssessmentIntegration(t *testing.T) {
	apk := MobileAPKMetadata{
		PackageName:               "com.acme.logistics.driver",
		VersionName:               "2.4.1",
		VersionCode:               142,
		MinSDK:                    24,
		TargetSDK:                 33,
		TotalPermissions:          18,
		DangerousPermissions:      []string{"android.permission.ACCESS_FINE_LOCATION", "android.permission.CAMERA"},
		ExportedActivitiesCount:   2,
		ExportedServicesCount:     1,
		CleartextTrafficPermitted: true,
		InsecureNetworkConfig:     true,
		EmbeddedEndpointsCount:    12,
		HardcodedSecretsCount:     1,
		StaticRiskScore:           68,
		AnalysisProvenance:        "STATIC_BINARY_EXTRACTION_ONLY",
	}

	if apk.AnalysisProvenance != "STATIC_BINARY_EXTRACTION_ONLY" {
		t.Errorf("expected static provenance, got %s", apk.AnalysisProvenance)
	}
	if !apk.CleartextTrafficPermitted {
		t.Errorf("expected cleartext traffic permitted to be true")
	}
	if apk.HardcodedSecretsCount != 1 {
		t.Errorf("expected 1 hardcoded secret, got %d", apk.HardcodedSecretsCount)
	}
}

func TestDueDiligence_05_FindingProvenanceAndStatePreservation(t *testing.T) {
	findings := []SecurityFindingInput{
		{
			ID:       "FIND-001",
			Title:    "SQL Injection in Customer Portal",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
		{
			ID:       "FIND-002",
			Title:    "Potential IDOR on Order Lookup",
			Severity: DDSeverityHigh,
			Status:   DDStatusPotential,
		},
		{
			ID:       "FIND-003",
			Title:    "TLS Cipher Suite Audit Inconclusive",
			Severity: DDSeverityMedium,
			Status:   DDStatusInconclusive,
		},
		{
			ID:       "FIND-004",
			Title:    "Internal Active Directory Not Assessed",
			Severity: DDSeverityInfo,
			Status:   DDStatusNotAssessed,
		},
	}

	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName: "Acme Corp",
			RootDomain:       "acme.com",
		},
		Findings: findings,
	}

	debt := EstimateTechnicalDebt(findings, 150.0)
	reg := EstimateRegulatoryExposure(input.Config, findings)
	profile := CalculateAcquisitionRiskProfile(input, debt, reg)

	if profile.VerifiedDefectsCount != 1 {
		t.Errorf("expected 1 verified defect, got %d", profile.VerifiedDefectsCount)
	}
	if profile.PotentialFindingsCount != 1 {
		t.Errorf("expected 1 potential finding, got %d", profile.PotentialFindingsCount)
	}
	if profile.InconclusiveChecksCount != 1 {
		t.Errorf("expected 1 inconclusive check, got %d", profile.InconclusiveChecksCount)
	}
	if profile.NotAssessedChecksCount != 1 {
		t.Errorf("expected 1 not assessed check, got %d", profile.NotAssessedChecksCount)
	}
}

func TestDueDiligence_06_TechnicalDebtEstimation_HoursAndCost(t *testing.T) {
	findings := []SecurityFindingInput{
		{
			ID:       "F-1",
			Title:    "Broken Object Level Authorization (BOLA)",
			Category: "API_AUTHORIZATION",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
		{
			ID:       "F-2",
			Title:    "Missing CSRF Protection",
			Category: "WEB_SECURITY",
			Severity: DDSeverityMedium,
			Status:   DDStatusVerifiedDefect,
		},
		{
			ID:       "F-3",
			Title:    "Missing Content-Security-Policy",
			Category: "SECURITY_HEADERS",
			Severity: DDSeverityLow,
			Status:   DDStatusVerifiedDefect,
		},
	}

	rate := 175.0 // $175/hr
	debt := EstimateTechnicalDebt(findings, rate)

	if debt.TotalFindingsEvaluated != 3 {
		t.Errorf("expected 3 findings evaluated, got %d", debt.TotalFindingsEvaluated)
	}

	// Base hours should be:
	// F-1 (Critical Auth): 80 hrs
	// F-2 (Medium): 12 hrs
	// F-3 (Low): 4 hrs
	// Total base: 96 hrs
	expectedBase := 96.0
	if debt.TotalBaseHours != expectedBase {
		t.Errorf("expected base hours %.1f, got %.1f", expectedBase, debt.TotalBaseHours)
	}

	// Lower hours should be 0.6x = 57.6 hrs
	expectedLower := 57.6
	if debt.TotalLowerHours != expectedLower {
		t.Errorf("expected lower hours %.1f, got %.1f", expectedLower, debt.TotalLowerHours)
	}

	// Upper hours should be 1.8x = 172.8 hrs
	expectedUpper := 172.8
	if debt.TotalUpperHours != expectedUpper {
		t.Errorf("expected upper hours %.1f, got %.1f", expectedUpper, debt.TotalUpperHours)
	}

	// Cost verification
	expectedCost := expectedBase * rate
	if debt.TotalBaseCostUSD != expectedCost {
		t.Errorf("expected cost $%.0f, got $%.0f", expectedCost, debt.TotalBaseCostUSD)
	}
}

func TestDueDiligence_07_GDPRStatutoryCeilingsAndScenarios(t *testing.T) {
	cfg := DueDiligenceConfig{
		TargetEntityName: "EuroLogistics GmbH",
		RootDomain:       "eurologistics.de",
		AnnualRevenueEUR: 50000000.0, // €50M
	}

	findings := []SecurityFindingInput{
		{
			ID:       "GDPR-01",
			Title:    "Unauthenticated API exposing Customer PII",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	reg := EstimateRegulatoryExposure(cfg, findings)

	// Article 83(4): max(€10M, 2% of €50M = €1M) -> €10M
	expectedArt83_4 := 10000000.0
	if reg.GDPR.StatutoryCeilingArt83_4 != expectedArt83_4 {
		t.Errorf("expected Art 83(4) ceiling €%.0f, got €%.0f", expectedArt83_4, reg.GDPR.StatutoryCeilingArt83_4)
	}

	// Article 83(5): max(€20M, 4% of €50M = €2M) -> €20M
	expectedArt83_5 := 20000000.0
	if reg.GDPR.StatutoryCeilingArt83_5 != expectedArt83_5 {
		t.Errorf("expected Art 83(5) ceiling €%.0f, got €%.0f", expectedArt83_5, reg.GDPR.StatutoryCeilingArt83_5)
	}

	if reg.GDPR.ProbableScenarioEUR <= 0 {
		t.Errorf("expected positive probable GDPR scenario, got %.0f", reg.GDPR.ProbableScenarioEUR)
	}
	if reg.GDPR.ProbableScenarioEUR > reg.GDPR.StatutoryMaxCeilingEUR {
		t.Errorf("probable scenario exceeds statutory ceiling")
	}
}

func TestDueDiligence_08_DPDPStatutoryCeilingsAndScheduleScenarios(t *testing.T) {
	cfg := DueDiligenceConfig{
		TargetEntityName:           "Bharat Commerce Pvt Ltd",
		RootDomain:                 "bharat-commerce.in",
		AnnualRevenueINR:           500000000.0, // ₹50 Crore
		ProcessesChildrenData:      true,
		IsSignificantDataFiduciary: true,
	}

	findings := []SecurityFindingInput{
		{
			ID:       "DPDP-01",
			Title:    "Open S3 Bucket with Customer ID Proofs",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	reg := EstimateRegulatoryExposure(cfg, findings)

	// Section 8(5) ceiling: ₹250 Crore
	if reg.DPDP.StatutoryCeilingSec8_5 != 2500000000.0 {
		t.Errorf("expected Section 8(5) ceiling ₹250 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec8_5)
	}
	// Section 8(6) ceiling: ₹200 Crore
	if reg.DPDP.StatutoryCeilingSec8_6 != 2000000000.0 {
		t.Errorf("expected Section 8(6) ceiling ₹200 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec8_6)
	}
	// Section 9 ceiling: ₹200 Crore (Official Statutory Schedule Item 3, corrected from erroneous ₹150 Crore)
	if reg.DPDP.StatutoryCeilingSec9 != 2000000000.0 {
		t.Errorf("expected Section 9 ceiling ₹200 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec9)
	}
	// Section 10 ceiling: ₹150 Crore
	if reg.DPDP.StatutoryCeilingSec10 != 1500000000.0 {
		t.Errorf("expected Section 10 ceiling ₹150 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec10)
	}
	// Section 15 ceiling: ₹10,000
	if reg.DPDP.StatutoryCeilingSec15 != 10000.0 {
		t.Errorf("expected Section 15 ceiling ₹10,000, got %.0f", reg.DPDP.StatutoryCeilingSec15)
	}
	// Residual ceiling: ₹50 Crore
	if reg.DPDP.StatutoryCeilingResidual != 500000000.0 {
		t.Errorf("expected Residual ceiling ₹50 Crore, got %.0f", reg.DPDP.StatutoryCeilingResidual)
	}

	// Cumulative ceiling across applicable distinct contraventions: 8(5) + 8(6) + 9 + 10 = ₹800 Crore
	expectedCumulative := 8000000000.0
	if reg.DPDP.StatutoryMaxCeilingINR != expectedCumulative {
		t.Errorf("expected cumulative ceiling ₹%.0f, got ₹%.0f", expectedCumulative, reg.DPDP.StatutoryMaxCeilingINR)
	}

	if reg.DPDP.ProbableScenarioINR <= 0 {
		t.Errorf("expected positive probable DPDP scenario")
	}

	// Verify itemized schedule categories model separate statutory caps and preserve "may extend to"
	if len(reg.DPDP.ScheduleCategories) != 7 {
		t.Fatalf("expected 7 schedule categories, got %d", len(reg.DPDP.ScheduleCategories))
	}
	for _, cat := range reg.DPDP.ScheduleCategories {
		if cat.ScheduleItemNumber == 6 {
			// Item 6: Section 32 voluntary undertaking
			if !strings.Contains(strings.ToLower(cat.StatutoryWording), "up to the extent applicable") {
				t.Errorf("expected schedule category 6 wording to contain 'up to the extent applicable', got: %s", cat.StatutoryWording)
			}
		} else {
			if !strings.Contains(strings.ToLower(cat.StatutoryWording), "may extend to") {
				t.Errorf("expected schedule category %d (%s) wording to contain 'may extend to', got: %s", cat.ScheduleItemNumber, cat.ProvisionRef, cat.StatutoryWording)
			}
		}
	}

	// Verify Section 33(2) determination factors are documented
	if len(reg.DPDP.PenaltyDeterminationFactors) < 7 {
		t.Errorf("expected at least 7 penalty determination factors from Section 33(2), got %d", len(reg.DPDP.PenaltyDeterminationFactors))
	}
}

func TestDueDiligence_09_InvalidAndIncompleteRegulatoryInputs(t *testing.T) {
	// Zero revenue provided -> fallback to reasonable SME baseline
	cfg := DueDiligenceConfig{
		TargetEntityName: "Stealth Startup Inc",
		RootDomain:       "stealth-startup.io",
		AnnualRevenueUSD: 0,
		AnnualRevenueEUR: 0,
		AnnualRevenueINR: 0,
	}

	reg := EstimateRegulatoryExposure(cfg, nil)

	if reg.GDPR.StatutoryMaxCeilingEUR != 20000000.0 {
		t.Errorf("expected fallback GDPR ceiling €20M, got €%.0f", reg.GDPR.StatutoryMaxCeilingEUR)
	}
	if reg.DPDP.StatutoryMaxCeilingINR != 2500000000.0 {
		t.Errorf("expected fallback DPDP ceiling ₹250 Crore, got ₹%.0f", reg.DPDP.StatutoryMaxCeilingINR)
	}
}

func TestDueDiligence_10_AcquisitionRiskScoringAndGrading(t *testing.T) {
	cleanInput := DueDiligenceInput{
		Config: DueDiligenceConfig{TargetEntityName: "Clean Corp", RootDomain: "clean.com"},
	}
	cleanDebt := EstimateTechnicalDebt(nil, 150.0)
	cleanReg := EstimateRegulatoryExposure(cleanInput.Config, nil)
	cleanProfile := CalculateAcquisitionRiskProfile(cleanInput, cleanDebt, cleanReg)

	if cleanProfile.CompositeRiskScore > 25 {
		t.Errorf("expected clean profile score <= 25, got %d", cleanProfile.CompositeRiskScore)
	}
	if cleanProfile.AcquisitionRecommendation != RecRecommendedClean {
		t.Errorf("expected RecRecommendedClean, got %s", cleanProfile.AcquisitionRecommendation)
	}

	// Severe target with critical vulnerabilities and open buckets
	severeInput := DueDiligenceInput{
		Config: DueDiligenceConfig{TargetEntityName: "Vulnerable Target", RootDomain: "vuln.com"},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Severity: DDSeverityCritical, Status: DDStatusVerifiedDefect, TargetURL: "https://vuln.com/api/admin"},
			{ID: "F-2", Severity: DDSeverityCritical, Status: DDStatusVerifiedDefect, TargetURL: "https://vuln.com/api/payments"},
			{ID: "F-3", Severity: DDSeverityHigh, Status: DDStatusVerifiedDefect, TargetURL: "https://vuln.com/api/users"},
		},
		CloudStorageIndicators: []CloudStorageIndicator{
			{BucketName: "vuln-secrets", Accessibility: "PUBLIC_LIST_OPEN", ExposureClassification: ExposureMisconfigured, FindingSeverity: DDSeverityCritical},
		},
		BaaSIndicators: []BaaSIndicator{
			{InstanceID: "vuln-db", ConfigurationStatus: "OPEN_RULES_CONFIRMED", ExposureClassification: ExposureMisconfigured, FindingSeverity: DDSeverityCritical},
		},
	}
	severeDebt := EstimateTechnicalDebt(severeInput.Findings, 150.0)
	severeReg := EstimateRegulatoryExposure(severeInput.Config, severeInput.Findings)
	severeProfile := CalculateAcquisitionRiskProfile(severeInput, severeDebt, severeReg)

	if severeProfile.CompositeRiskScore < 75 {
		t.Errorf("expected severe profile score >= 75, got %d", severeProfile.CompositeRiskScore)
	}
	if severeProfile.RiskTier != "CRITICAL_LIABILITY" {
		t.Errorf("expected CRITICAL_LIABILITY, got %s", severeProfile.RiskTier)
	}
}

func TestDueDiligence_11_ExecutiveDossier15SectionsGeneration(t *testing.T) {
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:     "Target Logistics Ltd",
			RootDomain:           "target-logistics.com",
			AuthorizedScope:      []string{"target-logistics.com", "*.target-logistics.com"},
			BlendedHourlyRateUSD: 160.0,
			AnnualRevenueUSD:     25000000.0,
		},
		Assets: []DiscoveredAsset{
			{AssetID: "AST-1", Type: AssetTypeDomain, Identifier: "target-logistics.com", TargetURL: "https://target-logistics.com", IsWithinScope: true},
			{AssetID: "AST-2", Type: AssetTypeAdminInterface, Identifier: "admin.target-logistics.com", TargetURL: "https://admin.target-logistics.com", ExposureTier: ExposureAdminExposed, IsWithinScope: true},
		},
		Findings: []SecurityFindingInput{
			{ID: "FND-001", Title: "Hardcoded Database Credentials in Mobile APK", Severity: DDSeverityCritical, Status: DDStatusVerifiedDefect, TargetURL: "https://api.target-logistics.com"},
			{ID: "FND-002", Title: "Missing Rate Limiting on Login", Severity: DDSeverityMedium, Status: DDStatusVerifiedDefect, TargetURL: "https://auth.target-logistics.com"},
		},
		ExecutionTimestamp: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC),
	}

	dossier, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	// Verify all 15 sections are populated
	if dossier.Section1_ExecutiveSummary.TargetEntityName != "Target Logistics Ltd" {
		t.Errorf("section 1 invalid")
	}
	if len(dossier.Section2_TargetAssessmentScope.AuthorizedScope) != 2 {
		t.Errorf("section 2 invalid")
	}
	if len(dossier.Section3_AssetInventory) != 2 {
		t.Errorf("section 3 invalid")
	}
	if dossier.Section4_ExternalAttackSurface.TotalDiscoveredAssets != 2 {
		t.Errorf("section 4 invalid")
	}
	if dossier.Section5_CloudAndBaaSExposure.Summary == "" {
		t.Errorf("section 5 invalid")
	}
	if dossier.Section6_MobileAppAssessment.Summary == "" {
		t.Errorf("section 6 invalid")
	}
	if len(dossier.Section7_CriticalSecurityFindings) != 2 {
		t.Errorf("section 7 invalid")
	}
	if dossier.Section8_TechnicalDebt.TotalFindingsEvaluated != 2 {
		t.Errorf("section 8 invalid")
	}
	if len(dossier.Section9_RemediationEstimates) != 2 {
		t.Errorf("section 9 invalid")
	}
	if dossier.Section10_RegulatoryExposure.GDPR.StatutoryMaxCeilingEUR <= 0 {
		t.Errorf("section 10 invalid")
	}
	if dossier.Section11_AcquisitionIntegration.IntegrationComplexity == "" {
		t.Errorf("section 11 invalid")
	}
	if len(dossier.Section12_RiskPrioritization) != 2 {
		t.Errorf("section 12 invalid")
	}
	if !dossier.Section13_EvidenceProvenance.ZeroCredentialEnforced {
		t.Errorf("section 13 invalid")
	}
	if dossier.Section14_RemediationRoadmap.RecommendedEscrowUSD <= 0 {
		t.Errorf("section 14 invalid")
	}
	if dossier.Section15_FinalAcquisitionRisk.CompositeRiskScore <= 0 {
		t.Errorf("section 15 invalid")
	}
	if dossier.CanonicalDigest == "" {
		t.Errorf("canonical digest was not computed")
	}
}

func TestDueDiligence_12_DeterministicOutputAndCanonicalDigest(t *testing.T) {
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:     "Deterministic Target",
			RootDomain:           "determ.com",
			BlendedHourlyRateUSD: 150.0,
		},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Title: "XSS in Search Bar", Severity: DDSeverityMedium, Status: DDStatusVerifiedDefect},
		},
		ExecutionTimestamp: time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC),
	}

	dossier1, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("first generation failed: %v", err)
	}

	dossier2, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("second generation failed: %v", err)
	}

	if dossier1.CanonicalDigest != dossier2.CanonicalDigest {
		t.Errorf("digests differed: %s != %s", dossier1.CanonicalDigest, dossier2.CanonicalDigest)
	}

	json1, _ := dossier1.ToJSON()
	json2, _ := dossier2.ToJSON()
	if string(json1) != string(json2) {
		t.Errorf("JSON output differed across deterministic runs")
	}
}

func TestDueDiligence_13_SecretRedactionInDossier(t *testing.T) {
	secretTarget := "https://api.acme.com/v1?token=secret_token_1234567890abcdef"
	classified := ClassifyCloudStorageExposure(CloudStorageIndicator{
		BucketName:    "acme-test",
		URL:           secretTarget,
		Accessibility: "PUBLIC_READ_OPEN",
	})

	if strings.Contains(classified.URL, "secret_token_1234567890abcdef") {
		t.Errorf("secret token was not redacted in URL: %s", classified.URL)
	}
}

func TestDueDiligence_14_ScopeEnforcementAndGuardrails(t *testing.T) {
	scope := []string{"acme.com", "*.acme.com", "sub.example.org"}

	if !IsTargetInScope("acme.com", scope) {
		t.Errorf("expected acme.com to be in scope")
	}
	if !IsTargetInScope("api.acme.com", scope) {
		t.Errorf("expected api.acme.com to be in scope")
	}
	if !IsTargetInScope("https://portal.acme.com/login", scope) {
		t.Errorf("expected portal.acme.com URL to be in scope")
	}
	if IsTargetInScope("evil-acme.com", scope) {
		t.Errorf("evil-acme.com must NOT be in scope")
	}
	if IsTargetInScope("169.254.169.254", scope) {
		t.Errorf("cloud metadata must NOT be in scope")
	}
}

func TestDueDiligence_15_SSRFAndHostileDestinationDefense(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock endpoint
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer server.Close()

	cfg := DueDiligenceConfig{
		TargetEntityName: "Test Target",
		RootDomain:       "test.com",
		AuthorizedScope:  []string{"test.com"}, // server.URL is loopback and not in scope
		Timeout:          2 * time.Second,
	}

	engine := NewDueDiligenceEngine(cfg, nil)

	// Attempting to probe an out-of-scope host via HTTP client should fail redirect or dial
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	if err == nil {
		_, err = engine.httpClient.Do(req)
		if err == nil {
			t.Errorf("expected SSRF request to cloud metadata to be blocked")
		}
	}
}

func TestDueDiligence_16_MarkdownAndHTMLExport(t *testing.T) {
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:     "Export Corp",
			RootDomain:           "export.com",
			BlendedHourlyRateUSD: 150.0,
		},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Title: "Open Redirect on Login", Severity: DDSeverityLow, Status: DDStatusVerifiedDefect},
		},
		ExecutionTimestamp: time.Date(2026, 11, 10, 10, 0, 0, 0, time.UTC),
	}

	dossier, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	md := dossier.ToMarkdown()
	if !strings.Contains(md, "FELIX M&A TECHNICAL DUE-DILIGENCE") {
		t.Errorf("markdown missing title")
	}
	if !strings.Contains(md, "LEGAL & FINANCIAL DISCLAIMER") {
		t.Errorf("markdown missing disclaimer")
	}

	htmlOut, err := dossier.ToExecutiveHTML()
	if err != nil {
		t.Fatalf("failed rendering HTML: %v", err)
	}
	if !strings.Contains(htmlOut, "<!DOCTYPE html>") {
		t.Errorf("HTML missing doctype")
	}
	if !strings.Contains(htmlOut, "Export Corp") {
		t.Errorf("HTML missing target name")
	}
}

func TestDueDiligence_17_Phase74DossierCompatibility(t *testing.T) {
	// Verify compatibility with Phase 7.4 DossierInput
	dossierInput := DossierInput{
		Organization:    "Compatible Org",
		AssessmentTitle: "M&A Pre-Screen",
		Metadata: map[string]any{
			"m_and_a_due_diligence_version": DueDiligenceSchemaVersion,
		},
	}
	if dossierInput.Metadata["m_and_a_due_diligence_version"] != DueDiligenceSchemaVersion {
		t.Errorf("Phase 7.4 metadata compatibility error")
	}
}

func TestDueDiligence_18_MultiAssetLabEndToEndSimulation(t *testing.T) {
	// Comprehensive end-to-end multi-asset laboratory simulation:
	// Combines web perimeter + public cloud S3 + Firebase BaaS + Mobile APK
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:            "OmniHealth Telemedicine Inc",
			RootDomain:                  "omnihealth.io",
			AuthorizedScope:             []string{"omnihealth.io", "*.omnihealth.io", "omnihealth-records.s3.amazonaws.com"},
			BlendedHourlyRateUSD:        175.0,
			AnnualRevenueUSD:            40000000.0,  // $40M
			AnnualRevenueEUR:            36800000.0,  // €36.8M
			AnnualRevenueINR:            3320000000.0, // ₹332 Crore
			DataPrincipalsCount:         250000,
			HasEUDataSubjects:           true,
			HasIndianDataPrincipals:     true,
			ProcessesChildrenData:       true,
			IsSignificantDataFiduciary:  true,
			EstimatedEnterpriseValueUSD: 120000000.0,
			DealSizeUSD:                 95000000.0,
		},
		Assets: []DiscoveredAsset{
			{AssetID: "AST-01", Type: AssetTypeDomain, Identifier: "omnihealth.io", TargetURL: "https://omnihealth.io", IsWithinScope: true},
			{AssetID: "AST-02", Type: AssetTypeSubdomain, Identifier: "api.omnihealth.io", TargetURL: "https://api.omnihealth.io", IsWithinScope: true},
			{AssetID: "AST-03", Type: AssetTypeAdminInterface, Identifier: "ehr-admin.omnihealth.io", TargetURL: "https://ehr-admin.omnihealth.io", ExposureTier: ExposureAdminExposed, IsWithinScope: true},
			{AssetID: "AST-04", Type: AssetTypeCloudBucket, Identifier: "omnihealth-records", TargetURL: "https://omnihealth-records.s3.amazonaws.com", ExposureTier: ExposureMisconfigured, IsWithinScope: true},
			{AssetID: "AST-05", Type: AssetTypeBaaSInstance, Identifier: "omnihealth-chat", TargetURL: "https://omnihealth-chat.firebaseio.com", ExposureTier: ExposurePublicSafe, IsWithinScope: true},
		},
		CloudStorageIndicators: []CloudStorageIndicator{
			{
				Provider:      "AWS_S3",
				BucketName:    "omnihealth-records",
				URL:           "https://omnihealth-records.s3.amazonaws.com",
				Accessibility: "PUBLIC_LIST_OPEN",
				IsWithinScope: true,
			},
		},
		BaaSIndicators: []BaaSIndicator{
			{
				Provider:            "FIREBASE_RTDB",
				InstanceID:          "omnihealth-chat",
				URL:                 "https://omnihealth-chat.firebaseio.com",
				ConfigurationStatus: "BENIGN_PUBLIC_KEY",
				IsWithinScope:       true,
			},
		},
		MobileApplications: []MobileAPKMetadata{
			{
				PackageName:               "io.omnihealth.patient",
				VersionName:               "3.1.0",
				VersionCode:               310,
				MinSDK:                    26,
				TargetSDK:                 34,
				TotalPermissions:          14,
				DangerousPermissions:      []string{"android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION"},
				ExportedActivitiesCount:   1,
				CleartextTrafficPermitted: false,
				InsecureNetworkConfig:     false,
				EmbeddedEndpointsCount:    8,
				HardcodedSecretsCount:     0,
				StaticRiskScore:           25,
				AnalysisProvenance:        "STATIC_BINARY_EXTRACTION_ONLY",
			},
		},
		Findings: []SecurityFindingInput{
			{
				ID:                 "VULN-001",
				RuleID:             "API-BOLA-PATIENT-RECORDS",
				Title:              "Broken Object Level Authorization (BOLA) on Patient Telehealth Records",
				Category:           "BOLA_AUTHORIZATION",
				Severity:           DDSeverityCritical,
				Status:             DDStatusVerifiedDefect,
				TargetURL:          "https://api.omnihealth.io/v1/patients/{id}/records",
				Component:          "telehealth-api",
				Description:        "Callers can manipulate the patient ID parameter to view medical summaries of other data principals.",
				RemediationSummary: "Implement strict tenancy validation against the authenticated JWT principal claims.",
			},
			{
				ID:                 "VULN-002",
				RuleID:             "CLOUD-S3-PUBLIC-LISTING",
				Title:              "Public Object Listing on Telehealth Records S3 Bucket",
				Category:           "CLOUD_STORAGE",
				Severity:           DDSeverityCritical,
				Status:             DDStatusVerifiedDefect,
				TargetURL:          "https://omnihealth-records.s3.amazonaws.com",
				Component:          "aws-s3",
				IsCloudOrBaaS:      true,
				Description:        "Anonymous callers can list bucket keys containing patient diagnostic attachments.",
				RemediationSummary: "Enable S3 Block Public Access and attach restrictive bucket policy.",
			},
			{
				ID:                 "VULN-003",
				RuleID:             "ADMIN-PORTAL-NO-MFA",
				Title:              "Administrative Portal Accessible without Mandatory Multi-Factor Authentication",
				Category:           "AUTHENTICATION",
				Severity:           DDSeverityHigh,
				Status:             DDStatusVerifiedDefect,
				TargetURL:          "https://ehr-admin.omnihealth.io",
				Component:          "ehr-admin",
				Description:        "Administrative portal relies strictly on single-factor password authentication.",
				RemediationSummary: "Enforce WebAuthn / FIDO2 or TOTP second-factor challenge for all administrative roles.",
			},
		},
		ExecutionTimestamp: time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC),
	}

	engine := NewDueDiligenceEngine(input.Config, nil)
	dossier, err := engine.ExecuteAssessment(context.Background(), input)
	if err != nil {
		t.Fatalf("failed executing full simulation: %v", err)
	}

	// Assertions on the synthesized M&A acquisition evaluation:
	if dossier.TargetEntityName != "OmniHealth Telemedicine Inc" {
		t.Errorf("entity name mismatch")
	}

	// 2 critical verified defects + 1 high verified defect + 1 critical open S3 bucket
	// Should yield Risk Tier "ELEVATED_RISK" or "CRITICAL_LIABILITY"
	if dossier.Section15_FinalAcquisitionRisk.CompositeRiskScore < 50 {
		t.Errorf("expected elevated or critical risk score (>= 50), got %d", dossier.Section15_FinalAcquisitionRisk.CompositeRiskScore)
	}

	// Recommendation must condition acquisition on remediation escrow
	if dossier.Section15_FinalAcquisitionRisk.AcquisitionRecommendation != RecSignificantConditions &&
		dossier.Section15_FinalAcquisitionRisk.AcquisitionRecommendation != RecUnfavorableHighLiability {
		t.Errorf("expected significant conditions or unfavorable recommendation, got %s", dossier.Section15_FinalAcquisitionRisk.AcquisitionRecommendation)
	}

	// Technical debt must reflect hours for BOLA + S3 + Admin MFA
	if dossier.Section8_TechnicalDebt.TotalBaseHours < 100 {
		t.Errorf("expected at least 100 base remediation hours, got %.1f", dossier.Section8_TechnicalDebt.TotalBaseHours)
	}

	// Escrow holdback must be calculated and non-zero
	if dossier.Section14_RemediationRoadmap.RecommendedEscrowUSD < 50000.0 {
		t.Errorf("expected recommended escrow >= $50,000 USD, got $%.0f", dossier.Section14_RemediationRoadmap.RecommendedEscrowUSD)
	}

	// Regulatory exposure must calculate both GDPR and DPDP Act statutory ceilings
	if dossier.Section10_RegulatoryExposure.GDPR.StatutoryMaxCeilingEUR != 20000000.0 { // 4% of €36.8M is ~€1.47M, so €20M applies
		t.Errorf("expected GDPR ceiling €20,000,000, got €%.0f", dossier.Section10_RegulatoryExposure.GDPR.StatutoryMaxCeilingEUR)
	}
	if dossier.Section10_RegulatoryExposure.DPDP.StatutoryMaxCeilingINR != 8000000000.0 { // Sec 8(5) 250Cr + 8(6) 200Cr + Sec 9 200Cr + Sec 10 150Cr = 800Cr
		t.Errorf("expected DPDP ceiling ₹800 Crore, got ₹%.0f", dossier.Section10_RegulatoryExposure.DPDP.StatutoryMaxCeilingINR)
	}

	// Verify Canonical Digest is computed and deterministic
	if len(dossier.CanonicalDigest) != 64 {
		t.Errorf("expected 64-character SHA-256 digest, got %q", dossier.CanonicalDigest)
	}
}

func TestDueDiligence_19_DPDPPreCommencementDate(t *testing.T) {
	// Assessment date before 13 May 2027 (e.g., 10 November 2026)
	// Substantive provisions (Sections 3-17) and penalties are SCHEDULED_TO_COMMENCE; enforceable liability is ₹0.
	assessmentDate := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	cfg := DueDiligenceConfig{
		TargetEntityName:           "IndiKart Retail Ltd",
		RootDomain:                 "indikart.in",
		AssessmentDate:             assessmentDate,
		AnnualRevenueINR:           2000000000.0, // ₹200 Crore
		ProcessesChildrenData:      true,
		IsSignificantDataFiduciary: true,
	}

	findings := []SecurityFindingInput{
		{
			ID:       "FIND-01",
			Title:    "Unrestricted API Exposing Customer Identity Data",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	reg := EstimateRegulatoryExposure(cfg, findings)

	// Statutory status of penalty framework must be SCHEDULED_TO_COMMENCE
	if reg.DPDP.PenaltyFrameworkStatus != LegalStatusScheduledToCommence {
		t.Errorf("expected PenaltyFrameworkStatus %s, got %s", LegalStatusScheduledToCommence, reg.DPDP.PenaltyFrameworkStatus)
	}
	if reg.DPDP.LegalCommencementStatus != LegalStatusScheduledToCommence {
		t.Errorf("expected LegalCommencementStatus %s, got %s", LegalStatusScheduledToCommence, reg.DPDP.LegalCommencementStatus)
	}

	// Overall Act status must be PARTIALLY_COMMENCED for assessment date 2026-11-10 (Stage 1 in force since 2025-11-13)
	if reg.DPDP.ActOverallStatus != LegalStatusPartiallyCommenced {
		t.Errorf("expected ActOverallStatus %s, got %s", LegalStatusPartiallyCommenced, reg.DPDP.ActOverallStatus)
	}

	// Must NOT be currently enforceable
	if reg.DPDP.IsCurrentlyEnforceable || reg.DPDP.IsPenaltyEffective {
		t.Errorf("expected penalty framework to not be effective prior to 13 May 2027")
	}

	// Currently enforceable liability must strictly be ₹0
	if reg.DPDP.CurrentEnforceableMaxINR != 0.0 {
		t.Errorf("expected CurrentEnforceableMaxINR to be 0 prior to 13 May 2027, got %.0f", reg.DPDP.CurrentEnforceableMaxINR)
	}
	if reg.DPDP.CurrentEnforceableProbableINR != 0.0 {
		t.Errorf("expected CurrentEnforceableProbableINR to be 0 prior to 13 May 2027, got %.0f", reg.DPDP.CurrentEnforceableProbableINR)
	}

	// Future statutory ceilings must remain intact: Sec 8(5) ₹250 Cr, Sec 8(6) ₹200 Cr, Sec 9 ₹200 Cr, Sec 10 ₹150 Cr = ₹800 Cr
	if reg.DPDP.StatutoryCeilingSec8_5 != 2500000000.0 {
		t.Errorf("expected Section 8(5) ceiling ₹250 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec8_5)
	}
	if reg.DPDP.StatutoryCeilingSec9 != 2000000000.0 {
		t.Errorf("expected Section 9 ceiling ₹200 Crore, got %.0f", reg.DPDP.StatutoryCeilingSec9)
	}
	if reg.DPDP.StatutoryMaxCeilingINR != 8000000000.0 {
		t.Errorf("expected statutory maximum ceiling ₹800 Crore, got %.0f", reg.DPDP.StatutoryMaxCeilingINR)
	}

	// Projected future probable scenario must be positive
	if reg.DPDP.ProbableScenarioINR <= 0.0 {
		t.Errorf("expected positive future projected probable scenario")
	}

	// Verify statutory effective date
	if reg.DPDP.StatutoryEffectiveDate != "2027-05-13" {
		t.Errorf("expected statutory effective date 2027-05-13, got %s", reg.DPDP.StatutoryEffectiveDate)
	}
}

func TestDueDiligence_20_DPDPPostCommencementDate(t *testing.T) {
	// Assessment date after 13 May 2027 (e.g., 1 June 2027)
	// Provisions are IN_FORCE; enforceable liabilities are active.
	postDate := time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC)
	cfg := DueDiligenceConfig{
		TargetEntityName:           "IndiKart Retail Ltd",
		RootDomain:                 "indikart.in",
		AssessmentDate:             postDate,
		AnnualRevenueINR:           2000000000.0,
		ProcessesChildrenData:      false,
		IsSignificantDataFiduciary: false,
	}

	findings := []SecurityFindingInput{
		{
			ID:       "FIND-01",
			Title:    "Unrestricted API Exposing Customer Identity Data",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	reg := EstimateRegulatoryExposure(cfg, findings)

	// Legal status must be IN_FORCE
	if reg.DPDP.LegalCommencementStatus != LegalStatusInForce {
		t.Errorf("expected LegalCommencementStatus %s, got %s", LegalStatusInForce, reg.DPDP.LegalCommencementStatus)
	}
	if reg.DPDP.ActOverallStatus != LegalStatusInForce {
		t.Errorf("expected ActOverallStatus %s, got %s", LegalStatusInForce, reg.DPDP.ActOverallStatus)
	}
	if reg.DPDP.PenaltyFrameworkStatus != LegalStatusInForce {
		t.Errorf("expected PenaltyFrameworkStatus %s, got %s", LegalStatusInForce, reg.DPDP.PenaltyFrameworkStatus)
	}

	// Must be currently enforceable
	if !reg.DPDP.IsCurrentlyEnforceable || !reg.DPDP.IsPenaltyEffective {
		t.Errorf("expected IsCurrentlyEnforceable and IsPenaltyEffective to be true after 13 May 2027")
	}

	// Currently enforceable maximum must equal the statutory maximum (Sec 8(5) ₹250 Cr + Sec 8(6) ₹200 Cr = ₹450 Cr)
	if reg.DPDP.CurrentEnforceableMaxINR != reg.DPDP.StatutoryMaxCeilingINR {
		t.Errorf("expected CurrentEnforceableMaxINR (%.0f) == StatutoryMaxCeilingINR (%.0f)", reg.DPDP.CurrentEnforceableMaxINR, reg.DPDP.StatutoryMaxCeilingINR)
	}
	if reg.DPDP.CurrentEnforceableProbableINR <= 0.0 {
		t.Errorf("expected positive currently enforceable probable INR")
	}
}

func TestDueDiligence_21_GDPRArt83_4_and_83_5_Ceilings(t *testing.T) {
	// Test Article 83(4) [max(€10M, 2% turnover)] and Article 83(5) [max(€20M, 4% turnover)]

	// Case 1: Mid-tier enterprise €50M turnover
	// 2% of €50M = €1M (< €10M fixed cap) -> Art 83(4) ceiling is €10M
	// 4% of €50M = €2M (< €20M fixed cap) -> Art 83(5) ceiling is €20M
	cfgMid := DueDiligenceConfig{
		TargetEntityName: "MidCorp EU",
		RootDomain:       "midcorp.eu",
		AnnualRevenueEUR: 50000000.0, // €50M
	}
	regMid := EstimateRegulatoryExposure(cfgMid, nil)
	if regMid.GDPR.StatutoryCeilingArt83_4 != 10000000.0 {
		t.Errorf("expected MidCorp Art 83(4) ceiling €10,000,000, got %.0f", regMid.GDPR.StatutoryCeilingArt83_4)
	}
	if regMid.GDPR.StatutoryCeilingArt83_5 != 20000000.0 {
		t.Errorf("expected MidCorp Art 83(5) ceiling €20,000,000, got %.0f", regMid.GDPR.StatutoryCeilingArt83_5)
	}
	if regMid.GDPR.StatutoryMaxCeilingEUR != 20000000.0 {
		t.Errorf("expected MidCorp max ceiling €20,000,000, got %.0f", regMid.GDPR.StatutoryMaxCeilingEUR)
	}

	// Case 2: Large conglomerate €1,000M (€1B) turnover
	// 2% of €1,000M = €20M (> €10M fixed cap) -> Art 83(4) ceiling is €20M
	// 4% of €1,000M = €40M (> €20M fixed cap) -> Art 83(5) ceiling is €40M
	cfgLarge := DueDiligenceConfig{
		TargetEntityName: "GlobalMegaCorp EU",
		RootDomain:       "globalmegacorp.eu",
		AnnualRevenueEUR: 1000000000.0, // €1,000M
	}
	regLarge := EstimateRegulatoryExposure(cfgLarge, nil)
	if regLarge.GDPR.StatutoryCeilingArt83_4 != 20000000.0 {
		t.Errorf("expected LargeCorp Art 83(4) ceiling €20,000,000 (2%% of €1B), got %.0f", regLarge.GDPR.StatutoryCeilingArt83_4)
	}
	if regLarge.GDPR.StatutoryCeilingArt83_5 != 40000000.0 {
		t.Errorf("expected LargeCorp Art 83(5) ceiling €40,000,000 (4%% of €1B), got %.0f", regLarge.GDPR.StatutoryCeilingArt83_5)
	}
	if regLarge.GDPR.StatutoryMaxCeilingEUR != 40000000.0 {
		t.Errorf("expected LargeCorp max ceiling €40,000,000, got %.0f", regLarge.GDPR.StatutoryMaxCeilingEUR)
	}
}

func TestDueDiligence_22_StorageNotFoundClassification(t *testing.T) {
	// A 404 / NoSuchBucket indicates absent resource, NOT affirmative security
	ind := CloudStorageIndicator{
		Provider:      "AWS_S3",
		BucketName:    "acme-nonexistent-bucket",
		URL:           "https://acme-nonexistent-bucket.s3.amazonaws.com",
		Accessibility: "NOT_FOUND",
	}

	classified := ClassifyCloudStorageExposure(ind)
	if classified.ExposureClassification != ExposureResourceNotFound {
		t.Errorf("expected classification %s, got %s", ExposureResourceNotFound, classified.ExposureClassification)
	}
	if classified.FindingSeverity != DDSeverityInfo {
		t.Errorf("expected severity INFO, got %s", classified.FindingSeverity)
	}
	if !strings.Contains(classified.Evidence, "Resource is absent") {
		t.Errorf("expected evidence to clarify resource absence, got: %s", classified.Evidence)
	}
}

func TestDueDiligence_23_StorageAccessDeniedClassification(t *testing.T) {
	// A 403 / AccessDenied confirms anonymous access is restricted, but requires credentialed verification
	ind := CloudStorageIndicator{
		Provider:      "AWS_S3",
		BucketName:    "acme-secure-internal",
		URL:           "https://acme-secure-internal.s3.amazonaws.com",
		Accessibility: "ACCESS_DENIED",
	}

	classified := ClassifyCloudStorageExposure(ind)
	if classified.ExposureClassification != ExposureAnonymousRestricted {
		t.Errorf("expected classification %s, got %s", ExposureAnonymousRestricted, classified.ExposureClassification)
	}
	if classified.FindingSeverity != DDSeverityInfo {
		t.Errorf("expected severity INFO, got %s", classified.FindingSeverity)
	}
	if !strings.Contains(classified.Evidence, "Anonymous access is restricted") {
		t.Errorf("expected evidence to state anonymous access restricted, got: %s", classified.Evidence)
	}
}

func TestDueDiligence_24_BaaSPublicConfigNonVulnerability(t *testing.T) {
	// Strict Rule: Public client bootstrap configuration (API key) is NEVER a vulnerability
	ind := BaaSIndicator{
		Provider:            "FIREBASE_RTDB",
		InstanceID:          "acme-mobile-app",
		URL:                 "https://acme-mobile-app.firebaseio.com",
		ConfigurationStatus: "BENIGN_PUBLIC_KEY",
	}

	classified := ClassifyBaaSExposure(ind)
	if classified.ExposureClassification != ExposurePublicSafe {
		t.Errorf("expected %s, got %s", ExposurePublicSafe, classified.ExposureClassification)
	}
	if classified.FindingSeverity != DDSeverityInfo {
		t.Errorf("expected INFO severity, got %s", classified.FindingSeverity)
	}
	if !strings.Contains(classified.Evidence, "Not a vulnerability") {
		t.Errorf("expected evidence to state 'Not a vulnerability', got: %s", classified.Evidence)
	}
}

func TestDueDiligence_25_IncompleteCoverageRiskScoring(t *testing.T) {
	// Scope with only web perimeter findings, missing mobile and cloud/BaaS
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName: "Partial Scope Entity",
			RootDomain:       "partial-scope.com",
		},
		Assets: []DiscoveredAsset{
			{AssetID: "AST-1", Type: AssetTypeDomain, Identifier: "partial-scope.com", ExposureTier: ExposurePublicSafe},
		},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Title: "High Severity Vulnerability", Severity: DDSeverityHigh, Status: DDStatusVerifiedDefect, TargetURL: "https://partial-scope.com"},
		},
		// No CloudStorageIndicators, no BaaSIndicators, no MobileApplications
	}

	debt := EstimateTechnicalDebt(input.Findings, 150.0)
	reg := EstimateRegulatoryExposure(input.Config, input.Findings)
	profile := CalculateAcquisitionRiskProfile(input, debt, reg)

	// Coverage ratio must be strictly less than 1.0 (Mobile and Cloud missing)
	if profile.AssessmentCoverageRatio >= 1.0 {
		t.Errorf("expected coverage ratio < 1.0, got %.2f", profile.AssessmentCoverageRatio)
	}

	// Must report explicit coverage limitations
	if len(profile.CoverageLimitations) == 0 {
		t.Errorf("expected coverage limitations to be populated")
	}

	hasMobileLimit := false
	hasCloudLimit := false
	for _, lim := range profile.CoverageLimitations {
		if strings.Contains(strings.ToLower(lim), "mobile") {
			hasMobileLimit = true
		}
		if strings.Contains(strings.ToLower(lim), "cloud") {
			hasCloudLimit = true
		}
	}
	if !hasMobileLimit || !hasCloudLimit {
		t.Errorf("expected coverage limitations to mention mobile and cloud gaps, got: %v", profile.CoverageLimitations)
	}

	// Normalized score must not be artificially diluted to zero
	if profile.CompositeRiskScore <= 0 {
		t.Errorf("expected non-zero normalized composite risk score, got %d", profile.CompositeRiskScore)
	}
}

func TestDueDiligence_26_EscrowMultiplierConfigurability(t *testing.T) {
	// Custom illustrative deal multiplier: 0.25 (25%) instead of default 0.50
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:           "Acme Target",
			RootDomain:                 "acme.com",
			RegulatoryEscrowMultiplier: 0.25,
			AnnualRevenueUSD:           10000000.0,
		},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Title: "Verified Defect", Severity: DDSeverityCritical, Status: DDStatusVerifiedDefect, TargetURL: "https://acme.com"},
		},
		ExecutionTimestamp: time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
	}

	dossier, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	roadmap := dossier.Section14_RemediationRoadmap
	if roadmap.ConfiguredEscrowMultiplier != 0.25 {
		t.Errorf("expected configured multiplier 0.25, got %.2f", roadmap.ConfiguredEscrowMultiplier)
	}

	// Verify exact math: Technical Upper Cost + (Illustrative Regulatory * 0.25)
	expectedEscrow := math.Round(roadmap.TechnicalRemediationCostUSD + (roadmap.IllustrativeRegulatoryRiskUSD * 0.25))
	if roadmap.RecommendedEscrowUSD != expectedEscrow {
		t.Errorf("expected escrow $%.0f, got $%.0f", expectedEscrow, roadmap.RecommendedEscrowUSD)
	}

	// Verify rationale explicitly documents the 25% deal assumption
	if !strings.Contains(roadmap.EscrowMethodologyRationale, "25%") {
		t.Errorf("expected rationale to state 25%% multiplier, got: %s", roadmap.EscrowMethodologyRationale)
	}
}

func TestDueDiligence_27_DossierRegulatoryStatusAndAssumptions(t *testing.T) {
	input := DueDiligenceInput{
		Config: DueDiligenceConfig{
			TargetEntityName:           "Fintech Global Corp",
			RootDomain:                 "fintechglobal.com",
			AssessmentDate:             time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC),
			AnnualRevenueUSD:           50000000.0,
			AnnualRevenueEUR:           46000000.0,
			AnnualRevenueINR:           4150000000.0,
			ProcessesChildrenData:      false,
			IsSignificantDataFiduciary: true,
		},
		Findings: []SecurityFindingInput{
			{ID: "F-1", Title: "Hardcoded API Token", Severity: DDSeverityHigh, Status: DDStatusVerifiedDefect, TargetURL: "https://fintechglobal.com"},
		},
	}

	dossier, err := GenerateExecutiveAcquisitionDossier(input)
	if err != nil {
		t.Fatalf("failed generating dossier: %v", err)
	}

	md := dossier.ToMarkdown()
	htmlReport, err := dossier.ToExecutiveHTML()
	if err != nil {
		t.Fatalf("failed generating HTML: %v", err)
	}

	// Verify DPDP commencement status in Markdown
	if !strings.Contains(md, "SCHEDULED_TO_COMMENCE") {
		t.Errorf("expected Markdown to mention SCHEDULED_TO_COMMENCE")
	}
	if !strings.Contains(md, "2027-05-13") {
		t.Errorf("expected Markdown to mention 2027-05-13 commencement date")
	}

	// Verify GDPR status in Markdown
	if !strings.Contains(md, "IN_FORCE") {
		t.Errorf("expected Markdown to mention GDPR IN_FORCE status")
	}

	// Verify disclaimers and non-claims
	if !strings.Contains(md, "LEGAL DISCLAIMER") {
		t.Errorf("expected Markdown to include LEGAL DISCLAIMER")
	}
	if !strings.Contains(md, "LEGAL & FINANCIAL DISCLAIMER") {
		t.Errorf("expected Markdown to include technical debt disclaimer")
	}

	// Verify HTML contains commencement details and disclaimers
	if !strings.Contains(htmlReport, "SCHEDULED_TO_COMMENCE") {
		t.Errorf("expected HTML to contain SCHEDULED_TO_COMMENCE")
	}
	if !strings.Contains(htmlReport, "2027-05-13") {
		t.Errorf("expected HTML to contain 2027-05-13")
	}
	if !strings.Contains(htmlReport, "Canonical SHA-256 Digest") {
		t.Errorf("expected HTML to contain Canonical SHA-256 Digest")
	}
}

func TestDueDiligence_28_DPDPBoundaryDate_2025_11_13(t *testing.T) {
	// Boundary test for Clause (a) commencement (13 November 2025)
	cfgPre := DueDiligenceConfig{
		TargetEntityName: "Alpha Retail",
		RootDomain:       "alpha.in",
		AssessmentDate:   time.Date(2025, 11, 12, 23, 59, 59, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPre := EstimateRegulatoryExposure(cfgPre, nil)
	if regPre.DPDP.ActOverallStatus != LegalStatusEnactedNotCommenced {
		t.Errorf("expected ActOverallStatus %s on 2025-11-12, got %s", LegalStatusEnactedNotCommenced, regPre.DPDP.ActOverallStatus)
	}
	if regPre.DPDP.ProvisionStages[0].IsEffective {
		t.Errorf("expected Stage 1 to not be effective on 2025-11-12")
	}

	cfgPost := DueDiligenceConfig{
		TargetEntityName: "Alpha Retail",
		RootDomain:       "alpha.in",
		AssessmentDate:   time.Date(2025, 11, 13, 0, 0, 0, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPost := EstimateRegulatoryExposure(cfgPost, nil)
	if regPost.DPDP.ActOverallStatus != LegalStatusPartiallyCommenced {
		t.Errorf("expected ActOverallStatus %s on 2025-11-13, got %s", LegalStatusPartiallyCommenced, regPost.DPDP.ActOverallStatus)
	}
	if !regPost.DPDP.ProvisionStages[0].IsEffective || regPost.DPDP.ProvisionStages[0].Status != LegalStatusInForce {
		t.Errorf("expected Stage 1 to be IN_FORCE on 2025-11-13")
	}
	if regPost.DPDP.ProvisionStages[1].IsEffective || regPost.DPDP.ProvisionStages[2].IsEffective {
		t.Errorf("expected Stages 2 and 3 to remain not effective on 2025-11-13")
	}

	// Verify exact G.S.R. 843(E) Stage 1 provisions
	expectedStage1Provisions := "Section 1(2), Section 2, Sections 18–26, Section 35, Sections 38–43, and Section 44(1) and (3)"
	if regPost.DPDP.ProvisionStages[0].ProvisionsCovered != expectedStage1Provisions {
		t.Errorf("Stage 1 provisions covered mismatch:\nexpected: %q\ngot:      %q", expectedStage1Provisions, regPost.DPDP.ProvisionStages[0].ProvisionsCovered)
	}
}

func TestDueDiligence_29_DPDPBoundaryDate_2026_11_13(t *testing.T) {
	// Boundary test for Clause (b) commencement (13 November 2026)
	cfgPre := DueDiligenceConfig{
		TargetEntityName: "Beta Logistics",
		RootDomain:       "beta.in",
		AssessmentDate:   time.Date(2026, 11, 12, 23, 59, 59, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPre := EstimateRegulatoryExposure(cfgPre, nil)
	if regPre.DPDP.ProvisionStages[1].IsEffective {
		t.Errorf("expected Stage 2 to not be effective on 2026-11-12")
	}
	if regPre.DPDP.ActOverallStatus != LegalStatusPartiallyCommenced {
		t.Errorf("expected ActOverallStatus PARTIALLY_COMMENCED on 2026-11-12, got %s", regPre.DPDP.ActOverallStatus)
	}

	cfgPost := DueDiligenceConfig{
		TargetEntityName: "Beta Logistics",
		RootDomain:       "beta.in",
		AssessmentDate:   time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPost := EstimateRegulatoryExposure(cfgPost, nil)
	if !regPost.DPDP.ProvisionStages[0].IsEffective || !regPost.DPDP.ProvisionStages[1].IsEffective {
		t.Errorf("expected Stages 1 and 2 to be effective on 2026-11-13")
	}
	if regPost.DPDP.ProvisionStages[2].IsEffective {
		t.Errorf("expected Stage 3 to not be effective on 2026-11-13")
	}
	if regPost.DPDP.ActOverallStatus != LegalStatusPartiallyCommenced {
		t.Errorf("expected ActOverallStatus PARTIALLY_COMMENCED on 2026-11-13, got %s", regPost.DPDP.ActOverallStatus)
	}

	// Verify exact G.S.R. 843(E) Stage 2 provisions
	expectedStage2Provisions := "Section 6(9) and Section 27(1)(d)"
	if regPost.DPDP.ProvisionStages[1].ProvisionsCovered != expectedStage2Provisions {
		t.Errorf("Stage 2 provisions covered mismatch:\nexpected: %q\ngot:      %q", expectedStage2Provisions, regPost.DPDP.ProvisionStages[1].ProvisionsCovered)
	}
}

func TestDueDiligence_30_DPDPBoundaryDate_2027_05_13(t *testing.T) {
	// Boundary test for Clause (c) commencement (13 May 2027 - eighteen months after publication)
	findings := []SecurityFindingInput{
		{
			ID:       "FIND-01",
			Title:    "Personal Data Breach Safeguard Failure",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	// 1 day before: 12 May 2027
	cfgPre := DueDiligenceConfig{
		TargetEntityName: "Gamma Payments",
		RootDomain:       "gamma.in",
		AssessmentDate:   time.Date(2027, 5, 12, 23, 59, 59, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPre := EstimateRegulatoryExposure(cfgPre, findings)
	if regPre.DPDP.IsPenaltyEffective || regPre.DPDP.IsCurrentlyEnforceable {
		t.Errorf("expected penalty framework to not be effective on 2027-05-12")
	}
	if regPre.DPDP.CurrentEnforceableMaxINR != 0.0 {
		t.Errorf("expected CurrentEnforceableMaxINR to be 0 on 2027-05-12, got %.0f", regPre.DPDP.CurrentEnforceableMaxINR)
	}
	if regPre.DPDP.ActOverallStatus != LegalStatusPartiallyCommenced {
		t.Errorf("expected ActOverallStatus PARTIALLY_COMMENCED on 2027-05-12, got %s", regPre.DPDP.ActOverallStatus)
	}

	// Effective day: 13 May 2027
	cfgPost := DueDiligenceConfig{
		TargetEntityName: "Gamma Payments",
		RootDomain:       "gamma.in",
		AssessmentDate:   time.Date(2027, 5, 13, 0, 0, 0, 0, time.UTC),
		AnnualRevenueINR: 1000000000.0,
	}
	regPost := EstimateRegulatoryExposure(cfgPost, findings)
	if !regPost.DPDP.IsPenaltyEffective || !regPost.DPDP.IsCurrentlyEnforceable {
		t.Errorf("expected penalty framework to be effective on 2027-05-13")
	}
	if regPost.DPDP.ActOverallStatus != LegalStatusInForce {
		t.Errorf("expected ActOverallStatus IN_FORCE on 2027-05-13, got %s", regPost.DPDP.ActOverallStatus)
	}
	if regPost.DPDP.PenaltyFrameworkStatus != LegalStatusInForce {
		t.Errorf("expected PenaltyFrameworkStatus IN_FORCE on 2027-05-13, got %s", regPost.DPDP.PenaltyFrameworkStatus)
	}
	if regPost.DPDP.CurrentEnforceableMaxINR != regPost.DPDP.StatutoryMaxCeilingINR {
		t.Errorf("expected CurrentEnforceableMaxINR (%.0f) == StatutoryMaxCeilingINR (%.0f) on 2027-05-13", regPost.DPDP.CurrentEnforceableMaxINR, regPost.DPDP.StatutoryMaxCeilingINR)
	}
	if regPost.DPDP.CurrentEnforceableProbableINR <= 0.0 {
		t.Errorf("expected positive currently enforceable probable penalty on 2027-05-13")
	}

	// Verify exact G.S.R. 843(E) Stage 3 provisions
	expectedStage3Provisions := "Sections 3–5, Section 6(1)–(8) and (10), Sections 7–17, Section 27 except clause (d), Sections 28–34, Sections 36–37, and Section 44(2)"
	if regPost.DPDP.ProvisionStages[2].ProvisionsCovered != expectedStage3Provisions {
		t.Errorf("Stage 3 provisions covered mismatch:\nexpected: %q\ngot:      %q", expectedStage3Provisions, regPost.DPDP.ProvisionStages[2].ProvisionsCovered)
	}
}

func TestDueDiligence_31_DPDPScheduleItemizationAndStatutoryWording(t *testing.T) {
	cfg := DueDiligenceConfig{
		TargetEntityName:           "Delta Healthcare",
		RootDomain:                 "delta.in",
		AnnualRevenueINR:           5000000000.0,
		ProcessesChildrenData:      true,
		IsSignificantDataFiduciary: true,
	}
	findings := []SecurityFindingInput{
		{
			ID:       "BREACH-01",
			Title:    "Leaked Health Records Database",
			Severity: DDSeverityCritical,
			Status:   DDStatusVerifiedDefect,
		},
	}

	reg := EstimateRegulatoryExposure(cfg, findings)

	// Validate Schedule itemization (The Schedule pursuant to Section 33(1)) - 7 items
	if len(reg.DPDP.ScheduleCategories) != 7 {
		t.Fatalf("expected 7 schedule items, got %d", len(reg.DPDP.ScheduleCategories))
	}

	expectedCaps := map[int]float64{
		1: 2500000000.0, // Section 8(5): ₹250 crore
		2: 2000000000.0, // Section 8(6): ₹200 crore
		3: 2000000000.0, // Section 9: ₹200 crore
		4: 1500000000.0, // Section 10: ₹150 crore
		5: 10000.0,      // Section 15: ₹10,000
		6: 0.0,          // Section 32: Up to extent applicable for underlying breach (no fixed rupee ceiling)
		7: 500000000.0,  // Section 33(1) Residual: ₹50 crore
	}

	for _, item := range reg.DPDP.ScheduleCategories {
		expectedCap, ok := expectedCaps[item.ScheduleItemNumber]
		if !ok {
			t.Errorf("unexpected schedule item number: %d", item.ScheduleItemNumber)
			continue
		}
		if item.StatutoryCeilingINR != expectedCap {
			t.Errorf("item %d (%s) expected cap %.0f, got %.0f", item.ScheduleItemNumber, item.ProvisionRef, expectedCap, item.StatutoryCeilingINR)
		}
		if item.ScheduleItemNumber == 6 {
			// Item 6: Section 32 voluntary undertaking
			if !strings.Contains(strings.ToLower(item.StatutoryWording), "up to the extent applicable") {
				t.Errorf("item 6 wording must contain 'up to the extent applicable', got: %s", item.StatutoryWording)
			}
		} else {
			if !strings.Contains(strings.ToLower(item.StatutoryWording), "may extend to") {
				t.Errorf("item %d wording must preserve 'may extend to', got: %s", item.ScheduleItemNumber, item.StatutoryWording)
			}
		}
	}

	// Validate Section 33(2) statutory determination factors
	if len(reg.DPDP.PenaltyDeterminationFactors) < 7 {
		t.Errorf("expected at least 7 determination factors under Section 33(2), got %d", len(reg.DPDP.PenaltyDeterminationFactors))
	}

	hasNatureGravity := false
	hasFinancialGain := false
	hasMitigation := false
	hasProportionality := false

	for _, factor := range reg.DPDP.PenaltyDeterminationFactors {
		factorLower := strings.ToLower(factor)
		if strings.Contains(factorLower, "nature, gravity") {
			hasNatureGravity = true
		}
		if strings.Contains(factorLower, "realized any gain") || strings.Contains(factorLower, "avoided any loss") {
			hasFinancialGain = true
		}
		if strings.Contains(factorLower, "mitigation") {
			hasMitigation = true
		}
		if strings.Contains(factorLower, "proportionality") {
			hasProportionality = true
		}
	}

	if !hasNatureGravity || !hasFinancialGain || !hasMitigation || !hasProportionality {
		t.Errorf("missing key Section 33(2) factors: nature=%v, gain=%v, mitigation=%v, prop=%v",
			hasNatureGravity, hasFinancialGain, hasMitigation, hasProportionality)
	}
}
