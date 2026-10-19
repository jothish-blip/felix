package test

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
)

// =============================================================================
// PHASE 6.1: RISK SCORING — REGRESSION SUITE
// Formula Validation, Score Caps, Explainability & Architecture Invariants
// =============================================================================

// 1. Finding score formula validation with independent calculations across
// all severity, confidence, verification, and category modifier combinations.
func TestRiskScoring_FindingFormulaValidation(t *testing.T) {
	severities := []struct {
		name string
		base int
	}{
		{"CRITICAL", 40},
		{"HIGH", 25},
		{"MEDIUM", 12},
		{"LOW", 5},
		{"INFORMATIONAL", 1},
	}

	confidences := []struct {
		name   string
		weight float64
	}{
		{"HIGH", 1.0},
		{"MEDIUM", 0.75},
		{"LOW", 0.5},
	}

	verifications := []struct {
		status report.VerificationStatus
		weight float64
	}{
		{report.VerificationVerified, 1.0},
		{report.VerificationDetected, 0.8},
		{report.VerificationNotVerified, 0.7},
		{report.VerificationObserved, 0.3},
		{report.VerificationNotExposed, 0.0},
	}

	categories := []struct {
		category string
		modifier int
	}{
		{"general-web-vuln", 0},
		{"hardcoded-service-secret", 5},
		{"cloud-provider-token", 5},
		{"iam-credential-leak", 5},
	}

	for _, sev := range severities {
		for _, conf := range confidences {
			for _, ver := range verifications {
				for _, cat := range categories {
					f := report.Finding{
						ID:         "test-formula-fnd",
						Severity:   sev.name,
						Confidence: conf.name,
						Category:   cat.category,
						Verification: report.VerificationRecord{
							Status: ver.status,
						},
					}

					expl := report.ExplainFindingScore(f)
					score := report.CalculateFindingScore(f)

					if expl.Score != score {
						t.Fatalf("Score mismatch between ExplainFindingScore (%d) and CalculateFindingScore (%d) for %s/%s/%s/%s",
							expl.Score, score, sev.name, conf.name, ver.status, cat.category)
					}

					// Defended / not exposed should score 0
					if ver.status == report.VerificationNotExposed {
						if score != 0 {
							t.Fatalf("Expected score 0 for NOT_EXPOSED, got %d", score)
						}
						continue
					}

					// Independent calculation
					basePlusMod := sev.base
					if sev.name != "INFORMATIONAL" {
						basePlusMod += cat.modifier
					}
					if basePlusMod > 40 {
						basePlusMod = 40
					}
					expectedFloat := float64(basePlusMod) * conf.weight * ver.weight
					expectedScore := int(math.Round(expectedFloat))
					if expectedScore < 0 {
						expectedScore = 0
					}
					if expectedScore > 40 {
						expectedScore = 40
					}

					if score != expectedScore {
						t.Errorf("Formula validation failed for %s/%s/%s/%s: got %d, expected %d (formula: %s)",
							sev.name, conf.name, ver.status, cat.category, score, expectedScore, expl.Formula)
					}

					// Enforce strict upper bound
					if score < 0 || score > 40 {
						t.Fatalf("Finding score out of bounds [0, 40]: got %d", score)
					}
				}
			}
		}
	}
}

// 2. Extreme and invalid inputs: negative scores, scores > 40, scores > 100, unknown severities, empty statuses.
func TestRiskScoring_ExtremeAndInvalidInputs(t *testing.T) {
	testCases := []struct {
		name        string
		finding     report.Finding
		maxScore    int
		minScore    int
		description string
	}{
		{
			name: "Unknown severity with high confidence",
			finding: report.Finding{
				Severity:   "EXTREME_CRITICAL",
				Confidence: "HIGH",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
			},
			minScore: 0,
			maxScore: 40,
		},
		{
			name: "Negative score passed into normalize",
			finding: report.Finding{
				Severity: "MEDIUM",
				Score:    -50,
			},
			minScore: 0,
			maxScore: 40,
		},
		{
			name: "Out of bounds score (150) passed into finding",
			finding: report.Finding{
				Severity: "HIGH",
				Score:    150,
			},
			minScore: 0,
			maxScore: 40,
		},
		{
			name: "Completely empty finding",
			finding: report.Finding{},
			minScore: 0,
			maxScore: 0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			normalized := report.NormalizeFinding(tc.finding)
			if normalized.Score < tc.minScore || normalized.Score > tc.maxScore {
				t.Fatalf("Normalized score %d out of bounds [%d, %d]", normalized.Score, tc.minScore, tc.maxScore)
			}
			expl := report.ExplainFindingScore(normalized)
			if expl.Score < tc.minScore || expl.Score > tc.maxScore {
				t.Fatalf("Explained score %d out of bounds [%d, %d]", expl.Score, tc.minScore, tc.maxScore)
			}
		})
	}
}

// 3. Exact severity bands and thresholds: 0-19, 20-39, 40-59, 60-79, 80-100.
func TestRiskScoring_SeverityBandsAndBoundaries(t *testing.T) {
	thresholds := []struct {
		score         int
		expectedLevel string
	}{
		{0, "INFORMATIONAL"},
		{1, "INFORMATIONAL"},
		{19, "INFORMATIONAL"},
		{20, "LOW"},
		{39, "LOW"},
		{40, "MEDIUM"},
		{59, "MEDIUM"},
		{60, "HIGH"},
		{79, "HIGH"},
		{80, "CRITICAL"},
		{99, "CRITICAL"},
		{100, "CRITICAL"},
	}

	for _, th := range thresholds {
		level := report.RiskLevelBand(th.score)
		if level != th.expectedLevel {
			t.Errorf("RiskLevelBand(%d) = %q; expected %q", th.score, level, th.expectedLevel)
		}
	}

	// Empty findings produces INFORMATIONAL
	score, level := report.CalculateReportRisk(nil, nil)
	if score != 0 || level != "INFORMATIONAL" {
		t.Fatalf("Empty findings risk = (%d, %s); expected (0, INFORMATIONAL)", score, level)
	}
}

// 4. Score caps: hardening subtotal cap at 20.0, story bonus cap at 15.0, total score cap at 100.
func TestRiskScoring_ScoreCapsEnforcement(t *testing.T) {
	// A. Hardening subtotal cap at 20.0
	// Create 10 hardening findings each with score 20
	var hardeningFindings []report.Finding
	for i := 0; i < 10; i++ {
		hardeningFindings = append(hardeningFindings, report.Finding{
			ID:          "fnd-hardening-" + string(rune('a'+i)),
			Category:    "missing-security-header",
			Severity:    "HIGH",
			Confidence:  "HIGH",
			Score:       20,
			Fingerprint: "fp-hard-" + string(rune('a'+i)),
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
		})
	}

	_, hBreakdown, _ := report.CalculateRiskBreakdown(hardeningFindings, nil)
	if hBreakdown.HardeningSubtotal > 20.0 {
		t.Fatalf("Hardening subtotal %f exceeded cap of 20.0", hBreakdown.HardeningSubtotal)
	}
	if hBreakdown.RawHardeningSubtotal <= 20.0 {
		t.Fatalf("Expected raw hardening subtotal to exceed 20.0, got %f", hBreakdown.RawHardeningSubtotal)
	}
	if !hBreakdown.IsCapped {
		t.Fatalf("Expected IsCapped to be true when hardening subtotal exceeds 20.0")
	}
	if !strings.Contains(strings.ToLower(hBreakdown.CapRationale), "hardening capped at 20.0") {
		t.Fatalf("CapRationale missing hardening cap explanation: %s", hBreakdown.CapRationale)
	}

	// B. Story bonus cap at 15.0
	// 5 distinct stories each contributing 5.0 points = 25.0 raw bonus
	var stories []report.SecurityStory
	for i := 0; i < 5; i++ {
		stories = append(stories, report.SecurityStory{
			ID:               "story-bonus-" + string(rune('1'+i)),
			Title:            "Multi-Step Escalation Story " + string(rune('1'+i)),
			RiskContribution: 5,
		})
	}

	baseFinding := report.Finding{
		ID:          "fnd-base-core",
		Category:    "bola",
		Severity:    "HIGH",
		Confidence:  "HIGH",
		Score:       20,
		Fingerprint: "fp-core-01",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	_, sBreakdown, _ := report.CalculateRiskBreakdown([]report.Finding{baseFinding}, stories)
	if sBreakdown.StoryBonus > 15.0 {
		t.Fatalf("Story bonus %f exceeded cap of 15.0", sBreakdown.StoryBonus)
	}
	if sBreakdown.RawStoryBonus <= 15.0 {
		t.Fatalf("Expected raw story bonus to exceed 15.0, got %f", sBreakdown.RawStoryBonus)
	}
	if !strings.Contains(strings.ToLower(sBreakdown.CapRationale), "story bonus capped at 15.0") {
		t.Fatalf("CapRationale missing story bonus cap explanation: %s", sBreakdown.CapRationale)
	}

	// C. Total score cap at 100
	// Create multiple critical findings + stories + hardening to exceed 100 points
	var massiveFindings []report.Finding
	for i := 0; i < 15; i++ {
		massiveFindings = append(massiveFindings, report.Finding{
			ID:          "fnd-crit-" + string(rune('a'+i)),
			Category:    "command-injection",
			Severity:    "CRITICAL",
			Confidence:  "HIGH",
			Score:       30,
			Fingerprint: "fp-crit-" + string(rune('a'+i)),
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
		})
	}
	for i := 0; i < 10; i++ {
		massiveFindings = append(massiveFindings, hardeningFindings[i])
	}

	_, mBreakdown, mLevel := report.CalculateRiskBreakdown(massiveFindings, stories)
	if mBreakdown.TotalScore > 100 {
		t.Fatalf("Total score %d exceeded 100", mBreakdown.TotalScore)
	}
	if mBreakdown.TotalScore != 100 {
		t.Fatalf("Expected massive findings to cap at exactly 100, got %d", mBreakdown.TotalScore)
	}
	if mBreakdown.RawTotalScore <= 100 {
		t.Fatalf("Expected raw total score > 100, got %d", mBreakdown.RawTotalScore)
	}
	if mLevel != "CRITICAL" {
		t.Fatalf("Expected level CRITICAL for capped score 100, got %s", mLevel)
	}
	if !strings.Contains(strings.ToLower(mBreakdown.CapRationale), "total score capped at 100") {
		t.Fatalf("CapRationale missing total score cap explanation: %s", mBreakdown.CapRationale)
	}
}

// 5. Severity anchor rule: verified findings anchor categorical level even with lower accumulated score;
// unverified candidate findings do not anchor.
func TestRiskScoring_SeverityAnchorRule(t *testing.T) {
	// A. Verified CRITICAL finding with score 30
	// 30 points falls into numerical band LOW (20-39), but anchor must escalate to CRITICAL
	verifiedCrit := report.Finding{
		ID:          "fnd-anchor-crit",
		Category:    "sql-injection",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Score:       30,
		Fingerprint: "fp-anchor-crit",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	_, bCrit, levelCrit := report.CalculateRiskBreakdown([]report.Finding{verifiedCrit}, nil)
	if bCrit.TotalScore != 30 {
		t.Fatalf("Expected total score 30, got %d", bCrit.TotalScore)
	}
	if bCrit.ScoreBandLevel != "LOW" {
		t.Fatalf("Expected ScoreBandLevel LOW, got %s", bCrit.ScoreBandLevel)
	}
	if bCrit.AnchorLevel != "CRITICAL" {
		t.Fatalf("Expected AnchorLevel CRITICAL, got %s", bCrit.AnchorLevel)
	}
	if levelCrit != "CRITICAL" {
		t.Fatalf("Expected final risk level to anchor to CRITICAL, got %s", levelCrit)
	}
	if bCrit.AnchorFindingID != verifiedCrit.ID {
		t.Fatalf("Expected AnchorFindingID %s, got %s", verifiedCrit.ID, bCrit.AnchorFindingID)
	}
	if !strings.Contains(bCrit.AnchorRationale, "anchored by verified CRITICAL") {
		t.Fatalf("AnchorRationale does not explain anchor: %s", bCrit.AnchorRationale)
	}

	// B. Unverified / Candidate CRITICAL finding with score 24 (30 * 0.8)
	// Must NOT anchor! Should remain at numerical score band (LOW for score 24)
	candidateCrit := report.Finding{
		ID:          "fnd-cand-crit",
		Category:    "sql-injection",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Score:       24,
		Fingerprint: "fp-cand-crit",
		Verification: report.VerificationRecord{
			Status: report.VerificationDetected, // Candidate / detected only
		},
	}

	_, bCand, levelCand := report.CalculateRiskBreakdown([]report.Finding{candidateCrit}, nil)
	if bCand.AnchorLevel != "" {
		t.Fatalf("Expected AnchorLevel to be empty for candidate finding, got %s", bCand.AnchorLevel)
	}
	if levelCand != "LOW" {
		t.Fatalf("Expected candidate finding not to anchor (should be LOW), got %s", levelCand)
	}

	// C. Defended CRITICAL finding (NOT_EXPOSED) must NOT anchor
	defendedCrit := report.Finding{
		ID:          "fnd-def-crit",
		Category:    "sql-injection",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Score:       0,
		Fingerprint: "fp-def-crit",
		Verification: report.VerificationRecord{
			Status: report.VerificationNotExposed,
		},
	}

	_, bDef, levelDef := report.CalculateRiskBreakdown([]report.Finding{defendedCrit}, nil)
	if bDef.TotalScore != 0 {
		t.Fatalf("Expected score 0 for defended finding, got %d", bDef.TotalScore)
	}
	if bDef.AnchorLevel != "" {
		t.Fatalf("Defended finding must not anchor, got %s", bDef.AnchorLevel)
	}
	if levelDef != "INFORMATIONAL" {
		t.Fatalf("Expected INFORMATIONAL risk level for score 0, got %s", levelDef)
	}
}

// 6. Defended / boundary invariant: 0 score for NOT_EXPOSED, AUTH_REQUIRED, FORBIDDEN, NOT_FOUND.
func TestRiskScoring_DefendedBoundaryInvariant(t *testing.T) {
	testCases := []struct {
		name    string
		finding report.Finding
	}{
		{
			name: "Verification Not Exposed",
			finding: report.Finding{
				ID:         "fnd-def-ver",
				Category:   "privilege-escalation",
				Severity:   "CRITICAL",
				Confidence: "HIGH",
				Verification: report.VerificationRecord{
					Status: report.VerificationNotExposed,
				},
			},
		},
		{
			name: "Detection Not Exposed",
			finding: report.Finding{
				ID:         "fnd-def-det",
				Category:   "privilege-escalation",
				Severity:   "CRITICAL",
				Confidence: "HIGH",
				EvidenceDetails: report.EvidenceDetails{
					DetectionStatus: "NOT_EXPOSED",
				},
			},
		},
		{
			name: "Auth State AUTH_REQUIRED",
			finding: report.Finding{
				ID:         "fnd-def-auth",
				Category:   "privilege-escalation",
				Severity:   "CRITICAL",
				Confidence: "HIGH",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"auth_state": "AUTH_REQUIRED",
					},
				},
			},
		},
		{
			name: "Auth State FORBIDDEN",
			finding: report.Finding{
				ID:         "fnd-def-forb",
				Category:   "privilege-escalation",
				Severity:   "CRITICAL",
				Confidence: "HIGH",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"auth_state": "FORBIDDEN",
					},
				},
			},
		},
		{
			name: "Auth State NOT_FOUND",
			finding: report.Finding{
				ID:         "fnd-def-nf",
				Category:   "privilege-escalation",
				Severity:   "CRITICAL",
				Confidence: "HIGH",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"auth_state": "NOT_FOUND",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			expl := report.ExplainFindingScore(tc.finding)
			if expl.Score != 0 {
				t.Fatalf("%s received non-zero score: %d", tc.name, expl.Score)
			}
			if !expl.IsDefended {
				t.Fatalf("%s was not marked IsDefended=true", tc.name)
			}
			if expl.DefendedReason == "" {
				t.Fatalf("%s has empty DefendedReason", tc.name)
			}

			score := report.CalculateFindingScore(tc.finding)
			if score != 0 {
				t.Fatalf("CalculateFindingScore for %s returned %d (expected 0)", tc.name, score)
			}
		})
	}
}

// 7. Score explanation agreement with final score, formula, weights, and rationale.
func TestRiskScoring_ExplanationAgreement(t *testing.T) {
	finding := report.Finding{
		ID:          "fnd-expl-01",
		Title:       "AWS Secret Access Key Leaked in S3 Bucket",
		Category:    "cloud-provider-token",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Fingerprint: "fp-aws-key-01",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	normalized := report.NormalizeFinding(finding)
	expl := report.ExplainFindingScore(normalized)

	if normalized.Score != expl.Score {
		t.Fatalf("Normalized score (%d) does not match explanation score (%d)", normalized.Score, expl.Score)
	}
	if expl.BaseScore != 40.0 {
		t.Fatalf("Expected BaseScore 40 for CRITICAL, got %.1f", expl.BaseScore)
	}
	if expl.CategoryModifier != 5.0 {
		t.Fatalf("Expected CategoryModifier +5 for cloud-provider-token, got %.1f", expl.CategoryModifier)
	}
	if expl.ConfidenceWeight != 1.0 {
		t.Fatalf("Expected ConfidenceWeight 1.0, got %f", expl.ConfidenceWeight)
	}
	if expl.VerificationWeight != 1.0 {
		t.Fatalf("Expected VerificationWeight 1.0, got %f", expl.VerificationWeight)
	}
	if expl.Score != 40 {
		t.Fatalf("Expected final score 40 (capped at 40), got %d", expl.Score)
	}
	if !strings.Contains(expl.Formula, "(40.00 base + 5.00 mod)") {
		t.Fatalf("Formula %q does not match expected calculation string", expl.Formula)
	}
	if !strings.Contains(expl.Rationale, "CRITICAL severity") {
		t.Fatalf("Rationale %q does not explain severity base", expl.Rationale)
	}
	if !strings.Contains(expl.Rationale, "mod +5.0") {
		t.Fatalf("Rationale %q does not explain cloud modifier", expl.Rationale)
	}
}

// 8. Deduplication and order invariance: permuting the findings slice must produce
// identical risk scores and categorical levels.
func TestRiskScoring_DeduplicationAndOrderInvariance(t *testing.T) {
	findings := []report.Finding{
		{ID: "f1", Category: "bola", Severity: "CRITICAL", Confidence: "HIGH", Score: 30, Fingerprint: "fp-1", Verification: report.VerificationRecord{Status: report.VerificationVerified}},
		{ID: "f2", Category: "bfla", Severity: "HIGH", Confidence: "HIGH", Score: 20, Fingerprint: "fp-2", Verification: report.VerificationRecord{Status: report.VerificationVerified}},
		{ID: "f3", Category: "session-fixation", Severity: "HIGH", Confidence: "MEDIUM", Score: 15, Fingerprint: "fp-3", Verification: report.VerificationRecord{Status: report.VerificationDetected}},
		{ID: "f4", Category: "missing-security-header", Severity: "LOW", Confidence: "HIGH", Score: 5, Fingerprint: "fp-4", Verification: report.VerificationRecord{Status: report.VerificationDetected}},
		{ID: "f5", Category: "cookie-security", Severity: "MEDIUM", Confidence: "HIGH", Score: 10, Fingerprint: "fp-5", Verification: report.VerificationRecord{Status: report.VerificationDetected}},
	}

	stories := []report.SecurityStory{
		{ID: "s1", Title: "Story One"},
		{ID: "s2", Title: "Story Two"},
	}

	_, baseBreakdown, baseLevel := report.CalculateRiskBreakdown(findings, stories)

	// Reverse order
	reversed := make([]report.Finding, len(findings))
	for i, f := range findings {
		reversed[len(findings)-1-i] = f
	}
	_, revBreakdown, revLevel := report.CalculateRiskBreakdown(reversed, stories)

	if baseBreakdown.TotalScore != revBreakdown.TotalScore {
		t.Fatalf("Order invariance failed: forward total %d != reversed total %d",
			baseBreakdown.TotalScore, revBreakdown.TotalScore)
	}
	if baseLevel != revLevel {
		t.Fatalf("Order invariance failed: forward level %s != reversed level %s",
			baseLevel, revLevel)
	}
	if baseBreakdown.ExposureSubtotal != revBreakdown.ExposureSubtotal {
		t.Fatalf("Exposure subtotal mismatch on reorder: %f vs %f",
			baseBreakdown.ExposureSubtotal, revBreakdown.ExposureSubtotal)
	}
	if baseBreakdown.HardeningSubtotal != revBreakdown.HardeningSubtotal {
		t.Fatalf("Hardening subtotal mismatch on reorder: %f vs %f",
			baseBreakdown.HardeningSubtotal, revBreakdown.HardeningSubtotal)
	}

	// Test DeduplicateFindings preserves highest score and updates score explanation
	dup1 := report.Finding{
		ID:          "dup-1",
		Fingerprint: "fp-shared",
		Category:    "sqli",
		Severity:    "HIGH",
		Confidence:  "MEDIUM",
		Score:       19,
		Verification: report.VerificationRecord{Status: report.VerificationVerified},
	}
	dup2 := report.Finding{
		ID:          "dup-2",
		Fingerprint: "fp-shared",
		Category:    "sqli",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Score:       40,
		Verification: report.VerificationRecord{Status: report.VerificationVerified},
	}
	deduped := report.DeduplicateFindings([]report.Finding{dup1, dup2})
	if len(deduped) != 1 {
		t.Fatalf("Expected 1 deduped finding, got %d", len(deduped))
	}
	if deduped[0].Score != 40 {
		t.Fatalf("Expected deduped finding to retain higher score 40, got %d", deduped[0].Score)
	}
	if deduped[0].ScoreExplanation == nil || deduped[0].ScoreExplanation.Score != 40 {
		t.Fatalf("ScoreExplanation was not synchronized to higher score")
	}
}

// 9. Persistence round-trip fidelity in SQLite store: score, explanation, formula, rationale.
func TestRiskScoring_PersistenceRoundTripFidelity(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "felix-risk-store-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test_risk_roundtrip.db")
	store, err := assessment.NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("failed to open SQLite store: %v", err)
	}
	defer store.Close()

	client := &assessment.Client{ID: "cli_risk_01", Name: "Risk Test Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &assessment.Assessment{
		ID:             "asm_risk_01",
		Ref:            "ASM-2026-RISK1",
		ClientID:       client.ID,
		Name:           "Risk Score Assessment",
		AssessmentType: "API_AUDIT",
		ScopeMode:      "explicit",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	target := &assessment.AssessmentTarget{
		ID:           "tgt_risk_01",
		AssessmentID: asm.ID,
		TargetURL:    "https://api.example.com",
		TargetType:   assessment.TargetAPIBaseURL,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}

	exec := &assessment.AssessmentExecution{
		ID:           "exec_risk_01",
		AssessmentID: asm.ID,
		Status:       assessment.StatusCompleted,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	origFinding := report.Finding{
		ID:          "fnd_risk_orig_01",
		Category:    "cloud-service-credential",
		Title:       "GCP Service Account Private Key Exposed",
		Severity:    "CRITICAL",
		Confidence:  "HIGH",
		Target:      "https://api.example.com/creds",
		Endpoint:    "/creds",
		Method:      "GET",
		Fingerprint: "fp_risk_store_01",
		Verification: report.VerificationRecord{
			Status: report.VerificationVerified,
		},
	}

	// Normalize computes score and score explanation
	normalized := report.NormalizeFinding(origFinding)
	af := assessment.ToAssessmentFinding(asm.ID, exec.ID, target.ID, normalized)

	if err := store.SaveFindings([]assessment.AssessmentFinding{af}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	retrieved, err := store.GetFindings(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}
	if len(retrieved) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(retrieved))
	}

	rFnd := retrieved[0]
	if rFnd.Score != af.Score {
		t.Fatalf("Score mismatch on round-trip: got %d, expected %d", rFnd.Score, af.Score)
	}
	if rFnd.ScoreExplanation == nil {
		t.Fatalf("ScoreExplanation was nil after SQLite round-trip")
	}
	if rFnd.ScoreExplanation.Score != af.Score {
		t.Fatalf("ScoreExplanation.Score mismatch: got %d, expected %d", rFnd.ScoreExplanation.Score, af.Score)
	}
	if rFnd.ScoreExplanation.Formula != af.ScoreExplanation.Formula {
		t.Fatalf("Formula mismatch: got %q, expected %q", rFnd.ScoreExplanation.Formula, af.ScoreExplanation.Formula)
	}
	if rFnd.ScoreExplanation.Rationale != af.ScoreExplanation.Rationale {
		t.Fatalf("Rationale mismatch: got %q, expected %q", rFnd.ScoreExplanation.Rationale, af.ScoreExplanation.Rationale)
	}

	// Convert back to report.Finding and verify fidelity
	toRep := assessment.ToReportFinding(rFnd)
	if toRep.Score != rFnd.Score {
		t.Fatalf("ToReportFinding score mismatch: got %d, expected %d", toRep.Score, rFnd.Score)
	}
	if toRep.ScoreExplanation == nil || toRep.ScoreExplanation.Formula != af.ScoreExplanation.Formula {
		t.Fatalf("ToReportFinding explanation fidelity lost")
	}
}

// 10. Report generation reconciliation: Commercial Report, JSON Report, and in-memory calculations
// agree on score, risk level, contributions, and explainability.
func TestRiskScoring_ReportGenerationReconciliation(t *testing.T) {
	findings := []report.Finding{
		{
			ID:          "fnd-rec-01",
			Title:       "SQL Injection on Login",
			Category:    "sql-injection",
			Severity:    "HIGH",
			Confidence:  "HIGH",
			Fingerprint: "fp-rec-01",
			Target:      "https://example.com/api/login",
			Endpoint:    "/api/login",
			Method:      "POST",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
		},
		{
			ID:          "fnd-rec-02",
			Title:       "Strict-Transport-Security Header Missing",
			Category:    "missing-security-header",
			Severity:    "LOW",
			Confidence:  "HIGH",
			Fingerprint: "fp-rec-02",
			Target:      "https://example.com/",
			Endpoint:    "/",
			Method:      "GET",
			Verification: report.VerificationRecord{
				Status: report.VerificationDetected,
			},
		},
	}

	stories := []report.SecurityStory{
		{
			ID:    "story-rec-01",
			Title: "Unauthenticated Account Takeover Chain",
		},
	}

	for i := range findings {
		findings[i] = report.NormalizeFinding(findings[i])
	}

	// In-memory breakdown
	expectedContribs, expectedBreakdown, expectedLevel := report.CalculateRiskBreakdown(findings, stories)

	rep := report.BuildReport("https://example.com", findings)
	report.AttachSecurityStories(&rep, stories)
	report.RecalculateReportRisk(&rep)

	// Commercial Report
	commReport := report.BuildCommercialReport(
		rep,
		report.WithScopeDetails([]string{"example.com"}, []string{"https://example.com"}),
	)

	if commReport.RiskOverview.RiskScore != expectedBreakdown.TotalScore {
		t.Fatalf("Commercial report RiskScore (%d) != breakdown TotalScore (%d)",
			commReport.RiskOverview.RiskScore, expectedBreakdown.TotalScore)
	}
	if commReport.RiskOverview.RiskLevel != expectedLevel {
		t.Fatalf("Commercial report RiskLevel (%s) != expected level (%s)",
			commReport.RiskOverview.RiskLevel, expectedLevel)
	}
	if commReport.RiskOverview.ScoreBreakdown.FinalRiskLevel != expectedLevel {
		t.Fatalf("ScoreBreakdown.FinalRiskLevel (%s) != expected level (%s)",
			commReport.RiskOverview.ScoreBreakdown.FinalRiskLevel, expectedLevel)
	}
	if len(commReport.RiskOverview.FindingRiskContributions) != len(expectedContribs) {
		t.Fatalf("Commercial report RiskContributions count (%d) != expected (%d)",
			len(commReport.RiskOverview.FindingRiskContributions), len(expectedContribs))
	}

	// Verify each contribution has valid score, formula, and rationale
	for _, c := range commReport.RiskOverview.FindingRiskContributions {
		if c.Score < 0 || c.Score > 40 {
			t.Fatalf("Risk contribution score out of bounds [0, 40]: %d", c.Score)
		}
		if c.Formula == "" {
			t.Fatalf("Risk contribution formula is empty for finding %s", c.FindingID)
		}
		if c.Rationale == "" {
			t.Fatalf("Risk contribution rationale is empty for finding %s", c.FindingID)
		}
	}

	// JSON Report
	repJSON, err := report.GenerateJSON(rep)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	parsedRep, err := report.ParseReport(repJSON)
	if err != nil {
		t.Fatalf("ParseReport failed: %v", err)
	}

	if parsedRep.RiskScore != commReport.RiskOverview.RiskScore {
		t.Fatalf("Parsed JSON report RiskScore (%d) != Commercial report RiskScore (%d)",
			parsedRep.RiskScore, commReport.RiskOverview.RiskScore)
	}
	if parsedRep.RiskLevel != commReport.RiskOverview.RiskLevel {
		t.Fatalf("Parsed JSON report RiskLevel (%s) != Commercial report RiskLevel (%s)",
			parsedRep.RiskLevel, commReport.RiskOverview.RiskLevel)
	}

	// Verify JSON marshal/unmarshal round-trip
	commJSON, err := json.Marshal(commReport)
	if err != nil {
		t.Fatalf("Failed to marshal CommercialReport: %v", err)
	}
	var unmarshaledComm report.CommercialReport
	if err := json.Unmarshal(commJSON, &unmarshaledComm); err != nil {
		t.Fatalf("Failed to unmarshal CommercialReport: %v", err)
	}
	if unmarshaledComm.RiskOverview.RiskScore != commReport.RiskOverview.RiskScore {
		t.Fatalf("RiskScore changed after JSON serialization: %d vs %d",
			unmarshaledComm.RiskOverview.RiskScore, commReport.RiskOverview.RiskScore)
	}
	if unmarshaledComm.RiskOverview.ScoreBreakdown.TotalScore != commReport.RiskOverview.ScoreBreakdown.TotalScore {
		t.Fatalf("ScoreBreakdown.TotalScore changed after JSON serialization")
	}
}
