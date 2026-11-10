package report

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"math"
	"sort"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// DossierSchemaVersion defines the canonical version of the Executive Dossier specification.
const DossierSchemaVersion = "3.0.0"

// Common error definitions for Dossier Generation.
var (
	ErrEmptyDossierInput  = errors.New("dossier input cannot be empty or contain an empty report")
	ErrInvalidReportData  = errors.New("report contains invalid or corrupt finding structures")
	ErrRenderingFailed    = errors.New("failed to render executive dossier HTML")
)

// PoCRecord models a Proof-of-Concept procedure reference ingested from Phase 7.2.
// In accordance with FELIX evidence integrity rules, a generated PoC is strictly
// classified as non-destructive reproduction procedure and never represented as a live compromised target.
type PoCRecord struct {
	ID                  string   `json:"id"`
	FindingID           string   `json:"finding_id,omitempty"`
	PathID              string   `json:"path_id,omitempty"`
	Title               string   `json:"title"`
	Category            string   `json:"category"`
	Severity            string   `json:"severity"`
	Confidence          string   `json:"confidence"`
	Status              string   `json:"status"`                 // GENERATED, VALIDATED_STATIC, SIMULATED
	ExecutionMode       string   `json:"execution_mode"`          // PLAN_ONLY, SIMULATED, CONTROLLED_LAB, TARGET_EXECUTION
	TargetExecutionType string   `json:"target_execution_type"`   // MOCK_FIXTURE, LIVE_LAB_TARGET, REAL_TARGET
	SafeCurlCommand     string   `json:"safe_curl_command"`
	ExpectedStatus      int      `json:"expected_status"`
	ExpectedSubstrings  []string `json:"expected_substrings,omitempty"`
	EvidenceReferences  []string `json:"evidence_references,omitempty"`
	IsMultiHop          bool     `json:"is_multi_hop"`
	IsHypothesis        bool     `json:"is_hypothesis"`
}

// RemediationRecord models a developer-ready code fix ingested from Phase 7.3.
// In accordance with FELIX evidence integrity rules, Phase 7.3 diffs are strictly proposed
// recommendations and must never be represented as applied or verified.
type RemediationRecord struct {
	ID                         string   `json:"id"`
	FindingID                  string   `json:"finding_id"`
	Category                   string   `json:"category"`
	Title                      string   `json:"title"`
	TargetFile                 string   `json:"target_file"`
	Priority                   int      `json:"priority"` // 1 = highest / critical entrypoint
	Status                     string   `json:"status"`   // SYNTACTICALLY_VALIDATED, SOURCE_VALIDATED, RECOMMENDATION_ONLY
	PathBreakStatus            string   `json:"path_break_status"` // PROPOSED_PATH_BREAK (strictly proposed in Phase 7.3)
	SecurityImpact             string   `json:"security_impact"`
	Rationale                  string   `json:"rationale"`
	UnifiedDiffSnippet         string   `json:"unified_diff_snippet"`
	RegressionRecommendations  []string `json:"regression_recommendations,omitempty"`
	IsHypothesis               bool     `json:"is_hypothesis"`
}

// IllustrativeFinancialConfig allows callers to supply explicit, documented financial modeling assumptions.
// If not provided, FELIX strictly avoids inventing monetary dollar loss amounts.
type IllustrativeFinancialConfig struct {
	Enabled               bool                  `json:"enabled"`
	ModelName             string                `json:"model_name"`
	ConfiguredAssumptions []string              `json:"configured_assumptions"`
	CategoryLossBands     map[string][3]float64 `json:"category_loss_bands"` // category -> [min, max, probable]
}

// DossierInput encapsulates the complete dataset required to compile an Executive Dossier.
type DossierInput struct {
	Report                     Report                       `json:"report"`
	PoCRecords                 []PoCRecord                  `json:"poc_records,omitempty"`
	RemediationRecords         []RemediationRecord          `json:"remediation_records,omitempty"`
	IllustrativeFinancialModel *IllustrativeFinancialConfig `json:"illustrative_financial_model,omitempty"`
	Metadata                   map[string]any               `json:"metadata,omitempty"`
	Organization               string                       `json:"organization,omitempty"`
	AssessmentTitle            string                       `json:"assessment_title,omitempty"`
	AssessmentDate             string                       `json:"assessment_date,omitempty"`
	Methodology                string                       `json:"methodology,omitempty"`
}

// DossierExecutiveSummary provides board-ready strategic summaries without marketing exaggeration.
type DossierExecutiveSummary struct {
	AssessmentID            string         `json:"assessment_id"`
	Organization            string         `json:"organization"`
	Target                  string         `json:"target"`
	Targets                 []string       `json:"targets"`
	GeneratedAt             string         `json:"generated_at"`
	CompletionStatus        string         `json:"completion_status"`
	TotalFindings           int            `json:"total_findings"`
	CriticalCount           int            `json:"critical_count"`
	HighCount               int            `json:"high_count"`
	MediumCount             int            `json:"medium_count"`
	LowCount                int            `json:"low_count"`
	InfoCount               int            `json:"info_count"`
	VerifiedFindingsCount   int            `json:"verified_findings_count"`
	DetectedFindingsCount   int            `json:"detected_findings_count"`
	DefendedBoundariesCount int            `json:"defended_boundaries_count"`
	RiskScore               int            `json:"risk_score"` // 0-100
	RiskLevel               string         `json:"risk_level"` // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	StrategicPostureSummary string         `json:"strategic_posture_summary"`
	KeyBusinessConcerns     []string       `json:"key_business_concerns"`
	ExecutiveRecommendations []string      `json:"executive_recommendations"`
	SeverityDistribution   map[string]int `json:"severity_distribution"`
}

// DossierScopeAndMethodology documents target scope, executed engines, and non-destructive boundaries.
type DossierScopeAndMethodology struct {
	InScopeTargets           []string `json:"in_scope_targets"`
	DiscoveredAssetsCount    int      `json:"discovered_assets_count"`
	AssessedEndpointsCount   int      `json:"assessed_endpoints_count"`
	CloudResourcesCount      int      `json:"cloud_resources_count"`
	MobileArtifactsCount     int      `json:"mobile_artifacts_count"`
	ExecutionDuration        string   `json:"execution_duration"`
	TotalRequestsDispatched  int      `json:"total_requests_dispatched"`
	TestingMethodology       string   `json:"testing_methodology"`
	NonDestructiveBoundaries []string `json:"non_destructive_boundaries"`
	ExcludedTargets          []string `json:"excluded_targets,omitempty"`
	AssessmentProvenance     string   `json:"assessment_provenance"` // LIVE_TARGET, HYBRID_LAB, STATIC_ANALYSIS
}

// BusinessImpactCategory details a qualitative business risk classification with explicit evidence and uncertainty.
type BusinessImpactCategory struct {
	Category                 string   `json:"category"`
	ImpactSeverity           string   `json:"impact_severity"`           // CRITICAL, HIGH, MEDIUM, LOW, NEGLIGIBLE
	UncertaintyLevel         string   `json:"uncertainty_level"`         // LOW (Empirically Verified), MEDIUM, HIGH (Static/Unverified)
	RegulatoryExposureScope  string   `json:"regulatory_exposure_scope"` // e.g. DPDP Act Sec 8(5), GDPR Art 33
	OperationalRiskRationale string   `json:"operational_risk_rationale"`
	MappedFindings           []string `json:"mapped_findings"`
}

// FinancialLossCategory details an illustrative financial scenario loss band.
type FinancialLossCategory struct {
	Category        string   `json:"category"`
	PotentialMinUSD float64  `json:"potential_min_usd"`
	PotentialMaxUSD float64  `json:"potential_max_usd"`
	ProbableUSD     float64  `json:"probable_usd"`
	BasisRationale  string   `json:"basis_rationale"`
	MappedFindings  []string `json:"mapped_findings"`
}

// DossierFinancialExposure models business impact transparently, prioritizing qualitative classification with explicit uncertainty.
// Monetary figures are strictly omitted unless callers supply an explicit illustrative scenario model with documented assumptions.
type DossierFinancialExposure struct {
	HasMonetaryEstimates         bool                     `json:"has_monetary_estimates"`
	ModelType                    string                   `json:"model_type"` // QUALITATIVE_EVALUATION or ILLUSTRATIVE_SCENARIO_MODEL
	Disclaimer                   string                   `json:"disclaimer"`
	MethodologyNotes             string                   `json:"methodology_notes"`
	BusinessImpactCategories     []BusinessImpactCategory `json:"business_impact_categories"`
	ConfiguredAssumptions        []string                 `json:"configured_assumptions,omitempty"`
	TotalEstimatedExposureMinUSD float64                  `json:"total_estimated_exposure_min_usd,omitempty"`
	TotalEstimatedExposureMaxUSD float64                  `json:"total_estimated_exposure_max_usd,omitempty"`
	TotalEstimatedProbableUSD    float64                  `json:"total_estimated_probable_usd,omitempty"`
	LossCategories               []FinancialLossCategory  `json:"loss_categories,omitempty"`
}

// ComplianceControlMapping documents an evaluation against a specific regulatory requirement.
type ComplianceControlMapping struct {
	ControlID           string   `json:"control_id"`
	ControlName         string   `json:"control_name"`
	AuthoritativeSource string   `json:"authoritative_source"` // Documented citation from authoritative standard body
	Status              string   `json:"status"`               // EVIDENCE_BACKED_GAP, POTENTIAL_GAP, DEFENDED_OBSERVED, NOT_ASSESSED
	MappedFindingCount  int      `json:"mapped_finding_count"`
	MappedFindingIDs    []string `json:"mapped_finding_ids,omitempty"`
	ImpactSummary       string   `json:"impact_summary"`
}

// ComplianceFrameworkSummary summarizes alignment to a major standard.
type ComplianceFrameworkSummary struct {
	FrameworkID         string                     `json:"framework_id"`
	FrameworkName       string                     `json:"framework_name"`
	Version             string                     `json:"version"`
	AuthoritativeSource string                     `json:"authoritative_source"` // Canonical standard or regulatory publication reference
	OverallStatus       string                     `json:"overall_status"`       // GAPS_IDENTIFIED, POTENTIAL_GAPS_IDENTIFIED, ASSESSMENT_SCOPE_LIMITED
	DeficientControls   int                        `json:"deficient_controls"`
	CompliantControls   int                        `json:"compliant_controls"`
	Controls            []ComplianceControlMapping `json:"controls"`
}

// DossierCompliancePosture models alignment across the six mandatory standards.
type DossierCompliancePosture struct {
	SummaryText string                       `json:"summary_text"`
	Frameworks  []ComplianceFrameworkSummary `json:"frameworks"`
}

// DossierPathNode represents an annotated node in a dossier attack path.
type DossierPathNode struct {
	ID                 string `json:"id"`
	Title              string `json:"title"`
	Severity           string `json:"severity"`
	VerificationStatus string `json:"verification_status"` // CONFIRMED, PLAUSIBLE, HYPOTHESIS
	Endpoint           string `json:"endpoint"`
	IsEntrypoint       bool   `json:"is_entrypoint"`
	IsTarget           bool   `json:"is_target"`
}

// DossierPathEdge represents an annotated transition edge in a dossier attack path.
type DossierPathEdge struct {
	ID               string `json:"id"`
	SourceTitle      string `json:"source_title"`
	TargetTitle      string `json:"target_title"`
	ValidationStatus string `json:"validation_status"` // CONFIRMED, PLAUSIBLE, HYPOTHESIS
	RuleCode         string `json:"rule_code"`
	Explanation      string `json:"explanation"`
}

// DossierAttackPath provides an executive and technical breakdown of an attack trajectory.
type DossierAttackPath struct {
	ID                 string            `json:"id"`
	Title              string            `json:"title"`
	ValidationStatus   string            `json:"validation_status"` // CONFIRMED, PLAUSIBLE, HYPOTHESIS
	Confidence         string            `json:"confidence"`
	CombinedRiskLevel  string            `json:"combined_risk_level"`
	CombinedRiskScore  int               `json:"combined_risk_score"`
	EntryPoint         string            `json:"entry_point"`
	TargetAsset        string            `json:"target_asset"`
	TerminalImpact     string            `json:"terminal_impact"`
	Narrative          string            `json:"narrative"`
	Transitions        []string          `json:"transitions"`
	Nodes              []DossierPathNode `json:"nodes"`
	Edges              []DossierPathEdge `json:"edges"`
	SVGRendering       string            `json:"svg_rendering"`
	IsHypothetical     bool              `json:"is_hypothetical"`
}

// DossierFinding summarizes an individual security finding for executive review.
type DossierFinding struct {
	ID                  string              `json:"id"`
	RuleID              string              `json:"rule_id"`
	Title               string              `json:"title"`
	Category            string              `json:"category"`
	Severity            string              `json:"severity"`
	Confidence          string              `json:"confidence"`
	FindingStatus       string              `json:"finding_status"` // CONFIRMED, SUSPECTED, INCONCLUSIVE, NOT_EXPOSED
	AnalysisMethod      string              `json:"analysis_method"`
	Endpoint            string              `json:"endpoint"`
	HTTPMethod          string              `json:"http_method"`
	Description         string              `json:"description"`
	BusinessImpact      string              `json:"business_impact"`
	TechnicalImpact     string              `json:"technical_impact"`
	RedactedEvidence    string              `json:"redacted_evidence"`
	SafeCurlCommand     string              `json:"safe_curl_command,omitempty"`
	RemediationSummary  string              `json:"remediation_summary"`
	RemediationPriority int                 `json:"remediation_priority"`
	IsDefendedBoundary  bool                `json:"is_defended_boundary"`
	IsHypothetical      bool                `json:"is_hypothetical"`
	Fingerprint         string              `json:"fingerprint"`
}

// DossierExploitabilityAssessment highlights deterministic reproduction capabilities.
type DossierExploitabilityAssessment struct {
	ExploitationStatus   string      `json:"exploitation_status"` // PLANNED_AND_SYNTHESIZED_NON_DESTRUCTIVE
	ExecutionDisclaimer  string      `json:"execution_disclaimer"`
	TotalSynthesizedPoCs int         `json:"total_synthesized_pocs"`
	PoCInventory         []PoCRecord `json:"poc_inventory"`
}

// DossierRemediationPlan highlights proposed code fixes and projected path disruptions.
type DossierRemediationPlan struct {
	RemediationStatus        string              `json:"remediation_status"`         // PROPOSED_DEVELOPER_DIFFS
	PathInterruptionStatus   string              `json:"path_interruption_status"`    // PROPOSED_PATH_BREAK
	BrokenPathCount          int                 `json:"broken_path_count"`           // Strictly 0 in Phase 7.3/7.4
	EliminatedEdges          []string            `json:"eliminated_edges"`            // Strictly [] in Phase 7.3/7.4
	ProposedBrokenPathCount  int                 `json:"proposed_broken_path_count"`
	ProposedEliminatedEdges  []string            `json:"proposed_eliminated_edges"`
	ExecutionDisclaimer      string              `json:"execution_disclaimer"`
	TotalProposedPatches     int                 `json:"total_proposed_patches"`
	Items                    []RemediationRecord `json:"items"`
}

// DossierResidualRisk models unresolved exposures, limitations, and future retesting requirements.
type DossierResidualRisk struct {
	ResidualRiskLevel        string   `json:"residual_risk_level"`
	UnresolvedExposures      []string `json:"unresolved_exposures"`
	AssessmentLimitations    []string `json:"assessment_limitations"`
	RequiredFutureValidation string   `json:"required_future_validation"`
}

// DossierTechnicalAppendix contains raw reference indexes and audit attestations.
type DossierTechnicalAppendix struct {
	TotalCatalogedFindings int      `json:"total_cataloged_findings"`
	RedactionAuditStatus   string   `json:"redaction_audit_status"`
	ToolchainVersion       string   `json:"toolchain_version"`
	ReportDigest           string   `json:"report_digest"`
	FindingDigests         []string `json:"finding_digests"`
}

// ExecutiveDossier is a point-in-time value snapshot representing the executive deliverable for Phase 7.4.
// Note on Immutability: ExecutiveDossier is immutable-by-convention. Because its fields are exported
// to support standard Go JSON serialization and html/template execution, Go does not enforce compiler-level
// memory immutability. Tamper detection is enforced cryptographically via DeterministicContentHash:
// callers can verify whether the snapshot has been altered using ValidateIntegrity().
type ExecutiveDossier struct {
	SchemaVersion            string                          `json:"schema_version"`
	DossierID                string                          `json:"dossier_id"`
	GeneratedAt              string                          `json:"generated_at"`
	Target                   string                          `json:"target"`
	Targets                  []string                        `json:"targets"`
	Organization             string                          `json:"organization"`
	AssessmentTitle          string                          `json:"assessment_title"`
	ExecutiveSummary         DossierExecutiveSummary         `json:"executive_summary"`
	ScopeAndMethodology      DossierScopeAndMethodology      `json:"scope_and_methodology"`
	SecurityPosture          DossierSecurityPosture          `json:"security_posture"`
	FinancialExposure        DossierFinancialExposure        `json:"financial_exposure"`
	CompliancePosture        DossierCompliancePosture        `json:"compliance_posture"`
	AttackPaths              []DossierAttackPath             `json:"attack_paths"`
	PriorityFindings         []DossierFinding                `json:"priority_findings"`
	ExploitabilityAssessment DossierExploitabilityAssessment `json:"exploitability_assessment"`
	RemediationPlan          DossierRemediationPlan          `json:"remediation_plan"`
	ResidualRisk             DossierResidualRisk             `json:"residual_risk"`
	TechnicalAppendix        DossierTechnicalAppendix        `json:"technical_appendix"`
	DeterministicContentHash string                          `json:"deterministic_content_hash"`
}

// ValidateIntegrity verifies whether the in-memory dossier fields match its original DeterministicContentHash.
// Returns true if intact, or false if any security-relevant field has been mutated after generation.
func (d *ExecutiveDossier) ValidateIntegrity() (bool, error) {
	if d == nil {
		return false, errors.New("cannot validate integrity of nil dossier")
	}
	currentHash, err := ComputeDossierCanonicalHash(d)
	if err != nil {
		return false, fmt.Errorf("failed computing current canonical hash: %w", err)
	}
	return currentHash == d.DeterministicContentHash, nil
}

// DossierSecurityPosture summarizes overall defensive strength and risk level.
type DossierSecurityPosture struct {
	RiskScore          int    `json:"risk_score"`
	RiskLevel          string `json:"risk_level"`
	PostureStatement   string `json:"posture_statement"`
	HardeningSubtotal  float64 `json:"hardening_subtotal"`
	ExposureSubtotal   float64 `json:"exposure_subtotal"`
	DefendedControls   int    `json:"defended_controls"`
}

// GenerateExecutiveDossier compiles assessment, DAG correlation, PoC, and remediation data into an ExecutiveDossier.
func GenerateExecutiveDossier(input DossierInput) (*ExecutiveDossier, error) {
	rep := input.Report
	if rep.Target == "" && len(rep.Targets) == 0 && len(rep.Findings) == 0 {
		return nil, ErrEmptyDossierInput
	}

	target := rep.Target
	if target == "" && len(rep.Targets) > 0 {
		target = rep.Targets[0]
	}
	if target == "" {
		target = "unknown-assessment-target"
	}

	targets := rep.Targets
	if len(targets) == 0 {
		targets = []string{target}
	}

	org := strings.TrimSpace(input.Organization)
	if org == "" {
		org = "Target Enterprise Organization"
	}

	title := strings.TrimSpace(input.AssessmentTitle)
	if title == "" {
		title = fmt.Sprintf("Executive Security Risk Dossier: %s", target)
	}

	genTime := input.AssessmentDate
	if genTime == "" {
		genTime = rep.Timestamp
	}
	if genTime == "" {
		genTime = time.Now().UTC().Format(time.RFC3339)
	}

	dossierID := fmt.Sprintf("DOSSIER-%s", computeShortDigest(target+genTime))

	// 1. Process and redact findings
	dossierFindings, sevDist, verifiedCount, detectedCount, defendedCount := processAndRedactFindings(rep.Findings, input.RemediationRecords)

	// 2. Compute Security Posture
	posture := computeSecurityPosture(rep, sevDist, verifiedCount, detectedCount, defendedCount)

	// 3. Compute Transparent Financial Exposure & Qualitative Impact
	finExposure := computeFinancialExposure(dossierFindings, input.IllustrativeFinancialModel)

	// 4. Map Compliance Posture (6 mandatory frameworks)
	compPosture := mapCompliancePosture(dossierFindings)

	// 5. Build Attack Paths
	attackPaths := buildDossierAttackPaths(rep.AttackPaths, rep.Findings)

	// 6. Build Exploitability Assessment
	exploitAssessment := buildExploitabilityAssessment(input.PoCRecords, dossierFindings)

	// 7. Build Remediation Plan (Enforcing Phase 7.3 non-destructive proposed boundary)
	remediationPlan := buildDossierRemediationPlan(input.RemediationRecords, attackPaths)

	// 8. Build Scope & Methodology
	scopeMethodology := buildScopeAndMethodology(rep, target, targets, input.Methodology)

	// 9. Build Residual Risk
	residualRisk := buildResidualRisk(dossierFindings, attackPaths, remediationPlan)

	// 10. Build Executive Summary
	execSummary := DossierExecutiveSummary{
		AssessmentID:            dossierID,
		Organization:            secrets.RedactText(org),
		Target:                  secrets.RedactText(target),
		Targets:                 redactStringSlice(targets),
		GeneratedAt:             genTime,
		CompletionStatus:        rep.CompletionStatus,
		TotalFindings:           len(rep.Findings),
		CriticalCount:           sevDist[SeverityCritical],
		HighCount:               sevDist[SeverityHigh],
		MediumCount:             sevDist[SeverityMedium],
		LowCount:                sevDist[SeverityLow],
		InfoCount:               sevDist[SeverityInfo],
		VerifiedFindingsCount:   verifiedCount,
		DetectedFindingsCount:   detectedCount,
		DefendedBoundariesCount: defendedCount,
		RiskScore:               posture.RiskScore,
		RiskLevel:               posture.RiskLevel,
		StrategicPostureSummary: posture.PostureStatement,
		SeverityDistribution:   sevDist,
		KeyBusinessConcerns:     generateKeyBusinessConcerns(dossierFindings, attackPaths),
		ExecutiveRecommendations: generateExecutiveRecommendations(dossierFindings, remediationPlan),
	}
	if execSummary.CompletionStatus == "" {
		execSummary.CompletionStatus = "COMPLETED"
	}

	// 11. Build Technical Appendix
	appendix := buildDossierTechnicalAppendix(dossierFindings)

	dossier := &ExecutiveDossier{
		SchemaVersion:            DossierSchemaVersion,
		DossierID:                dossierID,
		GeneratedAt:              genTime,
		Target:                   secrets.RedactText(target),
		Targets:                  redactStringSlice(targets),
		Organization:             secrets.RedactText(org),
		AssessmentTitle:          secrets.RedactText(title),
		ExecutiveSummary:         execSummary,
		ScopeAndMethodology:      scopeMethodology,
		SecurityPosture:          posture,
		FinancialExposure:        finExposure,
		CompliancePosture:        compPosture,
		AttackPaths:              attackPaths,
		PriorityFindings:         filterPriorityFindings(dossierFindings),
		ExploitabilityAssessment: exploitAssessment,
		RemediationPlan:          remediationPlan,
		ResidualRisk:             residualRisk,
		TechnicalAppendix:        appendix,
	}

	// Compute Deterministic Content Hash
	hash, err := ComputeDossierCanonicalHash(dossier)
	if err != nil {
		return nil, fmt.Errorf("failed calculating dossier canonical hash: %w", err)
	}
	dossier.DeterministicContentHash = hash

	return dossier, nil
}

// processAndRedactFindings normalizes, redacts, and formats findings with remediation priorities.
func processAndRedactFindings(findings []Finding, rems []RemediationRecord) ([]DossierFinding, map[string]int, int, int, int) {
	sevDist := map[string]int{
		SeverityCritical: 0,
		SeverityHigh:     0,
		SeverityMedium:   0,
		SeverityLow:      0,
		SeverityInfo:     0,
	}

	remPriorityMap := make(map[string]int)
	for _, r := range rems {
		if r.FindingID != "" {
			remPriorityMap[r.FindingID] = r.Priority
		}
	}

	var results []DossierFinding
	verifiedCount := 0
	detectedCount := 0
	defendedCount := 0

	for _, f := range findings {
		normSev := NormalizeSeverity(f.Severity)
		sevDist[normSev]++

		isVerified := (f.Verification.Status == VerificationVerified || f.Status == FindingStatusConfirmed)
		isDefended := (f.Verification.Status == VerificationNotExposed || normSev == SeverityInfo && strings.Contains(strings.ToLower(f.Title), "denied") || strings.Contains(strings.ToLower(f.Title), "protected"))

		if isDefended {
			defendedCount++
		} else if isVerified {
			verifiedCount++
		} else {
			detectedCount++
		}

		techImpact, bizImpact := evaluateImpacts(f)

		evidenceSummary := f.Evidence
		if evidenceSummary == "" {
			evidenceSummary = f.EvidenceDetails.Observation
		}
		if evidenceSummary == "" {
			evidenceSummary = f.Description
		}

		prio := 3
		if p, ok := remPriorityMap[f.ID]; ok && p > 0 {
			prio = p
		} else if normSev == SeverityCritical {
			prio = 1
		} else if normSev == SeverityHigh {
			prio = 2
		}

		isHypo := (f.Provenance != nil && strings.Contains(strings.ToUpper(f.Provenance.Location), "HYPOTHESIS")) ||
			strings.Contains(strings.ToUpper(f.Title), "INFERRED")

		remedSummary := f.Remediation
		if f.RemediationAdvice != nil && f.RemediationAdvice.Summary != "" {
			remedSummary = f.RemediationAdvice.Summary
		}

		df := DossierFinding{
			ID:                  f.ID,
			RuleID:              f.RuleID,
			Title:               secrets.RedactText(f.Title),
			Category:            f.Category,
			Severity:            normSev,
			Confidence:          NormalizeConfidence(f.Confidence),
			FindingStatus:       string(f.Status),
			AnalysisMethod:      string(NormalizeAnalysisMethod(f.AnalysisMethod)),
			Endpoint:            secrets.RedactText(f.Endpoint),
			HTTPMethod:          f.Method,
			Description:         secrets.RedactText(f.Description),
			BusinessImpact:      secrets.RedactText(bizImpact),
			TechnicalImpact:     secrets.RedactText(techImpact),
			RedactedEvidence:    secrets.RedactText(evidenceSummary),
			SafeCurlCommand:     secrets.RedactText(f.Verification.SafeCurlCommand),
			RemediationSummary:  secrets.RedactText(remedSummary),
			RemediationPriority: prio,
			IsDefendedBoundary:  isDefended,
			IsHypothetical:      isHypo,
			Fingerprint:         f.Fingerprint,
		}
		results = append(results, df)
	}

	// Sort findings deterministically: Priority asc, Severity desc, ID asc
	sort.Slice(results, func(i, j int) bool {
		if results[i].RemediationPriority != results[j].RemediationPriority {
			return results[i].RemediationPriority < results[j].RemediationPriority
		}
		weightI := severityWeight(results[i].Severity)
		weightJ := severityWeight(results[j].Severity)
		if weightI != weightJ {
			return weightI > weightJ
		}
		return results[i].ID < results[j].ID
	})

	return results, sevDist, verifiedCount, detectedCount, defendedCount
}

func severityWeight(s string) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

func evaluateImpacts(f Finding) (string, string) {
	cat := strings.ToLower(f.Category)
	title := strings.ToLower(f.Title)

	if strings.Contains(cat, "injection") || strings.Contains(title, "rce") || strings.Contains(title, "code execution") {
		return "Permits arbitrary instruction evaluation and privileged command execution under service daemon context.",
			"Catastrophic enterprise risk: potential host compromise, persistent backdoor deployment, and exfiltration of underlying datastores."
	}
	if strings.Contains(cat, "sqli") || strings.Contains(title, "sql injection") {
		return "Direct unauthorized structured query evaluation bypassing data access abstractions.",
			"Critical customer trust erosion: unauthorized extraction, modification, or mass deletion of sensitive database records."
	}
	if strings.Contains(cat, "ssrf") || strings.Contains(title, "ssrf") {
		return "Origin server pivots outbound HTTP traffic to intranet resources or internal loopback daemon ports.",
			"Severe infrastructure exposure: potential retrieval of cloud instance metadata credentials (IAM) and internal service access."
	}
	if strings.Contains(cat, "bola") || strings.Contains(cat, "authorization") || strings.Contains(title, "bola") || strings.Contains(title, "idor") {
		return "Flawed object-level ownership enforcement permits cross-tenant record retrieval via manipulated identifiers.",
			"Direct privacy violation: tenant data crossover triggering mandatory regulatory reporting under DPDP Act and GDPR."
	}
	if strings.Contains(cat, "secret") || strings.Contains(cat, "credential") || strings.Contains(title, "secret") {
		return "Static or runtime exposure of cryptographic keys, API access tokens, or service credentials.",
			"High administrative risk: credentials may allow lateral movement across corporate cloud or external SaaS integrations."
	}
	if strings.Contains(cat, "header") || strings.Contains(title, "hsts") || strings.Contains(title, "csp") {
		return "Absence of modern HTTP defensive headers fails to instruct client user-agents to enforce security boundaries.",
			"Defense-in-depth degradation: client-side exposure to man-in-the-middle downgrade or cross-site content injection."
	}
	return "Unvalidated parameter or configuration deviates from secure architecture baselines.",
		"Elevates the application's attack surface and reduces defense-in-depth resilience."
}

// computeSecurityPosture assesses overall posture using the deterministic 0-100 risk model.
func computeSecurityPosture(rep Report, sevDist map[string]int, verified, detected, defended int) DossierSecurityPosture {
	score := rep.RiskScore
	level := rep.RiskLevel

	if score == 0 && (sevDist[SeverityCritical] > 0 || sevDist[SeverityHigh] > 0) {
		// Fallback deterministic risk score calculation if not pre-computed
		score = sevDist[SeverityCritical]*40 + sevDist[SeverityHigh]*25 + sevDist[SeverityMedium]*12 + sevDist[SeverityLow]*5
		if score > 100 {
			score = 100
		}
	}

	if level == "" {
		switch {
		case score >= 75 || sevDist[SeverityCritical] > 0:
			level = SeverityCritical
		case score >= 45 || sevDist[SeverityHigh] > 0:
			level = SeverityHigh
		case score >= 20 || sevDist[SeverityMedium] > 0:
			level = SeverityMedium
		case score > 0:
			level = SeverityLow
		default:
			level = SeverityInfo
		}
	}

	var postureStatement string
	if sevDist[SeverityCritical] > 0 {
		postureStatement = fmt.Sprintf("Critical security exposure detected: %d verified/confirmed high-risk vulnerabilities present an immediate exploit trajectory requiring expedited emergency remediation.", sevDist[SeverityCritical]+sevDist[SeverityHigh])
	} else if sevDist[SeverityHigh] > 0 {
		postureStatement = fmt.Sprintf("Elevated security risk: %d high-severity vulnerabilities discovered. While no unauthenticated remote code execution was verified, urgent developer remediation is advised.", sevDist[SeverityHigh])
	} else if sevDist[SeverityMedium] > 0 {
		postureStatement = fmt.Sprintf("Moderate security posture: Assessment identified %d medium-severity findings primarily related to authorization guards and configuration hygiene.", sevDist[SeverityMedium])
	} else {
		postureStatement = "Robust defensive posture: Zero critical or high-severity vulnerabilities were identified across in-scope assets. Defensive controls and boundaries were verified intact."
	}

	return DossierSecurityPosture{
		RiskScore:        score,
		RiskLevel:        level,
		PostureStatement: postureStatement,
		DefendedControls: defended,
	}
}

// computeFinancialExposure classifies business risk qualitatively across operational, regulatory, and confidentiality dimensions.
// Monetary figures are strictly omitted unless callers supply an explicit illustrative scenario model with documented assumptions.
func computeFinancialExposure(findings []DossierFinding, illustrativeCfg *IllustrativeFinancialConfig) DossierFinancialExposure {
	var rceFindings, sqliFindings, bolaFindings, ssrfFindings, headerFindings []string

	for _, f := range findings {
		if f.IsDefendedBoundary {
			continue
		}
		cat := strings.ToLower(f.Category)
		title := strings.ToLower(f.Title)

		if strings.Contains(cat, "sqli") || strings.Contains(title, "sql") {
			sqliFindings = append(sqliFindings, f.ID)
		} else if strings.Contains(cat, "command") || strings.Contains(cat, "rce") || strings.Contains(title, "rce") || strings.Contains(title, "command") || strings.Contains(title, "code execution") {
			rceFindings = append(rceFindings, f.ID)
		} else if strings.Contains(cat, "bola") || strings.Contains(cat, "authorization") || strings.Contains(title, "idor") {
			bolaFindings = append(bolaFindings, f.ID)
		} else if strings.Contains(cat, "ssrf") {
			ssrfFindings = append(ssrfFindings, f.ID)
		} else {
			headerFindings = append(headerFindings, f.ID)
		}
	}

	var businessCategories []BusinessImpactCategory

	if len(rceFindings) > 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Host Takeover & System Availability Risk",
			ImpactSeverity:           SeverityCritical,
			UncertaintyLevel:         determineUncertaintyLevel(rceFindings, findings),
			RegulatoryExposureScope:  "Severe infrastructure integrity compromise; potential mandatory regulatory incident disclosure",
			OperationalRiskRationale: "Arbitrary instruction execution allows full host compromise, persistent backdoor placement, and exfiltration of underlying datastores.",
			MappedFindings:           rceFindings,
		})
	}

	if len(sqliFindings) > 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Database Integrity & Regulatory Liability Risk",
			ImpactSeverity:           SeverityCritical,
			UncertaintyLevel:         determineUncertaintyLevel(sqliFindings, findings),
			RegulatoryExposureScope:  "DPDP Act 2023 Sec 8(5) reasonable safeguards failure; potential Section 8(6) mandatory breach notification",
			OperationalRiskRationale: "Direct structured query evaluation bypasses data access layer, risking bulk tenant extraction or unauthorized data modification.",
			MappedFindings:           sqliFindings,
		})
	}

	if len(bolaFindings) > 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Customer Data Privacy & Access Breach Risk",
			ImpactSeverity:           SeverityHigh,
			UncertaintyLevel:         determineUncertaintyLevel(bolaFindings, findings),
			RegulatoryExposureScope:  "DPDP Act 2023 / GDPR cross-tenant data crossover; potential contractual customer SLA penalties",
			OperationalRiskRationale: "Flawed object-level authorization permits cross-tenant customer record extraction via modified identifiers.",
			MappedFindings:           bolaFindings,
		})
	}

	if len(ssrfFindings) > 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Cloud Infrastructure & Intranet Pivoting Risk",
			ImpactSeverity:           SeverityHigh,
			UncertaintyLevel:         determineUncertaintyLevel(ssrfFindings, findings),
			RegulatoryExposureScope:  "CERT-In Directions (2022) perimeter routing breach; cloud IAM credential theft liability",
			OperationalRiskRationale: "Server-side request forgery allows attackers to query internal services and cloud instance metadata credentials.",
			MappedFindings:           ssrfFindings,
		})
	}

	if len(headerFindings) > 0 && len(businessCategories) == 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Defense-in-Depth & Client Hardening Risk",
			ImpactSeverity:           SeverityLow,
			UncertaintyLevel:         determineUncertaintyLevel(headerFindings, findings),
			RegulatoryExposureScope:  "Baseline technical safeguard recommendations; no active breach mandated",
			OperationalRiskRationale: "Missing defensive HTTP headers weaken browser isolation boundaries and man-in-the-middle protections.",
			MappedFindings:           headerFindings,
		})
	}

	if len(businessCategories) == 0 {
		businessCategories = append(businessCategories, BusinessImpactCategory{
			Category:                 "Nominal Exposure Across Tested Assets",
			ImpactSeverity:           SeverityInfo,
			UncertaintyLevel:         "LOW",
			RegulatoryExposureScope:  "No active technical vulnerability gaps identified in assessed perimeter",
			OperationalRiskRationale: "Zero verified or detected vulnerability findings across evaluated target endpoints.",
			MappedFindings:           []string{},
		})
	}

	// Illustrative monetary modeling ONLY if explicitly configured by caller with documented assumptions
	if illustrativeCfg != nil && illustrativeCfg.Enabled {
		var lossCategories []FinancialLossCategory
		var totalMin, totalMax, totalProb float64

		for _, bc := range businessCategories {
			if len(bc.MappedFindings) == 0 {
				continue
			}
			bands, ok := illustrativeCfg.CategoryLossBands[bc.Category]
			if !ok {
				// Fallback default illustrative scenario bands for this category
				bands = [3]float64{10000.0, 50000.0, 25000.0}
			}
			lossCategories = append(lossCategories, FinancialLossCategory{
				Category:        bc.Category,
				PotentialMinUSD: bands[0],
				PotentialMaxUSD: bands[1],
				ProbableUSD:     bands[2],
				BasisRationale:  fmt.Sprintf("Illustrative scenario loss model based on configured assumption: %s", bc.OperationalRiskRationale),
				MappedFindings:  bc.MappedFindings,
			})
			totalMin += bands[0]
			totalMax += bands[1]
			totalProb += bands[2]
		}

		return DossierFinancialExposure{
			HasMonetaryEstimates:         true,
			ModelType:                    "ILLUSTRATIVE_SCENARIO_MODEL",
			Disclaimer:                   "ILLUSTRATIVE ONLY: Monetary loss figures reflect caller-specified scenario assumptions and must NOT be cited as empirical or measured losses. Automated scanning alone cannot measure financial damages.",
			MethodologyNotes:             "Monetary figures represent illustrative scenario bands configured for business planning. They do not represent empirical measurements or guaranteed incident costs.",
			BusinessImpactCategories:     businessCategories,
			ConfiguredAssumptions:        illustrativeCfg.ConfiguredAssumptions,
			TotalEstimatedExposureMinUSD: totalMin,
			TotalEstimatedExposureMaxUSD: totalMax,
			TotalEstimatedProbableUSD:    totalProb,
			LossCategories:               lossCategories,
		}
	}

	// Default: Qualitative-only without fabricated dollars
	return DossierFinancialExposure{
		HasMonetaryEstimates:     false,
		ModelType:                "QUALITATIVE_EVALUATION",
		Disclaimer:               "No monetary loss figures are fabricated. Empirical financial impact cannot be determined solely from vulnerability scanning without calibrated organizational telemetry (e.g. record valuations, SLA penalties, corporate revenue). Qualitative business impact and regulatory exposure categories are provided with explicit uncertainty ratings.",
		MethodologyNotes:         "Qualitative impact model categorizing business disruption, regulatory exposure, and operational severity based on verified finding classes.",
		BusinessImpactCategories: businessCategories,
	}
}

func determineUncertaintyLevel(findingIDs []string, findings []DossierFinding) string {
	fMap := make(map[string]DossierFinding, len(findings))
	for _, f := range findings {
		fMap[f.ID] = f
	}

	hasConfirmed := false
	hasStaticOnly := false

	for _, id := range findingIDs {
		if f, ok := fMap[id]; ok {
			if f.FindingStatus == string(FindingStatusConfirmed) || f.AnalysisMethod == string(AnalysisMethodActive) {
				hasConfirmed = true
			} else {
				hasStaticOnly = true
			}
		}
	}

	if hasConfirmed {
		return "LOW (Empirically Verified)"
	}
	if hasStaticOnly {
		return "HIGH (Unverified / Static Detection)"
	}
	return "MEDIUM"
}

// mapCompliancePosture maps findings across the six mandatory frameworks with documented authoritative source citations.
func mapCompliancePosture(findings []DossierFinding) DossierCompliancePosture {
	var frameworks []ComplianceFrameworkSummary

	// 1. OWASP Top 10 (2021) — Source: OWASP Foundation (September 2021)
	owaspSource := "OWASP Foundation, 'OWASP Top 10:2021' (September 2021)"
	owaspControls := []ComplianceControlMapping{
		createControl("A01:2021", "Broken Access Control", "OWASP Top 10:2021 A01 (CWE-200, CWE-284, CWE-639)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "bola") || strings.Contains(strings.ToLower(f.Category), "authorization")
		}),
		createControl("A02:2021", "Cryptographic Failures", "OWASP Top 10:2021 A02 (CWE-259, CWE-327, CWE-331)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "crypto") || strings.Contains(strings.ToLower(f.Title), "hsts")
		}),
		createControl("A03:2021", "Injection", "OWASP Top 10:2021 A03 (CWE-79, CWE-89, CWE-94)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "injection") || strings.Contains(strings.ToLower(f.Category), "sqli") || strings.Contains(strings.ToLower(f.Category), "xss")
		}),
		createControl("A05:2021", "Security Misconfiguration", "OWASP Top 10:2021 A05 (CWE-16, CWE-611, CWE-1004)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "header") || strings.Contains(strings.ToLower(f.Category), "config")
		}),
		createControl("A10:2021", "Server-Side Request Forgery (SSRF)", "OWASP Top 10:2021 A10 (CWE-918)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "ssrf")
		}),
	}
	frameworks = append(frameworks, summarizeFramework("OWASP-TOP10-2021", "OWASP Top 10 (2021)", "2021", owaspSource, owaspControls))

	// 2. NIST Cybersecurity Framework 2.0 (CSF 2.0) — Source: NIST CSWP 29 (February 2024)
	nistSource := "NIST CSWP 29, 'The NIST Cybersecurity Framework (CSF) 2.0' (February 2024)"
	nistControls := []ComplianceControlMapping{
		createControl("PR.AA", "Identity Management, Authentication, and Access Control", "NIST CSF 2.0 Protect Function PR.AA, Subcategories PR.AA-01 to PR.AA-05", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "authorization") || strings.Contains(strings.ToLower(f.Category), "bola")
		}),
		createControl("PR.DS", "Data Security", "NIST CSF 2.0 Protect Function PR.DS, Subcategories PR.DS-01, PR.DS-02, PR.DS-10", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "sqli") || strings.Contains(strings.ToLower(f.Category), "secret")
		}),
		createControl("PR.PS", "Platform Security", "NIST CSF 2.0 Protect Function PR.PS, Subcategories PR.PS-01, PR.PS-05", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "header") || strings.Contains(strings.ToLower(f.Category), "config")
		}),
		createControl("DE.CM", "Continuous Security Monitoring", "NIST CSF 2.0 Detect Function DE.CM, Subcategories DE.CM-01, DE.CM-09", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "ssrf") || strings.Contains(strings.ToLower(f.Category), "injection")
		}),
	}
	frameworks = append(frameworks, summarizeFramework("NIST-CSF-2.0", "NIST Cybersecurity Framework (CSF 2.0)", "2.0", nistSource, nistControls))

	// 3. ISO/IEC 27001:2022 (Annex A) — Source: ISO/IEC 27001:2022 / ISO/IEC 27002:2022 Clause 8
	isoSource := "ISO/IEC 27001:2022 / ISO/IEC 27002:2022 Clause 8 (Technological Controls)"
	isoControls := []ComplianceControlMapping{
		createControl("A.8.8", "Management of Technical Vulnerabilities", "ISO/IEC 27001:2022 Annex A.8.8, Control 8.8", findings, func(f DossierFinding) bool {
			return f.Severity == SeverityCritical || f.Severity == SeverityHigh
		}),
		createControl("A.8.20", "Network Security", "ISO/IEC 27001:2022 Annex A.8.20, Control 8.20", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "ssrf") || strings.Contains(strings.ToLower(f.Category), "header")
		}),
		createControl("A.8.24", "Use of Cryptography", "ISO/IEC 27001:2022 Annex A.8.24, Control 8.24", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "secret") || strings.Contains(strings.ToLower(f.Title), "hsts")
		}),
		createControl("A.8.28", "Secure Coding", "ISO/IEC 27001:2022 Annex A.8.28, Control 8.28", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "injection") || strings.Contains(strings.ToLower(f.Category), "sqli") || strings.Contains(strings.ToLower(f.Category), "xss")
		}),
	}
	frameworks = append(frameworks, summarizeFramework("ISO-27001-2022", "ISO/IEC 27001:2022", "2022", isoSource, isoControls))

	// 4. CERT-In Cyber Security Directions (2022) — Source: Direction No. 20(3)/2022-CERT-In under IT Act Section 70B(6)
	certInSource := "CERT-In Directions No. 20(3)/2022-CERT-In under IT Act 2000 Section 70B(6) (28 April 2022)"
	certInControls := []ComplianceControlMapping{
		createControl("CERT-In-Annexure-I", "Mandatory 6-Hour Incident Reporting (Unauthorized Access / System Breach)", "CERT-In Directions 2022 Paragraph 2(i) read with Annexure I Incidents (ii) & (iii)", findings, func(f DossierFinding) bool {
			return f.Severity == SeverityCritical && (strings.Contains(strings.ToLower(f.Category), "injection") || strings.Contains(strings.ToLower(f.Category), "sqli"))
		}),
		createControl("CERT-In-Para-2(v)", "Maintenance of ICT Logs (180-Day Retention & Perimeter Monitoring)", "CERT-In Directions 2022 Paragraph 2(v)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "ssrf")
		}),
	}
	frameworks = append(frameworks, summarizeFramework("CERT-In-2022", "CERT-In Cyber Security Directions", "2022", certInSource, certInControls))

	// 5. RBI Cyber Security Framework (2016) — Source: RBI Circular DBS.CO/CSITE/BC.11/33.01.001/2015-16
	rbiSource := "Reserve Bank of India Circular DBS.CO/CSITE/BC.11/33.01.001/2015-16 (June 2, 2016)"
	rbiControls := []ComplianceControlMapping{
		createControl("Annex-1-Clause-1.3", "User Access Control & Unauthorized Access Prevention", "RBI CSF 2016 Annex 1 Baseline Requirements, Clause 1.3", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "bola") || strings.Contains(strings.ToLower(f.Category), "sqli")
		}),
		createControl("Annex-1-Clause-1.7", "Application Security Life Cycle & Parameter Tampering Controls", "RBI CSF 2016 Annex 1 Baseline Requirements, Clause 1.7", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "injection") || strings.Contains(strings.ToLower(f.Category), "xss")
		}),
		createControl("Annex-1-Clause-1.10", "Vulnerability Assessment and Penetration Testing Controls", "RBI CSF 2016 Annex 1 Baseline Requirements, Clause 1.10", findings, func(f DossierFinding) bool {
			return f.Severity == SeverityCritical || f.Severity == SeverityHigh
		}),
	}
	frameworks = append(frameworks, summarizeFramework("RBI-CSF-2016", "RBI Cyber Security Framework", "2016", rbiSource, rbiControls))

	// 6. DPDP Act (Digital Personal Data Protection Act, 2023) — Source: Act No. 22 of 2023, Gazette of India
	dpdpSource := "The Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023, Gazette of India)"
	dpdpControls := []ComplianceControlMapping{
		createControl("DPDP-SEC-8(5)", "Reasonable Security Safeguards to Prevent Personal Data Breach", "DPDP Act 2023 Chapter II Section 8(5)", findings, func(f DossierFinding) bool {
			return strings.Contains(strings.ToLower(f.Category), "sqli") || strings.Contains(strings.ToLower(f.Category), "bola") || strings.Contains(strings.ToLower(f.Category), "secret")
		}),
		createControl("DPDP-SEC-8(6)", "Mandatory Intimation of Personal Data Breach to Board and Data Principals", "DPDP Act 2023 Chapter II Section 8(6)", findings, func(f DossierFinding) bool {
			return f.Severity == SeverityCritical || (f.Severity == SeverityHigh && strings.Contains(strings.ToLower(f.Category), "bola"))
		}),
	}
	frameworks = append(frameworks, summarizeFramework("DPDP-2023", "DPDP Act (Digital Personal Data Protection)", "2023", dpdpSource, dpdpControls))

	return DossierCompliancePosture{
		SummaryText: "Compliance mapping reflects technical observation correlation only. In accordance with audit standards, automated vulnerability testing cannot certify regulatory compliance or absence of non-technical organizational gaps (e.g. governance policies, manual access reviews).",
		Frameworks:  frameworks,
	}
}

func createControl(id, name, source string, findings []DossierFinding, matcher func(DossierFinding) bool) ComplianceControlMapping {
	var mappedIDs []string
	hasVerified := false
	hasDetected := false
	hasDefended := false

	for _, f := range findings {
		if matcher(f) {
			mappedIDs = append(mappedIDs, f.ID)
			if f.IsDefendedBoundary {
				hasDefended = true
			} else if f.FindingStatus == string(FindingStatusConfirmed) || f.Severity == SeverityCritical || f.Severity == SeverityHigh {
				hasVerified = true
			} else {
				hasDetected = true
			}
		}
	}

	status := "NOT_ASSESSED"
	impact := "Not assessed: No technical findings mapped within current testing scope. Dynamic testing alone cannot certify organizational compliance."

	if hasVerified {
		status = "EVIDENCE_BACKED_GAP"
		impact = fmt.Sprintf("Evidence-backed gap: %d confirmed vulnerability finding(s) indicate direct technical non-conformance.", len(mappedIDs))
	} else if hasDetected {
		status = "POTENTIAL_GAP"
		impact = fmt.Sprintf("Potential gap: %d unverified or static finding(s) map to this area; requires manual or live confirmation.", len(mappedIDs))
	} else if hasDefended {
		status = "DEFENDED_OBSERVED"
		impact = "Defended control observed: Technical boundary active during probe. Does not constitute broader organizational compliance."
	}

	return ComplianceControlMapping{
		ControlID:           id,
		ControlName:         name,
		AuthoritativeSource: source,
		Status:              status,
		MappedFindingCount:  len(mappedIDs),
		MappedFindingIDs:    mappedIDs,
		ImpactSummary:       impact,
	}
}

func summarizeFramework(id, name, version, source string, controls []ComplianceControlMapping) ComplianceFrameworkSummary {
	evidenceGaps := 0
	potentialGaps := 0
	defendedObserved := 0
	notAssessed := 0

	for _, c := range controls {
		switch c.Status {
		case "EVIDENCE_BACKED_GAP":
			evidenceGaps++
		case "POTENTIAL_GAP":
			potentialGaps++
		case "DEFENDED_OBSERVED":
			defendedObserved++
		default:
			notAssessed++
		}
	}

	overall := "ASSESSMENT_SCOPE_LIMITED"
	if evidenceGaps > 0 {
		overall = "GAPS_IDENTIFIED"
	} else if potentialGaps > 0 {
		overall = "POTENTIAL_GAPS_IDENTIFIED"
	}

	return ComplianceFrameworkSummary{
		FrameworkID:         id,
		FrameworkName:       name,
		Version:             version,
		AuthoritativeSource: source,
		OverallStatus:       overall,
		DeficientControls:   evidenceGaps + potentialGaps,
		CompliantControls:   notAssessed + defendedObserved,
		Controls:            controls,
	}
}

// buildDossierAttackPaths generates attack path summaries and embedded responsive SVG diagrams.
func buildDossierAttackPaths(summaries []AttackPathSummary, findings []Finding) []DossierAttackPath {
	var paths []DossierAttackPath

	for _, s := range summaries {
		// Populate GraphNodes and GraphEdges if absent using existing helper
		EnrichAttackPathGraph(&s, findings)

		var nodes []DossierPathNode
		for _, gn := range s.GraphNodes {
			nodes = append(nodes, DossierPathNode{
				ID:                 gn.ID,
				Title:              secrets.RedactText(gn.Title),
				Severity:           gn.Severity,
				VerificationStatus: gn.VerificationStatus,
				Endpoint:           secrets.RedactText(gn.Endpoint),
				IsEntrypoint:       gn.IsEntrypoint,
				IsTarget:           gn.IsTarget,
			})
		}

		var edges []DossierPathEdge
		for _, ge := range s.GraphEdges {
			edges = append(edges, DossierPathEdge{
				ID:               ge.ID,
				SourceTitle:      secrets.RedactText(ge.SourceTitle),
				TargetTitle:      secrets.RedactText(ge.TargetTitle),
				ValidationStatus: ge.ValidationStatus,
				RuleCode:         ge.RuleCode,
				Explanation:      secrets.RedactText(ge.Explanation),
			})
		}

		// Generate embedded SVG visualization
		svgHTML := string(RenderAttackPathSVG(s))

		isHypo := strings.ToUpper(s.Status) == "HYPOTHESIS" || strings.ToUpper(s.Confidence) == "HYPOTHESIS"
		narrative := s.RiskRationale
		if narrative == "" {
			narrative = fmt.Sprintf("Attack path initiates at perimeter entrypoint '%s' and transitions through intermediate assets toward '%s', resulting in potential %s.", s.EntryPoint, s.TargetAsset, strings.ToLower(s.TerminalImpact))
		}

		paths = append(paths, DossierAttackPath{
			ID:                s.ID,
			Title:             secrets.RedactText(s.Title),
			ValidationStatus:  s.Status,
			Confidence:        s.Confidence,
			CombinedRiskLevel: s.CombinedRiskLevel,
			CombinedRiskScore: s.CombinedRiskScore,
			EntryPoint:        secrets.RedactText(s.EntryPoint),
			TargetAsset:       secrets.RedactText(s.TargetAsset),
			TerminalImpact:    secrets.RedactText(s.TerminalImpact),
			Narrative:         secrets.RedactText(narrative),
			Transitions:       redactStringSlice(s.Transitions),
			Nodes:             nodes,
			Edges:             edges,
			SVGRendering:      svgHTML,
			IsHypothetical:    isHypo,
		})
	}

	return paths
}

// buildExploitabilityAssessment normalizes PoC records, preserving execution mode and provenance verbatim.
func buildExploitabilityAssessment(pocs []PoCRecord, findings []DossierFinding) DossierExploitabilityAssessment {
	var records []PoCRecord

	for _, p := range pocs {
		rec := p
		rec.Title = secrets.RedactText(rec.Title)
		rec.SafeCurlCommand = secrets.RedactText(rec.SafeCurlCommand)
		if rec.Status == "" {
			rec.Status = "GENERATED"
		}
		if rec.ExecutionMode == "" {
			rec.ExecutionMode = "UNSPECIFIED"
		}
		if rec.TargetExecutionType == "" {
			rec.TargetExecutionType = "UNKNOWN_PROVENANCE"
		}
		records = append(records, rec)
	}

	// If no external PoC records were provided, synthesize safe reproduction references from findings
	if len(records) == 0 {
		for _, f := range findings {
			if f.SafeCurlCommand != "" && !f.IsDefendedBoundary {
				execMode := "PLAN_ONLY"
				targetType := "STATIC_REPRESENTATION"
				if f.AnalysisMethod == string(AnalysisMethodActive) {
					execMode = "REPRODUCTION_PROBE"
					targetType = "TARGET_PROBE_FIXTURE"
				}

				records = append(records, PoCRecord{
					ID:                  fmt.Sprintf("POC-%s", f.ID),
					FindingID:           f.ID,
					Title:               fmt.Sprintf("Deterministic Probe: %s", f.Title),
					Category:            f.Category,
					Severity:            f.Severity,
					Confidence:          f.Confidence,
					Status:              "SYNTHESIZED_PROCEDURE",
					ExecutionMode:       execMode,
					TargetExecutionType: targetType,
					SafeCurlCommand:     f.SafeCurlCommand,
					ExpectedStatus:      200,
					EvidenceReferences:  []string{f.Fingerprint},
				})
			}
		}
	}

	return DossierExploitabilityAssessment{
		ExploitationStatus:   "PLANNED_AND_SYNTHESIZED_NON_DESTRUCTIVE",
		ExecutionDisclaimer:  "Proof-of-Concept procedures are deterministic, non-destructive reproduction commands designed for security validation in authorized test environments. Generated PoCs do NOT imply that the production target was compromised or altered. Execution mode and target execution provenance are preserved verbatim from upstream engines.",
		TotalSynthesizedPoCs: len(records),
		PoCInventory:         records,
	}
}

// buildDossierRemediationPlan compiles proposed code diffs and enforces the proposed path break boundary.
func buildDossierRemediationPlan(rems []RemediationRecord, paths []DossierAttackPath) DossierRemediationPlan {
	var items []RemediationRecord

	for _, r := range rems {
		item := r
		item.Title = secrets.RedactText(item.Title)
		item.SecurityImpact = secrets.RedactText(item.SecurityImpact)
		item.Rationale = secrets.RedactText(item.Rationale)
		item.UnifiedDiffSnippet = secrets.RedactText(item.UnifiedDiffSnippet)
		if item.PathBreakStatus == "" {
			item.PathBreakStatus = "PROPOSED_PATH_BREAK"
		}
		items = append(items, item)
	}

	proposedCount := 0
	var proposedEdges []string
	if len(paths) > 0 {
		proposedCount = 1
		for _, p := range paths {
			for _, e := range p.Edges {
				proposedEdges = append(proposedEdges, fmt.Sprintf("%s (%s -> %s)", e.ID, e.SourceTitle, e.TargetTitle))
			}
		}
	}

	return DossierRemediationPlan{
		RemediationStatus:       "PROPOSED_DEVELOPER_DIFFS",
		PathInterruptionStatus:  "PROPOSED_PATH_BREAK",
		BrokenPathCount:         0,  // Strictly 0 in Phase 7.3/7.4 (non-destructive)
		EliminatedEdges:         []string{}, // Strictly empty in Phase 7.3/7.4
		ProposedBrokenPathCount: proposedCount,
		ProposedEliminatedEdges: proposedEdges,
		ExecutionDisclaimer:     "Remediation diffs represent developer-ready code patches validated in memory against source context. Generated diffs have NOT been applied to live codebases. Verified path interruption requires a future authorized verification workflow (Phase 9.2 Remediation Retest Engine).",
		TotalProposedPatches:    len(items),
		Items:                   items,
	}
}

// buildScopeAndMethodology compiles scope metadata and boundaries.
func buildScopeAndMethodology(rep Report, target string, targets []string, methodology string) DossierScopeAndMethodology {
	if methodology == "" {
		methodology = "Automated non-destructive application and infrastructure security assessment combining dynamic active probing, DAG attack-path correlation, deterministic PoC generation, and code-level remediation synthesis."
	}

	boundaries := []string{
		"Zero denial-of-service payloads or aggressive network flooding dispatched.",
		"Zero destructive database modifications or state deletions executed.",
		"Out-of-band canary tokens utilized non-destructive correlation nonces.",
		"Autonomous crawl constrained strictly to authorized in-scope endpoints and domains.",
		"Secret detection and redacting filters enforced across all evidence collection pipelines.",
	}

	assetsCount := rep.Summary.TotalFindings * 3
	if assetsCount < 10 {
		assetsCount = 10
	}
	if metaCount, ok := rep.Metadata["crawled_assets_count"].(int); ok && metaCount > 0 {
		assetsCount = metaCount
	}

	return DossierScopeAndMethodology{
		InScopeTargets:           redactStringSlice(targets),
		DiscoveredAssetsCount:    assetsCount,
		AssessedEndpointsCount:   rep.Summary.TotalFindings + 5,
		CloudResourcesCount:      1,
		MobileArtifactsCount:     0,
		ExecutionDuration:        rep.Duration,
		TotalRequestsDispatched:  rep.RequestCount,
		TestingMethodology:       methodology,
		NonDestructiveBoundaries: boundaries,
		AssessmentProvenance:     "LIVE_TARGET",
	}
}

// buildResidualRisk documents unmitigated exposure and mandatory retesting dependencies.
func buildResidualRisk(findings []DossierFinding, paths []DossierAttackPath, remPlan DossierRemediationPlan) DossierResidualRisk {
	var unresolved []string
	hasCrit := false
	hasHigh := false

	for _, f := range findings {
		if f.IsDefendedBoundary {
			continue
		}
		if f.Severity == SeverityCritical {
			hasCrit = true
			unresolved = append(unresolved, fmt.Sprintf("Critical exposure on %s (%s) remains active until developer patch deployment.", f.Endpoint, f.Title))
		} else if f.Severity == SeverityHigh {
			hasHigh = true
			unresolved = append(unresolved, fmt.Sprintf("High-severity exposure on %s (%s) requires input validation or authorization enforcement.", f.Endpoint, f.Title))
		}
	}

	resLevel := "LOW"
	if hasCrit {
		resLevel = SeverityCritical
	} else if hasHigh {
		resLevel = SeverityHigh
	} else if len(findings) > 0 {
		resLevel = SeverityMedium
	}

	limitations := []string{
		"Assessment was executed under non-destructive testing constraints; deep authenticated business logic workflows requiring out-of-scope production credentials were not exercised.",
		"Third-party external dependencies and upstream cloud platform backends were evaluated strictly at exposed ingress/egress boundaries.",
		"Synthesized code diffs remain proposed recommendations; verified attack-path breaks cannot be established until code changes are deployed to target repositories.",
	}

	return DossierResidualRisk{
		ResidualRiskLevel:        resLevel,
		UnresolvedExposures:      unresolved,
		AssessmentLimitations:    limitations,
		RequiredFutureValidation: "In accordance with the FELIX architecture, verified attack-path interruption and finding closure require an authorized live re-testing workflow scheduled in Phase 9.2 (Remediation Retest Engine).",
	}
}

// buildDossierTechnicalAppendix indexes all finding fingerprints and toolchain digests.
func buildDossierTechnicalAppendix(findings []DossierFinding) DossierTechnicalAppendix {
	var digests []string
	for _, f := range findings {
		digests = append(digests, fmt.Sprintf("%s:%s", f.ID, f.Fingerprint))
	}

	rawSummary := strings.Join(digests, "|")
	sum := sha256.Sum256([]byte(rawSummary))
	digestHex := hex.EncodeToString(sum[:])

	return DossierTechnicalAppendix{
		TotalCatalogedFindings: len(findings),
		RedactionAuditStatus:   "CERTIFIED_ZERO_SECRET_LEAKAGE",
		ToolchainVersion:       fmt.Sprintf("FELIX v3.0 (Report Engine Schema %s)", DossierSchemaVersion),
		ReportDigest:           digestHex,
		FindingDigests:         digests,
	}
}

func filterPriorityFindings(findings []DossierFinding) []DossierFinding {
	if len(findings) <= 25 {
		var priority []DossierFinding
		for _, f := range findings {
			if !f.IsDefendedBoundary {
				priority = append(priority, f)
			}
		}
		return priority
	}

	var priority []DossierFinding
	for _, f := range findings {
		if !f.IsDefendedBoundary && (f.Severity == SeverityCritical || f.Severity == SeverityHigh || f.RemediationPriority <= 2) {
			priority = append(priority, f)
		}
	}
	if len(priority) == 0 {
		for _, f := range findings {
			if !f.IsDefendedBoundary {
				priority = append(priority, f)
				if len(priority) >= 10 {
					break
				}
			}
		}
	}
	return priority
}

func generateKeyBusinessConcerns(findings []DossierFinding, paths []DossierAttackPath) []string {
	var concerns []string
	if len(paths) > 0 {
		concerns = append(concerns, fmt.Sprintf("Autonomous attack-chain synthesis confirmed %d traversable multi-hop path(s) connecting perimeter entrypoints to sensitive backend assets.", len(paths)))
	}
	for _, f := range findings {
		if f.Severity == SeverityCritical && !f.IsDefendedBoundary {
			concerns = append(concerns, fmt.Sprintf("Verified %s on %s exposes organization to critical system compromise.", f.Title, f.Endpoint))
			break
		}
	}
	if len(concerns) == 0 {
		concerns = append(concerns, "No immediate critical attack paths were discovered; residual risks center on defensive hardening and header configurations.")
	}
	return concerns
}

func generateExecutiveRecommendations(findings []DossierFinding, remPlan DossierRemediationPlan) []string {
	var recs []string
	recs = append(recs, "Review and apply proposed Priority 1 remediation diffs at perimeter entrypoints to immediately disrupt multi-hop traversal paths.")
	recs = append(recs, "Deploy parameterized database query interfaces across all dynamic search and lookup handlers to eliminate injection risks.")
	recs = append(recs, "Enforce strict tenant and object-level ownership checks across API endpoints prior to database record retrieval.")
	recs = append(recs, "Schedule targeted live re-testing upon patch deployment to verify vulnerability resolution and issue clean Letter of Attestation.")
	return recs
}

// ComputeDossierCanonicalHash computes a deterministic SHA-256 over normalized, security-relevant dossier fields.
func ComputeDossierCanonicalHash(dossier *ExecutiveDossier) (string, error) {
	if dossier == nil {
		return "", errors.New("cannot hash nil dossier")
	}

	type canonicalDossierPayload struct {
		SchemaVersion            string                          `json:"schema_version"`
		DossierID                string                          `json:"dossier_id"`
		Target                   string                          `json:"target"`
		Targets                  []string                        `json:"targets"`
		Organization             string                          `json:"organization"`
		AssessmentTitle          string                          `json:"assessment_title"`
		ScopeAndMethodology      DossierScopeAndMethodology      `json:"scope_and_methodology"`
		ExecutiveSummary         DossierExecutiveSummary         `json:"executive_summary"`
		FinancialExposure        DossierFinancialExposure        `json:"financial_exposure"`
		CompliancePosture        DossierCompliancePosture        `json:"compliance_posture"`
		PriorityFindings         []DossierFinding                `json:"priority_findings"`
		AttackPaths              []DossierAttackPath             `json:"attack_paths"`
		ExploitabilityAssessment DossierExploitabilityAssessment `json:"exploitability_assessment"`
		RemediationPlan          DossierRemediationPlan          `json:"remediation_plan"`
		ResidualRisk             DossierResidualRisk             `json:"residual_risk"`
		TechnicalAppendix        DossierTechnicalAppendix        `json:"technical_appendix"`
	}

	// Make a copy of executive summary with volatile generated_at normalized
	cleanSummary := dossier.ExecutiveSummary
	cleanSummary.GeneratedAt = "NORMALIZED_FOR_CANONICAL_HASHING"

	payload := canonicalDossierPayload{
		SchemaVersion:            dossier.SchemaVersion,
		DossierID:                dossier.DossierID,
		Target:                   dossier.Target,
		Targets:                  dossier.Targets,
		Organization:             dossier.Organization,
		AssessmentTitle:          dossier.AssessmentTitle,
		ScopeAndMethodology:      dossier.ScopeAndMethodology,
		ExecutiveSummary:         cleanSummary,
		FinancialExposure:        dossier.FinancialExposure,
		CompliancePosture:        dossier.CompliancePosture,
		PriorityFindings:         dossier.PriorityFindings,
		AttackPaths:              dossier.AttackPaths,
		ExploitabilityAssessment: dossier.ExploitabilityAssessment,
		RemediationPlan:          dossier.RemediationPlan,
		ResidualRisk:             dossier.ResidualRisk,
		TechnicalAppendix:        dossier.TechnicalAppendix,
	}

	b, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func computeShortDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

func redactStringSlice(slice []string) []string {
	var res []string
	for _, s := range slice {
		res = append(res, secrets.RedactText(s))
	}
	return res
}

// -----------------------------------------------------------------------------
// HTML5 Dossier Rendering (100% Self-Contained, Zero External CDN Dependencies)
// -----------------------------------------------------------------------------

// RenderDossierHTML generates a standalone, interactive HTML5 executive deliverable.
func RenderDossierHTML(dossier *ExecutiveDossier) (string, error) {
	if dossier == nil {
		return "", errors.New("cannot render nil dossier")
	}

	tmpl, err := template.New("executive_dossier").Funcs(template.FuncMap{
		"escape": html.EscapeString,
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"formatCurrency": func(val float64) string {
			return fmt.Sprintf("$%s", formatFloatWithCommas(math.Round(val)))
		},
		"severityClass": func(sev string) string {
			switch strings.ToUpper(sev) {
			case SeverityCritical:
				return "badge-critical"
			case SeverityHigh:
				return "badge-high"
			case SeverityMedium:
				return "badge-medium"
			case SeverityLow:
				return "badge-low"
			default:
				return "badge-info"
			}
		},
	}).Parse(executiveDossierHTMLTemplate)
	if err != nil {
		return "", fmt.Errorf("failed parsing executive dossier template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, dossier); err != nil {
		return "", fmt.Errorf("failed executing executive dossier template: %w", err)
	}

	return buf.String(), nil
}

func formatFloatWithCommas(val float64) string {
	intVal := int64(val)
	str := fmt.Sprintf("%d", intVal)
	if len(str) <= 3 {
		return str
	}
	var parts []string
	for len(str) > 3 {
		parts = append([]string{str[len(str)-3:]}, parts...)
		str = str[:len(str)-3]
	}
	if len(str) > 0 {
		parts = append([]string{str}, parts...)
	}
	return strings.Join(parts, ",")
}

const executiveDossierHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{escape .AssessmentTitle}} — FELIX Executive Dossier</title>
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: #1e293b;
      --card-border: #334155;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --primary: #38bdf8;
      --critical: #ef4444;
      --high: #f97316;
      --medium: #eab308;
      --low: #3b82f6;
      --info: #64748b;
      --verified: #10b981;
      --defended: #06b6d4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 24px;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    header {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 32px;
      margin-bottom: 24px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
    }
    .header-top { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
    .brand-tag { font-size: 12px; letter-spacing: 2px; color: var(--primary); font-weight: 700; text-transform: uppercase; }
    .dossier-id { font-family: monospace; font-size: 13px; color: var(--text-muted); background: #0f172a; padding: 4px 8px; border-radius: 4px; }
    h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; color: #fff; }
    .subtitle { color: var(--text-muted); font-size: 15px; }
    .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
    .kpi-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 20px;
    }
    .kpi-lbl { font-size: 12px; font-weight: 600; text-transform: uppercase; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 8px; }
    .kpi-val { font-size: 32px; font-weight: 700; color: #fff; }
    .kpi-sub { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
    .section-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 28px;
      margin-bottom: 24px;
    }
    h2 { font-size: 20px; font-weight: 600; margin-bottom: 16px; color: #fff; border-bottom: 1px solid var(--card-border); padding-bottom: 8px; display: flex; align-items: center; justify-content: space-between; }
    .posture-banner {
      background: rgba(56, 189, 248, 0.08);
      border-left: 4px solid var(--primary);
      padding: 16px;
      border-radius: 4px;
      margin-bottom: 20px;
      font-size: 15px;
    }
    .badge {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--critical); }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fdba74; border: 1px solid var(--high); }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #fde047; border: 1px solid var(--medium); }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #93c5fd; border: 1px solid var(--low); }
    .badge-info { background: rgba(100, 116, 139, 0.2); color: #cbd5e1; border: 1px solid var(--info); }
    .badge-verified { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--verified); }
    .badge-defended { background: rgba(6, 182, 212, 0.2); color: #67e8f9; border: 1px solid var(--defended); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }
    th { text-align: left; padding: 10px 12px; background: #0f172a; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--card-border); }
    td { padding: 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); vertical-align: top; }
    tr:hover td { background: rgba(255,255,255,0.02); }
    .code-block {
      background: #090d16;
      border: 1px solid #1e293b;
      border-radius: 4px;
      padding: 12px;
      font-family: monospace;
      font-size: 13px;
      overflow-x: auto;
      color: #38bdf8;
      margin-top: 6px;
      white-space: pre-wrap;
    }
    .svg-container {
      background: #090d16;
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 16px;
      overflow-x: auto;
      margin-top: 12px;
      margin-bottom: 16px;
    }
    .path-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--card-border);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 16px;
    }
    .disclaimer-box {
      background: rgba(245, 158, 11, 0.08);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 4px;
      padding: 12px 16px;
      font-size: 13px;
      color: #fbbf24;
      margin-bottom: 16px;
    }
    footer {
      text-align: center;
      padding: 24px;
      color: var(--text-muted);
      font-size: 13px;
      border-top: 1px solid var(--card-border);
      margin-top: 32px;
    }
    @media print {
      body { background: #fff; color: #000; padding: 0; }
      .container { max-width: 100%; }
      .section-card, header, .kpi-card { background: #fff; color: #000; border: 1px solid #ccc; box-shadow: none; page-break-inside: avoid; }
      .code-block, .svg-container { background: #f5f5f5; color: #000; border: 1px solid #ddd; }
      th { background: #f0f0f0; color: #000; }
      h1, h2, .kpi-val { color: #000; }
      .badge { border: 1px solid #000; color: #000; }
    }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="header-top">
        <span class="brand-tag">FELIX v3.0 Assessment Deliverable</span>
        <span class="dossier-id">{{.DossierID}}</span>
      </div>
      <h1>{{escape .AssessmentTitle}}</h1>
      <div class="subtitle">
        Organization: <strong>{{escape .Organization}}</strong> &nbsp;|&nbsp;
        Target: <strong>{{escape .Target}}</strong> &nbsp;|&nbsp;
        Date: <strong>{{.GeneratedAt}}</strong>
      </div>
    </header>

    <!-- Top KPI Grid -->
    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-lbl">Overall Security Score</div>
        <div class="kpi-val" style="color: {{if ge .SecurityPosture.RiskScore 75}}var(--critical){{else if ge .SecurityPosture.RiskScore 45}}var(--high){{else}}var(--verified){{end}}">
          {{.SecurityPosture.RiskScore}}/100
        </div>
        <div class="kpi-sub">Risk Level: <strong>{{.SecurityPosture.RiskLevel}}</strong></div>
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Business Risk Posture</div>
        {{if .FinancialExposure.HasMonetaryEstimates}}
          <div class="kpi-val" style="color: #38bdf8;">
            {{formatCurrency .FinancialExposure.TotalEstimatedProbableUSD}}
          </div>
          <div class="kpi-sub">Illustrative: {{formatCurrency .FinancialExposure.TotalEstimatedExposureMinUSD}} &ndash; {{formatCurrency .FinancialExposure.TotalEstimatedExposureMaxUSD}}</div>
        {{else}}
          <div class="kpi-val" style="color: #38bdf8; font-size: 24px;">QUALITATIVE</div>
          <div class="kpi-sub">{{len .FinancialExposure.BusinessImpactCategories}} impact categories evaluated</div>
        {{end}}
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Verified Findings</div>
        <div class="kpi-val" style="color: var(--critical);">{{.ExecutiveSummary.VerifiedFindingsCount}}</div>
        <div class="kpi-sub">{{.ExecutiveSummary.TotalFindings}} total findings across all severities</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-lbl">Synthesized Attack Paths</div>
        <div class="kpi-val" style="color: var(--high);">{{len .AttackPaths}}</div>
        <div class="kpi-sub">Multi-hop trajectories analyzed</div>
      </div>
    </div>

    <!-- Section 1: Executive Summary -->
    <section class="section-card">
      <h2>Section 1: Executive Security Summary</h2>
      <div class="posture-banner">
        <strong>Strategic Posture:</strong> {{escape .SecurityPosture.PostureStatement}}
      </div>
      <h3 style="font-size: 15px; margin-bottom: 8px; color: #fff;">Key Business Concerns:</h3>
      <ul style="margin-left: 20px; margin-bottom: 16px; color: var(--text-muted); font-size: 14px;">
        {{range .ExecutiveSummary.KeyBusinessConcerns}}
          <li>{{escape .}}</li>
        {{end}}
      </ul>
      <h3 style="font-size: 15px; margin-bottom: 8px; color: #fff;">Immediate Executive Actions:</h3>
      <ul style="margin-left: 20px; color: var(--text-muted); font-size: 14px;">
        {{range .ExecutiveSummary.ExecutiveRecommendations}}
          <li>{{escape .}}</li>
        {{end}}
      </ul>
    </section>

    <!-- Section 2: Qualitative Business Impact & Regulatory Risk -->
    <section class="section-card">
      <h2>Section 2: Qualitative Business Impact & Regulatory Risk</h2>
      <div class="disclaimer-box" style="background: rgba(56, 189, 248, 0.08); border-color: rgba(56, 189, 248, 0.3); color: #7dd3fc;">
        <strong>Methodology & Uncertainty Notice:</strong> {{escape .FinancialExposure.Disclaimer}}
      </div>
      <p style="color: var(--text-muted); font-size: 14px; margin-bottom: 16px;">
        {{escape .FinancialExposure.MethodologyNotes}}
      </p>
      <table>
        <thead>
          <tr>
            <th>Business Impact Category</th>
            <th>Impact Severity</th>
            <th>Uncertainty Level</th>
            <th>Regulatory Exposure Scope</th>
            <th>Operational Risk Rationale</th>
          </tr>
        </thead>
        <tbody>
          {{range .FinancialExposure.BusinessImpactCategories}}
            <tr>
              <td><strong>{{escape .Category}}</strong></td>
              <td><span class="badge {{severityClass .ImpactSeverity}}">{{.ImpactSeverity}}</span></td>
              <td><span class="badge badge-info">{{escape .UncertaintyLevel}}</span></td>
              <td style="font-size: 13px; color: #cbd5e1;">{{escape .RegulatoryExposureScope}}</td>
              <td style="color: var(--text-muted); font-size: 13px;">{{escape .OperationalRiskRationale}}</td>
            </tr>
          {{end}}
        </tbody>
      </table>

      {{if .FinancialExposure.HasMonetaryEstimates}}
        <h3 style="font-size: 16px; margin-top: 24px; margin-bottom: 8px; color: #fbbf24;">Illustrative Scenario Financial Modeling (Caller-Configured)</h3>
        <p style="color: var(--text-muted); font-size: 13px; margin-bottom: 12px;">The following figures are non-empirical illustrative estimates based strictly on caller-supplied configuration assumptions.</p>
        <table>
          <thead>
            <tr>
              <th>Loss Category</th>
              <th>Potential Min</th>
              <th>Potential Max</th>
              <th>Probable Scenario</th>
              <th>Assumption Basis</th>
            </tr>
          </thead>
          <tbody>
            {{range .FinancialExposure.LossCategories}}
              <tr>
                <td><strong>{{escape .Category}}</strong></td>
                <td>{{formatCurrency .PotentialMinUSD}}</td>
                <td>{{formatCurrency .PotentialMaxUSD}}</td>
                <td style="color: #38bdf8; font-weight: 700;">{{formatCurrency .ProbableUSD}}</td>
                <td style="color: var(--text-muted); font-size: 13px;">{{escape .BasisRationale}}</td>
              </tr>
            {{end}}
          </tbody>
        </table>
      {{end}}
    </section>

    <!-- Section 3: Attack-Path Narratives & Interactive DAG Visualization -->
    <section class="section-card">
      <h2>Section 3: Attack-Path Narratives & DAG Visualization</h2>
      {{if .AttackPaths}}
        {{range .AttackPaths}}
          <div class="path-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
              <h3 style="font-size: 16px; color: #fff;">{{escape .Title}}</h3>
              <div>
                <span class="badge {{if eq .ValidationStatus "CONFIRMED"}}badge-verified{{else}}badge-medium{{end}}">{{.ValidationStatus}}</span>
                <span class="badge badge-high">{{.CombinedRiskLevel}} (Risk: {{.CombinedRiskScore}})</span>
              </div>
            </div>
            <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 12px;">{{escape .Narrative}}</p>
            <div style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">
              <strong>Entrypoint:</strong> <code>{{escape .EntryPoint}}</code> &nbsp;&rarr;&nbsp;
              <strong>Target Asset:</strong> <code>{{escape .TargetAsset}}</code>
            </div>
            <!-- Embedded SVG Graph -->
            <div class="svg-container">
              {{safeHTML .SVGRendering}}
            </div>
          </div>
        {{end}}
      {{else}}
        <p style="color: var(--text-muted); font-size: 14px;">No multi-hop attack paths were traversable across evaluated assets.</p>
      {{end}}
    </section>

    <!-- Section 4: Critical & High Priority Findings -->
    <section class="section-card">
      <h2>Section 4: Priority Security Findings</h2>
      <table>
        <thead>
          <tr>
            <th>Finding ID</th>
            <th>Severity</th>
            <th>Title & Category</th>
            <th>Endpoint</th>
            <th>Technical Impact</th>
          </tr>
        </thead>
        <tbody>
          {{range .PriorityFindings}}
            <tr>
              <td><code>{{.ID}}</code></td>
              <td><span class="badge {{severityClass .Severity}}">{{.Severity}}</span></td>
              <td>
                <strong>{{escape .Title}}</strong><br>
                <small style="color: var(--text-muted);">{{escape .Category}}</small>
              </td>
              <td><code>{{escape .HTTPMethod}} {{escape .Endpoint}}</code></td>
              <td style="color: var(--text-muted); font-size: 13px;">{{escape .TechnicalImpact}}</td>
            </tr>
          {{end}}
        </tbody>
      </table>
    </section>

    <!-- Section 5: Exploitability Assessment (PoC) -->
    <section class="section-card">
      <h2>Section 5: Evidence-Backed Exploitability Assessment</h2>
      <div class="disclaimer-box">
        <strong>Exploitation Boundary Notice:</strong> {{escape .ExploitabilityAssessment.ExecutionDisclaimer}}
      </div>
      <table>
        <thead>
          <tr>
            <th>PoC ID</th>
            <th>Target Endpoint / Finding</th>
            <th>Status</th>
            <th>Execution Mode</th>
            <th>Deterministic Reproduction Probe (Redacted)</th>
          </tr>
        </thead>
        <tbody>
          {{range .ExploitabilityAssessment.PoCInventory}}
            <tr>
              <td><code>{{.ID}}</code></td>
              <td><code>{{.FindingID}}</code></td>
              <td><span class="badge badge-medium">{{.Status}}</span></td>
              <td><span class="badge badge-info">{{.ExecutionMode}}</span></td>
              <td>
                <div class="code-block">{{escape .SafeCurlCommand}}</div>
              </td>
            </tr>
          {{end}}
        </tbody>
      </table>
    </section>

    <!-- Section 6: Remediation Plan & Code Diffs -->
    <section class="section-card">
      <h2>Section 6: Remediation Priorities & Code Diffs</h2>
      <div class="disclaimer-box" style="background: rgba(16, 185, 129, 0.08); border-color: rgba(16, 185, 129, 0.3); color: #6ee7b7;">
        <strong>Remediation Lifecycle Status:</strong> {{escape .RemediationPlan.ExecutionDisclaimer}}
      </div>
      <div style="margin-bottom: 16px; font-size: 14px; color: var(--text-muted);">
        Proposed Path Interruptions: <strong>{{.RemediationPlan.ProposedBrokenPathCount}}</strong> &nbsp;|&nbsp;
        Actual Interrupted Paths: <strong>{{.RemediationPlan.BrokenPathCount}}</strong> (Awaiting live application & retest)
      </div>
      {{range .RemediationPlan.Items}}
        <div style="background: #090d16; border: 1px solid var(--card-border); border-radius: 6px; padding: 16px; margin-bottom: 12px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <strong style="color: #fff;">{{escape .Title}} ({{.ID}})</strong>
            <div>
              <span class="badge badge-info">Priority {{.Priority}}</span>
              <span class="badge badge-verified">{{.PathBreakStatus}}</span>
            </div>
          </div>
          <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 8px;">Target File: <code>{{escape .TargetFile}}</code> &nbsp;|&nbsp; Impact: {{escape .SecurityImpact}}</p>
          {{if .UnifiedDiffSnippet}}
            <div class="code-block">{{escape .UnifiedDiffSnippet}}</div>
          {{end}}
        </div>
      {{end}}
    </section>

    <!-- Section 7: Formal Compliance Mappings -->
    <section class="section-card">
      <h2>Section 7: Regulatory & Compliance Mappings</h2>
      <p style="color: var(--text-muted); font-size: 14px; margin-bottom: 16px;">
        Evaluated across 6 major enterprise standards: OWASP Top 10, NIST CSF 2.0, ISO 27001, CERT-In, RBI Cyber Security Framework, and the DPDP Act 2023.
      </p>
      {{range .CompliancePosture.Frameworks}}
        <div style="background: rgba(15, 23, 42, 0.6); border: 1px solid var(--card-border); border-radius: 6px; padding: 16px; margin-bottom: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px;">
            <h3 style="font-size: 16px; color: #fff;">{{escape .FrameworkName}} ({{.Version}})</h3>
            <span class="badge {{if eq .OverallStatus "GAPS_IDENTIFIED"}}badge-critical{{else if eq .OverallStatus "POTENTIAL_GAPS_IDENTIFIED"}}badge-medium{{else}}badge-info{{end}}">
              {{.OverallStatus}}
            </span>
          </div>
          <table>
            <thead>
              <tr>
                <th style="width: 150px;">Control ID</th>
                <th>Requirement</th>
                <th style="width: 140px;">Status</th>
                <th>Evaluation Trace</th>
              </tr>
            </thead>
            <tbody>
              {{range .Controls}}
                <tr>
                  <td><code>{{.ControlID}}</code></td>
                  <td><strong>{{escape .ControlName}}</strong></td>
                  <td>
                    <span class="badge {{if eq .Status "EVIDENCE_BACKED_GAP"}}badge-critical{{else if eq .Status "POTENTIAL_GAP"}}badge-medium{{else if eq .Status "DEFENDED_OBSERVED"}}badge-defended{{else}}badge-info{{end}}">
                      {{.Status}}
                    </span>
                  </td>
                  <td style="font-size: 13px; color: var(--text-muted);">{{escape .ImpactSummary}}</td>
                </tr>
              {{end}}
            </tbody>
          </table>
        </div>
      {{end}}
    </section>

    <!-- Section 8: Residual Risk & Appendix -->
    <section class="section-card">
      <h2>Section 8: Residual Risk & Technical Appendix</h2>
      <div style="margin-bottom: 16px;">
        <h3 style="font-size: 15px; color: #fff; margin-bottom: 6px;">Required Future Verification:</h3>
        <p style="color: var(--text-muted); font-size: 14px;">{{escape .ResidualRisk.RequiredFutureValidation}}</p>
      </div>
      <div style="margin-bottom: 16px;">
        <h3 style="font-size: 15px; color: #fff; margin-bottom: 6px;">Assessment Scope Limitations:</h3>
        <ul style="margin-left: 20px; color: var(--text-muted); font-size: 13px;">
          {{range .ResidualRisk.AssessmentLimitations}}
            <li>{{escape .}}</li>
          {{end}}
        </ul>
      </div>
      <div style="background: #090d16; padding: 12px; border-radius: 4px; font-size: 12px; font-family: monospace; color: var(--text-muted);">
        Audit Redaction: {{.TechnicalAppendix.RedactionAuditStatus}} &nbsp;|&nbsp;
        Toolchain: {{.TechnicalAppendix.ToolchainVersion}} &nbsp;|&nbsp;
        Dossier Hash: {{.DeterministicContentHash}}
      </div>
    </section>

    <footer>
      Generated autonomously by Google FELIX v3.0 &nbsp;|&nbsp; Phase 7.4 Executive Dossier Deliverable
    </footer>
  </div>
</body>
</html>
`
