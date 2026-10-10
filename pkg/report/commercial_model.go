package report

// CommercialReportSchemaVersion identifies the specification version of the Commercial Report 2.0.
const CommercialReportSchemaVersion = "2.0.0"

// CommercialReport is the top-level structured presentation model for Felix Stage 12.
// It enforces strict separation between assessment data, aggregation/classification,
// presentation, and export across the eight canonical report sections.
type CommercialReport struct {
	SchemaVersion     string                      `json:"schema_version"`
	ReportID          string                      `json:"report_id"`
	GeneratedAt       string                      `json:"generated_at"`
	ExecutiveSummary  CommercialExecutiveSummary  `json:"executive_summary"`
	AssessmentScope   CommercialAssessmentScope   `json:"assessment_scope"`
	AttackSurface     CommercialAttackSurface     `json:"attack_surface"`
	RiskOverview      CommercialRiskOverview      `json:"risk_overview"`
	VerifiedFindings  []CommercialFinding         `json:"verified_findings"`
	DetectedFindings  []CommercialFinding         `json:"detected_findings"`
	Observations      []CommercialObservation     `json:"observations"`
	TechnicalAppendix CommercialTechnicalAppendix `json:"technical_appendix"`
}

// -----------------------------------------------------------------------------
// Section 1: Executive Summary
// -----------------------------------------------------------------------------

// CommercialExecutiveSummary provides high-level assessment outcomes for security
// leadership and business stakeholders without marketing or unsupported claims.
type CommercialExecutiveSummary struct {
	AssessmentID            string         `json:"assessment_id"`
	Target                  string         `json:"target"`
	Targets                 []string       `json:"targets"`
	Timestamp               string         `json:"timestamp"`
	ScopeSummary            string         `json:"scope_summary"`
	CompletionStatus        string         `json:"completion_status"` // COMPLETED, COMPLETED_WITH_ERRORS, PARTIAL, EMPTY
	AssetsDiscoveredCount   int            `json:"assets_discovered_count"`
	FindingsDetectedCount   int            `json:"findings_detected_count"`
	FindingsVerifiedCount   int            `json:"findings_verified_count"`
	FindingsUnverifiedCount int            `json:"findings_unverified_count"`
	ObservationsCount       int            `json:"observations_count"`
	InconclusiveChecksCount int            `json:"inconclusive_checks_count"`
	NotAssessedChecksCount  int            `json:"not_assessed_checks_count"`
	SeverityDistribution    map[string]int `json:"severity_distribution"`
	RiskScore               int            `json:"risk_score"` // 0-100
	RiskLevel               string         `json:"risk_level"` // CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
	AttackSurfaceHighlights []string       `json:"attack_surface_highlights"`
	KeyConcerns             []string       `json:"key_concerns"`
	AssessmentLimitations   []string       `json:"assessment_limitations"`
	PostureStatement        string         `json:"posture_statement"`
}

// -----------------------------------------------------------------------------
// Section 2: Assessment Scope
// -----------------------------------------------------------------------------

// CommercialAssessmentScope documents what Felix evaluated, separating discovered from tested assets.
type CommercialAssessmentScope struct {
	InScopeDomains           []string `json:"in_scope_domains"`
	InScopeURLs              []string `json:"in_scope_urls"`
	DiscoveredEndpointsCount int      `json:"discovered_endpoints_count"`
	AssessedEndpointsCount   int      `json:"assessed_endpoints_count"`
	APIServices              []string `json:"api_services"`
	CloudResources           []string `json:"cloud_resources"`
	AuthenticationContexts   []string `json:"authentication_contexts"`
	StartedAt                string   `json:"started_at"`
	CompletedAt              string   `json:"completed_at"`
	Duration                 string   `json:"duration"`
	EnginesExecuted          []string `json:"engines_executed"`
	EnginesSkipped           []string `json:"engines_skipped"`
	CompletedChecksCount     int      `json:"completed_checks_count"`
	IncompleteChecksCount    int      `json:"incomplete_checks_count"`
	InconclusiveChecksCount  int      `json:"inconclusive_checks_count"`
	ExplicitRestrictions     []string `json:"explicit_restrictions"`
	ExcludedTargets          []string `json:"excluded_targets"`
	Provenance               string   `json:"provenance"` // LIVE, STATIC, SYNTHETIC, HYBRID
	SyntheticFixture         bool     `json:"synthetic_fixture"`
	ExecutionErrors          []string `json:"execution_errors,omitempty"`
}

// -----------------------------------------------------------------------------
// Section 3: Attack Surface
// -----------------------------------------------------------------------------

// CommercialAttackSurface organizes discovered assets without equating reachability to vulnerability.
type CommercialAttackSurface struct {
	TotalAssets  int                            `json:"total_assets"`
	AssetsByType map[string]int                 `json:"assets_by_type"`
	Assets       []CommercialAttackSurfaceAsset `json:"assets"`
}

// CommercialAttackSurfaceAsset represents an individual discovered surface item.
type CommercialAttackSurfaceAsset struct {
	AssetID               string   `json:"asset_id"`
	URL                   string   `json:"url"`
	AssetType             string   `json:"asset_type"` // DOMAIN, SUBDOMAIN, WEB_ROUTE, API_ENDPOINT, AUTH_ENTRYPOINT, CLOUD_RESOURCE, CLIENT_ASSET
	DiscoverySource       string   `json:"discovery_source"`
	AssessmentState       string   `json:"assessment_state"` // ASSESSED, DISCOVERED_ONLY, NOT_ASSESSED, OUT_OF_SCOPE
	AuthenticationContext string   `json:"authentication_context"`
	AssociatedFindingIDs  []string `json:"associated_finding_ids,omitempty"`
	ExposureInfo          string   `json:"exposure_info"`
	HTTPStatus            int      `json:"http_status,omitempty"`
}

// -----------------------------------------------------------------------------
// Section 4: Risk Overview
// -----------------------------------------------------------------------------

// CommercialRiskOverview details the deterministic risk calculation and correlation models.
type CommercialRiskOverview struct {
	RiskScore                int                           `json:"risk_score"`
	RiskLevel                string                        `json:"risk_level"`
	ScoringModelDescription  string                        `json:"scoring_model_description"`
	SeverityDistribution     map[string]int                `json:"severity_distribution"`
	VerifiedCountsBySeverity map[string]int                `json:"verified_counts_by_severity"`
	DetectedCountsBySeverity map[string]int                `json:"detected_counts_by_severity"`
	FindingRiskContributions []CommercialRiskContribution  `json:"finding_risk_contributions"`
	SecurityStories          []SecurityStory               `json:"security_stories,omitempty"`
	AttackPaths              []AttackPathSummary           `json:"attack_paths,omitempty"`
	RiskConcentrations       []CommercialRiskConcentration `json:"risk_concentrations"`
	RiskLimitations          []string                      `json:"risk_limitations"`
}

// CommercialRiskConcentration summarizes risk accumulated in a specific component or endpoint.
type CommercialRiskConcentration struct {
	Component string `json:"component"`
	RiskLevel string `json:"risk_level"`
	Score     int    `json:"score"`
	Count     int    `json:"count"`
}

// -----------------------------------------------------------------------------
// Sections 5 & 6: Finding Detail (Verified & Detected)
// -----------------------------------------------------------------------------

// CommercialFinding exposes the ten required fields (A-J) for a security finding.
// Remediations and fix recommendations are strictly excluded from Commercial Report 2.0.
type CommercialFinding struct {
	ID                  string                       `json:"id"`
	Title               string                       `json:"title"`
	// A. Description
	Description         string                       `json:"description"`
	// B. Affected Asset
	AffectedAsset       string                       `json:"affected_asset"`
	AssetLocation       string                       `json:"asset_location,omitempty"`
	// C. Severity
	Severity            string                       `json:"severity"`
	// D. Confidence
	Confidence          CommercialConfidenceDetail   `json:"confidence"`
	// E. Authentication State
	AuthenticationState string                       `json:"authentication_state"`
	// F. Detection Method
	DetectionMethod     string                       `json:"detection_method"`
	// G. Verification
	Verification        CommercialVerificationDetail `json:"verification"`
	// H. Evidence
	Evidence            CommercialEvidenceDetail     `json:"evidence"`
	// I. Security Impact (Excludes remediation advice)
	SecurityImpact      CommercialSecurityImpact     `json:"security_impact"`
	// J. Risk Contribution
	RiskContribution    CommercialRiskContribution   `json:"risk_contribution"`
	// Metadata
	Category            string                       `json:"category"`
	Source              string                       `json:"source"`
	SyntheticFixture    bool                         `json:"synthetic_fixture,omitempty"`
}

// CommercialConfidenceDetail distinctly preserves detection and verification confidence.
type CommercialConfidenceDetail struct {
	DetectionConfidence    string `json:"detection_confidence"`
	VerificationConfidence string `json:"verification_confidence"`
	OverallConfidence      string `json:"overall_confidence"`
	ConfidenceScore        int    `json:"confidence_score,omitempty"`
	Rationale              string `json:"rationale,omitempty"`
}

// CommercialVerificationDetail captures empirical verification parameters.
type CommercialVerificationDetail struct {
	Status                VerificationStatus `json:"status"` // VERIFIED, DETECTED, NOT_VERIFIED, INCONCLUSIVE, NOT_ASSESSED
	MethodOrPolicy        string             `json:"method_or_policy"`
	CriteriaSatisfied     []string           `json:"criteria_satisfied,omitempty"`
	CriteriaNotSatisfied  []string           `json:"criteria_not_satisfied,omitempty"`
	Preconditions         []string           `json:"preconditions,omitempty"`
	InconclusiveOrBlocked string             `json:"inconclusive_or_blocked,omitempty"`
	Limitations           []string           `json:"limitations,omitempty"`
	ResultSummary         string             `json:"result_summary"`
}

// CommercialEvidenceDetail contains sanitized evidence excerpts, reproduction steps, and provenance.
type CommercialEvidenceDetail struct {
	Observation        string              `json:"observation"`
	Location           string              `json:"location"`
	HTTPMethod         string              `json:"http_method,omitempty"`
	HTTPStatus         int                 `json:"http_status,omitempty"`
	Headers            map[string]string   `json:"headers,omitempty"`
	SanitizedExcerpt   string              `json:"sanitized_excerpt,omitempty"`
	EvidenceSummary    string              `json:"evidence_summary,omitempty"`
	NegativeEvidence   string              `json:"negative_evidence,omitempty"`
	EvidenceReferences []string            `json:"evidence_references,omitempty"`
	ReproductionSteps  []string            `json:"reproduction_steps,omitempty"`
	SafeCurlCommand    string              `json:"safe_curl_command,omitempty"`
	Provenance         string              `json:"provenance"` // LIVE, STATIC, FIXTURE, MOCK, IMPORTED
	Timestamp          string              `json:"timestamp,omitempty"`
	IsAvailable        bool                `json:"is_available"`
}

// CommercialSecurityImpact categorizes potential and demonstrated consequences without prescribing fixes.
type CommercialSecurityImpact struct {
	DemonstratedImpact string `json:"demonstrated_impact"`
	PlausibleImpact    string `json:"plausible_impact"`
	UnverifiedImpact   string `json:"unverified_impact"`
	Summary            string `json:"summary"`
}

// CommercialRiskContribution captures the finding's score contribution under the Felix risk model.
type CommercialRiskContribution struct {
	FindingID          string   `json:"finding_id"`
	Title              string   `json:"title,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	VerificationStatus string   `json:"verification_status,omitempty"`
	Score              int      `json:"score"` // 0-40 individual score
	Model              string   `json:"model"` // "felix_deterministic_v1"
	RiskType           string   `json:"risk_type"` // "INDIVIDUAL", "CORRELATED", "ATTACK_PATH", "HARDENING_DEFENSE_IN_DEPTH"
	CorrelatedStoryIDs []string `json:"correlated_story_ids,omitempty"`
	AttackPathIDs      []string `json:"attack_path_ids,omitempty"`
	Rationale          string   `json:"rationale"`
	IsAvailable        bool     `json:"is_available"`
}

// -----------------------------------------------------------------------------
// Section 7: Observations
// -----------------------------------------------------------------------------

// CommercialObservation presents non-vulnerability observations, configuration facts, or limitations.
type CommercialObservation struct {
	ObservationID     string   `json:"observation_id"`
	Title             string   `json:"title"`
	Description       string   `json:"description"`
	AffectedAsset     string   `json:"affected_asset"`
	ObservationSource string   `json:"observation_source"`
	Evidence          string   `json:"evidence"`
	AssessmentContext string   `json:"assessment_context"`
	Limitations       []string `json:"limitations,omitempty"`
	ObservationType   string   `json:"observation_type"` // INFORMATIONAL_SIGNAL, ATTACK_SURFACE_CHARACTERISTIC, DEFENSIVE_CONFIGURATION, COVERAGE_CONSTRAINT
	Category          string   `json:"category,omitempty"`
	SyntheticFixture  bool     `json:"synthetic_fixture,omitempty"`
}

// -----------------------------------------------------------------------------
// Section 8: Technical Appendix
// -----------------------------------------------------------------------------

// CommercialTechnicalAppendix provides complete auditable records, metadata, and indexes.
type CommercialTechnicalAppendix struct {
	AssessmentMetadata           map[string]any                `json:"assessment_metadata"`
	EngineExecutionSummary       []CommercialEngineSummary     `json:"engine_execution_summary"`
	DiscoveryAndDetectionStats   map[string]int                `json:"discovery_and_detection_stats"`
	VerificationStatusCounts     map[string]int                `json:"verification_status_counts"`
	NegativeVerificationOutcomes []CommercialNegativeOutcome   `json:"negative_verification_outcomes"`
	FindingIndex                 []CommercialTraceabilityEntry `json:"finding_index"`
	CorrelationRulesEvaluated    []string                      `json:"correlation_rules_evaluated"`
	ErrorsAndCoverageGaps        []string                      `json:"errors_and_coverage_gaps"`
	SyntheticFixtureIndicators   []string                      `json:"synthetic_fixture_indicators"`
	RiskModelMetadata            map[string]any                `json:"risk_model_metadata"`
	ReportGeneratedAt            string                        `json:"report_generated_at"`
	ReportSchemaVersion          string                        `json:"report_schema_version"`
}

// CommercialEngineSummary records engine execution metrics.
type CommercialEngineSummary struct {
	EngineName     string `json:"engine_name"`
	Version        string `json:"version"`
	Status         string `json:"status"` // EXECUTED, SKIPPED, NOT_APPLICABLE
	AssetsAnalyzed int    `json:"assets_analyzed"`
	FindingsCount  int    `json:"findings_count"`
}

// CommercialNegativeOutcome documents affirmative non-exposures (NOT_EXPOSED) without calling them vulnerabilities.
type CommercialNegativeOutcome struct {
	FindingID     string   `json:"finding_id"`
	TargetURL     string   `json:"target_url"`
	Endpoint      string   `json:"endpoint"`
	PolicyID      string   `json:"policy_id"`
	ResultSummary string   `json:"result_summary"`
	Evidence      string   `json:"evidence"`
	Limitations   []string `json:"limitations"`
}

// CommercialTraceabilityEntry indexes a finding for complete provenance audits.
type CommercialTraceabilityEntry struct {
	FindingID           string `json:"finding_id"`
	Title               string `json:"title"`
	SourceEngine        string `json:"source_engine"`
	Category            string `json:"category"`
	DetectionMethod     string `json:"detection_method"`
	PolicyOrRuleID      string `json:"policy_or_rule_id"`
	EvidenceReferences  string `json:"evidence_references"`
	Provenance          string `json:"provenance"`
	AuthenticationState string `json:"authentication_state"`
	CanonicalStatus     string `json:"canonical_status"`
	Severity            string `json:"severity"`
}
