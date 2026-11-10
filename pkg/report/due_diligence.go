package report

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// DueDiligenceSchemaVersion defines the canonical version of the M&A Technical Due-Diligence specification.
const DueDiligenceSchemaVersion = "1.0.0"

// Standard severity and status constants for M&A Due Diligence.
const (
	DDSeverityCritical = "CRITICAL"
	DDSeverityHigh     = "HIGH"
	DDSeverityMedium   = "MEDIUM"
	DDSeverityLow      = "LOW"
	DDSeverityInfo     = "INFO"

	DDStatusVerifiedDefect = "VERIFIED_DEFECT"
	DDStatusPotential      = "POTENTIAL"
	DDStatusInconclusive   = "INCONCLUSIVE"
	DDStatusNotAssessed    = "NOT_ASSESSED"

	// Recon Asset Types
	AssetTypeDomain         = "ROOT_DOMAIN"
	AssetTypeSubdomain      = "SUBDOMAIN"
	AssetTypeDNSRecord      = "DNS_RECORD"
	AssetTypeCloudBucket    = "PUBLIC_CLOUD_STORAGE"
	AssetTypeBaaSInstance   = "BAAS_BACKEND"
	AssetTypeAdminInterface = "EXPOSED_ADMIN_PORTAL"
	AssetTypeAPIEndpoint    = "REST_API_ENDPOINT"
	AssetTypeMobileAPK      = "MOBILE_APPLICATION_APK"

	// Exposure Tiers
	ExposurePublicSafe          = "PUBLIC_SAFE_INTENDED"
	ExposureInternalLeaked      = "INTERNAL_LEAKED_ASSET"
	ExposureMisconfigured       = "CONFIRMED_MISCONFIGURATION"
	ExposureAdminExposed        = "EXPOSED_ADMIN_PORTAL"
	ExposureAnonymousRestricted = "ANONYMOUS_ACCESS_RESTRICTED"
	ExposureResourceNotFound    = "RESOURCE_NOT_FOUND_ABSENT"
	ExposureInconclusiveAccess  = "INCONCLUSIVE_ACCESS_CHALLENGE"
	ExposureAccessDenied        = "ANONYMOUS_ACCESS_RESTRICTED" // Backward compatibility alias

	// Legal Commencement Status Metadata
	LegalStatusEnactedNotCommenced = "ENACTED_NOT_COMMENCED"
	LegalStatusPartiallyCommenced  = "PARTIALLY_COMMENCED"
	LegalStatusScheduledToCommence = "SCHEDULED_TO_COMMENCE"
	LegalStatusInForce             = "IN_FORCE"
	LegalStatusSupersededOrAmended = "SUPERSEDED_OR_AMENDED"

	// Complexity Tiers
	ComplexityTrivial       = "TRIVIAL"
	ComplexityLow           = "LOW"
	ComplexityMedium        = "MEDIUM"
	ComplexityHigh          = "HIGH"
	ComplexityArchitectural = "ARCHITECTURAL"

	// Acquisition Risk Grades
	RiskGradeA = "A (LOW_RISK)"
	RiskGradeB = "B (MODERATE_RISK)"
	RiskGradeC = "C (ELEVATED_RISK)"
	RiskGradeD = "D (HIGH_RISK)"
	RiskGradeF = "F (CRITICAL_LIABILITY)"

	// Recommendations
	RecRecommendedClean         = "ACQUISITION_RECOMMENDED_CLEAN"
	RecRecommendedWithEscrow    = "ACQUISITION_RECOMMENDED_WITH_REMEDIATION_ESCROW"
	RecSignificantConditions    = "SIGNIFICANT_CONDITIONS_REQUIRED"
	RecUnfavorableHighLiability = "UNFAVORABLE_HIGH_LIABILITY"
)

// DPDP Staged Commencement Dates pursuant to MeitY Commencement Notification G.S.R. 843(E) dated 13 November 2025:
var (
	// DPDPCommencementStage1: Clause (a) provisions taking effect on publication date (13 November 2025).
	// Covers preliminary provisions, definitions, and Data Protection Board of India constitution (Sections 1, 2, 18–26, 29–32, 34, 36–40, 42–44).
	DPDPCommencementStage1 = time.Date(2025, 11, 13, 0, 0, 0, 0, time.UTC)

	// DPDPCommencementStage2: Clause (b) provisions taking effect 1 year post-publication (13 November 2026).
	// Covers Section 6(9) (Grievance Redressal access mechanism) and Section 27(1)(d) (Calling for Information by the Board).
	DPDPCommencementStage2 = time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)

	// DPDPCommencementStage3: Clause (c) provisions taking effect 18 months post-publication (13 May 2027).
	// Covers substantive obligations of Data Fiduciaries (Sections 7–17) and the substantive penalty framework (Section 33 & The Schedule).
	DPDPCommencementStage3 = time.Date(2027, 5, 13, 0, 0, 0, 0, time.UTC)

	// Backward-compatible aliases
	DPDPCommencementDate = DPDPCommencementStage3
	DPDPNotificationDate = DPDPCommencementStage1
)

// -----------------------------------------------------------------------------
// Configuration & Inputs
// -----------------------------------------------------------------------------

// DueDiligenceConfig configures the M&A Due-Diligence & Acquisition Risk Profiler engine.
type DueDiligenceConfig struct {
	TargetEntityName            string                 `json:"target_entity_name"`
	RootDomain                  string                 `json:"root_domain"`
	AuthorizedScope             []string               `json:"authorized_scope"`
	AllowLoopback               bool                   `json:"allow_loopback"`
	AllowPrivateIPs             bool                   `json:"allow_private_ips"`
	RateLimitPerSecond          int                    `json:"rate_limit_per_second"`
	Timeout                     time.Duration          `json:"timeout"`
	PassiveOnly                 bool                   `json:"passive_only"`
	BlendedHourlyRateUSD        float64                `json:"blended_hourly_rate_usd"`
	AnnualRevenueUSD            float64                `json:"annual_revenue_usd"`
	AnnualRevenueEUR            float64                `json:"annual_revenue_eur"`
	AnnualRevenueINR            float64                `json:"annual_revenue_inr"`
	EstimatedEnterpriseValueUSD float64                `json:"estimated_enterprise_value_usd"`
	DealSizeUSD                 float64                `json:"deal_size_usd"`
	DataPrincipalsCount         int                    `json:"data_principals_count"`
	HasEUDataSubjects           bool                   `json:"has_eu_data_subjects"`
	HasIndianDataPrincipals     bool                   `json:"has_indian_data_principals"`
	ProcessesChildrenData       bool                   `json:"processes_children_data"`
	IsSignificantDataFiduciary  bool                   `json:"is_significant_data_fiduciary"`
	RegulatoryEscrowMultiplier  float64                `json:"regulatory_escrow_multiplier"` // Configurable illustrative deal assumption, default 0.50
	AssessmentDate              time.Time              `json:"assessment_date"`              // Diligence assessment date for statutory commencement evaluation
	CustomRegulatoryMultiplier  float64                `json:"custom_regulatory_multiplier"`
	Metadata                    map[string]interface{} `json:"metadata,omitempty"`
}

// DiscoveredAsset captures an externally observable technical asset identified during perimeter reconnaissance.
type DiscoveredAsset struct {
	AssetID         string            `json:"asset_id"`
	Type            string            `json:"type"`
	Identifier      string            `json:"identifier"`
	TargetURL       string            `json:"target_url"`
	IPAddresses     []string          `json:"ip_addresses,omitempty"`
	TechnologyStack []string          `json:"technology_stack,omitempty"`
	ExposedServices []string          `json:"exposed_services,omitempty"`
	ExposureTier    string            `json:"exposure_tier"`
	IsWithinScope   bool              `json:"is_within_scope"`
	DiscoveredVia   string            `json:"discovered_via"`
	Metadata        map[string]string `json:"metadata,omitempty"`
}

// CloudStorageIndicator models observed public cloud storage posture (S3, GCS, Azure).
type CloudStorageIndicator struct {
	Provider               string `json:"provider"` // AWS_S3, GCP_STORAGE, AZURE_BLOB
	BucketName             string `json:"bucket_name"`
	URL                    string `json:"url"`
	Accessibility          string `json:"accessibility"`           // PUBLIC_READ_OPEN, PUBLIC_LIST_OPEN, ACCESS_DENIED, AUTHENTICATED_REQUIRED, NOT_FOUND
	ExposureClassification string `json:"exposure_classification"` // CONFIRMED_MISCONFIGURATION, ANONYMOUS_ACCESS_RESTRICTED, RESOURCE_NOT_FOUND_ABSENT, INCONCLUSIVE_ACCESS_CHALLENGE
	FindingSeverity        string `json:"finding_severity"`        // CRITICAL, HIGH, LOW, INFO
	Evidence               string `json:"evidence"`
	IsWithinScope          bool   `json:"is_within_scope"`
}

// BaaSIndicator models observed Backend-as-a-Service exposure (Firebase, Supabase, etc.).
type BaaSIndicator struct {
	Provider               string `json:"provider"` // FIREBASE_RTDB, FIREBASE_FIRESTORE, SUPABASE, POCKETBASE
	InstanceID             string `json:"instance_id"`
	URL                    string `json:"url"`
	ConfigurationStatus    string `json:"configuration_status"`    // BENIGN_PUBLIC_KEY, OPEN_RULES_CONFIRMED, AUTHENTICATION_ENFORCED, ACCESS_DENIED
	ExposureClassification string `json:"exposure_classification"` // CONFIRMED_MISCONFIGURATION, PUBLIC_SAFE_INTENDED, ANONYMOUS_ACCESS_RESTRICTED, INCONCLUSIVE_ACCESS_CHALLENGE
	FindingSeverity        string `json:"finding_severity"`        // CRITICAL, HIGH, LOW, INFO
	Evidence               string `json:"evidence"`
	IsWithinScope          bool   `json:"is_within_scope"`
}

// MobileAPKMetadata models deconstructed mobile application security attributes from Phase 6.
type MobileAPKMetadata struct {
	PackageName                   string   `json:"package_name"`
	VersionName                   string   `json:"version_name"`
	VersionCode                   int      `json:"version_code"`
	MinSDK                        int      `json:"min_sdk"`
	TargetSDK                     int      `json:"target_sdk"`
	TotalPermissions              int      `json:"total_permissions"`
	DangerousPermissions          []string `json:"dangerous_permissions,omitempty"`
	ExportedActivitiesCount       int      `json:"exported_activities_count"`
	ExportedServicesCount         int      `json:"exported_services_count"`
	ExportedReceiversCount        int      `json:"exported_receivers_count"`
	CleartextTrafficPermitted     bool     `json:"cleartext_traffic_permitted"`
	InsecureNetworkConfig         bool     `json:"insecure_network_config"`
	EmbeddedEndpointsCount        int      `json:"embedded_endpoints_count"`
	HardcodedSecretsCount         int      `json:"hardcoded_secrets_count"`
	StaticRiskScore               int      `json:"static_risk_score"`   // 0-100
	AnalysisProvenance            string   `json:"analysis_provenance"` // STATIC_BINARY_EXTRACTION_ONLY
	IdentifiedBackendDependencies []string `json:"identified_backend_dependencies,omitempty"`
}

// SecurityFindingInput models a normalized finding ingested for due-diligence risk profiling.
type SecurityFindingInput struct {
	ID                 string   `json:"id"`
	RuleID             string   `json:"rule_id"`
	Title              string   `json:"title"`
	Category           string   `json:"category"`
	Severity           string   `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Status             string   `json:"status"`   // VERIFIED_DEFECT, POTENTIAL, INCONCLUSIVE, NOT_ASSESSED
	TargetURL          string   `json:"target_url"`
	Component          string   `json:"component"`
	Description        string   `json:"description"`
	RemediationSummary string   `json:"remediation_summary"`
	CWEIDs             []string `json:"cwe_ids,omitempty"`
	OWASPRef           string   `json:"owasp_ref,omitempty"`
	EvidenceDetails    string   `json:"evidence_details,omitempty"`
	IsCloudOrBaaS      bool     `json:"is_cloud_or_baas"`
	IsMobileArtifact   bool     `json:"is_mobile_artifact"`
}

// DueDiligenceInput aggregates all technical inputs for compiling an M&A Technical Due-Diligence assessment.
type DueDiligenceInput struct {
	Config                 DueDiligenceConfig      `json:"config"`
	Assets                 []DiscoveredAsset       `json:"assets"`
	CloudStorageIndicators []CloudStorageIndicator `json:"cloud_storage_indicators,omitempty"`
	BaaSIndicators         []BaaSIndicator         `json:"baas_indicators,omitempty"`
	MobileApplications     []MobileAPKMetadata     `json:"mobile_applications,omitempty"`
	Findings               []SecurityFindingInput  `json:"findings"`
	ExecutionTimestamp     time.Time               `json:"execution_timestamp"`
}

// -----------------------------------------------------------------------------
// Technical Debt & Remediation Hours Estimation Model
// -----------------------------------------------------------------------------

// RemediationEffortItem captures granular engineering effort estimates for an individual security finding.
type RemediationEffortItem struct {
	FindingID      string   `json:"finding_id"`
	Title          string   `json:"title"`
	Severity       string   `json:"severity"`
	Category       string   `json:"category"`
	ComplexityTier string   `json:"complexity_tier"` // TRIVIAL, LOW, MEDIUM, HIGH, ARCHITECTURAL
	LowerHours     float64  `json:"lower_hours"`
	BaseHours      float64  `json:"base_hours"`
	UpperHours     float64  `json:"upper_hours"`
	LowerCostUSD   float64  `json:"lower_cost_usd"`
	BaseCostUSD    float64  `json:"base_cost_usd"`
	UpperCostUSD   float64  `json:"upper_cost_usd"`
	ComponentCount int      `json:"component_count"`
	Assumptions    []string `json:"assumptions"`
	KeyCostDrivers []string `json:"key_cost_drivers"`
}

// HoursRange holds aggregated hours and dollar estimates for a category or severity tier.
type HoursRange struct {
	FindingCount int     `json:"finding_count"`
	LowerHours   float64 `json:"lower_hours"`
	BaseHours    float64 `json:"base_hours"`
	UpperHours   float64 `json:"upper_hours"`
	BaseCostUSD  float64 `json:"base_cost_usd"`
}

// TechnicalDebtAssessment details the bottom-up engineering hours and financial remediation cost modeling.
type TechnicalDebtAssessment struct {
	TotalFindingsEvaluated int                     `json:"total_findings_evaluated"`
	TotalLowerHours        float64                 `json:"total_lower_hours"`
	TotalBaseHours         float64                 `json:"total_base_hours"`
	TotalUpperHours        float64                 `json:"total_upper_hours"`
	TotalLowerCostUSD      float64                 `json:"total_lower_cost_usd"`
	TotalBaseCostUSD       float64                 `json:"total_base_cost_usd"`
	TotalUpperCostUSD      float64                 `json:"total_upper_cost_usd"`
	BlendedHourlyRateUSD   float64                 `json:"blended_hourly_rate_usd"`
	EffortBySeverity       map[string]HoursRange   `json:"effort_by_severity"`
	EffortByCategory       map[string]HoursRange   `json:"effort_by_category"`
	EffortItems            []RemediationEffortItem `json:"effort_items"`
	ConfidenceLevel        string                  `json:"confidence_level"` // HIGH, MEDIUM, PRELIMINARY_ESTIMATE
	Methodology            string                  `json:"methodology"`
	Assumptions            []string                `json:"assumptions"`
	EstimationDisclaimer   string                  `json:"estimation_disclaimer"`
}

// -----------------------------------------------------------------------------
// GDPR & DPDP Statutory Regulatory Exposure Modeling
// -----------------------------------------------------------------------------

// GDPRExposureScenario details statutory maximums and estimated exposure scenarios under EU GDPR.
type GDPRExposureScenario struct {
	Jurisdiction            string   `json:"jurisdiction"` // European Union (GDPR - Regulation (EU) 2016/679)
	LegalSourceVersion      string   `json:"legal_source_version"`
	LegalCommencementStatus string   `json:"legal_commencement_status"`     // IN_FORCE
	StatutoryEffectiveDate  string   `json:"statutory_effective_date"`       // 2018-05-25
	IsCurrentlyEnforceable  bool     `json:"is_currently_enforceable"`       // true
	StatutoryCeilingArt83_4 float64  `json:"statutory_ceiling_art83_4_eur"` // Up to €10M or 2% turnover
	StatutoryCeilingArt83_5 float64  `json:"statutory_ceiling_art83_5_eur"` // Up to €20M or 4% turnover
	StatutoryMaxCeilingEUR  float64  `json:"statutory_max_ceiling_eur"`
	ConservativeScenarioEUR float64  `json:"conservative_scenario_eur"`
	ProbableScenarioEUR     float64  `json:"probable_scenario_eur"`
	HighImpactScenarioEUR   float64  `json:"high_impact_scenario_eur"`
	AnnualTurnoverEUR       float64  `json:"annual_turnover_eur"`
	DataPrincipalsAffected  int      `json:"data_principals_affected"`
	ApplicableArticles      []string `json:"applicable_articles"`
	CalculationAssumptions  []string `json:"calculation_assumptions"`
}

// DPDPProvisionStatus captures staged commencement status for an individual statutory provision group.
type DPDPProvisionStatus struct {
	ProvisionGroup    string `json:"provision_group"`
	ProvisionsCovered string `json:"provisions_covered"`
	CommencementDate  string `json:"commencement_date"`
	Status            string `json:"status"` // ENACTED_NOT_COMMENCED, SCHEDULED_TO_COMMENCE, IN_FORCE
	IsEffective       bool   `json:"is_effective"`
	Notes             string `json:"notes"`
}

// DPDPScheduleCategory captures an individual penalty category from The Schedule to the DPDP Act, 2023.
type DPDPScheduleCategory struct {
	ScheduleItemNumber   int     `json:"schedule_item_number"`
	ProvisionRef         string  `json:"provision_ref"`
	ObligationSubject    string  `json:"obligation_subject"`
	StatutoryCeilingINR  float64 `json:"statutory_ceiling_inr"`
	StatutoryWording     string  `json:"statutory_wording"` // "May extend to ₹..."
	IsApplicableToTarget bool    `json:"is_applicable_to_target"`
	ApplicabilityReason  string  `json:"applicability_reason"`
}

// DPDPExposureScenario details statutory penalty ceilings and scenarios under India's DPDP Act, 2023.
type DPDPExposureScenario struct {
	Jurisdiction                  string                 `json:"jurisdiction"` // India (The Digital Personal Data Protection Act, 2023)
	LegalSourceVersion            string                 `json:"legal_source_version"`
	CommencementNotificationRef   string                 `json:"commencement_notification_ref"`
	ActOverallStatus              string                 `json:"act_overall_status"`        // ENACTED_NOT_COMMENCED, PARTIALLY_COMMENCED, IN_FORCE
	PenaltyFrameworkStatus        string                 `json:"penalty_framework_status"`  // SCHEDULED_TO_COMMENCE, IN_FORCE
	LegalCommencementStatus       string                 `json:"legal_commencement_status"` // Backward-compatible alias for penalty framework status
	StatutoryEffectiveDate        string                 `json:"statutory_effective_date"`  // 2027-05-13
	AssessmentDate                string                 `json:"assessment_date"`
	IsPenaltyEffective            bool                   `json:"is_penalty_effective"`
	IsCurrentlyEnforceable        bool                   `json:"is_currently_enforceable"` // Backward-compatible alias
	CurrentEnforceableMaxINR      float64                `json:"current_enforceable_max_inr"`
	CurrentEnforceableProbableINR float64                `json:"current_enforceable_probable_inr"`
	StatutoryCeilingSec8_5        float64                `json:"statutory_ceiling_sec8_5_inr"`   // Security Safeguards: Up to ₹250 Crore
	StatutoryCeilingSec8_6        float64                `json:"statutory_ceiling_sec8_6_inr"`   // Failure to Notify: Up to ₹200 Crore
	StatutoryCeilingSec9          float64                `json:"statutory_ceiling_sec9_inr"`     // Children Data Breach: Up to ₹200 Crore (Corrected from ₹150 Crore)
	StatutoryCeilingSec10         float64                `json:"statutory_ceiling_sec10_inr"`    // Significant Data Fiduciary: Up to ₹150 Crore
	StatutoryCeilingSec15         float64                `json:"statutory_ceiling_sec15_inr"`    // Duties of Data Principal: Up to ₹10,000
	StatutoryCeilingResidual      float64                `json:"statutory_ceiling_residual_inr"` // Residual breaches: Up to ₹50 Crore
	StatutoryMaxCeilingINR        float64                `json:"statutory_max_ceiling_inr"`      // Upper statutory ceiling across evaluated categories
	ConservativeScenarioINR       float64                `json:"conservative_scenario_inr"`
	ProbableScenarioINR           float64                `json:"probable_scenario_inr"`
	HighImpactScenarioINR         float64                `json:"high_impact_scenario_inr"`
	DataPrincipalsAffected        int                    `json:"data_principals_affected"`
	ProvisionStages               []DPDPProvisionStatus  `json:"provision_stages"`
	ScheduleCategories            []DPDPScheduleCategory `json:"schedule_categories"`
	ApplicableScheduleClauses     []string               `json:"applicable_schedule_clauses"`
	CalculationAssumptions        []string               `json:"calculation_assumptions"`
	PenaltyDeterminationFactors   []string               `json:"penalty_determination_factors"`
}

// RegulatoryExposureAssessment bundles multi-jurisdictional statutory risk estimations with mandatory disclaimers.
type RegulatoryExposureAssessment struct {
	GDPR                              GDPRExposureScenario `json:"gdpr"`
	DPDP                              DPDPExposureScenario `json:"dpdp"`
	PreferredCurrency                 string               `json:"preferred_currency"`
	CurrentEnforceableProbableCostUSD float64              `json:"current_enforceable_probable_cost_usd"`
	FutureProjectedProbableCostUSD    float64              `json:"future_projected_probable_cost_usd"`
	TotalProbableCostUSD              float64              `json:"total_probable_cost_usd"`
	CurrentEnforceableMaxCeilingUSD   float64              `json:"current_enforceable_max_ceiling_usd"`
	FutureProjectedMaxCeilingUSD      float64              `json:"future_projected_max_ceiling_usd"`
	LegalDisclaimer                   string               `json:"legal_disclaimer"`
}

// -----------------------------------------------------------------------------
// Acquisition Risk Profiler Model
// -----------------------------------------------------------------------------

// AcquisitionRiskProfile synthesizes technical, cloud, mobile, financial, and legal risk dimensions into an M&A profile.
type AcquisitionRiskProfile struct {
	CompositeRiskScore           int      `json:"composite_risk_score"` // 0 to 100
	RiskGrade                    string   `json:"risk_grade"`           // A, B, C, D, F
	RiskTier                     string   `json:"risk_tier"`            // LOW_RISK, MODERATE_RISK, ELEVATED_RISK, HIGH_RISK, CRITICAL_LIABILITY
	PerimeterSubScore            float64  `json:"perimeter_sub_score"`  // 0-100
	CloudBaaSSubScore            float64  `json:"cloud_baas_sub_score"` // 0-100
	MobileSubScore               float64  `json:"mobile_sub_score"`     // 0-100
	VulnerabilitySubScore        float64  `json:"vulnerability_sub_score"` // 0-100
	TechnicalDebtSubScore        float64  `json:"technical_debt_sub_score"` // 0-100
	RegulatorySubScore           float64  `json:"regulatory_sub_score"`     // 0-100
	AssessmentCoverageRatio      float64  `json:"assessment_coverage_ratio"` // 0.0 - 1.0
	CoverageLimitations          []string `json:"coverage_limitations,omitempty"`
	ScoringMethodologyDisclaimer string   `json:"scoring_methodology_disclaimer"`
	VerifiedDefectsCount         int      `json:"verified_defects_count"`
	PotentialFindingsCount       int      `json:"potential_findings_count"`
	InconclusiveChecksCount      int      `json:"inconclusive_checks_count"`
	NotAssessedChecksCount       int      `json:"not_assessed_checks_count"`
	CriticalAssetsImpacted       []string `json:"critical_assets_impacted"`
	IntegrationComplexityTier    string   `json:"integration_complexity_tier"` // LOW, MEDIUM, HIGH, SEVERE_REFACTOR_REQUIRED
	AcquisitionRecommendation    string   `json:"acquisition_recommendation"`
	KeyRiskDrivers               []string `json:"key_risk_drivers"`
	ScoringExplanation           string   `json:"scoring_explanation"`
}

// -----------------------------------------------------------------------------
// Executive Acquisition Dossier (15 Canonical Sections)
// -----------------------------------------------------------------------------

// ExecutiveAcquisitionDossier encapsulates the complete board-ready M&A acquisition evaluation report.
type ExecutiveAcquisitionDossier struct {
	SchemaVersion    string `json:"schema_version"`
	DossierID        string `json:"dossier_id"`
	GeneratedAt      string `json:"generated_at"`
	TargetEntityName string `json:"target_entity_name"`
	TargetRootDomain string `json:"target_root_domain"`
	CanonicalDigest  string `json:"canonical_digest"`

	// 15 Canonical Sections:
	Section1_ExecutiveSummary         DossierExecutiveSummarySection `json:"section_1_executive_summary"`
	Section2_TargetAssessmentScope    DossierScopeSection            `json:"section_2_target_assessment_scope"`
	Section3_AssetInventory           []DiscoveredAsset              `json:"section_3_asset_inventory"`
	Section4_ExternalAttackSurface    DossierAttackSurfaceSection    `json:"section_4_external_attack_surface"`
	Section5_CloudAndBaaSExposure     DossierCloudBaaSSection        `json:"section_5_cloud_and_baas_exposure"`
	Section6_MobileAppAssessment      DossierMobileSection           `json:"section_6_mobile_app_assessment"`
	Section7_CriticalSecurityFindings []SecurityFindingInput         `json:"section_7_critical_security_findings"`
	Section8_TechnicalDebt            TechnicalDebtAssessment        `json:"section_8_technical_debt"`
	Section9_RemediationEstimates     []RemediationEffortItem        `json:"section_9_remediation_estimates"`
	Section10_RegulatoryExposure      RegulatoryExposureAssessment   `json:"section_10_regulatory_exposure"`
	Section11_AcquisitionIntegration  DossierIntegrationRiskSection  `json:"section_11_acquisition_integration"`
	Section12_RiskPrioritization      []DossierPriorityItem          `json:"section_12_risk_prioritization"`
	Section13_EvidenceProvenance      DossierProvenanceSection       `json:"section_13_evidence_provenance"`
	Section14_RemediationRoadmap      DossierRemediationRoadmap      `json:"section_14_remediation_roadmap"`
	Section15_FinalAcquisitionRisk    AcquisitionRiskProfile         `json:"section_15_final_acquisition_risk"`
}

// Section Models:

type DossierExecutiveSummarySection struct {
	TargetEntityName         string   `json:"target_entity_name"`
	RootDomain               string   `json:"root_domain"`
	RiskGrade                string   `json:"risk_grade"`
	RiskTier                 string   `json:"risk_tier"`
	CompositeScore           int      `json:"composite_score"`
	AcquisitionVerdict       string   `json:"acquisition_verdict"`
	KeyStrategicConcerns     []string `json:"key_strategic_concerns"`
	EstimatedRemediationCost string   `json:"estimated_remediation_cost"`
	EstimatedRemediationTime string   `json:"estimated_remediation_time"`
	RegulatoryCeilingSummary string   `json:"regulatory_ceiling_summary"`
	HeadlinePosture          string   `json:"headline_posture"`
}

type DossierScopeSection struct {
	AuthorizedScope          []string `json:"authorized_scope"`
	TestingMode              string   `json:"testing_mode"` // ZERO_CREDENTIAL_BLACK_BOX
	PassiveDiscoveryOnly     bool     `json:"passive_discovery_only"`
	NonDestructiveGuarantees []string `json:"non_destructive_guarantees"`
	ExcludedTargets          []string `json:"excluded_targets,omitempty"`
}

type DossierAttackSurfaceSection struct {
	TotalDiscoveredAssets    int      `json:"total_discovered_assets"`
	PublicDomainCount        int      `json:"public_domain_count"`
	SubdomainCount           int      `json:"subdomain_count"`
	ExposedAdminPortalsCount int      `json:"exposed_admin_portals_count"`
	APIEndpointsCount        int      `json:"api_endpoints_count"`
	IdentifiedTechnologies   []string `json:"identified_technologies"`
	SurfaceHighlights        []string `json:"surface_highlights"`
}

type DossierCloudBaaSSection struct {
	StorageIndicatorsCount int                     `json:"storage_indicators_count"`
	BaaSIndicatorsCount    int                     `json:"baas_indicators_count"`
	ConfirmedBucketLeaks   int                     `json:"confirmed_bucket_leaks"`
	ConfirmedBaaSLeaks     int                     `json:"confirmed_baas_leaks"`
	StorageDetails         []CloudStorageIndicator `json:"storage_details,omitempty"`
	BaaSDetails            []BaaSIndicator         `json:"baas_details,omitempty"`
	Summary                string                  `json:"summary"`
}

type DossierMobileSection struct {
	ApplicationsEvaluated    int                 `json:"applications_evaluated"`
	HighestStaticRiskScore   int                 `json:"highest_static_risk_score"`
	CleartextTrafficDetected bool                `json:"cleartext_traffic_detected"`
	HardcodedSecretsDetected int                 `json:"hardcoded_secrets_detected"`
	Applications             []MobileAPKMetadata `json:"applications,omitempty"`
	Summary                  string              `json:"summary"`
}

type DossierIntegrationRiskSection struct {
	IntegrationComplexity    string   `json:"integration_complexity"` // LOW, MEDIUM, HIGH, SEVERE_REFACTOR_REQUIRED
	NetworkIsolationRequired bool     `json:"network_isolation_required"`
	IdentityFederationRisks  []string `json:"identity_federation_risks"`
	LegacyProtocolRisks      []string `json:"legacy_protocol_risks"`
	RecommendedSafeguards    []string `json:"recommended_safeguards"`
}

type DossierPriorityItem struct {
	Rank           int    `json:"rank"`
	Title          string `json:"title"`
	Category       string `json:"category"`
	Severity       string `json:"severity"`
	Status         string `json:"status"`
	RemediationETA string `json:"remediation_eta"`
	DealImpact     string `json:"deal_impact"`
}

type DossierProvenanceSection struct {
	EngineVersion            string   `json:"engine_version"`
	AttestationType          string   `json:"attestation_type"` // ED25519_CANONICAL_DIGEST
	ZeroCredentialEnforced   bool     `json:"zero_credential_enforced"`
	ScopeGuardrailsEnforced  bool     `json:"scope_guardrails_enforced"`
	LimitationsAndExclusions []string `json:"limitations_and_exclusions"`
	NonClaims                []string `json:"non_claims"`
}

type DossierRemediationRoadmap struct {
	PreCloseMustFixItems          []string `json:"pre_close_must_fix_items"`
	PostClose30DayItems           []string `json:"post_close_30_day_items"`
	PostClose90DayItems           []string `json:"post_close_90_day_items"`
	ArchitecturalUpgrades         []string `json:"architectural_upgrades"`
	TechnicalRemediationCostUSD   float64  `json:"technical_remediation_cost_usd"`
	StatutoryMaxLiabilityUSD      float64  `json:"statutory_max_liability_usd"`
	IllustrativeRegulatoryRiskUSD float64  `json:"illustrative_regulatory_risk_usd"`
	ConfiguredEscrowMultiplier    float64  `json:"configured_escrow_multiplier"`
	RecommendedEscrowUSD          float64  `json:"recommended_escrow_usd"`
	EscrowMethodologyRationale    string   `json:"escrow_methodology_rationale"`
}

// -----------------------------------------------------------------------------
// Engine Implementation
// -----------------------------------------------------------------------------

// DueDiligenceEngine coordinates reconnaissance, classification, estimation, and dossier synthesis.
// FeatureGateChecker verifies whether a commercial feature is entitled for execution.
type FeatureGateChecker interface {
	CheckFeature(feature string) error
}

var (
	globalFeatureGate FeatureGateChecker
	globalFGMu        sync.RWMutex
)

// SetGlobalFeatureGate registers the feature gate checker for due diligence audits.
func SetGlobalFeatureGate(fg FeatureGateChecker) {
	globalFGMu.Lock()
	defer globalFGMu.Unlock()
	globalFeatureGate = fg
}

// GetGlobalFeatureGate returns the active feature gate checker.
func GetGlobalFeatureGate() FeatureGateChecker {
	globalFGMu.RLock()
	defer globalFGMu.RUnlock()
	return globalFeatureGate
}

type DueDiligenceEngine struct {
	cfg        DueDiligenceConfig
	httpClient *http.Client
	mu         sync.RWMutex
}

// NewDueDiligenceEngine initializes the M&A Technical Due-Diligence Engine with safe transport.
func NewDueDiligenceEngine(cfg DueDiligenceConfig, client *http.Client) *DueDiligenceEngine {
	if cfg.BlendedHourlyRateUSD <= 0 {
		cfg.BlendedHourlyRateUSD = 150.0 // Default $150/hr industry rate
	}
	if cfg.RegulatoryEscrowMultiplier <= 0 {
		cfg.RegulatoryEscrowMultiplier = 0.50 // Default 50% illustrative deal assumption
	}
	if client == nil {
		safeTransport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
			Timeout:         cfg.Timeout,
			AllowLoopback:   cfg.AllowLoopback,
			AllowPrivateIPs: cfg.AllowPrivateIPs,
		})
		client = &http.Client{
			Transport: safeTransport,
			Timeout:   cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("stopped after 5 redirects")
				}
				// Verify scheme
				scheme := strings.ToLower(req.URL.Scheme)
				if scheme != "http" && scheme != "https" {
					return fmt.Errorf("redirect to unsupported scheme %q blocked", scheme)
				}
				// Verify scope
				if !IsTargetInScope(req.URL.String(), cfg.AuthorizedScope) {
					return fmt.Errorf("redirect to out-of-scope host blocked: %s", req.URL.Host)
				}
				return nil
			},
		}
	}
	return &DueDiligenceEngine{
		cfg:        cfg,
		httpClient: client,
	}
}

// ExecuteAssessment runs an M&A due-diligence audit and generates an Executive Acquisition Dossier.
func (e *DueDiligenceEngine) ExecuteAssessment(ctx context.Context, input DueDiligenceInput) (*ExecutiveAcquisitionDossier, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if fg := GetGlobalFeatureGate(); fg != nil {
		if err := fg.CheckFeature("report.due_diligence"); err != nil {
			return nil, fmt.Errorf("licensing refusal: %w", err)
		}
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Merge engine config into input config if empty
	if input.Config.TargetEntityName == "" {
		input.Config.TargetEntityName = e.cfg.TargetEntityName
	}
	if input.Config.RootDomain == "" {
		input.Config.RootDomain = e.cfg.RootDomain
	}
	if len(input.Config.AuthorizedScope) == 0 {
		input.Config.AuthorizedScope = e.cfg.AuthorizedScope
	}
	if input.Config.BlendedHourlyRateUSD <= 0 {
		input.Config.BlendedHourlyRateUSD = e.cfg.BlendedHourlyRateUSD
	}
	if input.Config.RegulatoryEscrowMultiplier <= 0 {
		input.Config.RegulatoryEscrowMultiplier = e.cfg.RegulatoryEscrowMultiplier
	}
	if input.Config.AssessmentDate.IsZero() {
		input.Config.AssessmentDate = e.cfg.AssessmentDate
	}
	if input.Config.AnnualRevenueUSD <= 0 {
		input.Config.AnnualRevenueUSD = e.cfg.AnnualRevenueUSD
	}
	if input.Config.AnnualRevenueEUR <= 0 {
		input.Config.AnnualRevenueEUR = e.cfg.AnnualRevenueEUR
	}
	if input.Config.AnnualRevenueINR <= 0 {
		input.Config.AnnualRevenueINR = e.cfg.AnnualRevenueINR
	}

	return GenerateExecutiveAcquisitionDossier(input)
}

// DiscoverPerimeterAssets performs zero-credential external reconnaissance across candidate targets.
func (e *DueDiligenceEngine) DiscoverPerimeterAssets(ctx context.Context, candidates []string) ([]DiscoveredAsset, error) {
	if ctx != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	var discovered []DiscoveredAsset
	for _, cand := range candidates {
		cand = strings.TrimSpace(cand)
		if cand == "" {
			continue
		}
		inScope := IsTargetInScope(cand, e.cfg.AuthorizedScope)
		assetType := AssetTypeSubdomain
		if strings.EqualFold(cand, e.cfg.RootDomain) {
			assetType = AssetTypeDomain
		} else if strings.Contains(cand, "admin") || strings.Contains(cand, "dashboard") || strings.Contains(cand, "portal") {
			assetType = AssetTypeAdminInterface
		} else if strings.Contains(cand, "api") || strings.Contains(cand, "/v1") {
			assetType = AssetTypeAPIEndpoint
		} else if strings.Contains(cand, ".s3.") || strings.Contains(cand, "storage.googleapis.com") {
			assetType = AssetTypeCloudBucket
		} else if strings.Contains(cand, "firebaseio.com") || strings.Contains(cand, "supabase.co") {
			assetType = AssetTypeBaaSInstance
		}

		exposureTier := ExposurePublicSafe
		if assetType == AssetTypeAdminInterface {
			exposureTier = ExposureAdminExposed
		}

		discovered = append(discovered, DiscoveredAsset{
			AssetID:       fmt.Sprintf("AST-%s-%d", sanitizeID(cand), len(discovered)+1),
			Type:          assetType,
			Identifier:    cand,
			TargetURL:     secrets.RedactText(cand),
			ExposureTier:  exposureTier,
			IsWithinScope: inScope,
			DiscoveredVia: "EXTERNAL_RECONNAISSANCE_ENGINE",
		})
	}
	return discovered, nil
}

// IsTargetInScope verifies whether a candidate target URL or host falls strictly within the authorized scope.
func IsTargetInScope(target string, authorizedScope []string) bool {
	if len(authorizedScope) == 0 {
		return false // Fail-closed: empty scope allows nothing
	}
	cleanTarget := strings.TrimSpace(target)
	if strings.Contains(cleanTarget, "://") {
		if parsed, err := url.Parse(cleanTarget); err == nil {
			cleanTarget = parsed.Hostname()
		}
	}
	cleanTarget = strings.ToLower(cleanTarget)

	for _, scope := range authorizedScope {
		scope = strings.TrimSpace(strings.ToLower(scope))
		if strings.Contains(scope, "://") {
			if parsed, err := url.Parse(scope); err == nil {
				scope = parsed.Hostname()
			}
		}
		if scope == cleanTarget {
			return true
		}
		// Subdomain wildcard matching (e.g., .acme.com or *.acme.com)
		if strings.HasPrefix(scope, "*.") {
			root := scope[2:]
			if cleanTarget == root || strings.HasSuffix(cleanTarget, "."+root) {
				return true
			}
		}
		if strings.HasPrefix(scope, ".") {
			root := scope[1:]
			if cleanTarget == root || strings.HasSuffix(cleanTarget, "."+root) {
				return true
			}
		}
		// Suffix match
		if strings.HasSuffix(cleanTarget, "."+scope) {
			return true
		}
	}
	return false
}

// ClassifyCloudStorageExposure evaluates public cloud storage posture without accessing customer data.
func ClassifyCloudStorageExposure(indicator CloudStorageIndicator) CloudStorageIndicator {
	res := indicator
	res.URL = secrets.RedactText(res.URL)

	switch strings.ToUpper(strings.TrimSpace(res.Accessibility)) {
	case "PUBLIC_LIST_OPEN":
		res.ExposureClassification = ExposureMisconfigured
		res.FindingSeverity = DDSeverityCritical
		res.Evidence = fmt.Sprintf("Public bucket listing enabled on %s (%s). Anonymous callers can enumerate bucket objects without authentication. Confirmed reproducible misconfiguration.", res.BucketName, res.Provider)
	case "PUBLIC_READ_OPEN":
		res.ExposureClassification = ExposureMisconfigured
		res.FindingSeverity = DDSeverityHigh
		res.Evidence = fmt.Sprintf("Public object retrieval enabled on %s (%s). Anonymous callers can download public objects directly. Confirmed reproducible misconfiguration.", res.BucketName, res.Provider)
	case "ACCESS_DENIED", "AUTHENTICATED_REQUIRED":
		res.ExposureClassification = ExposureAnonymousRestricted
		res.FindingSeverity = DDSeverityInfo
		res.Evidence = fmt.Sprintf("Cloud storage bucket %s (%s) returns Access Denied / 403 Forbidden to anonymous callers. Anonymous access is restricted; comprehensive access controls require authenticated IAM review.", res.BucketName, res.Provider)
	case "NOT_FOUND":
		res.ExposureClassification = ExposureResourceNotFound
		res.FindingSeverity = DDSeverityInfo
		res.Evidence = fmt.Sprintf("Cloud storage bucket %s (%s) returned 404 / NoSuchBucket. Resource is absent; does not demonstrate affirmative security controls.", res.BucketName, res.Provider)
	default:
		res.ExposureClassification = ExposureInconclusiveAccess
		res.FindingSeverity = DDSeverityLow
		res.Evidence = fmt.Sprintf("Cloud storage bucket %s (%s) exhibits indeterminate exposure state %q; requires authorized credentialed validation.", res.BucketName, res.Provider, res.Accessibility)
	}
	return res
}

// ClassifyBaaSExposure evaluates Firebase/Supabase configuration posture adhering to the strict rule:
// A public configuration or client API key alone is NEVER a vulnerability.
func ClassifyBaaSExposure(indicator BaaSIndicator) BaaSIndicator {
	res := indicator
	res.URL = secrets.RedactText(res.URL)

	switch strings.ToUpper(strings.TrimSpace(res.ConfigurationStatus)) {
	case "OPEN_RULES_CONFIRMED":
		res.ExposureClassification = ExposureMisconfigured
		res.FindingSeverity = DDSeverityCritical
		res.Evidence = fmt.Sprintf("BaaS instance %s (%s) has open read/write security rules (.read=true / public REST response). Anonymous callers can read database records without authentication. Confirmed reproducible misconfiguration.", res.InstanceID, res.Provider)
	case "BENIGN_PUBLIC_KEY", "PUBLIC_CONFIG_PRESENT":
		res.ExposureClassification = ExposurePublicSafe
		res.FindingSeverity = DDSeverityInfo
		res.Evidence = fmt.Sprintf("BaaS client configuration identified for %s (%s). Public API key and project metadata present as expected for client-side SDK bootstrap; security rules enforce authentication. Not a vulnerability.", res.InstanceID, res.Provider)
	case "AUTHENTICATION_ENFORCED", "ACCESS_DENIED":
		res.ExposureClassification = ExposureAnonymousRestricted
		res.FindingSeverity = DDSeverityInfo
		res.Evidence = fmt.Sprintf("BaaS instance %s (%s) rejects anonymous requests with 401 Unauthorized / Permission Denied. Anonymous access is restricted; comprehensive access controls require internal security rules review.", res.InstanceID, res.Provider)
	default:
		res.ExposureClassification = ExposureInconclusiveAccess
		res.FindingSeverity = DDSeverityLow
		res.Evidence = fmt.Sprintf("BaaS instance %s (%s) exhibits indeterminate exposure status %q; requires authorized internal rule review.", res.InstanceID, res.Provider, res.ConfigurationStatus)
	}
	return res
}

// EstimateTechnicalDebt computes bottom-up security remediation engineering hours and cost ranges.
func EstimateTechnicalDebt(findings []SecurityFindingInput, blendedHourlyRate float64) TechnicalDebtAssessment {
	if blendedHourlyRate <= 0 {
		blendedHourlyRate = 150.0
	}

	assessment := TechnicalDebtAssessment{
		TotalFindingsEvaluated: len(findings),
		BlendedHourlyRateUSD:   blendedHourlyRate,
		EffortBySeverity:       make(map[string]HoursRange),
		EffortByCategory:       make(map[string]HoursRange),
		ConfidenceLevel:        "HIGH",
		Methodology:            "Bottom-up parametric complexity modeling: Base remediation hours scaled by component scope, architectural dependencies, regression validation factor (0.6x lower, 1.0x base, 1.8x upper), and blended engineering rate.",
		Assumptions: []string{
			"Estimates reflect software engineering, code refactoring, test automation, and verification hours.",
			"Does not include commercial product licensing, third-party vendor retainer fees, or business downtime costs.",
			fmt.Sprintf("Blended engineering compensation rate assumed at $%.2f USD/hour.", blendedHourlyRate),
			"All estimates are analytical technical-debt calculations and strictly do not constitute contractual fixed-price quotes.",
		},
		EstimationDisclaimer: "LEGAL & FINANCIAL DISCLAIMER: Estimated engineering hours and projected remediation costs represent analytical technical-debt benchmarks for acquisition diligence. They do not constitute a contractual warranty or fixed quotation.",
	}

	for _, f := range findings {
		item := computeFindingRemediationEffort(f, blendedHourlyRate)
		assessment.EffortItems = append(assessment.EffortItems, item)

		assessment.TotalLowerHours += item.LowerHours
		assessment.TotalBaseHours += item.BaseHours
		assessment.TotalUpperHours += item.UpperHours

		assessment.TotalLowerCostUSD += item.LowerCostUSD
		assessment.TotalBaseCostUSD += item.BaseCostUSD
		assessment.TotalUpperCostUSD += item.UpperCostUSD

		// Aggregate by Severity
		sevRange := assessment.EffortBySeverity[item.Severity]
		sevRange.FindingCount++
		sevRange.LowerHours += item.LowerHours
		sevRange.BaseHours += item.BaseHours
		sevRange.UpperHours += item.UpperHours
		sevRange.BaseCostUSD += item.BaseCostUSD
		assessment.EffortBySeverity[item.Severity] = sevRange

		// Aggregate by Category
		catKey := item.Category
		if catKey == "" {
			catKey = "GENERAL_SECURITY"
		}
		catRange := assessment.EffortByCategory[catKey]
		catRange.FindingCount++
		catRange.LowerHours += item.LowerHours
		catRange.BaseHours += item.BaseHours
		catRange.UpperHours += item.UpperHours
		catRange.BaseCostUSD += item.BaseCostUSD
		assessment.EffortByCategory[catKey] = catRange
	}

	// Round totals for explainable reporting
	assessment.TotalLowerHours = math.Round(assessment.TotalLowerHours*10) / 10
	assessment.TotalBaseHours = math.Round(assessment.TotalBaseHours*10) / 10
	assessment.TotalUpperHours = math.Round(assessment.TotalUpperHours*10) / 10
	assessment.TotalLowerCostUSD = math.Round(assessment.TotalLowerCostUSD)
	assessment.TotalBaseCostUSD = math.Round(assessment.TotalBaseCostUSD)
	assessment.TotalUpperCostUSD = math.Round(assessment.TotalUpperCostUSD)

	return assessment
}

func computeFindingRemediationEffort(f SecurityFindingInput, rate float64) RemediationEffortItem {
	var baseHours float64
	var tier string
	var drivers []string

	sev := strings.ToUpper(strings.TrimSpace(f.Severity))
	cat := strings.ToUpper(strings.TrimSpace(f.Category))

	switch sev {
	case DDSeverityCritical:
		if strings.Contains(cat, "AUTH") || strings.Contains(cat, "CRYPTO") || strings.Contains(cat, "BOLA") {
			baseHours = 80.0
			tier = ComplexityArchitectural
			drivers = append(drivers, "Architectural authorization or cryptographic subsystem refactor required across services")
		} else {
			baseHours = 40.0
			tier = ComplexityHigh
			drivers = append(drivers, "Critical code remediation, input parameter validation, and comprehensive regression test suite")
		}
	case DDSeverityHigh:
		baseHours = 24.0
		tier = ComplexityMedium
		drivers = append(drivers, "Targeted component fix, sanitization, and automated integration test coverage")
	case DDSeverityMedium:
		baseHours = 12.0
		tier = ComplexityLow
		drivers = append(drivers, "Standard security configuration or localized code modification")
	case DDSeverityLow:
		baseHours = 4.0
		tier = ComplexityTrivial
		drivers = append(drivers, "Header adjustment, flag setting, or minor configuration update")
	default: // INFO
		baseHours = 1.0
		tier = ComplexityTrivial
		drivers = append(drivers, "Documentation update or non-functional configuration hardening")
	}

	// Component factor: If component indicates multiple services or mobile/cloud bridge
	compFactor := 1.0
	compCount := 1
	if f.IsCloudOrBaaS || f.IsMobileArtifact {
		compFactor = 1.25
		compCount = 2
		drivers = append(drivers, "Cross-platform cloud/mobile deployment synchronization and artifact re-signing")
	}

	effectiveBase := baseHours * compFactor
	lowerHours := math.Round(effectiveBase*0.6*10) / 10
	upperHours := math.Round(effectiveBase*1.8*10) / 10

	return RemediationEffortItem{
		FindingID:      f.ID,
		Title:          f.Title,
		Severity:       sev,
		Category:       f.Category,
		ComplexityTier: tier,
		LowerHours:     lowerHours,
		BaseHours:      effectiveBase,
		UpperHours:     upperHours,
		LowerCostUSD:   math.Round(lowerHours * rate),
		BaseCostUSD:    math.Round(effectiveBase * rate),
		UpperCostUSD:   math.Round(upperHours * rate),
		ComponentCount: compCount,
		Assumptions: []string{
			fmt.Sprintf("Remediation effort assumes %s complexity with %.1f base engineering hours.", tier, effectiveBase),
			"Includes developer unit tests and staging environment pre-flight validation.",
		},
		KeyCostDrivers: drivers,
	}
}

// EstimateRegulatoryExposure computes transparent statutory liability ceilings and realistic exposure scenarios.
func EstimateRegulatoryExposure(cfg DueDiligenceConfig, findings []SecurityFindingInput) RegulatoryExposureAssessment {
	res := RegulatoryExposureAssessment{
		PreferredCurrency: "USD",
		LegalDisclaimer:   "LEGAL DISCLAIMER: Regulatory exposure figures are technical modeling estimations based on statutory maximum penalty schedules under GDPR (Regulation (EU) 2016/679) and India's Digital Personal Data Protection Act, 2023. These numbers do NOT constitute legal advice, a formal regulatory adjudication, or a prediction of actual fines from supervisory authorities.",
	}

	// Determine assessment date for commencement-aware statutory modeling
	assessmentDate := cfg.AssessmentDate
	if assessmentDate.IsZero() {
		assessmentDate = time.Now().UTC()
	}
	assessmentDateOnly := time.Date(assessmentDate.Year(), assessmentDate.Month(), assessmentDate.Day(), 0, 0, 0, 0, time.UTC)

	// 1. Evaluate GDPR (EU)
	turnoverEUR := cfg.AnnualRevenueEUR
	if turnoverEUR <= 0 && cfg.AnnualRevenueUSD > 0 {
		turnoverEUR = cfg.AnnualRevenueUSD * 0.92 // Approximate EUR conversion
	}
	if turnoverEUR <= 0 {
		turnoverEUR = 10000000.0 // Baseline €10M enterprise assumption if omitted
	}

	// Article 83(4): up to €10,000,000 or 2% worldwide turnover, whichever is higher
	art83_4 := math.Max(10000000.0, turnoverEUR*0.02)
	// Article 83(5): up to €20,000,000 or 4% worldwide turnover, whichever is higher
	art83_5 := math.Max(20000000.0, turnoverEUR*0.04)
	statMaxEUR := art83_5

	// Analyze finding severity to establish realistic GDPR scenarios
	critCount := 0
	highCount := 0
	hasPersonalDataExposure := false
	for _, f := range findings {
		if strings.EqualFold(f.Severity, DDSeverityCritical) {
			critCount++
			hasPersonalDataExposure = true
		} else if strings.EqualFold(f.Severity, DDSeverityHigh) {
			highCount++
			hasPersonalDataExposure = true
		}
	}

	var gdprConservativeEUR, gdprProbableEUR, gdprHighImpactEUR float64
	var applicableArticles []string

	applicableArticles = append(applicableArticles, "Article 32 (Security of Processing - technical and organisational measures)")
	if hasPersonalDataExposure {
		applicableArticles = append(applicableArticles, "Article 33 (Notification of a personal data breach to the supervisory authority)")
		applicableArticles = append(applicableArticles, "Article 5 (Principles relating to processing of personal data - integrity and confidentiality)")
	}

	if critCount > 0 {
		gdprConservativeEUR = math.Min(statMaxEUR, math.Max(50000.0, turnoverEUR*0.002))
		gdprProbableEUR = math.Min(statMaxEUR, math.Max(250000.0, turnoverEUR*0.010))
		gdprHighImpactEUR = math.Min(statMaxEUR, math.Max(1000000.0, turnoverEUR*0.025))
	} else if highCount > 0 {
		gdprConservativeEUR = math.Min(statMaxEUR, math.Max(25000.0, turnoverEUR*0.001))
		gdprProbableEUR = math.Min(statMaxEUR, math.Max(100000.0, turnoverEUR*0.005))
		gdprHighImpactEUR = math.Min(statMaxEUR, math.Max(500000.0, turnoverEUR*0.015))
	} else {
		gdprConservativeEUR = math.Min(statMaxEUR, 10000.0)
		gdprProbableEUR = math.Min(statMaxEUR, 25000.0)
		gdprHighImpactEUR = math.Min(statMaxEUR, 100000.0)
	}

	res.GDPR = GDPRExposureScenario{
		Jurisdiction:            "European Union (GDPR - Regulation (EU) 2016/679)",
		LegalSourceVersion:      "Regulation (EU) 2016/679 of the European Parliament and of the Council",
		LegalCommencementStatus: LegalStatusInForce,
		StatutoryEffectiveDate:  "2018-05-25",
		IsCurrentlyEnforceable:  true,
		StatutoryCeilingArt83_4: art83_4,
		StatutoryCeilingArt83_5: art83_5,
		StatutoryMaxCeilingEUR:  statMaxEUR,
		ConservativeScenarioEUR: math.Round(gdprConservativeEUR),
		ProbableScenarioEUR:     math.Round(gdprProbableEUR),
		HighImpactScenarioEUR:   math.Round(gdprHighImpactEUR),
		AnnualTurnoverEUR:       turnoverEUR,
		DataPrincipalsAffected:  cfg.DataPrincipalsCount,
		ApplicableArticles:      applicableArticles,
		CalculationAssumptions: []string{
			"Article 83 statutory maximums calculated based on global revenue turnover.",
			"Article 83(4) ceiling is max(€10M, 2% of annual turnover); Article 83(5) ceiling is max(€20M, 4% of annual turnover).",
			"Realistic scenarios reflect mitigating factors: proactive audit identification, lack of confirmed exfiltration, and technical scope.",
			"Statutory ceilings represent theoretical legislative maximums, not expected penalties.",
		},
	}

	// 2. Evaluate DPDP Act, 2023 (India)
	// Official Schedule to Section 33(1) of The Digital Personal Data Protection Act, 2023:
	// Item 1: Section 8(5) (failure to take reasonable security safeguards to prevent personal data breach): May extend to ₹250 crore.
	// Item 2: Section 8(6) (failure to notify Board & Data Principal of personal data breach): May extend to ₹200 crore.
	// Item 3: Section 9 (breach of additional obligations in relation to children): May extend to ₹200 crore.
	// Item 4: Section 10 (breach of additional obligations of Significant Data Fiduciary): May extend to ₹150 crore.
	// Item 5: Section 15 (breach in observance of duties of Data Principal): May extend to ₹10,000.
	// Item 6: Section 32 (breach of any term of voluntary undertaking accepted by the Board): Up to the extent applicable for the breach in respect of which proceedings under section 33 were instituted (no fixed rupee ceiling).
	// Item 7: Residual (breach of any other provision of this Act or rules made thereunder): May extend to ₹50 crore.
	sec8_5Cap := 2500000000.0     // ₹250 Crore
	sec8_6Cap := 2000000000.0     // ₹200 Crore
	sec9Cap := 2000000000.0       // ₹200 Crore (Official Statutory Schedule Item 3)
	sec10Cap := 1500000000.0      // ₹150 Crore
	sec15Cap := 10000.0           // ₹10,000
	secResidualCap := 500000000.0 // ₹50 Crore (Official Statutory Schedule Item 7)

	// Staged Commencement Evaluation pursuant to MeitY Notification G.S.R. 843(E) dated 13 November 2025:
	// Clause (a): 13 November 2025 -> Section 1(2), Section 2, Sections 18–26, Section 35, Sections 38–43, and Section 44(1) and (3)
	// Clause (b): 13 November 2026 -> Section 6(9) and Section 27(1)(d)
	// Clause (c): Eighteen months after publication (13 May 2027) -> Sections 3–5, Section 6(1)–(8) and (10), Sections 7–17, Section 27 except clause (d), Sections 28–34, Sections 36–37, and Section 44(2)
	stage1Effective := !assessmentDateOnly.Before(DPDPCommencementStage1)
	stage2Effective := !assessmentDateOnly.Before(DPDPCommencementStage2)
	stage3Effective := !assessmentDateOnly.Before(DPDPCommencementStage3)

	var actOverallStatus string
	if !stage1Effective {
		actOverallStatus = LegalStatusEnactedNotCommenced
	} else if !stage3Effective {
		actOverallStatus = LegalStatusPartiallyCommenced
	} else {
		actOverallStatus = LegalStatusInForce
	}

	stage1Status := LegalStatusScheduledToCommence
	if stage1Effective {
		stage1Status = LegalStatusInForce
	}
	stage2Status := LegalStatusScheduledToCommence
	if stage2Effective {
		stage2Status = LegalStatusInForce
	}
	stage3Status := LegalStatusScheduledToCommence
	if stage3Effective {
		stage3Status = LegalStatusInForce
	}

	// Substantive penalty framework effectiveness (Clause (c) - 13 May 2027)
	penaltyFrameworkStatus := LegalStatusScheduledToCommence
	isPenaltyEffective := false
	if stage3Effective {
		penaltyFrameworkStatus = LegalStatusInForce
		isPenaltyEffective = true
	}

	// Model each statutory penalty category separately pursuant to Section 33(1) and The Schedule
	scheduleCategories := []DPDPScheduleCategory{
		{
			ScheduleItemNumber:   1,
			ProvisionRef:         "Section 8(5)",
			ObligationSubject:    "Failure to take reasonable security safeguards to prevent personal data breach",
			StatutoryCeilingINR:  sec8_5Cap,
			StatutoryWording:     "May extend to two hundred and fifty crore rupees (₹250 crore)",
			IsApplicableToTarget: true,
			ApplicabilityReason:  "Primary technical security safeguard obligation for all Data Fiduciaries.",
		},
		{
			ScheduleItemNumber:   2,
			ProvisionRef:         "Section 8(6)",
			ObligationSubject:    "Failure to give Board or affected Data Principal intimation of personal data breach",
			StatutoryCeilingINR:  sec8_6Cap,
			StatutoryWording:     "May extend to two hundred crore rupees (₹200 crore)",
			IsApplicableToTarget: hasPersonalDataExposure,
			ApplicabilityReason:  "Applicable where confirmed data breach or unnotified personal data exposure occurs.",
		},
		{
			ScheduleItemNumber:   3,
			ProvisionRef:         "Section 9",
			ObligationSubject:    "Breach of additional obligations in relation to children",
			StatutoryCeilingINR:  sec9Cap,
			StatutoryWording:     "May extend to two hundred crore rupees (₹200 crore)",
			IsApplicableToTarget: cfg.ProcessesChildrenData,
			ApplicabilityReason:  "Applicable where target processes personal data belonging to children.",
		},
		{
			ScheduleItemNumber:   4,
			ProvisionRef:         "Section 10",
			ObligationSubject:    "Breach of additional obligations of Significant Data Fiduciary",
			StatutoryCeilingINR:  sec10Cap,
			StatutoryWording:     "May extend to one hundred and fifty crore rupees (₹150 crore)",
			IsApplicableToTarget: cfg.IsSignificantDataFiduciary,
			ApplicabilityReason:  "Applicable where entity is classified as Significant Data Fiduciary (DPO, DPIA, audit).",
		},
		{
			ScheduleItemNumber:   5,
			ProvisionRef:         "Section 15",
			ObligationSubject:    "Breach in observance of duties of Data Principal",
			StatutoryCeilingINR:  sec15Cap,
			StatutoryWording:     "May extend to ten thousand rupees (₹10,000)",
			IsApplicableToTarget: false,
			ApplicabilityReason:  "Applies to individual Data Principals, not corporate Data Fiduciaries.",
		},
		{
			ScheduleItemNumber:   6,
			ProvisionRef:         "Section 32",
			ObligationSubject:    "Breach of any term of voluntary undertaking accepted by the Board",
			StatutoryCeilingINR:  0.0,
			StatutoryWording:     "Up to the extent applicable for the breach in respect of which the proceedings under section 33 were instituted",
			IsApplicableToTarget: false,
			ApplicabilityReason:  "Applicable to the extent of the underlying breach in respect of which Section 33 proceedings were instituted (no independent fixed rupee ceiling).",
		},
		{
			ScheduleItemNumber:   7,
			ProvisionRef:         "Section 33(1) Residual",
			ObligationSubject:    "Breach of any other provision of this Act or rules made thereunder",
			StatutoryCeilingINR:  secResidualCap,
			StatutoryWording:     "May extend to fifty crore rupees (₹50 crore)",
			IsApplicableToTarget: false,
			ApplicabilityReason:  "Residual statutory category for uncategorized non-compliance.",
		},
	}

	provisionStages := []DPDPProvisionStatus{
		{
			ProvisionGroup:    "Clause (a): Preliminary, Definitions, Board Constitution & Powers",
			ProvisionsCovered: "Section 1(2), Section 2, Sections 18–26, Section 35, Sections 38–43, and Section 44(1) and (3)",
			CommencementDate:  "2025-11-13",
			Status:            stage1Status,
			IsEffective:       stage1Effective,
			Notes:             "Data Protection Board of India establishment, appointment, proceedings, powers to make rules, and preliminary provisions.",
		},
		{
			ProvisionGroup:    "Clause (b): Redressal Access & Information Requests",
			ProvisionsCovered: "Section 6(9) and Section 27(1)(d)",
			CommencementDate:  "2026-11-13",
			Status:            stage2Status,
			IsEffective:       stage2Effective,
			Notes:             "Data Principal grievance redressal access mechanism and Board inquiry calling for information.",
		},
		{
			ProvisionGroup:    "Clause (c): Substantive Obligations, Penalties & Remaining Provisions",
			ProvisionsCovered: "Sections 3–5, Section 6(1)–(8) and (10), Sections 7–17, Section 27 except clause (d), Sections 28–34, Sections 36–37, and Section 44(2)",
			CommencementDate:  "2027-05-13",
			Status:            stage3Status,
			IsEffective:       stage3Effective,
			Notes:             "Substantive security safeguards, children data protection, Significant Data Fiduciary obligations, voluntary undertakings, and Section 33 statutory monetary penalties.",
		},
	}

	// Calculate statutory ceiling across applicable distinct violations:
	// Section 33(1) ceilings represent separate statutory caps for distinct contraventions.
	statMaxINR := sec8_5Cap
	var applicableClauses []string
	applicableClauses = append(applicableClauses, "Schedule Item 1: Section 8(5) reasonable security safeguards (May extend to ₹250 Crore)")

	if hasPersonalDataExposure {
		applicableClauses = append(applicableClauses, "Schedule Item 2: Section 8(6) intimation of personal data breach (May extend to ₹200 Crore)")
		statMaxINR += sec8_6Cap
	}
	if cfg.ProcessesChildrenData {
		applicableClauses = append(applicableClauses, "Schedule Item 3: Section 9 additional obligations for children (May extend to ₹200 Crore)")
		statMaxINR += sec9Cap
	}
	if cfg.IsSignificantDataFiduciary {
		applicableClauses = append(applicableClauses, "Schedule Item 4: Section 10 Significant Data Fiduciary obligations (May extend to ₹150 Crore)")
		statMaxINR += sec10Cap
	}

	var dpdpConservativeINR, dpdpProbableINR, dpdpHighImpactINR float64
	if critCount > 0 {
		dpdpConservativeINR = 10000000.0 // ₹1 Crore
		dpdpProbableINR = 150000000.0    // ₹15 Crore
		dpdpHighImpactINR = 1000000000.0 // ₹100 Crore
	} else if highCount > 0 {
		dpdpConservativeINR = 2500000.0  // ₹25 Lakh
		dpdpProbableINR = 30000000.0     // ₹3 Crore
		dpdpHighImpactINR = 200000000.0  // ₹20 Crore
	} else {
		dpdpConservativeINR = 500000.0 // ₹5 Lakh
		dpdpProbableINR = 2000000.0    // ₹20 Lakh
		dpdpHighImpactINR = 10000000.0 // ₹1 Crore
	}

	var currentEnforceableMaxINR, currentEnforceableProbableINR float64
	if isPenaltyEffective {
		currentEnforceableMaxINR = statMaxINR
		currentEnforceableProbableINR = dpdpProbableINR
	} else {
		currentEnforceableMaxINR = 0.0
		currentEnforceableProbableINR = 0.0
	}

	penaltyFactors := []string{
		"Nature, gravity, and duration of the breach (Section 33(2)(a)).",
		"Type and nature of the personal data affected by the breach (Section 33(2)(b)).",
		"Repetitive nature of the breach (Section 33(2)(c)).",
		"Whether the data fiduciary realized any gain or avoided any loss as a result of the breach (Section 33(2)(d)).",
		"Mitigation actions taken to reduce consequences and timeliness/effectiveness of such action (Section 33(2)(e)).",
		"Proportionality and effectiveness of the proposed monetary penalty (Section 33(2)(f)).",
		"Likely financial impact on the entity being penalized (Section 33(2)(g)).",
	}

	dpdpAssumptions := []string{
		"Penalties are modeled from The Schedule pursuant to Section 33 of the DPDP Act, 2023.",
		"Statutory ceilings represent the legislative upper limit ('may extend to'); actual penalties are non-automatic and determined by the Data Protection Board of India pursuant to Section 33(2) factors.",
		"Summing applicable category ceilings represents a theoretical cumulative maximum across distinct infractions, not an automatic single fine applicable to an acquisition.",
		"Commencement staged pursuant to MeitY Notification G.S.R. 843(E) dated 13 November 2025: Clause (a) in force 13 Nov 2025; Clause (b) in force 13 Nov 2026; Clause (c) substantive obligations and Section 33 penalty framework in force 13 May 2027 (eighteen months after publication).",
	}
	if !isPenaltyEffective {
		dpdpAssumptions = append(dpdpAssumptions, fmt.Sprintf("COMMENCEMENT STATUS: As of the assessment date (%s), the Section 33 monetary penalty framework and The Schedule are not yet in force (scheduled to commence 13 May 2027 under Clause (c) of Notification G.S.R. 843(E)); monetary penalties under Section 33 are not currently enforceable at this time. However, the DPDP Act is %s with governance, definitions, and Data Protection Board establishment provisions in force under Clause (a), and other legal duties or broader statutory liabilities may apply. Projected penalties represent future statutory fine exposure upon 13 May 2027 commencement.", assessmentDate.Format("2006-01-02"), actOverallStatus))
	} else {
		dpdpAssumptions = append(dpdpAssumptions, fmt.Sprintf("COMMENCEMENT STATUS: As of the assessment date (%s), the Section 33 monetary penalty framework and The Schedule are %s following the 13 May 2027 statutory commencement date.", assessmentDate.Format("2006-01-02"), penaltyFrameworkStatus))
	}

	res.DPDP = DPDPExposureScenario{
		Jurisdiction:                  "India (The Digital Personal Data Protection Act, 2023)",
		LegalSourceVersion:            "The Digital Personal Data Protection Act, 2023 (Act No. 22 of 2023)",
		CommencementNotificationRef:   "Ministry of Electronics and Information Technology Notification G.S.R. 843(E) dated 13 November 2025",
		ActOverallStatus:              actOverallStatus,
		PenaltyFrameworkStatus:        penaltyFrameworkStatus,
		LegalCommencementStatus:       penaltyFrameworkStatus, // Backward-compatible alias
		StatutoryEffectiveDate:        "2027-05-13",
		AssessmentDate:                assessmentDate.Format("2006-01-02"),
		IsPenaltyEffective:            isPenaltyEffective,
		IsCurrentlyEnforceable:        isPenaltyEffective, // Backward-compatible alias
		CurrentEnforceableMaxINR:      currentEnforceableMaxINR,
		CurrentEnforceableProbableINR: currentEnforceableProbableINR,
		StatutoryCeilingSec8_5:        sec8_5Cap,
		StatutoryCeilingSec8_6:        sec8_6Cap,
		StatutoryCeilingSec9:          sec9Cap,
		StatutoryCeilingSec10:         sec10Cap,
		StatutoryCeilingSec15:         sec15Cap,
		StatutoryCeilingResidual:      secResidualCap,
		StatutoryMaxCeilingINR:        statMaxINR,
		ConservativeScenarioINR:       dpdpConservativeINR,
		ProbableScenarioINR:           dpdpProbableINR,
		HighImpactScenarioINR:         dpdpHighImpactINR,
		DataPrincipalsAffected:        cfg.DataPrincipalsCount,
		ProvisionStages:               provisionStages,
		ScheduleCategories:            scheduleCategories,
		ApplicableScheduleClauses:     applicableClauses,
		CalculationAssumptions:        dpdpAssumptions,
		PenaltyDeterminationFactors:   penaltyFactors,
	}

	// Currency conversion: EUR -> USD ~ 1.08; INR -> USD ~ 0.012
	probableEURinUSD := res.GDPR.ProbableScenarioEUR * 1.08
	probableINRinUSD := res.DPDP.ProbableScenarioINR * 0.012
	statMaxEURinUSD := res.GDPR.StatutoryMaxCeilingEUR * 1.08
	statMaxINRinUSD := res.DPDP.StatutoryMaxCeilingINR * 0.012

	if isPenaltyEffective {
		res.CurrentEnforceableProbableCostUSD = math.Round(probableEURinUSD + probableINRinUSD)
		res.CurrentEnforceableMaxCeilingUSD = math.Round(statMaxEURinUSD + statMaxINRinUSD)
	} else {
		res.CurrentEnforceableProbableCostUSD = math.Round(probableEURinUSD)
		res.CurrentEnforceableMaxCeilingUSD = math.Round(statMaxEURinUSD)
	}

	res.FutureProjectedProbableCostUSD = math.Round(probableEURinUSD + probableINRinUSD)
	res.FutureProjectedMaxCeilingUSD = math.Round(statMaxEURinUSD + statMaxINRinUSD)
	res.TotalProbableCostUSD = res.FutureProjectedProbableCostUSD

	return res
}

// CalculateAcquisitionRiskProfile compiles a multi-dimensional risk score and acquisition recommendation.
// Normalizes across evaluated dimensions so missing/unassessed dimensions do not silently dilute risk.
func CalculateAcquisitionRiskProfile(
	input DueDiligenceInput,
	debt TechnicalDebtAssessment,
	reg RegulatoryExposureAssessment,
) AcquisitionRiskProfile {
	var verifiedDefects, potentialCount, inconclusiveCount, notAssessedCount int
	criticalAssets := make(map[string]bool)

	var vulnScore, perimeterScore, cloudScore, mobileScore, debtScore, regScore float64

	// Track which dimensions were actively evaluated in this diligence scope
	evaluatedWeights := 0.0
	var coverageLimitations []string

	// 1. Vulnerability scoring (Weight: 0.30)
	evaluatedWeights += 0.30
	for _, f := range input.Findings {
		switch strings.ToUpper(strings.TrimSpace(f.Status)) {
		case DDStatusVerifiedDefect:
			verifiedDefects++
			switch strings.ToUpper(strings.TrimSpace(f.Severity)) {
			case DDSeverityCritical:
				vulnScore += 25.0
				criticalAssets[f.TargetURL] = true
			case DDSeverityHigh:
				vulnScore += 10.0
				criticalAssets[f.TargetURL] = true
			case DDSeverityMedium:
				vulnScore += 4.0
			case DDSeverityLow:
				vulnScore += 1.0
			}
		case DDStatusPotential:
			potentialCount++
			switch strings.ToUpper(strings.TrimSpace(f.Severity)) {
			case DDSeverityCritical:
				vulnScore += 6.25
			case DDSeverityHigh:
				vulnScore += 2.5
			case DDSeverityMedium:
				vulnScore += 1.0
			}
		case DDStatusInconclusive:
			inconclusiveCount++
		case DDStatusNotAssessed:
			notAssessedCount++
		}
	}
	vulnScore = math.Min(100.0, vulnScore)

	// 2. Perimeter scoring (Weight: 0.20)
	if len(input.Assets) > 0 {
		evaluatedWeights += 0.20
		for _, a := range input.Assets {
			if a.ExposureTier == ExposureAdminExposed {
				perimeterScore += 20.0
				criticalAssets[a.Identifier] = true
			} else if a.ExposureTier == ExposureInternalLeaked {
				perimeterScore += 15.0
			}
		}
		perimeterScore = math.Min(100.0, perimeterScore)
	} else {
		coverageLimitations = append(coverageLimitations, "Perimeter reconnaissance not evaluated (no discovered assets provided in scope)")
	}

	// 3. Cloud & BaaS scoring (Weight: 0.15)
	if len(input.CloudStorageIndicators) > 0 || len(input.BaaSIndicators) > 0 {
		evaluatedWeights += 0.15
		for _, c := range input.CloudStorageIndicators {
			classified := c
			if classified.ExposureClassification == "" {
				classified = ClassifyCloudStorageExposure(c)
			}
			if classified.ExposureClassification == ExposureMisconfigured {
				if classified.FindingSeverity == DDSeverityCritical {
					cloudScore += 50.0
				} else {
					cloudScore += 25.0
				}
				criticalAssets[c.BucketName] = true
			}
		}
		for _, b := range input.BaaSIndicators {
			classified := b
			if classified.ExposureClassification == "" {
				classified = ClassifyBaaSExposure(b)
			}
			if classified.ExposureClassification == ExposureMisconfigured {
				cloudScore += 50.0
				criticalAssets[b.InstanceID] = true
			}
		}
		cloudScore = math.Min(100.0, cloudScore)
	} else {
		coverageLimitations = append(coverageLimitations, "Cloud storage and BaaS backends not evaluated (no cloud/BaaS targets provided in scope)")
	}

	// 4. Mobile scoring (Weight: 0.15)
	if len(input.MobileApplications) > 0 {
		evaluatedWeights += 0.15
		for _, m := range input.MobileApplications {
			if m.CleartextTrafficPermitted {
				mobileScore += 20.0
			}
			if m.InsecureNetworkConfig {
				mobileScore += 20.0
			}
			mobileScore += float64(m.HardcodedSecretsCount) * 15.0
			if len(m.DangerousPermissions) > 5 {
				mobileScore += 15.0
			}
		}
		mobileScore = math.Min(100.0, mobileScore)
	} else {
		coverageLimitations = append(coverageLimitations, "Mobile application security not evaluated (no APK packages provided in scope)")
	}

	// 5. Technical debt scoring (Weight: 0.10)
	evaluatedWeights += 0.10
	if debt.TotalBaseHours > 300 {
		debtScore = 90.0
	} else if debt.TotalBaseHours > 120 {
		debtScore = 60.0
	} else if debt.TotalBaseHours > 40 {
		debtScore = 30.0
	} else if debt.TotalBaseHours > 0 {
		debtScore = 15.0
	}

	// 6. Regulatory scoring (Weight: 0.10)
	evaluatedWeights += 0.10
	if reg.TotalProbableCostUSD > 2000000 {
		regScore = 90.0
	} else if reg.TotalProbableCostUSD > 500000 {
		regScore = 60.0
	} else if reg.TotalProbableCostUSD > 100000 {
		regScore = 30.0
	} else {
		regScore = 10.0
	}

	// If there are explicit unassessed checks in findings
	if notAssessedCount > 0 {
		coverageLimitations = append(coverageLimitations, fmt.Sprintf("%d security checks marked NOT_ASSESSED; excluded from negative scoring to prevent artificial score suppression", notAssessedCount))
	}

	// Count critical/high defects and confirmed leaks for risk floor
	critDefectCount := 0
	highDefectCount := 0
	for _, f := range input.Findings {
		if strings.EqualFold(f.Status, DDStatusVerifiedDefect) {
			if strings.EqualFold(f.Severity, DDSeverityCritical) {
				critDefectCount++
			} else if strings.EqualFold(f.Severity, DDSeverityHigh) {
				highDefectCount++
			}
		}
	}
	confirmedLeakCount := 0
	for _, c := range input.CloudStorageIndicators {
		if c.ExposureClassification == ExposureMisconfigured {
			confirmedLeakCount++
		}
	}
	for _, b := range input.BaaSIndicators {
		if b.ExposureClassification == ExposureMisconfigured {
			confirmedLeakCount++
		}
	}

	// Weighted sum across all evaluated dimensions
	rawWeightedSum := (vulnScore * 0.30)
	if len(input.Assets) > 0 {
		rawWeightedSum += (perimeterScore * 0.20)
	}
	if len(input.CloudStorageIndicators) > 0 || len(input.BaaSIndicators) > 0 {
		rawWeightedSum += (cloudScore * 0.15)
	}
	if len(input.MobileApplications) > 0 {
		rawWeightedSum += (mobileScore * 0.15)
	}
	rawWeightedSum += (debtScore * 0.10)
	rawWeightedSum += (regScore * 0.10)

	// Normalize composite score over evaluated dimension weights to prevent dilution
	if evaluatedWeights <= 0 {
		evaluatedWeights = 1.0
	}
	normalizedComposite := rawWeightedSum / evaluatedWeights

	// Base risk floor for critical findings and confirmed data leaks:
	var riskFloor float64
	if critDefectCount >= 2 || (critDefectCount >= 1 && confirmedLeakCount >= 1) {
		riskFloor = 76.0 // Critical liability
	} else if critDefectCount >= 1 || confirmedLeakCount >= 1 || highDefectCount >= 2 {
		riskFloor = 52.0 // Elevated risk
	} else if highDefectCount >= 1 {
		riskFloor = 30.0 // Moderate risk
	}

	finalCompositeFloat := math.Max(normalizedComposite, riskFloor)
	composite := int(math.Round(math.Min(100.0, math.Max(0.0, finalCompositeFloat))))

	coverageRatio := math.Round(evaluatedWeights*100) / 100

	var grade, tier, recommendation, complexity string
	var drivers []string

	if composite <= 25 {
		grade = RiskGradeA
		tier = "LOW_RISK"
		recommendation = RecRecommendedClean
		complexity = "LOW"
		drivers = append(drivers, "Minimal technical debt and robust perimeter safeguards.")
	} else if composite <= 50 {
		grade = RiskGradeB
		tier = "MODERATE_RISK"
		recommendation = RecRecommendedWithEscrow
		complexity = "MEDIUM"
		drivers = append(drivers, "Standard security hygiene gaps; manageable technical debt addressable within 60 days.")
	} else if composite <= 75 {
		grade = RiskGradeC
		tier = "ELEVATED_RISK"
		recommendation = RecSignificantConditions
		complexity = "HIGH"
		drivers = append(drivers, "Significant verified vulnerabilities and architectural technical debt requiring escrow covenants.")
	} else {
		grade = RiskGradeD
		if composite > 85 {
			grade = RiskGradeF
		}
		tier = "CRITICAL_LIABILITY"
		recommendation = RecUnfavorableHighLiability
		complexity = "SEVERE_REFACTOR_REQUIRED"
		drivers = append(drivers, "Critical verified defects, open cloud/BaaS exposure, or substantial regulatory liability.")
	}

	if coverageRatio < 0.70 && notAssessedCount > 0 {
		drivers = append(drivers, fmt.Sprintf("Diligence coverage ratio is %.0f%%; %d checks were marked NOT_ASSESSED.", coverageRatio*100, notAssessedCount))
	}

	if verifiedDefects > 0 {
		drivers = append(drivers, fmt.Sprintf("%d verified security defects require pre-close remediation.", verifiedDefects))
	}
	if debt.TotalBaseHours > 100 {
		drivers = append(drivers, fmt.Sprintf("High technical debt burden of %.1f engineering hours ($%.0f USD).", debt.TotalBaseHours, debt.TotalBaseCostUSD))
	}
	if reg.TotalProbableCostUSD > 250000 {
		drivers = append(drivers, fmt.Sprintf("Substantial regulatory liability estimated at $%.0f USD across GDPR and DPDP.", reg.TotalProbableCostUSD))
	}

	var assetsList []string
	for a := range criticalAssets {
		assetsList = append(assetsList, a)
	}
	sort.Strings(assetsList)

	scoringExplanation := fmt.Sprintf("Composite score %d/100 computed via multi-dimensional analysis normalized over active evaluated weights (%.2f/1.00 coverage). Raw weighted score: %.1f, normalized: %.1f.", composite, evaluatedWeights, rawWeightedSum, normalizedComposite)
	if riskFloor > normalizedComposite {
		scoringExplanation += fmt.Sprintf(" Enforced risk floor %.0f applied due to confirmed critical defects/leaks.", riskFloor)
	}

	return AcquisitionRiskProfile{
		CompositeRiskScore:           composite,
		RiskGrade:                    grade,
		RiskTier:                     tier,
		PerimeterSubScore:            math.Round(perimeterScore*10) / 10,
		CloudBaaSSubScore:            math.Round(cloudScore*10) / 10,
		MobileSubScore:               math.Round(mobileScore*10) / 10,
		VulnerabilitySubScore:        math.Round(vulnScore*10) / 10,
		TechnicalDebtSubScore:        math.Round(debtScore*10) / 10,
		RegulatorySubScore:           math.Round(regScore*10) / 10,
		AssessmentCoverageRatio:      coverageRatio,
		CoverageLimitations:          coverageLimitations,
		ScoringMethodologyDisclaimer: "RISK SCORING DISCLAIMER: Composite risk score is normalized over evaluated dimensions so unassessed domains do not dilute risk. Unassessed checks do not reduce risk scores.",
		VerifiedDefectsCount:         verifiedDefects,
		PotentialFindingsCount:       potentialCount,
		InconclusiveChecksCount:      inconclusiveCount,
		NotAssessedChecksCount:       notAssessedCount,
		CriticalAssetsImpacted:       assetsList,
		IntegrationComplexityTier:    complexity,
		AcquisitionRecommendation:    recommendation,
		KeyRiskDrivers:               drivers,
		ScoringExplanation:           scoringExplanation,
	}
}

// GenerateExecutiveAcquisitionDossier synthesizes the complete 15-section acquisition dossier.
func GenerateExecutiveAcquisitionDossier(input DueDiligenceInput) (*ExecutiveAcquisitionDossier, error) {
	if fg := GetGlobalFeatureGate(); fg != nil {
		if err := fg.CheckFeature("report.due_diligence"); err != nil {
			return nil, fmt.Errorf("licensing refusal: %w", err)
		}
	}
	if strings.TrimSpace(input.Config.TargetEntityName) == "" && strings.TrimSpace(input.Config.RootDomain) == "" {
		return nil, errors.New("target entity name or root domain must be specified in due diligence config")
	}

	now := input.Config.AssessmentDate
	if now.IsZero() {
		now = input.ExecutionTimestamp
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	input.Config.AssessmentDate = now

	dossierID := fmt.Sprintf("DOSSIER-MA-%s-%d", sanitizeID(input.Config.RootDomain), now.Unix())

	// 1. Technical Debt Estimation
	techDebt := EstimateTechnicalDebt(input.Findings, input.Config.BlendedHourlyRateUSD)

	// 2. Regulatory Exposure Estimation
	regulatory := EstimateRegulatoryExposure(input.Config, input.Findings)

	// 3. Acquisition Risk Profiling
	riskProfile := CalculateAcquisitionRiskProfile(input, techDebt, regulatory)

	// 4. Classify Cloud Storage & BaaS
	var classifiedStorage []CloudStorageIndicator
	var confirmedStorageLeaks int
	for _, c := range input.CloudStorageIndicators {
		classified := ClassifyCloudStorageExposure(c)
		classifiedStorage = append(classifiedStorage, classified)
		if classified.ExposureClassification == ExposureMisconfigured {
			confirmedStorageLeaks++
		}
	}

	var classifiedBaaS []BaaSIndicator
	var confirmedBaaSLeaks int
	for _, b := range input.BaaSIndicators {
		classified := ClassifyBaaSExposure(b)
		classifiedBaaS = append(classifiedBaaS, classified)
		if classified.ExposureClassification == ExposureMisconfigured {
			confirmedBaaSLeaks++
		}
	}

	// 5. Build Attack Surface Highlights
	var techStack []string
	techMap := make(map[string]bool)
	var subdomainsCount, adminPortalsCount, apiEndpointsCount int
	for _, a := range input.Assets {
		if a.Type == AssetTypeSubdomain {
			subdomainsCount++
		} else if a.Type == AssetTypeAdminInterface {
			adminPortalsCount++
		} else if a.Type == AssetTypeAPIEndpoint {
			apiEndpointsCount++
		}
		for _, t := range a.TechnologyStack {
			if !techMap[t] {
				techMap[t] = true
				techStack = append(techStack, t)
			}
		}
	}
	sort.Strings(techStack)

	// 6. Build Prioritized Findings
	var priorityItems []DossierPriorityItem
	for i, f := range input.Findings {
		rank := i + 1
		dealImpact := "LOW_IMPACT"
		eta := "30-60 Days"
		if strings.EqualFold(f.Severity, DDSeverityCritical) {
			dealImpact = "ESCROW_CONDITIONAL"
			eta = "Immediate / Pre-Close"
		} else if strings.EqualFold(f.Severity, DDSeverityHigh) {
			dealImpact = "PRE_INTEGRATION_FIX"
			eta = "14-30 Days"
		}
		priorityItems = append(priorityItems, DossierPriorityItem{
			Rank:           rank,
			Title:          f.Title,
			Category:       f.Category,
			Severity:       f.Severity,
			Status:         f.Status,
			RemediationETA: eta,
			DealImpact:     dealImpact,
		})
	}

	// 7. Build Remediation Roadmap & Escrow
	var preClose, post30, post90, archUpgrades []string
	for _, f := range input.Findings {
		if strings.EqualFold(f.Severity, DDSeverityCritical) {
			preClose = append(preClose, fmt.Sprintf("%s: %s (Target: %s)", f.ID, f.Title, f.TargetURL))
		} else if strings.EqualFold(f.Severity, DDSeverityHigh) {
			post30 = append(post30, fmt.Sprintf("%s: %s", f.ID, f.Title))
		} else if strings.EqualFold(f.Severity, DDSeverityMedium) {
			post90 = append(post90, fmt.Sprintf("%s: %s", f.ID, f.Title))
		}
	}
	if confirmedStorageLeaks > 0 || confirmedBaaSLeaks > 0 {
		preClose = append(preClose, "Immediate access control remediation on exposed public cloud buckets and BaaS instances")
	}
	if techDebt.TotalBaseHours > 200 {
		archUpgrades = append(archUpgrades, "Comprehensive architecture modernization and dependency refactoring sprint")
	}

	// Configurable illustrative deal escrow multiplier (default 0.50)
	escrowMultiplier := input.Config.RegulatoryEscrowMultiplier
	if escrowMultiplier <= 0 {
		escrowMultiplier = 0.50
	}
	technicalRemediationUpper := techDebt.TotalUpperCostUSD
	illustrativeRegulatory := regulatory.TotalProbableCostUSD
	recommendedEscrow := technicalRemediationUpper + (illustrativeRegulatory * escrowMultiplier)
	escrowRationale := fmt.Sprintf("Recommended escrow holdback of $%.0f USD combines upper-bound engineering remediation estimate ($%.0f USD) plus %.0f%% illustrative regulatory risk factor ($%.0f USD). Note: The %.0f%% multiplier is an illustrative contractual deal-making assumption and does not constitute statutory law.",
		recommendedEscrow, technicalRemediationUpper, escrowMultiplier*100, illustrativeRegulatory*escrowMultiplier, escrowMultiplier*100)

	dpdpSummary := fmt.Sprintf("DPDP Ceiling: ₹%.0f", regulatory.DPDP.StatutoryMaxCeilingINR)
	if !regulatory.DPDP.IsPenaltyEffective {
		dpdpSummary += fmt.Sprintf(" (Section 33 monetary penalty framework scheduled 13 May 2027; Act overall status is %s)", regulatory.DPDP.ActOverallStatus)
	}

	dossier := &ExecutiveAcquisitionDossier{
		SchemaVersion:    DueDiligenceSchemaVersion,
		DossierID:        dossierID,
		GeneratedAt:      now.Format(time.RFC3339),
		TargetEntityName: input.Config.TargetEntityName,
		TargetRootDomain: input.Config.RootDomain,

		Section1_ExecutiveSummary: DossierExecutiveSummarySection{
			TargetEntityName:         input.Config.TargetEntityName,
			RootDomain:               input.Config.RootDomain,
			RiskGrade:                riskProfile.RiskGrade,
			RiskTier:                 riskProfile.RiskTier,
			CompositeScore:           riskProfile.CompositeRiskScore,
			AcquisitionVerdict:       riskProfile.AcquisitionRecommendation,
			KeyStrategicConcerns:     riskProfile.KeyRiskDrivers,
			EstimatedRemediationCost: fmt.Sprintf("$%.0f - $%.0f USD (Base: $%.0f USD)", techDebt.TotalLowerCostUSD, techDebt.TotalUpperCostUSD, techDebt.TotalBaseCostUSD),
			EstimatedRemediationTime: fmt.Sprintf("%.1f - %.1f Engineering Hours", techDebt.TotalLowerHours, techDebt.TotalUpperHours),
			RegulatoryCeilingSummary: fmt.Sprintf("GDPR Max: €%.0f | %s", regulatory.GDPR.StatutoryMaxCeilingEUR, dpdpSummary),
			HeadlinePosture:          fmt.Sprintf("Target software entity exhibits %s with a composite risk score of %d/100 (%s). Diligence coverage ratio: %.0f%%.", riskProfile.RiskTier, riskProfile.CompositeRiskScore, riskProfile.RiskGrade, riskProfile.AssessmentCoverageRatio*100),
		},

		Section2_TargetAssessmentScope: DossierScopeSection{
			AuthorizedScope:      input.Config.AuthorizedScope,
			TestingMode:          "ZERO_CREDENTIAL_BLACK_BOX",
			PassiveDiscoveryOnly: input.Config.PassiveOnly,
			NonDestructiveGuarantees: []string{
				"Zero credentials utilized by default.",
				"No destructive exploitation or state-altering probes.",
				"No downloading, modification, or harvesting of private customer data.",
				"Strict adherence to Phase 9.4 pre-flight scope guardrails and safe dialing.",
			},
			ExcludedTargets: []string{"Out-of-scope third-party SaaS hosts", "Payment gateway provider endpoints"},
		},

		Section3_AssetInventory: input.Assets,

		Section4_ExternalAttackSurface: DossierAttackSurfaceSection{
			TotalDiscoveredAssets:    len(input.Assets),
			PublicDomainCount:        1,
			SubdomainCount:           subdomainsCount,
			ExposedAdminPortalsCount: adminPortalsCount,
			APIEndpointsCount:        apiEndpointsCount,
			IdentifiedTechnologies:   techStack,
			SurfaceHighlights: []string{
				fmt.Sprintf("%d total external assets cataloged across root domain %s.", len(input.Assets), input.Config.RootDomain),
				fmt.Sprintf("%d exposed administrative or management interfaces discovered.", adminPortalsCount),
			},
		},

		Section5_CloudAndBaaSExposure: DossierCloudBaaSSection{
			StorageIndicatorsCount: len(classifiedStorage),
			BaaSIndicatorsCount:    len(classifiedBaaS),
			ConfirmedBucketLeaks:   confirmedStorageLeaks,
			ConfirmedBaaSLeaks:     confirmedBaaSLeaks,
			StorageDetails:         classifiedStorage,
			BaaSDetails:            classifiedBaaS,
			Summary:                fmt.Sprintf("Evaluated %d cloud storage buckets and %d BaaS backends; %d confirmed open bucket exposures, %d confirmed BaaS rule misconfigurations.", len(classifiedStorage), len(classifiedBaaS), confirmedStorageLeaks, confirmedBaaSLeaks),
		},

		Section6_MobileAppAssessment: DossierMobileSection{
			ApplicationsEvaluated:    len(input.MobileApplications),
			HighestStaticRiskScore:   computeHighestMobileScore(input.MobileApplications),
			CleartextTrafficDetected: checkCleartextMobile(input.MobileApplications),
			HardcodedSecretsDetected: countHardcodedSecretsMobile(input.MobileApplications),
			Applications:             input.MobileApplications,
			Summary:                  fmt.Sprintf("Deconstructed %d mobile package(s); provenance: STATIC_BINARY_EXTRACTION_ONLY (no dynamic claims).", len(input.MobileApplications)),
		},

		Section7_CriticalSecurityFindings: input.Findings,
		Section8_TechnicalDebt:            techDebt,
		Section9_RemediationEstimates:     techDebt.EffortItems,
		Section10_RegulatoryExposure:      regulatory,

		Section11_AcquisitionIntegration: DossierIntegrationRiskSection{
			IntegrationComplexity:    riskProfile.IntegrationComplexityTier,
			NetworkIsolationRequired: riskProfile.CompositeRiskScore > 50,
			IdentityFederationRisks: []string{
				"Potential credential stuffing or token replay exposure across legacy auth endpoints.",
				"Role-based access control (RBAC) consistency across unified corporate directory.",
			},
			LegacyProtocolRisks: []string{
				"Insecure cleartext transmission in mobile endpoints.",
				"Potential unvalidated CORS configurations on development endpoints.",
			},
			RecommendedSafeguards: []string{
				"Establish network isolation boundary prior to VPC peering.",
				"Require MFA across all administrative and developer endpoints.",
				"Implement API gateway mediation for legacy target backends.",
			},
		},

		Section12_RiskPrioritization: priorityItems,

		Section13_EvidenceProvenance: DossierProvenanceSection{
			EngineVersion:           fmt.Sprintf("FELIX v%s M&A Due-Diligence Engine", DueDiligenceSchemaVersion),
			AttestationType:         "ED25519_CANONICAL_DIGEST",
			ZeroCredentialEnforced:  true,
			ScopeGuardrailsEnforced: true,
			LimitationsAndExclusions: []string{
				"Evaluation is limited to authorized external perimeter targets and provided mobile packages.",
				"Internal private corporate networks and third-party SaaS services were not directly penetrated.",
				"Dynamic mobile runtime instrumentation requires dedicated device emulation and was excluded from static review.",
				"Static binary deconstruction only for mobile APKs; dynamic instrumentation excluded from zero-credential scope.",
				"DPDP Act, 2023 provisions evaluated with awareness of Notification G.S.R. 843(E) staged commencement dates (13 Nov 2025, 13 Nov 2026, 13 May 2027).",
			},
			NonClaims: []string{
				"Do not claim 100% vulnerability discovery or absolute security guarantee.",
				"Regulatory exposure figures are analytical risk models, not legal advice.",
				"Engineering hours are technical debt estimates, not contractual quotes.",
				"Regulatory escrow multiplier is an illustrative contractual deal assumption, not statutory law.",
			},
		},

		Section14_RemediationRoadmap: DossierRemediationRoadmap{
			PreCloseMustFixItems:          preClose,
			PostClose30DayItems:           post30,
			PostClose90DayItems:           post90,
			ArchitecturalUpgrades:         archUpgrades,
			TechnicalRemediationCostUSD:   technicalRemediationUpper,
			StatutoryMaxLiabilityUSD:      regulatory.FutureProjectedMaxCeilingUSD,
			IllustrativeRegulatoryRiskUSD: illustrativeRegulatory,
			ConfiguredEscrowMultiplier:    escrowMultiplier,
			RecommendedEscrowUSD:          math.Round(recommendedEscrow),
			EscrowMethodologyRationale:    escrowRationale,
		},

		Section15_FinalAcquisitionRisk: riskProfile,
	}

	// Compute canonical digest
	canonBytes, hashHex, err := dossier.ToCanonicalJSON()
	if err == nil {
		dossier.CanonicalDigest = hashHex
		_ = canonBytes
	}

	return dossier, nil
}

func computeHighestMobileScore(apps []MobileAPKMetadata) int {
	highest := 0
	for _, a := range apps {
		if a.StaticRiskScore > highest {
			highest = a.StaticRiskScore
		}
	}
	return highest
}

func checkCleartextMobile(apps []MobileAPKMetadata) bool {
	for _, a := range apps {
		if a.CleartextTrafficPermitted {
			return true
		}
	}
	return false
}

func countHardcodedSecretsMobile(apps []MobileAPKMetadata) int {
	total := 0
	for _, a := range apps {
		total += a.HardcodedSecretsCount
	}
	return total
}

func sanitizeID(s string) string {
	clean := strings.ReplaceAll(s, ".", "-")
	clean = strings.ReplaceAll(clean, ":", "-")
	clean = strings.ReplaceAll(clean, "/", "")
	if clean == "" {
		return "unknown"
	}
	return clean
}

// -----------------------------------------------------------------------------
// Serialization & Export Formats
// -----------------------------------------------------------------------------

// ToJSON serializes the executive acquisition dossier to standard formatted JSON.
func (d *ExecutiveAcquisitionDossier) ToJSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(d); err != nil {
		return nil, err
	}
	return bytes.TrimSpace(buf.Bytes()), nil
}

// ToCanonicalJSON serializes the dossier deterministically and returns the bytes and canonical SHA-256 hash.
func (d *ExecutiveAcquisitionDossier) ToCanonicalJSON() ([]byte, string, error) {
	clone := *d
	clone.CanonicalDigest = ""

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(clone); err != nil {
		return nil, "", err
	}
	raw := bytes.TrimSpace(buf.Bytes())
	sum := sha256.Sum256(raw)
	hashHex := hex.EncodeToString(sum[:])
	return raw, hashHex, nil
}

// ToMarkdown generates an executive Markdown dossier report.
func (d *ExecutiveAcquisitionDossier) ToMarkdown() string {
	var sb strings.Builder

	sb.WriteString("# FELIX M&A TECHNICAL DUE-DILIGENCE & ACQUISITION DOSSIER\n\n")
	sb.WriteString(fmt.Sprintf("**Target Entity:** %s | **Root Domain:** %s\n", d.TargetEntityName, d.TargetRootDomain))
	sb.WriteString(fmt.Sprintf("**Generated At:** %s | **Dossier ID:** %s\n", d.GeneratedAt, d.DossierID))
	sb.WriteString(fmt.Sprintf("**Canonical Digest:** `%s`\n\n", d.CanonicalDigest))

	sb.WriteString("## 1. Executive Summary & Acquisition Posture\n\n")
	sb.WriteString(fmt.Sprintf("- **Acquisition Recommendation:** **%s**\n", d.Section1_ExecutiveSummary.AcquisitionVerdict))
	sb.WriteString(fmt.Sprintf("- **Risk Grade:** **%s** (Composite Score: **%d/100**)\n", d.Section1_ExecutiveSummary.RiskGrade, d.Section1_ExecutiveSummary.CompositeScore))
	sb.WriteString(fmt.Sprintf("- **Assessment Coverage:** **%.0f%%**\n", d.Section15_FinalAcquisitionRisk.AssessmentCoverageRatio*100))
	sb.WriteString(fmt.Sprintf("- **Estimated Remediation Cost:** %s\n", d.Section1_ExecutiveSummary.EstimatedRemediationCost))
	sb.WriteString(fmt.Sprintf("- **Estimated Engineering Hours:** %s\n", d.Section1_ExecutiveSummary.EstimatedRemediationTime))
	sb.WriteString(fmt.Sprintf("- **Regulatory Exposure:** %s\n\n", d.Section1_ExecutiveSummary.RegulatoryCeilingSummary))

	sb.WriteString("### Key Strategic Concerns\n")
	for _, c := range d.Section1_ExecutiveSummary.KeyStrategicConcerns {
		sb.WriteString(fmt.Sprintf("- %s\n", c))
	}
	sb.WriteString("\n")

	if len(d.Section15_FinalAcquisitionRisk.CoverageLimitations) > 0 {
		sb.WriteString("### Diligence Coverage Limitations\n")
		for _, lim := range d.Section15_FinalAcquisitionRisk.CoverageLimitations {
			sb.WriteString(fmt.Sprintf("- %s\n", lim))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("## 2. Technical Debt & Remediation Estimates\n\n")
	sb.WriteString(fmt.Sprintf("- **Total Base Hours:** %.1f hrs (Range: %.1f - %.1f hrs)\n", d.Section8_TechnicalDebt.TotalBaseHours, d.Section8_TechnicalDebt.TotalLowerHours, d.Section8_TechnicalDebt.TotalUpperHours))
	sb.WriteString(fmt.Sprintf("- **Projected Cost:** $%.0f USD (Range: $%.0f - $%.0f USD)\n\n", d.Section8_TechnicalDebt.TotalBaseCostUSD, d.Section8_TechnicalDebt.TotalLowerCostUSD, d.Section8_TechnicalDebt.TotalUpperCostUSD))

	sb.WriteString("## 3. Statutory Regulatory Exposure (GDPR & DPDP)\n\n")
	sb.WriteString(fmt.Sprintf("- **EU GDPR Statutory Ceiling:** €%.0f EUR (Status: %s, Effective: %s)\n", d.Section10_RegulatoryExposure.GDPR.StatutoryMaxCeilingEUR, d.Section10_RegulatoryExposure.GDPR.LegalCommencementStatus, d.Section10_RegulatoryExposure.GDPR.StatutoryEffectiveDate))
	sb.WriteString(fmt.Sprintf("- **India DPDP Act Overall Status:** %s | **Section 33 Penalty Framework:** %s (Scheduled Effective: %s)\n", d.Section10_RegulatoryExposure.DPDP.ActOverallStatus, d.Section10_RegulatoryExposure.DPDP.PenaltyFrameworkStatus, d.Section10_RegulatoryExposure.DPDP.StatutoryEffectiveDate))
	if !d.Section10_RegulatoryExposure.DPDP.IsPenaltyEffective {
		sb.WriteString("- **Section 33 Monetary Penalty Enforceability:** Not in force as of assessment date (Section 33 penalty framework scheduled to commence 13 May 2027; broader statutory compliance obligations under in-force provisions apply)\n")
	} else {
		sb.WriteString(fmt.Sprintf("- **Section 33 Current Enforceable Penalty Ceiling:** Up to ₹%.0f INR\n", d.Section10_RegulatoryExposure.DPDP.CurrentEnforceableMaxINR))
	}
	sb.WriteString(fmt.Sprintf("- **DPDP Projected Statutory Upper Ceiling:** ₹%.0f INR (Non-automatic; individual category caps apply pursuant to Section 33 factors)\n", d.Section10_RegulatoryExposure.DPDP.StatutoryMaxCeilingINR))
	sb.WriteString("### DPDP Schedule Breakdown (Statutory Maximum Caps):\n")
	for _, cat := range d.Section10_RegulatoryExposure.DPDP.ScheduleCategories {
		if cat.IsApplicableToTarget {
			sb.WriteString(fmt.Sprintf("  - **%s (%s):** %s (Max: ₹%.0f INR)\n", cat.ProvisionRef, cat.ObligationSubject, cat.StatutoryWording, cat.StatutoryCeilingINR))
		}
	}
	sb.WriteString(fmt.Sprintf("- **Combined Illustrative Probable Risk:** ~$%.0f USD\n\n", d.Section10_RegulatoryExposure.TotalProbableCostUSD))

	sb.WriteString("## 4. Remediation Roadmap & Recommended Escrow\n\n")
	sb.WriteString(fmt.Sprintf("- **Recommended Escrow Holdback:** **$%.0f USD** (Configured Multiplier: %.0f%%)\n", d.Section14_RemediationRoadmap.RecommendedEscrowUSD, d.Section14_RemediationRoadmap.ConfiguredEscrowMultiplier*100))
	sb.WriteString(fmt.Sprintf("- **Escrow Methodology:** %s\n\n", d.Section14_RemediationRoadmap.EscrowMethodologyRationale))
	sb.WriteString("### Pre-Close Must-Fix Items:\n")
	for _, item := range d.Section14_RemediationRoadmap.PreCloseMustFixItems {
		sb.WriteString(fmt.Sprintf("- %s\n", item))
	}
	sb.WriteString("\n")

	sb.WriteString("## 5. Non-Claims & Legal Disclaimer\n\n")
	sb.WriteString(fmt.Sprintf("> %s\n\n", d.Section10_RegulatoryExposure.LegalDisclaimer))
	sb.WriteString(fmt.Sprintf("> %s\n\n", d.Section8_TechnicalDebt.EstimationDisclaimer))
	sb.WriteString(fmt.Sprintf("> %s\n", d.Section15_FinalAcquisitionRisk.ScoringMethodologyDisclaimer))

	return sb.String()
}

// ToExecutiveHTML generates an executive HTML dossier report suitable for executive review.
func (d *ExecutiveAcquisitionDossier) ToExecutiveHTML() (string, error) {
	var buf strings.Builder

	buf.WriteString("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n")
	buf.WriteString("<meta charset=\"UTF-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
	buf.WriteString(fmt.Sprintf("<title>FELIX M&A Due Diligence - %s</title>\n", html.EscapeString(d.TargetEntityName)))
	buf.WriteString("<style>\n")
	buf.WriteString("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; margin: 0; padding: 24px; color: #1f2937; background: #f9fafb; }\n")
	buf.WriteString(".container { max-width: 1100px; margin: 0 auto; background: #fff; padding: 36px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }\n")
	buf.WriteString("h1 { color: #111827; border-bottom: 2px solid #e5e7eb; padding-bottom: 12px; margin-top: 0; }\n")
	buf.WriteString("h2 { color: #1f2937; margin-top: 28px; border-bottom: 1px solid #f3f4f6; padding-bottom: 6px; }\n")
	buf.WriteString(".badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 14px; }\n")
	buf.WriteString(".badge-a { background: #d1fae5; color: #065f46; }\n")
	buf.WriteString(".badge-b { background: #dbeafe; color: #1e40af; }\n")
	buf.WriteString(".badge-c { background: #fef3c7; color: #92400e; }\n")
	buf.WriteString(".badge-df { background: #fee2e2; color: #991b1b; }\n")
	buf.WriteString(".metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin: 20px 0; }\n")
	buf.WriteString(".metric-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 16px; }\n")
	buf.WriteString(".metric-val { font-size: 24px; font-weight: bold; color: #0f172a; margin-top: 4px; }\n")
	buf.WriteString("table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 14px; }\n")
	buf.WriteString("th, td { border: 1px solid #e2e8f0; padding: 10px; text-align: left; }\n")
	buf.WriteString("th { background: #f1f5f9; font-weight: 600; }\n")
	buf.WriteString(".disclaimer { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; margin: 24px 0; font-size: 13px; color: #78350f; }\n")
	buf.WriteString("</style>\n</head>\n<body>\n")

	buf.WriteString("<div class=\"container\">\n")
	buf.WriteString(fmt.Sprintf("<h1>FELIX M&A Technical Due-Diligence Dossier: %s</h1>\n", html.EscapeString(d.TargetEntityName)))
	buf.WriteString(fmt.Sprintf("<p><strong>Target Root Domain:</strong> %s | <strong>Dossier ID:</strong> %s | <strong>Generated:</strong> %s</p>\n", html.EscapeString(d.TargetRootDomain), html.EscapeString(d.DossierID), html.EscapeString(d.GeneratedAt)))

	// Executive Summary Cards
	badgeClass := "badge-b"
	if strings.Contains(d.Section1_ExecutiveSummary.RiskGrade, "A") {
		badgeClass = "badge-a"
	} else if strings.Contains(d.Section1_ExecutiveSummary.RiskGrade, "C") {
		badgeClass = "badge-c"
	} else if strings.Contains(d.Section1_ExecutiveSummary.RiskGrade, "D") || strings.Contains(d.Section1_ExecutiveSummary.RiskGrade, "F") {
		badgeClass = "badge-df"
	}

	buf.WriteString("<div class=\"metric-grid\">\n")
	buf.WriteString(fmt.Sprintf("<div class=\"metric-card\"><div>Acquisition Verdict</div><div class=\"metric-val\"><span class=\"badge %s\">%s</span></div></div>\n", badgeClass, html.EscapeString(d.Section1_ExecutiveSummary.AcquisitionVerdict)))
	buf.WriteString(fmt.Sprintf("<div class=\"metric-card\"><div>Composite Risk Score</div><div class=\"metric-val\">%d / 100 (%s)</div></div>\n", d.Section1_ExecutiveSummary.CompositeScore, html.EscapeString(d.Section1_ExecutiveSummary.RiskGrade)))
	buf.WriteString(fmt.Sprintf("<div class=\"metric-card\"><div>Technical Debt Burden</div><div class=\"metric-val\">%s</div></div>\n", html.EscapeString(d.Section1_ExecutiveSummary.EstimatedRemediationCost)))
	buf.WriteString(fmt.Sprintf("<div class=\"metric-card\"><div>Recommended Escrow</div><div class=\"metric-val\">$%.0f USD</div></div>\n", d.Section14_RemediationRoadmap.RecommendedEscrowUSD))
	buf.WriteString("</div>\n")

	// Key Concerns
	buf.WriteString("<h2>1. Key Strategic Concerns</h2>\n<ul>\n")
	for _, c := range d.Section1_ExecutiveSummary.KeyStrategicConcerns {
		buf.WriteString(fmt.Sprintf("<li>%s</li>\n", html.EscapeString(c)))
	}
	buf.WriteString("</ul>\n")

	// Technical Debt
	buf.WriteString("<h2>2. Technical Debt & Remediation Engineering Hours</h2>\n")
	buf.WriteString(fmt.Sprintf("<p>Base Remediation Hours: <strong>%.1f hours</strong> (Range: %.1f - %.1f hours) at blended $%.2f/hr.</p>\n", d.Section8_TechnicalDebt.TotalBaseHours, d.Section8_TechnicalDebt.TotalLowerHours, d.Section8_TechnicalDebt.TotalUpperHours, d.Section8_TechnicalDebt.BlendedHourlyRateUSD))
	buf.WriteString("<table>\n<tr><th>Severity</th><th>Findings</th><th>Lower Hours</th><th>Base Hours</th><th>Upper Hours</th><th>Base Cost (USD)</th></tr>\n")
	for sev, hr := range d.Section8_TechnicalDebt.EffortBySeverity {
		buf.WriteString(fmt.Sprintf("<tr><td><strong>%s</strong></td><td>%d</td><td>%.1f</td><td>%.1f</td><td>%.1f</td><td>$%.0f</td></tr>\n", html.EscapeString(sev), hr.FindingCount, hr.LowerHours, hr.BaseHours, hr.UpperHours, hr.BaseCostUSD))
	}
	buf.WriteString("</table>\n")

	// Regulatory
	buf.WriteString("<h2>3. Statutory Regulatory Exposure</h2>\n")
	buf.WriteString("<table>\n<tr><th>Regulatory Regime</th><th>Statutory Status</th><th>Statutory Maximum Ceiling</th><th>Conservative Scenario</th><th>Probable Scenario</th><th>High Impact Scenario</th></tr>\n")
	buf.WriteString(fmt.Sprintf("<tr><td><strong>EU GDPR</strong></td><td>%s (Eff: %s)</td><td>€%.0f EUR</td><td>€%.0f EUR</td><td>€%.0f EUR</td><td>€%.0f EUR</td></tr>\n", html.EscapeString(d.Section10_RegulatoryExposure.GDPR.LegalCommencementStatus), html.EscapeString(d.Section10_RegulatoryExposure.GDPR.StatutoryEffectiveDate), d.Section10_RegulatoryExposure.GDPR.StatutoryMaxCeilingEUR, d.Section10_RegulatoryExposure.GDPR.ConservativeScenarioEUR, d.Section10_RegulatoryExposure.GDPR.ProbableScenarioEUR, d.Section10_RegulatoryExposure.GDPR.HighImpactScenarioEUR))
	buf.WriteString(fmt.Sprintf("<tr><td><strong>India DPDP Act</strong></td><td>%s (Penalties: %s; Eff: %s)</td><td>₹%.0f INR</td><td>₹%.0f INR</td><td>₹%.0f INR</td><td>₹%.0f INR</td></tr>\n", html.EscapeString(d.Section10_RegulatoryExposure.DPDP.ActOverallStatus), html.EscapeString(d.Section10_RegulatoryExposure.DPDP.PenaltyFrameworkStatus), html.EscapeString(d.Section10_RegulatoryExposure.DPDP.StatutoryEffectiveDate), d.Section10_RegulatoryExposure.DPDP.StatutoryMaxCeilingINR, d.Section10_RegulatoryExposure.DPDP.ConservativeScenarioINR, d.Section10_RegulatoryExposure.DPDP.ProbableScenarioINR, d.Section10_RegulatoryExposure.DPDP.HighImpactScenarioINR))
	buf.WriteString("</table>\n")

	// Disclaimers
	buf.WriteString("<div class=\"disclaimer\">\n")
	buf.WriteString(fmt.Sprintf("<strong>Statutory & Legal Disclaimer:</strong> %s<br><br>\n", html.EscapeString(d.Section10_RegulatoryExposure.LegalDisclaimer)))
	buf.WriteString(fmt.Sprintf("<strong>Technical Debt Disclaimer:</strong> %s<br><br>\n", html.EscapeString(d.Section8_TechnicalDebt.EstimationDisclaimer)))
	buf.WriteString(fmt.Sprintf("<strong>Scoring Methodology Disclaimer:</strong> %s\n", html.EscapeString(d.Section15_FinalAcquisitionRisk.ScoringMethodologyDisclaimer)))
	buf.WriteString("</div>\n")

	buf.WriteString(fmt.Sprintf("<p style=\"font-size:12px; color:#64748b;\">Canonical SHA-256 Digest: <code>%s</code> | Spec Version: %s</p>\n", html.EscapeString(d.CanonicalDigest), DueDiligenceSchemaVersion))
	buf.WriteString("</div>\n</body>\n</html>\n")

	return buf.String(), nil
}
