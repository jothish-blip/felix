package compliance

import (
	"strings"
	"time"
)

// LimitationCategory categorizes the technical or operational nature of an assessment limitation.
type LimitationCategory string

const (
	LimitationCategoryScope                  LimitationCategory = "scope"
	LimitationCategoryCoverage               LimitationCategory = "coverage"
	LimitationCategoryEvidence               LimitationCategory = "evidence"
	LimitationCategoryMapping                LimitationCategory = "mapping"
	LimitationCategoryEvaluation             LimitationCategory = "evaluation"
	LimitationCategoryIntegrity              LimitationCategory = "integrity"
	LimitationCategoryMethodology            LimitationCategory = "methodology"
	LimitationCategoryExternalValidation     LimitationCategory = "external_validation"
	LimitationCategoryCertification          LimitationCategory = "certification"
	LimitationCategoryUnsupportedRequirement LimitationCategory = "unsupported_requirement"
)

// CanonicalLimitationCategory validates and normalizes a limitation category string.
func CanonicalLimitationCategory(s string) (LimitationCategory, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "scope":
		return LimitationCategoryScope, true
	case "coverage":
		return LimitationCategoryCoverage, true
	case "evidence":
		return LimitationCategoryEvidence, true
	case "mapping":
		return LimitationCategoryMapping, true
	case "evaluation":
		return LimitationCategoryEvaluation, true
	case "integrity":
		return LimitationCategoryIntegrity, true
	case "methodology":
		return LimitationCategoryMethodology, true
	case "external_validation":
		return LimitationCategoryExternalValidation, true
	case "certification":
		return LimitationCategoryCertification, true
	case "unsupported_requirement":
		return LimitationCategoryUnsupportedRequirement, true
	default:
		return "", false
	}
}

// LimitationSeverity indicates the technical significance and potential for overclaiming compliance.
type LimitationSeverity string

const (
	LimitationSeverityInfo     LimitationSeverity = "INFO"
	LimitationSeverityWarning  LimitationSeverity = "WARNING"
	LimitationSeverityCritical LimitationSeverity = "CRITICAL"
)

// CanonicalLimitationSeverity validates and normalizes a limitation severity string.
func CanonicalLimitationSeverity(s string) (LimitationSeverity, bool) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "INFO":
		return LimitationSeverityInfo, true
	case "WARNING":
		return LimitationSeverityWarning, true
	case "CRITICAL":
		return LimitationSeverityCritical, true
	default:
		return "", false
	}
}

// ComplianceLimitation represents an authoritative, typed limitation or evidence boundary record.
type ComplianceLimitation struct {
	ID           string             `json:"id"`                      // Stable code, e.g. "LIM-COV-UNASSESSED", "LIM-CERT-DISCLAIMER"
	Category     LimitationCategory `json:"category"`                // scope, coverage, evidence, etc.
	Severity     LimitationSeverity `json:"severity"`                // INFO, WARNING, CRITICAL
	Title        string             `json:"title"`                   // Short human-readable summary
	Description  string             `json:"description"`             // Detailed explanation of limitation and technical implications
	AffectedItem string             `json:"affected_item,omitempty"` // Control ID, assessment ID, evidence ref, or catalog identity
	Impacts      []string           `json:"impacts,omitempty"`       // coverage, confidence, integrity, determination
	Remediation  string             `json:"remediation,omitempty"`   // What actions/external verifications are required to resolve
	Source       string             `json:"source,omitempty"`        // Component that emitted the limitation
	DeclaredAt   *time.Time         `json:"declared_at,omitempty"`   // Optional declaration timestamp
}

// CoverageBasis provides transparent, explicit mathematical basis for coverage calculations.
type CoverageBasis struct {
	TotalCatalogControls         int     `json:"total_catalog_controls"`
	ApplicableControls           int     `json:"applicable_controls"`
	NotApplicableControls        int     `json:"not_applicable_controls"`
	AssessedControls             int     `json:"assessed_controls"`
	UnassessedControls           int     `json:"unassessed_controls"`
	CompliantControls            int     `json:"compliant_controls"`
	NonCompliantControls         int     `json:"non_compliant_controls"`
	PartiallyCompliantControls   int     `json:"partially_compliant_controls"`
	InsufficientEvidenceControls int     `json:"insufficient_evidence_controls"`
	ErrorControls                int     `json:"error_controls"`
	AssessedCoveragePercent      float64 `json:"assessed_coverage_percent"`
	ComplianceRatePercent        float64 `json:"compliance_rate_percent"`
	BasisFormula                 string  `json:"basis_formula"`
	DenominatorDescription       string  `json:"denominator_description"`
	CoverageConfidence           string  `json:"coverage_confidence"` // "COMPLETE", "PARTIAL", "LIMITED"
	LimitationsSummary           string  `json:"limitations_summary,omitempty"`
}

// DeterminationBoundaryStatement encapsulates the clear statutory and technical distinctions
// between technical evidence, control evaluations, policy decisions, and regulatory certification.
type DeterminationBoundaryStatement struct {
	TechnicalEvidenceNotice string `json:"technical_evidence_notice"`
	ControlMappingNotice    string `json:"control_mapping_notice"`
	ControlEvaluationNotice string `json:"control_evaluation_notice"`
	AssessmentCoverageBasis string `json:"assessment_coverage_basis"`
	PolicyGateNotice        string `json:"policy_gate_notice"`
	FormalCertificationNote string `json:"formal_certification_disclaimer"`
}

// StandardDeterminationBoundaryStatement returns the canonical determination boundary declarations for FELIX.
func StandardDeterminationBoundaryStatement() DeterminationBoundaryStatement {
	return DeterminationBoundaryStatement{
		TechnicalEvidenceNotice: "Technical evidence consists of empirical observations gathered from scanners, configuration checks, API responses, or system logs. The presence or absence of specific technical findings does NOT independently establish compliance or non-compliance with broad regulatory or organizational security controls.",
		ControlMappingNotice:    "Finding-to-control mapping reflects heuristic or rule-based associations between observed security weaknesses and catalog requirements. A control mapping relationship establishes contextual relevance, NOT verified satisfaction or violation of the mapped control requirement.",
		ControlEvaluationNotice: "Control evaluations reflect automated technical assessments strictly bounded to defined test procedures and available evidence across seven discrete evaluation states. Evaluator outcomes cannot extrapolate beyond the empirical scope tested.",
		AssessmentCoverageBasis: "Assessment coverage is calculated strictly against applicable controls within the defined assessment scope. Controls not assessed, marked not applicable, or lacking sufficient evidence are explicitly disclosed and excluded from compliance percentage numerators.",
		PolicyGateNotice:        "CI/CD compliance gates evaluate whether automated test results satisfy configured technical thresholds. A passing compliance gate indicates acceptance under local automated policy; it does NOT constitute regulatory certification, external accreditation, or statutory compliance.",
		FormalCertificationNote: FormalCertificationDisclaimer(),
	}
}

// FormalCertificationDisclaimer returns the authoritative declaration that FELIX does NOT grant formal regulatory certification.
func FormalCertificationDisclaimer() string {
	return "FELIX Statutory Disclaimer: Automated technical security assessments, compliance dossiers, OSCAL exports, and CI/CD gate passes produced by FELIX do NOT constitute a formal regulatory certification, statutory audit accreditation, legal indemnification, or proof of complete organizational compliance with NIST, ISO, SOC 2, HIPAA, PCI-DSS, or any other compliance framework. Formal regulatory compliance requires accredited independent third-party audit, physical and administrative control verification, and authorized certifying official determination."
}
