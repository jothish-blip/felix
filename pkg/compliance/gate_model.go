package compliance

import (
	"strings"
	"time"
)

// CurrentComplianceGateSchemaVersion defines the canonical version of the FELIX compliance gate policy schema.
const CurrentComplianceGateSchemaVersion = "1.0"

// GateDecisionStatus represents the conclusive decision status of the compliance gate.
type GateDecisionStatus string

const (
	// GateStatusPassed: All enforced conditions satisfied; zero violations established (Exit 0).
	GateStatusPassed GateDecisionStatus = "PASSED"

	// GateStatusPolicyFailed: Trustworthy completed evaluation established compliance policy violations (Exit 1).
	GateStatusPolicyFailed GateDecisionStatus = "POLICY_FAILED"

	// GateStatusOperationalFailed: Operational error, missing inputs, corrupt records, or incomplete assessment (Exit 2).
	GateStatusOperationalFailed GateDecisionStatus = "OPERATIONAL_FAILED"

	// GateStatusIndeterminate: Uncertain assessment outcome where policy fails closed or indeterminate (Exit 2).
	GateStatusIndeterminate GateDecisionStatus = "INDETERMINATE"
)

// ComplianceGatePolicy defines a declarative, evidence-backed compliance gating policy.
type ComplianceGatePolicy struct {
	SchemaVersion              string   `json:"schema_version"`
	ID                         string   `json:"id"`
	Name                       string   `json:"name,omitempty"`
	Version                    string   `json:"version"`
	Description                string   `json:"description,omitempty"`
	TargetCatalog              string   `json:"target_catalog,omitempty"`
	TargetCatalogVersion       string   `json:"target_catalog_version,omitempty"`
	EnforcedControls           []string `json:"enforced_controls,omitempty"`
	EnforcedCategories         []string `json:"enforced_categories,omitempty"`
	PartiallyCompliantPolicy   string   `json:"partially_compliant_policy,omitempty"`   // "fail" (default), "allow"
	UnassessedPolicy           string   `json:"unassessed_policy,omitempty"`            // "fail_closed" (default), "indeterminate", "allow"
	InsufficientEvidencePolicy string   `json:"insufficient_evidence_policy,omitempty"` // "fail_closed" (default), "indeterminate", "allow"
	NotApplicablePolicy        string   `json:"not_applicable_policy,omitempty"`        // "ignore" (default), "fail"
	MaxNonCompliant            *int     `json:"max_non_compliant,omitempty"`            // default 0
	MaxPartiallyCompliant      *int     `json:"max_partially_compliant,omitempty"`      // default 0
	MinCompliancePercent       *float64 `json:"min_compliance_percent,omitempty"`       // default 100.0
	MinAssessedPercent         *float64 `json:"min_assessed_percent,omitempty"`         // default 100.0
	MaxFindingSeverity         string   `json:"max_finding_severity,omitempty"`         // optional ceiling, e.g. "MEDIUM"
	RequireIntegrity           *bool    `json:"require_integrity,omitempty"`            // default false
	RequireHMAC                *bool    `json:"require_hmac,omitempty"`                 // default false
	StrictIntegrity            *bool    `json:"strict_integrity,omitempty"`             // default false
	FailOnOverdueSLA           *bool    `json:"fail_on_overdue_sla,omitempty"`          // default false
	MaxOverdueSLA              *int     `json:"max_overdue_sla,omitempty"`              // default 0
}

// GetPartiallyCompliantPolicy returns the canonical policy for partially compliant controls ("fail" or "allow").
func (p *ComplianceGatePolicy) GetPartiallyCompliantPolicy() string {
	s := strings.ToLower(strings.TrimSpace(p.PartiallyCompliantPolicy))
	if s == "" {
		return "fail"
	}
	return s
}

// GetUnassessedPolicy returns the canonical policy for unassessed controls ("fail_closed", "indeterminate", "allow").
func (p *ComplianceGatePolicy) GetUnassessedPolicy() string {
	s := strings.ToLower(strings.TrimSpace(p.UnassessedPolicy))
	if s == "" {
		return "fail_closed"
	}
	return s
}

// GetInsufficientEvidencePolicy returns the policy for inconclusive evidence ("fail_closed", "indeterminate", "allow").
func (p *ComplianceGatePolicy) GetInsufficientEvidencePolicy() string {
	s := strings.ToLower(strings.TrimSpace(p.InsufficientEvidencePolicy))
	if s == "" {
		return "fail_closed"
	}
	return s
}

// GetNotApplicablePolicy returns the canonical policy for not applicable controls ("ignore" or "fail").
func (p *ComplianceGatePolicy) GetNotApplicablePolicy() string {
	s := strings.ToLower(strings.TrimSpace(p.NotApplicablePolicy))
	if s == "" {
		return "ignore"
	}
	return s
}

// GetMaxNonCompliant returns the maximum allowable non-compliant controls (default: 0).
func (p *ComplianceGatePolicy) GetMaxNonCompliant() int {
	if p.MaxNonCompliant == nil {
		return 0
	}
	return *p.MaxNonCompliant
}

// GetMaxPartiallyCompliant returns the maximum allowable partially compliant controls (default: 0).
func (p *ComplianceGatePolicy) GetMaxPartiallyCompliant() int {
	if p.MaxPartiallyCompliant == nil {
		return 0
	}
	return *p.MaxPartiallyCompliant
}

// GetMinCompliancePercent returns the minimum compliance percentage (default: 100.0).
func (p *ComplianceGatePolicy) GetMinCompliancePercent() float64 {
	if p.MinCompliancePercent == nil {
		return 100.0
	}
	return *p.MinCompliancePercent
}

// GetMinAssessedPercent returns the minimum assessed coverage percentage (default: 100.0).
func (p *ComplianceGatePolicy) GetMinAssessedPercent() float64 {
	if p.MinAssessedPercent == nil {
		return 100.0
	}
	return *p.MinAssessedPercent
}

// GetRequireIntegrity returns whether content integrity is required.
func (p *ComplianceGatePolicy) GetRequireIntegrity() bool {
	if p.RequireIntegrity == nil {
		return false
	}
	return *p.RequireIntegrity
}

// GetRequireHMAC returns whether HMAC cryptographic authenticity is required.
func (p *ComplianceGatePolicy) GetRequireHMAC() bool {
	if p.RequireHMAC == nil {
		return false
	}
	return *p.RequireHMAC
}

// GetStrictIntegrity returns whether missing keys or verification failures fail closed.
func (p *ComplianceGatePolicy) GetStrictIntegrity() bool {
	if p.StrictIntegrity == nil {
		return false
	}
	return *p.StrictIntegrity
}

// GetFailOnOverdueSLA returns whether overdue remediation SLAs fail the gate.
func (p *ComplianceGatePolicy) GetFailOnOverdueSLA() bool {
	if p.FailOnOverdueSLA == nil {
		return false
	}
	return *p.FailOnOverdueSLA
}

// GetMaxOverdueSLA returns the maximum allowable overdue remediations (default: 0).
func (p *ComplianceGatePolicy) GetMaxOverdueSLA() int {
	if p.MaxOverdueSLA == nil {
		return 0
	}
	return *p.MaxOverdueSLA
}

// GateConditionResult details an individual condition evaluated by the compliance gate.
type GateConditionResult struct {
	Name     string `json:"name"`
	Category string `json:"category"` // "assessment_status", "integrity", "control_compliance", "thresholds", "sla"
	Target   string `json:"target,omitempty"`
	Status   string `json:"status"` // "PASSED", "FAILED", "INDETERMINATE", "SKIPPED"
	Message  string `json:"message"`
	Expected string `json:"expected,omitempty"`
	Actual   string `json:"actual,omitempty"`
}

// GateSummary summarizes the quantitative results of the compliance gate evaluation.
type GateSummary struct {
	TotalConditions              int     `json:"total_conditions"`
	PassedConditions             int     `json:"passed_conditions"`
	FailedConditions             int     `json:"failed_conditions"`
	IndeterminateConditions      int     `json:"indeterminate_conditions"`
	TotalControls                int     `json:"total_controls"`
	CompliantControls            int     `json:"compliant_controls"`
	NonCompliantControls         int     `json:"non_compliant_controls"`
	PartiallyCompliantControls   int     `json:"partially_compliant_controls"`
	NotAssessedControls          int     `json:"not_assessed_controls"`
	InsufficientEvidenceControls int     `json:"insufficient_evidence_controls"`
	NotApplicableControls        int     `json:"not_applicable_controls"`
	ErrorControls                int     `json:"error_controls"`
	CompliancePercent            float64 `json:"compliance_percent"`
	AssessedPercent              float64 `json:"assessed_percent"`
	OverdueSLACount              int     `json:"overdue_sla_count"`
}

// ComplianceGateResult captures the complete evaluation decision produced by the compliance gate.
type ComplianceGateResult struct {
	Decision               GateDecisionStatus           `json:"decision"`
	ExitCode               int                          `json:"exit_code"`
	Summary                GateSummary                  `json:"summary"`
	AssessmentID           string                       `json:"assessment_id"`
	ExecutionID            string                       `json:"execution_id,omitempty"`
	CatalogIdentity        string                       `json:"catalog_identity"`
	CatalogDigest          string                       `json:"catalog_digest"`
	MappingRuleSetIdentity string                       `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string                       `json:"mapping_ruleset_digest,omitempty"`
	PolicyID               string                       `json:"policy_id"`
	PolicyVersion          string                       `json:"policy_version"`
	PolicyName             string                       `json:"policy_name,omitempty"`
	EvaluatedAt            time.Time                    `json:"evaluated_at"`
	Violations             []string                     `json:"violations,omitempty"`
	OperationalErrors      []string                     `json:"operational_errors,omitempty"`
	IndeterminateReasons   []string                     `json:"indeterminate_reasons,omitempty"`
	Conditions             []GateConditionResult        `json:"conditions"`
	Integrity              *IntegrityVerificationResult `json:"integrity,omitempty"`
	StructuredLimitations  []ComplianceLimitation       `json:"structured_limitations,omitempty"`
	CoverageBasis          *CoverageBasis               `json:"coverage_basis,omitempty"`
	LimitationsNotice      string                       `json:"limitations_notice"`
}

// ComplianceGateLimitationsNotice returns the authoritative statutory limitations notice for compliance gates.
func ComplianceGateLimitationsNotice() string {
	return "FELIX Compliance Gate Notice: A passing compliance gate indicates that automated security assessment findings and evidence linkage satisfied the configured technical policy thresholds for the evaluated scope. A passing gate does NOT constitute a formal regulatory certification, statutory audit accreditation, legal indemnification, or guarantee of complete organizational security."
}
