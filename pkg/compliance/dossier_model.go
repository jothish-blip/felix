package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CurrentDossierSchemaVersion defines the canonical version of the FELIX compliance dossier schema.
const CurrentDossierSchemaVersion = "felix.compliance.dossier.v1"

// DossierGenerationMode defines the integrity enforcement mode for dossier assembly.
type DossierGenerationMode string

const (
	// DossierModeDefault produces a dossier representing only verifiable data, logging explicit warnings
	// and partial completeness markers for unverified or failing source records.
	DossierModeDefault DossierGenerationMode = "DEFAULT"

	// DossierModeStrict fails closed immediately if any required source evaluation or remediation record
	// fails cryptographic integrity verification or exhibits evidence tampering.
	DossierModeStrict DossierGenerationMode = "STRICT"
)

// DossierCompletenessStatus represents the overall data completeness of the generated dossier snapshot.
type DossierCompletenessStatus string

const (
	DossierCompletenessComplete DossierCompletenessStatus = "COMPLETE"
	DossierCompletenessPartial  DossierCompletenessStatus = "PARTIAL"
	DossierCompletenessLimited  DossierCompletenessStatus = "LIMITED"
)

// DossierIdentity encapsulates authoritative metadata identifying the dossier snapshot.
type DossierIdentity struct {
	DossierID               string                    `json:"dossier_id"`
	SchemaVersion           string                    `json:"schema_version"`
	GeneratedAt             time.Time                 `json:"generated_at"`
	AssessmentID            string                    `json:"assessment_id"`
	ExecutionID             string                    `json:"execution_id,omitempty"`
	CatalogID               string                    `json:"catalog_id"`
	CatalogVersion          string                    `json:"catalog_version,omitempty"`
	CatalogDigest           string                    `json:"catalog_digest,omitempty"`
	MappingRuleSetID        string                    `json:"mapping_ruleset_id,omitempty"`
	MappingRuleSetVersion   string                    `json:"mapping_ruleset_version,omitempty"`
	MappingRuleSetDigest    string                    `json:"mapping_ruleset_digest,omitempty"`
	ApplicablePolicyID      string                    `json:"applicable_policy_id,omitempty"`
	ApplicablePolicyVersion string                    `json:"applicable_policy_version,omitempty"`
	FelixVersion            string                    `json:"felix_version,omitempty"`
	SourceRevision          string                    `json:"source_revision,omitempty"`
	GenerationMode          DossierGenerationMode     `json:"generation_mode"`
	CompletenessStatus      DossierCompletenessStatus `json:"completeness_status"`
}

// MTTRSummarySnapshot encapsulates a high-level MTTR snapshot embedded into the dossier summary.
type MTTRSummarySnapshot struct {
	HasData             bool   `json:"has_data"`
	CompletedEpisodes   int    `json:"completed_episodes"`
	UniqueFindings      int    `json:"unique_findings"`
	MTTRString          string `json:"mttr"`
	TotalDurationString string `json:"total_duration"`
	CoverageStatus      string `json:"coverage_status"`
}

// DossierAssessmentSummary provides aggregate quantitative metrics across all controls and findings.
type DossierAssessmentSummary struct {
	OverallStatus              string                 `json:"overall_status"`
	CompletionStatus           string                 `json:"completion_status"`
	TotalControls              int                    `json:"total_controls"`
	CompliantCount             int                    `json:"compliant_count"`
	NonCompliantCount          int                    `json:"non_compliant_count"`
	PartiallyCompliantCount    int                    `json:"partially_compliant_count"`
	NotAssessedCount           int                    `json:"not_assessed_count"`
	InsufficientEvidenceCount  int                    `json:"insufficient_evidence_count"`
	NotApplicableCount         int                    `json:"not_applicable_count"`
	ErrorCount                 int                    `json:"error_count"`
	ApplicableControls         int                    `json:"applicable_controls"`
	AssessedControls           int                    `json:"assessed_controls"`
	TotalFindings              int                    `json:"total_findings"`
	MappedFindings             int                    `json:"mapped_findings"`
	PartiallyMappedFindings    int                    `json:"partially_mapped_findings"`
	UnmappedFindings           int                    `json:"unmapped_findings"`
	AmbiguousFindings          int                    `json:"ambiguous_findings"`
	TotalEvidenceLinks         int                    `json:"total_evidence_links"`
	SupportingEvidenceCount    int                    `json:"supporting_evidence_count"`
	ContradictingEvidenceCount int                    `json:"contradicting_evidence_count"`
	VerifiedEvidenceCount      int                    `json:"verified_evidence_count"`
	UnverifiedEvidenceCount    int                    `json:"unverified_evidence_count"`
	TotalRemediations          int                    `json:"total_remediations"`
	OpenRemediations           int                    `json:"open_remediations"`
	InProgressRemediations     int                    `json:"in_progress_remediations"`
	RemediatedCount            int                    `json:"remediated_count"`
	AcceptedRiskCount          int                    `json:"accepted_risk_count"`
	ReopenedCount              int                    `json:"reopened_count"`
	OverdueRemediations        int                    `json:"overdue_remediations"`
	SLAPerformance             *SLAPerformanceMetrics `json:"sla_performance,omitempty"`
	MTTRSummary                *MTTRSummarySnapshot   `json:"mttr_summary,omitempty"`
	Limitations                []string               `json:"limitations,omitempty"`
}

// DossierMappedFindingRef links a control result to an identified security finding.
type DossierMappedFindingRef struct {
	FindingID       string              `json:"finding_id"`
	Relationship    MappingRelationship `json:"relationship"`
	FindingRuleID   string              `json:"finding_rule_id,omitempty"`
	FindingTitle    string              `json:"finding_title,omitempty"`
	FindingSeverity string              `json:"finding_severity,omitempty"`
}

// DossierControlRemediationSummary provides concise remediation status for a control.
type DossierControlRemediationSummary struct {
	RecordID     string                     `json:"record_id"`
	Status       RemediationLifecycleStatus `json:"status"`
	Severity     string                     `json:"severity"`
	Deadline     *time.Time                 `json:"deadline,omitempty"`
	IsOverdue    bool                       `json:"is_overdue"`
	CompletedAt  *time.Time                 `json:"completed_at,omitempty"`
	MetSLA       *bool                      `json:"met_sla,omitempty"`
	RiskAccepted bool                       `json:"risk_accepted"`
}

// DossierControlResult captures the complete, evidence-backed evaluation details for one control.
type DossierControlResult struct {
	ControlID                   string                            `json:"control_id"`
	ControlTitle                string                            `json:"control_title,omitempty"`
	CatalogID                   string                            `json:"catalog_id"`
	CatalogVersion              string                            `json:"catalog_version,omitempty"`
	Category                    string                            `json:"category,omitempty"`
	Severity                    string                            `json:"severity,omitempty"`
	EvaluationState             EvaluationState                   `json:"evaluation_state"`
	Rationale                   string                            `json:"rationale"`
	RequirementsEvaluated       []string                          `json:"requirements_evaluated,omitempty"`
	SupportingEvidence          []string                          `json:"supporting_evidence,omitempty"`
	ContradictingEvidence       []string                          `json:"contradicting_evidence,omitempty"`
	MissingOrUnverifiedEvidence []string                          `json:"missing_or_unverified_evidence,omitempty"`
	MappedFindings              []DossierMappedFindingRef         `json:"mapped_findings,omitempty"`
	Remediation                 *DossierControlRemediationSummary `json:"remediation,omitempty"`
	Limitations                 []string                          `json:"limitations,omitempty"`
	Errors                      []string                          `json:"errors,omitempty"`
}

// DossierFindingMappingRelationship specifies a finding's association to a control.
type DossierFindingMappingRelationship struct {
	ControlID    string              `json:"control_id"`
	Relationship MappingRelationship `json:"relationship"`
}

// DossierFindingEntry represents a consolidated finding in the dossier's finding register.
type DossierFindingEntry struct {
	FindingID            string                              `json:"finding_id"`
	FindingSource        string                              `json:"finding_source,omitempty"`
	RuleID               string                              `json:"rule_id,omitempty"`
	Title                string                              `json:"title"`
	Severity             string                              `json:"severity"`
	Category             string                              `json:"category,omitempty"`
	AssessmentID         string                              `json:"assessment_id"`
	ExecutionID          string                              `json:"execution_id,omitempty"`
	AssociatedControlIDs []string                            `json:"associated_control_ids,omitempty"`
	MappingRelationships []DossierFindingMappingRelationship `json:"mapping_relationships,omitempty"`
	EvidenceReferenceIDs []string                            `json:"evidence_reference_ids,omitempty"`
	RemediationRecordID  string                              `json:"remediation_record_id,omitempty"`
}

// DossierEvidenceEntry represents an empirical evidence reference in the dossier register.
type DossierEvidenceEntry struct {
	EvidenceID         string `json:"evidence_id"`
	EvidenceType       string `json:"evidence_type"` // "supporting", "contradicting", "reference", "finding", "positive"
	ReferenceID        string `json:"reference_id"`
	Source             string `json:"source,omitempty"`
	Description        string `json:"description,omitempty"`
	ControlID          string `json:"control_id"`
	FindingID          string `json:"finding_id,omitempty"`
	EvaluationID       string `json:"evaluation_id,omitempty"`
	VerificationStatus string `json:"verification_status"` // "VERIFIED", "UNVERIFIED", "UNAVAILABLE", "INTEGRITY_MISMATCH"
	Verified           bool   `json:"verified"`
}

// DossierRemediationEntry represents a remediation record in the dossier register.
type DossierRemediationEntry struct {
	RemediationID            string                     `json:"remediation_id"`
	FindingID                string                     `json:"finding_id"`
	ControlID                string                     `json:"control_id"`
	Status                   RemediationLifecycleStatus `json:"status"`
	Severity                 string                     `json:"severity"`
	AssignedAt               time.Time                  `json:"assigned_at"`
	SLAStartTime             time.Time                  `json:"sla_start_time"`
	Deadline                 time.Time                  `json:"deadline"`
	IsOverdue                bool                       `json:"is_overdue"`
	CompletedAt              *time.Time                 `json:"completed_at,omitempty"`
	ReopenCount              int                        `json:"reopen_count"`
	RiskAccepted             bool                       `json:"risk_accepted"`
	RiskAcceptanceRationale  string                     `json:"risk_acceptance_rationale,omitempty"`
	RiskAcceptanceApprovedBy string                     `json:"risk_acceptance_approved_by,omitempty"`
	PolicyID                 string                     `json:"policy_id,omitempty"`
	PolicyVersion            string                     `json:"policy_version,omitempty"`
	VerifiedCompletion       bool                       `json:"verified_completion"`
}

// DossierIntegrityStatement provides an audited summary of source data verification outcomes.
type DossierIntegrityStatement struct {
	VerifiedSourceRecords        []string           `json:"verified_source_records,omitempty"`
	UnverifiedLegacyRecords      []string           `json:"unverified_legacy_records,omitempty"`
	IntegrityFailures            []string           `json:"integrity_failures,omitempty"`
	CoverageStatus               string             `json:"coverage_status"` // "COMPLETE", "PARTIAL", "LIMITED"
	UnverifiedInputs             []string           `json:"unverified_inputs,omitempty"`
	EvaluationIntegrityStatus    VerificationStatus `json:"evaluation_integrity_status"`
	RemediationIntegrityStatus   VerificationStatus `json:"remediation_integrity_status,omitempty"`
	LimitationsNotice            string             `json:"limitations_notice"`
	DossierAuthenticityStatement string             `json:"dossier_authenticity_statement"`
}

// DefaultDossierAuthenticityStatement returns the standard distinction between source verification and snapshot authenticity.
func DefaultDossierAuthenticityStatement() string {
	return "FELIX Compliance Dossier Authenticity Notice: Source evaluation and remediation records were independently verified against database integrity metadata and cryptographic signatures where available. This dossier represents a point-in-time consolidated snapshot derived from those verified source records. Generating this dossier does not alter original assessment records or create an independent external cryptographic seal unless signed separately."
}

// ComplianceDossier represents a complete, evidence-backed, reproducible compliance assessment snapshot.
type ComplianceDossier struct {
	Identity              DossierIdentity           `json:"identity"`
	Summary               DossierAssessmentSummary  `json:"summary"`
	Controls              []DossierControlResult    `json:"controls"`
	Findings              []DossierFindingEntry     `json:"findings,omitempty"`
	Evidence              []DossierEvidenceEntry    `json:"evidence,omitempty"`
	Remediation           []DossierRemediationEntry `json:"remediation,omitempty"`
	Integrity             DossierIntegrityStatement `json:"integrity"`
	StructuredLimitations []ComplianceLimitation    `json:"structured_limitations,omitempty"`
	CoverageBasis         *CoverageBasis            `json:"coverage_basis,omitempty"`
	LogicalDigest         string                    `json:"logical_digest"`
}

// ComputeDossierLogicalDigest calculates a deterministic canonical SHA-256 digest over the dossier's logical content.
// Volatile fields (DossierID, GeneratedAt, FelixVersion, SourceRevision) are deliberately excluded to ensure
// identical source assessments produce the exact same logical digest.
func ComputeDossierLogicalDigest(d *ComplianceDossier) string {
	if d == nil {
		return ""
	}

	canonicalControls := make([]map[string]any, len(d.Controls))
	for i, c := range d.Controls {
		mapped := make([]string, len(c.MappedFindings))
		for j, mf := range c.MappedFindings {
			mapped[j] = fmt.Sprintf("%s:%s", mf.FindingID, mf.Relationship)
		}
		sort.Strings(mapped)

		supp := append([]string{}, c.SupportingEvidence...)
		sort.Strings(supp)
		contra := append([]string{}, c.ContradictingEvidence...)
		sort.Strings(contra)
		lims := append([]string{}, c.Limitations...)
		sort.Strings(lims)

		canonicalControls[i] = map[string]any{
			"control_id":       c.ControlID,
			"catalog_id":       c.CatalogID,
			"evaluation_state": string(c.EvaluationState),
			"rationale":        c.Rationale,
			"mapped_findings":  mapped,
			"supporting":       supp,
			"contradicting":    contra,
			"limitations":      lims,
		}
	}
	sort.SliceStable(canonicalControls, func(i, j int) bool {
		return canonicalControls[i]["control_id"].(string) < canonicalControls[j]["control_id"].(string)
	})

	canonicalFindings := make([]map[string]any, len(d.Findings))
	for i, f := range d.Findings {
		ctrls := append([]string{}, f.AssociatedControlIDs...)
		sort.Strings(ctrls)
		evs := append([]string{}, f.EvidenceReferenceIDs...)
		sort.Strings(evs)

		canonicalFindings[i] = map[string]any{
			"finding_id": f.FindingID,
			"severity":   strings.ToUpper(f.Severity),
			"controls":   ctrls,
			"evidence":   evs,
		}
	}
	sort.SliceStable(canonicalFindings, func(i, j int) bool {
		return canonicalFindings[i]["finding_id"].(string) < canonicalFindings[j]["finding_id"].(string)
	})

	canonicalEvidence := make([]map[string]any, len(d.Evidence))
	for i, e := range d.Evidence {
		canonicalEvidence[i] = map[string]any{
			"evidence_id":         e.EvidenceID,
			"control_id":          e.ControlID,
			"finding_id":          e.FindingID,
			"evidence_type":       e.EvidenceType,
			"reference_id":        e.ReferenceID,
			"verification_status": e.VerificationStatus,
		}
	}
	sort.SliceStable(canonicalEvidence, func(i, j int) bool {
		return canonicalEvidence[i]["evidence_id"].(string) < canonicalEvidence[j]["evidence_id"].(string)
	})

	canonicalRemediation := make([]map[string]any, len(d.Remediation))
	for i, r := range d.Remediation {
		canonicalRemediation[i] = map[string]any{
			"remediation_id": r.RemediationID,
			"finding_id":     r.FindingID,
			"control_id":     r.ControlID,
			"status":         string(r.Status),
			"deadline":       r.Deadline.UTC().Format(time.RFC3339Nano),
		}
	}
	sort.SliceStable(canonicalRemediation, func(i, j int) bool {
		return canonicalRemediation[i]["remediation_id"].(string) < canonicalRemediation[j]["remediation_id"].(string)
	})

	sumLims := append([]string{}, d.Summary.Limitations...)
	sort.Strings(sumLims)

	canonicalMap := map[string]any{
		"schema_version":            d.Identity.SchemaVersion,
		"assessment_id":             d.Identity.AssessmentID,
		"execution_id":              d.Identity.ExecutionID,
		"catalog_id":                d.Identity.CatalogID,
		"catalog_version":           d.Identity.CatalogVersion,
		"catalog_digest":            d.Identity.CatalogDigest,
		"mapping_ruleset_id":        d.Identity.MappingRuleSetID,
		"mapping_ruleset_version":   d.Identity.MappingRuleSetVersion,
		"mapping_ruleset_digest":    d.Identity.MappingRuleSetDigest,
		"applicable_policy_id":      d.Identity.ApplicablePolicyID,
		"applicable_policy_version": d.Identity.ApplicablePolicyVersion,
		"generation_mode":           string(d.Identity.GenerationMode),
		"completeness_status":       string(d.Identity.CompletenessStatus),
		"summary": map[string]any{
			"total_controls":          d.Summary.TotalControls,
			"compliant_count":         d.Summary.CompliantCount,
			"non_compliant_count":     d.Summary.NonCompliantCount,
			"partially_compliant":     d.Summary.PartiallyCompliantCount,
			"not_assessed_count":      d.Summary.NotAssessedCount,
			"insufficient_evidence":   d.Summary.InsufficientEvidenceCount,
			"not_applicable_count":    d.Summary.NotApplicableCount,
			"error_count":             d.Summary.ErrorCount,
			"total_findings":          d.Summary.TotalFindings,
			"mapped_findings":         d.Summary.MappedFindings,
			"unmapped_findings":       d.Summary.UnmappedFindings,
			"total_evidence_links":    d.Summary.TotalEvidenceLinks,
			"verified_evidence_count": d.Summary.VerifiedEvidenceCount,
			"limitations":             sumLims,
		},
		"controls":    canonicalControls,
		"findings":    canonicalFindings,
		"evidence":    canonicalEvidence,
		"remediation": canonicalRemediation,
	}

	b, _ := json.Marshal(canonicalMap)
	sum := sha256.Sum256(b)
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
}

// ToJSON serializes the compliance dossier to compact JSON.
func (d *ComplianceDossier) ToJSON() ([]byte, error) {
	return json.Marshal(d)
}

// ToPrettyJSON serializes the compliance dossier to formatted JSON.
func (d *ComplianceDossier) ToPrettyJSON() ([]byte, error) {
	return json.MarshalIndent(d, "", "  ")
}
