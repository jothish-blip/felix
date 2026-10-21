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

// CurrentNormalizedExportSchemaVersion defines the authoritative schema version for FELIX normalized compliance exports.
const CurrentNormalizedExportSchemaVersion = "felix.compliance.export.v1"

// ExportFormat specifies the target serialization format for compliance exports.
type ExportFormat string

const (
	ExportFormatNormalizedJSON         ExportFormat = "normalized_json"
	ExportFormatOSCALAssessmentResults ExportFormat = "oscal_assessment_results"
	ExportFormatOSCALPOAM              ExportFormat = "oscal_poam"
)

// ExportMetadata encapsulates authoritative provenance and contextual details regarding the export operation.
type ExportMetadata struct {
	ExportID            string                    `json:"export_id"`
	ExportedAt          time.Time                 `json:"exported_at"`
	Format              ExportFormat              `json:"format"`
	FelixVersion        string                    `json:"felix_version,omitempty"`
	SourceRevision      string                    `json:"source_revision,omitempty"`
	SourceDossierID     string                    `json:"source_dossier_id,omitempty"`
	SourceDossierDigest string                    `json:"source_dossier_digest,omitempty"`
	GenerationMode      DossierGenerationMode     `json:"generation_mode"`
	CompletenessStatus  DossierCompletenessStatus `json:"completeness_status"`
}

// ExportAssessmentDetails captures authoritative assessment project and execution identifiers.
type ExportAssessmentDetails struct {
	AssessmentID            string    `json:"assessment_id"`
	ExecutionID             string    `json:"execution_id,omitempty"`
	EvaluatedAt             time.Time `json:"evaluated_at"`
	OverallStatus           string    `json:"overall_status"`
	CompletionStatus        string    `json:"completion_status"`
	ApplicablePolicyID      string    `json:"applicable_policy_id,omitempty"`
	ApplicablePolicyVersion string    `json:"applicable_policy_version,omitempty"`
}

// ExportCatalogDetails summarizes the evaluated compliance benchmark catalog.
type ExportCatalogDetails struct {
	CatalogID      string `json:"catalog_id"`
	CatalogVersion string `json:"catalog_version,omitempty"`
	CatalogDigest  string `json:"catalog_digest,omitempty"`
	Title          string `json:"title,omitempty"`
	TotalControls  int    `json:"total_controls"`
}

// ExportMappingDetails summarizes the finding-to-control mapping rule set applied.
type ExportMappingDetails struct {
	MappingRuleSetID      string `json:"mapping_ruleset_id,omitempty"`
	MappingRuleSetVersion string `json:"mapping_ruleset_version,omitempty"`
	MappingRuleSetDigest  string `json:"mapping_ruleset_digest,omitempty"`
	TotalRules            int    `json:"total_rules,omitempty"`
}

// ExportSummaryDetails provides aggregate quantitative metrics across all controls, findings, evidence, and remediations.
type ExportSummaryDetails struct {
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
	UnmappedFindings           int                    `json:"unmapped_findings"`
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
}

// ExportControlRecord represents the evaluation outcome and evidence linkage for one control.
type ExportControlRecord struct {
	ControlID                   string                            `json:"control_id"`
	Title                       string                            `json:"title,omitempty"`
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

// ExportFindingRecord represents an empirical security finding associated with compliance controls.
type ExportFindingRecord struct {
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

// ExportEvidenceRecord represents a verifiable evidence reference in the normalized export register.
type ExportEvidenceRecord struct {
	EvidenceID         string `json:"evidence_id"`
	ControlID          string `json:"control_id"`
	FindingID          string `json:"finding_id,omitempty"`
	EvaluationID       string `json:"evaluation_id,omitempty"`
	EvidenceType       string `json:"evidence_type"`
	ReferenceID        string `json:"reference_id"`
	Source             string `json:"source,omitempty"`
	Description        string `json:"description,omitempty"`
	VerificationStatus string `json:"verification_status"`
	Verified           bool   `json:"verified"`
}

// ExportRemediationRecord represents a remediation tracking record and its SLA compliance.
type ExportRemediationRecord struct {
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

// ExportIntegrityDetails provides verified cryptographic statements and coverage markers.
type ExportIntegrityDetails struct {
	VerifiedSourceRecords      []string           `json:"verified_source_records,omitempty"`
	UnverifiedLegacyRecords    []string           `json:"unverified_legacy_records,omitempty"`
	IntegrityFailures          []string           `json:"integrity_failures,omitempty"`
	CoverageStatus             string             `json:"coverage_status"`
	EvaluationIntegrityStatus  VerificationStatus `json:"evaluation_integrity_status"`
	RemediationIntegrityStatus VerificationStatus `json:"remediation_integrity_status,omitempty"`
	LimitationsNotice          string             `json:"limitations_notice"`
	AuthenticityStatement      string             `json:"authenticity_statement"`
}

// NormalizedComplianceExport represents the complete, stable, normalized JSON compliance document.
type NormalizedComplianceExport struct {
	SchemaVersion         string                    `json:"schema_version"`
	ExportMetadata        ExportMetadata            `json:"export_metadata"`
	Assessment            ExportAssessmentDetails   `json:"assessment"`
	Catalog               ExportCatalogDetails      `json:"catalog"`
	Mapping               ExportMappingDetails      `json:"mapping"`
	Summary               ExportSummaryDetails      `json:"summary"`
	Controls              []ExportControlRecord     `json:"controls"`
	Findings              []ExportFindingRecord     `json:"findings,omitempty"`
	Evidence              []ExportEvidenceRecord    `json:"evidence,omitempty"`
	Remediation           []ExportRemediationRecord `json:"remediation,omitempty"`
	Integrity             ExportIntegrityDetails    `json:"integrity"`
	Limitations           []string                  `json:"limitations,omitempty"`
	StructuredLimitations []ComplianceLimitation    `json:"structured_limitations,omitempty"`
	CoverageBasis         *CoverageBasis            `json:"coverage_basis,omitempty"`
	LogicalDigest         string                    `json:"logical_digest"`
}

// ComputeNormalizedExportDigest calculates a deterministic canonical SHA-256 digest over the normalized export content.
// Volatile fields (ExportID, ExportedAt, FelixVersion, SourceRevision, and LogicalDigest itself) are deliberately excluded.
func ComputeNormalizedExportDigest(exp *NormalizedComplianceExport) string {
	if exp == nil {
		return ""
	}

	canonicalControls := make([]map[string]any, len(exp.Controls))
	for i, c := range exp.Controls {
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
			"catalog_version":  c.CatalogVersion,
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

	canonicalFindings := make([]map[string]any, len(exp.Findings))
	for i, f := range exp.Findings {
		ctrls := append([]string{}, f.AssociatedControlIDs...)
		sort.Strings(ctrls)
		evs := append([]string{}, f.EvidenceReferenceIDs...)
		sort.Strings(evs)

		canonicalFindings[i] = map[string]any{
			"finding_id": f.FindingID,
			"rule_id":    f.RuleID,
			"severity":   strings.ToUpper(f.Severity),
			"controls":   ctrls,
			"evidence":   evs,
		}
	}
	sort.SliceStable(canonicalFindings, func(i, j int) bool {
		return canonicalFindings[i]["finding_id"].(string) < canonicalFindings[j]["finding_id"].(string)
	})

	canonicalEvidence := make([]map[string]any, len(exp.Evidence))
	for i, e := range exp.Evidence {
		canonicalEvidence[i] = map[string]any{
			"evidence_id":         e.EvidenceID,
			"control_id":          e.ControlID,
			"finding_id":          e.FindingID,
			"evidence_type":       e.EvidenceType,
			"reference_id":        e.ReferenceID,
			"verification_status": e.VerificationStatus,
			"verified":            e.Verified,
		}
	}
	sort.SliceStable(canonicalEvidence, func(i, j int) bool {
		return canonicalEvidence[i]["evidence_id"].(string) < canonicalEvidence[j]["evidence_id"].(string)
	})

	canonicalRemediation := make([]map[string]any, len(exp.Remediation))
	for i, r := range exp.Remediation {
		canonicalRemediation[i] = map[string]any{
			"remediation_id": r.RemediationID,
			"finding_id":     r.FindingID,
			"control_id":     r.ControlID,
			"status":         string(r.Status),
			"deadline":       r.Deadline.UTC().Format(time.RFC3339Nano),
			"is_overdue":     r.IsOverdue,
			"risk_accepted":  r.RiskAccepted,
		}
	}
	sort.SliceStable(canonicalRemediation, func(i, j int) bool {
		return canonicalRemediation[i]["remediation_id"].(string) < canonicalRemediation[j]["remediation_id"].(string)
	})

	sumLims := append([]string{}, exp.Limitations...)
	sort.Strings(sumLims)

	canonicalMap := map[string]any{
		"schema_version":            exp.SchemaVersion,
		"generation_mode":           string(exp.ExportMetadata.GenerationMode),
		"completeness_status":       string(exp.ExportMetadata.CompletenessStatus),
		"assessment_id":             exp.Assessment.AssessmentID,
		"execution_id":              exp.Assessment.ExecutionID,
		"overall_status":            exp.Assessment.OverallStatus,
		"completion_status":         exp.Assessment.CompletionStatus,
		"applicable_policy_id":      exp.Assessment.ApplicablePolicyID,
		"applicable_policy_version": exp.Assessment.ApplicablePolicyVersion,
		"catalog_id":                exp.Catalog.CatalogID,
		"catalog_version":           exp.Catalog.CatalogVersion,
		"catalog_digest":            exp.Catalog.CatalogDigest,
		"mapping_ruleset_id":        exp.Mapping.MappingRuleSetID,
		"mapping_ruleset_version":   exp.Mapping.MappingRuleSetVersion,
		"mapping_ruleset_digest":    exp.Mapping.MappingRuleSetDigest,
		"summary": map[string]any{
			"total_controls":          exp.Summary.TotalControls,
			"compliant_count":         exp.Summary.CompliantCount,
			"non_compliant_count":     exp.Summary.NonCompliantCount,
			"partially_compliant":     exp.Summary.PartiallyCompliantCount,
			"not_assessed_count":      exp.Summary.NotAssessedCount,
			"insufficient_evidence":   exp.Summary.InsufficientEvidenceCount,
			"not_applicable_count":    exp.Summary.NotApplicableCount,
			"error_count":             exp.Summary.ErrorCount,
			"total_findings":          exp.Summary.TotalFindings,
			"mapped_findings":         exp.Summary.MappedFindings,
			"total_evidence_links":    exp.Summary.TotalEvidenceLinks,
			"verified_evidence_count": exp.Summary.VerifiedEvidenceCount,
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

// ToJSON serializes the normalized export to compact JSON.
func (exp *NormalizedComplianceExport) ToJSON() ([]byte, error) {
	return json.Marshal(exp)
}

// ToPrettyJSON serializes the normalized export to formatted JSON.
func (exp *NormalizedComplianceExport) ToPrettyJSON() ([]byte, error) {
	return json.MarshalIndent(exp, "", "  ")
}
