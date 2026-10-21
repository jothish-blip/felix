package compliance

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

var (
	// ErrInvalidExport is returned when export structural, referential, or semantic validation fails.
	ErrInvalidExport = errors.New("invalid compliance export")

	// ErrUnsupportedExportSchema is returned when the normalized export schema version is unsupported.
	ErrUnsupportedExportSchema = errors.New("unsupported compliance export schema version")

	// ErrUnsupportedOSCALVersion is returned when an OSCAL export document uses an unsupported version.
	ErrUnsupportedOSCALVersion = errors.New("unsupported OSCAL specification version")

	// ErrExportDigestMismatch is returned when the declared logical digest does not match the computed digest.
	ErrExportDigestMismatch = errors.New("export logical content digest mismatch")

	// ErrExportPayloadTooLarge is returned when an export file exceeds the 50MB size limit.
	ErrExportPayloadTooLarge = errors.New("export payload exceeds maximum allowed size of 50MB")
)

const maxExportPayloadBytes = 50 * 1024 * 1024 // 50MB

// ExportValidationReport details the five distinct validation tiers for an export artifact.
type ExportValidationReport struct {
	FilePath                string         `json:"file_path,omitempty"`
	DetectedFormat          ExportFormat   `json:"detected_format"`
	SyntaxValid             bool           `json:"syntax_valid"`
	SchemaValid             bool           `json:"schema_valid"`
	ReferentiallyValid      bool           `json:"referentially_valid"`
	SemanticallyConsistent  bool           `json:"semantically_consistent"`
	SourceIntegrityVerified bool           `json:"source_integrity_verified"`
	IsValid                 bool           `json:"is_valid"`
	Errors                  []string       `json:"errors,omitempty"`
	Warnings                []string       `json:"warnings,omitempty"`
	Summary                 map[string]any `json:"summary,omitempty"`
}

// HasErrors returns true if validation reported any errors or failed.
func (r *ExportValidationReport) HasErrors() bool {
	return !r.IsValid || len(r.Errors) > 0
}

// ============================================================================
// NORMALIZED JSON VALIDATION
// ============================================================================

// ValidateNormalizedExport validates a NormalizedComplianceExport against syntax, schema, referential,
// semantic consistency, and cryptographic digest rules.
func ValidateNormalizedExport(exp *NormalizedComplianceExport) error {
	if exp == nil {
		return fmt.Errorf("%w: normalized export cannot be nil", ErrInvalidExport)
	}

	if exp.SchemaVersion != "" && exp.SchemaVersion != CurrentNormalizedExportSchemaVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrUnsupportedExportSchema, exp.SchemaVersion, CurrentNormalizedExportSchemaVersion)
	}

	if exp.LogicalDigest != "" {
		if !strings.HasPrefix(exp.LogicalDigest, "sha256:") || len(exp.LogicalDigest) != 71 {
			return fmt.Errorf("%w: invalid logical_digest format %q; must be sha256:<64 hex chars>", ErrInvalidExport, exp.LogicalDigest)
		}
		recomputed := ComputeNormalizedExportDigest(exp)
		if recomputed != exp.LogicalDigest {
			return fmt.Errorf("%w: recorded %s, recomputed %s", ErrExportDigestMismatch, exp.LogicalDigest, recomputed)
		}
	}

	report := &ExportValidationReport{
		DetectedFormat:          ExportFormatNormalizedJSON,
		SyntaxValid:             true,
		SchemaValid:             true,
		ReferentiallyValid:      true,
		SemanticallyConsistent:  true,
		SourceIntegrityVerified: true,
	}

	validateNormalizedTiers(exp, report)

	if len(report.Errors) > 0 {
		return fmt.Errorf("%w (%d error(s)): %s", ErrInvalidExport, len(report.Errors), strings.Join(report.Errors, "; "))
	}
	return nil
}

func validateNormalizedTiers(exp *NormalizedComplianceExport, report *ExportValidationReport) {
	// Tier 1: Schema & Version
	if strings.TrimSpace(exp.SchemaVersion) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "schema_version is required")
	} else if exp.SchemaVersion != CurrentNormalizedExportSchemaVersion {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("%v: got %q, expected %q", ErrUnsupportedExportSchema, exp.SchemaVersion, CurrentNormalizedExportSchemaVersion))
	}

	if strings.TrimSpace(exp.ExportMetadata.ExportID) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "export_metadata.export_id is required")
	}
	if exp.ExportMetadata.ExportedAt.IsZero() {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "export_metadata.exported_at timestamp is required")
	}
	if exp.ExportMetadata.Format != "" && exp.ExportMetadata.Format != ExportFormatNormalizedJSON {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("export_metadata.format must be %q, got %q", ExportFormatNormalizedJSON, exp.ExportMetadata.Format))
	}
	if strings.TrimSpace(exp.Assessment.AssessmentID) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment.assessment_id is required")
	}
	if strings.TrimSpace(exp.Catalog.CatalogID) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "catalog.catalog_id is required")
	}

	// Tier 2: Source Integrity Check
	if exp.ExportMetadata.CompletenessStatus == DossierCompletenessComplete {
		if len(exp.Integrity.IntegrityFailures) > 0 {
			report.SourceIntegrityVerified = false
			report.Errors = append(report.Errors, "export marked complete but contains source integrity failures")
		}
		if exp.Integrity.CoverageStatus == "PARTIAL" || exp.Integrity.CoverageStatus == "LIMITED" {
			report.SourceIntegrityVerified = false
			report.Errors = append(report.Errors, fmt.Sprintf("export marked complete but integrity coverage status is %s", exp.Integrity.CoverageStatus))
		}
	}

	// Tier 3: Controls, States, and Mappings
	controlMap := make(map[string]bool)
	stateCounts := make(map[EvaluationState]int)

	for i, c := range exp.Controls {
		cID := strings.TrimSpace(c.ControlID)
		if cID == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("controls[%d].control_id is required", i))
			continue
		}
		if controlMap[cID] {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("duplicate control_id %q in controls register", cID))
		}
		controlMap[cID] = true

		if err := ValidateEvaluationState(c.EvaluationState); err != nil {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("controls[%d] (%s): %v", i, cID, err))
		} else {
			stateCounts[c.EvaluationState]++
		}

		if strings.TrimSpace(c.Rationale) == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("controls[%d] (%s): evaluation rationale is required", i, cID))
		}

		for j, mf := range c.MappedFindings {
			if strings.TrimSpace(mf.FindingID) == "" {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("controls[%d] (%s).mapped_findings[%d]: finding_id is required", i, cID, j))
			}
			if _, ok := CanonicalMappingRelationship(string(mf.Relationship)); !ok {
				report.SemanticallyConsistent = false
				report.Errors = append(report.Errors, fmt.Sprintf("controls[%d] (%s).mapped_findings[%d]: invalid relationship %q", i, cID, j, mf.Relationship))
			}
		}

		if c.Remediation != nil {
			if c.Remediation.CompletedAt != nil && c.Remediation.Deadline != nil {
				if c.Remediation.CompletedAt.After(*c.Remediation.Deadline) && c.Remediation.MetSLA != nil && *c.Remediation.MetSLA {
					report.SemanticallyConsistent = false
					report.Errors = append(report.Errors, fmt.Sprintf("controls[%d] (%s).remediation: met_sla cannot be true when completion exceeds deadline", i, cID))
				}
			}
		}
	}

	// Tier 4: Quantitative Aggregates
	if exp.Summary.TotalControls != len(exp.Controls) {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.total_controls (%d) does not match controls count (%d)",
			exp.Summary.TotalControls, len(exp.Controls)))
	}
	if exp.Summary.CompliantCount != stateCounts[StateCompliant] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.compliant_count (%d) does not match control records (%d)",
			exp.Summary.CompliantCount, stateCounts[StateCompliant]))
	}
	if exp.Summary.NonCompliantCount != stateCounts[StateNonCompliant] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.non_compliant_count (%d) does not match control records (%d)",
			exp.Summary.NonCompliantCount, stateCounts[StateNonCompliant]))
	}
	if exp.Summary.PartiallyCompliantCount != stateCounts[StatePartiallyCompliant] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.partially_compliant_count (%d) does not match control records (%d)",
			exp.Summary.PartiallyCompliantCount, stateCounts[StatePartiallyCompliant]))
	}
	if exp.Summary.NotAssessedCount != stateCounts[StateNotAssessed] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.not_assessed_count (%d) does not match control records (%d)",
			exp.Summary.NotAssessedCount, stateCounts[StateNotAssessed]))
	}
	if exp.Summary.InsufficientEvidenceCount != stateCounts[StateInsufficientEvidence] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.insufficient_evidence_count (%d) does not match control records (%d)",
			exp.Summary.InsufficientEvidenceCount, stateCounts[StateInsufficientEvidence]))
	}
	if exp.Summary.NotApplicableCount != stateCounts[StateNotApplicable] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.not_applicable_count (%d) does not match control records (%d)",
			exp.Summary.NotApplicableCount, stateCounts[StateNotApplicable]))
	}
	if exp.Summary.ErrorCount != stateCounts[StateError] {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.error_count (%d) does not match control records (%d)",
			exp.Summary.ErrorCount, stateCounts[StateError]))
	}

	// Tier 5: Findings Register
	findingMap := make(map[string]bool)
	for i, f := range exp.Findings {
		fID := strings.TrimSpace(f.FindingID)
		if fID == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("findings[%d].finding_id is required", i))
			continue
		}
		if findingMap[fID] {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("duplicate finding_id %q in findings register", fID))
		}
		findingMap[fID] = true

		for _, cID := range f.AssociatedControlIDs {
			if !controlMap[cID] {
				hasLimitation := false
				for _, lim := range exp.Limitations {
					if strings.Contains(lim, cID) {
						hasLimitation = true
						break
					}
				}
				if !hasLimitation {
					report.ReferentiallyValid = false
					report.Errors = append(report.Errors, fmt.Sprintf("findings[%d] (%s): associated control %q not found in controls register", i, fID, cID))
				}
			}
		}
	}
	if len(exp.Findings) > 0 && exp.Summary.TotalFindings != len(exp.Findings) {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.total_findings (%d) does not match findings count (%d)",
			exp.Summary.TotalFindings, len(exp.Findings)))
	}

	// Tier 6: Evidence Register & Source Integrity Verification
	evidenceMap := make(map[string]bool)
	for i, e := range exp.Evidence {
		eID := strings.TrimSpace(e.EvidenceID)
		if eID == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("evidence[%d].evidence_id is required", i))
			continue
		}
		if evidenceMap[eID] {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("duplicate evidence_id %q in evidence register", eID))
		}
		evidenceMap[eID] = true

		if e.ControlID != "" && !controlMap[e.ControlID] {
			hasLimitation := false
			for _, lim := range exp.Limitations {
				if strings.Contains(lim, e.ControlID) {
					hasLimitation = true
					break
				}
			}
			if !hasLimitation {
				report.ReferentiallyValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("evidence[%d] (%s): references control %q not found in controls register", i, eID, e.ControlID))
			}
		}

		if e.FindingID != "" && len(exp.Findings) > 0 && !findingMap[e.FindingID] {
			report.ReferentiallyValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("evidence[%d] (%s): references finding %q not found in findings register", i, eID, e.FindingID))
		}

		// Fail closed against fraudulent verification claims
		if e.Verified && e.VerificationStatus != "VERIFIED" {
			report.SourceIntegrityVerified = false
			report.Errors = append(report.Errors, fmt.Sprintf("evidence[%d] (%s): marked verified=true but verification_status is %q", i, eID, e.VerificationStatus))
		}
	}
	if len(exp.Evidence) > 0 && exp.Summary.TotalEvidenceLinks != len(exp.Evidence) {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.total_evidence_links (%d) does not match evidence count (%d)",
			exp.Summary.TotalEvidenceLinks, len(exp.Evidence)))
	}

	// Tier 7: Remediation Register
	remMap := make(map[string]bool)
	for i, r := range exp.Remediation {
		rID := strings.TrimSpace(r.RemediationID)
		if rID == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("remediation[%d].remediation_id is required", i))
			continue
		}
		if remMap[rID] {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("duplicate remediation_id %q in remediation register", rID))
		}
		remMap[rID] = true

		if r.ControlID != "" && !controlMap[r.ControlID] {
			report.ReferentiallyValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("remediation[%d] (%s): references control %q not found in controls register", i, rID, r.ControlID))
		}

		if r.FindingID != "" && len(exp.Findings) > 0 && !findingMap[r.FindingID] {
			report.ReferentiallyValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("remediation[%d] (%s): references finding %q not found in findings register", i, rID, r.FindingID))
		}

		if r.CompletedAt != nil {
			if !r.SLAStartTime.IsZero() && r.CompletedAt.Before(r.SLAStartTime) {
				report.SemanticallyConsistent = false
				report.Errors = append(report.Errors, fmt.Sprintf("remediation[%d] (%s): completed_at precedes sla_start_time", i, rID))
			}
			if !r.AssignedAt.IsZero() && r.CompletedAt.Before(r.AssignedAt) {
				report.SemanticallyConsistent = false
				report.Errors = append(report.Errors, fmt.Sprintf("remediation[%d] (%s): completed_at precedes assigned_at", i, rID))
			}
		}
	}
	if len(exp.Remediation) > 0 && exp.Summary.TotalRemediations != len(exp.Remediation) {
		report.SemanticallyConsistent = false
		report.Errors = append(report.Errors, fmt.Sprintf("summary.total_remediations (%d) does not match remediation count (%d)",
			exp.Summary.TotalRemediations, len(exp.Remediation)))
	}

	// Tier 7b: Limitations & Coverage Basis Validation
	if len(exp.StructuredLimitations) > 0 {
		if err := ValidateLimitations(exp.StructuredLimitations); err != nil {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("invalid structured limitations: %v", err))
		}
	}
	if exp.CoverageBasis != nil {
		cb := exp.CoverageBasis
		if cb.ApplicableControls != (cb.TotalCatalogControls - cb.NotApplicableControls) {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("invalid coverage basis: applicable (%d) != total (%d) - not_applicable (%d)",
				cb.ApplicableControls, cb.TotalCatalogControls, cb.NotApplicableControls))
		}
	}

	// Tier 8: Canonical SHA-256 Logical Digest Verification
	if exp.LogicalDigest != "" {
		if !strings.HasPrefix(exp.LogicalDigest, "sha256:") || len(exp.LogicalDigest) != 71 {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("invalid logical_digest format %q; must be sha256:<64 hex chars>", exp.LogicalDigest))
		} else {
			recomputed := ComputeNormalizedExportDigest(exp)
			if recomputed != exp.LogicalDigest {
				report.SourceIntegrityVerified = false
				report.Errors = append(report.Errors, fmt.Sprintf("%v: recorded %s, recomputed %s", ErrExportDigestMismatch, exp.LogicalDigest, recomputed))
			}
		}
	}

	if len(report.Errors) == 0 {
		report.IsValid = true
	} else {
		report.IsValid = false
	}
}

// ============================================================================
// OSCAL ASSESSMENT RESULTS VALIDATION
// ============================================================================

// ValidateOSCALAssessmentResults validates an OSCALAssessmentResultsDocument for conformance,
// valid UUIDs, non-empty reviewed controls, observations, and findings.
func ValidateOSCALAssessmentResults(doc *OSCALAssessmentResultsDocument) error {
	if doc == nil {
		return fmt.Errorf("%w: OSCAL assessment results document cannot be nil", ErrInvalidExport)
	}

	if doc.AssessmentResults.Metadata.OSCALVersion != "" && doc.AssessmentResults.Metadata.OSCALVersion != CurrentOSCALVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrUnsupportedOSCALVersion, doc.AssessmentResults.Metadata.OSCALVersion, CurrentOSCALVersion)
	}

	report := &ExportValidationReport{
		DetectedFormat:          ExportFormatOSCALAssessmentResults,
		SyntaxValid:             true,
		SchemaValid:             true,
		ReferentiallyValid:      true,
		SemanticallyConsistent:  true,
		SourceIntegrityVerified: true,
	}

	validateOSCALAssessmentResultsTiers(doc, report)

	rawJSON, err := json.Marshal(doc)
	if err == nil {
		if err := ValidateOSCALAssessmentResultsJSONSchema(rawJSON); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("OSCAL assessment-results official schema validation failed: %v", err))
		}
	} else {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("failed marshaling OSCAL assessment-results for schema validation: %v", err))
	}

	if len(report.Errors) == 0 {
		report.IsValid = true
	} else {
		report.IsValid = false
	}

	if len(report.Errors) > 0 {
		return fmt.Errorf("%w (%d error(s)): %s", ErrInvalidExport, len(report.Errors), strings.Join(report.Errors, "; "))
	}
	return nil
}

func validateOSCALAssessmentResultsTiers(doc *OSCALAssessmentResultsDocument, report *ExportValidationReport) {
	ar := &doc.AssessmentResults

	// Check Root UUID
	if _, err := uuid.Parse(ar.UUID); err != nil {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("assessment-results.uuid %q is not a valid UUID: %v", ar.UUID, err))
	}

	// Check Metadata
	if strings.TrimSpace(ar.Metadata.Title) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.metadata.title is required")
	}
	if ar.Metadata.Published.IsZero() {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.metadata.published timestamp is required")
	}
	if ar.Metadata.LastModified.IsZero() {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.metadata.last-modified timestamp is required")
	}
	if strings.TrimSpace(ar.Metadata.Version) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.metadata.version is required")
	}
	if strings.TrimSpace(ar.Metadata.OSCALVersion) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.metadata.oscal-version is required")
	} else if ar.Metadata.OSCALVersion != CurrentOSCALVersion {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("%v: got %q, expected %q", ErrUnsupportedOSCALVersion, ar.Metadata.OSCALVersion, CurrentOSCALVersion))
	}

	// Check Parties
	for pIdx, p := range ar.Metadata.Parties {
		if p.Type != "organization" && p.Type != "person" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("assessment-results.metadata.parties[%d].type %q is invalid; must be organization or person", pIdx, p.Type))
		}
	}

	// Check ImportAP
	if strings.TrimSpace(ar.ImportAP.Href) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.import-ap.href is required")
	}

	// Check Results
	if len(ar.Results) == 0 {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "assessment-results.results must contain at least one result")
		report.IsValid = false
		return
	}

	for rIdx, res := range ar.Results {
		if _, err := uuid.Parse(res.UUID); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].uuid %q is not a valid UUID: %v", rIdx, res.UUID, err))
		}
		if strings.TrimSpace(res.Title) == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].title is required", rIdx))
		}
		if res.Start.IsZero() {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].start timestamp is required", rIdx))
		}
		if res.End.IsZero() {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].end timestamp is required", rIdx))
		}
		if !res.Start.IsZero() && !res.End.IsZero() && res.End.Before(res.Start) {
			report.SemanticallyConsistent = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].end precedes start timestamp", rIdx))
		}

		// Reviewed controls
		if len(res.ReviewedControls.ControlSelections) == 0 {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("results[%d].reviewed-controls.control-selections is required", rIdx))
		}

		controlIDs := make(map[string]bool)
		for csIdx, cs := range res.ReviewedControls.ControlSelections {
			for cIdx, cRef := range cs.IncludeControls {
				if strings.TrimSpace(cRef.ControlID) == "" {
					report.SchemaValid = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].control-selections[%d].include-controls[%d].control-id is required", rIdx, csIdx, cIdx))
				} else {
					controlIDs[cRef.ControlID] = true
				}
			}
		}

		for oIdx, obj := range res.ReviewedControls.ControlObjectiveSelections {
			for ioIdx, incObj := range obj.IncludeObjectives {
				if strings.TrimSpace(incObj.ObjectiveID) == "" {
					report.SchemaValid = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].control-objective-selections[%d].include-objectives[%d].objective-id is required", rIdx, oIdx, ioIdx))
				}
			}
		}

		// Observations
		obsUUIDMap := make(map[string]bool)
		for oIdx, obs := range res.Observations {
			if _, err := uuid.Parse(obs.UUID); err != nil {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].observations[%d].uuid %q is not a valid UUID: %v", rIdx, oIdx, obs.UUID, err))
			} else {
				if obsUUIDMap[obs.UUID] {
					report.SemanticallyConsistent = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].observations: duplicate observation UUID %q", rIdx, obs.UUID))
				}
				obsUUIDMap[obs.UUID] = true
			}

			if len(obs.Methods) == 0 {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].observations[%d].methods must not be empty", rIdx, oIdx))
			}
			if len(obs.Types) == 0 {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].observations[%d].types must not be empty", rIdx, oIdx))
			}
			if obs.Collected.IsZero() {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].observations[%d].collected timestamp is required", rIdx, oIdx))
			}
		}

		// Findings
		findingUUIDMap := make(map[string]bool)
		for fIdx, f := range res.Findings {
			if _, err := uuid.Parse(f.UUID); err != nil {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d].uuid %q is not a valid UUID: %v", rIdx, fIdx, f.UUID, err))
			} else {
				if findingUUIDMap[f.UUID] {
					report.SemanticallyConsistent = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings: duplicate finding UUID %q", rIdx, f.UUID))
				}
				findingUUIDMap[f.UUID] = true
			}

			if strings.TrimSpace(f.Target.TargetID) == "" {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d].target.target-id is required", rIdx, fIdx))
			}
			if f.Target.Type != "statement-id" && f.Target.Type != "objective-id" {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d].target.type %q is invalid; must be statement-id or objective-id", rIdx, fIdx, f.Target.Type))
			}
			if f.Target.Status.State != "satisfied" && f.Target.Status.State != "not-satisfied" {
				report.SchemaValid = false
				report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d].target.status.state %q is invalid; must be satisfied or not-satisfied", rIdx, fIdx, f.Target.Status.State))
			}

			// Validate observation references
			for roIdx, ro := range f.RelatedObservations {
				if strings.TrimSpace(ro.ObservationUUID) == "" {
					report.SchemaValid = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d].related-observations[%d].observation-uuid is required", rIdx, fIdx, roIdx))
				} else if !obsUUIDMap[ro.ObservationUUID] {
					report.ReferentiallyValid = false
					report.Errors = append(report.Errors, fmt.Sprintf("results[%d].findings[%d]: references nonexistent observation UUID %q", rIdx, fIdx, ro.ObservationUUID))
				}
			}
		}
	}

	if len(report.Errors) == 0 {
		report.IsValid = true
	} else {
		report.IsValid = false
	}
}

// ============================================================================
// OSCAL POA&M VALIDATION
// ============================================================================

// ValidateOSCALPOAM validates an OSCALPOAMDocument for conformance, valid UUIDs,
// valid metadata, system-id, and remediation items.
func ValidateOSCALPOAM(doc *OSCALPOAMDocument) error {
	if doc == nil {
		return fmt.Errorf("%w: OSCAL POA&M document cannot be nil", ErrInvalidExport)
	}

	if doc.PlanOfActionAndMilestones.Metadata.OSCALVersion != "" && doc.PlanOfActionAndMilestones.Metadata.OSCALVersion != CurrentOSCALVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrUnsupportedOSCALVersion, doc.PlanOfActionAndMilestones.Metadata.OSCALVersion, CurrentOSCALVersion)
	}

	report := &ExportValidationReport{
		DetectedFormat:          ExportFormatOSCALPOAM,
		SyntaxValid:             true,
		SchemaValid:             true,
		ReferentiallyValid:      true,
		SemanticallyConsistent:  true,
		SourceIntegrityVerified: true,
	}

	validateOSCALPOAMTiers(doc, report)

	rawJSON, err := json.Marshal(doc)
	if err == nil {
		if err := ValidateOSCALPOAMJSONSchema(rawJSON); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("OSCAL plan-of-action-and-milestones official schema validation failed: %v", err))
		}
	} else {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("failed marshaling OSCAL POA&M for schema validation: %v", err))
	}

	if len(report.Errors) == 0 {
		report.IsValid = true
	} else {
		report.IsValid = false
	}

	if len(report.Errors) > 0 {
		return fmt.Errorf("%w (%d error(s)): %s", ErrInvalidExport, len(report.Errors), strings.Join(report.Errors, "; "))
	}
	return nil
}

func validateOSCALPOAMTiers(doc *OSCALPOAMDocument, report *ExportValidationReport) {
	poam := &doc.PlanOfActionAndMilestones

	// Check Root UUID
	if _, err := uuid.Parse(poam.UUID); err != nil {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("plan-of-action-and-milestones.uuid %q is not a valid UUID: %v", poam.UUID, err))
	}

	// Check Metadata
	if strings.TrimSpace(poam.Metadata.Title) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.metadata.title is required")
	}
	if poam.Metadata.Published.IsZero() {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.metadata.published timestamp is required")
	}
	if poam.Metadata.LastModified.IsZero() {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.metadata.last-modified timestamp is required")
	}
	if strings.TrimSpace(poam.Metadata.Version) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.metadata.version is required")
	}
	if strings.TrimSpace(poam.Metadata.OSCALVersion) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.metadata.oscal-version is required")
	} else if poam.Metadata.OSCALVersion != CurrentOSCALVersion {
		report.SchemaValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("%v: got %q, expected %q", ErrUnsupportedOSCALVersion, poam.Metadata.OSCALVersion, CurrentOSCALVersion))
	}

	// Check Parties
	for pIdx, p := range poam.Metadata.Parties {
		if p.Type != "organization" && p.Type != "person" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("plan-of-action-and-milestones.metadata.parties[%d].type %q is invalid; must be organization or person", pIdx, p.Type))
		}
	}

	// Check ImportSSP
	if strings.TrimSpace(poam.ImportSSP.Href) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.import-ssp.href is required")
	}

	// Check SystemID
	if strings.TrimSpace(poam.SystemID.ID) == "" {
		report.SchemaValid = false
		report.Errors = append(report.Errors, "plan-of-action-and-milestones.system-id.id is required")
	}

	// Check POAM Items
	itemUUIDMap := make(map[string]bool)
	for iIdx, item := range poam.POAMItems {
		if _, err := uuid.Parse(item.UUID); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("poam-items[%d].uuid %q is not a valid UUID: %v", iIdx, item.UUID, err))
		} else {
			if itemUUIDMap[item.UUID] {
				report.SemanticallyConsistent = false
				report.Errors = append(report.Errors, fmt.Sprintf("poam-items: duplicate item UUID %q", item.UUID))
			}
			itemUUIDMap[item.UUID] = true
		}

		if strings.TrimSpace(item.Title) == "" {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("poam-items[%d].title is required", iIdx))
		}
	}

	if len(report.Errors) == 0 {
		report.IsValid = true
	} else {
		report.IsValid = false
	}
}

// ============================================================================
// FILE VALIDATION AND PARSING
// ============================================================================

// ValidateExportFile inspects an on-disk export file, auto-detects its schema format,
// executes all tiered validation checks, and returns a detailed ExportValidationReport.
func ValidateExportFile(path string) (*ExportValidationReport, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("export file path cannot be empty")
	}

	cleanPath = filepath.Clean(cleanPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed accessing export file %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("export path %q is a directory, not a file", cleanPath)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening export file %q: %w", cleanPath, err)
	}
	defer f.Close()

	limitReader := io.LimitReader(f, int64(maxExportPayloadBytes)+1)
	raw, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading export file: %w", err)
	}
	if len(raw) > maxExportPayloadBytes {
		return nil, fmt.Errorf("%w (file size %d bytes)", ErrExportPayloadTooLarge, len(raw))
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("export file is empty")
	}

	report := &ExportValidationReport{
		FilePath: cleanPath,
		Summary:  make(map[string]any),
	}

	// 1. Syntax check
	var rawEnvelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawEnvelope); err != nil {
		report.SyntaxValid = false
		report.IsValid = false
		report.Errors = append(report.Errors, fmt.Sprintf("malformed JSON syntax: %v", err))
		return report, nil
	}
	report.SyntaxValid = true

	// 2. Format detection
	if _, ok := rawEnvelope["schema_version"]; ok {
		report.DetectedFormat = ExportFormatNormalizedJSON
		report.SchemaValid = true
		report.ReferentiallyValid = true
		report.SemanticallyConsistent = true
		report.SourceIntegrityVerified = true

		var exp NormalizedComplianceExport
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&exp); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("failed parsing normalized export: %v", err))
		} else {
			validateNormalizedTiers(&exp, report)
			report.Summary["schema_version"] = exp.SchemaVersion
			report.Summary["assessment_id"] = exp.Assessment.AssessmentID
			report.Summary["catalog_id"] = exp.Catalog.CatalogID
			report.Summary["total_controls"] = exp.Summary.TotalControls
			report.Summary["non_compliant_count"] = exp.Summary.NonCompliantCount
			report.Summary["logical_digest"] = exp.LogicalDigest
		}
	} else if _, ok := rawEnvelope["assessment-results"]; ok {
		report.DetectedFormat = ExportFormatOSCALAssessmentResults
		report.SchemaValid = true
		report.ReferentiallyValid = true
		report.SemanticallyConsistent = true
		report.SourceIntegrityVerified = true

		if err := ValidateOSCALAssessmentResultsJSONSchema(raw); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("OSCAL assessment-results official schema validation failed: %v", err))
		}

		var doc OSCALAssessmentResultsDocument
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("failed parsing OSCAL assessment-results: %v", err))
		} else {
			validateOSCALAssessmentResultsTiers(&doc, report)
			report.Summary["oscal_version"] = doc.AssessmentResults.Metadata.OSCALVersion
			report.Summary["title"] = doc.AssessmentResults.Metadata.Title
			report.Summary["results_count"] = len(doc.AssessmentResults.Results)
			if len(doc.AssessmentResults.Results) > 0 {
				res := doc.AssessmentResults.Results[0]
				report.Summary["findings_count"] = len(res.Findings)
				report.Summary["observations_count"] = len(res.Observations)
			}
		}
	} else if _, ok := rawEnvelope["plan-of-action-and-milestones"]; ok {
		report.DetectedFormat = ExportFormatOSCALPOAM
		report.SchemaValid = true
		report.ReferentiallyValid = true
		report.SemanticallyConsistent = true
		report.SourceIntegrityVerified = true

		if err := ValidateOSCALPOAMJSONSchema(raw); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("OSCAL plan-of-action-and-milestones official schema validation failed: %v", err))
		}

		var doc OSCALPOAMDocument
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&doc); err != nil {
			report.SchemaValid = false
			report.Errors = append(report.Errors, fmt.Sprintf("failed parsing OSCAL plan-of-action-and-milestones: %v", err))
		} else {
			validateOSCALPOAMTiers(&doc, report)
			report.Summary["oscal_version"] = doc.PlanOfActionAndMilestones.Metadata.OSCALVersion
			report.Summary["title"] = doc.PlanOfActionAndMilestones.Metadata.Title
			report.Summary["poam_items_count"] = len(doc.PlanOfActionAndMilestones.POAMItems)
		}
	} else {
		report.DetectedFormat = "unknown"
		report.SchemaValid = false
		report.IsValid = false
		report.Errors = append(report.Errors, "unrecognized compliance export format: payload lacks schema_version, assessment-results, or plan-of-action-and-milestones")
	}

	if len(report.Errors) > 0 {
		report.IsValid = false
	} else {
		report.IsValid = true
	}

	return report, nil
}

// LoadNormalizedExportFromJSON parses and validates a NormalizedComplianceExport from JSON bytes.
func LoadNormalizedExportFromJSON(data []byte) (*NormalizedComplianceExport, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty export payload")
	}

	var exp NormalizedComplianceExport
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&exp); err != nil {
		return nil, fmt.Errorf("failed parsing normalized compliance export JSON: %w", err)
	}

	if err := ValidateNormalizedExport(&exp); err != nil {
		return nil, err
	}

	return &exp, nil
}

// LoadNormalizedExportFromFile reads, parses, and validates a NormalizedComplianceExport from a file.
func LoadNormalizedExportFromFile(path string) (*NormalizedComplianceExport, error) {
	rep, err := ValidateExportFile(path)
	if err != nil {
		return nil, err
	}
	if rep.HasErrors() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidExport, strings.Join(rep.Errors, "; "))
	}
	if rep.DetectedFormat != ExportFormatNormalizedJSON {
		return nil, fmt.Errorf("%w: expected %s, detected %s", ErrInvalidExport, ExportFormatNormalizedJSON, rep.DetectedFormat)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var exp NormalizedComplianceExport
	_ = json.Unmarshal(raw, &exp)
	return &exp, nil
}

// LoadOSCALAssessmentResultsFromJSON parses and validates an OSCALAssessmentResultsDocument from JSON bytes.
func LoadOSCALAssessmentResultsFromJSON(data []byte) (*OSCALAssessmentResultsDocument, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty OSCAL payload")
	}

	var doc OSCALAssessmentResultsDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed parsing OSCAL assessment-results JSON: %w", err)
	}

	if err := ValidateOSCALAssessmentResults(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// LoadOSCALAssessmentResultsFromFile reads, parses, and validates an OSCALAssessmentResultsDocument from a file.
func LoadOSCALAssessmentResultsFromFile(path string) (*OSCALAssessmentResultsDocument, error) {
	rep, err := ValidateExportFile(path)
	if err != nil {
		return nil, err
	}
	if rep.HasErrors() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidExport, strings.Join(rep.Errors, "; "))
	}
	if rep.DetectedFormat != ExportFormatOSCALAssessmentResults {
		return nil, fmt.Errorf("%w: expected %s, detected %s", ErrInvalidExport, ExportFormatOSCALAssessmentResults, rep.DetectedFormat)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc OSCALAssessmentResultsDocument
	_ = json.Unmarshal(raw, &doc)
	return &doc, nil
}

// LoadOSCALPOAMFromJSON parses and validates an OSCALPOAMDocument from JSON bytes.
func LoadOSCALPOAMFromJSON(data []byte) (*OSCALPOAMDocument, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty OSCAL POA&M payload")
	}

	var doc OSCALPOAMDocument
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed parsing OSCAL plan-of-action-and-milestones JSON: %w", err)
	}

	if err := ValidateOSCALPOAM(&doc); err != nil {
		return nil, err
	}

	return &doc, nil
}

// LoadOSCALPOAMFromFile reads, parses, and validates an OSCALPOAMDocument from a file.
func LoadOSCALPOAMFromFile(path string) (*OSCALPOAMDocument, error) {
	rep, err := ValidateExportFile(path)
	if err != nil {
		return nil, err
	}
	if rep.HasErrors() {
		return nil, fmt.Errorf("%w: %s", ErrInvalidExport, strings.Join(rep.Errors, "; "))
	}
	if rep.DetectedFormat != ExportFormatOSCALPOAM {
		return nil, fmt.Errorf("%w: expected %s, detected %s", ErrInvalidExport, ExportFormatOSCALPOAM, rep.DetectedFormat)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc OSCALPOAMDocument
	_ = json.Unmarshal(raw, &doc)
	return &doc, nil
}
