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
)

var (
	// ErrInvalidDossier is returned when dossier structural or semantic validation fails.
	ErrInvalidDossier = errors.New("invalid compliance dossier")

	// ErrUnsupportedDossierSchema is returned when the dossier schema version is unsupported.
	ErrUnsupportedDossierSchema = errors.New("unsupported compliance dossier schema version")

	// ErrDossierDigestMismatch is returned when the declared logical digest does not match the computed digest.
	ErrDossierDigestMismatch = errors.New("dossier logical content digest mismatch")
)

// ValidateDossier performs comprehensive semantic and cross-reference validation on a ComplianceDossier.
func ValidateDossier(d *ComplianceDossier) error {
	if d == nil {
		return fmt.Errorf("%w: dossier cannot be nil", ErrInvalidDossier)
	}

	var validationErrors []string

	// 1. Identity Validation
	if strings.TrimSpace(d.Identity.SchemaVersion) == "" {
		validationErrors = append(validationErrors, "identity.schema_version is required")
	} else if d.Identity.SchemaVersion != CurrentDossierSchemaVersion {
		return fmt.Errorf("%w: got %q, expected %q", ErrUnsupportedDossierSchema, d.Identity.SchemaVersion, CurrentDossierSchemaVersion)
	}

	if strings.TrimSpace(d.Identity.AssessmentID) == "" {
		validationErrors = append(validationErrors, "identity.assessment_id is required")
	}
	if strings.TrimSpace(d.Identity.CatalogID) == "" {
		validationErrors = append(validationErrors, "identity.catalog_id is required")
	}
	if d.Identity.GeneratedAt.IsZero() {
		validationErrors = append(validationErrors, "identity.generated_at timestamp is required")
	}

	// 2. Completeness & Integrity Consistency
	if d.Identity.CompletenessStatus == DossierCompletenessComplete {
		if len(d.Integrity.IntegrityFailures) > 0 {
			validationErrors = append(validationErrors, "dossier marked complete but contains integrity failures in source records")
		}
		if d.Integrity.CoverageStatus == "PARTIAL" || d.Integrity.CoverageStatus == "LIMITED" {
			validationErrors = append(validationErrors, "dossier marked complete but integrity coverage status indicates partial or limited data")
		}
	}

	// 3. Control Results & State Validation
	controlMap := make(map[string]bool)
	stateCounts := make(map[EvaluationState]int)

	for i, c := range d.Controls {
		cID := strings.TrimSpace(c.ControlID)
		if cID == "" {
			validationErrors = append(validationErrors, fmt.Sprintf("controls[%d].control_id is required", i))
			continue
		}
		if controlMap[cID] {
			validationErrors = append(validationErrors, fmt.Sprintf("duplicate control_id %q in controls register", cID))
		}
		controlMap[cID] = true

		if err := ValidateEvaluationState(c.EvaluationState); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("controls[%d] (%s): %v", i, cID, err))
		} else {
			stateCounts[c.EvaluationState]++
		}

		if strings.TrimSpace(c.Rationale) == "" {
			validationErrors = append(validationErrors, fmt.Sprintf("controls[%d] (%s): evaluation rationale is required", i, cID))
		}

		// Validate mapped findings
		for j, mf := range c.MappedFindings {
			if strings.TrimSpace(mf.FindingID) == "" {
				validationErrors = append(validationErrors, fmt.Sprintf("controls[%d] (%s).mapped_findings[%d]: finding_id is required", i, cID, j))
			}
			if _, ok := CanonicalMappingRelationship(string(mf.Relationship)); !ok {
				validationErrors = append(validationErrors, fmt.Sprintf("controls[%d] (%s).mapped_findings[%d]: invalid relationship %q", i, cID, j, mf.Relationship))
			}
		}

		// Validate control remediation
		if c.Remediation != nil {
			if c.Remediation.CompletedAt != nil && c.Remediation.Deadline != nil {
				if c.Remediation.CompletedAt.After(*c.Remediation.Deadline) && c.Remediation.MetSLA != nil && *c.Remediation.MetSLA {
					validationErrors = append(validationErrors, fmt.Sprintf("controls[%d] (%s).remediation: met_sla cannot be true when completion exceeds deadline", i, cID))
				}
			}
		}
	}

	// 4. Quantitative Aggregates & Consistency Check
	if d.Summary.TotalControls != len(d.Controls) {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.total_controls (%d) does not match controls count (%d)",
			d.Summary.TotalControls, len(d.Controls)))
	}
	if d.Summary.CompliantCount != stateCounts[StateCompliant] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.compliant_count (%d) does not match control records (%d)",
			d.Summary.CompliantCount, stateCounts[StateCompliant]))
	}
	if d.Summary.NonCompliantCount != stateCounts[StateNonCompliant] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.non_compliant_count (%d) does not match control records (%d)",
			d.Summary.NonCompliantCount, stateCounts[StateNonCompliant]))
	}
	if d.Summary.PartiallyCompliantCount != stateCounts[StatePartiallyCompliant] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.partially_compliant_count (%d) does not match control records (%d)",
			d.Summary.PartiallyCompliantCount, stateCounts[StatePartiallyCompliant]))
	}
	if d.Summary.NotAssessedCount != stateCounts[StateNotAssessed] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.not_assessed_count (%d) does not match control records (%d)",
			d.Summary.NotAssessedCount, stateCounts[StateNotAssessed]))
	}
	if d.Summary.InsufficientEvidenceCount != stateCounts[StateInsufficientEvidence] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.insufficient_evidence_count (%d) does not match control records (%d)",
			d.Summary.InsufficientEvidenceCount, stateCounts[StateInsufficientEvidence]))
	}
	if d.Summary.NotApplicableCount != stateCounts[StateNotApplicable] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.not_applicable_count (%d) does not match control records (%d)",
			d.Summary.NotApplicableCount, stateCounts[StateNotApplicable]))
	}
	if d.Summary.ErrorCount != stateCounts[StateError] {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.error_count (%d) does not match control records (%d)",
			d.Summary.ErrorCount, stateCounts[StateError]))
	}

	// 5. Findings Register Validation
	findingMap := make(map[string]bool)
	for i, f := range d.Findings {
		fID := strings.TrimSpace(f.FindingID)
		if fID == "" {
			validationErrors = append(validationErrors, fmt.Sprintf("findings[%d].finding_id is required", i))
			continue
		}
		if findingMap[fID] {
			validationErrors = append(validationErrors, fmt.Sprintf("duplicate finding_id %q in findings register", fID))
		}
		findingMap[fID] = true

		// Check associated control IDs exist in controls list or limitations
		for _, cID := range f.AssociatedControlIDs {
			if !controlMap[cID] {
				hasLimitation := false
				for _, lim := range d.Summary.Limitations {
					if strings.Contains(lim, cID) {
						hasLimitation = true
						break
					}
				}
				if !hasLimitation {
					validationErrors = append(validationErrors, fmt.Sprintf("findings[%d] (%s): associated control %q not found in dossier controls", i, fID, cID))
				}
			}
		}
	}
	if len(d.Findings) > 0 && d.Summary.TotalFindings != len(d.Findings) {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.total_findings (%d) does not match findings count (%d)",
			d.Summary.TotalFindings, len(d.Findings)))
	}

	// 6. Evidence Register Validation
	evidenceMap := make(map[string]bool)
	for i, e := range d.Evidence {
		eID := strings.TrimSpace(e.EvidenceID)
		if eID == "" {
			validationErrors = append(validationErrors, fmt.Sprintf("evidence[%d].evidence_id is required", i))
			continue
		}
		if evidenceMap[eID] {
			validationErrors = append(validationErrors, fmt.Sprintf("duplicate evidence_id %q in evidence register", eID))
		}
		evidenceMap[eID] = true

		if e.ControlID != "" && !controlMap[e.ControlID] {
			hasLimitation := false
			for _, lim := range d.Summary.Limitations {
				if strings.Contains(lim, e.ControlID) {
					hasLimitation = true
					break
				}
			}
			if !hasLimitation {
				validationErrors = append(validationErrors, fmt.Sprintf("evidence[%d] (%s): references control %q not found in dossier controls", i, eID, e.ControlID))
			}
		}

		if e.FindingID != "" && len(d.Findings) > 0 && !findingMap[e.FindingID] {
			validationErrors = append(validationErrors, fmt.Sprintf("evidence[%d] (%s): references finding %q not found in dossier findings", i, eID, e.FindingID))
		}

		// Reject claim of verified evidence when verification status does not support it
		if e.Verified && e.VerificationStatus != "VERIFIED" {
			validationErrors = append(validationErrors, fmt.Sprintf("evidence[%d] (%s): marked verified=true but verification_status is %q", i, eID, e.VerificationStatus))
		}
	}
	if len(d.Evidence) > 0 && d.Summary.TotalEvidenceLinks != len(d.Evidence) {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.total_evidence_links (%d) does not match evidence count (%d)",
			d.Summary.TotalEvidenceLinks, len(d.Evidence)))
	}

	// 7. Remediation Register Validation
	remMap := make(map[string]bool)
	for i, r := range d.Remediation {
		rID := strings.TrimSpace(r.RemediationID)
		if rID == "" {
			validationErrors = append(validationErrors, fmt.Sprintf("remediation[%d].remediation_id is required", i))
			continue
		}
		if remMap[rID] {
			validationErrors = append(validationErrors, fmt.Sprintf("duplicate remediation_id %q in remediation register", rID))
		}
		remMap[rID] = true

		if r.ControlID != "" && !controlMap[r.ControlID] {
			validationErrors = append(validationErrors, fmt.Sprintf("remediation[%d] (%s): references control %q not found in dossier controls", i, rID, r.ControlID))
		}

		if r.FindingID != "" && len(d.Findings) > 0 && !findingMap[r.FindingID] {
			validationErrors = append(validationErrors, fmt.Sprintf("remediation[%d] (%s): references finding %q not found in dossier findings", i, rID, r.FindingID))
		}

		// Impossible lifecycle timestamps
		if r.CompletedAt != nil {
			if !r.SLAStartTime.IsZero() && r.CompletedAt.Before(r.SLAStartTime) {
				validationErrors = append(validationErrors, fmt.Sprintf("remediation[%d] (%s): completed_at precedes sla_start_time", i, rID))
			}
			if !r.AssignedAt.IsZero() && r.CompletedAt.Before(r.AssignedAt) {
				validationErrors = append(validationErrors, fmt.Sprintf("remediation[%d] (%s): completed_at precedes assigned_at", i, rID))
			}
		}
	}
	if len(d.Remediation) > 0 && d.Summary.TotalRemediations != len(d.Remediation) {
		validationErrors = append(validationErrors, fmt.Sprintf("summary.total_remediations (%d) does not match remediation count (%d)",
			d.Summary.TotalRemediations, len(d.Remediation)))
	}

	// 7b. Structured Limitations & Coverage Basis Validation
	if len(d.StructuredLimitations) > 0 {
		if err := ValidateLimitations(d.StructuredLimitations); err != nil {
			validationErrors = append(validationErrors, fmt.Sprintf("invalid structured limitations: %v", err))
		}
	}
	if d.CoverageBasis != nil {
		cb := d.CoverageBasis
		if cb.ApplicableControls != (cb.TotalCatalogControls - cb.NotApplicableControls) {
			validationErrors = append(validationErrors, fmt.Sprintf("invalid coverage basis: applicable (%d) != total (%d) - not_applicable (%d)",
				cb.ApplicableControls, cb.TotalCatalogControls, cb.NotApplicableControls))
		}
	}

	// 8. Logical Digest Validation
	if d.LogicalDigest != "" {
		if !strings.HasPrefix(d.LogicalDigest, "sha256:") || len(d.LogicalDigest) != 71 {
			validationErrors = append(validationErrors, fmt.Sprintf("invalid logical_digest format %q; must be sha256:<64 hex chars>", d.LogicalDigest))
		} else {
			recomputed := ComputeDossierLogicalDigest(d)
			if recomputed != d.LogicalDigest {
				return fmt.Errorf("%w: recorded %s, recomputed %s", ErrDossierDigestMismatch, d.LogicalDigest, recomputed)
			}
		}
	}

	if len(validationErrors) > 0 {
		return fmt.Errorf("%w (%d error(s)): %s", ErrInvalidDossier, len(validationErrors), strings.Join(validationErrors, "; "))
	}

	return nil
}

// LoadDossierFromJSON parses and validates a ComplianceDossier from JSON bytes.
func LoadDossierFromJSON(data []byte) (*ComplianceDossier, error) {
	if len(data) == 0 || len(bytes.TrimSpace(data)) == 0 {
		return nil, errors.New("empty dossier payload")
	}

	var d ComplianceDossier
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return nil, fmt.Errorf("failed parsing compliance dossier JSON: %w", err)
	}

	if err := ValidateDossier(&d); err != nil {
		return nil, err
	}

	return &d, nil
}

// LoadDossierFromFile reads, parses, and validates a ComplianceDossier from a file path.
func LoadDossierFromFile(path string) (*ComplianceDossier, error) {
	cleanPath := strings.TrimSpace(path)
	if cleanPath == "" {
		return nil, errors.New("dossier file path cannot be empty")
	}

	cleanPath = filepath.Clean(cleanPath)
	info, err := os.Stat(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed accessing dossier file %q: %w", cleanPath, err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("dossier path %q is a directory, not a file", cleanPath)
	}

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed opening dossier file %q: %w", cleanPath, err)
	}
	defer f.Close()

	// Max dossier payload limit: 50MB
	limitReader := io.LimitReader(f, 50*1024*1024+1)
	raw, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading dossier file: %w", err)
	}
	if len(raw) > 50*1024*1024 {
		return nil, fmt.Errorf("dossier payload exceeds maximum allowed size of 50MB")
	}

	return LoadDossierFromJSON(raw)
}
