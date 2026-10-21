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

// CurrentEvaluationEngineVersion defines the semantic version of the FELIX compliance evaluation engine.
const CurrentEvaluationEngineVersion = "1.0.0"

// EvaluationState defines the discrete compliance outcome for a control.
// Invariant: An evaluation outcome must never claim more than the available evidence establishes.
type EvaluationState string

const (
	// StateCompliant: Sufficient valid evidence establishes that the defined control requirement is satisfied within the assessed scope.
	StateCompliant EvaluationState = "compliant"

	// StateNonCompliant: Sufficient valid evidence establishes that the defined control requirement is not satisfied.
	StateNonCompliant EvaluationState = "non_compliant"

	// StatePartiallyCompliant: Reliable evidence establishes that some, but not all, applicable control requirements are satisfied.
	StatePartiallyCompliant EvaluationState = "partially_compliant"

	// StateNotAssessed: No valid evaluation was performed for the control.
	StateNotAssessed EvaluationState = "not_assessed"

	// StateInsufficientEvidence: An evaluation was attempted, but available evidence cannot justify a conclusive outcome.
	StateInsufficientEvidence EvaluationState = "insufficient_evidence"

	// StateNotApplicable: The control was explicitly determined not to apply to the assessed target, based on a supported, recorded applicability determination.
	StateNotApplicable EvaluationState = "not_applicable"

	// StateError: The control could not be evaluated because of a concrete evaluation error.
	StateError EvaluationState = "error"
)

// CanonicalEvaluationState parses, normalizes, and validates an evaluation state string.
func CanonicalEvaluationState(s string) (EvaluationState, bool) {
	trimmed := strings.ToLower(strings.TrimSpace(s))
	switch trimmed {
	case "compliant":
		return StateCompliant, true
	case "non_compliant":
		return StateNonCompliant, true
	case "partially_compliant":
		return StatePartiallyCompliant, true
	case "not_assessed":
		return StateNotAssessed, true
	case "insufficient_evidence":
		return StateInsufficientEvidence, true
	case "not_applicable":
		return StateNotApplicable, true
	case "error":
		return StateError, true
	default:
		return "", false
	}
}

// ValidateEvaluationState checks if an evaluation state is one of the 7 supported canonical states.
func ValidateEvaluationState(s EvaluationState) error {
	if _, ok := CanonicalEvaluationState(string(s)); ok {
		return nil
	}
	return fmt.Errorf("invalid evaluation state %q; must be one of: compliant, non_compliant, partially_compliant, not_assessed, insufficient_evidence, not_applicable, error", s)
}

// ApplicabilityDetermination captures an explicit, audited scoping decision for a control.
type ApplicabilityDetermination struct {
	ControlID  string         `json:"control_id"`
	Applicable bool           `json:"applicable"`
	Rationale  string         `json:"rationale"`
	Basis      string         `json:"basis"` // e.g. POLICY_EXEMPTION, CLOUD_PROVIDER_MANAGED, ARCHITECTURAL_INAPPLICABILITY
	ApprovedBy string         `json:"approved_by,omitempty"`
	Metadata   map[string]any `json:"metadata,omitempty"`
}

// PositiveEvidence represents verified proof that a security control or requirement is implemented and active.
type PositiveEvidence struct {
	ID          string    `json:"id"`
	ControlID   string    `json:"control_id"`
	Location    string    `json:"location,omitempty"`
	Requirement string    `json:"requirement,omitempty"`
	Observation string    `json:"observation"`
	Method      string    `json:"method"`
	Timestamp   time.Time `json:"timestamp,omitempty"`
	Provenance  string    `json:"provenance,omitempty"`
}

// EvaluationContext provides the operational assessment context, target scope, and applicability decisions for evaluation.
type EvaluationContext struct {
	AssessmentID        string                                `json:"assessment_id"`
	ExecutionID         string                                `json:"execution_id,omitempty"`
	AssessmentStatus    string                                `json:"assessment_status"` // e.g. COMPLETED, COMPLETED_WITH_ERRORS, CANCELLED, FAILED
	TargetScope         []string                              `json:"target_scope,omitempty"`
	ControlRequirements map[string][]string                   `json:"control_requirements,omitempty"`
	Applicability       map[string]ApplicabilityDetermination `json:"applicability,omitempty"`
	PositiveEvidence    []PositiveEvidence                    `json:"positive_evidence,omitempty"`
	EvaluatedControls   []string                              `json:"evaluated_controls,omitempty"`
	ExecutionErrors     map[string]string                     `json:"execution_errors,omitempty"` // map[control_id]errorMessage
	Metadata            map[string]any                        `json:"metadata,omitempty"`
}

// ControlEvaluationRecord represents the complete, evidence-backed evaluation result for a single control.
type ControlEvaluationRecord struct {
	EvaluationID          string          `json:"evaluation_id"`
	CatalogID             string          `json:"catalog_id"`
	CatalogVersion        string          `json:"catalog_version"`
	ControlID             string          `json:"control_id"`
	ControlTitle          string          `json:"control_title,omitempty"`
	AssessmentID          string          `json:"assessment_id"`
	ExecutionID           string          `json:"execution_id,omitempty"`
	State                 EvaluationState `json:"state"`
	Rationale             string          `json:"rationale"`
	FindingIDs            []string        `json:"finding_ids,omitempty"`
	EvidenceReferences    []string        `json:"evidence_references,omitempty"`
	SupportingEvidence    []string        `json:"supporting_evidence,omitempty"`    // Positive evidence satisfying requirement
	ContradictingEvidence []string        `json:"contradicting_evidence,omitempty"` // Violating evidence failing requirement
	EvaluatedAt           time.Time       `json:"evaluated_at"`
	EngineVersion         string          `json:"engine_version"`
	MappingRuleSetVersion string          `json:"mapping_ruleset_version,omitempty"`
	MappingRuleSetDigest  string          `json:"mapping_ruleset_digest,omitempty"`
	Limitations           string          `json:"limitations,omitempty"`
}

// EvaluationSummary provides quantitative aggregates of control outcomes across the evaluation scope.
type EvaluationSummary struct {
	TotalControls             int `json:"total_controls"`
	CompliantCount            int `json:"compliant_count"`
	NonCompliantCount         int `json:"non_compliant_count"`
	PartiallyCompliantCount   int `json:"partially_compliant_count"`
	NotAssessedCount          int `json:"not_assessed_count"`
	InsufficientEvidenceCount int `json:"insufficient_evidence_count"`
	NotApplicableCount        int `json:"not_applicable_count"`
	ErrorCount                int `json:"error_count"`
	ApplicableControls        int `json:"applicable_controls"`
	AssessedControls          int `json:"assessed_controls"`
}

// EvaluationPolicy configures evidence evaluation parameters and conflict resolution rules.
type EvaluationPolicy struct {
	AllowPartialCompliance bool `json:"allow_partial_compliance"` // Enable sub-requirement partial compliance evaluation
	RequireDirectEvidence  bool `json:"require_direct_evidence"`  // Require direct relationship for non-compliance determinations
	StrictAssessmentStatus bool `json:"strict_assessment_status"` // Require assessment status to be COMPLETED or COMPLETED_WITH_ERRORS
}

// DefaultEvaluationPolicy returns the canonical evaluation policy for FELIX.
func DefaultEvaluationPolicy() EvaluationPolicy {
	return EvaluationPolicy{
		AllowPartialCompliance: true,
		RequireDirectEvidence:  false,
		StrictAssessmentStatus: true,
	}
}

// EvaluationResult encapsulates the full compliance evaluation outcome for a catalog.
type EvaluationResult struct {
	CatalogIdentity        string                    `json:"catalog_identity"`
	CatalogDigest          string                    `json:"catalog_digest"`
	MappingRuleSetIdentity string                    `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string                    `json:"mapping_ruleset_digest,omitempty"`
	AssessmentID           string                    `json:"assessment_id"`
	ExecutionID            string                    `json:"execution_id,omitempty"`
	EvaluatedAt            time.Time                 `json:"evaluated_at"`
	EngineVersion          string                    `json:"engine_version"`
	Evaluations            []ControlEvaluationRecord `json:"evaluations"`
	Summary                EvaluationSummary         `json:"summary"`
	LimitationsNotice      string                    `json:"limitations_notice"`
	StructuredLimitations  []ComplianceLimitation    `json:"structured_limitations,omitempty"`
	CoverageBasis          *CoverageBasis            `json:"coverage_basis,omitempty"`
	IntegrityVersion       string                    `json:"integrity_version,omitempty"`
	Verified               bool                      `json:"verified,omitempty"`
}

// EvaluationLimitationsNotice returns the standard disclaimer clarifying that evaluation is strictly evidence-driven.
func EvaluationLimitationsNotice() string {
	return "FELIX Compliance Evaluation Notice: This evaluation reflects automated technical security assessment findings and evidence linkage against defined control requirements. It does NOT constitute a formal regulatory certification, statutory audit, accreditation, or guarantee of complete organizational security. Compliance evaluation states are bounded strictly by the assessed scope and available empirical evidence."
}

// Canonical structures for deterministic hashing of EvaluationResult
type canonicalEvaluationRecord struct {
	CatalogID             string   `json:"catalog_id"`
	CatalogVersion        string   `json:"catalog_version"`
	ControlID             string   `json:"control_id"`
	AssessmentID          string   `json:"assessment_id"`
	ExecutionID           string   `json:"execution_id,omitempty"`
	State                 string   `json:"state"`
	Rationale             string   `json:"rationale"`
	FindingIDs            []string `json:"finding_ids,omitempty"`
	EvidenceReferences    []string `json:"evidence_references,omitempty"`
	SupportingEvidence    []string `json:"supporting_evidence,omitempty"`
	ContradictingEvidence []string `json:"contradicting_evidence,omitempty"`
	EngineVersion         string   `json:"engine_version"`
	MappingRuleSetVersion string   `json:"mapping_ruleset_version,omitempty"`
	MappingRuleSetDigest  string   `json:"mapping_ruleset_digest,omitempty"`
}

type canonicalEvaluationResult struct {
	CatalogIdentity        string                      `json:"catalog_identity"`
	CatalogDigest          string                      `json:"catalog_digest"`
	MappingRuleSetIdentity string                      `json:"mapping_ruleset_identity,omitempty"`
	MappingRuleSetDigest   string                      `json:"mapping_ruleset_digest,omitempty"`
	AssessmentID           string                      `json:"assessment_id"`
	ExecutionID            string                      `json:"execution_id,omitempty"`
	EngineVersion          string                      `json:"engine_version"`
	Evaluations            []canonicalEvaluationRecord `json:"evaluations"`
	Summary                EvaluationSummary           `json:"summary"`
}

// Digest computes a deterministic SHA-256 digest of the semantic evaluation outcome.
// Timestamps are excluded from the digest calculation so identical evidence and policies yield equivalent digests.
func (res *EvaluationResult) Digest() string {
	if res == nil {
		return ""
	}

	cRes := canonicalEvaluationResult{
		CatalogIdentity:        strings.TrimSpace(res.CatalogIdentity),
		CatalogDigest:          strings.TrimSpace(res.CatalogDigest),
		MappingRuleSetIdentity: strings.TrimSpace(res.MappingRuleSetIdentity),
		MappingRuleSetDigest:   strings.TrimSpace(res.MappingRuleSetDigest),
		AssessmentID:           strings.TrimSpace(res.AssessmentID),
		ExecutionID:            strings.TrimSpace(res.ExecutionID),
		EngineVersion:          strings.TrimSpace(res.EngineVersion),
		Summary:                res.Summary,
	}

	if len(res.Evaluations) > 0 {
		cRes.Evaluations = make([]canonicalEvaluationRecord, len(res.Evaluations))
		for i, ev := range res.Evaluations {
			fIDs := append([]string(nil), ev.FindingIDs...)
			sort.Strings(fIDs)

			evRefs := append([]string(nil), ev.EvidenceReferences...)
			sort.Strings(evRefs)

			suppEv := append([]string(nil), ev.SupportingEvidence...)
			sort.Strings(suppEv)

			contraEv := append([]string(nil), ev.ContradictingEvidence...)
			sort.Strings(contraEv)

			cRes.Evaluations[i] = canonicalEvaluationRecord{
				CatalogID:             strings.TrimSpace(ev.CatalogID),
				CatalogVersion:        strings.TrimSpace(ev.CatalogVersion),
				ControlID:             strings.TrimSpace(ev.ControlID),
				AssessmentID:          strings.TrimSpace(ev.AssessmentID),
				ExecutionID:           strings.TrimSpace(ev.ExecutionID),
				State:                 string(ev.State),
				Rationale:             strings.TrimSpace(ev.Rationale),
				FindingIDs:            fIDs,
				EvidenceReferences:    evRefs,
				SupportingEvidence:    suppEv,
				ContradictingEvidence: contraEv,
				EngineVersion:         strings.TrimSpace(ev.EngineVersion),
				MappingRuleSetVersion: strings.TrimSpace(ev.MappingRuleSetVersion),
				MappingRuleSetDigest:  strings.TrimSpace(ev.MappingRuleSetDigest),
			}
		}

		sort.SliceStable(cRes.Evaluations, func(a, b int) bool {
			return cRes.Evaluations[a].ControlID < cRes.Evaluations[b].ControlID
		})
	}

	data, err := json.Marshal(cRes)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}
