package correlation

import (
	"fmt"
	"strings"
)

// Explicit Phase 5 ValidationStatus extensions (aligned with legacy ValidationStatus).
const (
	ValidationHighConfidence ValidationStatus = "HIGH_CONFIDENCE"
	ValidationCandidate      ValidationStatus = "CANDIDATE"
	ValidationNotReachable   ValidationStatus = "NOT_REACHABLE"
	ValidationNotTested      ValidationStatus = "NOT_TESTED"
	ValidationInvalid        ValidationStatus = "INVALID"
)

// Explicit Phase 5 PathStatus states.
const (
	PathConfirmed      PathStatus = "CONFIRMED"
	PathHighConfidence PathStatus = "HIGH_CONFIDENCE"
	PathNotReachable   PathStatus = "NOT_REACHABLE"
	PathNotTested      PathStatus = "NOT_TESTED"
)

// Explicit extensible Phase 5 RelationshipTypes.
const (
	RelCredEnablesAccess   RelationshipType = "CREDENTIAL_ENABLES_ACCESS"
	RelInfoRevealsResource RelationshipType = "INFO_DISCLOSURE_REVEALS_RESOURCE"
	RelBACCrossTenant      RelationshipType = "BROKEN_ACCESS_CONTROL_CROSS_TENANT"
	RelPrivEscRestricted   RelationshipType = "PRIVILEGE_ESCALATION_ENABLES_FUNCTION"
	RelSessionCompromise   RelationshipType = "SESSION_COMPROMISE_SWITCHES_IDENTITY"
)

// ReachabilityStatus describes step-to-step transition reachability.
type ReachabilityStatus string

const (
	ReachabilityReachable    ReachabilityStatus = "REACHABLE"
	ReachabilityNotReachable ReachabilityStatus = "NOT_REACHABLE"
	ReachabilityInconclusive ReachabilityStatus = "INCONCLUSIVE"
	ReachabilityNotTested    ReachabilityStatus = "NOT_TESTED"
)

// CredentialValidationStatus classifies credential relationship usability.
type CredentialValidationStatus string

const (
	CredVerified     CredentialValidationStatus = "VERIFIED"
	CredCandidate    CredentialValidationStatus = "CANDIDATE"
	CredInvalid      CredentialValidationStatus = "INVALID"
	CredNotTested    CredentialValidationStatus = "NOT_TESTED"
	CredInconclusive CredentialValidationStatus = "INCONCLUSIVE"
)

// CredentialVerificationResult records the outcome of credential relationship validation
// without exposing raw tokens or secrets.
type CredentialVerificationResult struct {
	ID                string                     `json:"id"`
	Status            CredentialValidationStatus `json:"status"`
	SourceFindingID   string                     `json:"source_finding_id"`
	SourceEvidenceRef string                     `json:"source_evidence_ref"`
	TokenFingerprint  string                     `json:"token_fingerprint,omitempty"`
	TokenKind         string                     `json:"token_kind,omitempty"`
	IsPlaceholder     bool                       `json:"is_placeholder,omitempty"`
	PlaceholderReason string                     `json:"placeholder_reason,omitempty"`
	IntendedIdentity  string                     `json:"intended_identity,omitempty"`
	ObservedIdentity  string                     `json:"observed_identity,omitempty"`
	IdentityMatched   bool                       `json:"identity_matched"`
	TargetScope       string                     `json:"target_scope,omitempty"`
	ScopeValid        bool                       `json:"scope_valid"`
	UsabilityChecked  bool                       `json:"usability_checked"`
	HTTPStatus        int                        `json:"http_status,omitempty"`
	EvidenceSummary   string                     `json:"evidence_summary"`
	Limitation        string                     `json:"limitation,omitempty"`
}

// StepVerification records the Phase 5 Section 4 validation trace for a single attack step.
type StepVerification struct {
	StepIndex           int                `json:"step_index"`
	FindingID           string             `json:"finding_id"`
	EdgeID              string             `json:"edge_id,omitempty"`
	EntryCondition      string             `json:"entry_condition"`
	RequiredIdentity    string             `json:"required_identity"`
	RequiredPermissions string             `json:"required_permissions"`
	TargetResource      string             `json:"target_resource"`
	Method              string             `json:"method,omitempty"`
	ExpectedResult      string             `json:"expected_result"`
	ObservedResult      string             `json:"observed_result"`
	EvidenceRefs        []string           `json:"evidence_refs"`
	NextStepReachable   ReachabilityStatus `json:"next_step_reachable"`
	ValidationStatus    ValidationStatus   `json:"validation_status"`
	HTTPStatus          int                `json:"http_status,omitempty"`
	ImpactVerified      bool               `json:"impact_verified"`
	DemonstratedImpact  string             `json:"demonstrated_impact,omitempty"`
	UnverifiedImpact    string             `json:"unverified_impact,omitempty"`
	Limitations         []string           `json:"limitations,omitempty"`
}

// IsConfirmedStatus reports whether a PathStatus represents full empirical confirmation
// (supporting both legacy PathVerified and Phase 5 PathConfirmed).
func IsConfirmedStatus(s PathStatus) bool {
	return s == PathConfirmed || s == PathVerified
}

// IsConfirmedEdgeStatus reports whether an edge ValidationStatus is confirmed.
func IsConfirmedEdgeStatus(s ValidationStatus) bool {
	return s == ValidationConfirmed
}

// NormalizeEdgeStatus maps legacy or variant edge statuses into Phase 5 taxonomy.
func NormalizeEdgeStatus(s ValidationStatus) ValidationStatus {
	upper := ValidationStatus(strings.ToUpper(strings.TrimSpace(string(s))))
	switch upper {
	case ValidationConfirmed:
		return ValidationConfirmed
	case ValidationHighConfidence:
		return ValidationHighConfidence
	case ValidationPlausible, ValidationCandidate:
		return ValidationCandidate
	case ValidationNotReachable:
		return ValidationNotReachable
	case ValidationNotTested, "":
		return ValidationNotTested
	case ValidationInvalid:
		return ValidationInvalid
	case ValidationInconclusive:
		return ValidationInconclusive
	default:
		return ValidationInconclusive
	}
}

// ClassifyPathConfidence deterministically derives the Phase 5 confidence level and human rationale
// from explicit step/edge verification evidence without arbitrary statistical numerical confidence.
func ClassifyPathConfidence(
	path *AttackPath,
	steps []StepVerification,
	credResults []CredentialVerificationResult,
) (PathStatus, string, string) {
	if path == nil {
		return PathInconclusive, string(PathInconclusive), "Nil attack path cannot be classified"
	}

	// Reject / mark invalid if any placeholder or identity-mismatched credential failed verification
	for _, cr := range credResults {
		if cr.Status == CredInvalid {
			reason := fmt.Sprintf("Credential relationship %s rejected as INVALID (%s)", cr.SourceFindingID, cr.EvidenceSummary)
			if cr.IsPlaceholder {
				reason = fmt.Sprintf("Placeholder/example credential %s (%s) cannot establish a verified transition", cr.SourceFindingID, cr.PlaceholderReason)
			}
			return PathNotReachable, string(PathNotReachable), reason
		}
	}

	confirmedEdges := 0
	highConfEdges := 0
	candidateEdges := 0
	inconclusiveEdges := 0
	notReachableEdges := 0
	notTestedEdges := 0
	invalidEdges := 0

	for _, e := range path.Edges {
		switch NormalizeEdgeStatus(e.ValidationStatus) {
		case ValidationConfirmed:
			confirmedEdges++
		case ValidationHighConfidence:
			highConfEdges++
		case ValidationCandidate:
			candidateEdges++
		case ValidationInconclusive:
			inconclusiveEdges++
		case ValidationNotReachable:
			notReachableEdges++
		case ValidationNotTested:
			notTestedEdges++
		case ValidationInvalid:
			invalidEdges++
		}
	}

	confirmedSteps := 0
	notReachableSteps := 0
	inconclusiveSteps := 0
	unverifiedImpactSteps := 0
	notTestedSteps := 0

	for _, st := range steps {
		switch NormalizeEdgeStatus(st.ValidationStatus) {
		case ValidationConfirmed:
			confirmedSteps++
			if !st.ImpactVerified {
				unverifiedImpactSteps++
			}
		case ValidationNotReachable:
			notReachableSteps++
		case ValidationInconclusive:
			inconclusiveSteps++
		case ValidationNotTested:
			notTestedSteps++
		}
		if st.NextStepReachable == ReachabilityNotReachable {
			notReachableSteps++
		}
	}

	hasUnverifiedNode := false
	hasCandidateNode := false
	for _, n := range path.Nodes {
		if !n.IsVerified {
			hasUnverifiedNode = true
			if n.IsCandidate {
				hasCandidateNode = true
			}
		}
	}

	totalEdges := len(path.Edges)
	if invalidEdges > 0 || notReachableEdges > 0 || notReachableSteps > 0 {
		rationale := fmt.Sprintf(
			"%d/%d edge transitions confirmed, %d unreachable/invalid transition(s) blocked traversal under required identity/preconditions",
			confirmedEdges, totalEdges, notReachableEdges+invalidEdges+notReachableSteps,
		)
		return PathNotReachable, string(PathNotReachable), rationale
	}

	if inconclusiveEdges > 0 || inconclusiveSteps > 0 {
		rationale := fmt.Sprintf(
			"%d/%d edge transitions confirmed; %d transition/step test(s) yielded inconclusive evidence",
			confirmedEdges, totalEdges, inconclusiveEdges+inconclusiveSteps,
		)
		return PathInconclusive, string(PathInconclusive), rationale
	}

	if totalEdges > 0 && notTestedEdges == totalEdges && confirmedSteps == 0 {
		rationale := fmt.Sprintf(
			"Structural correlation matched %d transition(s), but active transition reachability validation was not performed (%d NOT_TESTED)",
			totalEdges, notTestedEdges,
		)
		return PathNotTested, string(PathNotTested), rationale
	}

	if totalEdges > 0 && confirmedEdges == totalEdges && len(steps) == 0 {
		rationale := fmt.Sprintf(
			"Edges satisfied %d structural rule transitions, but step-level transition validation has not been executed (NOT_TESTED)",
			totalEdges,
		)
		return PathNotTested, string(PathNotTested), rationale
	}

	if totalEdges > 0 && confirmedEdges == totalEdges && !hasUnverifiedNode && len(steps) > 0 && unverifiedImpactSteps == 0 && notTestedSteps == 0 {
		rationale := fmt.Sprintf(
			"All %d/%d directed transitions and %d step impact checks passed with direct observable evidence and verified identity isolation",
			confirmedEdges, totalEdges, len(steps),
		)
		return PathConfirmed, string(PathConfirmed), rationale
	}

	// Partial validation: e.g., 2 verified transitions and 1 unverified/candidate/not-tested transition (Fixture I),
	// OR all edges confirmed at HTTP transition level while final impact demonstration awaits non-destructive fixture verification
	if (confirmedEdges >= 2 && (candidateEdges > 0 || notTestedEdges > 0 || highConfEdges > 0 || unverifiedImpactSteps > 0 || hasUnverifiedNode)) ||
		(confirmedEdges == totalEdges && (highConfEdges > 0 || unverifiedImpactSteps > 0)) {
		unverified := totalEdges - confirmedEdges + unverifiedImpactSteps
		if unverified <= 0 {
			unverified = 1
		}
		rationale := fmt.Sprintf(
			"Partially validated path: %d/%d transitions empirically verified, %d transition/impact check(s) remain unverified or constrained; cannot be classified CONFIRMED",
			confirmedEdges, totalEdges, unverified,
		)
		return PathHighConfidence, string(PathHighConfidence), rationale
	}

	if hasCandidateNode || candidateEdges > 0 || notTestedEdges > 0 {
		rationale := fmt.Sprintf(
			"Plausible path: %d/%d transitions verified, %d candidate/untested transition(s) require transition reachability proof",
			confirmedEdges, totalEdges, candidateEdges+notTestedEdges,
		)
		return PathCandidate, string(PathCandidate), rationale
	}

	return PathInconclusive, string(PathInconclusive), "Insufficient direct evidence to confirm attack path transitions"
}
