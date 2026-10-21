package compliance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/clierror"
)

// GateOptions configures the runtime environment for gate evaluation.
type GateOptions struct {
	KeyProvider      KeyProvider
	StrictIntegrity  bool
	AssessmentStatus string // Override status if provided (e.g. COMPLETED, FAILED, CANCELLED)
	ComplianceStore  ComplianceStore
	RemediationStore ComplianceStore
	Now              time.Time // Deterministic clock override for testing
	ReportPath       string
}

// ComplianceGateService executes evidence-backed compliance gating decisions against evaluation records.
type ComplianceGateService struct{}

// NewComplianceGateService instantiates a new compliance gate evaluation service.
func NewComplianceGateService() *ComplianceGateService {
	return &ComplianceGateService{}
}

// EvaluateFromStore loads the evaluation and remediation records from a ComplianceStore and evaluates the gate.
func (s *ComplianceGateService) EvaluateFromStore(store ComplianceStore, assessmentID, catalogID string, policy *ComplianceGatePolicy, opts GateOptions) *ComplianceGateResult {
	if store == nil {
		return s.createOperationalFailureResult(assessmentID, catalogID, policy, "compliance store is nil", clierror.ExitOperational)
	}

	eval, err := store.GetEvaluationResult(assessmentID, catalogID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return s.createOperationalFailureResult(assessmentID, catalogID, policy, fmt.Sprintf("no compliance evaluation found for assessment %q (catalog: %q)", assessmentID, catalogID), clierror.ExitOperational)
		}
		return s.createOperationalFailureResult(assessmentID, catalogID, policy, fmt.Sprintf("failed retrieving evaluation result: %v", err), clierror.ExitOperational)
	}

	opts.ComplianceStore = store
	if opts.RemediationStore == nil {
		opts.RemediationStore = store
	}

	return s.EvaluateEvaluationResult(eval, policy, opts)
}

// EvaluateDossier adapts a ComplianceDossier snapshot and evaluates it against the compliance gate policy.
func (s *ComplianceGateService) EvaluateDossier(dossier *ComplianceDossier, policy *ComplianceGatePolicy, opts GateOptions) *ComplianceGateResult {
	if dossier == nil {
		return s.createOperationalFailureResult("", "", policy, "compliance dossier is nil", clierror.ExitOperational)
	}

	// Adapt dossier controls into ControlEvaluationRecords
	records := make([]ControlEvaluationRecord, 0, len(dossier.Controls))
	for _, c := range dossier.Controls {
		fIDs := make([]string, len(c.MappedFindings))
		for idx, mf := range c.MappedFindings {
			fIDs[idx] = mf.FindingID
		}
		records = append(records, ControlEvaluationRecord{
			EvaluationID:          fmt.Sprintf("dossier:%s:%s", dossier.Identity.AssessmentID, c.ControlID),
			CatalogID:             dossier.Identity.CatalogID,
			CatalogVersion:        dossier.Identity.CatalogVersion,
			ControlID:             c.ControlID,
			ControlTitle:          c.ControlTitle,
			AssessmentID:          dossier.Identity.AssessmentID,
			ExecutionID:           dossier.Identity.ExecutionID,
			State:                 c.EvaluationState,
			Rationale:             c.Rationale,
			FindingIDs:            fIDs,
			SupportingEvidence:    c.SupportingEvidence,
			ContradictingEvidence: c.ContradictingEvidence,
			EvaluatedAt:           dossier.Identity.GeneratedAt,
		})
	}

	eval := &EvaluationResult{
		CatalogIdentity:        fmt.Sprintf("%s:%s", dossier.Identity.CatalogID, dossier.Identity.CatalogVersion),
		CatalogDigest:          dossier.Identity.CatalogDigest,
		MappingRuleSetIdentity: dossier.Identity.MappingRuleSetID,
		MappingRuleSetDigest:   dossier.Identity.MappingRuleSetDigest,
		AssessmentID:           dossier.Identity.AssessmentID,
		ExecutionID:            dossier.Identity.ExecutionID,
		EvaluatedAt:            dossier.Identity.GeneratedAt,
		EngineVersion:          dossier.Identity.FelixVersion,
		Evaluations:            records,
		Summary: EvaluationSummary{
			TotalControls:             dossier.Summary.TotalControls,
			CompliantCount:            dossier.Summary.CompliantCount,
			NonCompliantCount:         dossier.Summary.NonCompliantCount,
			PartiallyCompliantCount:   dossier.Summary.PartiallyCompliantCount,
			NotAssessedCount:          dossier.Summary.NotAssessedCount,
			InsufficientEvidenceCount: dossier.Summary.InsufficientEvidenceCount,
			NotApplicableCount:        dossier.Summary.NotApplicableCount,
			ErrorCount:                dossier.Summary.ErrorCount,
			ApplicableControls:        dossier.Summary.ApplicableControls,
			AssessedControls:          dossier.Summary.AssessedControls,
		},
		LimitationsNotice: EvaluationLimitationsNotice(),
	}

	return s.EvaluateEvaluationResult(eval, policy, opts)
}

// EvaluateEvaluationResult executes the complete, deterministic compliance gate algorithm against an EvaluationResult.
func (s *ComplianceGateService) EvaluateEvaluationResult(eval *EvaluationResult, policy *ComplianceGatePolicy, opts GateOptions) *ComplianceGateResult {
	now := opts.Now
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// 1. Guard against nil or empty inputs
	if eval == nil {
		return s.createOperationalFailureResult("", "", policy, "compliance evaluation result is nil", clierror.ExitOperational)
	}
	if policy == nil {
		return s.createOperationalFailureResult(eval.AssessmentID, eval.CatalogIdentity, nil, "compliance gate policy is nil", clierror.ExitOperational)
	}
	if err := ValidateGatePolicy(policy); err != nil {
		return s.createOperationalFailureResult(eval.AssessmentID, eval.CatalogIdentity, policy, fmt.Sprintf("gate policy validation failed: %v", err), clierror.ExitOperational)
	}

	res := &ComplianceGateResult{
		AssessmentID:           eval.AssessmentID,
		ExecutionID:            eval.ExecutionID,
		CatalogIdentity:        eval.CatalogIdentity,
		CatalogDigest:          eval.CatalogDigest,
		MappingRuleSetIdentity: eval.MappingRuleSetIdentity,
		MappingRuleSetDigest:   eval.MappingRuleSetDigest,
		PolicyID:               policy.ID,
		PolicyVersion:          policy.Version,
		PolicyName:             policy.Name,
		EvaluatedAt:            now,
		Conditions:             make([]GateConditionResult, 0),
		Violations:             make([]string, 0),
		OperationalErrors:      make([]string, 0),
		IndeterminateReasons:   make([]string, 0),
		LimitationsNotice:      ComplianceGateLimitationsNotice(),
	}

	// 2. Assessment Status and Completeness Verification
	status := strings.ToUpper(strings.TrimSpace(opts.AssessmentStatus))
	if status == "FAILED" || status == "CANCELLED" || status == "INTERRUPTED" || status == "DRAFT" || status == "READY" || status == "SKIPPED" {
		msg := fmt.Sprintf("assessment execution was not completed (status: %s)", status)
		res.OperationalErrors = append(res.OperationalErrors, msg)
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Assessment Execution Completeness",
			Category: "assessment_status",
			Status:   "FAILED",
			Message:  msg,
			Expected: "COMPLETED",
			Actual:   status,
		})
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Assessment Execution Completeness",
			Category: "assessment_status",
			Status:   "PASSED",
			Message:  "Assessment execution is completed and valid for gate evaluation",
			Expected: "COMPLETED",
			Actual:   status,
		})
	}

	// 3. Target Catalog & Version Verification
	if policy.TargetCatalog != "" {
		expectedCat := strings.TrimSpace(policy.TargetCatalog)
		catIdentity := strings.TrimSpace(eval.CatalogIdentity)

		match := catIdentity == expectedCat ||
			strings.HasPrefix(catIdentity, expectedCat+":") ||
			strings.Split(catIdentity, ":")[0] == expectedCat

		if !match {
			msg := fmt.Sprintf("evaluation catalog %q does not match policy target catalog %q", catIdentity, expectedCat)
			res.OperationalErrors = append(res.OperationalErrors, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Target Catalog Match",
				Category: "catalog_validation",
				Status:   "FAILED",
				Message:  msg,
				Expected: expectedCat,
				Actual:   catIdentity,
			})
		} else {
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Target Catalog Match",
				Category: "catalog_validation",
				Status:   "PASSED",
				Message:  fmt.Sprintf("Catalog %q satisfies policy target %q", catIdentity, expectedCat),
				Expected: expectedCat,
				Actual:   catIdentity,
			})
		}
	}

	// 4. Cryptographic Integrity and Authenticity Verification
	reqIntegrity := policy.GetRequireIntegrity() || opts.StrictIntegrity
	reqHMAC := policy.GetRequireHMAC()

	if reqIntegrity || reqHMAC {
		if opts.ComplianceStore != nil {
			integ, err := opts.ComplianceStore.VerifyEvaluationIntegrity(eval.AssessmentID, eval.CatalogIdentity, opts.KeyProvider)
			if err != nil {
				msg := fmt.Sprintf("integrity verification failed: %v", err)
				res.OperationalErrors = append(res.OperationalErrors, msg)
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     "Cryptographic Integrity",
					Category: "integrity",
					Status:   "FAILED",
					Message:  msg,
					Expected: "VERIFIED",
					Actual:   "ERROR",
				})
			} else {
				res.Integrity = integ
				switch integ.Status {
				case StatusVerified:
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     "Cryptographic Integrity",
						Category: "integrity",
						Status:   "PASSED",
						Message:  "Cryptographic integrity and HMAC authenticity verified successfully",
						Expected: "VERIFIED",
						Actual:   string(integ.Status),
					})
				case StatusIntegrityOnly:
					if reqHMAC {
						msg := "record content digest matches, but cryptographic authenticity (HMAC) is missing"
						res.Violations = append(res.Violations, msg)
						res.Conditions = append(res.Conditions, GateConditionResult{
							Name:     "Cryptographic HMAC Authenticity",
							Category: "integrity",
							Status:   "FAILED",
							Message:  msg,
							Expected: "HMAC Authenticated",
							Actual:   string(integ.Status),
						})
					} else {
						res.Conditions = append(res.Conditions, GateConditionResult{
							Name:     "Cryptographic Integrity",
							Category: "integrity",
							Status:   "PASSED",
							Message:  "Record content digest verified (unauthenticated hash mode)",
							Expected: "INTEGRITY_ONLY",
							Actual:   string(integ.Status),
						})
					}
				case StatusIntegrityMismatch:
					msg := "cryptographic integrity mismatch detected: evaluation record or evidence links were tampered with or corrupted"
					if len(integ.Violations) > 0 {
						msg = fmt.Sprintf("cryptographic integrity mismatch detected: %s", strings.Join(integ.Violations, "; "))
					}
					res.OperationalErrors = append(res.OperationalErrors, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     "Cryptographic Integrity",
						Category: "integrity",
						Status:   "FAILED",
						Message:  msg,
						Expected: "VERIFIED",
						Actual:   string(integ.Status),
					})
				case StatusUnknownKey, StatusVerificationUnavailable:
					msg := fmt.Sprintf("integrity verification key missing or unavailable: %s", integ.Status)
					res.OperationalErrors = append(res.OperationalErrors, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     "Cryptographic Integrity Key",
						Category: "integrity",
						Status:   "FAILED",
						Message:  msg,
						Expected: "Configured Verification Key",
						Actual:   string(integ.Status),
					})
				case StatusUnverifiedLegacy:
					msg := "evaluation record persisted without integrity protection (unverified legacy record)"
					if opts.StrictIntegrity {
						res.OperationalErrors = append(res.OperationalErrors, msg)
					} else {
						res.Violations = append(res.Violations, msg)
					}
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     "Cryptographic Integrity Protection",
						Category: "integrity",
						Status:   "FAILED",
						Message:  msg,
						Expected: "Integrity Protected",
						Actual:   string(integ.Status),
					})
				default:
					msg := fmt.Sprintf("integrity verification operational error: %s", integ.Status)
					res.OperationalErrors = append(res.OperationalErrors, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     "Cryptographic Integrity",
						Category: "integrity",
						Status:   "FAILED",
						Message:  msg,
						Expected: "VERIFIED",
						Actual:   string(integ.Status),
					})
				}
			}
		} else if opts.StrictIntegrity {
			msg := "strict integrity required but compliance store is not available for verification"
			res.OperationalErrors = append(res.OperationalErrors, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Cryptographic Integrity Store",
				Category: "integrity",
				Status:   "FAILED",
				Message:  msg,
				Expected: "Available Store",
				Actual:   "nil",
			})
		}
	}

	// 5. Build Control Index & Breakdown
	ctrlsByID := make(map[string]ControlEvaluationRecord, len(eval.Evaluations))
	for _, ce := range eval.Evaluations {
		ctrlsByID[ce.ControlID] = ce
	}

	// Compute quantitative summary aggregates
	sum := eval.Summary
	if sum.TotalControls == 0 && len(eval.Evaluations) > 0 {
		sum.TotalControls = len(eval.Evaluations)
		for _, ce := range eval.Evaluations {
			switch ce.State {
			case StateCompliant:
				sum.CompliantCount++
			case StateNonCompliant:
				sum.NonCompliantCount++
			case StatePartiallyCompliant:
				sum.PartiallyCompliantCount++
			case StateNotAssessed:
				sum.NotAssessedCount++
			case StateInsufficientEvidence:
				sum.InsufficientEvidenceCount++
			case StateNotApplicable:
				sum.NotApplicableCount++
			case StateError:
				sum.ErrorCount++
			}
		}
		sum.ApplicableControls = sum.TotalControls - sum.NotApplicableCount
		sum.AssessedControls = sum.TotalControls - sum.NotApplicableCount - sum.NotAssessedCount
	}

	applicableControls := sum.TotalControls - sum.NotApplicableCount
	if applicableControls < 0 {
		applicableControls = 0
	}

	compliancePct := 0.0
	if applicableControls > 0 {
		compliancePct = (float64(sum.CompliantCount) / float64(applicableControls)) * 100.0
	} else if sum.TotalControls > 0 {
		compliancePct = 100.0
	}

	assessedPct := 0.0
	if applicableControls > 0 {
		assessedCount := applicableControls - sum.NotAssessedCount
		if assessedCount < 0 {
			assessedCount = 0
		}
		assessedPct = (float64(assessedCount) / float64(applicableControls)) * 100.0
	} else if sum.TotalControls > 0 {
		assessedPct = 100.0
	}

	res.Summary = GateSummary{
		TotalControls:                sum.TotalControls,
		CompliantControls:            sum.CompliantCount,
		NonCompliantControls:         sum.NonCompliantCount,
		PartiallyCompliantControls:   sum.PartiallyCompliantCount,
		NotAssessedControls:          sum.NotAssessedCount,
		InsufficientEvidenceControls: sum.InsufficientEvidenceCount,
		NotApplicableControls:        sum.NotApplicableCount,
		ErrorControls:                sum.ErrorCount,
		CompliancePercent:            compliancePct,
		AssessedPercent:              assessedPct,
	}

	// 6. Check Execution Errors
	if sum.ErrorCount > 0 {
		msg := fmt.Sprintf("%d control(s) encountered execution errors during assessment", sum.ErrorCount)
		res.OperationalErrors = append(res.OperationalErrors, msg)
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Zero Execution Errors",
			Category: "control_compliance",
			Status:   "FAILED",
			Message:  msg,
			Expected: "0",
			Actual:   fmt.Sprintf("%d", sum.ErrorCount),
		})
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Zero Execution Errors",
			Category: "control_compliance",
			Status:   "PASSED",
			Message:  "Zero control execution errors recorded",
			Expected: "0",
			Actual:   "0",
		})
	}

	// 7. Check Non-Compliant Controls
	maxNonComp := policy.GetMaxNonCompliant()
	if sum.NonCompliantCount > maxNonComp {
		msg := fmt.Sprintf("observed %d non-compliant control(s), exceeding policy limit of %d", sum.NonCompliantCount, maxNonComp)
		res.Violations = append(res.Violations, msg)
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Maximum Non-Compliant Controls",
			Category: "control_compliance",
			Status:   "FAILED",
			Message:  msg,
			Expected: fmt.Sprintf("<= %d", maxNonComp),
			Actual:   fmt.Sprintf("%d", sum.NonCompliantCount),
		})
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Maximum Non-Compliant Controls",
			Category: "control_compliance",
			Status:   "PASSED",
			Message:  fmt.Sprintf("Non-compliant control count (%d) within policy limit (%d)", sum.NonCompliantCount, maxNonComp),
			Expected: fmt.Sprintf("<= %d", maxNonComp),
			Actual:   fmt.Sprintf("%d", sum.NonCompliantCount),
		})
	}

	// 8. Check Partially-Compliant Controls
	pcPolicy := policy.GetPartiallyCompliantPolicy()
	maxPartComp := policy.GetMaxPartiallyCompliant()
	if sum.PartiallyCompliantCount > 0 {
		if pcPolicy == "fail" && sum.PartiallyCompliantCount > maxPartComp {
			msg := fmt.Sprintf("observed %d partially-compliant control(s); policy enforces full compliance", sum.PartiallyCompliantCount)
			res.Violations = append(res.Violations, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Partially-Compliant Controls Enforcement",
				Category: "control_compliance",
				Status:   "FAILED",
				Message:  msg,
				Expected: fmt.Sprintf("<= %d (policy: %s)", maxPartComp, pcPolicy),
				Actual:   fmt.Sprintf("%d", sum.PartiallyCompliantCount),
			})
		} else {
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Partially-Compliant Controls Enforcement",
				Category: "control_compliance",
				Status:   "PASSED",
				Message:  fmt.Sprintf("%d partially-compliant control(s) tolerated by policy (%s)", sum.PartiallyCompliantCount, pcPolicy),
				Expected: fmt.Sprintf("tolerated (policy: %s)", pcPolicy),
				Actual:   fmt.Sprintf("%d", sum.PartiallyCompliantCount),
			})
		}
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Partially-Compliant Controls Enforcement",
			Category: "control_compliance",
			Status:   "PASSED",
			Message:  "Zero partially-compliant controls observed",
			Expected: fmt.Sprintf("<= %d", maxPartComp),
			Actual:   "0",
		})
	}

	// 9. Check Insufficient Evidence Controls
	iePolicy := policy.GetInsufficientEvidencePolicy()
	if sum.InsufficientEvidenceCount > 0 {
		msg := fmt.Sprintf("observed %d control(s) with insufficient evidence", sum.InsufficientEvidenceCount)
		switch iePolicy {
		case "indeterminate":
			res.IndeterminateReasons = append(res.IndeterminateReasons, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Evidence Sufficiency",
				Category: "control_compliance",
				Status:   "INDETERMINATE",
				Message:  msg + "; policy treats insufficient evidence as indeterminate",
				Expected: "Sufficient Evidence",
				Actual:   fmt.Sprintf("%d insufficient", sum.InsufficientEvidenceCount),
			})
		case "fail_closed":
			res.Violations = append(res.Violations, msg+"; policy fails closed on missing proof")
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Evidence Sufficiency",
				Category: "control_compliance",
				Status:   "FAILED",
				Message:  msg + "; policy fails closed on missing proof",
				Expected: "0 insufficient controls",
				Actual:   fmt.Sprintf("%d insufficient", sum.InsufficientEvidenceCount),
			})
		default: // "allow"
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Evidence Sufficiency",
				Category: "control_compliance",
				Status:   "PASSED",
				Message:  fmt.Sprintf("%d insufficient evidence control(s) tolerated by policy", sum.InsufficientEvidenceCount),
				Expected: "tolerated",
				Actual:   fmt.Sprintf("%d", sum.InsufficientEvidenceCount),
			})
		}
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Evidence Sufficiency",
			Category: "control_compliance",
			Status:   "PASSED",
			Message:  "All evaluated controls possessed conclusive evidence",
			Expected: "0 insufficient",
			Actual:   "0",
		})
	}

	// 10. Check Unassessed Controls
	unassPolicy := policy.GetUnassessedPolicy()
	if sum.NotAssessedCount > 0 {
		msg := fmt.Sprintf("observed %d unassessed control(s)", sum.NotAssessedCount)
		switch unassPolicy {
		case "indeterminate":
			res.IndeterminateReasons = append(res.IndeterminateReasons, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Assessment Completeness (Unassessed Controls)",
				Category: "control_compliance",
				Status:   "INDETERMINATE",
				Message:  msg + "; policy treats unassessed controls as indeterminate",
				Expected: "Fully Assessed",
				Actual:   fmt.Sprintf("%d unassessed", sum.NotAssessedCount),
			})
		case "fail_closed":
			res.Violations = append(res.Violations, msg+"; policy fails closed on unassessed controls")
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Assessment Completeness (Unassessed Controls)",
				Category: "control_compliance",
				Status:   "FAILED",
				Message:  msg + "; policy fails closed on unassessed controls",
				Expected: "0 unassessed controls",
				Actual:   fmt.Sprintf("%d unassessed", sum.NotAssessedCount),
			})
		default: // "allow"
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Assessment Completeness (Unassessed Controls)",
				Category: "control_compliance",
				Status:   "PASSED",
				Message:  fmt.Sprintf("%d unassessed control(s) tolerated by policy", sum.NotAssessedCount),
				Expected: "tolerated",
				Actual:   fmt.Sprintf("%d", sum.NotAssessedCount),
			})
		}
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Assessment Completeness (Unassessed Controls)",
			Category: "control_compliance",
			Status:   "PASSED",
			Message:  "All catalog controls were assessed",
			Expected: "0 unassessed",
			Actual:   "0",
		})
	}

	// 11. Check Enforced Controls
	if len(policy.EnforcedControls) > 0 {
		for _, reqCtrlID := range policy.EnforcedControls {
			cleanCtrlID := strings.TrimSpace(reqCtrlID)
			rec, exists := ctrlsByID[cleanCtrlID]
			if !exists {
				msg := fmt.Sprintf("enforced control %q was not found in evaluation records", cleanCtrlID)
				res.Violations = append(res.Violations, msg)
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
					Category: "enforced_controls",
					Target:   cleanCtrlID,
					Status:   "FAILED",
					Message:  msg,
					Expected: "compliant",
					Actual:   "missing",
				})
				continue
			}

			switch rec.State {
			case StateCompliant:
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
					Category: "enforced_controls",
					Target:   cleanCtrlID,
					Status:   "PASSED",
					Message:  fmt.Sprintf("Enforced control %s is compliant: %s", cleanCtrlID, rec.Rationale),
					Expected: "compliant",
					Actual:   string(rec.State),
				})
			case StateNonCompliant:
				msg := fmt.Sprintf("enforced control %s is non-compliant: %s", cleanCtrlID, rec.Rationale)
				res.Violations = append(res.Violations, msg)
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
					Category: "enforced_controls",
					Target:   cleanCtrlID,
					Status:   "FAILED",
					Message:  msg,
					Expected: "compliant",
					Actual:   string(rec.State),
				})
			case StatePartiallyCompliant:
				if pcPolicy == "fail" {
					msg := fmt.Sprintf("enforced control %s is only partially compliant: %s", cleanCtrlID, rec.Rationale)
					res.Violations = append(res.Violations, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "FAILED",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				} else {
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "PASSED",
						Message:  fmt.Sprintf("Enforced control %s is partially compliant (tolerated by policy)", cleanCtrlID),
						Expected: "compliant or partial",
						Actual:   string(rec.State),
					})
				}
			case StateInsufficientEvidence:
				msg := fmt.Sprintf("enforced control %s has insufficient evidence: %s", cleanCtrlID, rec.Rationale)
				if iePolicy == "indeterminate" {
					res.IndeterminateReasons = append(res.IndeterminateReasons, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "INDETERMINATE",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				} else {
					res.Violations = append(res.Violations, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "FAILED",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				}
			case StateNotAssessed:
				msg := fmt.Sprintf("enforced control %s was not assessed", cleanCtrlID)
				if unassPolicy == "indeterminate" {
					res.IndeterminateReasons = append(res.IndeterminateReasons, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "INDETERMINATE",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				} else {
					res.Violations = append(res.Violations, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "FAILED",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				}
			case StateError:
				msg := fmt.Sprintf("enforced control %s encountered evaluation error: %s", cleanCtrlID, rec.Rationale)
				res.OperationalErrors = append(res.OperationalErrors, msg)
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
					Category: "enforced_controls",
					Target:   cleanCtrlID,
					Status:   "FAILED",
					Message:  msg,
					Expected: "compliant",
					Actual:   string(rec.State),
				})
			default: // StateNotApplicable
				if policy.GetNotApplicablePolicy() == "fail" {
					msg := fmt.Sprintf("enforced control %s evaluated as not applicable, but policy rejects inapplicability", cleanCtrlID)
					res.Violations = append(res.Violations, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "FAILED",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				} else {
					msg := fmt.Sprintf("enforced control %s evaluated as not applicable; does not satisfy compliance requirement", cleanCtrlID)
					res.Violations = append(res.Violations, msg)
					res.Conditions = append(res.Conditions, GateConditionResult{
						Name:     fmt.Sprintf("Enforced Control: %s", cleanCtrlID),
						Category: "enforced_controls",
						Target:   cleanCtrlID,
						Status:   "FAILED",
						Message:  msg,
						Expected: "compliant",
						Actual:   string(rec.State),
					})
				}
			}
		}
	}

	// 12. Check Minimum Compliance Percentage Threshold
	minCompPct := policy.GetMinCompliancePercent()
	if compliancePct < minCompPct {
		msg := fmt.Sprintf("compliance rate (%.2f%%) is below required minimum threshold of %.2f%%", compliancePct, minCompPct)
		res.Violations = append(res.Violations, msg)
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Minimum Compliance Percentage",
			Category: "thresholds",
			Status:   "FAILED",
			Message:  msg,
			Expected: fmt.Sprintf(">= %.2f%%", minCompPct),
			Actual:   fmt.Sprintf("%.2f%%", compliancePct),
		})
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Minimum Compliance Percentage",
			Category: "thresholds",
			Status:   "PASSED",
			Message:  fmt.Sprintf("Compliance rate (%.2f%%) meets required threshold (>= %.2f%%)", compliancePct, minCompPct),
			Expected: fmt.Sprintf(">= %.2f%%", minCompPct),
			Actual:   fmt.Sprintf("%.2f%%", compliancePct),
		})
	}

	// 13. Check Minimum Assessed Coverage Percentage Threshold
	minAssessedPct := policy.GetMinAssessedPercent()
	if assessedPct < minAssessedPct {
		msg := fmt.Sprintf("assessment coverage rate (%.2f%%) is below required threshold of %.2f%%", assessedPct, minAssessedPct)
		res.Violations = append(res.Violations, msg)
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Minimum Assessed Coverage Percentage",
			Category: "thresholds",
			Status:   "FAILED",
			Message:  msg,
			Expected: fmt.Sprintf(">= %.2f%%", minAssessedPct),
			Actual:   fmt.Sprintf("%.2f%%", assessedPct),
		})
	} else {
		res.Conditions = append(res.Conditions, GateConditionResult{
			Name:     "Minimum Assessed Coverage Percentage",
			Category: "thresholds",
			Status:   "PASSED",
			Message:  fmt.Sprintf("Assessment coverage (%.2f%%) meets required threshold (>= %.2f%%)", assessedPct, minAssessedPct),
			Expected: fmt.Sprintf(">= %.2f%%", minAssessedPct),
			Actual:   fmt.Sprintf("%.2f%%", assessedPct),
		})
	}

	// 14. Remediation SLA Checks (if configured)
	if policy.GetFailOnOverdueSLA() {
		overdueCount := 0
		if opts.RemediationStore != nil {
			records, err := opts.RemediationStore.ListRemediationRecords(RemediationFilter{
				AssessmentID: eval.AssessmentID,
				OnlyOverdue:  true,
			})
			if err != nil {
				msg := fmt.Sprintf("failed querying overdue remediation records: %v", err)
				res.OperationalErrors = append(res.OperationalErrors, msg)
				res.Conditions = append(res.Conditions, GateConditionResult{
					Name:     "Remediation SLA Overdue Check",
					Category: "sla",
					Status:   "FAILED",
					Message:  msg,
					Expected: "Available Store",
					Actual:   "ERROR",
				})
			} else {
				overdueCount = len(records)
			}
		}

		res.Summary.OverdueSLACount = overdueCount
		maxOverdue := policy.GetMaxOverdueSLA()
		if overdueCount > maxOverdue {
			msg := fmt.Sprintf("observed %d overdue remediation SLA item(s), exceeding policy limit of %d", overdueCount, maxOverdue)
			res.Violations = append(res.Violations, msg)
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Remediation SLA Overdue Items",
				Category: "sla",
				Status:   "FAILED",
				Message:  msg,
				Expected: fmt.Sprintf("<= %d", maxOverdue),
				Actual:   fmt.Sprintf("%d", overdueCount),
			})
		} else {
			res.Conditions = append(res.Conditions, GateConditionResult{
				Name:     "Remediation SLA Overdue Items",
				Category: "sla",
				Status:   "PASSED",
				Message:  fmt.Sprintf("Overdue remediation count (%d) within policy limit (%d)", overdueCount, maxOverdue),
				Expected: fmt.Sprintf("<= %d", maxOverdue),
				Actual:   fmt.Sprintf("%d", overdueCount),
			})
		}
	}

	// 15. Tally Final Condition Summary
	passedConds := 0
	failedConds := 0
	indetConds := 0
	for _, c := range res.Conditions {
		switch c.Status {
		case "PASSED":
			passedConds++
		case "FAILED":
			failedConds++
		case "INDETERMINATE":
			indetConds++
		}
	}
	res.Summary.TotalConditions = len(res.Conditions)
	res.Summary.PassedConditions = passedConds
	res.Summary.FailedConditions = failedConds
	res.Summary.IndeterminateConditions = indetConds

	// 16. Sort Violations and Operational Errors Deterministically
	sort.Strings(res.Violations)
	sort.Strings(res.OperationalErrors)
	sort.Strings(res.IndeterminateReasons)

	// 17. Final Decision & Exit Code Resolution
	// Precedence hierarchy:
	// 1. Operational failure (Exit 2)
	// 2. Indeterminate / uncertain evaluation (Exit 2)
	// 3. Trustworthy policy failure (Exit 1)
	// 4. Clean compliance pass (Exit 0)
	if len(res.OperationalErrors) > 0 {
		res.Decision = GateStatusOperationalFailed
		res.ExitCode = clierror.ExitOperational
	} else if len(res.IndeterminateReasons) > 0 {
		res.Decision = GateStatusIndeterminate
		res.ExitCode = clierror.ExitOperational
	} else if len(res.Violations) > 0 {
		res.Decision = GateStatusPolicyFailed
		res.ExitCode = clierror.ExitSecurityFail
	} else {
		res.Decision = GateStatusPassed
		res.ExitCode = clierror.ExitSuccess
	}

	covBasis := CalculateCoverageBasis(sum)
	res.CoverageBasis = &covBasis
	res.StructuredLimitations = DeriveLimitationsFromEvaluation(eval, nil)

	return res
}

func (s *ComplianceGateService) createOperationalFailureResult(assID, catID string, policy *ComplianceGatePolicy, errorMsg string, exitCode int) *ComplianceGateResult {
	polID := ""
	polVer := ""
	polName := ""
	if policy != nil {
		polID = policy.ID
		polVer = policy.Version
		polName = policy.Name
	}

	return &ComplianceGateResult{
		Decision:          GateStatusOperationalFailed,
		ExitCode:          exitCode,
		AssessmentID:      assID,
		CatalogIdentity:   catID,
		PolicyID:          polID,
		PolicyVersion:     polVer,
		PolicyName:        polName,
		EvaluatedAt:       time.Now().UTC(),
		OperationalErrors: []string{errorMsg},
		Conditions: []GateConditionResult{
			{
				Name:     "Operational Execution",
				Category: "operational",
				Status:   "FAILED",
				Message:  errorMsg,
			},
		},
		LimitationsNotice: ComplianceGateLimitationsNotice(),
	}
}
