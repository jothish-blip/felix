package compliance

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
)

// EvaluationEngine coordinates the evidence-driven evaluation of compliance controls.
type EvaluationEngine struct {
	policy EvaluationPolicy
	clock  func() time.Time
}

// NewEvaluationEngine creates a new EvaluationEngine with the specified policy (or DefaultEvaluationPolicy).
func NewEvaluationEngine(policies ...EvaluationPolicy) *EvaluationEngine {
	p := DefaultEvaluationPolicy()
	if len(policies) > 0 {
		p = policies[0]
	}
	return &EvaluationEngine{
		policy: p,
	}
}

// WithClock sets a custom timestamp generator for deterministic reproducibility.
func (e *EvaluationEngine) WithClock(fn func() time.Time) *EvaluationEngine {
	e.clock = fn
	return e
}

func (e *EvaluationEngine) now() time.Time {
	if e.clock != nil {
		return e.clock()
	}
	return time.Now().UTC().Truncate(time.Second)
}

// Evaluate evaluates a control catalog against assessment findings, mapping results, and assessment context.
func (e *EvaluationEngine) Evaluate(
	catalog *ControlCatalog,
	mappingResult *MappingResult,
	findings []report.Finding,
	context *EvaluationContext,
) (*EvaluationResult, error) {
	if catalog == nil {
		return nil, errors.New("control catalog cannot be nil")
	}
	if err := ValidateCatalog(catalog); err != nil {
		return nil, fmt.Errorf("invalid control catalog: %w", err)
	}
	if context == nil {
		return nil, errors.New("evaluation context cannot be nil")
	}
	if strings.TrimSpace(context.AssessmentID) == "" {
		return nil, errors.New("evaluation context assessment_id is required")
	}

	// Reject catalog version mismatch between mapping result and evaluated catalog
	if mappingResult != nil {
		if mappingResult.CatalogIdentity != "" && catalog.Identity() != "" &&
			!strings.EqualFold(mappingResult.CatalogIdentity, catalog.Identity()) {
			return nil, fmt.Errorf("catalog version mismatch: mapping result targets %q but evaluating %q",
				mappingResult.CatalogIdentity, catalog.Identity())
		}
	}

	// Build catalog control lookup
	knownControls := make(map[string]Control, len(catalog.Controls))
	for _, ctrl := range catalog.Controls {
		knownControls[ctrl.ID] = ctrl
	}

	// Validate applicability control references against catalog
	if context.Applicability != nil {
		for cID := range context.Applicability {
			if _, exists := knownControls[cID]; !exists {
				return nil, fmt.Errorf("applicability determination references unknown control ID %q in catalog %q", cID, catalog.ID)
			}
		}
	}

	// Build index of findings by FindingID
	findingsByID := make(map[string]report.Finding, len(findings))
	for _, f := range findings {
		fID := strings.TrimSpace(f.ID)
		if fID != "" {
			findingsByID[fID] = f
		}
	}

	// Build index of mappings by ControlID
	mappingsByControl := make(map[string][]FindingControlMapping)
	if mappingResult != nil {
		for _, m := range mappingResult.Mappings {
			cID := strings.TrimSpace(m.ControlID)
			mappingsByControl[cID] = append(mappingsByControl[cID], m)
		}
	}

	// Build index of positive evidence by ControlID
	posEvByControl := make(map[string][]PositiveEvidence)
	for _, pe := range context.PositiveEvidence {
		cID := strings.TrimSpace(pe.ControlID)
		posEvByControl[cID] = append(posEvByControl[cID], pe)
	}

	currentTime := e.now()
	ruleSetVersion := ""
	ruleSetDigest := ""
	if mappingResult != nil {
		ruleSetVersion = mappingResult.MappingRuleSetIdentity
		ruleSetDigest = mappingResult.MappingRuleSetDigest
	}

	assessmentStatus := strings.ToUpper(strings.TrimSpace(context.AssessmentStatus))
	isAssessmentIncomplete := assessmentStatus == "CANCELLED" ||
		assessmentStatus == "FAILED" ||
		assessmentStatus == "INTERRUPTED" ||
		assessmentStatus == "SKIPPED" ||
		assessmentStatus == "DRAFT" ||
		assessmentStatus == "READY"

	evaluations := make([]ControlEvaluationRecord, 0, len(catalog.Controls))

	// Evaluate every control defined in the catalog
	for _, ctrl := range catalog.Controls {
		cID := ctrl.ID
		evalID := fmt.Sprintf("eval:%s:%s:%s", context.AssessmentID, catalog.ID, cID)

		rec := ControlEvaluationRecord{
			EvaluationID:          evalID,
			CatalogID:             catalog.ID,
			CatalogVersion:        catalog.Version,
			ControlID:             cID,
			ControlTitle:          ctrl.Title,
			AssessmentID:          context.AssessmentID,
			ExecutionID:           context.ExecutionID,
			EvaluatedAt:           currentTime,
			EngineVersion:         CurrentEvaluationEngineVersion,
			MappingRuleSetVersion: ruleSetVersion,
			MappingRuleSetDigest:  ruleSetDigest,
			Limitations:           ctrl.Description,
		}

		// Execution error tracking for this control
		hasExecutionError := context.ExecutionErrors != nil && context.ExecutionErrors[cID] != ""
		executionErrorMsg := ""
		if hasExecutionError {
			executionErrorMsg = context.ExecutionErrors[cID]
		}

		// 2. Applicability determination check
		if context.Applicability != nil {
			if det, exists := context.Applicability[cID]; exists {
				if !det.Applicable {
					if strings.TrimSpace(det.Rationale) == "" || strings.TrimSpace(det.Basis) == "" {
						rec.State = StateInsufficientEvidence
						rec.Rationale = fmt.Sprintf("Inapplicability claim for control %s is unsupported: missing required rationale or basis", cID)
					} else {
						rec.State = StateNotApplicable
						rec.Rationale = fmt.Sprintf("Control explicitly determined not applicable: %s (basis: %s)", det.Rationale, det.Basis)
						rec.EvidenceReferences = []string{det.Basis}
					}
					evaluations = append(evaluations, rec)
					continue
				}
			}
		}

		// 3. Evidence collection and classification for control
		ctrlMappings := mappingsByControl[cID]
		ctrlPosEv := posEvByControl[cID]

		var (
			violatingFindingIDs    []string
			violatingEvidence      []string
			inconclusiveFindingIDs []string
			satisfyingEvidence     []string
			subReqSatisfied        = make(map[string]bool)
			subReqViolated         = make(map[string]bool)
			reqLocDefended         = make(map[string]bool)
			reqLocVulnerable       = make(map[string]bool)
		)

		for _, m := range ctrlMappings {
			f, exists := findingsByID[m.FindingID]

			// A mapping without concrete evidence cannot prove a violation
			if !m.HasEvidence {
				inconclusiveFindingIDs = append(inconclusiveFindingIDs, m.FindingID)
				continue
			}

			fStatus := ""
			vStatus := ""
			if exists {
				fStatus = strings.ToUpper(strings.TrimSpace(string(f.Status)))
				vStatus = strings.ToUpper(strings.TrimSpace(string(f.Verification.Status)))
			}

			loc := m.EvidenceLocation
			if loc == "" && exists {
				loc = f.Endpoint
			}

			ruleKey := strings.ToLower(strings.TrimSpace(m.FindingRuleID))
			locKey := strings.ToLower(strings.TrimSpace(loc))

			// Confirmed violation vs verified negative defense vs inconclusive
			if fStatus == "CONFIRMED" || vStatus == "VERIFIED" {
				violatingFindingIDs = append(violatingFindingIDs, m.FindingID)
				evDetail := fmt.Sprintf("Finding %s: %s (severity: %s, rule: %s)", m.FindingID, m.FindingSeverity, m.FindingRuleID, m.Relationship)
				if exists && strings.TrimSpace(f.Evidence) != "" {
					evDetail += fmt.Sprintf(" - %s", f.Evidence)
				}
				violatingEvidence = append(violatingEvidence, evDetail)
				if locKey != "" {
					reqLocVulnerable[ruleKey+"@"+locKey] = true
					if ruleKey == "" {
						reqLocVulnerable["*@"+locKey] = true
					}
				}
				if m.FindingRuleID != "" {
					subReqViolated[m.FindingRuleID] = true
				}
			} else if vStatus == "NOT_EXPOSED" {
				// Verified negative evidence (defended)
				evDetail := fmt.Sprintf("Finding %s verified not exposed (defended)", m.FindingID)
				if exists && strings.TrimSpace(f.EvidenceDetails.NegativeEvidence) != "" {
					evDetail += fmt.Sprintf(": %s", f.EvidenceDetails.NegativeEvidence)
				}
				satisfyingEvidence = append(satisfyingEvidence, evDetail)
				if locKey != "" {
					reqLocDefended[ruleKey+"@"+locKey] = true
					if ruleKey == "" {
						reqLocDefended["*@"+locKey] = true
					}
				}
				if m.FindingRuleID != "" {
					subReqSatisfied[m.FindingRuleID] = true
				}
			} else {
				// Suspected, unverified, or inconclusive
				inconclusiveFindingIDs = append(inconclusiveFindingIDs, m.FindingID)
			}
		}

		// Positive evidence records
		for _, pe := range ctrlPosEv {
			if strings.TrimSpace(pe.Observation) == "" || strings.TrimSpace(pe.Method) == "" {
				// Invalid or unverifiable positive evidence cannot establish compliance
				continue
			}
			evDetail := fmt.Sprintf("Positive verification [%s]: %s (method: %s)", pe.ID, pe.Observation, pe.Method)
			satisfyingEvidence = append(satisfyingEvidence, evDetail)

			peReqKey := strings.ToLower(strings.TrimSpace(pe.Requirement))
			peLocKey := strings.ToLower(strings.TrimSpace(pe.Location))
			if peLocKey != "" {
				reqLocDefended[peReqKey+"@"+peLocKey] = true
				if peReqKey == "" {
					reqLocDefended["*@"+peLocKey] = true
				}
			}
			if pe.Requirement != "" {
				subReqSatisfied[pe.Requirement] = true
			}
		}

		// 4. Incomplete or cancelled assessment handling
		if isAssessmentIncomplete {
			// Incomplete assessments can record confirmed violations if verified evidence exists
			if len(violatingFindingIDs) > 0 {
				rec.State = StateNonCompliant
				rec.Rationale = fmt.Sprintf("Verified non-compliance observed prior to assessment %s: %d confirmed finding(s)",
					assessmentStatus, len(violatingFindingIDs))
				rec.FindingIDs = violatingFindingIDs
				rec.ContradictingEvidence = violatingEvidence
			} else if len(inconclusiveFindingIDs) > 0 {
				rec.State = StateInsufficientEvidence
				rec.Rationale = fmt.Sprintf("Assessment status was %s: evaluation incomplete", assessmentStatus)
				rec.FindingIDs = inconclusiveFindingIDs
			} else {
				rec.State = StateNotAssessed
				rec.Rationale = fmt.Sprintf("Assessment status was %s: control was not assessed", assessmentStatus)
			}
			evaluations = append(evaluations, rec)
			continue
		}

		// 5. Synthesis & Conflict Resolution
		// Case A: Contradictory evidence on identical target requirement and location
		hasDirectContradiction := false
		if len(violatingFindingIDs) > 0 && len(satisfyingEvidence) > 0 {
			for key := range reqLocVulnerable {
				if reqLocDefended[key] {
					hasDirectContradiction = true
					break
				}
				parts := strings.SplitN(key, "@", 2)
				if len(parts) == 2 {
					if reqLocDefended["*@"+parts[1]] || (parts[0] == "*" && reqLocDefended[key]) {
						hasDirectContradiction = true
						break
					}
				}
			}
		}

		if hasDirectContradiction {
			rec.State = StateInsufficientEvidence
			rec.Rationale = "Conflicting positive and negative evidence on identical target scope cannot be conclusively reconciled"
			rec.FindingIDs = violatingFindingIDs
			rec.SupportingEvidence = satisfyingEvidence
			rec.ContradictingEvidence = violatingEvidence
			evaluations = append(evaluations, rec)
			continue
		}

		// Case B: Verified violations present
		if len(violatingFindingIDs) > 0 {
			if e.policy.AllowPartialCompliance && len(subReqSatisfied) > 0 && len(subReqViolated) > 0 {
				rec.State = StatePartiallyCompliant
				rec.Rationale = fmt.Sprintf("Partial compliance: %d requirement(s) verified satisfied, %d requirement(s) violated",
					len(subReqSatisfied), len(subReqViolated))
			} else {
				rec.State = StateNonCompliant
				rec.Rationale = fmt.Sprintf("Control requirement violated: %d confirmed finding(s) observed with empirical evidence",
					len(violatingFindingIDs))
			}
			if hasExecutionError {
				rec.Rationale += fmt.Sprintf(" (note: partial execution error also occurred: %s)", executionErrorMsg)
				rec.Limitations = fmt.Sprintf("Partial evaluation error on control: %s", executionErrorMsg)
			}
			rec.FindingIDs = violatingFindingIDs
			rec.SupportingEvidence = satisfyingEvidence
			rec.ContradictingEvidence = violatingEvidence
			evaluations = append(evaluations, rec)
			continue
		}

		// Case C: Execution error on this control without confirmed violation
		if hasExecutionError {
			rec.State = StateError
			rec.Rationale = fmt.Sprintf("Evaluation error encountered during assessment of control %s: %s", cID, executionErrorMsg)
			evaluations = append(evaluations, rec)
			continue
		}

		// Case D: Inconclusive findings present
		if len(inconclusiveFindingIDs) > 0 {
			rec.State = StateInsufficientEvidence
			rec.Rationale = fmt.Sprintf("Evaluation attempted but evidence is insufficient: %d finding(s) inconclusive or unverified without confirmed violation proof",
				len(inconclusiveFindingIDs))
			rec.FindingIDs = inconclusiveFindingIDs
			rec.SupportingEvidence = satisfyingEvidence
			evaluations = append(evaluations, rec)
			continue
		}

		// Case E: Verified positive evidence exists
		if len(satisfyingEvidence) > 0 {
			definedReqs := getDefinedRequirementsForControl(&ctrl, ctrlMappings, ctrlPosEv, context)

			// 1. Verify all defined control requirements have positive satisfaction
			if len(definedReqs) > 1 {
				var missingReqs []string
				var satisfiedReqs []string
				for _, req := range definedReqs {
					if subReqSatisfied[req] {
						satisfiedReqs = append(satisfiedReqs, req)
					} else {
						missingReqs = append(missingReqs, req)
					}
				}
				if len(missingReqs) > 0 {
					rec.State = StateInsufficientEvidence
					rec.Rationale = fmt.Sprintf("Insufficient evidence for full compliance: verified %d of %d defined control requirements (%s satisfied; %s unverified)",
						len(satisfiedReqs), len(definedReqs), strings.Join(satisfiedReqs, ", "), strings.Join(missingReqs, ", "))
					rec.SupportingEvidence = satisfyingEvidence
					evaluations = append(evaluations, rec)
					continue
				}
			}

			// 2. Verify target scope coverage
			if len(context.TargetScope) > 1 {
				coveredTargets := make(map[string]bool)
				hasLocationEvidence := false
				for _, pe := range ctrlPosEv {
					peLoc := strings.ToLower(strings.TrimSpace(pe.Location))
					if peLoc == "" {
						continue
					}
					hasLocationEvidence = true
					for _, target := range context.TargetScope {
						tClean := strings.ToLower(strings.TrimSpace(target))
						if strings.Contains(peLoc, tClean) || strings.Contains(tClean, peLoc) {
							coveredTargets[target] = true
						}
					}
				}
				if hasLocationEvidence && len(coveredTargets) < len(context.TargetScope) {
					var uncovered []string
					for _, target := range context.TargetScope {
						if !coveredTargets[target] {
							uncovered = append(uncovered, target)
						}
					}
					rec.State = StateInsufficientEvidence
					rec.Rationale = fmt.Sprintf("Insufficient evidence for full compliance: positive verification only covers %d of %d targets in scope (uncovered: %s)",
						len(coveredTargets), len(context.TargetScope), strings.Join(uncovered, ", "))
					rec.SupportingEvidence = satisfyingEvidence
					evaluations = append(evaluations, rec)
					continue
				}
			}

			rec.State = StateCompliant
			rec.Rationale = fmt.Sprintf("Control requirement satisfied: verified positive evidence establishes implementation within assessed scope (%d evidence record(s))",
				len(satisfyingEvidence))
			rec.SupportingEvidence = satisfyingEvidence
			evaluations = append(evaluations, rec)
			continue
		}

		// Case F: No findings and no positive evidence
		rec.State = StateNotAssessed
		rec.Rationale = "Control was not assessed: no assessment findings or positive verification evidence recorded; absence of findings does not establish compliance"
		evaluations = append(evaluations, rec)
	}

	// Deterministic sorting of evaluation records by ControlID
	sort.SliceStable(evaluations, func(i, j int) bool {
		return evaluations[i].ControlID < evaluations[j].ControlID
	})

	// Deterministic sorting of inner slices for each evaluation record
	for i := range evaluations {
		sort.Strings(evaluations[i].FindingIDs)
		sort.Strings(evaluations[i].EvidenceReferences)
		sort.Strings(evaluations[i].SupportingEvidence)
		sort.Strings(evaluations[i].ContradictingEvidence)
	}

	// Compute quantitative evaluation summary
	summary := EvaluationSummary{
		TotalControls: len(evaluations),
	}

	for _, ev := range evaluations {
		switch ev.State {
		case StateCompliant:
			summary.CompliantCount++
			summary.ApplicableControls++
			summary.AssessedControls++
		case StateNonCompliant:
			summary.NonCompliantCount++
			summary.ApplicableControls++
			summary.AssessedControls++
		case StatePartiallyCompliant:
			summary.PartiallyCompliantCount++
			summary.ApplicableControls++
			summary.AssessedControls++
		case StateInsufficientEvidence:
			summary.InsufficientEvidenceCount++
			summary.ApplicableControls++
			summary.AssessedControls++
		case StateNotAssessed:
			summary.NotAssessedCount++
			summary.ApplicableControls++
		case StateNotApplicable:
			summary.NotApplicableCount++
		case StateError:
			summary.ErrorCount++
			summary.ApplicableControls++
		}
	}

	res := &EvaluationResult{
		CatalogIdentity:        catalog.Identity(),
		CatalogDigest:          catalog.Digest(),
		MappingRuleSetIdentity: ruleSetVersion,
		MappingRuleSetDigest:   ruleSetDigest,
		AssessmentID:           context.AssessmentID,
		ExecutionID:            context.ExecutionID,
		EvaluatedAt:            currentTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		Evaluations:            evaluations,
		Summary:                summary,
		LimitationsNotice:      EvaluationLimitationsNotice(),
	}

	covBasis := CalculateCoverageBasis(res.Summary)
	res.CoverageBasis = &covBasis
	res.StructuredLimitations = DeriveLimitationsFromEvaluation(res, catalog)

	return res, nil
}

func getDefinedRequirementsForControl(
	ctrl *Control,
	ctrlMappings []FindingControlMapping,
	ctrlPosEv []PositiveEvidence,
	context *EvaluationContext,
) []string {
	reqMap := make(map[string]bool)

	// 1. Explicitly configured requirements in evaluation context
	if context != nil && context.ControlRequirements != nil {
		if reqs, ok := context.ControlRequirements[ctrl.ID]; ok {
			for _, r := range reqs {
				trimmed := strings.TrimSpace(r)
				if trimmed != "" {
					reqMap[trimmed] = true
				}
			}
		}
	}

	// 2. Control metadata sub-requirements
	if ctrl != nil && ctrl.Metadata != nil {
		if reqs, ok := ctrl.Metadata["required_requirements"].([]string); ok {
			for _, r := range reqs {
				trimmed := strings.TrimSpace(r)
				if trimmed != "" {
					reqMap[trimmed] = true
				}
			}
		} else if reqsAny, ok := ctrl.Metadata["required_requirements"].([]any); ok {
			for _, r := range reqsAny {
				if s, ok := r.(string); ok && strings.TrimSpace(s) != "" {
					reqMap[strings.TrimSpace(s)] = true
				}
			}
		}
		if reqs, ok := ctrl.Metadata["sub_requirements"].([]string); ok {
			for _, r := range reqs {
				trimmed := strings.TrimSpace(r)
				if trimmed != "" {
					reqMap[trimmed] = true
				}
			}
		} else if reqsAny, ok := ctrl.Metadata["sub_requirements"].([]any); ok {
			for _, r := range reqsAny {
				if s, ok := r.(string); ok && strings.TrimSpace(s) != "" {
					reqMap[strings.TrimSpace(s)] = true
				}
			}
		}
	}

	// 3. Requirements defined via mapping rules
	for _, m := range ctrlMappings {
		ruleID := strings.TrimSpace(m.FindingRuleID)
		if ruleID != "" {
			reqMap[ruleID] = true
		}
	}

	// 4. Requirements defined in positive evidence
	for _, pe := range ctrlPosEv {
		reqID := strings.TrimSpace(pe.Requirement)
		if reqID != "" {
			reqMap[reqID] = true
		}
	}

	reqs := make([]string, 0, len(reqMap))
	for r := range reqMap {
		reqs = append(reqs, r)
	}
	sort.Strings(reqs)
	return reqs
}
