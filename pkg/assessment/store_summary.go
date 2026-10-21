package assessment

import (
	"fmt"
	"strings"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"
)

// GetAssessmentChangeSummary computes a ChangeSummary between two executions or resolves
// an automatic eligible baseline for an assessment.
func (s *SQLiteStore) GetAssessmentChangeSummary(
	assessmentID string,
	baselineRef string,
	comparisonRef string,
	auth TenantAuthContext,
) (*report.ChangeSummary, error) {
	if assessmentID != "" {
		assessmentID = s.resolveAssessmentID(assessmentID)
	}

	// 1. Resolve Comparison Execution
	comparisonExec, err := s.ResolveExecutionRef(assessmentID, comparisonRef, auth, true)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve comparison execution: %w", err)
	}
	if !auth.Authorizes(comparisonExec.ClientID, comparisonExec.TenantID, comparisonExec.AccountID) {
		return nil, ErrExecutionUnauthorized
	}

	// 2. Resolve Baseline Execution
	var baselineExec *AssessmentExecution
	if baselineRef != "" {
		base, err := s.ResolveExecutionRef(assessmentID, baselineRef, auth, false)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve baseline execution %q: %w", baselineRef, err)
		}
		if !auth.Authorizes(base.ClientID, base.TenantID, base.AccountID) {
			return nil, ErrExecutionUnauthorized
		}

		// Prevent comparing an execution against itself
		if base.ID == comparisonExec.ID {
			return nil, fmt.Errorf("an execution (%s) cannot be compared against itself as a baseline", comparisonExec.ID)
		}

		// Prevent cross-tenant comparisons
		if base.TenantID != "" && comparisonExec.TenantID != "" && base.TenantID != comparisonExec.TenantID {
			return nil, fmt.Errorf("cross-tenant comparison denied (baseline tenant %q != comparison tenant %q): %w",
				base.TenantID, comparisonExec.TenantID, ErrExecutionUnauthorized)
		}
		if base.AccountID != "" && comparisonExec.AccountID != "" && base.AccountID != comparisonExec.AccountID {
			return nil, fmt.Errorf("cross-account comparison denied (baseline account %q != comparison account %q): %w",
				base.AccountID, comparisonExec.AccountID, ErrExecutionUnauthorized)
		}

		// Prevent incompatible assessment scopes
		if base.AssessmentID != comparisonExec.AssessmentID {
			baseTgts, _ := s.GetTargets(base.AssessmentID)
			compTgts, _ := s.GetTargets(comparisonExec.AssessmentID)
			if !areAssessmentTargetsCompatible(baseTgts, compTgts) {
				return nil, fmt.Errorf("incompatible assessment scopes (baseline %s != comparison %s): %w",
					base.AssessmentID, comparisonExec.AssessmentID, ErrIncompatibleAssessmentScope)
			}
		}

		// Prevent comparison between incompatible assessment types
		if base.AssessmentType != "" && comparisonExec.AssessmentType != "" && !AreAssessmentTypesCompatible(base.AssessmentType, comparisonExec.AssessmentType) {
			return nil, fmt.Errorf("incompatible assessment types (baseline %s != comparison %s): %w",
				base.AssessmentType, comparisonExec.AssessmentType, ErrIncompatibleAssessmentScope)
		}

		// An eligible baseline MUST be a completed execution (COMPLETED or COMPLETED_WITH_ERRORS).
		// FAILED, CANCELLED, INTERRUPTED, QUEUED, or RUNNING executions are ineligible as baselines.
		if base.Status != StatusCompleted && base.Status != StatusCompletedWithErrors {
			return nil, fmt.Errorf("ineligible baseline %s (status %s): baseline must be COMPLETED or COMPLETED_WITH_ERRORS: %w",
				base.ID, base.Status, ErrIneligibleBaseline)
		}

		// Inconclusive, corrupt, or compromised baseline snapshot cannot establish a trustworthy baseline
		if base.SnapshotID != "" {
			snap, err := s.GetSnapshot(base.SnapshotID, auth)
			if err != nil {
				return nil, fmt.Errorf("corrupt or missing baseline snapshot %q: %w", base.SnapshotID, err)
			}
			if snap == nil {
				return nil, fmt.Errorf("baseline snapshot %q not found: %w", base.SnapshotID, ErrIneligibleBaseline)
			}
			if snap.IsInconclusive() {
				return nil, fmt.Errorf("ineligible baseline %s: snapshot %s is marked inconclusive: %w",
					base.ID, snap.ID, ErrIneligibleBaseline)
			}
			if base.Status == StatusCompletedWithErrors {
				failedTgts := snap.GetFailedTargets()
				if len(failedTgts) > 0 {
					compTgts, _ := s.GetTargets(comparisonExec.AssessmentID)
					for _, ct := range compTgts {
						if correlation.IsSingleTargetInScope(ct.TargetURL, failedTgts) {
							return nil, fmt.Errorf("ineligible baseline %s: target %q suffered crawl failure in baseline: %w",
								base.ID, ct.TargetURL, ErrIneligibleBaseline)
						}
					}
				}
				if len(snap.GetFailedCategories()) > 0 {
					return nil, fmt.Errorf("ineligible baseline %s: detector category failure compromised baseline coverage: %w",
						base.ID, ErrIneligibleBaseline)
				}
			}
		} else if base.Status == StatusCompletedWithErrors {
			return nil, fmt.Errorf("ineligible baseline %s: status is COMPLETED_WITH_ERRORS without snapshot: %w",
				base.ID, ErrIneligibleBaseline)
		}

		baselineExec = base
	} else {
		// Automatic baseline selection: select most recent prior eligible execution for the same assessment scope
		execs, err := s.ListExecutions(comparisonExec.AssessmentID)
		if err != nil {
			return nil, fmt.Errorf("failed listing executions for baseline selection: %w", err)
		}

		var candidate *AssessmentExecution
		for i := range execs {
			e := &execs[i]
			if e.ID == comparisonExec.ID {
				continue
			}
			// Tenant and account authorization check
			if !auth.Authorizes(e.ClientID, e.TenantID, e.AccountID) {
				continue
			}
			if e.TenantID != "" && comparisonExec.TenantID != "" && e.TenantID != comparisonExec.TenantID {
				continue
			}
			if e.AccountID != "" && comparisonExec.AccountID != "" && e.AccountID != comparisonExec.AccountID {
				continue
			}

			// Incompatible assessment types are ineligible as baselines
			if e.AssessmentType != "" && comparisonExec.AssessmentType != "" && !AreAssessmentTypesCompatible(e.AssessmentType, comparisonExec.AssessmentType) {
				continue
			}

			// Must have started before or at same time as comparison
			if e.StartedAt.After(comparisonExec.StartedAt) {
				continue
			}
			if e.StartedAt.Equal(comparisonExec.StartedAt) && !e.CreatedAt.Before(comparisonExec.CreatedAt) {
				continue
			}

			// An eligible baseline MUST be a completed execution (COMPLETED or COMPLETED_WITH_ERRORS).
			// FAILED, CANCELLED, INTERRUPTED, QUEUED, or RUNNING executions are ineligible as baselines.
			if e.Status != StatusCompleted && e.Status != StatusCompletedWithErrors {
				continue
			}

			// If candidate has snapshot, ensure it is conclusive and coverage is not compromised
			if e.SnapshotID != "" {
				snap, err := s.GetSnapshot(e.SnapshotID, auth)
				if err != nil || snap == nil || snap.IsInconclusive() {
					continue
				}
				if e.Status == StatusCompletedWithErrors {
					failedTgts := snap.GetFailedTargets()
					if len(failedTgts) > 0 {
						compTgts, _ := s.GetTargets(comparisonExec.AssessmentID)
						compromised := false
						for _, ct := range compTgts {
							if correlation.IsSingleTargetInScope(ct.TargetURL, failedTgts) {
								compromised = true
								break
							}
						}
						if compromised {
							continue
						}
					}
					if len(snap.GetFailedCategories()) > 0 {
						continue
					}
				}
			} else if e.Status == StatusCompletedWithErrors {
				continue
			}

			candidate = e
			break
		}

		if candidate == nil {
			// No prior baseline execution exists -> return initial execution summary
			return s.buildInitialExecutionSummary(comparisonExec, auth)
		}
		baselineExec = candidate
	}

	// 3. Execute delta comparison via store's existing engine
	cmp, err := s.CompareExecutionHistory(baselineExec.ID, comparisonExec.ID, auth)
	if err != nil {
		return nil, fmt.Errorf("comparison failed between %s and %s: %w", baselineExec.ID, comparisonExec.ID, err)
	}

	// 4. Determine completeness & uncertainty
	isReliable := true
	reliabilityReason := ""

	if comparisonExec.Status != StatusCompleted && comparisonExec.Status != StatusCompletedWithErrors {
		isReliable = false
		reliabilityReason = fmt.Sprintf("comparison execution status is %s", comparisonExec.Status)
	} else if baselineExec.Status != StatusCompleted && baselineExec.Status != StatusCompletedWithErrors {
		isReliable = false
		reliabilityReason = fmt.Sprintf("baseline execution status is %s", baselineExec.Status)
	} else if cmp.ComparisonStatus == "PARTIAL" {
		isReliable = false
		reliabilityReason = cmp.ComparisonReason
		if reliabilityReason == "" {
			reliabilityReason = "target or category coverage in comparison run was partial"
		}
	}

	var baseTime *time.Time
	if !baselineExec.StartedAt.IsZero() {
		t := baselineExec.StartedAt
		baseTime = &t
	}

	opts := correlation.ChangeSummaryOptions{
		AssessmentID:          comparisonExec.AssessmentID,
		BaselineExecutionID:   baselineExec.ID,
		ComparisonExecutionID: comparisonExec.ID,
		BaselineSnapshotID:    baselineExec.SnapshotID,
		ComparisonSnapshotID:  comparisonExec.SnapshotID,
		BaselineTimestamp:     baseTime,
		ComparisonTimestamp:   comparisonExec.StartedAt,
		BaselineStatus:        string(baselineExec.Status),
		ComparisonStatus:      string(comparisonExec.Status),
		IsReliable:            isReliable,
		ReliabilityReason:     reliabilityReason,
	}

	return correlation.BuildChangeSummary(cmp, opts), nil
}

func (s *SQLiteStore) ResolveExecutionRef(
	assessmentID string,
	ref string,
	auth TenantAuthContext,
	isComparison bool,
) (*AssessmentExecution, error) {
	if ref != "" {
		// 1. Try execution ID or history
		if exec, err := s.GetExecutionHistory(ref, auth); err == nil && exec != nil {
			return exec, nil
		}
		// 2. Try snapshot ID
		if snap, err := s.GetSnapshot(ref, auth); err == nil && snap != nil && snap.ExecutionID != "" {
			if exec, err := s.GetExecutionHistory(snap.ExecutionID, auth); err == nil && exec != nil {
				return exec, nil
			}
		}
		// 3. Try direct GetExecution
		if exec, err := s.GetExecution(ref); err == nil && exec != nil {
			return exec, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrExecutionNotFound, ref)
	}

	// ref is empty: if isComparison and assessmentID is given, pick latest execution
	if isComparison && assessmentID != "" {
		execs, err := s.ListExecutions(assessmentID)
		if err != nil {
			return nil, err
		}
		if len(execs) == 0 {
			return nil, fmt.Errorf("%w: no executions for assessment %s", ErrExecutionNotFound, assessmentID)
		}
		return &execs[0], nil
	}

	return nil, fmt.Errorf("%w: reference cannot be empty", ErrExecutionNotFound)
}

func (s *SQLiteStore) buildInitialExecutionSummary(
	exec *AssessmentExecution,
	auth TenantAuthContext,
) (*report.ChangeSummary, error) {
	// Retrieve findings for this initial execution
	var afs []AssessmentFinding
	if exec.SnapshotID != "" {
		if findings, err := s.GetSnapshotFindings(exec.SnapshotID, auth); err == nil && len(findings) > 0 {
			afs = findings
		}
	}
	if len(afs) == 0 {
		if findings, err := s.GetFindings(exec.AssessmentID, exec.ID); err == nil {
			afs = findings
		}
	}

	reportFindings := make([]report.Finding, len(afs))
	for i, af := range afs {
		reportFindings[i] = ToReportFinding(af)
	}

	// Compare against empty baseline
	cmp := correlation.CompareFindingsWithOptions(nil, reportFindings, correlation.ComparisonOptions{
		CurrentCompleted: exec.Status == StatusCompleted || exec.Status == StatusCompletedWithErrors,
	})

	isReliable := exec.Status == StatusCompleted || exec.Status == StatusCompletedWithErrors
	relReason := ""
	if !isReliable {
		relReason = fmt.Sprintf("execution status is %s", exec.Status)
	}

	opts := correlation.ChangeSummaryOptions{
		AssessmentID:          exec.AssessmentID,
		BaselineExecutionID:   "",
		ComparisonExecutionID: exec.ID,
		BaselineSnapshotID:    "",
		ComparisonSnapshotID:  exec.SnapshotID,
		BaselineTimestamp:     nil,
		ComparisonTimestamp:   exec.StartedAt,
		BaselineStatus:        "",
		ComparisonStatus:      string(exec.Status),
		IsReliable:            isReliable,
		ReliabilityReason:     relReason,
	}

	return correlation.BuildChangeSummary(&cmp, opts), nil
}

func areAssessmentTargetsCompatible(base, comp []AssessmentTarget) bool {
	if len(base) == 0 || len(comp) == 0 {
		return true
	}
	baseMap := make(map[string]bool)
	for _, t := range base {
		baseMap[strings.ToLower(strings.TrimRight(t.TargetURL, "/"))] = true
	}
	for _, t := range comp {
		if baseMap[strings.ToLower(strings.TrimRight(t.TargetURL, "/"))] {
			return true
		}
	}
	return false
}
