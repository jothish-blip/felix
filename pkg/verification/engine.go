package verification

import (
	"context"
	"math"
	"strings"

	"felix/pkg/report"
)

// Engine orchestrates finding verification across all registered policies and safety controls.
type Engine struct {
	registry *PolicyRegistry
	safety   *SafetyChecker
	version  string
}

// NewEngine constructs a new Verification Engine 2.0.
func NewEngine(safety *SafetyChecker) *Engine {
	return &Engine{
		registry: NewDefaultRegistry(),
		safety:   safety,
		version:  "2.0.0",
	}
}

// Version returns the engine version.
func (e *Engine) Version() string {
	return e.version
}

// VerifyFinding executes policy-based verification on a single finding.
func (e *Engine) VerifyFinding(ctx context.Context, f report.Finding) VerificationResult {
	policy := e.registry.Resolve(f)
	res, err := policy.Verify(ctx, f, e.safety)
	if err != nil {
		// Error fail-safe: verification failure never defaults to VERIFIED
		synthetic := f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]")
		return VerificationResult{
			FindingID:              f.ID,
			TargetURL:              f.Target,
			Endpoint:               f.Endpoint,
			Category:               f.Category,
			Status:                 StatusNotVerified,
			FindingStatus:          report.FindingStatusError,
			VerificationMethod:     "error_fail_safe",
			PolicyID:               policy.ID(),
			PolicyVersion:          policy.Version(),
			Attempted:              true,
			DetectionConfidence:    f.Confidence,
			VerificationConfidence: ConfidenceNone,
			OverallConfidence:      ConfidenceLow,
			ConfidenceScore:        20,
			ConfidenceRationale:    "Verification execution failed: " + err.Error(),
			FailureReason:          err.Error(),
			InconclusiveReason:     "Internal evaluation error",
			SafetyDecision:         DecisionAllowed,
			SyntheticFixture:       synthetic,
			VerifierVersion:        e.version,
		}
	}
	return res
}

// VerifyFindings processes a slice of findings and returns structured results and a statistical summary.
func (e *Engine) VerifyFindings(ctx context.Context, findings []report.Finding) ([]VerificationResult, VerificationSummary) {
	var results []VerificationResult
	catStats := make(map[string]CategoryVerificationStat)

	summary := VerificationSummary{
		TotalFindings: len(findings),
		CategoryStats: catStats,
	}

	for _, f := range findings {
		if ctx.Err() != nil {
			break
		}
		res := e.VerifyFinding(ctx, f)
		results = append(results, res)

		cat := strings.ToUpper(f.Category)
		if cat == "" {
			cat = "UNCATEGORIZED"
		}
		stat := catStats[cat]
		stat.Category = cat
		stat.Total++

		if res.Attempted {
			summary.AttemptedCount++
		}
		if res.SyntheticFixture {
			summary.SyntheticCount++
		}
		if res.SafetyDecision == DecisionBlocked {
			summary.BlockedCount++
			stat.Blocked++
		}
		if res.InconclusiveReason != "" {
			summary.InconclusiveCount++
		}
		if res.PolicyID == "POL-GENERIC-01" {
			summary.UnsupportedCount++
		}

		switch res.Status {
		case StatusVerified:
			summary.VerifiedCount++
			stat.Verified++
		case StatusDetected:
			summary.DetectedCount++
			stat.Detected++
		case StatusObserved:
			summary.ObservedCount++
			stat.Observed++
		case StatusNotVerified:
			summary.NotVerifiedCount++
			stat.NotVerified++
		case StatusNotExposed:
			summary.NotExposedCount++
			stat.NotExposed++
		}

		catStats[cat] = stat
	}

	if summary.TotalFindings > 0 {
		summary.AttemptRate = math.Round(float64(summary.AttemptedCount)/float64(summary.TotalFindings)*1000) / 10
		rateTotal := float64(summary.VerifiedCount) / float64(summary.TotalFindings) * 100.0
		summary.VerificationRateTotal = math.Round(rateTotal*10) / 10
	} else {
		summary.AttemptRate = 0.0
		summary.VerificationRateTotal = 0.0
	}

	summary.ConclusiveCount = summary.VerifiedCount + summary.NotExposedCount
	if summary.AttemptedCount > 0 {
		rate := float64(summary.VerifiedCount) / float64(summary.AttemptedCount) * 100.0
		summary.ConfirmationRate = math.Round(rate*10) / 10
		summary.VerificationRateAttempted = summary.ConfirmationRate
		conclusiveRate := float64(summary.ConclusiveCount) / float64(summary.AttemptedCount) * 100.0
		summary.ConclusiveRate = math.Round(conclusiveRate*10) / 10
	} else {
		summary.ConfirmationRate = 0.0
		summary.VerificationRateAttempted = 0.0
		summary.ConclusiveRate = 0.0
	}

	return results, summary
}

// ApplyVerificationToFindings updates the input findings with their verified status, confidence, and verification records.
func ApplyVerificationToFindings(findings []report.Finding, results []VerificationResult) []report.Finding {
	resMap := make(map[string]VerificationResult)
	for _, r := range results {
		resMap[r.FindingID] = r
	}

	updated := make([]report.Finding, len(findings))
	for i, f := range findings {
		res, exists := resMap[f.ID]
		if !exists {
			updated[i] = f
			continue
		}

		fCopy := f
		fCopy.Verification.Status = res.Status
		fCopy.Verification.DetectionStatus = res.DetectionConfidence
		fCopy.Verification.PolicyID = res.PolicyID
		fCopy.Verification.VerificationMethod = res.VerificationMethod
		fCopy.Verification.ConfidenceScore = res.ConfidenceScore
		fCopy.Verification.ReproductionSteps = res.Reproduction.ReproductionSteps
		fCopy.Verification.SafeCurlCommand = res.Reproduction.SafeCurlCommand
		fCopy.Verification.Limitations = res.Limitations
		fCopy.Verification.SyntheticFixture = res.SyntheticFixture
		fCopy.Verification.Attempted = res.Attempted
		fCopy.Verification.Rationale = res.ConfidenceRationale
		if res.FailureReason != "" {
			fCopy.Verification.Result = res.FailureReason
		} else if res.ObservedBehavior != "" {
			fCopy.Verification.Result = res.ObservedBehavior
		}
		if res.ExpectedBehavior != "" {
			fCopy.EvidenceDetails.ExpectedBehavior = res.ExpectedBehavior
		}
		if res.ObservedBehavior != "" {
			fCopy.EvidenceDetails.ObservedBehavior = res.ObservedBehavior
		}

		// Honest Status and AnalysisMethod assignment
		if res.SafetyDecision == DecisionBlocked || (!res.Attempted && res.Status == StatusNotVerified) {
			fCopy.Status = report.FindingStatusNotTested
			// Detection confidence preserved; do not downgrade upon block/skip
			fCopy.Confidence = f.Confidence
			if res.AnalysisMethod != "" {
				fCopy.AnalysisMethod = res.AnalysisMethod
				fCopy.Verification.AnalysisMethod = res.AnalysisMethod
			}
		} else if res.FailureReason != "" && res.Attempted {
			fCopy.Status = report.FindingStatusError
			fCopy.AnalysisMethod = report.AnalysisMethodActive
			fCopy.Verification.AnalysisMethod = report.AnalysisMethodActive
			fCopy.Confidence = res.OverallConfidence
		} else if res.Attempted && (res.InconclusiveReason != "" || res.Status == StatusNotExposed) {
			fCopy.Status = report.FindingStatusInconclusive
			if res.Attempted {
				fCopy.AnalysisMethod = report.AnalysisMethodActive
				fCopy.Verification.AnalysisMethod = report.AnalysisMethodActive
			}
			fCopy.Confidence = res.OverallConfidence
		} else if res.Status == StatusVerified {
			fCopy.Status = report.FindingStatusConfirmed
			fCopy.AnalysisMethod = report.AnalysisMethodActive
			fCopy.Verification.AnalysisMethod = report.AnalysisMethodActive
			fCopy.Confidence = res.OverallConfidence
		} else if res.Status == StatusDetected {
			fCopy.Status = report.FindingStatusSuspected
			if res.Attempted {
				fCopy.AnalysisMethod = report.AnalysisMethodActive
				fCopy.Verification.AnalysisMethod = report.AnalysisMethodActive
			}
			fCopy.Confidence = res.OverallConfidence
		} else {
			fCopy.Status = report.FindingStatusFromVerification(res.Status)
			if res.AnalysisMethod != "" {
				fCopy.AnalysisMethod = res.AnalysisMethod
				fCopy.Verification.AnalysisMethod = res.AnalysisMethod
			}
			fCopy.Confidence = res.OverallConfidence
		}

		fCopy.Score = report.CalculateFindingScore(fCopy)
		updated[i] = fCopy
	}

	return updated
}
