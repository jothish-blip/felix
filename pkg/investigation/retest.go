package investigation

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// RetestEngine orchestrates empirical remediation retesting against previously investigated findings.
type RetestEngine struct {
	Prover *SafeProver
}

// NewRetestEngine creates a RetestEngine.
func NewRetestEngine(prover *SafeProver) *RetestEngine {
	if prover == nil {
		prover = NewSafeProver("retest_session", false)
	}
	return &RetestEngine{Prover: prover}
}

// RerunFinding re-evaluates a previously investigated finding against the live target.
func (e *RetestEngine) RerunFinding(ctx context.Context, orig *InvestigatedFinding, client *http.Client) (*RetestVerdict, error) {
	if orig == nil {
		return nil, fmt.Errorf("cannot retest nil finding")
	}

	origStatus := orig.ValidationStatus
	origHash := ""
	if orig.EvidenceBundle != nil {
		origHash = orig.EvidenceBundle.EvidenceHash
	}

	// 1. Re-execute the exact bounded safe proof procedure
	newBundle, newStatus, summary, err := e.Prover.ExecuteBoundedProof(ctx, orig.Finding, client)
	retestTime := time.Now().UTC()

	if err != nil {
		return &RetestVerdict{
			FindingID:            orig.Finding.ID,
			TargetURL:            orig.Finding.Target,
			OriginalStatus:       origStatus,
			RetestStatus:         RetestInconclusive,
			OriginalEvidenceHash: origHash,
			RetestTimestamp:      retestTime,
			Explanation:          fmt.Sprintf("Retest execution error: %v", err),
		}, nil
	}

	newHash := ""
	newResp := ""
	if newBundle != nil {
		newHash = newBundle.EvidenceHash
		newResp = newBundle.SanitizedResponse
	}

	var verdictStatus RetestStatus
	var explanation string
	var regression bool

	switch {
	// Case 1: Was confirmed, but new probe shows defect is no longer reproducible (fix detected)
	case (origStatus == StatusConfirmed || origStatus == StatusHighConfidence) && (newStatus != StatusConfirmed && newStatus != StatusHighConfidence):
		verdictStatus = RetestFixDetected
		explanation = fmt.Sprintf("Remediation verified: original defect is no longer reproducible. %s", summary)

	// Case 2: Was confirmed and is still confirmed (vulnerability still present)
	case (origStatus == StatusConfirmed || origStatus == StatusHighConfidence) && (newStatus == StatusConfirmed || newStatus == StatusHighConfidence):
		verdictStatus = RetestVulnerabilityPresent
		explanation = fmt.Sprintf("Vulnerability persists: live retest successfully reproduced defect. %s", summary)

	// Case 3: Was NOT confirmed/potential/clean originally, but now reproduces -> REGRESSION DETECTED!
	case (origStatus == StatusPotential || origStatus == StatusNotValidated || origStatus == StatusNotTested) && newStatus == StatusConfirmed:
		verdictStatus = RetestRegressionDetected
		regression = true
		explanation = fmt.Sprintf("Security regression detected: target condition now exhibits confirmed exploitability! %s", summary)

	// Case 4: Inconclusive
	default:
		verdictStatus = RetestInconclusive
		explanation = fmt.Sprintf("Retest outcome is inconclusive: %s", summary)
	}

	verdict := &RetestVerdict{
		FindingID:               orig.Finding.ID,
		TargetURL:               orig.Finding.Target,
		OriginalStatus:          origStatus,
		RetestStatus:            verdictStatus,
		OriginalEvidenceHash:    origHash,
		RetestEvidenceHash:      newHash,
		RetestTimestamp:         retestTime,
		Explanation:             explanation,
		RegressionDetected:      regression,
		SanitizedRetestResponse: newResp,
	}

	// Link retest verdict to finding
	orig.RetestVerdict = verdict
	return verdict, nil
}
