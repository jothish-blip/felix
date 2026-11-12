package investigation

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"felix/pkg/report"
)

// RetestEngine orchestrates empirical remediation retesting against previously investigated findings.
type RetestEngine struct {
	Prover *SafeProver
}

// NewRetestEngine creates a RetestEngine.
func NewRetestEngine(prover *SafeProver) *RetestEngine {
	var retestProver SafeProver
	if prover == nil {
		retestProver = *NewSafeProver("retest_session", false)
	} else {
		retestProver = *prover
	}
	retestProver.IsRetest = true
	return &RetestEngine{Prover: &retestProver}
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

	origCanonical := report.NormalizeVerificationStatus(report.VerificationStatus(origStatus))
	origWasConfirmed := origStatus == StatusConfirmed || origStatus == StatusHighConfidence || origCanonical == report.VerificationVerified
	untestedProcedure := (newBundle != nil && newBundle.TestIdentifier == "UNTESTED_CATEGORY_PROCEDURE") || newStatus == StatusNotTested

	switch {
	// Never claim FIX_DETECTED when no automated test procedure ran or outcome remained inconclusive/potential
	case untestedProcedure || newStatus == StatusPotential:
		if origWasConfirmed || newStatus == StatusNotTested || untestedProcedure {
			verdictStatus = RetestInconclusive
			explanation = fmt.Sprintf("Retest did not verify remediation (manual verification required or bounded check inconclusive): %s", summary)
		} else {
			verdictStatus = RetestInconclusive
			explanation = fmt.Sprintf("Retest outcome is inconclusive: %s", summary)
		}

	// Case 1: Was confirmed/verified, and an active check explicitly proved the defect is no longer reproducible
	case origWasConfirmed && newStatus == StatusNotValidated:
		verdictStatus = RetestFixDetected
		explanation = fmt.Sprintf("Remediation verified: active retest confirmed original defect is no longer reproducible. %s", summary)

	// Case 2: Was confirmed and is still confirmed/high-confidence (vulnerability still present)
	case origWasConfirmed && (newStatus == StatusConfirmed || newStatus == StatusHighConfidence):
		verdictStatus = RetestVulnerabilityPresent
		explanation = fmt.Sprintf("Vulnerability persists: live retest successfully reproduced defect. %s", summary)

	// Case 3: Was NOT confirmed/verified originally, but now reproduces -> REGRESSION DETECTED!
	case !origWasConfirmed && newStatus == StatusConfirmed:
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
