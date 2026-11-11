package investigation

import (
	"context"
	"net/http"
	"time"

	"felix/pkg/report"
)

// InvestigationOptions configures the InvestigationEngine.
type InvestigationOptions struct {
	AssessmentID string
	SafeMode     bool
}

// InvestigationEngine coordinates instant finding investigation, validation, attack path generation, and remediation.
type InvestigationEngine struct {
	Options InvestigationOptions
	Prover  *SafeProver
	Retest  *RetestEngine
}

// NewInvestigationEngine constructs an InvestigationEngine.
func NewInvestigationEngine(opts InvestigationOptions) *InvestigationEngine {
	prover := NewSafeProver(opts.AssessmentID, opts.SafeMode)
	return &InvestigationEngine{
		Options: opts,
		Prover:  prover,
		Retest:  NewRetestEngine(prover),
	}
}

// Investigate executes the full pipeline on a candidate finding:
// 1. Identifies context (endpoint, asset, parameter, identity)
// 2. Selects least invasive proof method and executes bounded verification
// 3. Captures sanitized evidence bundle and computes SHA-256 hash
// 4. Sets canonical validation status (CONFIRMED, HIGH CONFIDENCE, POTENTIAL, NOT VALIDATED, NOT TESTED)
// 5. Reconstructs structured attack path
// 6. Generates immediate remediation intelligence
func (e *InvestigationEngine) Investigate(ctx context.Context, f report.Finding, client *http.Client, tech string) (*InvestigatedFinding, error) {
	now := time.Now().UTC()

	if f.EvidenceDetails.Details == nil {
		f.EvidenceDetails.Details = make(map[string]string)
	}

	// 1. Execute bounded least-invasive proof
	bundle, status, _, err := e.Prover.ExecuteBoundedProof(ctx, f, client)
	if err != nil {
		status = StatusNotValidated
	}

	// 2. Reconstruct structured attack path
	attackPath := ReconstructAttackPath(f, status, bundle)

	// 3. Generate immediate remediation intelligence
	remediation := GenerateRemediationIntelligence(f, tech)

	investigated := &InvestigatedFinding{
		Finding:          f,
		ValidationStatus: status,
		EvidenceBundle:   bundle,
		AttackPath:       attackPath,
		Remediation:      remediation,
		InvestigatedAt:   now,
	}

	return investigated, nil
}
