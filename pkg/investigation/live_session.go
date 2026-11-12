package investigation

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// LiveAssessmentSession manages the real-time finding investigation, validation, and presentation lifecycle.
type LiveAssessmentSession struct {
	mu                   sync.RWMutex
	AssessmentID         string
	TargetURL            string
	Profile              string
	TargetTech           string
	Engine               *InvestigationEngine
	InvestigatedFindings []*InvestigatedFinding
	AttackChains         []AttackChain
	Roadmap              *RemediationRoadmap
	Output               io.Writer
	Verbose              bool
	Quiet                bool
}

// NewLiveAssessmentSession constructs a new thread-safe live assessment session.
func NewLiveAssessmentSession(assessmentID, targetURL, profile string, safeMode bool, out io.Writer) *LiveAssessmentSession {
	if out == nil {
		out = os.Stdout
	}
	engine := NewInvestigationEngine(InvestigationOptions{
		AssessmentID: assessmentID,
		SafeMode:     safeMode,
	})
	return &LiveAssessmentSession{
		AssessmentID: assessmentID,
		TargetURL:    targetURL,
		Profile:      profile,
		Engine:       engine,
		Roadmap:      &RemediationRoadmap{},
		Output:       out,
	}
}

// ProcessFinding takes a candidate finding, immediately investigates and proves it, updates the attack path
// and remediation roadmap, and displays it immediately on the live assessment interface.
func (s *LiveAssessmentSession) ProcessFinding(ctx context.Context, f report.Finding, client *http.Client) (*InvestigatedFinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Execute instant investigation and bounded proof
	inf, err := s.Engine.Investigate(ctx, f, client, s.TargetTech)
	if err != nil {
		return nil, err
	}

	s.InvestigatedFindings = append(s.InvestigatedFindings, inf)

	// 2. Re-evaluate multi-hop attack chains
	s.AttackChains = AnalyzeAttackChains(s.InvestigatedFindings)

	// 3. Continuously update the remediation roadmap
	s.Roadmap = BuildRemediationRoadmap(s.InvestigatedFindings)

	// 4. Immediately publish finding card to live assessment interface
	if !s.Quiet {
		s.renderFindingCard(inf)
	}

	return inf, nil
}

// renderFindingCard formats and writes an immediate real-time finding alert to the console.
func (s *LiveAssessmentSession) renderFindingCard(inf *InvestigatedFinding) {
	f := inf.Finding
	status := inf.ValidationStatus

	statusBadge := fmt.Sprintf("[%s]", status)
	switch status {
	case StatusConfirmed:
		statusBadge = fmt.Sprintf("\033[1;32m[CONFIRMED]\033[0m") // Green bold
	case StatusHighConfidence:
		statusBadge = fmt.Sprintf("\033[1;36m[HIGH CONFIDENCE]\033[0m") // Cyan bold
	case StatusPotential:
		statusBadge = fmt.Sprintf("\033[1;33m[POTENTIAL]\033[0m") // Yellow bold
	default:
		statusBadge = fmt.Sprintf("[%s]", status)
	}

	fmt.Fprintf(s.Output, "\n-----------------------------------------------------------\n")
	fmt.Fprintf(s.Output, "  [!] LIVE FINDING INVESTIGATED: %s\n", statusBadge)
	fmt.Fprintf(s.Output, "-----------------------------------------------------------\n")
	fmt.Fprintf(s.Output, "  Vulnerability:    %s\n", f.Title)
	fmt.Fprintf(s.Output, "  Severity:         %s | Confidence: %s\n", f.Severity, f.Confidence)
	fmt.Fprintf(s.Output, "  Validation State: %s\n", status)
	affectedRoute := f.Endpoint
	if affectedRoute == "" {
		affectedRoute = f.Target
	}
	method := f.Method
	if method == "" {
		method = "GET"
	}
	fmt.Fprintf(s.Output, "  Affected Route:   %s %s\n", method, affectedRoute)

	authCtx := "UNAUTHENTICATED"
	if f.AuthContext != "" && f.AuthContext != report.AuthContextNoChallenge {
		authCtx = string(f.AuthContext)
	} else if strings.Contains(strings.ToUpper(f.Category), "BOLA") || strings.Contains(strings.ToUpper(f.Category), "IDOR") {
		authCtx = "AUTHENTICATED_USER"
	}
	fmt.Fprintf(s.Output, "  Auth Context:     %s\n", authCtx)

	if inf.EvidenceBundle != nil {
		fmt.Fprintf(s.Output, "  Proof Summary:    %s\n", inf.EvidenceBundle.ProofSummary)
		fmt.Fprintf(s.Output, "  Evidence Hash:    %s\n", inf.EvidenceBundle.EvidenceHash)
		if inf.EvidenceBundle.SafeCurlCommand != "" && s.Verbose {
			fmt.Fprintf(s.Output, "  cURL Repro:       %s\n", inf.EvidenceBundle.SafeCurlCommand)
		}
	}

	if inf.AttackPath != nil {
		fmt.Fprintf(s.Output, "  Attack Path:      %s\n", inf.AttackPath.GraphVisual)
	}

	if inf.Remediation != nil {
		fmt.Fprintf(s.Output, "  Remediation:      %s\n", inf.Remediation.RecommendedFix)
		fmt.Fprintf(s.Output, "  Fix Priority:     %s\n", inf.Remediation.Priority)
	}

	if inf.RetestVerdict != nil {
		fmt.Fprintf(s.Output, "  Retest Status:    %s\n", inf.RetestVerdict.RetestStatus)
	}
	fmt.Fprintf(s.Output, "-----------------------------------------------------------\n")
}

// GetFindings returns a copy of all investigated findings in the session.
func (s *LiveAssessmentSession) GetFindings() []*InvestigatedFinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make([]*InvestigatedFinding, len(s.InvestigatedFindings))
	copy(res, s.InvestigatedFindings)
	return res
}

// GetRoadmap returns the current continuous remediation roadmap.
func (s *LiveAssessmentSession) GetRoadmap() *RemediationRoadmap {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Roadmap
}

// GetAttackChains returns all detected attack chains.
func (s *LiveAssessmentSession) GetAttackChains() []AttackChain {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.AttackChains
}

// EnrichReport updates the final report.Report with investigated findings, attack paths, and remediation advice.
func (s *LiveAssessmentSession) EnrichReport(rep *report.Report) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var enrichedFindings []report.Finding
	var attackSummaries []report.AttackPathSummary

	for _, inf := range s.InvestigatedFindings {
		f := inf.Finding

		// Synchronize verification state (keep ValidationStatus verbatim; report normalization maps to canonical statuses)
		f.Verification.Status = report.VerificationStatus(inf.ValidationStatus)
		f.Status = report.FindingStatusFromVerification(f.Verification.Status)
		f.Verification.Result = fmt.Sprintf("Validation outcome: %s", inf.ValidationStatus)
		if inf.EvidenceBundle != nil {
			f.Verification.Rationale = secrets.RedactText(inf.EvidenceBundle.ProofSummary)
			f.Verification.SafeCurlCommand = secrets.RedactText(inf.EvidenceBundle.SafeCurlCommand)
			var redSteps []string
			for _, stepStr := range inf.EvidenceBundle.ReproductionSteps {
				redSteps = append(redSteps, secrets.RedactText(stepStr))
			}
			f.Verification.ReproductionSteps = redSteps
			f.Verification.Attempted = true
			if inf.EvidenceBundle.EvidenceHash != "" {
				f.Provenance = &report.EvidenceProvenance{
					FindingID:     f.ID,
					ContentDigest: inf.EvidenceBundle.EvidenceHash,
					CollectedAt:   inf.EvidenceBundle.ValidationTime,
					SourceEngine:  inf.EvidenceBundle.ModuleID,
				}
			}
		}

		// Synchronize remediation advice
		if inf.Remediation != nil {
			f.Remediation = inf.Remediation.RecommendedFix
			f.RemediationAdvice = &report.RemediationAdvice{
				Summary:     inf.Remediation.RootCause,
				Steps:       []string{inf.Remediation.RecommendedFix, inf.Remediation.ImplementationGuidance},
				CodeSnippet: inf.Remediation.CodeSnippet,
			}
		}

		enrichedFindings = append(enrichedFindings, f)

		// Convert single attack path to report summary
		if inf.AttackPath != nil {
			var nodes []report.AttackPathNode
			for _, st := range inf.AttackPath.Steps {
				nodes = append(nodes, report.AttackPathNode{
					ID:                 fmt.Sprintf("%s_step%d", f.ID, st.StepNumber),
					Title:              st.Action,
					Severity:           f.Severity,
					VerificationStatus: string(inf.ValidationStatus),
					Endpoint:           secrets.SanitizeURL(st.Endpoint),
					EvidenceSummary:    secrets.RedactText(st.ObservedBehavior),
					IsEntrypoint:       st.StepNumber == 1,
					IsTarget:           st.StepNumber == len(inf.AttackPath.Steps),
				})
			}

			attackSummaries = append(attackSummaries, report.AttackPathSummary{
				ID:                "path_" + f.ID,
				Title:             fmt.Sprintf("Attack Path: %s (%s)", f.Title, inf.ValidationStatus),
				Status:            string(inf.ValidationStatus),
				Confidence:        f.Confidence,
				CombinedRiskLevel: f.Severity,
				CombinedRiskScore: f.Score,
				EntryPoint:        secrets.SanitizeURL(inf.AttackPath.InitialEntryPoint),
				TargetAsset:       secrets.SanitizeURL(inf.AttackPath.AffectedEndpoint),
				PrimaryWeakness:   secrets.RedactText(inf.AttackPath.FailedControl),
				TerminalImpact:    secrets.RedactText(inf.AttackPath.DemonstratedImpact),
				Remediation:       f.Remediation,
				NodeIDs:           []string{f.ID},
				GraphNodes:        nodes,
			})
		}
	}

	// Add multi-hop attack chains to report with honest status-derived risk/confidence metrics.
	for _, ac := range s.AttackChains {
		chainConf := "LOW"
		chainRisk := "MEDIUM"
		chainScore := 40
		var missing []string

		switch ac.Status {
		case StatusConfirmed:
			chainConf = "HIGH"
			chainRisk = "HIGH"
			chainScore = 75
		case StatusHighConfidence:
			chainConf = "MEDIUM"
			chainRisk = "HIGH"
			chainScore = 65
			missing = append(missing, "Full terminal exploitation impact verification pending safe read-only bounds")
		default:
			missing = append(missing, "Cross-step causal reachability between component findings has not been independently validated")
		}

		attackSummaries = append(attackSummaries, report.AttackPathSummary{
			ID:                ac.ID,
			Title:             secrets.RedactText(ac.Title),
			Status:            string(ac.Status),
			Confidence:        chainConf,
			CombinedRiskLevel: chainRisk,
			CombinedRiskScore: chainScore,
			RiskRationale:     secrets.RedactText(ac.Summary),
			EntryPoint:        secrets.RedactText(ac.DemonstratedPath),
			TargetAsset:       "Multi-Vulnerability Chain",
			TerminalImpact:    secrets.RedactText(ac.Summary),
			MissingEvidence:   missing,
			NodeIDs:           ac.FindingIDs,
		})
	}

	rep.Findings = enrichedFindings
	rep.AttackPaths = attackSummaries
	report.RecalculateReportRisk(rep)
}
