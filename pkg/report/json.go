package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"felix/pkg/secrets"
)

// SanitizeEvidence strips any residual sensitive values, passwords, or tokens from evidence strings.
func SanitizeEvidence(input string) string {
	return secrets.RedactText(input)
}

// SanitizeFinding sanitizes all string, URL, header, and structured evidence fields within a Finding
// to prevent leaking sensitive credentials, private keys, or tokens.
func SanitizeFinding(f Finding) Finding {
	cleanF := f
	cleanF.Title = SanitizeEvidence(f.Title)
	cleanF.Description = SanitizeEvidence(f.Description)
	cleanF.Evidence = SanitizeEvidence(f.Evidence)
	cleanF.Target = secrets.SanitizeURL(f.Target)
	cleanF.Endpoint = secrets.SanitizeURL(f.Endpoint)
	cleanF.Remediation = SanitizeEvidence(f.Remediation)

	cleanF.EvidenceDetails.Observation = SanitizeEvidence(f.EvidenceDetails.Observation)
	cleanF.EvidenceDetails.Location = secrets.SanitizeURL(f.EvidenceDetails.Location)
	cleanF.EvidenceDetails.NegativeEvidence = SanitizeEvidence(f.EvidenceDetails.NegativeEvidence)
	cleanF.EvidenceDetails.ExpectedBehavior = SanitizeEvidence(f.EvidenceDetails.ExpectedBehavior)
	cleanF.EvidenceDetails.ObservedBehavior = SanitizeEvidence(f.EvidenceDetails.ObservedBehavior)
	cleanF.EvidenceDetails.DetectionStatus = SanitizeEvidence(f.EvidenceDetails.DetectionStatus)
	cleanF.EvidenceDetails.DetectionMethod = SanitizeEvidence(f.EvidenceDetails.DetectionMethod)

	if len(f.EvidenceDetails.Details) > 0 {
		cleanDetails := make(map[string]string, len(f.EvidenceDetails.Details))
		for k, v := range f.EvidenceDetails.Details {
			if secrets.IsSensitiveKey(k) || secrets.IsSensitiveHeader(k) {
				cleanDetails[k] = "[REDACTED]"
			} else {
				cleanDetails[k] = SanitizeEvidence(v)
			}
		}
		cleanF.EvidenceDetails.Details = cleanDetails
	}

	cleanF.Verification.Result = SanitizeEvidence(f.Verification.Result)
	cleanF.Verification.Rationale = SanitizeEvidence(f.Verification.Rationale)
	cleanF.Verification.SafeCurlCommand = SanitizeEvidence(f.Verification.SafeCurlCommand)
	if len(f.Verification.ReproductionSteps) > 0 {
		cleanSteps := make([]string, len(f.Verification.ReproductionSteps))
		for j, step := range f.Verification.ReproductionSteps {
			cleanSteps[j] = SanitizeEvidence(step)
		}
		cleanF.Verification.ReproductionSteps = cleanSteps
	}
	if len(f.Verification.Limitations) > 0 {
		cleanLimits := make([]string, len(f.Verification.Limitations))
		for j, lim := range f.Verification.Limitations {
			cleanLimits[j] = SanitizeEvidence(lim)
		}
		cleanF.Verification.Limitations = cleanLimits
	}

	if f.RemediationAdvice != nil {
		cleanAdvice := *f.RemediationAdvice
		cleanAdvice.Summary = SanitizeEvidence(f.RemediationAdvice.Summary)
		cleanAdvice.CodeSnippet = SanitizeEvidence(f.RemediationAdvice.CodeSnippet)
		if len(f.RemediationAdvice.Steps) > 0 {
			cleanSteps := make([]string, len(f.RemediationAdvice.Steps))
			for j, s := range f.RemediationAdvice.Steps {
				cleanSteps[j] = SanitizeEvidence(s)
			}
			cleanAdvice.Steps = cleanSteps
		}
		if len(f.RemediationAdvice.References) > 0 {
			cleanRefs := make([]string, len(f.RemediationAdvice.References))
			for j, r := range f.RemediationAdvice.References {
				cleanRefs[j] = SanitizeEvidence(r)
			}
			cleanAdvice.References = cleanRefs
		}
		cleanF.RemediationAdvice = &cleanAdvice
	}

	if cleanF.Provenance != nil {
		sanProv := SanitizeEvidenceProvenance(*cleanF.Provenance)
		cleanF.Provenance = &sanProv
	}
	if cleanF.EvidenceDetails.Provenance != nil {
		sanProv := SanitizeEvidenceProvenance(*cleanF.EvidenceDetails.Provenance)
		cleanF.EvidenceDetails.Provenance = &sanProv
	}

	if cleanF.ScoreExplanation != nil {
		cleanExpl := *cleanF.ScoreExplanation
		cleanExpl.Rationale = SanitizeEvidence(cleanExpl.Rationale)
		cleanExpl.DefendedReason = SanitizeEvidence(cleanExpl.DefendedReason)
		cleanF.ScoreExplanation = &cleanExpl
	}

	return cleanF
}

// sanitizeFinding is an internal alias for SanitizeFinding.
func sanitizeFinding(f Finding) Finding {
	return SanitizeFinding(f)
}

// SanitizeReport ensures all findings and security stories in a report are fully redacted.
func SanitizeReport(rep Report) Report {
	rep.Target = secrets.SanitizeURL(rep.Target)
	if len(rep.Targets) > 0 {
		cleanTargets := make([]string, len(rep.Targets))
		for i, t := range rep.Targets {
			cleanTargets[i] = secrets.SanitizeURL(t)
		}
		rep.Targets = cleanTargets
	}

	cleanFindings := make([]Finding, len(rep.Findings))
	for i, f := range rep.Findings {
		cleanFindings[i] = sanitizeFinding(f)
	}

	cleanPriorities := make([]Finding, len(rep.TopPriorities))
	for i, f := range rep.TopPriorities {
		cleanPriorities[i] = sanitizeFinding(f)
	}

	cleanStories := make([]SecurityStory, len(rep.SecurityStories))
	for i, s := range rep.SecurityStories {
		cleanS := s
		cleanS.Title = SanitizeEvidence(s.Title)
		cleanS.Summary = SanitizeEvidence(s.Summary)
		cleanS.Description = SanitizeEvidence(s.Description)
		cleanS.InvestigateFirst = SanitizeEvidence(s.InvestigateFirst)
		cleanEv := make([]string, len(s.Evidence))
		for j, ev := range s.Evidence {
			cleanEv[j] = SanitizeEvidence(ev)
		}
		cleanS.Evidence = cleanEv
		cleanStories[i] = cleanS
	}

	cleanPaths := make([]AttackPathSummary, len(rep.AttackPaths))
	for i, p := range rep.AttackPaths {
		cleanP := p
		cleanP.Title = SanitizeEvidence(p.Title)
		cleanP.ConfidenceRationale = SanitizeEvidence(p.ConfidenceRationale)
		cleanP.RiskRationale = SanitizeEvidence(p.RiskRationale)
		cleanP.EntryPoint = secrets.SanitizeURL(p.EntryPoint)
		cleanP.TargetAsset = secrets.SanitizeURL(p.TargetAsset)
		cleanP.PrimaryWeakness = SanitizeEvidence(p.PrimaryWeakness)
		cleanP.TerminalImpact = SanitizeEvidence(p.TerminalImpact)
		cleanP.IdentityContext = SanitizeEvidence(p.IdentityContext)
		cleanP.DemonstratedImpact = SanitizeEvidence(p.DemonstratedImpact)
		cleanP.UnverifiedImpact = SanitizeEvidence(p.UnverifiedImpact)
		cleanP.Remediation = SanitizeEvidence(p.Remediation)

		if len(p.Preconditions) > 0 {
			cleanPre := make([]string, len(p.Preconditions))
			for j, pre := range p.Preconditions {
				cleanPre[j] = SanitizeEvidence(pre)
			}
			cleanP.Preconditions = cleanPre
		}
		if len(p.EvidenceRefs) > 0 {
			cleanRefs := make([]string, len(p.EvidenceRefs))
			for j, er := range p.EvidenceRefs {
				cleanRefs[j] = SanitizeEvidence(er)
			}
			cleanP.EvidenceRefs = cleanRefs
		}
		if len(p.Limitations) > 0 {
			cleanLim := make([]string, len(p.Limitations))
			for j, lm := range p.Limitations {
				cleanLim[j] = SanitizeEvidence(lm)
			}
			cleanP.Limitations = cleanLim
		}

		cleanTr := make([]string, len(p.Transitions))
		for j, tr := range p.Transitions {
			cleanTr[j] = SanitizeEvidence(tr)
		}
		cleanP.Transitions = cleanTr
		cleanAs := make([]string, len(p.Assumptions))
		for j, as := range p.Assumptions {
			cleanAs[j] = SanitizeEvidence(as)
		}
		cleanP.Assumptions = cleanAs
		cleanMe := make([]string, len(p.MissingEvidence))
		for j, me := range p.MissingEvidence {
			cleanMe[j] = SanitizeEvidence(me)
		}
		cleanP.MissingEvidence = cleanMe

		if len(p.StepVerifications) > 0 {
			cleanSteps := make([]StepVerificationSummary, len(p.StepVerifications))
			for j, sv := range p.StepVerifications {
				csv := sv
				csv.EntryCondition = SanitizeEvidence(sv.EntryCondition)
				csv.RequiredIdentity = SanitizeEvidence(sv.RequiredIdentity)
				csv.RequiredPermissions = SanitizeEvidence(sv.RequiredPermissions)
				csv.TargetResource = secrets.SanitizeURL(sv.TargetResource)
				csv.ExpectedResult = SanitizeEvidence(sv.ExpectedResult)
				csv.ObservedResult = SanitizeEvidence(sv.ObservedResult)
				csv.DemonstratedImpact = SanitizeEvidence(sv.DemonstratedImpact)
				csv.UnverifiedImpact = SanitizeEvidence(sv.UnverifiedImpact)
				if len(sv.EvidenceRefs) > 0 {
					erCopy := make([]string, len(sv.EvidenceRefs))
					for k, er := range sv.EvidenceRefs {
						erCopy[k] = SanitizeEvidence(er)
					}
					csv.EvidenceRefs = erCopy
				}
				if len(sv.Limitations) > 0 {
					limCopy := make([]string, len(sv.Limitations))
					for k, lm := range sv.Limitations {
						limCopy[k] = SanitizeEvidence(lm)
					}
					csv.Limitations = limCopy
				}
				cleanSteps[j] = csv
			}
			cleanP.StepVerifications = cleanSteps
		}

		if len(p.CredentialValidations) > 0 {
			cleanCreds := make([]CredentialValidationSummary, len(p.CredentialValidations))
			for j, cv := range p.CredentialValidations {
				ccv := cv
				ccv.SourceEvidenceRef = SanitizeEvidence(cv.SourceEvidenceRef)
				ccv.PlaceholderReason = SanitizeEvidence(cv.PlaceholderReason)
				ccv.IntendedIdentity = SanitizeEvidence(cv.IntendedIdentity)
				ccv.ObservedIdentity = SanitizeEvidence(cv.ObservedIdentity)
				ccv.TargetScope = secrets.SanitizeURL(cv.TargetScope)
				ccv.EvidenceSummary = SanitizeEvidence(cv.EvidenceSummary)
				ccv.Limitation = SanitizeEvidence(cv.Limitation)
				cleanCreds[j] = ccv
			}
			cleanP.CredentialValidations = cleanCreds
		}

		if len(p.GraphNodes) > 0 {
			cleanNodes := make([]AttackPathNode, len(p.GraphNodes))
			for j, n := range p.GraphNodes {
				cn := n
				cn.Title = SanitizeEvidence(n.Title)
				cn.Endpoint = secrets.SanitizeURL(n.Endpoint)
				cn.EvidenceSummary = SanitizeEvidence(n.EvidenceSummary)
				cleanNodes[j] = cn
			}
			cleanP.GraphNodes = cleanNodes
		}

		if len(p.GraphEdges) > 0 {
			cleanEdges := make([]AttackPathEdge, len(p.GraphEdges))
			for j, e := range p.GraphEdges {
				ce := e
				ce.SourceTitle = SanitizeEvidence(e.SourceTitle)
				ce.TargetTitle = SanitizeEvidence(e.TargetTitle)
				ce.Explanation = SanitizeEvidence(e.Explanation)
				ce.IdentityContext = SanitizeEvidence(e.IdentityContext)
				ce.AuthContext = SanitizeEvidence(e.AuthContext)
				ce.RequiredPrivileges = SanitizeEvidence(e.RequiredPrivileges)
				ce.ValidationResult = SanitizeEvidence(e.ValidationResult)
				cleanEdges[j] = ce
			}
			cleanP.GraphEdges = cleanEdges
		}

		cleanPaths[i] = cleanP
	}

	rep.Findings = cleanFindings
	rep.TopPriorities = cleanPriorities
	rep.SecurityStories = cleanStories
	rep.AttackPaths = cleanPaths
	if rep.AuthorizationReport != nil {
		rep.AuthorizationReport = SanitizeAuthorizationReport(rep.AuthorizationReport)
	}
	if len(rep.Metadata) > 0 {
		rep.Metadata = secrets.RedactMap(rep.Metadata)
	}
	return rep
}

// GenerateJSON serializes the audit report into formatted, redacted JSON bytes.
func GenerateJSON(rep Report) ([]byte, error) {
	sanitized := SanitizeReport(rep)
	if sanitized.CommercialReport != nil {
		cr := BuildCommercialReport(sanitized)
		sanitized.CommercialReport = &cr
	}
	return json.MarshalIndent(sanitized, "", "  ")
}

// WriteJSON writes the sanitized JSON report to disk with restricted permissions (0600).
func WriteJSON(rep Report, filePath string) error {
	data, err := GenerateJSON(rep)
	if err != nil {
		return err
	}
	return writeReportFileSafely(filePath, data)
}

// MaxReportFileSize defines the maximum permitted size (100 MB) for reading and parsing JSON, SARIF, and Commercial reports.
const MaxReportFileSize int64 = 100 * 1024 * 1024

// ParseReport deserializes a JSON scan result into a Report struct and ensures all findings are sanitized.
func ParseReport(data []byte) (Report, error) {
	if int64(len(data)) > MaxReportFileSize {
		return Report{}, fmt.Errorf("report payload size (%d bytes) exceeds maximum permitted limit (%d bytes)", len(data), MaxReportFileSize)
	}
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return rep, err
	}
	return SanitizeReport(rep), nil
}

// LoadReport reads and deserializes a saved scan result JSON file from disk without network access.
func LoadReport(filePath string) (Report, error) {
	cleanPath := filepath.Clean(filePath)
	fi, err := os.Stat(cleanPath)
	if err != nil {
		return Report{}, err
	}
	if fi.Size() > MaxReportFileSize {
		return Report{}, fmt.Errorf("report file %q size (%d bytes) exceeds maximum permitted limit (%d bytes)", filePath, fi.Size(), MaxReportFileSize)
	}
	data, err := os.ReadFile(cleanPath)
	if err != nil {
		return Report{}, err
	}
	return ParseReport(data)
}
