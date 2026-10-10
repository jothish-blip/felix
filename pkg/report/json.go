package report

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

var (
	jsonJWTRegex       = regexp.MustCompile(`\bey[A-Za-z0-9_-]{8,}\.ey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\b`)
	jsonSensitiveRegex = regexp.MustCompile(`(?i)(password|secret|key|token|auth|bearer|credential|api_key|private)\s*[:=]\s*["']?([^\s"'` + "`" + `,;]+)`)
)

// SanitizeEvidence strips any residual sensitive values, passwords, or tokens from evidence strings.
func SanitizeEvidence(input string) string {
	if input == "" {
		return ""
	}

	// Mask JWT tokens
	output := jsonJWTRegex.ReplaceAllString(input, "[REDACTED_JWT]")

	// Mask sensitive key-value pairs
	output = jsonSensitiveRegex.ReplaceAllStringFunc(output, func(m string) string {
		parts := strings.SplitN(m, "=", 2)
		if len(parts) == 2 {
			return parts[0] + "=[REDACTED]"
		}
		parts = strings.SplitN(m, ":", 2)
		if len(parts) == 2 {
			return parts[0] + ": [REDACTED]"
		}
		return "[REDACTED]"
	})

	return output
}

// sanitizeFinding sanitizes all string fields within a Finding to prevent leaking sensitive credentials.
func sanitizeFinding(f Finding) Finding {
	cleanF := f
	cleanF.Title = SanitizeEvidence(f.Title)
	cleanF.Description = SanitizeEvidence(f.Description)
	cleanF.Evidence = SanitizeEvidence(f.Evidence)
	cleanF.EvidenceDetails.Observation = SanitizeEvidence(f.EvidenceDetails.Observation)
	cleanF.EvidenceDetails.Location = SanitizeEvidence(f.EvidenceDetails.Location)
	cleanF.EvidenceDetails.NegativeEvidence = SanitizeEvidence(f.EvidenceDetails.NegativeEvidence)
	if len(f.EvidenceDetails.Details) > 0 {
		cleanDetails := make(map[string]string, len(f.EvidenceDetails.Details))
		for k, v := range f.EvidenceDetails.Details {
			cleanDetails[k] = SanitizeEvidence(v)
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
	return cleanF
}

// SanitizeReport ensures all findings and security stories in a report are fully redacted.
func SanitizeReport(rep Report) Report {
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
		cleanP.RiskRationale = SanitizeEvidence(p.RiskRationale)
		cleanP.EntryPoint = SanitizeEvidence(p.EntryPoint)
		cleanP.TargetAsset = SanitizeEvidence(p.TargetAsset)
		cleanP.PrimaryWeakness = SanitizeEvidence(p.PrimaryWeakness)
		cleanP.TerminalImpact = SanitizeEvidence(p.TerminalImpact)
		cleanP.Remediation = SanitizeEvidence(p.Remediation)
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
		cleanPaths[i] = cleanP
	}

	rep.Findings = cleanFindings
	rep.TopPriorities = cleanPriorities
	rep.SecurityStories = cleanStories
	rep.AttackPaths = cleanPaths
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

// WriteJSON writes the sanitized JSON report to disk.
func WriteJSON(rep Report, filePath string) error {
	data, err := GenerateJSON(rep)
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0644)
}

// ParseReport deserializes a JSON scan result into a Report struct.
func ParseReport(data []byte) (Report, error) {
	var rep Report
	if err := json.Unmarshal(data, &rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// LoadReport reads and deserializes a saved scan result JSON file from disk without network access.
func LoadReport(filePath string) (Report, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return Report{}, err
	}
	return ParseReport(data)
}
