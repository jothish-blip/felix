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
		cleanEv := make([]string, len(s.Evidence))
		for j, ev := range s.Evidence {
			cleanEv[j] = SanitizeEvidence(ev)
		}
		cleanS.Evidence = cleanEv
		cleanStories[i] = cleanS
	}

	rep.Findings = cleanFindings
	rep.TopPriorities = cleanPriorities
	rep.SecurityStories = cleanStories
	return rep
}

// GenerateJSON serializes the audit report into formatted, redacted JSON bytes.
func GenerateJSON(rep Report) ([]byte, error) {
	sanitized := SanitizeReport(rep)
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
