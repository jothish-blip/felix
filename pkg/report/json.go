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

// SanitizeReport ensures all findings and security stories in a report are fully redacted.
func SanitizeReport(rep Report) Report {
	cleanFindings := make([]Finding, len(rep.Findings))
	for i, f := range rep.Findings {
		cleanF := f
		cleanF.Evidence = SanitizeEvidence(f.Evidence)
		cleanFindings[i] = cleanF
	}

	cleanPriorities := make([]Finding, len(rep.TopPriorities))
	for i, f := range rep.TopPriorities {
		cleanF := f
		cleanF.Evidence = SanitizeEvidence(f.Evidence)
		cleanPriorities[i] = cleanF
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
