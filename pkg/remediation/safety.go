package remediation

import (
	"fmt"
	"regexp"
	"strings"

	"felix/pkg/secrets"
)

var (
	dangerousExecPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)child_process\s*\.\s*exec\s*\(`),
		regexp.MustCompile(`(?i)(os/)?exec\s*\.\s*Command\s*\(`),
		regexp.MustCompile(`(?i)subprocess\s*\.\s*call\s*\(.*shell\s*=\s*True`),
		regexp.MustCompile(`(?i)eval\s*\(\s*([a-zA-Z0-9_]+)\s*\)`),
		regexp.MustCompile(`(?i)Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(`),
	}

	weakenedSecurityPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)rejectUnauthorized\s*:\s*false`),
		regexp.MustCompile(`(?i)InsecureSkipVerify\s*:\s*true`),
		regexp.MustCompile(`(?i)verify\s*=\s*False`),
		regexp.MustCompile(`(?i)csrf\s*\(\s*\)\s*\.\s*disable\s*\(\s*\)`),
		regexp.MustCompile(`(?i)\.permitAll\s*\(\s*\)`),
		regexp.MustCompile(`(?i)bypass_auth\s*=\s*True`),
		regexp.MustCompile(`(?i)skip_auth\s*=\s*true`),
	}

	hardcodedSecretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|secret|api_key|apikey|token|access_token)\s*[:=]\s*["'][A-Za-z0-9_\-\.\/+=]{8,}["']`),
		regexp.MustCompile(`(?i)AKIA[0-9A-Z]{16}`),
		regexp.MustCompile(`-----BEGIN [A-Z ]+PRIVATE KEY-----`),
	}
)

// ValidatePatchSafety audits a remediation diff and patched code against security regression policies.
func ValidatePatchSafety(diff *RemediationDiff, patchedCode string) (bool, []string) {
	var violations []string

	if diff == nil {
		return false, []string{"cannot validate nil diff"}
	}

	// 1. Audit added lines in diff for security weakening, shell execution, or hardcoded secrets
	for _, hunk := range diff.Hunks {
		for _, line := range hunk.Lines {
			if !strings.HasPrefix(line, "+") {
				continue
			}
			addedContent := strings.TrimPrefix(line, "+")

			// Check for arbitrary command execution primitives
			for _, pat := range dangerousExecPatterns {
				if pat.MatchString(addedContent) {
					violations = append(violations, fmt.Sprintf("patch introduces arbitrary command execution primitive: %s", pat.String()))
				}
			}

			// Check for weakening security controls
			for _, pat := range weakenedSecurityPatterns {
				if pat.MatchString(addedContent) {
					violations = append(violations, fmt.Sprintf("patch weakens security controls: %s", pat.String()))
				}
			}

			// Check for hardcoded secrets
			for _, pat := range hardcodedSecretPatterns {
				if pat.MatchString(addedContent) {
					violations = append(violations, fmt.Sprintf("patch introduces hardcoded secret or credential: %s", pat.String()))
				}
			}

			// Standard secrets redaction check
			redacted := secrets.RedactText(addedContent)
			if redacted != addedContent && (strings.Contains(redacted, "[REDACTED") || strings.Contains(redacted, "[CANARY")) {
				violations = append(violations, "patch introduces detectable secret or credential token")
			}
		}
	}

	// 2. Audit patched code in its entirety
	for _, pat := range dangerousExecPatterns {
		if pat.MatchString(patchedCode) {
			violations = append(violations, fmt.Sprintf("patched source contains dangerous execution primitive: %s", pat.String()))
		}
	}

	return len(violations) == 0, violations
}
