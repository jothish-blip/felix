package ci

import (
	"fmt"
	"os"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// FormatSummary generates a clear, sanitized Markdown summary suitable for CI step summaries and logs.
func FormatSummary(res *Result, cfg *Config) string {
	if res == nil {
		return ""
	}

	var sb strings.Builder

	sb.WriteString("## 🛡️ FELIX Security Assessment Summary\n\n")

	// 1. Overall Status Alert Box
	switch res.ExitCode {
	case 0:
		sb.WriteString("> 🟢 **STATUS: PASSED** — Assessment completed with 0 policy threshold violations.\n\n")
	case 1:
		sb.WriteString("> 🔴 **STATUS: POLICY VIOLATION** — Assessment completed and established security policy threshold violations.\n\n")
	default:
		sb.WriteString("> ⚠️ **STATUS: OPERATIONAL FAILURE** — Assessment failed or encountered operational errors preventing a trustworthy result.\n\n")
	}

	// 2. Execution Scope & Target Info
	sb.WriteString("### Execution Overview\n\n")
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	if cfg.TargetURL != "" {
		sb.WriteString(fmt.Sprintf("| **Target URL** | `%s` |\n", cfg.TargetURL))
	}
	if cfg.AssessmentRef != "" {
		sb.WriteString(fmt.Sprintf("| **Assessment Project** | `%s` |\n", cfg.AssessmentRef))
	}
	if cfg.BaselineRef != "" {
		sb.WriteString(fmt.Sprintf("| **Baseline Reference** | `%s` |\n", cfg.BaselineRef))
		sb.WriteString(fmt.Sprintf("| **Baseline Scope** | `%s` |\n", cfg.BaselineScope))
	}
	if cfg.PolicyPath != "" {
		sb.WriteString(fmt.Sprintf("| **Policy File** | `%s` |\n", cfg.PolicyPath))
		if res.PolicyDecision != nil && res.PolicyDecision.PolicyDigest != "" {
			sb.WriteString(fmt.Sprintf("| **Policy Digest** | `%s` |\n", res.PolicyDecision.PolicyDigest))
		}
	}
	sb.WriteString(fmt.Sprintf("| **Total Findings** | `%d` |\n", res.TotalFindings))
	sb.WriteString(fmt.Sprintf("| **Exit Code** | `%d` |\n\n", res.ExitCode))

	// 3. Severity Breakdown Table
	sb.WriteString("### Findings by Severity\n\n")
	sb.WriteString("| Severity | Count | Policy Limit | Evaluation |\n")
	sb.WriteString("| :--- | :--- | :--- | :--- |\n")

	severities := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
	}

	for _, sev := range severities {
		count := 0
		if res.SeverityCounts != nil {
			count = res.SeverityCounts[sev]
		}

		limitStr := "N/A"
		statusStr := "—"

		if res.PolicyDecision != nil && res.PolicyDecision.AllowedLimits != nil {
			if limPtr, ok := res.PolicyDecision.AllowedLimits[sev]; ok && limPtr != nil {
				lim := *limPtr
				limitStr = fmt.Sprintf("≤ %d", lim)
				if count > lim {
					statusStr = "❌ **VIOLATION**"
				} else {
					statusStr = "✅ Pass"
				}
			} else {
				statusStr = "✅ Ignored"
			}
		}

		sb.WriteString(fmt.Sprintf("| **%s** | %d | %s | %s |\n", sev, count, limitStr, statusStr))
	}
	sb.WriteString("\n")

	// 4. Baseline Delta Summary (if available)
	if res.BaselineDeltas != nil {
		sb.WriteString("### Baseline Finding Deltas\n\n")
		sb.WriteString("| Delta Category | Count |\n")
		sb.WriteString("| :--- | :--- |\n")
		sb.WriteString(fmt.Sprintf("| **New Findings** | %d |\n", res.BaselineDeltas.Counts.New))
		sb.WriteString(fmt.Sprintf("| **Persistent Findings** | %d |\n", res.BaselineDeltas.Counts.Persistent))
		sb.WriteString(fmt.Sprintf("| **Resolved Findings** | %d |\n", res.BaselineDeltas.Counts.Resolved))
		sb.WriteString(fmt.Sprintf("| **Regressed Findings** | %d |\n", res.BaselineDeltas.Counts.Regressed))
		sb.WriteString(fmt.Sprintf("| **Changed Findings** | %d |\n", res.BaselineDeltas.Counts.Changed))
		sb.WriteString(fmt.Sprintf("| **Unverified Findings** | %d |\n\n", res.BaselineDeltas.Counts.Unverified))
	}

	// 5. Generated Artifacts
	sb.WriteString("### Generated Reports & Artifacts\n\n")
	sb.WriteString("| Format | File Path | Status |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")

	checkArtifact := func(format, path string) {
		if path == "" {
			sb.WriteString(fmt.Sprintf("| %s | *(none)* | Not Requested |\n", format))
			return
		}
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			sb.WriteString(fmt.Sprintf("| %s | `%s` | ✅ Present (%d bytes) |\n", format, path, info.Size()))
		} else {
			sb.WriteString(fmt.Sprintf("| %s | `%s` | ❌ Generation Failed |\n", format, path))
		}
	}

	checkArtifact("SARIF 2.1.0", res.SARIFPath)
	checkArtifact("JSON", res.JSONPath)
	checkArtifact("HTML", res.HTMLPath)
	sb.WriteString("\n")

	// 6. Policy Violations or Operational Error Messages
	if res.PolicyDecision != nil && len(res.PolicyDecision.Violations) > 0 {
		sb.WriteString("### ⚠️ Security Policy Threshold Violations\n\n")
		for _, v := range res.PolicyDecision.Violations {
			sb.WriteString(fmt.Sprintf("- %s\n", v.Message))
		}
		sb.WriteString("\n")
	}

	if res.Error != nil {
		sb.WriteString("### 🛑 Operational Diagnostic\n\n")
		sb.WriteString("```\n")
		sb.WriteString(res.Error.Error())
		sb.WriteString("\n```\n\n")
	}

	// Scrub sensitive data before returning to prevent credentials/tokens leaking to CI logs
	return secrets.RedactText(sb.String())
}

// WriteStepSummary appends the sanitized summary to the GitHub Actions step summary file.
func WriteStepSummary(summaryPath, content string) error {
	path := strings.TrimSpace(summaryPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("GITHUB_STEP_SUMMARY"))
	}
	if path == "" {
		return nil // Not in GitHub Actions or step summary disabled
	}

	sanitized := secrets.RedactText(content)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed opening GITHUB_STEP_SUMMARY (%s): %w", path, err)
	}
	defer f.Close()

	if _, err := f.WriteString(sanitized + "\n"); err != nil {
		return fmt.Errorf("failed writing to GITHUB_STEP_SUMMARY: %w", err)
	}
	return nil
}

// WriteStepOutputs writes key-value outputs to the GitHub Actions output file ($GITHUB_OUTPUT).
func WriteStepOutputs(outputPath string, outputs map[string]string) error {
	path := strings.TrimSpace(outputPath)
	if path == "" {
		path = strings.TrimSpace(os.Getenv("GITHUB_OUTPUT"))
	}
	if path == "" {
		return nil // Not in GitHub Actions or step outputs disabled
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("failed opening GITHUB_OUTPUT (%s): %w", path, err)
	}
	defer f.Close()

	for k, v := range outputs {
		cleanVal := secrets.RedactText(strings.TrimSpace(v))
		cleanKey := strings.TrimSpace(k)
		if strings.Contains(cleanVal, "\n") {
			// Delimited multiline output syntax for GitHub Actions
			delimiter := "EOF_FELIX"
			line := fmt.Sprintf("%s<<%s\n%s\n%s\n", cleanKey, delimiter, cleanVal, delimiter)
			if _, err := f.WriteString(line); err != nil {
				return err
			}
		} else {
			line := fmt.Sprintf("%s=%s\n", cleanKey, cleanVal)
			if _, err := f.WriteString(line); err != nil {
				return err
			}
		}
	}
	return nil
}

// EmitGitHubAnnotations outputs workflow commands to the console (::error::, ::notice::).
func EmitGitHubAnnotations(res *Result) {
	if res == nil {
		return
	}
	switch res.ExitCode {
	case 1:
		msg := "Assessment completed with security policy threshold violations."
		if res.PolicyDecision != nil && len(res.PolicyDecision.Violations) > 0 {
			msg = res.PolicyDecision.Violations[0].Message
		}
		cleanMsg := secrets.RedactText(msg)
		fmt.Printf("::error title=FELIX Policy Violation::%s\n", cleanMsg)
	case 2:
		msg := "Assessment encountered an operational failure or invalid configuration."
		if res.Error != nil {
			msg = res.Error.Error()
		}
		cleanMsg := secrets.RedactText(msg)
		fmt.Printf("::error title=FELIX Operational Error::%s\n", cleanMsg)
	case 0:
		fmt.Printf("::notice title=FELIX Assessment Passed::Security assessment satisfied all configured policy thresholds.\n")
	}
}
