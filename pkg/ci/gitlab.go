package ci

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// ansiRegex matches standard ANSI color, cursor, and control escape sequences.
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]|\x1b\].*?(\x07|\x1b\\)|\x1b[PX^_].*?\x1b\\|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// StripANSI strips all ANSI escape sequences and non-printable control characters from text.
func StripANSI(text string) string {
	return ansiRegex.ReplaceAllString(text, "")
}

// FormatGitLabSummary formats a human-readable summary for GitLab CI job execution logs.
func FormatGitLabSummary(result GateResult) string {
	var sb strings.Builder

	sb.WriteString("\n=======================================================\n")
	sb.WriteString("              FELIX SECURITY GATE REPORT               \n")
	sb.WriteString("=======================================================\n")

	statusStr := "UNKNOWN"
	switch result.Decision {
	case DecisionPass:
		statusStr = "PASSED (0 Policy Violations)"
	case DecisionFail:
		statusStr = fmt.Sprintf("FAILED (%d Policy Violations)", len(result.Violations))
	case DecisionError:
		statusStr = "ERROR (Operational Failure)"
	}

	sb.WriteString(fmt.Sprintf("Status      : %s\n", statusStr))
	sb.WriteString(fmt.Sprintf("Exit Code   : %d\n", result.ExitCode))
	sb.WriteString(fmt.Sprintf("Total Scanned: %d findings\n", result.TotalFindings))
	sb.WriteString(fmt.Sprintf("Executed At : %s\n\n", result.ExecutedAt.Format(time.RFC3339)))

	sb.WriteString("Policy Thresholds:\n")
	sb.WriteString(fmt.Sprintf("  - Fail On Severities : %s\n", strings.Join(result.Policy.FailOnSeverities, ", ")))
	sb.WriteString(fmt.Sprintf("  - Max CVSS Limit     : %.1f\n", result.Policy.MaxCVSS))
	sb.WriteString(fmt.Sprintf("  - Allow Unverified   : %t\n\n", result.Policy.AllowUnverified))

	sb.WriteString("Findings Breakdown:\n")
	for _, sev := range CanonicalSeverities {
		cnt := 0
		if result.SeverityCounts != nil {
			cnt = result.SeverityCounts[sev]
		}
		sb.WriteString(fmt.Sprintf("  - %-8s : %d\n", sev, cnt))
	}
	sb.WriteString("\n")

	if len(result.Violations) > 0 {
		sb.WriteString("-------------------------------------------------------\n")
		sb.WriteString("VIOLATIONS CAUSING PIPELINE FAILURE:\n")
		sb.WriteString("-------------------------------------------------------\n")
		for idx, v := range result.Violations {
			cvssStr := "N/A"
			if v.CVSS > 0 {
				cvssStr = fmt.Sprintf("%.1f", v.CVSS)
			}
			verStr := "Unverified"
			if v.Verified {
				verStr = "Verified"
			}
			sb.WriteString(fmt.Sprintf("[%d] %s (%s) - %s\n", idx+1, v.FindingID, v.Severity, v.Title))
			sb.WriteString(fmt.Sprintf("    Reason   : %s\n", v.Reason))
			sb.WriteString(fmt.Sprintf("    CVSS     : %s | Verification: %s\n", cvssStr, verStr))
		}
		sb.WriteString("-------------------------------------------------------\n")
	}

	sb.WriteString("=======================================================\n\n")

	cleanOutput := StripANSI(sb.String())
	return secrets.RedactText(cleanOutput)
}

// GitLabVulnerability represents a vulnerability entry conforming to GitLab CI SAST format.
type GitLabVulnerability struct {
	ID          string                 `json:"id"`
	Category    string                 `json:"category"`
	Name        string                 `json:"name"`
	Message     string                 `json:"message"`
	Description string                 `json:"description"`
	Severity    string                 `json:"severity"`
	Confidence  string                 `json:"confidence"`
	Scanner     GitLabScanner          `json:"scanner"`
	Location    GitLabLocation         `json:"location"`
	Identifiers []GitLabIdentifier     `json:"identifiers"`
	Details     map[string]interface{} `json:"details,omitempty"`
}

// GitLabScanner identifies the security scanner in GitLab CI.
type GitLabScanner struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GitLabLocation identifies the file or endpoint location in GitLab CI.
type GitLabLocation struct {
	File string `json:"file,omitempty"`
	Line int    `json:"line,omitempty"`
}

// GitLabIdentifier provides rule/CVE identifiers.
type GitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

// GitLabSecurityReport represents the GitLab SAST JSON report structure.
type GitLabSecurityReport struct {
	Schema          string                `json:"schema"`
	Version         string                `json:"version"`
	Vulnerabilities []GitLabVulnerability `json:"vulnerabilities"`
	Scan            GitLabScanMetadata    `json:"scan"`
	GateEvaluation  GitLabGateEvaluation  `json:"gate_evaluation"`
}

// GitLabScanMetadata describes the scan execution context.
type GitLabScanMetadata struct {
	Scanner   GitLabScanner `json:"scanner"`
	Type      string        `json:"type"`
	Status    string        `json:"status"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
}

// GitLabGateEvaluation captures the gate policy decision.
type GitLabGateEvaluation struct {
	Decision       string            `json:"decision"`
	ExitCode       int               `json:"exit_code"`
	Violations     []PolicyViolation `json:"violations"`
	TotalFindings  int               `json:"total_findings"`
	SeverityCounts map[string]int    `json:"severity_counts"`
}

// MapGitLabSeverity translates FELIX severity to GitLab SAST severity.
func MapGitLabSeverity(sev string) string {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case report.SeverityCritical:
		return "Critical"
	case report.SeverityHigh:
		return "High"
	case report.SeverityMedium:
		return "Medium"
	case report.SeverityLow:
		return "Low"
	case report.SeverityInfo:
		return "Info"
	default:
		return "Unknown"
	}
}

// GenerateGitLabReport produces a valid GitLab CI Security Report JSON.
func GenerateGitLabReport(result GateResult, rep report.Report) ([]byte, error) {
	scanner := GitLabScanner{
		ID:   "felix",
		Name: "Felix Security Engine",
	}

	var vulns []GitLabVulnerability
	for _, f := range rep.Findings {
		locFile := f.EvidenceDetails.Location
		if locFile == "" {
			locFile = f.Endpoint
		}
		if locFile == "" {
			locFile = f.Target
		}

		line := 0
		if f.EvidenceDetails.Details != nil {
			if lStr, ok := f.EvidenceDetails.Details["source_line"]; ok {
				if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
					line = l
				}
			}
		}

		cleanTitle := secrets.RedactText(f.Title)
		cleanDesc := secrets.RedactText(f.Description)
		cleanLoc := StripANSI(locFile)

		v := GitLabVulnerability{
			ID:          f.ID,
			Category:    "sast",
			Name:        cleanTitle,
			Message:     cleanTitle,
			Description: cleanDesc,
			Severity:    MapGitLabSeverity(f.Severity),
			Confidence:  f.Confidence,
			Scanner:     scanner,
			Location: GitLabLocation{
				File: cleanLoc,
				Line: line,
			},
			Identifiers: []GitLabIdentifier{
				{
					Type:  "felix_rule_id",
					Name:  f.RuleID,
					Value: f.RuleID,
				},
			},
			Details: map[string]interface{}{
				"verification_status": string(f.Verification.Status),
				"score":               f.Score,
			},
		}
		vulns = append(vulns, v)
	}

	reportObj := GitLabSecurityReport{
		Schema:          "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.0.0/dist/sast-report-format.json",
		Version:         "15.0.0",
		Vulnerabilities: vulns,
		Scan: GitLabScanMetadata{
			Scanner:   scanner,
			Type:      "sast",
			Status:    "success",
			StartTime: result.ExecutedAt.Format(time.RFC3339),
			EndTime:   result.ExecutedAt.Format(time.RFC3339),
		},
		GateEvaluation: GitLabGateEvaluation{
			Decision:       string(result.Decision),
			ExitCode:       result.ExitCode,
			Violations:     result.Violations,
			TotalFindings:  result.TotalFindings,
			SeverityCounts: result.SeverityCounts,
		},
	}

	data, err := json.MarshalIndent(reportObj, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed marshaling GitLab report: %w", err)
	}
	return data, nil
}
