package ci

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

const (
	GateCommentTag = "<!-- felix-ci-gate-summary -->"
)

// EscapeGitHubWorkflowMessage escapes characters in GitHub Actions workflow messages.
// GitHub Actions specification: % -> %25, \r -> %0D, \n -> %0A.
func EscapeGitHubWorkflowMessage(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A")
	return r.Replace(s)
}

// EscapeGitHubWorkflowProperty escapes characters in GitHub Actions workflow property values.
// Specification: % -> %25, \r -> %0D, \n -> %0A, : -> %3A, , -> %2C.
func EscapeGitHubWorkflowProperty(s string) string {
	r := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", ":", "%3A", ",", "%2C")
	return r.Replace(s)
}

// FormatGitHubAnnotation formats a single GitHub Actions workflow command annotation.
// If line is <= 0, line parameter is omitted (never fabricates line numbers).
func FormatGitHubAnnotation(level, file string, line int, title, message string) string {
	cleanLevel := strings.ToLower(strings.TrimSpace(level))
	if cleanLevel == "" {
		cleanLevel = "error"
	}

	// Redact secrets from title and message
	redactedTitle := secrets.RedactText(title)
	redactedMsg := secrets.RedactText(message)

	var props []string
	if strings.TrimSpace(file) != "" {
		props = append(props, fmt.Sprintf("file=%s", EscapeGitHubWorkflowProperty(strings.TrimSpace(file))))
	}
	if line > 0 {
		props = append(props, fmt.Sprintf("line=%d", line))
	}
	if strings.TrimSpace(redactedTitle) != "" {
		props = append(props, fmt.Sprintf("title=%s", EscapeGitHubWorkflowProperty(strings.TrimSpace(redactedTitle))))
	}

	propStr := ""
	if len(props) > 0 {
		propStr = " " + strings.Join(props, ",")
	}

	return fmt.Sprintf("::%s%s::%s", cleanLevel, propStr, EscapeGitHubWorkflowMessage(redactedMsg))
}

// FormatGitHubAnnotations returns workflow command annotations for all violations in a GateResult.
func FormatGitHubAnnotations(result GateResult, rep report.Report) string {
	if len(result.Violations) == 0 {
		return ""
	}

	// Index findings by ID for metadata extraction
	findingMap := make(map[string]report.Finding, len(rep.Findings))
	for _, f := range rep.Findings {
		findingMap[f.ID] = f
	}

	var lines []string
	for _, v := range result.Violations {
		file := ""
		line := 0
		f, ok := findingMap[v.FindingID]
		if ok {
			file = f.EvidenceDetails.Location
			if file == "" {
				file = f.Endpoint
			}
			if file == "" {
				file = f.Target
			}
			if f.EvidenceDetails.Details != nil {
				if lStr, hasLine := f.EvidenceDetails.Details["source_line"]; hasLine {
					if parsedLine, err := strconv.Atoi(lStr); err == nil && parsedLine > 0 {
						line = parsedLine
					}
				}
			}
		}

		level := "error"
		if v.Severity == report.SeverityLow || v.Severity == report.SeverityInfo {
			level = "warning"
		}

		title := fmt.Sprintf("[%s] %s (%s)", v.Severity, v.FindingID, v.RuleID)
		msg := fmt.Sprintf("%s: %s", v.Title, v.Reason)
		lines = append(lines, FormatGitHubAnnotation(level, file, line, title, msg))
	}

	return strings.Join(lines, "\n")
}

// sanitizeMarkdownCell removes control characters, pipes, and converts HTML script tags.
func sanitizeMarkdownCell(s string) string {
	clean := secrets.SanitizeControlCharacters(s)
	clean = strings.ReplaceAll(clean, "|", "\\|")
	clean = strings.ReplaceAll(clean, "<script", "&lt;script")
	clean = strings.ReplaceAll(clean, "</script>", "&lt;/script&gt;")
	return strings.TrimSpace(clean)
}

// GeneratePRSummary generates a comprehensive Markdown summary suitable for a Pull Request comment.
func GeneratePRSummary(result GateResult, rep report.Report) string {
	var sb strings.Builder

	sb.WriteString(GateCommentTag + "\n")
	sb.WriteString("## 🛡️ FELIX CI/CD Security Gate Report\n\n")

	// 1. Status Banner
	switch result.Decision {
	case DecisionPass:
		sb.WriteString("> 🟢 **STATUS: PASSED** — Security gate satisfied all configured policies (Exit Code 0).\n\n")
	case DecisionFail:
		sb.WriteString(fmt.Sprintf("> 🔴 **STATUS: FAILED** — Security gate failed with %d violation(s) (Exit Code 1).\n\n", len(result.Violations)))
	default:
		sb.WriteString(fmt.Sprintf("> ⚠️ **STATUS: ERROR** — Security gate evaluation encountered operational errors (Exit Code %d).\n\n", result.ExitCode))
	}

	// 2. Policy Configuration Overview
	sb.WriteString("### Policy Configuration\n\n")
	sb.WriteString("| Policy Parameter | Configured Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	sb.WriteString(fmt.Sprintf("| **Fail on Severities** | `%s` |\n", strings.Join(result.Policy.FailOnSeverities, ", ")))
	sb.WriteString(fmt.Sprintf("| **Max CVSS Threshold** | `%.1f` |\n", result.Policy.MaxCVSS))
	sb.WriteString(fmt.Sprintf("| **Allow Unverified Findings** | `%t` |\n", result.Policy.AllowUnverified))
	sb.WriteString(fmt.Sprintf("| **Total Findings Evaluated** | `%d` |\n", result.TotalFindings))
	sb.WriteString(fmt.Sprintf("| **Gate Violations** | `%d` |\n\n", len(result.Violations)))

	// 3. Severity Breakdown Table
	sb.WriteString("### Findings by Severity\n\n")
	sb.WriteString("| Severity | Count | Threshold Evaluation |\n")
	sb.WriteString("| :--- | :--- | :--- |\n")

	for _, sev := range CanonicalSeverities {
		cnt := 0
		if result.SeverityCounts != nil {
			cnt = result.SeverityCounts[sev]
		}
		status := "✅ Allowed"
		for _, failSev := range result.Policy.FailOnSeverities {
			if strings.EqualFold(failSev, sev) {
				if cnt > 0 {
					status = "❌ **FAIL THRESHOLD**"
				} else {
					status = "🛡️ Monitored (0 found)"
				}
				break
			}
		}
		sb.WriteString(fmt.Sprintf("| **%s** | %d | %s |\n", sev, cnt, status))
	}
	sb.WriteString("\n")

	// 4. Violations Detail Table (if any)
	if len(result.Violations) > 0 {
		sb.WriteString("### Gate Policy Violations\n\n")
		sb.WriteString("| Finding ID | Severity | CVSS | Verified | Reason | Description |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

		for _, v := range result.Violations {
			cvssStr := "N/A"
			if v.CVSS > 0 {
				cvssStr = fmt.Sprintf("%.1f", v.CVSS)
			}
			verStr := "❌ Unverified"
			if v.Verified {
				verStr = "✅ Verified"
			}
			sb.WriteString(fmt.Sprintf("| `%s` | **%s** | %s | %s | %s | %s |\n",
				sanitizeMarkdownCell(v.FindingID),
				sanitizeMarkdownCell(v.Severity),
				cvssStr,
				verStr,
				sanitizeMarkdownCell(v.Reason),
				sanitizeMarkdownCell(v.Title),
			))
		}
		sb.WriteString("\n")
	}

	// Redact all sensitive tokens across the entire generated Markdown
	return secrets.RedactText(sb.String())
}

// SetGitHubOutput writes gate evaluation parameters to the GitHub Actions output file.
func SetGitHubOutput(result GateResult, outputFile string) error {
	if strings.TrimSpace(outputFile) == "" {
		outputFile = os.Getenv("GITHUB_OUTPUT")
	}
	if strings.TrimSpace(outputFile) == "" {
		return nil
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("decision=%s\n", result.Decision))
	sb.WriteString(fmt.Sprintf("exit_code=%d\n", result.ExitCode))
	sb.WriteString(fmt.Sprintf("violations_count=%d\n", len(result.Violations)))
	sb.WriteString(fmt.Sprintf("total_findings=%d\n", result.TotalFindings))
	sb.WriteString(fmt.Sprintf("is_passing=%t\n", result.IsPassing()))
	sb.WriteString(fmt.Sprintf("summary=%s\n", EscapeGitHubWorkflowMessage(result.SummaryMessage)))

	for sev, cnt := range result.SeverityCounts {
		sb.WriteString(fmt.Sprintf("count_%s=%d\n", strings.ToLower(sev), cnt))
	}

	return os.WriteFile(outputFile, []byte(sb.String()), 0600)
}

// PRCommenter defines the interface for interacting with Pull Request review comments.
type PRCommenter interface {
	PostComment(ctx context.Context, repo string, prNumber int, body string) error
	FindExistingComment(ctx context.Context, repo string, prNumber int, tag string) (int64, error)
	UpdateComment(ctx context.Context, repo string, commentID int64, body string) error
}

// PostedComment represents an in-memory recorded comment.
type PostedComment struct {
	ID        int64
	Repo      string
	PRNumber  int
	Body      string
	UpdatedAt string
}

// MockPRCommenter provides a thread-safe in-memory PRCommenter implementation for testing.
type MockPRCommenter struct {
	mu       sync.Mutex
	comments map[int64]*PostedComment
	nextID   int64
}

// NewMockPRCommenter initializes an empty MockPRCommenter.
func NewMockPRCommenter() *MockPRCommenter {
	return &MockPRCommenter{
		comments: make(map[int64]*PostedComment),
		nextID:   1,
	}
}

// PostComment records a new comment.
func (m *MockPRCommenter) PostComment(ctx context.Context, repo string, prNumber int, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	id := m.nextID
	m.nextID++
	m.comments[id] = &PostedComment{
		ID:       id,
		Repo:     repo,
		PRNumber: prNumber,
		Body:     body,
	}
	return nil
}

// FindExistingComment searches for a comment containing the specified tag.
func (m *MockPRCommenter) FindExistingComment(ctx context.Context, repo string, prNumber int, tag string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var ids []int64
	for id, c := range m.comments {
		if c.Repo == repo && c.PRNumber == prNumber && strings.Contains(c.Body, tag) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return 0, nil
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] > ids[j] })
	return ids[0], nil
}

// UpdateComment updates an existing comment by ID.
func (m *MockPRCommenter) UpdateComment(ctx context.Context, repo string, commentID int64, body string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.comments[commentID]
	if !ok {
		return fmt.Errorf("comment %d not found", commentID)
	}
	c.Body = body
	return nil
}

// GetComments returns a copy of all posted comments.
func (m *MockPRCommenter) GetComments() []*PostedComment {
	m.mu.Lock()
	defer m.mu.Unlock()

	var res []*PostedComment
	for _, c := range m.comments {
		res = append(res, &PostedComment{
			ID:       c.ID,
			Repo:     c.Repo,
			PRNumber: c.PRNumber,
			Body:     c.Body,
		})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].ID < res[j].ID })
	return res
}
