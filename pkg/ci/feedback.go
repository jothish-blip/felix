package ci

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"felix/pkg/report"
	"felix/pkg/secrets"
)

// FormatPRSummary constructs a clear, deterministic Markdown summary for PR comments.
func FormatPRSummary(res *Result, cfg *Config, commentTag string) string {
	if res == nil {
		return ""
	}

	if commentTag == "" {
		commentTag = DefaultCommentTag
	}

	var sb strings.Builder
	sb.WriteString(commentTag + "\n")
	sb.WriteString("## 🛡️ FELIX Security Assessment Summary\n\n")

	// 1. Status Callout
	switch res.ExitCode {
	case 0:
		sb.WriteString("> 🟢 **STATUS: PASSED** — Security assessment satisfied all configured policy thresholds.\n\n")
	case 1:
		sb.WriteString("> 🔴 **STATUS: POLICY VIOLATION** — Assessment completed and established security policy threshold violations.\n\n")
	default:
		sb.WriteString("> ⚠️ **STATUS: INCONCLUSIVE / ERROR** — Assessment encountered operational issues or was incomplete.\n\n")
	}

	// 2. Execution Overview Table
	sb.WriteString("### Execution Overview\n\n")
	sb.WriteString("| Field | Value |\n")
	sb.WriteString("| :--- | :--- |\n")
	if cfg != nil && cfg.TargetURL != "" {
		sb.WriteString(fmt.Sprintf("| **Target** | `%s` |\n", escapeMarkdown(cfg.TargetURL)))
	}
	if cfg != nil && cfg.AssessmentRef != "" {
		sb.WriteString(fmt.Sprintf("| **Assessment Project** | `%s` |\n", escapeMarkdown(cfg.AssessmentRef)))
	}
	if cfg != nil && cfg.BaselineRef != "" {
		sb.WriteString(fmt.Sprintf("| **Baseline Reference** | `%s` |\n", escapeMarkdown(cfg.BaselineRef)))
		sb.WriteString(fmt.Sprintf("| **Baseline Scope** | `%s` |\n", escapeMarkdown(cfg.BaselineScope)))
	}
	if cfg != nil && cfg.PolicyPath != "" {
		sb.WriteString(fmt.Sprintf("| **Policy File** | `%s` |\n", escapeMarkdown(filepath.Base(cfg.PolicyPath))))
		if res.PolicyDecision != nil && res.PolicyDecision.PolicyDigest != "" {
			sb.WriteString(fmt.Sprintf("| **Policy Digest** | `%s` |\n", escapeMarkdown(res.PolicyDecision.PolicyDigest)))
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

		limitStr := "—"
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

	// 4. Baseline Delta Summary (if baseline was used)
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

	// 5. Actionable Findings (Top 10 deduplicated, ordered by severity)
	if len(res.Findings) > 0 {
		sortedFindings := sortAndDeduplicateFindings(res.Findings)
		maxDisplay := 10
		displayCount := len(sortedFindings)
		if displayCount > maxDisplay {
			displayCount = maxDisplay
		}

		sb.WriteString(fmt.Sprintf("### Top Actionable Findings (%d of %d)\n\n", displayCount, len(sortedFindings)))
		sb.WriteString("| Severity | Rule / Title | Location | Status | Remediation |\n")
		sb.WriteString("| :--- | :--- | :--- | :--- | :--- |\n")

		for i := 0; i < displayCount; i++ {
			f := sortedFindings[i]
			rule := f.RuleID
			if rule == "" {
				rule = f.Category
			}
			loc := f.Endpoint
			if loc == "" {
				loc = f.Target
			}
			if len(loc) > 40 {
				loc = "..." + loc[len(loc)-37:]
			}

			remed := f.Remediation
			if f.RemediationAdvice != nil && f.RemediationAdvice.Summary != "" {
				remed = f.RemediationAdvice.Summary
			}
			if len(remed) > 50 {
				remed = remed[:47] + "..."
			}

			lc := f.LifecycleStatus
			if lc == "" {
				lc = "—"
			}

			sb.WriteString(fmt.Sprintf("| **%s** | **%s**: %s | `%s` | %s | %s |\n",
				escapeMarkdown(f.Severity),
				escapeMarkdown(rule),
				escapeMarkdown(f.Title),
				escapeMarkdown(loc),
				escapeMarkdown(lc),
				escapeMarkdown(remed),
			))
		}
		sb.WriteString("\n")

		if len(sortedFindings) > maxDisplay {
			sb.WriteString(fmt.Sprintf("*... and %d additional findings documented in generated security artifacts.*\n\n", len(sortedFindings)-maxDisplay))
		}
	}

	// 6. Security Policy Violations
	if res.PolicyDecision != nil && len(res.PolicyDecision.Violations) > 0 {
		sb.WriteString("### ⚠️ Policy Violations\n\n")
		for _, v := range res.PolicyDecision.Violations {
			sb.WriteString(fmt.Sprintf("- ❌ %s\n", escapeMarkdown(v.Message)))
		}
		sb.WriteString("\n")
	}

	// 7. Operational Diagnostics
	if res.Error != nil {
		sb.WriteString("### 🛑 Operational Diagnostic\n\n")
		sb.WriteString("```\n")
		sb.WriteString(res.Error.Error())
		sb.WriteString("\n```\n\n")
	}

	// 8. Artifact References (only included when valid artifact files or URLs exist)
	var artLines []string
	if isValidArtifact(res.SARIFPath) {
		artLines = append(artLines, fmt.Sprintf("- **SARIF 2.1.0 Report:** `%s`", escapeMarkdown(filepath.Base(res.SARIFPath))))
	}
	if isValidArtifact(res.JSONPath) {
		artLines = append(artLines, fmt.Sprintf("- **Full JSON Report:** `%s`", escapeMarkdown(filepath.Base(res.JSONPath))))
	}
	if isValidArtifact(res.HTMLPath) {
		artLines = append(artLines, fmt.Sprintf("- **Executive HTML Report:** `%s`", escapeMarkdown(filepath.Base(res.HTMLPath))))
	}

	if len(artLines) > 0 {
		sb.WriteString("### Security Artifacts\n\n")
		for _, line := range artLines {
			sb.WriteString(line + "\n")
		}
		sb.WriteString("\n")
	}
	sb.WriteString("---\n*Automated review posted by [FELIX Security Platform](https://github.com/jothish-blip/felix)*\n")

	// Redact sensitive patterns (passwords, tokens, keys)
	return secrets.RedactText(sb.String())
}

// PublishPRFeedback orchestrates publishing PR comments and inline review comments.
func PublishPRFeedback(ctx context.Context, cfg *Config, res *Result) error {
	if cfg == nil || res == nil {
		return nil
	}

	// Check if feedback is enabled
	if !cfg.PRComment && !cfg.PRInline {
		return nil // Zero API calls when feedback is disabled
	}

	// 1. Resolve PR Number
	prNumber := cfg.PRNumber
	headSHA := cfg.CommitSHA
	repoSlug := cfg.GitHubRepo

	if prNumber == 0 || repoSlug == "" || headSHA == "" {
		detPR, detSHA, detRepo, err := DetectPullRequestContext("")
		if err == nil {
			if prNumber == 0 {
				prNumber = detPR
			}
			if headSHA == "" {
				headSHA = detSHA
			}
			if repoSlug == "" {
				repoSlug = detRepo
			}
		}
	}

	if prNumber == 0 {
		// Clean skip when not running in a pull request context
		if cfg.Verbose {
			fmt.Println("[*] PR feedback skipped: not executing in a pull request context (no PR number detected)")
		}
		return nil
	}

	// 2. Resolve Repository Identity
	if repoSlug == "" {
		repoSlug = os.Getenv("GITHUB_REPOSITORY")
	}
	if repoSlug == "" {
		return fmt.Errorf("GitHub repository identity is required for PR feedback (GITHUB_REPOSITORY not set)")
	}

	parts := strings.Split(repoSlug, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid repository format %q; expected 'owner/repo'", repoSlug)
	}
	owner, repo := parts[0], parts[1]

	// 3. Resolve GitHub Token
	token := cfg.GitHubToken
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	if token == "" {
		return fmt.Errorf("GitHub token is required for PR feedback (set GITHUB_TOKEN or --github-token)")
	}

	client := NewGitHubClient(cfg.GitHubAPIBaseURL, token)

	var actionsTaken []string

	// 4. Publish / Update PR Summary Comment
	if cfg.PRComment {
		commentTag := cfg.CommentTag
		if commentTag == "" {
			commentTag = DefaultCommentTag
		}

		summaryBody := FormatPRSummary(res, cfg, commentTag)

		// Search for existing comment with stable tag to update idempotently
		comments, err := client.ListIssueComments(ctx, owner, repo, prNumber)
		if err != nil {
			return fmt.Errorf("failed fetching PR comments: %w", err)
		}

		var existingCommentID int64
		for _, c := range comments {
			if strings.Contains(c.Body, commentTag) {
				existingCommentID = c.ID
				break
			}
		}

		if existingCommentID > 0 {
			_, err = client.UpdateIssueComment(ctx, owner, repo, existingCommentID, summaryBody)
			if err != nil {
				return fmt.Errorf("failed updating existing PR comment %d: %w", existingCommentID, err)
			}
			actionsTaken = append(actionsTaken, fmt.Sprintf("updated PR comment %d", existingCommentID))
		} else {
			created, err := client.CreateIssueComment(ctx, owner, repo, prNumber, summaryBody)
			if err != nil {
				return fmt.Errorf("failed creating PR comment: %w", err)
			}
			actionsTaken = append(actionsTaken, fmt.Sprintf("created PR comment %d", created.ID))
		}
		res.FeedbackPublished = true
	}

	// 5. Publish Inline Review Comments (if enabled and reliable locations exist)
	if cfg.PRInline {
		inlineCandidates := buildInlineReviewComments(res.Findings)
		if len(inlineCandidates) > 0 {
			var inlineComments []PRReviewComment

			// Fetch PR diff if available to ensure inline comments target actual diff lines
			diffText, diffErr := client.GetPRDiff(ctx, owner, repo, prNumber)
			if diffErr == nil && strings.TrimSpace(diffText) != "" {
				validDiffLines := ParsePRDiff(diffText)
				for _, c := range inlineCandidates {
					if linesMap, ok := validDiffLines[c.Path]; ok && linesMap[c.Line] {
						inlineComments = append(inlineComments, c)
					} else if cfg.Verbose {
						fmt.Printf("[*] Inline finding at %s:%d omitted: not within PR diff hunks\n", c.Path, c.Line)
					}
				}
			} else {
				// If diff couldn't be fetched, proceed with candidates and let review API validate
				inlineComments = inlineCandidates
			}

			if len(inlineComments) > 0 {
				if headSHA == "" {
					headSHA = os.Getenv("GITHUB_SHA")
				}
				reviewReq := PRReviewRequest{
					CommitID: headSHA,
					Event:    "COMMENT",
					Body:     "FELIX Security Assessment: Inline Code Findings",
					Comments: inlineComments,
				}

				// Check for existing review on this commit to ensure idempotency on retries
				alreadySubmitted := false
				if existingReviews, err := client.ListPRReviews(ctx, owner, repo, prNumber); err == nil {
					for _, r := range existingReviews {
						if (r.CommitID == headSHA || r.CommitID == "") && strings.Contains(r.Body, "FELIX Security Assessment") {
							alreadySubmitted = true
							break
						}
					}
				}

				if alreadySubmitted {
					actionsTaken = append(actionsTaken, "inline review already exists for this commit; skipped duplicate submission")
					res.FeedbackPublished = true
				} else {
					reviewResp, err := client.CreatePRReview(ctx, owner, repo, prNumber, reviewReq)
					if err != nil {
						if strings.Contains(err.Error(), "422") {
							// GitHub 422 Unprocessable Entity: comments line must be part of the diff
							if cfg.Verbose {
								fmt.Println("[*] Inline review skipped by GitHub (HTTP 422: comments outside diff); retained in summary")
							}
						} else {
							return fmt.Errorf("failed submitting PR inline review: %w", err)
						}
					} else {
						actionsTaken = append(actionsTaken, fmt.Sprintf("submitted inline review %d with %d comments", reviewResp.ID, len(inlineComments)))
						res.FeedbackPublished = true
					}
				}
			} else if cfg.Verbose {
				fmt.Println("[*] Inline feedback: all source findings are outside PR diff hunks; inline review omitted")
			}
		} else if cfg.Verbose {
			fmt.Println("[*] Inline feedback: zero findings with reliable source file locations; inline review omitted")
		}
	}

	if len(actionsTaken) > 0 {
		res.FeedbackSummary = strings.Join(actionsTaken, ", ")
	}

	return nil
}

// buildInlineReviewComments extracts genuine, reliable source code locations for inline comments.
// Fabricated line numbers for URLs, endpoints, or unmapped findings are strictly prohibited.
func buildInlineReviewComments(findings []report.Finding) []PRReviewComment {
	var comments []PRReviewComment
	seen := make(map[string]bool)

	for _, f := range findings {
		filePath, line, ok := ExtractSourceLocation(f)
		if !ok || filePath == "" || line <= 0 {
			continue // Omit findings without genuine source code locations
		}

		key := fmt.Sprintf("%s:%d:%s", filePath, line, f.RuleID)
		if seen[key] {
			continue
		}
		seen[key] = true

		rule := f.RuleID
		if rule == "" {
			rule = f.Category
		}

		body := fmt.Sprintf("🛡️ **[FELIX] [%s] %s: %s**\n\n%s",
			f.Severity,
			rule,
			f.Title,
			f.Description,
		)
		if f.Remediation != "" {
			body += fmt.Sprintf("\n\n**Remediation Guidance:**\n%s", f.Remediation)
		}

		comments = append(comments, PRReviewComment{
			Path: filePath,
			Line: line,
			Side: "RIGHT",
			Body: secrets.RedactText(body),
		})
	}

	return comments
}

// ExtractSourceLocation inspects finding provenance and evidence details to determine if a genuine source file and line exist.
// Returns (filePath, line, true) only if a valid, clean relative file path and positive line number are found.
func ExtractSourceLocation(f report.Finding) (string, int, bool) {
	// 1. Check Provenance Location
	candidates := []string{}
	if f.Provenance != nil && f.Provenance.Location != "" {
		candidates = append(candidates, f.Provenance.Location)
	}
	if f.EvidenceDetails.Location != "" {
		candidates = append(candidates, f.EvidenceDetails.Location)
	}
	if f.Endpoint != "" {
		candidates = append(candidates, f.Endpoint)
	}

	for _, raw := range candidates {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}

		// Reject URLs, HTTP schemes, and absolute web endpoints
		if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.HasPrefix(trimmed, "ftp://") || strings.Contains(trimmed, "://") {
			continue
		}

		// Check for file:line format (e.g. "src/auth/token.go:42" or "app.js:2")
		// Use LastIndex to properly split line numbers from paths
		lastColon := strings.LastIndex(trimmed, ":")
		if lastColon > 0 {
			pathCandidate := filepath.ToSlash(filepath.Clean(trimmed[:lastColon]))
			lineStr := strings.TrimSpace(trimmed[lastColon+1:])
			if lineNum, err := strconv.Atoi(lineStr); err == nil && lineNum > 0 {
				if isValidSourcePath(pathCandidate) {
					return pathCandidate, lineNum, true
				}
			}
		}

		// Reject leading slashes representing URL paths (e.g. /api/users) unless it points to an existing file
		if strings.HasPrefix(trimmed, "/") && !fileExists(trimmed) {
			continue
		}

		// Check if line is present in EvidenceDetails.Details
		if f.EvidenceDetails.Details != nil {
			if lineStr, ok := f.EvidenceDetails.Details["line"]; ok {
				if lineNum, err := strconv.Atoi(strings.TrimSpace(lineStr)); err == nil && lineNum > 0 {
					cleanPath := filepath.ToSlash(filepath.Clean(trimmed))
					if isValidSourcePath(cleanPath) {
						return cleanPath, lineNum, true
					}
				}
			}
		}
	}

	return "", 0, false
}

func isValidSourcePath(p string) bool {
	clean := filepath.ToSlash(filepath.Clean(p))
	if strings.HasPrefix(clean, "..") || clean == "." || clean == "/" || strings.Contains(clean, "://") {
		return false
	}
	// Must have a recognized source code / configuration extension
	ext := strings.ToLower(filepath.Ext(clean))
	validExts := map[string]bool{
		".go": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
		".py": true, ".java": true, ".rb": true, ".php": true, ".cs": true,
		".c": true, ".cpp": true, ".h": true, ".json": true, ".yaml": true,
		".yml": true, ".xml": true, ".html": true, ".sql": true, ".sh": true,
		".env": true, ".toml": true, ".ini": true,
	}
	return validExts[ext]
}

func isValidArtifact(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return true
	}
	info, err := os.Stat(p)
	return err == nil && !info.IsDir() && info.Size() > 0
}

// ParsePRDiff parses unified diff text and returns a map of normalized relative file paths
// to sets of valid line numbers on the RIGHT (new/modified) side of the pull request.
func ParsePRDiff(diffText string) map[string]map[int]bool {
	result := make(map[string]map[int]bool)
	normalized := strings.ReplaceAll(diffText, "\r\n", "\n")
	lines := strings.Split(normalized, "\n")

	var currentFile string
	var rightLine int
	inHunk := false

	for _, l := range lines {
		if strings.HasPrefix(l, "diff --git") {
			inHunk = false
			currentFile = ""
			continue
		}
		if strings.HasPrefix(l, "+++ b/") {
			currentFile = filepath.ToSlash(filepath.Clean(strings.TrimPrefix(l, "+++ b/")))
			if currentFile != "" && result[currentFile] == nil {
				result[currentFile] = make(map[int]bool)
			}
			continue
		}
		if strings.HasPrefix(l, "+++ /dev/null") {
			currentFile = "" // deleted file
			continue
		}
		if strings.HasPrefix(l, "@@ ") {
			inHunk = false
			plusIdx := strings.Index(l, "+")
			if plusIdx > 0 {
				afterPlus := l[plusIdx+1:]
				endIdx := strings.IndexAny(afterPlus, ", ")
				if endIdx > 0 {
					numStr := afterPlus[:endIdx]
					if n, err := strconv.Atoi(numStr); err == nil && n > 0 {
						rightLine = n
						inHunk = true
					}
				}
			}
			continue
		}

		if !inHunk || currentFile == "" {
			continue
		}

		switch {
		case strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++"):
			if result[currentFile] == nil {
				result[currentFile] = make(map[int]bool)
			}
			result[currentFile][rightLine] = true
			rightLine++
		case strings.HasPrefix(l, " "):
			if result[currentFile] == nil {
				result[currentFile] = make(map[int]bool)
			}
			result[currentFile][rightLine] = true
			rightLine++
		case strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---"):
			// Deleted line; only advances old (LEFT) line counter
		case strings.HasPrefix(l, `\`):
			// \ No newline at end of file
		}
	}

	return result
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func sortAndDeduplicateFindings(findings []report.Finding) []report.Finding {
	sevWeight := map[string]int{
		report.SeverityCritical: 5,
		report.SeverityHigh:     4,
		report.SeverityMedium:   3,
		report.SeverityLow:      2,
		report.SeverityInfo:     1,
		report.SeverityUnknown:  0,
	}

	seen := make(map[string]bool)
	var deduped []report.Finding

	for _, f := range findings {
		key := f.Fingerprint
		if key == "" {
			key = f.ID
		}
		if key == "" {
			key = fmt.Sprintf("%s:%s:%s", f.RuleID, f.Target, f.Endpoint)
		}
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, f)
		}
	}

	sort.SliceStable(deduped, func(i, j int) bool {
		wI := sevWeight[strings.ToUpper(deduped[i].Severity)]
		wJ := sevWeight[strings.ToUpper(deduped[j].Severity)]
		if wI != wJ {
			return wI > wJ
		}
		if deduped[i].RuleID != deduped[j].RuleID {
			return deduped[i].RuleID < deduped[j].RuleID
		}
		return deduped[i].Title < deduped[j].Title
	})

	return deduped
}

func escapeMarkdown(s string) string {
	r := strings.NewReplacer(
		"|", "\\|",
		"\n", " ",
		"\r", "",
	)
	return r.Replace(s)
}
