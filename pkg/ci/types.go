package ci

import (
	"os"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/policy"
	"felix/pkg/provenance"
	"felix/pkg/report"
)

// Provider identifies the continuous integration platform.
type Provider string

const (
	// ProviderGitHub represents GitHub Actions environment.
	ProviderGitHub Provider = "github"
	// ProviderGeneric represents a standard/generic CI environment.
	ProviderGeneric Provider = "generic"
)

// DetectProvider inspects the runtime environment to determine the active CI provider.
func DetectProvider() Provider {
	if strings.EqualFold(os.Getenv("GITHUB_ACTIONS"), "true") {
		return ProviderGitHub
	}
	return ProviderGeneric
}

// Config specifies the runtime parameters for a CI assessment run.
type Config struct {
	Provider              Provider
	TargetURL             string
	AssessmentRef         string
	PolicyPath            string
	BaselineRef           string
	BaselineScope         string // "all", "new", "new_and_regressed"
	OutputDir             string
	SARIFFile             string
	JSONFile              string
	HTMLFile              string
	Timeout               string
	Quiet                 bool
	Verbose               bool
	FailOnViolation       bool
	SummaryPath           string // Markdown step summary destination (defaults to $GITHUB_STEP_SUMMARY)
	OutputPath            string // Step output destination (defaults to $GITHUB_OUTPUT)
	DatabasePath          string // SQLite database path (optional override)
	ExpectedVersion       string
	ExpectedSHA256        string
	RequireSHA256         bool
	AllowLoopback         bool
	AllowPrivateIPs       bool
	VerifiedBinary        string
	PRComment             bool   // Publish or update Pull Request summary comment
	PRInline              bool   // Publish inline review annotations when reliable source locations exist
	PRNumber              int    // Pull request number (0 = auto-detect from environment / event payload)
	GitHubToken           string // GitHub authentication token (defaults to GITHUB_TOKEN)
	GitHubRepo            string // GitHub repository slug "owner/repo" (defaults to GITHUB_REPOSITORY)
	CommitSHA             string // Commit SHA for inline reviews (defaults to GITHUB_SHA)
	FeedbackFailurePolicy string // "warn" (default, best-effort) or "fail" (elevate to operational error)
	CommentTag            string // Unique HTML comment tag for idempotent PR summary updates
	GitHubAPIBaseURL      string // GitHub API endpoint (defaults to https://api.github.com; configurable for testing)
}

// Result captures the complete execution outcome of a CI assessment run.
type Result struct {
	ExitCode          int
	Classification    clierror.Classification
	PolicyStatus      string // "PASS", "FAIL", "NONE", "ERROR"
	TotalFindings     int
	SeverityCounts    map[string]int
	BaselineDeltas    *report.ChangeSummary
	PolicyDecision    *policy.EvaluationDecision
	Findings          []report.Finding
	SARIFPath         string
	JSONPath          string
	HTMLPath          string
	DiagnosticSummary string
	FeedbackPublished bool
	FeedbackSummary   string
	FeedbackError     error
	Provenance        *provenance.AssessmentProvenance
	Error             error
}
