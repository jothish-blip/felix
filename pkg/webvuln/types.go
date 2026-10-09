package webvuln

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/report"
)

// VulnCategory identifies one of the 13 web vulnerability categories.
type VulnCategory string

const (
	CategoryXSS              VulnCategory = "XSS"
	CategorySQLi             VulnCategory = "SQLI"
	CategoryNoSQLi           VulnCategory = "NOSQLI"
	CategoryCmdi             VulnCategory = "CMDI"
	CategoryPathTraversal    VulnCategory = "PATH_TRAVERSAL"
	CategoryFileInclusion    VulnCategory = "FILE_INCLUSION"
	CategorySSTI             VulnCategory = "SSTI"
	CategorySSRF             VulnCategory = "SSRF"
	CategoryOpenRedirect     VulnCategory = "OPEN_REDIRECT"
	CategoryRequestIssues    VulnCategory = "REQUEST_ISSUES"
	CategoryInfoDisclosure   VulnCategory = "INFO_DISCLOSURE"
	CategoryDeserialization  VulnCategory = "DESERIALIZATION"
	CategoryMisconfiguration VulnCategory = "MISCONFIGURATION"
)

// CategoryInfo provides metadata and verification boundaries for each category.
type CategoryInfo struct {
	Code                 string `json:"code"`
	Name                 string `json:"name"`
	CWE                  string `json:"cwe"`
	Description          string `json:"description"`
	VerificationBoundary string `json:"verification_boundary"`
}

// CategoryMetadata maps all 13 vulnerability categories to authoritative metadata.
var CategoryMetadata = map[VulnCategory]CategoryInfo{
	CategoryXSS: {
		Code:                 "WV-XSS",
		Name:                 "Cross-Site Scripting (XSS)",
		CWE:                  "CWE-79",
		Description:          "Untrusted input is reflected or included in web output without appropriate context-aware encoding or sanitization.",
		VerificationBoundary: "Verified exclusively via safe synthetic fixtures demonstrating unsafe interpretation. On live targets, lack of browser DOM instrumentation prevents execution proof, keeping plausible contexts as CANDIDATE and harmless text/strings/comments as OBSERVED. Encoded output is NOT_VULNERABLE.",
	},
	CategorySQLi: {
		Code:                 "WV-SQLI",
		Name:                 "SQL Injection",
		CWE:                  "CWE-89",
		Description:          "Untrusted user input is directly concatenated into database queries without parameterization.",
		VerificationBoundary: "Verified only when non-destructive syntax disruption produces database-specific syntax errors compared against baseline. Generic HTTP 500 errors remain CANDIDATE.",
	},
	CategoryNoSQLi: {
		Code:                 "WV-NOSQLI",
		Name:                 "NoSQL Injection",
		CWE:                  "CWE-943",
		Description:          "Untrusted user input allows modification of query logic in document or key-value stores.",
		VerificationBoundary: "Verified only on repeatable query manipulation differential with safe structure/operator probes. Ambiguous responses remain CANDIDATE.",
	},
	CategoryCmdi: {
		Code:                 "WV-CMDI",
		Name:                 "OS Command Injection",
		CWE:                  "CWE-78",
		Description:          "Application constructs host operating system commands using unsanitized user-supplied parameters.",
		VerificationBoundary: "Zero live command execution. Verified exclusively via synthetic test harness fixtures. Live findings strictly remain CANDIDATE or OBSERVED for safety.",
	},
	CategoryPathTraversal: {
		Code:                 "WV-PATH",
		Name:                 "Path Traversal",
		CWE:                  "CWE-22",
		Description:          "Application permits directory traversal sequences allowing unauthorized traversal of the filesystem hierarchy.",
		VerificationBoundary: "Zero live credential or system file retrieval. Verified exclusively via synthetic canary fixtures. Live traversal indicators remain CANDIDATE.",
	},
	CategoryFileInclusion: {
		Code:                 "WV-FILEINC",
		Name:                 "Local/Remote File Inclusion",
		CWE:                  "CWE-98",
		Description:          "Application includes or executes files specified via user input without path validation.",
		VerificationBoundary: "Zero remote attacker file inclusion. Static analysis and controlled safe parameter inspection. Live indicators remain CANDIDATE.",
	},
	CategorySSTI: {
		Code:                 "WV-SSTI",
		Name:                 "Server-Side Template Injection",
		CWE:                  "CWE-1336",
		Description:          "User input is concatenated into a template engine and evaluated on the server.",
		VerificationBoundary: "Verified only when harmless arithmetic expression (e.g. {{491*13}}) evaluates to calculated mathematical result (6383). Literal reflection is NOT_VULNERABLE.",
	},
	CategorySSRF: {
		Code:                 "WV-SSRF",
		Name:                 "Server-Side Request Forgery",
		CWE:                  "CWE-918",
		Description:          "Web server accepts user-supplied URLs and fetches remote resources without destination validation.",
		VerificationBoundary: "Zero probing of private, loopback, or cloud metadata ranges. Verified exclusively via pre-configured canary callback URL. URL parameters remain CANDIDATE.",
	},
	CategoryOpenRedirect: {
		Code:                 "WV-REDIRECT",
		Name:                 "Open Redirect",
		CWE:                  "CWE-601",
		Description:          "Application redirects users to an arbitrary external URL without destination validation.",
		VerificationBoundary: "Verified only when differential testing proves redirect destination is derived from user input and targets external canary. Static redirects remain OBSERVED or NOT_VULNERABLE.",
	},
	CategoryRequestIssues: {
		Code:                 "WV-REQISSUE",
		Name:                 "HTTP Request Issues / Smuggling",
		CWE:                  "CWE-444",
		Description:          "Inconsistencies or ambiguities in HTTP request parsing between front-end and back-end proxies.",
		VerificationBoundary: "Passive header analysis and normalization checks by default. Active desynchronization disabled by default. Live indicators remain OBSERVED or CANDIDATE.",
	},
	CategoryInfoDisclosure: {
		Code:                 "WV-INFODISC",
		Name:                 "Information Disclosure",
		CWE:                  "CWE-200",
		Description:          "Unintended exposure of sensitive debug information, stack traces, system paths, or environment secrets.",
		VerificationBoundary: "Zero live file content downloading for sensitive files (/.env, /.git/config); verified via synthetic fixtures or non-sensitive status pages. All secrets redacted.",
	},
	CategoryDeserialization: {
		Code:                 "WV-DESERIAL",
		Name:                 "Insecure Deserialization",
		CWE:                  "CWE-502",
		Description:          "Untrusted serialized objects processed without validation or integrity checks.",
		VerificationBoundary: "Passive observation and static signature matching only. Zero gadget chains or RCE probes. Live observations remain OBSERVED or CANDIDATE.",
	},
	CategoryMisconfiguration: {
		Code:                 "WV-MISCONFIG",
		Name:                 "Security Misconfiguration",
		CWE:                  "CWE-16",
		Description:          "Insecure default settings, exposed directory listings, unprotected debug consoles, or unsafe HTTP methods.",
		VerificationBoundary: "Verified when directory listings (Index of /) or unprotected debug consoles are confirmed accessible. Non-overlapping with apisec header checks.",
	},
}

// VerificationState represents the empirical verification state of a vulnerability test.
type VerificationState string

const (
	StateObserved      VerificationState = "OBSERVED"
	StateCandidate     VerificationState = "CANDIDATE"
	StateVerified      VerificationState = "VERIFIED"
	StateInconclusive  VerificationState = "INCONCLUSIVE"
	StateNotVulnerable VerificationState = "NOT_VULNERABLE"
)

// CoverageStatus represents the assessment status for a vulnerability category.
type CoverageStatus string

const (
	CoverageUntested           CoverageStatus = "UNTESTED"
	CoverageActivelyTested     CoverageStatus = "ACTIVELY_TESTED"
	CoveragePassivelyAssessed  CoverageStatus = "PASSIVELY_ASSESSED"
	CoverageVerifiedIssueFound CoverageStatus = "VERIFIED_ISSUE_FOUND"
	CoverageNotApplicable      CoverageStatus = "NOT_APPLICABLE"
)

// CategoryCoverage summarizes testing effort and verification state for one category.
type CategoryCoverage struct {
	Category     VulnCategory   `json:"category"`
	Code         string         `json:"code"`
	Name         string         `json:"name"`
	Status       CoverageStatus `json:"status"`
	TestsRun     int            `json:"tests_run"`
	Verified     int            `json:"verified"`
	Candidates   int            `json:"candidates"`
	Observations int            `json:"observations"`
	Explanation  string         `json:"explanation,omitempty"`
}

// Result records the outcome of a single vulnerability evaluation.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          VulnCategory      `json:"category"`
	VulnCode          string            `json:"vuln_code"`
	TestName          string            `json:"test_name"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	ObservedStatus    int               `json:"observed_status,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CorrelatedID      string            `json:"correlated_id,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// Summary aggregates vulnerability results across all categories.
type Summary struct {
	TotalTests         int                         `json:"total_tests"`
	CategoriesCovered  int                         `json:"categories_covered"`
	VerifiedCount      int                         `json:"verified_count"`
	CandidateCount     int                         `json:"candidate_count"`
	ObservedCount      int                         `json:"observed_count"`
	InconclusiveCount  int                         `json:"inconclusive_count"`
	NotVulnerableCount int                         `json:"not_vulnerable_count"`
	CoverageMap        map[string]CategoryCoverage `json:"coverage_map"`
}

// RunRecord represents a persistent run record in the database.
type RunRecord struct {
	ID                 string    `json:"id"`
	AssessmentID       string    `json:"assessment_id"`
	ExecutionID        string    `json:"execution_id"`
	TotalTests         int       `json:"total_tests"`
	CategoriesAssessed int       `json:"categories_assessed"`
	VerifiedCount      int       `json:"verified_count"`
	CandidateCount     int       `json:"candidate_count"`
	ObservedCount      int       `json:"observed_count"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// TargetEndpoint describes an endpoint target evaluated by the engine.
type TargetEndpoint struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Parameters []string          `json:"parameters,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Source     string            `json:"source,omitempty"`
	IsForm     bool              `json:"is_form"`
	FormFields []string          `json:"form_fields,omitempty"`
}

// Config defines the configuration for the Web Vulnerability Engine.
type Config struct {
	Timeout              time.Duration `json:"timeout"`
	Concurrency          int           `json:"concurrency"`
	CanaryCallbackURL    string        `json:"canary_callback_url,omitempty"`
	AllowActiveSmuggling bool          `json:"allow_active_smuggling"`
	AllowSyntheticProbes bool          `json:"allow_synthetic_probes"`
	MaxBodyReadBytes     int64         `json:"max_body_read_bytes"`
	UserAgent            string        `json:"user_agent"`
}

// DefaultConfig provides sensible, safe defaults for the Web Vulnerability Engine.
func DefaultConfig() Config {
	return Config{
		Timeout:              10 * time.Second,
		Concurrency:          5,
		CanaryCallbackURL:    "",
		AllowActiveSmuggling: false, // strictly disabled by default
		AllowSyntheticProbes: true,
		MaxBodyReadBytes:     2 * 1024 * 1024, // 2MB
		UserAgent:            "Felix/2.0 (Authorized Security Assessment; WebVuln)",
	}
}

// AssessmentContext contains all contextual inputs for a web vulnerability evaluation run.
type AssessmentContext struct {
	AssessmentID     string
	ExecutionID      string
	BaseURL          string
	Endpoints        []TargetEndpoint
	DiscoveredAssets []string
	IsAllowed        func(string) bool
	IsExcluded       func(string) bool
	SyntheticFixture bool // true in controlled test harness environments
}

// Regex patterns for comprehensive credential and token redaction.
var (
	pemPrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----.*?-----END [A-Z0-9_-]+ PRIVATE KEY-----`)
	bearerTokenPattern   = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-_.~+/=]{12,}`)
	jwtPattern           = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	cookieSecretPattern  = regexp.MustCompile(`(?i)((?:session|token|auth|access_token|jwt|sid|key)=)[^;,\s]+`)
	querySecretPattern   = regexp.MustCompile(`(?i)((?:token|api_key|apikey|secret|password|passwd|auth)=)[^&\s]+`)
	kvSecretPattern      = regexp.MustCompile(`(?i)\b(?:api_key|apikey|secret|password|passwd|auth_token|access_token|client_secret|db_password|private_key)\s*[:=]\s*["']?([^\s"']+)["']?`)
	htmlPasswordPattern1 = regexp.MustCompile(`(?i)(<input[^>]*type=["']?password["']?[^>]*value=["']?)([^"'>]+)(["']?[^>]*>)`)
	htmlPasswordPattern2 = regexp.MustCompile(`(?i)(<input[^>]*value=["']?)([^"'>]+)(["']?[^>]*type=["']?password["']?[^>]*>)`)
	htmlTokenPattern1    = regexp.MustCompile(`(?i)(<input[^>]*name=["']?(?:csrf|token|auth)[^"'>]*["']?[^>]*value=["']?)([^"'>]+)(["']?[^>]*>)`)
	htmlTokenPattern2    = regexp.MustCompile(`(?i)(<input[^>]*value=["']?)([^"'>]+)(["']?[^>]*name=["']?(?:csrf|token|auth)[^"'>]*["']?[^>]*>)`)
)

// RedactText removes credentials, tokens, session IDs, private keys, and secrets from text.
func RedactText(input string) string {
	if input == "" {
		return ""
	}
	s := input

	// 1. Redact PEM private keys
	s = pemPrivateKeyPattern.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")

	// 2. Redact Bearer tokens
	s = bearerTokenPattern.ReplaceAllString(s, "${1}[REDACTED]")

	// 3. Redact JWT tokens
	s = jwtPattern.ReplaceAllString(s, "[REDACTED_JWT]")

	// 4. Redact HTML form password and sensitive token inputs
	s = htmlPasswordPattern1.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlPasswordPattern2.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlTokenPattern1.ReplaceAllString(s, "${1}[REDACTED]${3}")
	s = htmlTokenPattern2.ReplaceAllString(s, "${1}[REDACTED]${3}")

	// 5. Redact session cookies
	s = cookieSecretPattern.ReplaceAllString(s, "${1}[REDACTED]")

	// 6. Redact URL query parameters
	s = querySecretPattern.ReplaceAllString(s, "${1}[REDACTED]")

	// 7. Redact key-value secrets
	s = kvSecretPattern.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, "[REDACTED") {
			return m
		}
		idx := strings.IndexAny(m, ":=")
		if idx == -1 {
			return m
		}
		key := m[:idx]
		sep := string(m[idx])
		return fmt.Sprintf("%s%s[REDACTED]", key, sep)
	})

	return s
}

// RedactBody produces a bounded, sanitized snippet of an HTTP body for evidence recording.
func RedactBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}

	var js any
	if err := json.Unmarshal(body, &js); err == nil {
		redacted := redactMapRecursive(js)
		b, err := json.Marshal(redacted)
		if err == nil {
			s := RedactText(string(b))
			if maxLen > 0 && len(s) > maxLen {
				return s[:maxLen] + " ... [TRUNCATED]"
			}
			return s
		}
	}

	s := RedactText(string(body))
	if maxLen > 0 && len(s) > maxLen {
		return s[:maxLen] + " ... [TRUNCATED]"
	}
	return s
}

func redactMapRecursive(v any) any {
	switch val := v.(type) {
	case map[string]any:
		out := make(map[string]any)
		for k, item := range val {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, "pass") || strings.Contains(lowerK, "secret") ||
				strings.Contains(lowerK, "token") || strings.Contains(lowerK, "key") ||
				strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "credit") ||
				strings.Contains(lowerK, "cookie") || strings.Contains(lowerK, "session") {
				out[k] = "[REDACTED]"
			} else {
				out[k] = redactMapRecursive(item)
			}
		}
		return out
	case []any:
		out := make([]any, len(val))
		for i, item := range val {
			out[i] = redactMapRecursive(item)
		}
		return out
	case string:
		return RedactText(val)
	default:
		return val
	}
}

// SanitizeURL strips query parameters and userInfo from URLs for safe reporting.
func SanitizeURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}
