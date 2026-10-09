package apisec

import (
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/report"
)

// OWASPCategory identifies one of the OWASP API Security Top 10 (2023) categories.
type OWASPCategory string

const (
	CategoryAPI1_BOLA                 OWASPCategory = "API1_BOLA"
	CategoryAPI2_BrokenAuth           OWASPCategory = "API2_BROKEN_AUTHENTICATION"
	CategoryAPI3_BOPLA                OWASPCategory = "API3_BOPLA"
	CategoryAPI4_ResourceConsumption  OWASPCategory = "API4_RESOURCE_CONSUMPTION"
	CategoryAPI5_BFLA                 OWASPCategory = "API5_BFLA"
	CategoryAPI6_BusinessFlows        OWASPCategory = "API6_BUSINESS_FLOWS"
	CategoryAPI7_SSRF                 OWASPCategory = "API7_SSRF"
	CategoryAPI8_Misconfiguration     OWASPCategory = "API8_MISCONFIGURATION"
	CategoryAPI9_ImproperInventory    OWASPCategory = "API9_IMPROPER_INVENTORY"
	CategoryAPI10_UnsafeConsumption   OWASPCategory = "API10_UNSAFE_CONSUMPTION"
)

// CategoryInfo provides metadata for an OWASP API category.
type CategoryInfo struct {
	Code        string `json:"code"`        // e.g. "API1:2023"
	Name        string `json:"name"`        // e.g. "Broken Object Level Authorization"
	Description string `json:"description"`
}

// OWASPCategoryMetadata maps each internal category to official OWASP Top 10 (2023) definitions.
var OWASPCategoryMetadata = map[OWASPCategory]CategoryInfo{
	CategoryAPI1_BOLA: {
		Code:        "API1:2023",
		Name:        "Broken Object Level Authorization",
		Description: "Object-level access control failure allowing unauthorized access to resources of other users or tenants.",
	},
	CategoryAPI2_BrokenAuth: {
		Code:        "API2:2023",
		Name:        "Broken Authentication",
		Description: "Authentication mechanisms implemented incorrectly, exposing endpoints to unauthenticated or compromised access.",
	},
	CategoryAPI3_BOPLA: {
		Code:        "API3:2023",
		Name:        "Broken Object Property Level Authorization",
		Description: "Unauthorized exposure or modification of sensitive object properties (excessive exposure or mass assignment).",
	},
	CategoryAPI4_ResourceConsumption: {
		Code:        "API4:2023",
		Name:        "Unrestricted Resource Consumption",
		Description: "Lack of rate limiting, unbounded page sizes, or request complexity leading to resource exhaustion.",
	},
	CategoryAPI5_BFLA: {
		Code:        "API5:2023",
		Name:        "Broken Function Level Authorization",
		Description: "Failure to enforce administrative or role-restricted permissions at the function/operation level.",
	},
	CategoryAPI6_BusinessFlows: {
		Code:        "API6:2023",
		Name:        "Unrestricted Access to Sensitive Business Flows",
		Description: "Exposing business workflows without anti-automation or abuse mitigations (e.g. mass registration, bulk action).",
	},
	CategoryAPI7_SSRF: {
		Code:        "API7:2023",
		Name:        "Server-Side Request Forgery",
		Description: "API fetches remote resources from user-supplied URLs without adequate destination validation.",
	},
	CategoryAPI8_Misconfiguration: {
		Code:        "API8:2023",
		Name:        "Security Misconfiguration",
		Description: "Insecure default settings, permissive CORS, unhandled HTTP methods, verbose error disclosures, or exposed docs.",
	},
	CategoryAPI9_ImproperInventory: {
		Code:        "API9:2023",
		Name:        "Improper Inventory Management",
		Description: "Undocumented, shadow, legacy, or deprecated API endpoints exposed to the public internet.",
	},
	CategoryAPI10_UnsafeConsumption: {
		Code:        "API10:2023",
		Name:        "Unsafe Consumption of APIs",
		Description: "Blind trust in third-party or partner API responses without proper validation or transport security.",
	},
}

// VerificationState represents the empirical verification state of an API security test.
// Rationale & Evidence Criteria:
// - StateObserved: A condition, endpoint, configuration, or architectural pattern was identified.
//   No demonstrated security control failure, unauthorized access, or vulnerability exists.
// - StateCandidate: Evidence suggests a potential security issue or missing defense-in-depth control,
//   but weakness or exploitability is not established under current testing context.
// - StateVerified: Empirical evidence directly demonstrates that a security control failed,
//   unauthorized access occurred, or a vulnerability exists under tested conditions.
// - StateInconclusive: Available responses or network telemetry are ambiguous or indeterminate.
// - StateNotVulnerable: The specific tested scenario demonstrated expected defensive enforcement.
type VerificationState string

const (
	StateObserved        VerificationState = "OBSERVED"
	StateCandidate       VerificationState = "CANDIDATE"
	StateVerified        VerificationState = "VERIFIED"
	StateInconclusive    VerificationState = "INCONCLUSIVE"
	StateNotVulnerable   VerificationState = "NOT_VULNERABLE"
)

// CoverageStatus describes the testing status of an OWASP category.
type CoverageStatus string

const (
	CoverageUntested           CoverageStatus = "UNTESTED"
	CoveragePassivelyAssessed  CoverageStatus = "PASSIVELY_ASSESSED"
	CoverageActivelyTested     CoverageStatus = "ACTIVELY_TESTED"
	CoverageVerifiedIssueFound CoverageStatus = "VERIFIED_VULNERABILITY_FOUND"
	CoveragePrereqMissing      CoverageStatus = "PREREQUISITE_MISSING"
)

// CategoryCoverage records the coverage and findings count for a specific OWASP category.
type CategoryCoverage struct {
	Category     OWASPCategory  `json:"category"`
	Code         string         `json:"code"`
	Name         string         `json:"name"`
	Status       CoverageStatus `json:"status"`
	TestsRun     int            `json:"tests_run"`
	Verified     int            `json:"verified_findings"`
	Candidates   int            `json:"candidate_findings"`
	Observations int            `json:"observed_findings"`
	Explanation  string         `json:"explanation"`
}

// Result records an individual test evaluation outcome within the API security engine.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          OWASPCategory     `json:"category"`
	OWASPCode         string            `json:"owasp_code"`
	TestName          string            `json:"test_name"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	ObservedStatus    int               `json:"observed_status,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	CorrelatedID      string            `json:"correlated_finding_id,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// Summary aggregates API security assessment coverage, findings, and metrics.
type Summary struct {
	TotalTests         int                         `json:"total_tests"`
	CategoriesCovered   int                         `json:"categories_covered"`
	VerifiedCount      int                         `json:"verified_count"`
	CandidateCount     int                         `json:"candidate_count"`
	ObservedCount      int                         `json:"observed_count"`
	InconclusiveCount  int                         `json:"inconclusive_count"`
	NotVulnerableCount int                         `json:"not_vulnerable_count"`
	CoverageMap        map[string]CategoryCoverage `json:"coverage"`
}

// Config specifies runtime parameters for the API security engine.
type Config struct {
	Timeout            time.Duration
	Concurrency        int
	MaxRequestsPerTest int
	AllowWriteTests    bool
	SpecPath           string // Optional path to declared API spec/schema
	CanaryCallbackURL  string // Approved callback destination for SSRF canary verification
}

// DefaultConfig returns safe default configuration for API security testing.
func DefaultConfig() Config {
	return Config{
		Timeout:            10 * time.Second,
		Concurrency:        5,
		MaxRequestsPerTest: 10,
		AllowWriteTests:    false, // Fail-safe default
	}
}

// RunRecord represents persistent execution metadata for an API security assessment run.
type RunRecord struct {
	ID                 string    `json:"id"`
	AssessmentID       string    `json:"assessment_id"`
	ExecutionID        string    `json:"execution_id"`
	TotalTests         int       `json:"total_tests"`
	CategoriesAssessed int       `json:"categories_assessed"`
	VerifiedCount      int       `json:"verified_count"`
	CandidateCount     int       `json:"candidate_count"`
	ObservedCount      int       `json:"observed_count,omitempty"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// SanitizeHeaders strips sensitive auth tokens and passwords from HTTP headers.
func SanitizeHeaders(h http.Header) map[string]string {
	out := make(map[string]string)
	if h == nil {
		return out
	}
	sensitive := map[string]struct{}{
		"authorization": {}, "cookie": {}, "set-cookie": {}, "x-api-key": {},
		"api-key": {}, "x-auth-token": {}, "x-session-id": {}, "token": {},
	}
	for k, vv := range h {
		lower := strings.ToLower(k)
		if _, ok := sensitive[lower]; ok || strings.Contains(lower, "auth") || strings.Contains(lower, "token") || strings.Contains(lower, "secret") {
			out[k] = "[REDACTED]"
		} else {
			out[k] = strings.Join(vv, ", ")
		}
	}
	return out
}

// SanitizeURL scrubs sensitive query parameter values from URL strings.
func SanitizeURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	q := parsed.Query()
	if len(q) == 0 {
		return rawURL
	}
	modified := false
	for k := range q {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "pass") || strings.Contains(lower, "key") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "session") {
			q.Set(k, "[REDACTED]")
			modified = true
		}
	}
	if modified {
		parsed.RawQuery = q.Encode()
		return parsed.String()
	}
	return rawURL
}

var secretJSONPattern = regexp.MustCompile(`(?i)"(password|passwd|secret|token|access_token|refresh_token|api_key|credit_card|cvv)"\s*:\s*"[^"]*"`)

// RedactBody sanitizes JSON bodies and truncates length for safe evidence presentation.
func RedactBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}
	var js any
	if err := json.Unmarshal(body, &js); err == nil {
		redacted := redactMapRecursive(js)
		b, err := json.Marshal(redacted)
		if err == nil {
			s := string(b)
			if maxLen > 0 && len(s) > maxLen {
				return s[:maxLen] + " ... [TRUNCATED]"
			}
			return s
		}
	}
	s := secretJSONPattern.ReplaceAllString(string(body), `"$1":"[REDACTED]"`)
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
				strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "credit") {
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
	default:
		return val
	}
}
