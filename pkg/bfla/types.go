package bfla

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"

	"felix/pkg/auth"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Category defines the BFLA assessment categories aligned with OWASP API Security Top 10 (2023).
type Category string

const (
	CategoryBFLAAdminEndpoint       Category = "BFLA-ADMIN-ENDPOINT"
	CategoryBFLAPrivilegeEscalation Category = "BFLA-PRIVILEGE-ESCALATION"
	CategoryBFLAMethodBypass        Category = "BFLA-METHOD-BYPASS"
	CategoryBFLAWriteMutation       Category = "BFLA-WRITE-MUTATION"
)

// CategoryInfo provides authoritative metadata, security boundaries, and preconditions for each category.
type CategoryInfo struct {
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	OWASP                string   `json:"owasp"`
	CWE                  string   `json:"cwe"`
	Description          string   `json:"description"`
	VerificationBoundary string   `json:"verification_boundary"`
	Preconditions        []string `json:"preconditions"`
}

// CategoryMetadata maps all BFLA categories to their authoritative metadata.
var CategoryMetadata = map[Category]CategoryInfo{
	CategoryBFLAAdminEndpoint: {
		Code:                 "BFLA-ADMIN-ENDPOINT",
		Name:                 "Lower-Privilege Role Accesses Admin-Only Endpoint",
		OWASP:                "API5:2023",
		CWE:                  "CWE-285",
		Description:          "Endpoint allows lower-privilege or standard users to access administrative/privileged functions.",
		VerificationBoundary: "Verified when lower-privilege identity accesses function restricted by policy to admin roles and receives matching protected response or administrative data. Status 200 alone, public static responses, or generic error/login pages are NOT verified.",
		Preconditions:        []string{"Privileged role (e.g. admin) identity", "Lower-privilege role identity", "Explicit function policy or role definition", "Protected administrative endpoint"},
	},
	CategoryBFLAPrivilegeEscalation: {
		Code:                 "BFLA-PRIVILEGE-ESCALATION",
		Name:                 "Principal Invokes Function Exceeding Assigned Privilege Level",
		OWASP:                "API5:2023",
		CWE:                  "CWE-269",
		Description:          "A principal with lower privilege level executes an operation requiring a strictly higher privilege level in the role hierarchy.",
		VerificationBoundary: "Verified when principal with privilege level below required threshold executes privileged function confirmed by protected execution marker or privileged output.",
		Preconditions:        []string{"Hierarchical privilege levels defined", "Lower-privilege principal context", "Higher-privilege target function"},
	},
	CategoryBFLAMethodBypass: {
		Code:                 "BFLA-METHOD-BYPASS",
		Name:                 "Function Authorization Inconsistently Enforced Across HTTP Methods",
		OWASP:                "API5:2023",
		CWE:                  "CWE-648",
		Description:          "Function authorization is enforced on one HTTP method (e.g., POST/GET) but missing on alternate methods (e.g., PUT/DELETE/GET/HEAD/OPTIONS).",
		VerificationBoundary: "Verified when restricted method is properly protected (401/403) but alternate method successfully executes the privileged function for a lower-privilege identity.",
		Preconditions:        []string{"Protected endpoint with method-specific authorization", "Alternative HTTP methods supported", "Lower-privilege test identity"},
	},
	CategoryBFLAWriteMutation: {
		Code:                 "BFLA-WRITE-MUTATION",
		Name:                 "Read-Only or Lower-Privilege Role Executes Privileged Mutation",
		OWASP:                "API5:2023",
		CWE:                  "CWE-285",
		Description:          "Lower-privilege or read-only identity executes privileged state-altering operations (POST, PUT, PATCH, DELETE).",
		VerificationBoundary: "Requires explicit test policy and opt-in (--allow-state-changing). Verified when state-changing function successfully executes and mutates state on synthetic test fixtures.",
		Preconditions:        []string{"Explicit state-changing opt-in (--allow-state-changing)", "Synthetic test fixture", "Lower-privilege test identity"},
	},
}

// VerificationState represents the procedural verification status of a BFLA test.
type VerificationState string

const (
	StateVerified      VerificationState = "VERIFIED"
	StateCandidate     VerificationState = "CANDIDATE"
	StateNotVulnerable VerificationState = "NOT_VULNERABLE"
	StateInconclusive  VerificationState = "INCONCLUSIVE"
	StateSkipped       VerificationState = "SKIPPED"
)

// CoverageStatus represents the assessment status for a category.
type CoverageStatus string

const (
	CoverageUntested             CoverageStatus = "UNTESTED"
	CoverageActivelyTested       CoverageStatus = "ACTIVELY_TESTED"
	CoverageVerifiedIssueFound   CoverageStatus = "VERIFIED_ISSUE_FOUND"
	CoverageCandidateIdentified  CoverageStatus = "CANDIDATE_IDENTIFIED"
	CoverageBlockedMissingPrereq CoverageStatus = "BLOCKED_MISSING_PREREQUISITES"
	CoverageNotApplicable        CoverageStatus = "NOT_APPLICABLE"
)

// PlanStatus defines the planning state of an individual test.
type PlanStatus string

const (
	PlanReady   PlanStatus = "READY"
	PlanBlocked PlanStatus = "BLOCKED"
	PlanSkipped PlanStatus = "SKIPPED"
)

// TestIdentity defines an authenticated identity context used in multi-role BFLA testing.
type TestIdentity struct {
	Alias          string            `json:"alias"` // e.g. "admin_user", "standard_user", "viewer_user"
	Role           string            `json:"role,omitempty"`
	TenantID       string            `json:"tenant_id,omitempty"`
	PrivilegeLevel int               `json:"privilege_level,omitempty"` // higher = more privileged (e.g. 5=admin, 1=user)
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
}

// AreIdentitiesDistinct verifies whether two identities have distinct authentication contexts.
func AreIdentitiesDistinct(idA, idB TestIdentity) bool {
	if idA.Alias != "" && idB.Alias != "" && strings.EqualFold(idA.Alias, idB.Alias) {
		return false
	}
	if idA.Username != "" && idB.Username != "" && strings.EqualFold(idA.Username, idB.Username) {
		return false
	}
	// Check auth headers
	tokenA := extractAuthToken(idA.Headers)
	tokenB := extractAuthToken(idB.Headers)
	if tokenA != "" && tokenB != "" && tokenA == tokenB {
		return false
	}
	// Check session cookies
	cookieA := extractSessionCookie(idA.Cookies)
	cookieB := extractSessionCookie(idB.Cookies)
	if cookieA != "" && cookieB != "" && cookieA == cookieB {
		return false
	}
	return true
}

func extractAuthToken(headers map[string]string) string {
	if headers == nil {
		return ""
	}
	for k, v := range headers {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "x-auth-token" || lk == "x-api-key" || lk == "x-session-token" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func extractSessionCookie(cookies map[string]string) string {
	if cookies == nil {
		return ""
	}
	for k, v := range cookies {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "sess") || strings.Contains(lk, "auth") || strings.Contains(lk, "jwt") || strings.Contains(lk, "token") {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// FunctionPolicy defines the authorization rules and expectations for a protected endpoint function.
type FunctionPolicy struct {
	FunctionID              string   `json:"function_id"`
	Name                    string   `json:"name"`
	Path                    string   `json:"path"`
	Method                  string   `json:"method"` // e.g. "GET", "POST", "PUT", "DELETE", "PATCH", "*"
	Category                Category `json:"category"`
	AllowedRoles            []string `json:"allowed_roles"`             // Roles authorized to execute this function (e.g. ["admin", "superadmin"])
	RestrictedRoles         []string `json:"restricted_roles"`          // Roles forbidden from executing this function (e.g. ["user", "viewer", "guest"])
	RequiredPrivilegeLevel  int      `json:"required_privilege_level"`  // Minimum privilege level required (e.g. 5)
	ProtectedResponseMarker string   `json:"protected_response_marker"` // Substring proving successful execution of privileged function
	PositiveControlRequired bool     `json:"positive_control_required"` // Whether positive control (admin access) must succeed first
	IsStateChanging         bool     `json:"is_state_changing"`
	Payload                 string   `json:"payload,omitempty"` // Optional request body for POST/PUT/PATCH
}

// PolicyFile allows loading function authorization policies and test identities from a JSON file.
type PolicyFile struct {
	Version    string           `json:"version"`
	Policies   []FunctionPolicy `json:"policies"`
	Identities []TestIdentity   `json:"identities,omitempty"`
}

// PlannedTest represents a planned BFLA test in dry-run or pre-assessment phase.
type PlannedTest struct {
	ID                string     `json:"id"`
	Category          Category   `json:"category"`
	Name              string     `json:"name"`
	OWASPRef          string     `json:"owasp_ref"`
	CWERef            string     `json:"cwe_ref"`
	Endpoint          string     `json:"endpoint"`
	Method            string     `json:"method"`
	AllowedRole       string     `json:"allowed_role"`
	TestedRole        string     `json:"tested_role"`
	TestedAlias       string     `json:"tested_alias"`
	IsStateChanging   bool       `json:"is_state_changing"`
	SecurityObjective string     `json:"security_objective"`
	Preconditions     []string   `json:"preconditions"`
	Status            PlanStatus `json:"status"`
	BlockedReason     string     `json:"blocked_reason,omitempty"`
}

// TestPlan aggregates planned tests and requirements.
type TestPlan struct {
	AssessmentID       string        `json:"assessment_id"`
	TargetURL          string        `json:"target_url"`
	GeneratedAt        time.Time     `json:"generated_at"`
	TotalTests         int           `json:"total_tests"`
	ActiveTests        int           `json:"active_tests"`
	StateChangingTests int           `json:"state_changing_tests"`
	ReadyTests         int           `json:"ready_tests"`
	BlockedTests       int           `json:"blocked_tests"`
	Tests              []PlannedTest `json:"tests"`
}

// Result records the empirical outcome of an executed BFLA test.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          Category          `json:"category"`
	VulnCode          string            `json:"vuln_code"`
	TestID            string            `json:"test_id"`
	TestName          string            `json:"test_name"`
	OWASPRef          string            `json:"owasp_ref"`
	CWERef            string            `json:"cwe_ref"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	RequiredRole      string            `json:"required_role"`
	AccessorRole      string            `json:"accessor_role"`
	AccessorAlias     string            `json:"accessor_alias"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	ObservedStatus    int               `json:"observed_status,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// CategoryCoverage summarizes test statistics and findings for one category.
type CategoryCoverage struct {
	Category     Category       `json:"category"`
	Code         string         `json:"code"`
	Name         string         `json:"name"`
	OWASPRef     string         `json:"owasp_ref"`
	Status       CoverageStatus `json:"status"`
	TestsRun     int            `json:"tests_run"`
	Verified     int            `json:"verified"`
	Candidates   int            `json:"candidates"`
	Inconclusive int            `json:"inconclusive"`
	Blocked      int            `json:"blocked"`
	Explanation  string         `json:"explanation"`
}

// Summary aggregates BFLA verification results across categories.
type Summary struct {
	TotalTests         int                         `json:"total_tests"`
	CategoriesCovered  int                         `json:"categories_covered"`
	VerifiedCount      int                         `json:"verified_count"`
	CandidateCount     int                         `json:"candidate_count"`
	NotVulnerableCount int                         `json:"not_vulnerable_count"`
	InconclusiveCount  int                         `json:"inconclusive_count"`
	BlockedCount       int                         `json:"blocked_count"`
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
	NotVulnerableCount int       `json:"not_vulnerable_count"`
	InconclusiveCount  int       `json:"inconclusive_count"`
	BlockedCount       int       `json:"blocked_count"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// AssessmentContext contains all contextual inputs for a BFLA assessment run.
type AssessmentContext struct {
	AssessmentID            string
	ExecutionID             string
	BaseURL                 string
	Policies                []FunctionPolicy
	Identities              []TestIdentity
	IsAllowed               func(string) bool
	IsExcluded              func(string) bool
	SyntheticFixture        bool
	AllowStateChangingTests bool
	DryRun                  bool
	Authorization           *auth.AuthorizationRecord
	MaxRequests             int
	DispatchedRequests      *int32
}

// Config defines the runtime configuration for the BFLA Verification Engine.
type Config struct {
	Timeout                 time.Duration `json:"timeout"`
	Concurrency             int           `json:"concurrency"`
	MaxBodyReadBytes        int64         `json:"max_body_read_bytes"`
	UserAgent               string        `json:"user_agent"`
	AllowActiveTesting      bool          `json:"allow_active_testing"`
	AllowStateChangingTests bool          `json:"allow_state_changing_tests"`
}

// DefaultConfig provides conservative, safe defaults for the BFLA Engine.
func DefaultConfig() Config {
	return Config{
		Timeout:                 10 * time.Second,
		Concurrency:             3,
		MaxBodyReadBytes:        1 * 1024 * 1024, // 1MB bounded read
		UserAgent:               "Felix/2.0 (Authorized Security Assessment; BFLA-Engine)",
		AllowActiveTesting:      true,
		AllowStateChangingTests: false, // strictly requires explicit opt-in
	}
}

// RedactText removes credentials, tokens, session IDs, passwords, and private secrets from text.
func RedactText(input string) string {
	return secrets.RedactText(input)
}

// HashSecret produces a safe, non-reversible SHA-256 fingerprint (first 8 hex characters)
// for verifying secret equality or reference without disclosing the actual secret.
func HashSecret(secret string) string {
	if secret == "" {
		return "empty"
	}
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:4]))
}

// SanitizeURL removes query parameters and userinfo from URLs for safe logging.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return secrets.SanitizeURL(rawURL)
	}
	u.RawQuery = ""
	u.User = nil
	return u.String()
}
