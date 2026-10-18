package bola

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

// Category defines the BOLA/IDOR assessment categories aligned with OWASP API Security Top 10 (2023).
type Category string

const (
	CategoryBOLAUserRead      Category = "BOLA-USER-READ"
	CategoryBOLATenantRead    Category = "BOLA-TENANT-READ"
	CategoryBOLACollection    Category = "BOLA-COLLECTION"
	CategoryBOLAWriteMutation Category = "BOLA-WRITE-MUTATION"
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

// CategoryMetadata maps all BOLA categories to their authoritative metadata.
var CategoryMetadata = map[Category]CategoryInfo{
	CategoryBOLAUserRead: {
		Code:                 "BOLA-USER-READ",
		Name:                 "Unauthorized Cross-User Object Read",
		OWASP:                "API1:2023",
		CWE:                  "CWE-639",
		Description:          "Endpoint allows User A to read User B's private object without proper authorization enforcement.",
		VerificationBoundary: "Verified only when non-owner accessing owner's object ID receives matching protected object representation. Status 200 alone, public static responses, or generic error/login pages are NOT verified.",
		Preconditions:        []string{"Two distinct authenticated identities (User A, User B)", "Owner-assigned object identifier", "Protected resource endpoint"},
	},
	CategoryBOLATenantRead: {
		Code:                 "BOLA-TENANT-READ",
		Name:                 "Cross-Tenant Object Isolation Failure",
		OWASP:                "API1:2023",
		CWE:                  "CWE-639",
		Description:          "Endpoint allows a principal from Tenant A to read resources belonging to Tenant B.",
		VerificationBoundary: "Verified when a principal from Tenant A successfully retrieves objects explicitly scoped to Tenant B with matching tenant data.",
		Preconditions:        []string{"Two distinct tenant identities", "Tenant-scoped object identifier", "Multi-tenant endpoint"},
	},
	CategoryBOLACollection: {
		Code:                 "BOLA-COLLECTION",
		Name:                 "Collection Object Level Authorization Leakage",
		OWASP:                "API1:2023",
		CWE:                  "CWE-639",
		Description:          "Collection, list, or search endpoint returns objects or records belonging to other tenants or users.",
		VerificationBoundary: "Verified when a collection query executed by User A includes private objects owned exclusively by User B.",
		Preconditions:        []string{"Two distinct test identities", "Private objects registered to User B", "Collection endpoint"},
	},
	CategoryBOLAWriteMutation: {
		Code:                 "BOLA-WRITE-MUTATION",
		Name:                 "Unauthorized Object Mutation or Deletion",
		OWASP:                "API1:2023",
		CWE:                  "CWE-639",
		Description:          "Endpoint allows a non-owner to modify (PUT, POST, PATCH) or delete (DELETE) another principal's object.",
		VerificationBoundary: "Requires explicit test policy and opt-in (--allow-state-changing). Verified when non-owner request mutates owner's designated test object, confirmed by state verification. Read-only by default.",
		Preconditions:        []string{"Two distinct identities", "Designated synthetic mutable object", "Explicit write opt-in"},
	},
}

// VerificationState represents the procedural verification status of a BOLA test.
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

// TestIdentity defines an authenticated identity context used in dual-identity BOLA testing.
type TestIdentity struct {
	Alias          string            `json:"alias"` // e.g. "user_a", "user_b", "tenant_a_user"
	Role           string            `json:"role,omitempty"`
	TenantID       string            `json:"tenant_id,omitempty"`
	PrivilegeLevel int               `json:"privilege_level,omitempty"`
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

// ObjectIdentifier models a reference to a protected object, its location, and owner.
type ObjectIdentifier struct {
	ID            string `json:"id"`
	Type          string `json:"type,omitempty"` // "user", "order", "document", "record", etc.
	Location      string `json:"location"`       // "path", "query", "body"
	ParamName     string `json:"param_name"`     // e.g. "id", "userId", "order_id"
	OwnerIdentity string `json:"owner_identity"` // Alias of owner identity (e.g. "user_b")
	TenantID      string `json:"tenant_id,omitempty"`
	ProtectedData string `json:"protected_data,omitempty"` // Known protected field or marker
}

// EndpointTemplate describes an endpoint surface evaluated for BOLA.
type EndpointTemplate struct {
	Method          string   `json:"method"`       // "GET", "PUT", "POST", "PATCH", "DELETE"
	PathPattern     string   `json:"path_pattern"` // e.g. "/api/users/{id}" or "/api/orders"
	Params          []string `json:"params,omitempty"`
	IsCollection    bool     `json:"is_collection,omitempty"`
	IsStateChanging bool     `json:"is_state_changing,omitempty"`
}

// PlannedTest represents a planned BOLA test in dry-run or pre-assessment phase.
type PlannedTest struct {
	ID                string   `json:"id"`
	Category          Category `json:"category"`
	Name              string   `json:"name"`
	OWASPRef          string   `json:"owasp_ref"`
	CWERef            string   `json:"cwe_ref"`
	Endpoint          string   `json:"endpoint"`
	Method            string   `json:"method"`
	ObjectID          string   `json:"object_id"`
	OwnerAlias        string   `json:"owner_alias"`
	AccessorAlias     string   `json:"accessor_alias"`
	IsStateChanging   bool     `json:"is_state_changing"`
	SecurityObjective string   `json:"security_objective"`
	Preconditions     []string `json:"preconditions"`
	Status            PlanStatus `json:"status"`
	BlockedReason     string   `json:"blocked_reason,omitempty"`
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

// Result records the empirical outcome of an executed BOLA test.
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
	ObjectID          string            `json:"object_id"`
	OwnerAlias        string            `json:"owner_alias"`
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

// Summary aggregates BOLA verification results across categories.
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

// AssessmentContext contains all contextual inputs for a BOLA assessment run.
type AssessmentContext struct {
	AssessmentID            string
	ExecutionID             string
	BaseURL                 string
	Endpoints               []EndpointTemplate
	Identities              []TestIdentity
	Objects                 []ObjectIdentifier
	IsAllowed               func(string) bool
	IsExcluded              func(string) bool
	SyntheticFixture        bool
	AllowStateChangingTests bool
	DryRun                  bool
	Authorization           *auth.AuthorizationRecord
	MaxRequests             int
	DispatchedRequests      *int32
}

// Config defines the runtime configuration for the BOLA Verification Engine.
type Config struct {
	Timeout                 time.Duration `json:"timeout"`
	Concurrency             int           `json:"concurrency"`
	MaxBodyReadBytes        int64         `json:"max_body_read_bytes"`
	UserAgent               string        `json:"user_agent"`
	AllowActiveTesting      bool          `json:"allow_active_testing"`
	AllowStateChangingTests bool          `json:"allow_state_changing_tests"`
}

// DefaultConfig provides conservative, safe defaults for the BOLA Engine.
func DefaultConfig() Config {
	return Config{
		Timeout:                 10 * time.Second,
		Concurrency:             3,
		MaxBodyReadBytes:        1 * 1024 * 1024, // 1MB bounded read
		UserAgent:               "Felix/2.0 (Authorized Security Assessment; BOLA-Engine)",
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
