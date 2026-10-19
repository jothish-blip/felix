package bopla

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"felix/pkg/auth"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// Category defines the BOPLA assessment categories aligned with OWASP API Security Top 10 (2023) API3:2023.
type Category string

const (
	CategoryBOPLAPropertyRead          Category = "BOPLA-PROPERTY-READ"
	CategoryBOPLAExcessiveExposure     Category = "BOPLA-EXCESSIVE-EXPOSURE"
	CategoryBOPLAPropertyWrite         Category = "BOPLA-PROPERTY-WRITE"
	CategoryBOPLAMassAssignment        Category = "BOPLA-MASS-ASSIGNMENT"
	CategoryBOPLARepresentationBypass  Category = "BOPLA-REPRESENTATION-BYPASS"
)

// ExpectedAccessRule defines expected accessibility for a property.
type ExpectedAccessRule string

const (
	ExpectedOmitted        ExpectedAccessRule = "OMITTED"
	ExpectedMasked         ExpectedAccessRule = "MASKED"
	ExpectedReadOnly       ExpectedAccessRule = "READ_ONLY"
	ExpectedImmutable      ExpectedAccessRule = "IMMUTABLE"
	ExpectedAuthorizedOnly ExpectedAccessRule = "AUTHORIZED_ONLY"
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

// CategoryMetadata maps all BOPLA categories to their authoritative metadata.
var CategoryMetadata = map[Category]CategoryInfo{
	CategoryBOPLAPropertyRead: {
		Code:                 "BOPLA-PROPERTY-READ",
		Name:                 "Unauthorized Read of Protected Object Properties",
		OWASP:                "API3:2023",
		CWE:                  "CWE-213",
		Description:          "Endpoint exposes sensitive or restricted object properties to an unauthorized lower-privilege identity.",
		VerificationBoundary: "Verified when a lower-privilege identity accesses an object and receives protected properties that policy designates as restricted or omitted. Status 200 alone or public properties do not verify.",
		Preconditions:        []string{"Authorized identity with property access", "Lower-privilege test identity", "Explicit property policy with designated restricted property", "Target API endpoint"},
	},
	CategoryBOPLAExcessiveExposure: {
		Code:                 "BOPLA-EXCESSIVE-EXPOSURE",
		Name:                 "Excessive Data Exposure of Sensitive Fields",
		OWASP:                "API3:2023",
		CWE:                  "CWE-213",
		Description:          "Endpoint returns sensitive properties in responses that should be masked or withheld according to policy or trusted baseline.",
		VerificationBoundary: "Verified when response contains unmasked sensitive data where policy requires omission or masking (e.g. cleartext PII, financial fields, internal identifiers).",
		Preconditions:        []string{"Baseline response containing property", "Expected masking or omission rule", "Lower-privilege identity context"},
	},
	CategoryBOPLAPropertyWrite: {
		Code:                 "BOPLA-PROPERTY-WRITE",
		Name:                 "Unauthorized Modification of Protected Object Properties",
		OWASP:                "API3:2023",
		CWE:                  "CWE-915",
		Description:          "Principal modifies restricted properties (e.g. role, ownership, account status, tenant identifier, or security settings) without authorization.",
		VerificationBoundary: "Requires explicit state-changing opt-in (--allow-state-changing) and confirmed synthetic test fixture. Verified only when independent read-back proves the unauthorized property was actually modified and persisted.",
		Preconditions:        []string{"Explicit state-changing opt-in", "Synthetic test fixture", "Lower-privilege test identity", "Protected property mutation definition", "Independent read-back verification"},
	},
	CategoryBOPLAMassAssignment: {
		Code:                 "BOPLA-MASS-ASSIGNMENT",
		Name:                 "Mass Assignment of Unauthorized Object Properties",
		OWASP:                "API3:2023",
		CWE:                  "CWE-915",
		Description:          "API endpoint binds request body parameters directly to internal object properties, allowing attackers to inject unauthorized fields.",
		VerificationBoundary: "Requires explicit state-changing opt-in and confirmed synthetic test fixture. Verified when injected unauthorized property is accepted and verified persisted via independent read-back. Echoed request body alone is insufficient.",
		Preconditions:        []string{"Explicit state-changing opt-in", "Synthetic test fixture", "Target endpoint with mass-assignment payload", "Independent read-back verification"},
	},
	CategoryBOPLARepresentationBypass: {
		Code:                 "BOPLA-REPRESENTATION-BYPASS",
		Name:                 "Property Authorization Bypass Across Representations",
		OWASP:                "API3:2023",
		CWE:                  "CWE-862",
		Description:          "Property-level restrictions are enforced on top-level properties but bypassed via nested objects, array wrappers, or alternate representations.",
		VerificationBoundary: "Verified when top-level property is restricted, but the same property is disclosed or modified through nested structures or alternate representations.",
		Preconditions:        []string{"Primary top-level property policy", "Nested or alternate representation structure", "Lower-privilege test identity"},
	},
}

// VerificationState represents the procedural verification status of a BOPLA test.
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

// TestIdentity defines an authenticated identity context used in BOPLA testing.
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
	tokenA := extractAuthToken(idA.Headers)
	tokenB := extractAuthToken(idB.Headers)
	if tokenA != "" && tokenB != "" && tokenA == tokenB {
		return false
	}
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

// PropertyPolicy defines the authorization rules and expectations for a specific object property.
type PropertyPolicy struct {
	PropertyID              string             `json:"property_id"`
	Name                    string             `json:"name"`
	Endpoint                string             `json:"endpoint"`
	Method                  string             `json:"method"` // e.g. "GET", "POST", "PUT", "PATCH"
	Category                Category           `json:"category"`
	PropertyPath            string             `json:"property_path"` // e.g. "role", "user.role", "account.status", "salary"
	SensitivityCategory     string             `json:"sensitivity_category,omitempty"` // e.g. "ADMIN_PRIVILEGE", "FINANCIAL", "PII", "TENANT_ISOLATION"
	ExpectedAccess          ExpectedAccessRule `json:"expected_access"` // OMITTED, MASKED, READ_ONLY, IMMUTABLE, AUTHORIZED_ONLY
	AllowedRoles            []string           `json:"allowed_roles"`   // Roles authorized to access this property (e.g. ["admin"])
	RestrictedRoles         []string           `json:"restricted_roles"`// Roles forbidden from accessing this property (e.g. ["user"])
	IsStateChanging         bool               `json:"is_state_changing"`
	MutationValue           any                `json:"mutation_value,omitempty"` // The value attempted in mutation (e.g. "admin", true, 9999)
	MutationPayload         string             `json:"mutation_payload,omitempty"` // Custom JSON body for mutation
	ReadBackEndpoint        string             `json:"read_back_endpoint,omitempty"` // Endpoint used to verify persistence
	ReadBackMethod          string             `json:"read_back_method,omitempty"` // Method for read-back (default: GET)
	MaskPattern             string             `json:"mask_pattern,omitempty"` // Substring or pattern expected if masked (e.g. "****")
	ProtectedResponseMarker string             `json:"protected_response_marker,omitempty"` // Substring proving disclosure
	PositiveControlRequired bool               `json:"positive_control_required"` // Whether authorized baseline must succeed first
}

// PolicyFile allows loading property authorization policies and test identities from a JSON file.
type PolicyFile struct {
	Version    string           `json:"version"`
	Policies   []PropertyPolicy `json:"policies"`
	Identities []TestIdentity   `json:"identities,omitempty"`
}

// PlannedTest represents a planned BOPLA test in dry-run or pre-assessment phase.
type PlannedTest struct {
	ID                string     `json:"id"`
	Category          Category   `json:"category"`
	Name              string     `json:"name"`
	OWASPRef          string     `json:"owasp_ref"`
	CWERef            string     `json:"cwe_ref"`
	Endpoint          string     `json:"endpoint"`
	Method            string     `json:"method"`
	PropertyPath      string     `json:"property_path"`
	ExpectedAccess    string     `json:"expected_access"`
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

// Result records the empirical outcome of an executed BOPLA test.
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
	PropertyPath      string            `json:"property_path"`
	ExpectedAccess    string            `json:"expected_access"`
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

// Summary aggregates BOPLA verification results across categories.
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

// AssessmentContext contains all contextual inputs for a BOPLA assessment run.
type AssessmentContext struct {
	AssessmentID            string
	ExecutionID             string
	BaseURL                 string
	Policies                []PropertyPolicy
	Identities              []TestIdentity
	AllowStateChangingTests bool
	SyntheticFixture        bool
	AuthorizedFixtureHosts  []string
	IsFixtureTarget         func(target string) bool
	DryRun                  bool
	MaxRequests             int
	DispatchedRequests      *int32
	Authorization           *auth.AuthorizationRecord
	IsAllowed               func(target string) bool
	IsExcluded              func(target string) bool
}

// Config controls engine execution parameters.
type Config struct {
	Timeout                 time.Duration
	MaxResponseBytes        int64
	AllowActiveTesting      bool
	AllowStateChangingTests bool
	MaxRequestsPerTest      int
}

// DefaultConfig provides safe default configuration.
func DefaultConfig() Config {
	return Config{
		Timeout:                 15 * time.Second,
		MaxResponseBytes:        2 * 1024 * 1024, // 2MB
		AllowActiveTesting:      false,
		AllowStateChangingTests: false,
		MaxRequestsPerTest:      5,
	}
}

// ResponseData captures empirical response details without logging secrets.
type ResponseData struct {
	StatusCode    int
	Header        map[string][]string
	Body          []byte
	ContentLength int64
	ExecutionTime time.Duration
}

// ComparisonResult encapsulates the outcome of differential property authorization analysis.
type ComparisonResult struct {
	State           VerificationState
	Severity        string
	Confidence      string
	EvidenceSummary string
	EvidenceDetails map[string]string
}

// DefaultPolicies provides baseline test policies covering all 5 BOPLA categories.
func DefaultPolicies() []PropertyPolicy {
	return []PropertyPolicy{
		{
			PropertyID:              "bopla-user-salary-read",
			Name:                    "Unauthorized Read of Sensitive Compensation Property",
			Endpoint:                "/api/users/profile",
			Method:                  "GET",
			Category:                CategoryBOPLAPropertyRead,
			PropertyPath:            "salary",
			SensitivityCategory:     "FINANCIAL",
			ExpectedAccess:          ExpectedOmitted,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			PositiveControlRequired: true,
			IsStateChanging:         false,
		},
		{
			PropertyID:              "bopla-profile-tenant-exposure",
			Name:                    "Excessive Data Exposure of Internal Tenant Identifier",
			Endpoint:                "/api/account/details",
			Method:                  "GET",
			Category:                CategoryBOPLAExcessiveExposure,
			PropertyPath:            "billing.tenant_id",
			SensitivityCategory:     "TENANT_ISOLATION",
			ExpectedAccess:          ExpectedMasked,
			MaskPattern:             "****",
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			PositiveControlRequired: true,
			IsStateChanging:         false,
		},
		{
			PropertyID:              "bopla-user-role-mutation",
			Name:                    "Unauthorized Modification of User Role Property",
			Endpoint:                "/api/users/profile",
			Method:                  "PUT",
			Category:                CategoryBOPLAPropertyWrite,
			PropertyPath:            "role",
			SensitivityCategory:     "ADMIN_PRIVILEGE",
			ExpectedAccess:          ExpectedImmutable,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			IsStateChanging:         true,
			MutationValue:           "admin",
			ReadBackEndpoint:        "/api/users/profile",
			ReadBackMethod:          "GET",
			PositiveControlRequired: true,
		},
		{
			PropertyID:              "bopla-registration-mass-assignment",
			Name:                    "Mass Assignment of Administrative Privilege Flag",
			Endpoint:                "/api/users/register",
			Method:                  "POST",
			Category:                CategoryBOPLAMassAssignment,
			PropertyPath:            "is_admin",
			SensitivityCategory:     "ADMIN_PRIVILEGE",
			ExpectedAccess:          ExpectedImmutable,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			IsStateChanging:         true,
			MutationValue:           true,
			ReadBackEndpoint:        "/api/users/me",
			ReadBackMethod:          "GET",
			PositiveControlRequired: true,
		},
		{
			PropertyID:              "bopla-nested-permissions-bypass",
			Name:                    "Property Restriction Bypass Across Nested Roles Representation",
			Endpoint:                "/api/users/permissions",
			Method:                  "GET",
			Category:                CategoryBOPLARepresentationBypass,
			PropertyPath:            "security.roles[0].level",
			SensitivityCategory:     "ADMIN_PRIVILEGE",
			ExpectedAccess:          ExpectedOmitted,
			AllowedRoles:            []string{"admin"},
			RestrictedRoles:         []string{"user"},
			PositiveControlRequired: true,
			IsStateChanging:         false,
		},
	}
}

// RedactValue safely masks sensitive property values for evidence presentation.
func RedactValue(val any) string {
	if val == nil {
		return "null"
	}
	s := fmt.Sprintf("%v", val)
	if len(s) <= 4 {
		return "****"
	}
	return s[:2] + "****" + s[len(s)-2:]
}

// BuildFindingID generates a deterministic finding ID.
func BuildFindingID(assessmentID, propertyID, category string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%s", assessmentID, propertyID, category)))
	return fmt.Sprintf("felix-bopla-%s", hex.EncodeToString(h[:8]))
}

// IsLoopbackHost returns whether a host is a loopback destination.
func IsLoopbackHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return h == "localhost" || h == "127.0.0.1" || h == "::1" || strings.HasPrefix(h, "127.")
}

// IsIsolatedFixtureTarget determines whether a target URL is bound to an authorized synthetic fixture
// or explicitly designated isolated test environment, preventing mutations against arbitrary production targets.
func IsIsolatedFixtureTarget(rawURL string, authorizedFixtures []string, isFixtureFunc func(string) bool) bool {
	if isFixtureFunc != nil && isFixtureFunc(rawURL) {
		return true
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	hostname := strings.ToLower(strings.TrimSpace(u.Hostname()))
	if hostname == "" {
		return false
	}

	// 1. Loopback addresses and local test harness fixtures
	if IsLoopbackHost(hostname) {
		return true
	}

	// 2. Safe local, test, or synthetic fixture domain suffixes
	fixtureSuffixes := []string{
		".local",
		".internal",
		".test",
		".example",
		".synthetic",
		".mock",
	}
	for _, suffix := range fixtureSuffixes {
		if strings.HasSuffix(hostname, suffix) {
			return true
		}
	}

	// 3. Explicitly configured authorized fixture hosts or patterns
	for _, af := range authorizedFixtures {
		clean := strings.ToLower(strings.TrimSpace(af))
		if clean == "" {
			continue
		}
		if strings.HasPrefix(clean, "*.") {
			suffix := clean[1:]
			if strings.HasSuffix(hostname, suffix) {
				return true
			}
		} else if strings.EqualFold(hostname, clean) {
			return true
		} else if parsedAF, err := url.Parse(af); err == nil && parsedAF.Hostname() != "" {
			if strings.EqualFold(hostname, parsedAF.Hostname()) {
				return true
			}
		}
	}

	return false
}

// EffectivePort returns the explicit or scheme-default port for a URL.
func EffectivePort(u *url.URL) string {
	if u == nil {
		return ""
	}
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	default:
		return ""
	}
}

// IsSameOrigin checks whether two URLs share the exact scheme, host, and effective port.
func IsSameOrigin(u1, u2 *url.URL) bool {
	if u1 == nil || u2 == nil {
		return false
	}
	if !strings.EqualFold(u1.Scheme, u2.Scheme) {
		return false
	}
	if !strings.EqualFold(u1.Hostname(), u2.Hostname()) {
		return false
	}
	return EffectivePort(u1) == EffectivePort(u2)
}

// SensitiveCredentialHeaders enumerates HTTP headers containing authentication credentials or session tokens.
var SensitiveCredentialHeaders = []string{
	"Authorization",
	"Cookie",
	"Cookie2",
	"X-Auth-Token",
	"X-API-Key",
	"X-Session-ID",
	"X-Session-Token",
	"X-CSRF-Token",
	"X-XSRF-Token",
	"Proxy-Authorization",
}

// StripSensitiveCredentials strips all sensitive authentication, token, and session headers from an HTTP request.
func StripSensitiveCredentials(req *http.Request) {
	if req == nil || req.Header == nil {
		return
	}
	for _, h := range SensitiveCredentialHeaders {
		req.Header.Del(h)
	}
}

// RedactText removes credentials, tokens, session IDs, passwords, and private secrets from text.
func RedactText(input string) string {
	return secrets.RedactText(input)
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

// ResolveURL combines baseURL and policy path safely.
func ResolveURL(base, path string) (string, error) {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path, nil
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	rel, err := url.Parse(path)
	if err != nil {
		return "", err
	}
	return u.ResolveReference(rel).String(), nil
}
