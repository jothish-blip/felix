package sessionsec

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/report"
)

// SessionCategory defines the 11 OWASP WSTG-aligned session and identity security categories.
type SessionCategory string

const (
	CategorySessionFixation        SessionCategory = "SESSION_FIXATION"
	CategoryCookieSecurity         SessionCategory = "COOKIE_SECURITY"
	CategorySessionInvalidation    SessionCategory = "SESSION_INVALIDATION"
	CategoryAuthStateInconsistency SessionCategory = "AUTH_STATE_INCONSISTENCY"
	CategoryTokenHandling          SessionCategory = "TOKEN_HANDLING"
	CategoryPrivilegeTransitions   SessionCategory = "PRIVILEGE_TRANSITIONS"
	CategoryLogoutBehavior         SessionCategory = "LOGOUT_BEHAVIOR"
	CategoryPasswordRecovery       SessionCategory = "PASSWORD_RECOVERY"
	CategoryAccountEnumeration     SessionCategory = "ACCOUNT_ENUMERATION"
	CategorySessionPuzzling        SessionCategory = "SESSION_PUZZLING"
	CategorySessionIsolation       SessionCategory = "SESSION_ISOLATION"
)

// CategoryInfo provides authoritative metadata and boundaries for each category.
type CategoryInfo struct {
	Code                 string   `json:"code"`
	Name                 string   `json:"name"`
	WSTG                 string   `json:"wstg"`
	CWE                  string   `json:"cwe"`
	Description          string   `json:"description"`
	VerificationBoundary string   `json:"verification_boundary"`
	Preconditions        []string `json:"preconditions"`
}

// CategoryMetadata maps all 11 session security categories to authoritative metadata.
var CategoryMetadata = map[SessionCategory]CategoryInfo{
	CategorySessionFixation: {
		Code:                 "SS-FIXATION",
		Name:                 "Session Fixation",
		WSTG:                 "WSTG-SESS-03",
		CWE:                  "CWE-384",
		Description:          "Application fails to renew session identifiers across authentication transitions, allowing session adoption.",
		VerificationBoundary: "Verified only when pre-authentication session identifier remains active and bound to the authenticated identity post-login. Distinct anonymous/auth cookies or safe token rotation is NOT_VULNERABLE. In-memory comparison only; zero raw tokens persisted.",
		Preconditions:        []string{"Valid test account credentials", "Login endpoint", "Pre-login session state"},
	},
	CategoryCookieSecurity: {
		Code:                 "SS-COOKIE",
		Name:                 "Insecure Cookie & Session Token Properties",
		WSTG:                 "WSTG-SESS-02",
		CWE:                  "CWE-614",
		Description:          "Session cookies or tokens lack critical security flags (Secure, HttpOnly, SameSite) or are exposed in URLs.",
		VerificationBoundary: "Missing flags on authenticated session cookies are classified as CANDIDATE or OBSERVED based on transport and context. Exposure of active session tokens in URLs is VERIFIED. Non-session cookies without flags remain OBSERVED.",
		Preconditions:        []string{"Target endpoint issuing cookies or tokens"},
	},
	CategorySessionInvalidation: {
		Code:                 "SS-INVALIDATION",
		Name:                 "Session Invalidation & Timeout",
		WSTG:                 "WSTG-SESS-06",
		CWE:                  "CWE-613",
		Description:          "Server fails to invalidate session state upon logout, timeout, or security transitions, allowing session replay.",
		VerificationBoundary: "Verified only when a previously valid session continues to successfully access protected resources after server-side invalidation event. Client-side cookie deletion alone does not constitute invalidation.",
		Preconditions:        []string{"Valid test session", "Protected test resource", "Invalidation trigger (logout/expire)"},
	},
	CategoryAuthStateInconsistency: {
		Code:                 "SS-AUTHSTATE",
		Name:                 "Authentication-State Inconsistencies",
		WSTG:                 "WSTG-ATHN-01",
		CWE:                  "CWE-287",
		Description:          "Inconsistencies between identity state, session tokens, and access-control enforcement allow unauthorized operations.",
		VerificationBoundary: "Verified when unauthenticated or expired requests successfully retrieve protected resources, or conflicting session tokens bypass boundary. Ambiguous HTTP statuses remain CANDIDATE.",
		Preconditions:        []string{"Protected endpoint", "Test identity credentials"},
	},
	CategoryTokenHandling: {
		Code:                 "SS-TOKEN",
		Name:                 "Token Handling & Lifetime Security",
		WSTG:                 "WSTG-SESS-04",
		CWE:                  "CWE-384",
		Description:          "Flaws in token lifecycle, insecure algorithms (e.g. alg:none), failure to rotate refresh tokens, or token exposure.",
		VerificationBoundary: "Verified when old tokens remain valid after rotation or alg:none is accepted. Token exposure in query strings or response bodies verified via structural match. Zero raw tokens retained.",
		Preconditions:        []string{"Token-bearing endpoint or refresh flow"},
	},
	CategoryPrivilegeTransitions: {
		Code:                 "SS-PRIVTRANS",
		Name:                 "Privilege & Role Transition Boundaries",
		WSTG:                 "WSTG-ATHZ-02",
		CWE:                  "CWE-269",
		Description:          "Session fails to properly revoke elevated privileges following role downgrade, revocation, or tenant transition.",
		VerificationBoundary: "Verified only when a session whose role or privileges were downgraded retains access to restricted administrative actions. Stale UI labels alone remain OBSERVED.",
		Preconditions:        []string{"Dual-role or privilege-change test account", "Restricted resource"},
	},
	CategoryLogoutBehavior: {
		Code:                 "SS-LOGOUT",
		Name:                 "Client & Server Logout Enforcement",
		WSTG:                 "WSTG-SESS-06",
		CWE:                  "CWE-613",
		Description:          "Logout mechanism only clears browser-side state while leaving the server-side session active and reusable.",
		VerificationBoundary: "Verified when a session identifier explicitly logged out remains accepted by server-side protected endpoints. Browser cache back-navigation alone without server validity remains OBSERVED.",
		Preconditions:        []string{"Logout endpoint", "Valid test session", "Protected verification endpoint"},
	},
	CategoryPasswordRecovery: {
		Code:                 "SS-RECOVERY",
		Name:                 "Password Reset & Account Recovery Lifecycle",
		WSTG:                 "WSTG-ATHN-09",
		CWE:                  "CWE-640",
		Description:          "Reusable password reset tokens, failure to terminate existing sessions after reset, or improper account binding.",
		VerificationBoundary: "Verified when a single-use recovery token can be consumed multiple times, or active sessions survive password reset. No unsolicited emails or SMS sent to live users.",
		Preconditions:        []string{"Password reset flow", "Controlled synthetic account"},
	},
	CategoryAccountEnumeration: {
		Code:                 "SS-ENUM",
		Name:                 "Account Enumeration Surface",
		WSTG:                 "WSTG-ATHN-04",
		CWE:                  "CWE-200",
		Description:          "Authentication or recovery workflows reveal valid user accounts through distinct response codes, messages, or timing.",
		VerificationBoundary: "Verified when repeatable, unambiguous error messages or statuses differentiate existing vs non-existent accounts under controlled probes. Timing noise does not constitute verified finding.",
		Preconditions:        []string{"Known existing synthetic account", "Known non-existent synthetic account"},
	},
	CategorySessionPuzzling: {
		Code:                 "SS-PUZZLING",
		Name:                 "Session Puzzling & Workflow Confusion",
		WSTG:                 "WSTG-SESS-08",
		CWE:                  "CWE-840",
		Description:          "Application reuses session variables across disparate multi-step workflows, allowing state manipulation.",
		VerificationBoundary: "Verified when pre-auth or unverified step state satisfies authentication requirement in another sensitive workflow. Discovered shared cookies alone remain CANDIDATE or OBSERVED.",
		Preconditions:        []string{"Multi-step identity workflow", "Controlled test session"},
	},
	CategorySessionIsolation: {
		Code:                 "SS-ISOLATION",
		Name:                 "Concurrent Sessions & Cross-Session Isolation",
		WSTG:                 "WSTG-SESS-09",
		CWE:                  "CWE-639",
		Description:          "Lack of isolation between concurrent user sessions, cross-tenant data leakage, or unintended session cross-talk.",
		VerificationBoundary: "Verified when User A's session accesses User B's private resources or tenant data. Inability to enforce single-session concurrency without explicit policy remains OBSERVED.",
		Preconditions:        []string{"Two distinct authorized test identities", "Protected resource"},
	},
}

// SessionState models the identity and session lifecycle state.
type SessionState string

const (
	StateAnonymous       SessionState = "ANONYMOUS"
	StatePreAuth         SessionState = "PRE_AUTH"
	StateAuthenticated   SessionState = "AUTHENTICATED"
	StatePrivileged      SessionState = "PRIVILEGED"
	StateReauthenticated SessionState = "REAUTHENTICATED"
	StatePasswordChanged SessionState = "PASSWORD_CHANGED"
	StateLoggedOut       SessionState = "LOGGED_OUT"
	StateExpired         SessionState = "EXPIRED"
	StateSuspended       SessionState = "SUSPENDED"
)

// VerificationState represents the procedural verification status of a session security test.
type VerificationState string

const (
	StateObserved      VerificationState = "OBSERVED"
	StateCandidate     VerificationState = "CANDIDATE"
	StateVerified      VerificationState = "VERIFIED"
	StateInconclusive  VerificationState = "INCONCLUSIVE"
	StateNotVulnerable VerificationState = "NOT_VULNERABLE"
)

// CoverageStatus represents the assessment status for a category.
type CoverageStatus string

const (
	CoverageUntested             CoverageStatus = "UNTESTED"
	CoverageActivelyTested       CoverageStatus = "ACTIVELY_TESTED"
	CoveragePassivelyAssessed    CoverageStatus = "PASSIVELY_ASSESSED"
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

// PlannedTest represents a planned session security test in dry-run or pre-assessment phase.
type PlannedTest struct {
	ID                string          `json:"id"`
	Category          SessionCategory `json:"category"`
	Name              string          `json:"name"`
	WSTGRef           string          `json:"wstg_ref"`
	SecurityObjective string          `json:"security_objective"`
	Preconditions     []string        `json:"preconditions"`
	RequiredState     SessionState    `json:"required_state"`
	IsActive          bool            `json:"is_active"`
	IsStateChanging   bool            `json:"is_state_changing"`
	ExpectedBehavior  string          `json:"expected_behavior"`
	Status            PlanStatus      `json:"status"`
	BlockedReason     string          `json:"blocked_reason,omitempty"`
}

// TestPlan aggregates the planned tests, requirements, and safety boundaries.
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

// Result records the empirical outcome of an executed session security test.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Category          SessionCategory   `json:"category"`
	VulnCode          string            `json:"vuln_code"`
	TestID            string            `json:"test_id"`
	TestName          string            `json:"test_name"`
	WSTGRef           string            `json:"wstg_ref"`
	Endpoint          string            `json:"endpoint"`
	Method            string            `json:"method"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	ObservedStatus    int               `json:"observed_status,omitempty"`
	StateBefore       SessionState      `json:"state_before,omitempty"`
	StateAfter        SessionState      `json:"state_after,omitempty"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// CategoryCoverage summarizes test statistics and findings for one category.
type CategoryCoverage struct {
	Category     SessionCategory `json:"category"`
	Code         string          `json:"code"`
	Name         string          `json:"name"`
	WSTGRef      string          `json:"wstg_ref"`
	Status       CoverageStatus  `json:"status"`
	TestsRun     int             `json:"tests_run"`
	Verified     int             `json:"verified"`
	Candidates   int             `json:"candidates"`
	Observations int             `json:"observations"`
	Inconclusive int             `json:"inconclusive"`
	Blocked      int             `json:"blocked"`
	Explanation  string          `json:"explanation"`
}

// Summary aggregates session security results across all categories.
type Summary struct {
	TotalTests         int                         `json:"total_tests"`
	CategoriesCovered  int                         `json:"categories_covered"`
	VerifiedCount      int                         `json:"verified_count"`
	CandidateCount     int                         `json:"candidate_count"`
	ObservedCount      int                         `json:"observed_count"`
	InconclusiveCount  int                         `json:"inconclusive_count"`
	NotVulnerableCount int                         `json:"not_vulnerable_count"`
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
	ObservedCount      int       `json:"observed_count"`
	InconclusiveCount  int       `json:"inconclusive_count"`
	BlockedCount       int       `json:"blocked_count"`
	CoverageJSON       string    `json:"coverage_json"`
	CreatedAt          time.Time `json:"created_at"`
}

// TestIdentity defines an authenticated identity used in session tests.
type TestIdentity struct {
	Alias          string            `json:"alias"` // e.g. "user_standard", "user_elevated", "user_peer"
	Role           string            `json:"role"`  // e.g. "user", "admin"
	TenantID       string            `json:"tenant_id,omitempty"`
	PrivilegeLevel int               `json:"privilege_level"`
	Username       string            `json:"username,omitempty"`
	Password       string            `json:"password,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Cookies        map[string]string `json:"cookies,omitempty"`
}

// TargetEndpoint describes an endpoint surface evaluated by the engine.
type TargetEndpoint struct {
	Method     string   `json:"method"`
	Path       string   `json:"path"`
	Parameters []string `json:"parameters,omitempty"`
	Type       string   `json:"type,omitempty"` // "login", "logout", "protected", "recovery", "profile"
	Source     string   `json:"source,omitempty"`
}

// AssessmentContext contains all contextual inputs for a session security assessment run.
type AssessmentContext struct {
	AssessmentID            string
	ExecutionID             string
	BaseURL                 string
	Endpoints               []TargetEndpoint
	Identities              []TestIdentity
	DiscoveredCookies       []string
	DiscoveredTokens        []string
	IsAllowed               func(string) bool
	IsExcluded              func(string) bool
	SyntheticFixture        bool
	AllowStateChangingTests bool
	DryRun                  bool
}

// Config defines the runtime configuration for the Session Security Engine.
type Config struct {
	Timeout                 time.Duration `json:"timeout"`
	Concurrency             int           `json:"concurrency"`
	MaxBodyReadBytes        int64         `json:"max_body_read_bytes"`
	UserAgent               string        `json:"user_agent"`
	AllowActiveTesting      bool          `json:"allow_active_testing"`
	AllowStateChangingTests bool          `json:"allow_state_changing_tests"`
}

// DefaultConfig provides conservative, safe defaults for the Session Security Engine.
func DefaultConfig() Config {
	return Config{
		Timeout:                 10 * time.Second,
		Concurrency:             3,
		MaxBodyReadBytes:        1 * 1024 * 1024, // 1MB
		UserAgent:               "Felix/2.0 (Authorized Security Assessment; SessionSec)",
		AllowActiveTesting:      true,
		AllowStateChangingTests: false, // strictly requires explicit opt-in
	}
}

// Regex patterns for comprehensive credential and token redaction.
var (
	pemPrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----.*?-----END [A-Z0-9_-]+ PRIVATE KEY-----`)
	bearerTokenPattern   = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-_.~+/=]{12,}`)
	jwtPattern           = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)
	cookieSecretPattern  = regexp.MustCompile(`(?i)((?:session|token|auth|access_token|jwt|sid|key|connect\.sid|phpsessid|jsessionid)=)[^;,\s]+`)
	querySecretPattern   = regexp.MustCompile(`(?i)((?:token|api_key|apikey|secret|password|passwd|auth|session_id|sid)=)[^&\s]+`)
	kvSecretPattern      = regexp.MustCompile(`(?i)\b(?:api_key|apikey|secret|password|passwd|auth_token|access_token|client_secret|db_password|private_key|session_id)\s*[:=]\s*["']?([^\s"']+)["']?`)
)

// RedactText removes credentials, tokens, session IDs, private keys, and secrets from text.
func RedactText(input string) string {
	if input == "" {
		return ""
	}
	s := input
	s = pemPrivateKeyPattern.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	s = bearerTokenPattern.ReplaceAllString(s, "${1}[REDACTED]")
	s = jwtPattern.ReplaceAllString(s, "[REDACTED_JWT]")
	s = cookieSecretPattern.ReplaceAllString(s, "${1}[REDACTED]")
	s = querySecretPattern.ReplaceAllString(s, "${1}[REDACTED]")
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

// HashSecret produces a safe, non-reversible SHA-256 fingerprint (first 8 hex characters)
// for verifying token equality/rotation in evidence without disclosing the actual secret.
func HashSecret(secret string) string {
	if secret == "" {
		return "empty"
	}
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:4]))
}

// RedactCookieHeader redacts sensitive values from a Cookie or Set-Cookie header string
// while preserving security attributes (Secure, HttpOnly, SameSite, Path, Domain).
func RedactCookieHeader(raw string) string {
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ";")
	if len(parts) == 0 {
		return ""
	}

	firstPart := strings.TrimSpace(parts[0])
	eqIdx := strings.Index(firstPart, "=")
	if eqIdx != -1 {
		name := firstPart[:eqIdx]
		parts[0] = fmt.Sprintf("%s=[REDACTED]", name)
	}

	return strings.Join(parts, "; ")
}

// SanitizeURL removes query parameters and userinfo from URLs for safe logging.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.User = nil
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "token") || strings.Contains(lower, "key") ||
				strings.Contains(lower, "secret") || strings.Contains(lower, "session") ||
				strings.Contains(lower, "auth") || strings.Contains(lower, "password") {
				q.Set(k, "[REDACTED]")
			}
		}
		u.RawQuery = q.Encode()
	}
	return u.String()
}
