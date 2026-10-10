package authz

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"felix/pkg/report"
)

// Classification categories for Authorization & Access Control Intelligence.
type Category string

const (
	CategoryBOLA               Category = "BOLA"
	CategoryBFLA               Category = "BFLA"
	CategoryBOPLAExposure      Category = "BOPLA_EXPOSURE"
	CategoryBOPLAModification  Category = "BOPLA_MODIFICATION"
	CategoryHorizontalEsc      Category = "HORIZONTAL_PRIVILEGE_ESCALATION"
	CategoryVerticalEsc        Category = "VERTICAL_PRIVILEGE_ESCALATION"
)

// FindingCategoryTitles maps authorization categories to canonical report titles.
var FindingCategoryTitles = map[Category]string{
	CategoryBOLA:              "API Security / Broken Object Level Authorization (BOLA)",
	CategoryBFLA:              "API Security / Broken Function Level Authorization (BFLA)",
	CategoryBOPLAExposure:     "API Security / Broken Object Property Level Authorization (Exposure)",
	CategoryBOPLAModification: "API Security / Broken Object Property Level Authorization (Modification)",
	CategoryHorizontalEsc:     "API Security / Horizontal Privilege Escalation",
	CategoryVerticalEsc:       "API Security / Vertical Privilege Escalation",
}

// VerificationState represents the procedural verification status of an authorization test.
type VerificationState string

const (
	StateObserved              VerificationState = "OBSERVED"
	StateCandidate             VerificationState = "CANDIDATE"
	StateVerified              VerificationState = "VERIFIED"
	StateInconclusive          VerificationState = "INCONCLUSIVE"
	StateNotVulnerable         VerificationState = "NOT_VULNERABLE"
	StateBlockedInvalidSession VerificationState = "BLOCKED_INVALID_SESSION"
)

// ExpectedResult defines what the authorization policy expects for a given test case.
type ExpectedResult string

const (
	ExpectedAllow ExpectedResult = "ALLOW"
	ExpectedDeny  ExpectedResult = "DENY"
)

// TestIdentity defines an authenticated identity used in authorization tests.
type TestIdentity struct {
	Alias          string            `json:"alias"`           // e.g. "user_a", "user_b", "admin"
	Role           string            `json:"role"`            // e.g. "user", "admin", "moderator"
	TenantID       string            `json:"tenant_id"`       // e.g. "tenant_1", "tenant_2"
	PrivilegeLevel int               `json:"privilege_level"` // e.g. 1=user, 5=admin
	Headers        map[string]string `json:"headers,omitempty"` // Runtime headers (Authorization, etc.)
	Cookies        map[string]string `json:"cookies,omitempty"` // Runtime session cookies
}

// ScrubbedHeaders returns headers with sensitive authorization tokens redacted.
func (ti *TestIdentity) ScrubbedHeaders() map[string]string {
	scrubbed := make(map[string]string)
	for k, v := range ti.Headers {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "token") ||
			strings.Contains(lowerK, "key") || strings.Contains(lowerK, "secret") ||
			strings.Contains(lowerK, "cookie") || strings.Contains(lowerK, "session") {
			scrubbed[k] = "[REDACTED]"
		} else {
			scrubbed[k] = v
		}
	}
	return scrubbed
}

// TestResource defines an object or resource used in object-level tests.
type TestResource struct {
	ID                  string   `json:"id"`                   // e.g. "order_101", "profile_alice"
	Type                string   `json:"type"`                 // e.g. "order", "document", "profile"
	OwnerAlias          string   `json:"owner_alias"`          // Alias of the owner identity (e.g. "user_a")
	TenantID            string   `json:"tenant_id"`            // Tenant ID this resource belongs to
	IsShared            bool     `json:"is_shared"`            // True if resource is legitimately shared
	AllowedIdentities   []string `json:"allowed_identities"`   // Explicitly authorized identities if shared
	SensitiveProperties []string `json:"sensitive_properties"` // Properties restricted to owner/admin
	ImmutableProperties []string `json:"immutable_properties"` // Properties the client cannot modify
}

// EndpointRule defines expected role, operation, and property access rules for an API route.
type EndpointRule struct {
	Pattern             string   `json:"pattern"`              // Path pattern, e.g. "/api/v1/admin/*", "/api/orders/{id}"
	Method              string   `json:"method"`               // HTTP Method ("GET", "POST", "PUT", "DELETE")
	AllowedRoles        []string `json:"allowed_roles"`        // Roles permitted to call this endpoint
	DeniedRoles         []string `json:"denied_roles"`         // Roles explicitly denied
	AdminOnly           bool     `json:"admin_only"`           // True if restricted to administrative roles
	TenantScoped        bool     `json:"tenant_scoped"`        // True if cross-tenant access must be blocked
	MonitoredProperties []string `json:"monitored_properties"` // Sensitive properties (e.g. "role", "price")
}

// AuthzPolicy defines the explicit permission matrix provided for an assessment.
type AuthzPolicy struct {
	AssessmentRef   string                  `json:"assessment_ref"`
	AuthorizationDoc string                 `json:"authorization_doc"`
	AllowWriteTests bool                    `json:"allow_write_tests"` // Guard: must be true to perform PUT/POST/DELETE tests
	Identities      map[string]TestIdentity `json:"identities"`        // Keyed by alias
	Resources       map[string]TestResource `json:"resources"`         // Keyed by resource ID
	Endpoints       []EndpointRule          `json:"endpoints"`
}

// AuthzTestCase represents a concrete authorization check planned against the target.
type AuthzTestCase struct {
	ID                  string         `json:"id"`
	Category            Category       `json:"category"`
	Endpoint            string         `json:"endpoint"`
	Method              string         `json:"method"`
	PrimaryIdentity     string         `json:"primary_identity"`     // Alias of the identity sending the request
	BaselineIdentity    string         `json:"baseline_identity"`    // Alias of identity for baseline comparison
	TargetResource      string         `json:"target_resource"`      // Resource ID being accessed
	ExpectedResult      ExpectedResult `json:"expected_result"`      // Expected policy outcome (ALLOW / DENY)
	Payload             string         `json:"payload,omitempty"`    // Body payload for mutation tests
	PropertyKey         string         `json:"property_key,omitempty"` // For BOPLA tests (e.g. "role", "price")
	PropertyValue       string         `json:"property_value,omitempty"`
	Description         string         `json:"description"`
}

// AuthzTestResult encapsulates the execution outcome, evidence, and verification state of a test case.
type AuthzTestResult struct {
	ID                 string            `json:"id"`
	TestCaseID         string            `json:"test_case_id"`
	AssessmentID       string            `json:"assessment_id"`
	ExecutionID        string            `json:"execution_id"`
	Category           Category          `json:"category"`
	VerificationState  VerificationState `json:"verification_state"`
	Endpoint           string            `json:"endpoint"`
	Method             string            `json:"method"`
	PrimaryIdentity    string            `json:"primary_identity"`
	BaselineIdentity   string            `json:"baseline_identity,omitempty"`
	TargetResource     string            `json:"target_resource,omitempty"`
	ObservedStatus     int               `json:"observed_status"`
	BaselineStatus     int               `json:"baseline_status,omitempty"`
	DisclosedData      bool              `json:"disclosed_data"`
	PropertyModified   bool              `json:"property_modified"`
	EvidenceSummary    string            `json:"evidence_summary"`
	RedactedRequest    string            `json:"redacted_request,omitempty"`
	RedactedResponse   string            `json:"redacted_response,omitempty"`
	CorrelatedCategory Category          `json:"correlated_category,omitempty"` // e.g. Horizontal/Vertical escalation link
	Finding            *report.Finding   `json:"finding,omitempty"`
	CreatedAt          time.Time         `json:"created_at"`
}

// AuthzSummary provides statistical metrics for an authorization assessment.
type AuthzSummary struct {
	TotalTests          int            `json:"total_tests"`
	VerifiedCount       int            `json:"verified_count"`
	CandidateCount      int            `json:"candidate_count"`
	InconclusiveCount   int            `json:"inconclusive_count"`
	NotVulnerableCount  int            `json:"not_vulnerable_count"`
	BlockedCount        int            `json:"blocked_count,omitempty"`
	CategoryBreakdown   map[string]int `json:"category_breakdown"`
	VerifiedBreakdown   map[string]int `json:"verified_breakdown"`
}

// SanitizeHeaders creates a sanitized copy of HTTP headers with all authorization secrets redacted.
func SanitizeHeaders(headers http.Header) map[string]string {
	out := make(map[string]string)
	if headers == nil {
		return out
	}
	sensitiveKeys := map[string]struct{}{
		"authorization": {}, "cookie": {}, "set-cookie": {}, "x-api-key": {},
		"x-auth-token": {}, "api-key": {}, "x-session-id": {}, "proxy-authorization": {},
	}
	for k, vv := range headers {
		lowerK := strings.ToLower(k)
		if _, ok := sensitiveKeys[lowerK]; ok || strings.Contains(lowerK, "token") ||
			strings.Contains(lowerK, "secret") || strings.Contains(lowerK, "key") {
			out[k] = "[REDACTED]"
		} else {
			out[k] = strings.Join(vv, ", ")
		}
	}
	return out
}

// SanitizeURL strips sensitive parameters from URL query strings.
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
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "token") || strings.Contains(lowerK, "secret") ||
			strings.Contains(lowerK, "pass") || strings.Contains(lowerK, "key") ||
			strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "session") {
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

var (
	secretJSONPattern = regexp.MustCompile(`(?i)"(password|passwd|secret|token|access_token|refresh_token|api_key|credit_card|cvv)"\s*:\s*"[^"]*"`)

	// PEM private key blocks
	pemPrivateKeyPattern = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

	// JWT tokens: three dot-separated base64url segments (minimum 10 chars each for header/payload)
	jwtPattern = regexp.MustCompile(`\bey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+\b`)

	// Bearer authorization tokens
	bearerTokenPattern = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9_\-\.~+/]+=*`)

	// Key-value pairs in form data, query strings, headers, config lines, etc.
	kvSecretPattern = regexp.MustCompile(`(?i)\b(access_token|client_secret|api_key|apikey|secret_key|secret|password|passwd|auth_token|refresh_token|private_key|token)\s*([:=])\s*(?:"([^"]*)"|'([^']*)'|([^&\s,;'"<>]+))`)

	// Session cookies in Set-Cookie / Cookie headers or response body text
	cookieSecretPattern = regexp.MustCompile(`(?i)\b(connect\.sid|phpsessid|jsessionid|sessionid|session_id|session|sid)\s*=\s*([^;\s\r\n]+)`)

	// Sensitive query parameters in embedded URLs
	querySecretPattern = regexp.MustCompile(`(?i)([?&](?:token|key|api_key|apikey|secret|password|passwd|auth|access_token|session)=)[^&\s"'<>]+`)

	// HTML password and hidden sensitive token inputs
	htmlPasswordPattern1 = regexp.MustCompile(`(?i)(<input[^>]+type=["']?password["']?[^>]*value=["'])([^"']*)(["'])`)
	htmlPasswordPattern2 = regexp.MustCompile(`(?i)(<input[^>]+value=["'])([^"']*)(["'][^>]*type=["']?password["']?)`)
	htmlTokenPattern1    = regexp.MustCompile(`(?i)(<input[^>]+name=["'][^"']*(?:token|secret|key|csrf|auth)[^"']*["'][^>]*value=["'])([^"']*)(["'])`)
	htmlTokenPattern2    = regexp.MustCompile(`(?i)(<input[^>]+value=["'])([^"']*)(["'][^>]*name=["'][^"']*(?:token|secret|key|csrf|auth)[^"']*["'])`)
)

// RedactText redacts all recognized sensitive credentials, tokens, cookies, private keys,
// HTML password inputs, and key-value secret pairs from free-form text.
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
	s = cookieSecretPattern.ReplaceAllString(s, "${1}=[REDACTED]")

	// 6. Redact URL query parameters
	s = querySecretPattern.ReplaceAllString(s, "${1}[REDACTED]")

	// 7. Redact key-value secrets (e.g. access_token=..., api_key: ...)
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

// RedactSensitiveJSON redacts sensitive key values in JSON string representations.
func RedactSensitiveJSON(jsonStr string) string {
	s := secretJSONPattern.ReplaceAllString(jsonStr, `"$1":"[REDACTED]"`)
	return RedactText(s)
}

// RedactBody produces a bounded, sanitized snippet of an HTTP body for evidence recording.
func RedactBody(body []byte, maxLen int) string {
	if len(body) == 0 {
		return ""
	}
	// Attempt structured JSON redaction first
	var js any
	if err := json.Unmarshal(body, &js); err == nil {
		redactedMap := redactMapRecursive(js)
		b, err := json.Marshal(redactedMap)
		if err == nil {
			s := RedactText(string(b))
			if maxLen > 0 && len(s) > maxLen {
				return s[:maxLen] + " ... [TRUNCATED]"
			}
			return s
		}
	}

	// Non-JSON or unstructured content: comprehensive text redaction
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

// RedactRequestSummary creates a sanitized representation of an HTTP request for audit logging.
func RedactRequestSummary(method, endpoint string, headers map[string]string, payload string) string {
	sanitizedEndpoint := SanitizeURL(endpoint)
	var parts []string
	parts = append(parts, fmt.Sprintf("%s %s", method, sanitizedEndpoint))
	for k, v := range headers {
		lowerK := strings.ToLower(k)
		if strings.Contains(lowerK, "auth") || strings.Contains(lowerK, "token") ||
			strings.Contains(lowerK, "key") || strings.Contains(lowerK, "secret") ||
			strings.Contains(lowerK, "cookie") || strings.Contains(lowerK, "session") {
			parts = append(parts, fmt.Sprintf("%s: [REDACTED]", k))
		} else {
			parts = append(parts, fmt.Sprintf("%s: %s", k, RedactText(v)))
		}
	}
	if payload != "" {
		redactedPayload := RedactBody([]byte(payload), 256)
		parts = append(parts, fmt.Sprintf("\n%s", redactedPayload))
	}
	return strings.Join(parts, "\n")
}
