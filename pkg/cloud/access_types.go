package cloud

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	sensitiveQueryRegex   = regexp.MustCompile(`(?i)(auth|token|secret|key|password|apikey|access_token|api_key|admin-secret)=([^&\s"'>]+)`)
	sensitiveHeaderRegex  = regexp.MustCompile(`(?i)(Bearer|Basic)\s+[A-Za-z0-9_\-\.\+/=]+`)
	sensitiveURIUserRegex = regexp.MustCompile(`://([^:@/\s]+):([^@/\s]+)@`)
)

// RedactSensitiveString removes tokens, passwords, and sensitive query/header values from strings.
func RedactSensitiveString(s string) string {
	if s == "" {
		return ""
	}
	s = sensitiveQueryRegex.ReplaceAllString(s, "$1=***REDACTED***")
	s = sensitiveHeaderRegex.ReplaceAllString(s, "$1 ***REDACTED***")
	s = sensitiveURIUserRegex.ReplaceAllString(s, "://$1:***REDACTED***@")
	return s
}

// AccessStatus defines the controlled vocabulary for access verification states.
type AccessStatus string

const (
	// StatusServiceDetected indicates empirical detection of the service technology without verifying reachability.
	StatusServiceDetected AccessStatus = "SERVICE_DETECTED"
	// StatusServiceReachable indicates network-level reachability (TCP handshake, HTTP responding, PING/PONG).
	StatusServiceReachable AccessStatus = "SERVICE_REACHABLE"
	// StatusAuthChallenged indicates the service explicitly required authentication (HTTP 401/403, -NOAUTH, handshake rejection).
	StatusAuthChallenged AccessStatus = "AUTH_CHALLENGED"
	// StatusUnauthenticatedAccess indicates verified access without any authentication credentials.
	StatusUnauthenticatedAccess AccessStatus = "UNAUTHENTICATED_ACCESS"
	// StatusAuthenticatedAccess indicates verified access using explicitly supplied, authorized credentials.
	StatusAuthenticatedAccess AccessStatus = "AUTHENTICATED_ACCESS"
	// StatusReadAllowed indicates read access was permitted for the specifically tested resource.
	StatusReadAllowed AccessStatus = "READ_ALLOWED"
	// StatusReadDenied indicates read access was explicitly denied or restricted by permissions/rules for the tested resource.
	StatusReadDenied AccessStatus = "READ_DENIED"
	// StatusAccessInconclusive indicates the response was ambiguous, truncated, or inconclusive.
	StatusAccessInconclusive AccessStatus = "INCONCLUSIVE"
	// StatusVerificationSkipped indicates verification was skipped due to scope rules, absence of authorization, or unsupported operations.
	StatusVerificationSkipped AccessStatus = "SKIPPED"
	// StatusWriteVerified indicates a controlled canary write succeeded under explicit authorization.
	StatusWriteVerified AccessStatus = "WRITE_VERIFIED"
	// StatusWriteDenied indicates write access was denied for the canary resource.
	StatusWriteDenied AccessStatus = "WRITE_DENIED"
)

// AccessDecision defines the authorization verdict for an attempted operation.
type AccessDecision string

const (
	DecisionAllowed      AccessDecision = "ALLOWED"
	DecisionDenied       AccessDecision = "DENIED"
	DecisionInconclusive AccessDecision = "INCONCLUSIVE"
	DecisionSkipped      AccessDecision = "SKIPPED"
	DecisionError        AccessDecision = "ERROR"
)

// AuthenticationContext specifies whether credentials were used.
type AuthenticationContext string

const (
	AuthContextUnauthenticated AuthenticationContext = "UNAUTHENTICATED"
	AuthContextAuthenticated   AuthenticationContext = "AUTHENTICATED"
	AuthContextNotApplicable   AuthenticationContext = "NOT_APPLICABLE"
)

// OperationTested defines the specific operation performed during verification.
type OperationTested string

const (
	OpProtocolProbe    OperationTested = "PROTOCOL_PROBE"
	OpMetadataRead     OperationTested = "METADATA_READ"
	OpBoundedRead      OperationTested = "BOUNDED_RESOURCE_READ"
	OpControlledCanary OperationTested = "CONTROLLED_CANARY_WRITE"
)

// ErrorClassification categorizes verification failures safely.
type ErrorClassification string

const (
	ErrClassNone              ErrorClassification = "ERR_NONE"
	ErrClassTimeout           ErrorClassification = "ERR_TIMEOUT"
	ErrClassConnectionRefused ErrorClassification = "ERR_CONNECTION_REFUSED"
	ErrClassSSRFBlocked       ErrorClassification = "ERR_SSRF_BLOCKED"
	ErrClassScopeExcluded     ErrorClassification = "ERR_SCOPE_EXCLUDED"
	ErrClassScopeOutOfScope   ErrorClassification = "ERR_SCOPE_OUT_OF_SCOPE"
	ErrClassRateLimited       ErrorClassification = "ERR_RATE_LIMITED"
	ErrClassTLSFailure        ErrorClassification = "ERR_TLS_FAILURE"
	ErrClassProtocolMalformed ErrorClassification = "ERR_PROTOCOL_MALFORMED"
	ErrClassUnsupported       ErrorClassification = "ERR_UNSUPPORTED"
	ErrClassUnknown           ErrorClassification = "ERR_UNKNOWN"
)

// CredentialProfile provides explicitly scoped, authorized credentials for verification testing.
type CredentialProfile struct {
	Name        string            `json:"name,omitempty"`
	Username    string            `json:"username,omitempty"`
	Secret      string            `json:"-"` // Never serialized to JSON
	Role        string            `json:"role,omitempty"`
	Headers     map[string]string `json:"-"` // May contain sensitive auth headers, never serialized
	Description string            `json:"description,omitempty"`
}

// Redacted returns a sanitized copy safe for logs, reporting, and inspection.
func (c CredentialProfile) Redacted() CredentialProfile {
	redactedHeaders := make(map[string]string)
	for k := range c.Headers {
		redactedHeaders[k] = "***REDACTED***"
	}
	sec := ""
	if c.Secret != "" {
		sec = "***REDACTED***"
	}
	return CredentialProfile{
		Name:        c.Name,
		Username:    c.Username,
		Secret:      sec,
		Role:        c.Role,
		Headers:     redactedHeaders,
		Description: c.Description,
	}
}

// TestResourceConfig defines the target resource for bounded read or canary verification.
type TestResourceConfig struct {
	ResourceID       string          `json:"resource_id"` // test_index, test_table, test-object.txt, etc.
	ExpectedDecision AccessDecision  `json:"expected_decision,omitempty"`
	Operation        OperationTested `json:"operation"`
	ReadOnly         bool            `json:"read_only"`
	Timeout          time.Duration   `json:"timeout,omitempty"`
	MaxResponseSize  int64           `json:"max_response_size,omitempty"`
}

// CanaryConfig configures optional, isolated write verification.
type CanaryConfig struct {
	Enabled                        bool   `json:"enabled"`
	ExplicitlyAuthorized           bool   `json:"explicitly_authorized"`
	TargetResource                 string `json:"target_resource"`
	CanaryKey                      string `json:"canary_key"`
	CanaryValue                    string `json:"canary_value"`
	AllowCleanup                   bool   `json:"allow_cleanup"`
	PreventOverwriteCheck          bool   `json:"prevent_overwrite_check"`
	IdentityLeastPrivilegeVerified bool   `json:"identity_least_privilege_verified"`
}

// AccessVerificationRecord captures the full empirical verification outcome for an access check.
type AccessVerificationRecord struct {
	Target              string                `json:"target"`
	Technology          ServiceTechnology     `json:"technology"`
	Family              ServiceFamily         `json:"family"`
	Status              AccessStatus          `json:"status"`
	Decision            AccessDecision        `json:"decision"`
	AuthContext         AuthenticationContext `json:"auth_context"`
	Operation           OperationTested       `json:"operation"`
	ResourceScope       string                `json:"resource_scope,omitempty"`
	CredentialUsed      bool                  `json:"credential_used"`
	FindingSuitable     bool                  `json:"finding_suitable"`
	Evidence            string                `json:"evidence"`
	Limitations         string                `json:"limitations,omitempty"`
	ErrorClassification ErrorClassification   `json:"error_classification"`
	VerifiedAt          time.Time             `json:"verified_at"`
}

// Validate verifies model integrity and enforces safety invariants.
func (r AccessVerificationRecord) Validate() error {
	if r.Target == "" {
		return errors.New("access verification record target must not be empty")
	}
	if r.Technology == "" {
		return errors.New("access verification record technology must not be empty")
	}

	// Validate status vocabulary
	switch r.Status {
	case StatusServiceDetected, StatusServiceReachable, StatusAuthChallenged,
		StatusUnauthenticatedAccess, StatusAuthenticatedAccess, StatusReadAllowed,
		StatusReadDenied, StatusAccessInconclusive, StatusVerificationSkipped,
		StatusWriteVerified, StatusWriteDenied:
		// Valid
	default:
		return fmt.Errorf("invalid access status %q", r.Status)
	}

	// Validate decision vocabulary
	switch r.Decision {
	case DecisionAllowed, DecisionDenied, DecisionInconclusive, DecisionSkipped, DecisionError:
		// Valid
	default:
		return fmt.Errorf("invalid access decision %q", r.Decision)
	}

	// Validate auth context
	switch r.AuthContext {
	case AuthContextUnauthenticated, AuthContextAuthenticated, AuthContextNotApplicable:
		// Valid
	default:
		return fmt.Errorf("invalid authentication context %q", r.AuthContext)
	}

	// Invariant: Unauthenticated data read requires an explicit resource scope.
	if r.Decision == DecisionAllowed && r.AuthContext == AuthContextUnauthenticated && r.Operation == OpBoundedRead {
		if strings.TrimSpace(r.ResourceScope) == "" {
			return errors.New("unauthenticated data read cannot be claimed without an explicit resource scope")
		}
	}

	// Invariant: Service reachability alone is never a security finding.
	if r.Status == StatusServiceReachable && r.FindingSuitable {
		return errors.New("service reachability alone is not suitable for a security finding")
	}

	// Invariant: Protocol probe or metadata read cannot claim application record read access.
	if (r.Operation == OpProtocolProbe || r.Operation == OpMetadataRead) && r.Status == StatusReadAllowed && r.ResourceScope != "" && !strings.Contains(r.ResourceScope, "metadata") {
		return errors.New("protocol probe or metadata read cannot claim application data read status")
	}

	// Invariant: Skipped or out-of-scope verification must not be marked Allowed.
	if r.Status == StatusVerificationSkipped && r.Decision == DecisionAllowed {
		return errors.New("skipped verification cannot have an Allowed decision")
	}

	return nil
}

// GenerateScopedFingerprint generates a unique SHA-256 deduplication fingerprint including resource scope.
func GenerateScopedFingerprint(p Provider, endpoint, category, scope string) string {
	h := sha256.New()
	cleanEndpoint := strings.ToLower(strings.TrimSpace(endpoint))
	cleanCategory := strings.ToLower(strings.TrimSpace(category))
	cleanScope := strings.ToLower(strings.TrimSpace(scope))
	h.Write([]byte(string(p) + ":" + cleanCategory + ":" + cleanEndpoint + ":" + cleanScope))
	return hex.EncodeToString(h.Sum(nil))
}

// ToCloudFinding converts an access verification record to a CloudFinding if suitable.
func (r AccessVerificationRecord) ToCloudFinding() (CloudFinding, bool) {
	if !r.FindingSuitable {
		return CloudFinding{}, false
	}

	category := fmt.Sprintf("Access Verification: %s", r.Technology)
	severity := SeverityInfo
	confidence := ConfidenceHigh

	switch r.Status {
	case StatusUnauthenticatedAccess, StatusReadAllowed:
		if r.AuthContext == AuthContextUnauthenticated && r.Operation == OpBoundedRead {
			severity = SeverityHigh
			category = fmt.Sprintf("Unauthenticated Data Access: %s", r.Technology)
		} else if r.AuthContext == AuthContextUnauthenticated && r.Operation == OpMetadataRead {
			severity = SeverityInfo
			category = fmt.Sprintf("Unauthenticated Metadata Exposure: %s", r.Technology)
		}
	case StatusWriteVerified:
		if r.AuthContext == AuthContextUnauthenticated {
			severity = SeverityCritical
			category = fmt.Sprintf("Unauthenticated Write Access: %s", r.Technology)
		} else {
			severity = SeverityMedium
			category = fmt.Sprintf("Verified Write Access: %s", r.Technology)
		}
	case StatusAuthChallenged, StatusReadDenied:
		severity = SeverityInfo
		category = fmt.Sprintf("Access Restricted: %s", r.Technology)
	}

	desc := fmt.Sprintf("Access verification for %s on %s resulted in %s (%s)", r.Technology, r.Target, r.Status, r.Decision)
	if r.ResourceScope != "" {
		desc = fmt.Sprintf("%s on resource [%s]", desc, r.ResourceScope)
	}

	fp := GenerateFingerprint(Provider(r.Technology), r.Target, category)
	if r.ResourceScope != "" {
		fp = GenerateScopedFingerprint(Provider(r.Technology), r.Target, category, r.ResourceScope)
	}

	details := map[string]string{
		"technology":          string(r.Technology),
		"family":              string(r.Family),
		"access_status":       string(r.Status),
		"decision":            string(r.Decision),
		"auth_context":        string(r.AuthContext),
		"operation":           string(r.Operation),
		"verification_status": r.ToVerificationStatus(),
		"analysis_method":     "ACTIVE_VERIFICATION",
	}
	if r.ResourceScope != "" {
		details["resource_scope"] = r.ResourceScope
	}
	if r.ErrorClassification != "" && r.ErrorClassification != ErrClassNone {
		details["error_classification"] = string(r.ErrorClassification)
	}

	return CloudFinding{
		Provider:    Provider(r.Technology),
		Category:    category,
		Endpoint:    r.Target,
		Description: desc,
		Evidence:    r.Evidence,
		Severity:    severity,
		Confidence:  confidence,
		Fingerprint: fp,
		Details:     details,
	}, true
}

// ToVerificationStatus maps AccessStatus to canonical verification status string ("VERIFIED", "NOT_EXPOSED", "NOT_VERIFIED").
func (r AccessVerificationRecord) ToVerificationStatus() string {
	switch r.Status {
	case StatusUnauthenticatedAccess, StatusReadAllowed, StatusWriteVerified:
		return "VERIFIED"
	case StatusAuthChallenged, StatusReadDenied, StatusWriteDenied:
		return "NOT_EXPOSED"
	case StatusServiceReachable, StatusServiceDetected, StatusAccessInconclusive:
		return "NOT_VERIFIED"
	case StatusVerificationSkipped:
		return "NOT_VERIFIED"
	default:
		return "NOT_VERIFIED"
	}
}
