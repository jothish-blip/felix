package cloudsec

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

// Provider identifies the target cloud platform.
type Provider string

const (
	ProviderAWS   Provider = "AWS"
	ProviderAzure Provider = "AZURE"
	ProviderGCP   Provider = "GCP"
	ProviderMulti Provider = "MULTI_CLOUD"
)

// AssessmentMode determines the boundary and method of assessment.
type AssessmentMode string

const (
	// ModeExternal assesses externally observable cloud infrastructure without credentials.
	ModeExternal AssessmentMode = "EXTERNAL"
	// ModeCredentialed assesses cloud configurations via authenticated, read-only provider APIs.
	ModeCredentialed AssessmentMode = "CREDENTIALED"
)

// VerificationState represents the procedural verification status of a cloud finding.
type VerificationState string

const (
	StateObserved      VerificationState = "OBSERVED"
	StateCandidate     VerificationState = "CANDIDATE"
	StateVerified      VerificationState = "VERIFIED"
	StateInconclusive  VerificationState = "INCONCLUSIVE"
	StateNotVulnerable VerificationState = "NOT_VULNERABLE"
)

// CoverageStatus represents the assessment status for a service.
type CoverageStatus string

const (
	CoverageSupported          CoverageStatus = "SUPPORTED"
	CoverageAssessed           CoverageStatus = "ASSESSED"
	CoveragePartiallyAssessed  CoverageStatus = "PARTIALLY_ASSESSED"
	CoverageBlockedPermissions CoverageStatus = "BLOCKED_PERMISSIONS"
	CoverageSkippedScope       CoverageStatus = "SKIPPED_SCOPE"
	CoverageSkippedConfig      CoverageStatus = "SKIPPED_CONFIG"
	CoverageFailedError        CoverageStatus = "FAILED_ERROR"
	CoverageNotImplemented     CoverageStatus = "NOT_IMPLEMENTED"
	CoverageNotApplicable      CoverageStatus = "NOT_APPLICABLE"
)

// DeclaredScope defines explicit boundaries configured by the client.
type DeclaredScope struct {
	Provider           Provider `json:"provider"`
	TargetAccountID    string   `json:"target_account_id,omitempty"`   // AWS: 12-digit account ID
	TargetSubscription string   `json:"target_subscription,omitempty"` // Azure: Subscription GUID
	TargetProjectID    string   `json:"target_project_id,omitempty"`   // GCP: Project ID
	Regions            []string `json:"regions,omitempty"`
	Services           []string `json:"services,omitempty"`
	ResourceGroups     []string `json:"resource_groups,omitempty"` // Azure
	Exclusions         []string `json:"exclusions,omitempty"`
	MaxResources       int      `json:"max_resources,omitempty"`
	RequestBudget      int      `json:"request_budget,omitempty"`
}

// VerifiedIdentity records the authenticated principal verified against provider APIs.
type VerifiedIdentity struct {
	Provider         Provider  `json:"provider"`
	PrincipalARN     string    `json:"principal_arn,omitempty"`   // AWS
	AccountID        string    `json:"account_id,omitempty"`      // AWS
	SubscriptionID   string    `json:"subscription_id,omitempty"` // Azure
	TenantID         string    `json:"tenant_id,omitempty"`       // Azure
	ProjectID        string    `json:"project_id,omitempty"`      // GCP
	ServiceAccount   string    `json:"service_account,omitempty"` // GCP
	IdentitySource   string    `json:"identity_source"`
	VerifiedAt       time.Time `json:"verified_at"`
	IsScopeMatched   bool      `json:"is_scope_matched"`
	ScopeMismatchMsg string    `json:"scope_mismatch_msg,omitempty"`
}

// Credentials holds client-supplied authentication materials in-memory only.
// NEVER persisted to database, reports, or debug logs.
type Credentials struct {
	Provider Provider `json:"provider"`

	// AWS
	AWSAccessKeyID     string `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	AWSSessionToken    string `json:"aws_session_token,omitempty"`
	AWSRegion          string `json:"aws_region,omitempty"`
	AWSAccountID       string `json:"aws_account_id,omitempty"`

	// Azure
	AzureTenantID       string `json:"azure_tenant_id,omitempty"`
	AzureClientID       string `json:"azure_client_id,omitempty"`
	AzureClientSecret   string `json:"azure_client_secret,omitempty"`
	AzureSubscriptionID string `json:"azure_subscription_id,omitempty"`

	// GCP
	GCPProjectID   string `json:"gcp_project_id,omitempty"`
	GCPClientEmail string `json:"gcp_client_email,omitempty"`
	GCPPrivateKey  string `json:"gcp_private_key,omitempty"`
	GCPAccessToken string `json:"gcp_access_token,omitempty"`
}

// RedactedCopy returns a copy of Credentials with all secret material stripped.
func (c Credentials) RedactedCopy() Credentials {
	redacted := c
	if redacted.AWSSecretAccessKey != "" {
		redacted.AWSSecretAccessKey = "[REDACTED]"
	}
	if redacted.AWSSessionToken != "" {
		redacted.AWSSessionToken = "[REDACTED]"
	}
	if redacted.AzureClientSecret != "" {
		redacted.AzureClientSecret = "[REDACTED]"
	}
	if redacted.GCPPrivateKey != "" {
		redacted.GCPPrivateKey = "[REDACTED]"
	}
	if redacted.GCPAccessToken != "" {
		redacted.GCPAccessToken = "[REDACTED]"
	}
	return redacted
}

// Scrub drops secret string references from the Credentials struct.
//
// Memory Limitation Note: In Go, string contents are immutable byte arrays allocated
// on the heap/GC memory. Zeroing struct fields drops pointer references so the runtime
// garbage collector can reclaim memory, but Go does not provide guaranteed immediate zeroing
// of string heap bytes. Callers in high-assurance environments should execute Felix in
// ephemeral, isolated process containers.
func (c *Credentials) Scrub() {
	c.AWSSecretAccessKey = ""
	c.AWSSessionToken = ""
	c.AzureClientSecret = ""
	c.GCPPrivateKey = ""
	c.GCPAccessToken = ""
}

// ExternalTarget describes an approved host/URL evaluated in external mode.
type ExternalTarget struct {
	URL        string            `json:"url"`
	Hostname   string            `json:"hostname"`
	Port       int               `json:"port"`
	Scheme     string            `json:"scheme"`
	Headers    map[string]string `json:"headers,omitempty"`
	Source     string            `json:"source"`
	TLSVersion string            `json:"tls_version,omitempty"`
}

// Result records the evaluation outcome of an individual cloud check.
type Result struct {
	ID                string            `json:"id"`
	AssessmentID      string            `json:"assessment_id"`
	ExecutionID       string            `json:"execution_id"`
	Provider          Provider          `json:"provider"`
	Mode              AssessmentMode    `json:"mode"`
	Service           string            `json:"service"`
	CheckID           string            `json:"check_id"`
	CheckName         string            `json:"check_name"`
	ResourceID        string            `json:"resource_id"`
	Region            string            `json:"region,omitempty"`
	VerificationState VerificationState `json:"verification_state"`
	Severity          string            `json:"severity"`
	Confidence        string            `json:"confidence"`
	EvidenceSummary   string            `json:"evidence_summary"`
	EvidenceDetails   map[string]string `json:"evidence_details,omitempty"`
	Finding           *report.Finding   `json:"finding,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
}

// ServiceCoverage records coverage statistics and status for a service.
type ServiceCoverage struct {
	Provider       Provider       `json:"provider"`
	Service        string         `json:"service"`
	Status         CoverageStatus `json:"status"`
	ResourcesFound int            `json:"resources_found"`
	ChecksRun      int            `json:"checks_run"`
	Verified       int            `json:"verified"`
	Candidates     int            `json:"candidates"`
	Observations   int            `json:"observations"`
	Inconclusive   int            `json:"inconclusive"`
	NotVulnerable  int            `json:"not_vulnerable"`
	Blocked        int            `json:"blocked"`
	Explanation    string         `json:"explanation"`
}

// Summary aggregates cloud security results and coverage across services.
type Summary struct {
	Mode               AssessmentMode             `json:"mode"`
	Provider           Provider                   `json:"provider"`
	TargetScope        string                     `json:"target_scope"`
	VerifiedPrincipal  string                     `json:"verified_principal,omitempty"`
	SyntheticFixture   bool                       `json:"synthetic_fixture,omitempty"`
	TotalChecks        int                        `json:"total_checks"`
	ServicesAssessed   int                        `json:"services_assessed"`
	VerifiedCount      int                        `json:"verified_count"`
	CandidateCount     int                        `json:"candidate_count"`
	ObservedCount      int                        `json:"observed_count"`
	InconclusiveCount  int                        `json:"inconclusive_count"`
	NotVulnerableCount int                        `json:"not_vulnerable_count"`
	BlockedCount       int                        `json:"blocked_count"`
	ServiceCoverageMap map[string]ServiceCoverage `json:"service_coverage_map"`
}

// RunRecord represents a persistent run record in the database.
type RunRecord struct {
	ID                string         `json:"id"`
	AssessmentID      string         `json:"assessment_id"`
	ExecutionID       string         `json:"execution_id"`
	Mode              AssessmentMode `json:"mode"`
	Provider          Provider       `json:"provider"`
	ScopeIdentifier   string         `json:"scope_identifier"`
	VerifiedPrincipal string         `json:"verified_principal,omitempty"`
	SyntheticFixture  bool           `json:"synthetic_fixture,omitempty"`
	TotalChecks       int            `json:"total_checks"`
	ServicesAssessed  int            `json:"services_assessed"`
	VerifiedCount     int            `json:"verified_count"`
	CandidateCount    int            `json:"candidate_count"`
	ObservedCount     int            `json:"observed_count"`
	CoverageJSON      string         `json:"coverage_json"`
	CreatedAt         time.Time      `json:"created_at"`
}

// PlannedCheck describes a check planned for execution in dry-run mode.
type PlannedCheck struct {
	ID          string         `json:"id"`
	Provider    Provider       `json:"provider"`
	Service     string         `json:"service"`
	Name        string         `json:"name"`
	Mode        AssessmentMode `json:"mode"`
	ReadOnly    bool           `json:"read_only"`
	RequiredAPI string         `json:"required_api"`
	Status      string         `json:"status"` // READY, BLOCKED, SKIPPED
	Reason      string         `json:"reason,omitempty"`
}

// PlanResult encapsulates dry-run planning analysis.
type PlanResult struct {
	AssessmentID      string         `json:"assessment_id"`
	Mode              AssessmentMode `json:"mode"`
	Provider          Provider       `json:"provider"`
	TargetScope       string         `json:"target_scope"`
	IdentitySource    string         `json:"identity_source,omitempty"`
	VerifiedPrincipal string         `json:"verified_principal,omitempty"`
	PlannedChecks     []PlannedCheck `json:"planned_checks"`
	ReadyChecks       int            `json:"ready_checks"`
	BlockedChecks     int            `json:"blocked_checks"`
	GeneratedAt       time.Time      `json:"generated_at"`
}

// AssessmentContext contains all contextual inputs for a cloud security run.
type AssessmentContext struct {
	AssessmentID     string
	ExecutionID      string
	Mode             AssessmentMode
	Provider         Provider
	Scope            DeclaredScope
	Credentials      Credentials
	ExternalTargets  []ExternalTarget
	IsAllowed        func(string) bool
	IsExcluded       func(string) bool
	SyntheticFixture bool
	DryRun           bool
}

// Config defines operational parameters for the cloud security engine.
type Config struct {
	Timeout         time.Duration
	MaxConcurrency  int
	UserAgent       string
	EnableExternal  bool
	EnableAPIChecks bool
	CanaryCallback  string
}

// DefaultConfig provides safe, bounded defaults.
func DefaultConfig() Config {
	return Config{
		Timeout:         15 * time.Second,
		MaxConcurrency:  4,
		UserAgent:       "Felix-CloudSec/2.0 (Security-Audit-Engine)",
		EnableExternal:  true,
		EnableAPIChecks: true,
	}
}

// -------------------------------------------------------------------------
// Secret Safety & Redaction Helpers
// -------------------------------------------------------------------------

var (
	awsKeyRegex      = regexp.MustCompile(`(?i)(AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}`)
	jwtTokenRegex    = regexp.MustCompile(`\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}\b`)
	bearerRegex      = regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9_\-\.~+/]+=*`)
	privateKeyRegex  = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]+PRIVATE KEY-----.*?-----END [A-Z ]+PRIVATE KEY-----`)
	secretParamRegex = regexp.MustCompile(`(?i)(sig|token|key|secret|password|auth|signature|code)=([^\s&"']+)`)
)

// RedactText sanitizes text by replacing secrets, tokens, and private keys.
func RedactText(s string) string {
	if s == "" {
		return ""
	}
	s = privateKeyRegex.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	s = jwtTokenRegex.ReplaceAllString(s, "[REDACTED_JWT]")
	s = bearerRegex.ReplaceAllString(s, "Bearer [REDACTED]")
	s = awsKeyRegex.ReplaceAllString(s, "[REDACTED_AWS_KEY]")
	s = secretParamRegex.ReplaceAllString(s, "$1=[REDACTED]")
	return s
}

// HashSecret produces a safe, one-way fingerprint of a secret for comparison.
func HashSecret(secret string) string {
	if secret == "" {
		return ""
	}
	h := sha256.Sum256([]byte(secret))
	return fmt.Sprintf("sha256:%s", hex.EncodeToString(h[:8]))
}

// SanitizeURL strips sensitive parameters from URL strings.
func SanitizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return RedactText(rawURL)
	}
	q := u.Query()
	for k := range q {
		lower := strings.ToLower(k)
		if strings.Contains(lower, "token") || strings.Contains(lower, "sig") ||
			strings.Contains(lower, "key") || strings.Contains(lower, "secret") ||
			strings.Contains(lower, "auth") || strings.Contains(lower, "code") {
			q.Set(k, "[REDACTED]")
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// MaskIdentifier masks sensitive account numbers or resource IDs for display.
func MaskIdentifier(id string) string {
	if len(id) <= 6 {
		return "***"
	}
	return id[:3] + "..." + id[len(id)-3:]
}
