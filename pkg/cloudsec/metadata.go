package cloudsec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"felix/pkg/crawler"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// -------------------------------------------------------------------------
// Metadata Classification States (Roadmap Section 5)
// -------------------------------------------------------------------------

// MetadataClassification represents the verified posture of a cloud metadata endpoint.
type MetadataClassification string

const (
	ClassNotReachable                 MetadataClassification = "NOT_REACHABLE"
	ClassReachable                    MetadataClassification = "REACHABLE"
	ClassAccessDenied                 MetadataClassification = "ACCESS_DENIED"
	ClassIMDSv1Exposed                MetadataClassification = "IMDSV1_EXPOSED"
	ClassIMDSv2Protected              MetadataClassification = "IMDSV2_PROTECTED"
	ClassMetadataExposed              MetadataClassification = "METADATA_EXPOSED"
	ClassSyntheticCredentialsVerified MetadataClassification = "SYNTHETIC_CREDENTIALS_VERIFIED"
	ClassInconclusive                 MetadataClassification = "INCONCLUSIVE"
)

// Standard Cloud Metadata Endpoints
const (
	AWSMetadataBaseURL   = "http://169.254.169.254/latest/meta-data/"
	AWSTokenURL          = "http://169.254.169.254/latest/api/token"
	GCPMetadataBaseURL   = "http://metadata.google.internal/computeMetadata/v1/"
	AzureMetadataBaseURL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
)

var (
	cloudMetadataIPv4 = net.ParseIP("169.254.169.254")
	cloudMetadataIPv6 = net.ParseIP("fd00:ec2::254")
)

// isDeterministicSyntheticFixture validates that a target URL is strictly on local loopback
// with AllowLoopback enabled. Sensitive credential endpoints (STS secret keys, GCP access tokens,
// Azure MSI tokens) are NEVER queried against non-loopback or production hosts.
func isDeterministicSyntheticFixture(targetURL string, allowLoopback bool) bool {
	if !allowLoopback {
		return false
	}
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}
	return isLoopbackHost(u.Hostname())
}

// isStandardCloudMetadataEndpoint checks if rawURL points to standard cloud metadata targets.
func isStandardCloudMetadataEndpoint(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	return isProhibitedMetadataHost(u.Hostname())
}

// isProhibitedMetadataHost checks if a host is a recognized direct cloud metadata target.
func isProhibitedMetadataHost(host string) bool {
	if host == "169.254.169.254" || host == "metadata.google.internal" || host == "fd00:ec2::254" {
		return true
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.Equal(cloudMetadataIPv4) || ip.Equal(cloudMetadataIPv6) || ip.IsLinkLocalUnicast() {
			return true
		}
	}
	return false
}

// Default limits
const (
	DefaultMaxResponseSize int64         = 1024 * 1024 // 1 MB
	DefaultMetadataTimeout time.Duration = 10 * time.Second
	DefaultIMDSv2TTLSeconds              = 21600
)

// -------------------------------------------------------------------------
// Structured Synthetic Evidence Types (Safe by Design)
// -------------------------------------------------------------------------

// AWSSyntheticCredentials holds parsed AWS STS credentials for validation.
// Raw secrets are NEVER persisted to logs, reports, or evidence receipts.
type AWSSyntheticCredentials struct {
	Code            string    `json:"Code"`
	LastUpdated     time.Time `json:"LastUpdated,omitempty"`
	Type            string    `json:"Type"`
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration,omitempty"`
	RoleName        string    `json:"RoleName,omitempty"`
}

// AWSRedactedEvidence contains only safe, non-sensitive boolean flags and metadata.
type AWSRedactedEvidence struct {
	RoleName           string    `json:"role_name,omitempty"`
	HasAccessKeyID     bool      `json:"has_access_key_id"`
	HasSecretAccessKey bool      `json:"has_secret_access_key"`
	HasSessionToken    bool      `json:"has_session_token"`
	AccessKeyPrefix    string    `json:"access_key_prefix,omitempty"` // e.g. "ASIA..." (max 4 chars)
	Code               string    `json:"code,omitempty"`
	Type               string    `json:"type,omitempty"`
	Expiration         time.Time `json:"expiration,omitempty"`
	IsSynthetic        bool      `json:"is_synthetic"`
}

// -------------------------------------------------------------------------
// Synthetic Credential Validation & Memory Erasure Helpers (Safe by Design)
// -------------------------------------------------------------------------

var (
	// Real-looking AWS Access Key ID: 20 alphanumeric characters starting with AKIA, ASIA, ABIA, ACCA
	reRealAWSAccessKey = regexp.MustCompile(`^A[KSCB]IA[0-9A-Z]{16}$`)
	// Real-looking AWS Secret Key: 40 base64 chars without spaces/hyphens
	reRealAWSSecretKey = regexp.MustCompile(`^[A-Za-z0-9/+=]{40}$`)
	// Real-looking GCP OAuth2 access token: starts with ya29. followed by 30+ base64url characters
	reRealGCPToken = regexp.MustCompile(`^ya29\.[A-Za-z0-9_-]{30,}$`)
	// Real-looking Azure MSI Token: standard signed JWT structure (header.payload.sig)
	reRealAzureJWT = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// zeroBytes explicitly zeroes mutable byte slices to prevent secrets lingering in memory buffers.
//
// Go Memory-Erasure Limitation Notice:
// Go strings are immutable heap allocations managed by the Go runtime garbage collector. Assigning
// an empty string (s = "") re-points the string pointer but does not immediately zero the underlying
// heap array. To minimize risk, sensitive network response payloads are read into mutable byte slices
// ([]byte) and explicitly wiped with zeros via zeroBytes() immediately after synthetic parsing.
// Sensitive strings are NEVER retained in findings, logs, reports, or long-lived structs.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// isExplicitSyntheticField returns true if s explicitly contains approved synthetic fixture markers
// and does NOT match real production credential patterns.
func isExplicitSyntheticField(s string) bool {
	if s == "" {
		return false
	}
	upper := strings.ToUpper(s)
	return strings.Contains(upper, "SYNTHETIC") ||
		strings.Contains(upper, "MOCK") ||
		strings.Contains(upper, "FELIX-LAB") ||
		strings.Contains(upper, "FIXTURE")
}

// ValidateSyntheticAWSCredentials validates that EVERY field of an AWS STS credential response
// is explicitly synthetic, originates from an authorized fixture, and contains NO real-looking
// access keys, secret keys, or session tokens.
// If ANY single field is non-synthetic or matches real AWS patterns, it fails closed.
func ValidateSyntheticAWSCredentials(creds *AWSSyntheticCredentials) (bool, string) {
	if creds == nil {
		return false, "nil credentials"
	}

	// 1. Validate AccessKeyId
	if creds.AccessKeyID == "" {
		return false, "missing AccessKeyId"
	}
	if reRealAWSAccessKey.MatchString(creds.AccessKeyID) {
		return false, fmt.Sprintf("rejected: AccessKeyId %q matches real AWS IAM/STS access key pattern", creds.AccessKeyID)
	}
	if !isExplicitSyntheticField(creds.AccessKeyID) {
		return false, fmt.Sprintf("rejected: AccessKeyId %q lacks explicit synthetic fixture marker", creds.AccessKeyID)
	}

	// 2. Validate SecretAccessKey
	if creds.SecretAccessKey == "" {
		return false, "missing SecretAccessKey"
	}
	if reRealAWSSecretKey.MatchString(creds.SecretAccessKey) && !isExplicitSyntheticField(creds.SecretAccessKey) {
		return false, "rejected: SecretAccessKey matches real 40-character base64 secret pattern"
	}
	if !isExplicitSyntheticField(creds.SecretAccessKey) {
		return false, "rejected: SecretAccessKey lacks explicit synthetic fixture marker"
	}

	// 3. Validate Session Token (if present)
	if creds.Token != "" {
		if !isExplicitSyntheticField(creds.Token) {
			return false, "rejected: Token lacks explicit synthetic fixture marker"
		}
	}

	// 4. Validate RoleName
	if creds.RoleName != "" && !isExplicitSyntheticField(creds.RoleName) {
		return false, fmt.Sprintf("rejected: RoleName %q lacks explicit synthetic fixture marker", creds.RoleName)
	}

	return true, ""
}

// ValidateSyntheticGCPToken validates that the GCP default service account token is explicitly synthetic
// and does not match real Google OAuth2 access tokens.
func ValidateSyntheticGCPToken(token string, saEmail string) (bool, string) {
	if token == "" {
		return false, "missing access token"
	}
	if reRealGCPToken.MatchString(token) && !isExplicitSyntheticField(token) {
		return false, "rejected: GCP token matches real OAuth2 token format without synthetic marker"
	}
	if !isExplicitSyntheticField(token) {
		return false, "rejected: GCP token lacks explicit synthetic fixture marker"
	}
	if saEmail != "" && !isExplicitSyntheticField(saEmail) {
		return false, fmt.Sprintf("rejected: service account email %q lacks explicit synthetic marker", saEmail)
	}
	return true, ""
}

// ValidateSyntheticAzureToken validates that the Azure MSI access token is explicitly synthetic
// and does not match real production signed Azure JWTs without synthetic markers.
func ValidateSyntheticAzureToken(token string, vmID string, vmName string) (bool, string) {
	if token == "" {
		return false, "missing MSI token"
	}
	if reRealAzureJWT.MatchString(token) && !isExplicitSyntheticField(token) {
		return false, "rejected: Azure MSI token matches real JWT structure without synthetic marker"
	}
	if !isExplicitSyntheticField(token) {
		return false, "rejected: Azure MSI token lacks explicit synthetic fixture marker"
	}
	if vmName != "" && !isExplicitSyntheticField(vmName) && (vmID != "" && !isExplicitSyntheticField(vmID)) {
		return false, fmt.Sprintf("rejected: Azure VM metadata (%s / %s) lacks explicit synthetic marker", vmName, vmID)
	}
	return true, ""
}

// Redact converts raw parsed credentials into safe, non-sensitive evidence.
func (c *AWSSyntheticCredentials) Redact() *AWSRedactedEvidence {
	if c == nil {
		return nil
	}
	prefix := ""
	if len(c.AccessKeyID) >= 4 {
		prefix = c.AccessKeyID[:4]
	}
	isSynth, _ := ValidateSyntheticAWSCredentials(c)

	return &AWSRedactedEvidence{
		RoleName:           c.RoleName,
		HasAccessKeyID:     c.AccessKeyID != "",
		HasSecretAccessKey: c.SecretAccessKey != "",
		HasSessionToken:    c.Token != "",
		AccessKeyPrefix:    prefix,
		Code:               c.Code,
		Type:               c.Type,
		Expiration:         c.Expiration,
		IsSynthetic:        isSynth,
	}
}

// GCPSyntheticIdentity represents parsed GCP metadata service responses.
type GCPSyntheticIdentity struct {
	InstanceID     string `json:"instance_id,omitempty"`
	Zone           string `json:"zone,omitempty"`
	ServiceAccount string `json:"service_account,omitempty"`
	HasToken       bool   `json:"has_token"`
	TokenType      string `json:"token_type,omitempty"`
	ExpiresIn      int    `json:"expires_in,omitempty"`
	IsSynthetic    bool   `json:"is_synthetic"`
}

// AzureSyntheticIdentity represents parsed Azure metadata service responses.
type AzureSyntheticIdentity struct {
	Location       string `json:"location,omitempty"`
	Name           string `json:"name,omitempty"`
	OSType         string `json:"os_type,omitempty"`
	VMID           string `json:"vm_id,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	HasMSIToken    bool   `json:"has_msi_token"`
	Resource       string `json:"resource,omitempty"`
	IsSynthetic    bool   `json:"is_synthetic"`
}

// -------------------------------------------------------------------------
// Assessment Result Structure
// -------------------------------------------------------------------------

// MetadataProbeResult records the outcome of an individual metadata assessment.
type MetadataProbeResult struct {
	ID                 string                  `json:"id"`
	Provider           Provider                `json:"provider"`
	Classification     MetadataClassification  `json:"classification"`
	TargetEndpoint     string                  `json:"target_endpoint"`
	HTTPStatus         int                     `json:"http_status"`
	Reachable          bool                    `json:"reachable"`
	IMDSv2Required     bool                    `json:"imdsv2_required,omitempty"`
	IMDSv2TokenPassed  bool                    `json:"imdsv2_token_passed,omitempty"`
	RoleName           string                  `json:"role_name,omitempty"`
	EvidenceSummary    string                  `json:"evidence_summary"`
	EvidenceDetails    map[string]string       `json:"evidence_details"`
	AWSEvidence        *AWSRedactedEvidence    `json:"aws_evidence,omitempty"`
	GCPEvidence        *GCPSyntheticIdentity   `json:"gcp_evidence,omitempty"`
	AzureEvidence      *AzureSyntheticIdentity `json:"azure_evidence,omitempty"`
	Finding            *report.Finding         `json:"finding,omitempty"`
	DurationMs         float64                 `json:"duration_ms"`
	IsSSRFVerified     bool                    `json:"is_ssrf_verified"`
	OriginatingContext string                  `json:"originating_context,omitempty"`
	ExecutedAt         time.Time               `json:"executed_at"`
}

// -------------------------------------------------------------------------
// Metadata Engine Configuration
// -------------------------------------------------------------------------

// MetadataEngineOptions configures operational safety and transport boundaries.
type MetadataEngineOptions struct {
	Timeout         time.Duration
	MaxResponseSize int64
	AllowLoopback   bool // Permits loopback for local mock tests
	AllowPrivateIPs bool
	UserAgent       string
	Transport       http.RoundTripper
	ScopeCheck      func(targetURL string) bool
}

// MetadataEngine assesses cloud metadata exposure and verifies SSRF pathways.
type MetadataEngine struct {
	options MetadataEngineOptions
	client  *http.Client
	mu      sync.Mutex
}

// NewMetadataEngine constructs a safe, bounded metadata engine.
func NewMetadataEngine(opts MetadataEngineOptions) *MetadataEngine {
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultMetadataTimeout
	}
	if opts.MaxResponseSize <= 0 {
		opts.MaxResponseSize = DefaultMaxResponseSize
	}
	if opts.UserAgent == "" {
		opts.UserAgent = "Felix-CloudSec-MetadataEngine/3.0"
	}

	transport := opts.Transport
	if transport == nil {
		// Use SafeDialer to strictly prevent unauthorized SSRF, DNS rebinding, and external leaks
		safeOpts := crawler.SafeTransportOptions{
			Timeout:         opts.Timeout,
			AllowLoopback:   opts.AllowLoopback,
			AllowPrivateIPs: opts.AllowPrivateIPs,
		}
		transport = crawler.NewSafeTransport(safeOpts)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   opts.Timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("metadata probe: maximum redirect limit (5) reached")
			}
			// Enforce http or https scheme only (blocks file://, gopher://, ftp://, etc.)
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("metadata probe: redirect to unsupported scheme %q blocked", req.URL.Scheme)
			}
			// Enforce explicit scope policy on redirects
			if opts.ScopeCheck != nil && !opts.ScopeCheck(req.URL.String()) {
				return fmt.Errorf("metadata probe: redirect to %s blocked by scope policy", req.URL.String())
			}
			// Enforce redirect destination prohibitions
			if !opts.AllowLoopback && isLoopbackHost(req.URL.Hostname()) {
				return fmt.Errorf("metadata probe: redirect to loopback address %s blocked by security policy", req.URL.Hostname())
			}
			if isProhibitedMetadataHost(req.URL.Hostname()) {
				return fmt.Errorf("metadata probe: redirect to cloud metadata service %s blocked by security policy", req.URL.Hostname())
			}
			return nil
		},
	}

	return &MetadataEngine{
		options: opts,
		client:  client,
	}
}

// -------------------------------------------------------------------------
// AWS Metadata Assessment (IMDSv1 & IMDSv2)
// -------------------------------------------------------------------------

// AssessAWS assesses an AWS metadata service base endpoint (direct or mock).
func (e *MetadataEngine) AssessAWS(ctx context.Context, baseURL string) (*MetadataProbeResult, error) {
	start := time.Now()
	res := &MetadataProbeResult{
		ID:              uuid.New().String(),
		Provider:        ProviderAWS,
		TargetEndpoint:  baseURL,
		Classification:  ClassInconclusive,
		EvidenceDetails: make(map[string]string),
		ExecutedAt:      time.Now().UTC(),
	}

	if baseURL == "" {
		baseURL = AWSMetadataBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	// Validate scope
	if e.options.ScopeCheck != nil && !e.options.ScopeCheck(baseURL) {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("Scope refusal: target %s is not in authorized scope", baseURL)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Step 1: Probe IMDSv1 root (without token)
	metaURL := baseURL + "/"
	reqV1, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating IMDSv1 request: %w", err)
	}
	reqV1.Header.Set("User-Agent", e.options.UserAgent)

	respV1, bodyV1, err := e.doRequest(reqV1)
	if err != nil {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("IMDS endpoint not reachable: %v", err)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}
	res.Reachable = true
	res.HTTPStatus = respV1.StatusCode

	// Step 2: Test IMDSv2 Token Acquisition
	tokenURL := strings.Replace(baseURL, "/meta-data", "/api/token", 1)
	if !strings.Contains(tokenURL, "/api/token") {
		tokenURL = baseURL + "/../api/token"
	}
	tokenReq, err := http.NewRequestWithContext(ctx, http.MethodPut, tokenURL, nil)
	var imdsV2Token string
	if err == nil {
		tokenReq.Header.Set("User-Agent", e.options.UserAgent)
		tokenReq.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", strconv.Itoa(DefaultIMDSv2TTLSeconds))
		respToken, bodyToken, tokenErr := e.doRequest(tokenReq)
		if tokenErr == nil && respToken.StatusCode == http.StatusOK {
			imdsV2Token = strings.TrimSpace(string(bodyToken))
			res.EvidenceDetails["imdsv2_token_endpoint_accessible"] = "true"
		}
	}

	// Classify IMDSv2 Protected vs IMDSv1 Exposed
	if respV1.StatusCode == http.StatusUnauthorized || respV1.StatusCode == http.StatusForbidden {
		res.IMDSv2Required = true
		if imdsV2Token != "" {
			// Test if token unlocks metadata
			reqV2, _ := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
			reqV2.Header.Set("User-Agent", e.options.UserAgent)
			reqV2.Header.Set("X-aws-ec2-metadata-token", imdsV2Token)
			respV2, _, errV2 := e.doRequest(reqV2)
			if errV2 == nil && respV2.StatusCode == http.StatusOK {
				res.IMDSv2TokenPassed = true
				res.Classification = ClassIMDSv2Protected
				res.EvidenceSummary = "AWS IMDSv2 enforced: direct v1 access rejected (401/403); token request succeeded"
				res.EvidenceDetails["imdsv2_enforced"] = "true"
				res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
				return res, nil
			}
		}
		res.Classification = ClassAccessDenied
		res.EvidenceSummary = fmt.Sprintf("AWS IMDS access denied: HTTP %d", respV1.StatusCode)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Check if body reflects expected AWS metadata directory
	bodyStr := string(bodyV1)
	isAWSMetadata := strings.Contains(bodyStr, "instance-id") ||
		strings.Contains(bodyStr, "ami-id") ||
		strings.Contains(bodyStr, "iam/") ||
		strings.EqualFold(respV1.Header.Get("Server"), "EC2ws")

	if !isAWSMetadata && respV1.StatusCode == http.StatusOK {
		res.Classification = ClassReachable
		res.EvidenceSummary = "HTTP endpoint reachable but response does not match AWS metadata structure"
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Step 3: Check IAM Roles and Security Credentials
	res.Classification = ClassIMDSv1Exposed
	res.EvidenceSummary = "AWS IMDSv1 metadata accessible without token authentication"
	res.EvidenceDetails["imdsv1_exposed"] = "true"

	iamURL := baseURL + "/iam/security-credentials/"
	reqIAM, _ := http.NewRequestWithContext(ctx, http.MethodGet, iamURL, nil)
	reqIAM.Header.Set("User-Agent", e.options.UserAgent)
	respIAM, bodyIAM, errIAM := e.doRequest(reqIAM)

	if errIAM == nil && respIAM.StatusCode == http.StatusOK {
		roles := strings.Fields(strings.TrimSpace(string(bodyIAM)))
		if len(roles) > 0 {
			roleName := roles[0]
			res.RoleName = roleName
			res.EvidenceDetails["iam_role_found"] = roleName

			// Safe-by-Design Gate: ONLY query sensitive credential endpoints when target
			// is a deterministic synthetic test fixture on loopback.
			// Real AWS STS credentials are NEVER retrieved or accessed over the wire.
			if !isDeterministicSyntheticFixture(baseURL, e.options.AllowLoopback) {
				res.Classification = ClassIMDSv1Exposed
				res.EvidenceSummary = fmt.Sprintf("AWS IMDSv1 exposed IAM role %q (credential download restricted by safe-by-design policy: credentials restricted to local synthetic test fixtures)", roleName)
			} else {
				// Step 4: Parse synthetic STS credentials safely
				credURL := baseURL + "/iam/security-credentials/" + url.PathEscape(roleName)
				reqCred, _ := http.NewRequestWithContext(ctx, http.MethodGet, credURL, nil)
				reqCred.Header.Set("User-Agent", e.options.UserAgent)
				respCred, bodyCred, errCred := e.doRequest(reqCred)

				if errCred == nil && respCred.StatusCode == http.StatusOK {
					var creds AWSSyntheticCredentials
					if err := json.Unmarshal(bodyCred, &creds); err == nil {
						creds.RoleName = roleName
						if creds.AccessKeyID != "" && creds.SecretAccessKey != "" {
							isSynth, reason := ValidateSyntheticAWSCredentials(&creds)
							if !isSynth {
								res.Classification = ClassIMDSv1Exposed
								res.EvidenceSummary = fmt.Sprintf("AWS IMDSv1 exposed IAM role %q (%s)", roleName, reason)
							} else {
								res.Classification = ClassSyntheticCredentialsVerified
								res.AWSEvidence = creds.Redact()
								res.EvidenceSummary = fmt.Sprintf("AWS IMDSv1 exposed IAM role %q with verified STS credential structure", roleName)
								res.EvidenceDetails["synthetic_credentials_verified"] = "true"
							}
						}
					}
					// Zero out raw response bytes and clear struct handles
					zeroBytes(bodyCred)
					creds.SecretAccessKey = ""
					creds.Token = ""
				}
			}
		} else {
			res.Classification = ClassMetadataExposed
			res.EvidenceSummary = "AWS IMDSv1 metadata exposed (no active IAM roles attached)"
		}
	} else {
		res.Classification = ClassMetadataExposed
	}

	// Generate finding if exposed
	if res.Classification == ClassIMDSv1Exposed || res.Classification == ClassMetadataExposed || res.Classification == ClassSyntheticCredentialsVerified {
		res.Finding = createMetadataFinding(res)
	}

	res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
	return res, nil
}

// -------------------------------------------------------------------------
// GCP Metadata Assessment
// -------------------------------------------------------------------------

// AssessGCP assesses Google Cloud Platform instance metadata.
func (e *MetadataEngine) AssessGCP(ctx context.Context, baseURL string) (*MetadataProbeResult, error) {
	start := time.Now()
	res := &MetadataProbeResult{
		ID:              uuid.New().String(),
		Provider:        ProviderGCP,
		TargetEndpoint:  baseURL,
		Classification:  ClassInconclusive,
		EvidenceDetails: make(map[string]string),
		ExecutedAt:      time.Now().UTC(),
	}

	if baseURL == "" {
		baseURL = GCPMetadataBaseURL
	}
	baseURL = strings.TrimRight(baseURL, "/")

	if e.options.ScopeCheck != nil && !e.options.ScopeCheck(baseURL) {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("Scope refusal: target %s is not in authorized scope", baseURL)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Step 1: Probe WITHOUT required Metadata-Flavor header (should be 403 Forbidden on GCP)
	reqNoHeader, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating GCP request: %w", err)
	}
	reqNoHeader.Header.Set("User-Agent", e.options.UserAgent)
	respNoHeader, _, errNoHeader := e.doRequest(reqNoHeader)
	if errNoHeader != nil {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("GCP metadata endpoint not reachable: %v", errNoHeader)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}
	res.Reachable = true
	res.HTTPStatus = respNoHeader.StatusCode

	// Step 2: Probe WITH Metadata-Flavor: Google header
	reqGCP, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/", nil)
	reqGCP.Header.Set("User-Agent", e.options.UserAgent)
	reqGCP.Header.Set("Metadata-Flavor", "Google")
	respGCP, bodyGCP, errGCP := e.doRequest(reqGCP)

	if errGCP != nil {
		res.Classification = ClassAccessDenied
		res.EvidenceSummary = fmt.Sprintf("GCP metadata request with header failed: %v", errGCP)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	if respGCP.StatusCode == http.StatusForbidden {
		res.Classification = ClassAccessDenied
		res.EvidenceSummary = "GCP metadata request returned 403 Forbidden"
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Validate GCP response structure
	isFlavorResp := strings.EqualFold(respGCP.Header.Get("Metadata-Flavor"), "Google")
	bodyStr := string(bodyGCP)
	isGCP := isFlavorResp || strings.Contains(bodyStr, "instance/") || strings.Contains(bodyStr, "project/")

	if !isGCP || respGCP.StatusCode != http.StatusOK {
		res.Classification = ClassReachable
		res.EvidenceSummary = fmt.Sprintf("Endpoint reachable (status %d) but response does not match GCP metadata structure", respGCP.StatusCode)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	res.Classification = ClassMetadataExposed
	res.EvidenceSummary = "GCP instance metadata exposed via Metadata-Flavor: Google header"
	res.EvidenceDetails["metadata_flavor_accepted"] = "true"

	// Step 3: Inspect Service Account metadata and tokens
	saIdentity := &GCPSyntheticIdentity{}

	// Query service account email (identity, non-secret)
	saEmailURL := baseURL + "/instance/service-accounts/default/email"
	reqEmail, _ := http.NewRequestWithContext(ctx, http.MethodGet, saEmailURL, nil)
	reqEmail.Header.Set("User-Agent", e.options.UserAgent)
	reqEmail.Header.Set("Metadata-Flavor", "Google")
	respEmail, bodyEmail, errEmail := e.doRequest(reqEmail)
	if errEmail == nil && respEmail.StatusCode == http.StatusOK {
		saIdentity.ServiceAccount = strings.TrimSpace(string(bodyEmail))
		res.EvidenceDetails["service_account_email"] = saIdentity.ServiceAccount
	}

	// Safe-by-Design Gate: ONLY query service account token when target is a deterministic
	// synthetic test fixture on loopback. Real GCP access tokens are NEVER retrieved over the wire.
	if !isDeterministicSyntheticFixture(baseURL, e.options.AllowLoopback) {
		res.Classification = ClassMetadataExposed
		res.EvidenceSummary = "GCP instance metadata exposed via Metadata-Flavor: Google header (credential token query restricted by safe-by-design policy)"
	} else {
		saTokenURL := baseURL + "/instance/service-accounts/default/token"
		reqSAToken, _ := http.NewRequestWithContext(ctx, http.MethodGet, saTokenURL, nil)
		reqSAToken.Header.Set("User-Agent", e.options.UserAgent)
		reqSAToken.Header.Set("Metadata-Flavor", "Google")
		respToken, bodyToken, errToken := e.doRequest(reqSAToken)

		if errToken == nil && respToken.StatusCode == http.StatusOK {
			var tokenData struct {
				AccessToken string `json:"access_token"`
				ExpiresIn   int    `json:"expires_in"`
				TokenType   string `json:"token_type"`
			}
			if err := json.Unmarshal(bodyToken, &tokenData); err == nil && tokenData.AccessToken != "" {
				isSynth, reason := ValidateSyntheticGCPToken(tokenData.AccessToken, saIdentity.ServiceAccount)
				if !isSynth {
					res.Classification = ClassMetadataExposed
					res.EvidenceSummary = fmt.Sprintf("GCP metadata exposed default service account (%s)", reason)
				} else {
					saIdentity.HasToken = true
					saIdentity.TokenType = tokenData.TokenType
					saIdentity.ExpiresIn = tokenData.ExpiresIn
					saIdentity.IsSynthetic = true
					res.Classification = ClassSyntheticCredentialsVerified
					res.EvidenceSummary = "GCP metadata exposed default service account OAuth2 token"
					res.EvidenceDetails["service_account_token_verified"] = "true"
				}
				zeroBytes(bodyToken)
				tokenData.AccessToken = ""
			}
		}
	}

	res.GCPEvidence = saIdentity
	if res.Classification == ClassMetadataExposed || res.Classification == ClassSyntheticCredentialsVerified {
		res.Finding = createMetadataFinding(res)
	}

	res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
	return res, nil
}

// -------------------------------------------------------------------------
// Azure Metadata Assessment
// -------------------------------------------------------------------------

// AssessAzure assesses Azure Instance Metadata Service (IMDS).
func (e *MetadataEngine) AssessAzure(ctx context.Context, baseURL string) (*MetadataProbeResult, error) {
	start := time.Now()
	res := &MetadataProbeResult{
		ID:              uuid.New().String(),
		Provider:        ProviderAzure,
		TargetEndpoint:  baseURL,
		Classification:  ClassInconclusive,
		EvidenceDetails: make(map[string]string),
		ExecutedAt:      time.Now().UTC(),
	}

	if baseURL == "" {
		baseURL = AzureMetadataBaseURL
	}

	// Ensure api-version parameter is present
	if !strings.Contains(baseURL, "api-version=") {
		if strings.Contains(baseURL, "?") {
			baseURL += "&api-version=2021-02-01"
		} else {
			baseURL += "?api-version=2021-02-01"
		}
	}

	if e.options.ScopeCheck != nil && !e.options.ScopeCheck(baseURL) {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("Scope refusal: target %s is not in authorized scope", baseURL)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Step 1: Probe WITHOUT Metadata: true header (Azure should return 400 Bad Request)
	reqNoHeader, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating Azure request: %w", err)
	}
	reqNoHeader.Header.Set("User-Agent", e.options.UserAgent)
	respNoHeader, _, errNoHeader := e.doRequest(reqNoHeader)
	if errNoHeader != nil {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("Azure metadata endpoint not reachable: %v", errNoHeader)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}
	res.Reachable = true
	res.HTTPStatus = respNoHeader.StatusCode

	// Step 2: Probe WITH Metadata: true header
	reqAzure, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	reqAzure.Header.Set("User-Agent", e.options.UserAgent)
	reqAzure.Header.Set("Metadata", "true")
	respAzure, bodyAzure, errAzure := e.doRequest(reqAzure)

	if errAzure != nil {
		res.Classification = ClassAccessDenied
		res.EvidenceSummary = fmt.Sprintf("Azure metadata request failed: %v", errAzure)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	if respAzure.StatusCode == http.StatusForbidden {
		res.Classification = ClassAccessDenied
		res.EvidenceSummary = "Azure metadata request returned 403 Forbidden"
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	if respAzure.StatusCode != http.StatusOK {
		res.Classification = ClassReachable
		res.EvidenceSummary = fmt.Sprintf("Azure metadata returned status %d", respAzure.StatusCode)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Parse compute metadata
	var azureDoc struct {
		Compute struct {
			Location       string `json:"location"`
			Name           string `json:"name"`
			OSType         string `json:"osType"`
			VMID           string `json:"vmId"`
			SubscriptionID string `json:"subscriptionId"`
		} `json:"compute"`
	}

	azureEvidence := &AzureSyntheticIdentity{}
	if err := json.Unmarshal(bodyAzure, &azureDoc); err == nil && azureDoc.Compute.VMID != "" {
		azureEvidence.Location = azureDoc.Compute.Location
		azureEvidence.Name = azureDoc.Compute.Name
		azureEvidence.OSType = azureDoc.Compute.OSType
		azureEvidence.VMID = azureDoc.Compute.VMID
		azureEvidence.SubscriptionID = azureDoc.Compute.SubscriptionID
		azureEvidence.IsSynthetic = strings.Contains(azureDoc.Compute.Name, "synthetic") ||
			strings.Contains(azureDoc.Compute.VMID, "11111111")
		res.Classification = ClassMetadataExposed
		res.EvidenceSummary = fmt.Sprintf("Azure instance compute metadata exposed for VM %q (vmId: %s)", azureDoc.Compute.Name, azureDoc.Compute.VMID)
		res.EvidenceDetails["azure_vm_name"] = azureDoc.Compute.Name
		res.EvidenceDetails["azure_vm_id"] = azureDoc.Compute.VMID
	} else {
		res.Classification = ClassReachable
		res.EvidenceSummary = "Azure endpoint returned 200 OK but JSON did not contain standard compute metadata schema"
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// Step 3: Probe Managed Identity OAuth2 token endpoint
	// Safe-by-Design Gate: ONLY query MSI token when target is a deterministic
	// synthetic test fixture on loopback. Real Azure MSI tokens are NEVER retrieved over the wire.
	if !isDeterministicSyntheticFixture(baseURL, e.options.AllowLoopback) {
		res.Classification = ClassMetadataExposed
		res.EvidenceSummary = fmt.Sprintf("Azure instance compute metadata exposed for VM %q (MSI token query restricted by safe-by-design policy)", azureDoc.Compute.Name)
	} else {
		parsedURL, _ := url.Parse(baseURL)
		tokenURL := fmt.Sprintf("%s://%s/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
			parsedURL.Scheme, parsedURL.Host)
		reqToken, _ := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
		reqToken.Header.Set("User-Agent", e.options.UserAgent)
		reqToken.Header.Set("Metadata", "true")
		respToken, bodyToken, errToken := e.doRequest(reqToken)

		if errToken == nil && respToken.StatusCode == http.StatusOK {
			var tokenData struct {
				AccessToken string `json:"access_token"`
				Resource    string `json:"resource"`
				TokenType   string `json:"token_type"`
			}
			if err := json.Unmarshal(bodyToken, &tokenData); err == nil && tokenData.AccessToken != "" {
				isSynth, reason := ValidateSyntheticAzureToken(tokenData.AccessToken, azureEvidence.VMID, azureEvidence.Name)
				if !isSynth {
					res.Classification = ClassMetadataExposed
					res.EvidenceSummary = fmt.Sprintf("Azure instance metadata exposed for VM %q (%s)", azureDoc.Compute.Name, reason)
				} else {
					azureEvidence.HasMSIToken = true
					azureEvidence.Resource = tokenData.Resource
					res.Classification = ClassSyntheticCredentialsVerified
					res.EvidenceSummary = fmt.Sprintf("Azure instance metadata exposed managed identity token for resource %s", tokenData.Resource)
					res.EvidenceDetails["managed_identity_token_verified"] = "true"
				}
				zeroBytes(bodyToken)
				tokenData.AccessToken = ""
			}
		}
	}

	res.AzureEvidence = azureEvidence
	if res.Classification == ClassMetadataExposed || res.Classification == ClassSyntheticCredentialsVerified {
		res.Finding = createMetadataFinding(res)
	}

	res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
	return res, nil
}

// -------------------------------------------------------------------------
// SSRF Verification Integration (Section 4)
// -------------------------------------------------------------------------

// SSRFMetadataTest describes an injection test against an SSRF-capable endpoint.
type SSRFMetadataTest struct {
	VulnerableURL string            `json:"vulnerable_url"` // e.g. "http://target.local/preview?url="
	ParameterName string            `json:"parameter_name"` // e.g. "url"
	HTTPMethod    string            `json:"http_method"`    // GET or POST
	Headers       map[string]string `json:"headers,omitempty"`
	TargetProvider Provider         `json:"target_provider"`
	MockBaseURL   string            `json:"mock_base_url,omitempty"` // Local mock for testing
}

// AssessSSRF routes eligible SSRF input points into the cloud metadata verification pipeline.
func (e *MetadataEngine) AssessSSRF(ctx context.Context, test SSRFMetadataTest) (*MetadataProbeResult, error) {
	start := time.Now()
	res := &MetadataProbeResult{
		ID:                 uuid.New().String(),
		Provider:           test.TargetProvider,
		Classification:     ClassInconclusive,
		EvidenceDetails:    make(map[string]string),
		IsSSRFVerified:     true,
		OriginatingContext: fmt.Sprintf("%s [%s %s]", test.VulnerableURL, test.HTTPMethod, test.ParameterName),
		ExecutedAt:         time.Now().UTC(),
	}

	// 1. Enforce explicit scope check on vulnerable target URL
	if e.options.ScopeCheck != nil && !e.options.ScopeCheck(test.VulnerableURL) {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("Scope refusal: target %s is not in authorized scope", test.VulnerableURL)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	// 2. Determine upstream metadata URL to inject
	var upstreamMetadataURL string
	if test.MockBaseURL != "" {
		// Mock base URL must not target arbitrary external hosts
		if e.options.ScopeCheck != nil && !e.options.ScopeCheck(test.MockBaseURL) {
			res.Classification = ClassNotReachable
			res.EvidenceSummary = fmt.Sprintf("Scope refusal: mock base URL %s is not in authorized scope", test.MockBaseURL)
			res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
			return res, nil
		}
		if !isDeterministicSyntheticFixture(test.MockBaseURL, e.options.AllowLoopback) &&
			!isStandardCloudMetadataEndpoint(test.MockBaseURL) {
			res.Classification = ClassNotReachable
			res.EvidenceSummary = fmt.Sprintf("Security refusal: mock base URL %s is not an authorized loopback or cloud metadata fixture", test.MockBaseURL)
			res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
			return res, nil
		}
		upstreamMetadataURL = test.MockBaseURL
	} else {
		switch test.TargetProvider {
		case ProviderAWS:
			upstreamMetadataURL = AWSMetadataBaseURL
		case ProviderGCP:
			upstreamMetadataURL = GCPMetadataBaseURL
		case ProviderAzure:
			upstreamMetadataURL = AzureMetadataBaseURL
		default:
			upstreamMetadataURL = AWSMetadataBaseURL
		}
	}

	res.TargetEndpoint = upstreamMetadataURL

	// 2. Build injection URL
	u, err := url.Parse(test.VulnerableURL)
	if err != nil {
		return nil, fmt.Errorf("invalid vulnerable URL %q: %w", test.VulnerableURL, err)
	}

	q := u.Query()
	q.Set(test.ParameterName, upstreamMetadataURL)
	u.RawQuery = q.Encode()

	// 3. Dispatch SSRF probe through vulnerable target
	req, err := http.NewRequestWithContext(ctx, test.HTTPMethod, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed creating SSRF probe request: %w", err)
	}
	req.Header.Set("User-Agent", e.options.UserAgent)
	for k, v := range test.Headers {
		req.Header.Set(k, v)
	}

	resp, bodyBytes, err := e.doRequest(req)
	if err != nil {
		res.Classification = ClassNotReachable
		res.EvidenceSummary = fmt.Sprintf("SSRF injection endpoint failed to contact metadata: %v", err)
		res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
		return res, nil
	}

	res.HTTPStatus = resp.StatusCode
	res.Reachable = true
	bodyStr := string(bodyBytes)

	// 4. Classify response according to provider
	switch test.TargetProvider {
	case ProviderAWS:
		if strings.Contains(bodyStr, "instance-id") || strings.Contains(bodyStr, "iam/") {
			res.Classification = ClassIMDSv1Exposed
			res.EvidenceSummary = fmt.Sprintf("SSRF vector %s successfully retrieved AWS IMDS metadata", test.ParameterName)
			res.EvidenceDetails["ssrf_parameter"] = test.ParameterName
			res.EvidenceDetails["aws_metadata_leak"] = "true"
		} else if strings.Contains(bodyStr, "Unauthorized") || resp.StatusCode == http.StatusUnauthorized {
			res.Classification = ClassIMDSv2Protected
			res.EvidenceSummary = "SSRF target returned 401 Unauthorized; IMDSv2 token enforcement active"
		} else if resp.StatusCode == http.StatusForbidden {
			res.Classification = ClassAccessDenied
			res.EvidenceSummary = "SSRF target returned 403 Forbidden on metadata probe"
		} else {
			res.Classification = ClassReachable
			res.EvidenceSummary = "SSRF target responded but did not leak recognized AWS metadata"
		}

	case ProviderGCP:
		if strings.Contains(bodyStr, "instance/") || strings.Contains(bodyStr, "project/") {
			res.Classification = ClassMetadataExposed
			res.EvidenceSummary = fmt.Sprintf("SSRF vector %s successfully retrieved GCP instance metadata", test.ParameterName)
			res.EvidenceDetails["gcp_metadata_leak"] = "true"
		} else if resp.StatusCode == http.StatusForbidden {
			res.Classification = ClassAccessDenied
			res.EvidenceSummary = "GCP metadata probe rejected with 403 Forbidden"
		} else {
			res.Classification = ClassReachable
			res.EvidenceSummary = "SSRF target responded without GCP metadata reflection"
		}

	case ProviderAzure:
		if strings.Contains(bodyStr, "compute") && strings.Contains(bodyStr, "vmId") {
			res.Classification = ClassMetadataExposed
			res.EvidenceSummary = fmt.Sprintf("SSRF vector %s successfully retrieved Azure instance compute metadata", test.ParameterName)
			res.EvidenceDetails["azure_metadata_leak"] = "true"
		} else if resp.StatusCode == http.StatusBadRequest || resp.StatusCode == http.StatusForbidden {
			res.Classification = ClassAccessDenied
			res.EvidenceSummary = fmt.Sprintf("Azure metadata probe rejected with HTTP %d", resp.StatusCode)
		} else {
			res.Classification = ClassReachable
			res.EvidenceSummary = "SSRF target responded without Azure compute metadata reflection"
		}
	}

	if res.Classification == ClassIMDSv1Exposed || res.Classification == ClassMetadataExposed || res.Classification == ClassSyntheticCredentialsVerified {
		res.Finding = createMetadataFinding(res)
	}

	res.DurationMs = float64(time.Since(start).Nanoseconds()) / 1e6
	return res, nil
}

// -------------------------------------------------------------------------
// Helper: doRequest with bounded reading and context safety
// -------------------------------------------------------------------------

func (e *MetadataEngine) doRequest(req *http.Request) (*http.Response, []byte, error) {
	resp, err := e.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	// Enforce strict response size limit to prevent memory exhaustion
	limitReader := io.LimitReader(resp.Body, e.options.MaxResponseSize+1)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return resp, nil, err
	}
	if int64(len(body)) > e.options.MaxResponseSize {
		return resp, nil, fmt.Errorf("response exceeded maximum size limit (%d bytes)", e.options.MaxResponseSize)
	}

	return resp, body, nil
}

// -------------------------------------------------------------------------
// Helper: createMetadataFinding
// -------------------------------------------------------------------------

func createMetadataFinding(r *MetadataProbeResult) *report.Finding {
	sanitizedEndpoint := SanitizeURL(r.TargetEndpoint)
	fpData := fmt.Sprintf("%s|CLOUD_METADATA|%s|%s", r.Provider, r.Classification, sanitizedEndpoint)
	hash := sha256.Sum256([]byte(fpData))
	fingerprint := fmt.Sprintf("metadata-%s", hex.EncodeToString(hash[:8]))

	severity := report.SeverityHigh
	if r.Classification == ClassSyntheticCredentialsVerified {
		severity = report.SeverityCritical
	}

	title := fmt.Sprintf("Cloud Metadata Exposure: %s (%s)", r.Provider, r.Classification)

	return &report.Finding{
		ID:          uuid.New().String(),
		Title:       title,
		Category:    fmt.Sprintf("CLOUD_SECURITY / %s_METADATA", r.Provider),
		Severity:    severity,
		Confidence:  report.ConfidenceHigh,
		Target:      sanitizedEndpoint,
		Endpoint:    sanitizedEndpoint,
		Method:      "METADATA_PROBE",
		Description: fmt.Sprintf("[%s Metadata Assessment] %s", r.Provider, r.EvidenceSummary),
		Evidence:    RedactText(r.EvidenceSummary),
		EvidenceDetails: report.EvidenceDetails{
			Observation:     RedactText(r.EvidenceSummary),
			Location:        sanitizedEndpoint,
			DetectionMethod: "METADATA_EXPLOITATION_ENGINE",
			Details: func() map[string]string {
				d := map[string]string{
					"provider":       string(r.Provider),
					"classification": string(r.Classification),
					"status_code":    strconv.Itoa(r.HTTPStatus),
					"fingerprint":    fingerprint,
				}
				for k, v := range r.EvidenceDetails {
					d[k] = RedactText(v)
				}
				if r.AWSEvidence != nil {
					d["role_name"] = r.AWSEvidence.RoleName
					d["has_access_key"] = strconv.FormatBool(r.AWSEvidence.HasAccessKeyID)
					d["has_secret_key"] = strconv.FormatBool(r.AWSEvidence.HasSecretAccessKey)
					d["has_token"] = strconv.FormatBool(r.AWSEvidence.HasSessionToken)
					d["is_synthetic"] = strconv.FormatBool(r.AWSEvidence.IsSynthetic)
				}
				if r.GCPEvidence != nil {
					d["service_account"] = r.GCPEvidence.ServiceAccount
					d["has_token"] = strconv.FormatBool(r.GCPEvidence.HasToken)
					d["is_synthetic"] = strconv.FormatBool(r.GCPEvidence.IsSynthetic)
				}
				if r.AzureEvidence != nil {
					d["azure_vm_name"] = r.AzureEvidence.Name
					d["azure_vm_id"] = r.AzureEvidence.VMID
					d["has_msi_token"] = strconv.FormatBool(r.AzureEvidence.HasMSIToken)
					d["is_synthetic"] = strconv.FormatBool(r.AzureEvidence.IsSynthetic)
				}
				return d
			}(),
		},
		Remediation: func() string {
			switch r.Provider {
			case ProviderAWS:
				return "Enforce IMDSv2 exclusively across all EC2 instances using 'aws ec2 modify-instance-metadata-options --http-tokens required --http-endpoint enabled'. Disable IMDSv1."
			case ProviderGCP:
				return "Ensure application HTTP clients do not forward untrusted user input to http://metadata.google.internal and validate the Metadata-Flavor header."
			case ProviderAzure:
				return "Restrict SSRF pathways, disable unused Managed Identities, and apply Azure Network Security Groups to isolate internal metadata queries."
			default:
				return "Enforce strict URL allowlists and apply SSRF egress filtering."
			}
		}(),
	}
}
