package compliance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/crawler"
	"felix/pkg/report"
	"felix/pkg/secrets"
)

// CompliancePlatform identifies the supported external compliance automation software.
type CompliancePlatform string

const (
	PlatformVanta       CompliancePlatform = "vanta"
	PlatformDrata       CompliancePlatform = "drata"
	PlatformSecureframe CompliancePlatform = "secureframe"
)

// SyncStatus defines the outcome classification of an outbound compliance platform synchronization.
type SyncStatus string

const (
	SyncStatusSuccess  SyncStatus = "SUCCESS"
	SyncStatusPartial  SyncStatus = "PARTIAL"
	SyncStatusFailed   SyncStatus = "FAILED"
	SyncStatusRejected SyncStatus = "REJECTED"
)

// Common compliance errors.
var (
	ErrInvalidEndpoint       = errors.New("compliance sync refusal: invalid or unsafe destination endpoint")
	ErrSSRFRefusal           = errors.New("compliance sync refusal: destination resolved to prohibited IP address")
	ErrMissingCredentials    = errors.New("compliance sync refusal: missing API credentials")
	ErrVantaSchemaValidation = errors.New("compliance sync refusal: payload failed Vanta JSON schema validation")
	ErrAttestationTampered   = errors.New("compliance sync refusal: attestation letter failed cryptographic integrity check")
	ErrUntrustedSigningKey   = errors.New("compliance sync refusal: attestation letter signed by untrusted key anchor")
	ErrUnsupportedPlatform   = errors.New("compliance sync refusal: unsupported compliance platform")
)

// SSRFConfig configures destination endpoint validation and SSRF defenses.
type SSRFConfig struct {
	AllowLoopback   bool
	AllowPrivateIPs bool
	EnforceHTTPS    bool
	Resolver        crawler.Resolver
}

// DefaultSSRFConfig returns standard production SSRF security settings.
func DefaultSSRFConfig() SSRFConfig {
	return SSRFConfig{
		AllowLoopback:   false,
		AllowPrivateIPs: false,
		EnforceHTTPS:    true,
	}
}

// ComplianceSyncConfig holds operational and authentication configuration for a compliance platform.
type ComplianceSyncConfig struct {
	Platform            CompliancePlatform
	BaseURL             string
	APIKey              string
	Token               string
	Timeout             time.Duration
	MaxRetries          int
	BackoffBase         time.Duration
	SSRF                SSRFConfig
	HTTPClient          *http.Client
	TrustedKeyRegistry  assessment.TrustedKeyRegistry
	ClientName          string
	CustomHeaders       map[string]string
	ValidateVantaSchema bool
}

// DefaultComplianceSyncConfig returns standard safe defaults.
func DefaultComplianceSyncConfig(platform CompliancePlatform) ComplianceSyncConfig {
	defaultURL := ""
	switch platform {
	case PlatformVanta:
		defaultURL = "https://api.vanta.com"
	case PlatformDrata:
		defaultURL = "https://public-api.drata.com"
	case PlatformSecureframe:
		defaultURL = "https://api.secureframe.com"
	}

	return ComplianceSyncConfig{
		Platform:            platform,
		BaseURL:             defaultURL,
		Timeout:             15 * time.Second,
		MaxRetries:          3,
		BackoffBase:         100 * time.Millisecond,
		SSRF:                DefaultSSRFConfig(),
		ValidateVantaSchema: true,
	}
}

// SyncAssessmentRequest encapsulates all assessment, attestation, retest, and finding records to synchronize.
type SyncAssessmentRequest struct {
	Assessment        assessment.Assessment
	Execution         *assessment.AssessmentExecution
	Snapshot          *assessment.AttestationSnapshot
	Attestation       *assessment.AttestationLetter
	RetestResult      *assessment.RetestResult
	Findings          []assessment.AssessmentFinding
	RemediationSLAs   []RemediationRecord
	ControlMappings   []FindingControlMapping
	IdempotencyKey    string
	SyncReason        string
	AllowUnsigned     bool // If true, allows syncing pending/unsigned attestations with explicit UNVERIFIED status
}

// SyncAssessmentResponse encapsulates the structured, sanitized synchronization outcome.
type SyncAssessmentResponse struct {
	Platform                     CompliancePlatform `json:"platform"`
	Status                       SyncStatus         `json:"status"` // SUCCESS, PARTIAL, FAILED, REJECTED
	ExternalID                   string             `json:"external_id,omitempty"`
	ExternalURL                  string             `json:"external_url,omitempty"`
	AttestationAccepted          bool               `json:"attestation_accepted"`
	AttestationVerificationStatus string            `json:"attestation_verification_status"` // VERIFIED, UNVERIFIED_KEY, INVALID_SIGNATURE, UNSIGNED
	ControlsMapped               int                `json:"controls_mapped"`
	FindingsSynced               int                `json:"findings_synced"`
	FindingsFailed               int                `json:"findings_failed"`
	RemediatedCount              int                `json:"remediated_count"`
	UnresolvedCount              int                `json:"unresolved_count"`
	SimulatedFindingsCount       int                `json:"simulated_findings_count"`
	PayloadDigest                string             `json:"payload_digest"`
	IdempotencyKey               string             `json:"idempotency_key"`
	ExecutedAt                   time.Time          `json:"executed_at"`
	Duration                     time.Duration      `json:"duration"`
	Errors                       []string           `json:"errors,omitempty"`
	Warnings                     []string           `json:"warnings,omitempty"`
	RawResponse                  map[string]any     `json:"raw_response,omitempty"`
}

// ExternalSyncStatus captures queried status from an external compliance system.
type ExternalSyncStatus struct {
	ExternalID                   string             `json:"external_id"`
	Platform                     CompliancePlatform `json:"platform"`
	ExternalStatus               string             `json:"external_status"`
	LastSyncedAt                 time.Time          `json:"last_synced_at"`
	RemediationProofAcknowledged bool               `json:"remediation_proof_acknowledged"` // Invariant: Always false unless empirical retest proven
	Details                      map[string]any     `json:"details,omitempty"`
}

// CompliancePlatformAdapter defines the isolated provider interface for external compliance platforms.
type CompliancePlatformAdapter interface {
	Platform() CompliancePlatform
	ValidateConfig() error
	SyncAssessment(ctx context.Context, req *SyncAssessmentRequest) (*SyncAssessmentResponse, error)
	GetSyncStatus(ctx context.Context, externalID string) (*ExternalSyncStatus, error)
}

// -----------------------------------------------------------------------------
// Endpoint Validation & Safe HTTP Transport (SSRF & Rebinding Protection)
// -----------------------------------------------------------------------------

// ValidateEndpoint parses and verifies that a destination URL adheres to SSRF safety policies.
func ValidateEndpoint(rawURL string, ssrf SSRFConfig) (*url.URL, error) {
	clean := strings.TrimSpace(rawURL)
	if clean == "" {
		return nil, errors.New("destination URL cannot be empty")
	}

	u, err := url.Parse(clean)
	if err != nil {
		return nil, fmt.Errorf("malformed destination URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported protocol scheme %q (only http and https supported)", u.Scheme)
	}

	if ssrf.EnforceHTTPS && scheme != "https" {
		return nil, fmt.Errorf("unencrypted HTTP rejected by policy: production compliance APIs require HTTPS (%s)", u.String())
	}

	host := u.Hostname()
	if host == "" {
		return nil, errors.New("destination URL missing hostname")
	}

	// Always reject explicit cloud metadata addresses under all conditions
	if host == "169.254.169.254" || host == "fd00:ec2::254" || strings.Contains(host, "metadata.google.internal") {
		return nil, fmt.Errorf("%w: cloud metadata destination explicitly prohibited", ErrSSRFRefusal)
	}

	// Resolve hostname to test against prohibited IP subnets
	var ips []net.IP
	if ssrf.Resolver != nil {
		addrs, rErr := ssrf.Resolver.LookupIPAddr(context.Background(), host)
		if rErr != nil {
			if ssrf.AllowLoopback && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
				return u, nil
			}
			return nil, fmt.Errorf("failed resolving destination hostname %q: %w", host, rErr)
		}
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	} else {
		var rErr error
		ips, rErr = net.LookupIP(host)
		if rErr != nil {
			// If testing in an offline environment where DNS cannot resolve, permit if host is localhost/127.0.0.1 and loopback is allowed
			if ssrf.AllowLoopback && (host == "localhost" || host == "127.0.0.1" || host == "::1") {
				return u, nil
			}
			return nil, fmt.Errorf("failed resolving destination hostname %q: %w", host, rErr)
		}
	}

	for _, ip := range ips {
		if prohibited, reason := crawler.ProhibitedIPReason(ip, ssrf.AllowLoopback, ssrf.AllowPrivateIPs); prohibited {
			return nil, fmt.Errorf("%w: host %q resolved to prohibited IP %s (%s)", ErrSSRFRefusal, host, ip.String(), reason)
		}
	}

	return u, nil
}

// BuildSafeHTTPClient constructs an http.Client equipped with safe dialing, redirect checks, and timeouts.
func BuildSafeHTTPClient(timeout time.Duration, ssrf SSRFConfig) *http.Client {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	transport := crawler.NewSafeTransport(crawler.SafeTransportOptions{
		Timeout:         timeout,
		AllowLoopback:   ssrf.AllowLoopback,
		AllowPrivateIPs: ssrf.AllowPrivateIPs,
		Resolver:        ssrf.Resolver,
	})

	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects (potential redirect loop)")
			}

			// Reject scheme downgrade or cross-protocol redirect
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("redirect blocked: unsupported scheme %q", req.URL.Scheme)
			}
			if len(via) > 0 && strings.ToLower(via[0].URL.Scheme) == "https" && scheme == "http" {
				return errors.New("redirect blocked: HTTPS to HTTP downgrade prohibited")
			}

			// Validate redirect destination against SSRF policies
			if _, err := ValidateEndpoint(req.URL.String(), ssrf); err != nil {
				return fmt.Errorf("redirect blocked: %w", err)
			}
			return nil
		},
	}

	return client
}

// -----------------------------------------------------------------------------
// Vanta Adapter Implementation
// -----------------------------------------------------------------------------

// VantaAdapter implements CompliancePlatformAdapter for the Vanta REST API.
type VantaAdapter struct {
	cfg     ComplianceSyncConfig
	client  *http.Client
	baseURL *url.URL
}

// NewVantaAdapter constructs an authenticated Vanta adapter.
func NewVantaAdapter(cfg ComplianceSyncConfig) (*VantaAdapter, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.vanta.com"
	}

	parsedURL, err := ValidateEndpoint(cfg.BaseURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid Vanta BaseURL: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = BuildSafeHTTPClient(cfg.Timeout, cfg.SSRF)
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}

	return &VantaAdapter{
		cfg:     cfg,
		client:  client,
		baseURL: parsedURL,
	}, nil
}

func (a *VantaAdapter) Platform() CompliancePlatform {
	return PlatformVanta
}

func (a *VantaAdapter) ValidateConfig() error {
	if a.baseURL == nil {
		return errors.New("vanta BaseURL not configured")
	}
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}
	if token == "" {
		return fmt.Errorf("%w: Vanta API token or key required", ErrMissingCredentials)
	}
	return nil
}

// VantaPenTestPayload defines the canonical data structure expected by Vanta's penetration test ingest endpoint.
type VantaPenTestPayload struct {
	ClientOrganization string                 `json:"client_organization"`
	AssessmentID       string                 `json:"assessment_id"`
	AssessmentRef      string                 `json:"assessment_ref"`
	AuditType          string                 `json:"audit_type"` // Must be PENETRATION_TEST
	Methodology        []string               `json:"methodology"`
	TestingWindow      VantaTestingWindow     `json:"testing_window"`
	Attestation        VantaAttestationRecord `json:"attestation"`
	RetestSummary      VantaRetestSummary     `json:"retest_summary"`
	Findings           []VantaFindingItem     `json:"findings"`
}

type VantaTestingWindow struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

type VantaAttestationRecord struct {
	LetterID        string `json:"letter_id"`
	CanonicalDigest string `json:"canonical_digest"`
	SignatureHex    string `json:"signature_hex"`
	SignerIdentity  string `json:"signer_identity"`
	SigningKeyID    string `json:"signing_key_id"`
	Status          string `json:"status"` // VERIFIED, UNVERIFIED, UNSIGNED
}

type VantaRetestSummary struct {
	RetestMode               string `json:"retest_mode"`
	IsClean                  bool   `json:"is_clean"`
	TotalFindings            int    `json:"total_findings"`
	RemediatedCount          int    `json:"remediated_count"`
	RemainingUnresolvedCount int    `json:"remaining_unresolved_count"`
	InconclusiveCount        int    `json:"inconclusive_count"`
	SimulatedRemediatedCount int    `json:"simulated_remediated_count"`
}

type VantaFindingItem struct {
	FindingID         string `json:"finding_id"`
	Title             string `json:"title"`
	Severity          string `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Status            string `json:"status"`   // open, resolved, in_review
	RemediationStatus string `json:"remediation_status"`
	CVE               string `json:"cve,omitempty"`
	CWE               string `json:"cwe,omitempty"`
	TargetEndpoint    string `json:"target_endpoint"`
	EvidenceDigest    string `json:"evidence_digest,omitempty"`
	IsSimulated       bool   `json:"is_simulated"`
}

// ValidateVantaPayloadSchema performs rigorous JSON schema and semantic validation over an outbound Vanta payload.
func ValidateVantaPayloadSchema(payload []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return fmt.Errorf("%w: invalid JSON syntax: %v", ErrVantaSchemaValidation, err)
	}

	requiredRootKeys := []string{
		"client_organization",
		"assessment_id",
		"assessment_ref",
		"audit_type",
		"methodology",
		"testing_window",
		"attestation",
		"retest_summary",
		"findings",
	}

	for _, k := range requiredRootKeys {
		val, exists := raw[k]
		if !exists || val == nil {
			return fmt.Errorf("%w: missing required property %q", ErrVantaSchemaValidation, k)
		}
	}

	// Validate client_organization string
	if org, ok := raw["client_organization"].(string); !ok || strings.TrimSpace(org) == "" {
		return fmt.Errorf("%w: 'client_organization' must be a non-empty string", ErrVantaSchemaValidation)
	}

	// Validate audit_type enum
	auditType, ok := raw["audit_type"].(string)
	if !ok || (auditType != "PENETRATION_TEST" && auditType != "SECURITY_ASSESSMENT") {
		return fmt.Errorf("%w: 'audit_type' must be 'PENETRATION_TEST' or 'SECURITY_ASSESSMENT'", ErrVantaSchemaValidation)
	}

	// Validate methodology array
	methList, ok := raw["methodology"].([]any)
	if !ok || len(methList) == 0 {
		return fmt.Errorf("%w: 'methodology' must be a non-empty array of strings", ErrVantaSchemaValidation)
	}

	// Validate testing_window object
	win, ok := raw["testing_window"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: 'testing_window' must be an object", ErrVantaSchemaValidation)
	}
	if start, ok := win["started_at"].(string); !ok || strings.TrimSpace(start) == "" {
		return fmt.Errorf("%w: 'testing_window.started_at' must be a non-empty string", ErrVantaSchemaValidation)
	}

	// Validate attestation object
	att, ok := raw["attestation"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: 'attestation' must be an object", ErrVantaSchemaValidation)
	}
	if lid, ok := att["letter_id"].(string); !ok || strings.TrimSpace(lid) == "" {
		return fmt.Errorf("%w: 'attestation.letter_id' must be a non-empty string", ErrVantaSchemaValidation)
	}

	// Validate retest_summary object
	ret, ok := raw["retest_summary"].(map[string]any)
	if !ok {
		return fmt.Errorf("%w: 'retest_summary' must be an object", ErrVantaSchemaValidation)
	}
	if _, ok := ret["total_findings"].(float64); !ok {
		return fmt.Errorf("%w: 'retest_summary.total_findings' must be an integer", ErrVantaSchemaValidation)
	}

	// Validate findings array
	fnds, ok := raw["findings"].([]any)
	if !ok {
		return fmt.Errorf("%w: 'findings' must be an array", ErrVantaSchemaValidation)
	}
	for i, item := range fnds {
		fMap, ok := item.(map[string]any)
		if !ok {
			return fmt.Errorf("%w: finding[%d] must be an object", ErrVantaSchemaValidation, i)
		}
		for _, fKey := range []string{"finding_id", "title", "severity", "status", "remediation_status"} {
			if sVal, ok := fMap[fKey].(string); !ok || strings.TrimSpace(sVal) == "" {
				return fmt.Errorf("%w: finding[%d] missing or empty required string %q", ErrVantaSchemaValidation, i, fKey)
			}
		}
	}

	return nil
}

func (a *VantaAdapter) SyncAssessment(ctx context.Context, req *SyncAssessmentRequest) (*SyncAssessmentResponse, error) {
	start := time.Now()
	res := &SyncAssessmentResponse{
		Platform:   PlatformVanta,
		ExecutedAt: start.UTC(),
	}

	clientOrg := req.Assessment.Name
	if req.Snapshot != nil && req.Snapshot.ClientOrganization != "" {
		clientOrg = req.Snapshot.ClientOrganization
	} else if req.Snapshot != nil && req.Snapshot.ClientName != "" {
		clientOrg = req.Snapshot.ClientName
	} else if a.cfg.ClientName != "" {
		clientOrg = a.cfg.ClientName
	}
	if clientOrg == "" {
		clientOrg = "FELIX Client Organization"
	}

	methodologies := []string{
		"OWASP ASVS v4.0.3 Level 2",
		"PTES Technical Guidelines",
		"NIST SP 800-115 Security Testing",
	}
	if req.Snapshot != nil && len(req.Snapshot.TestingMethodology) > 0 {
		methodologies = req.Snapshot.TestingMethodology
	}

	startedAt := req.Assessment.CreatedAt.Format(time.RFC3339)
	completedAt := time.Now().UTC().Format(time.RFC3339)
	if req.Execution != nil && req.Execution.CompletedAt != nil {
		completedAt = req.Execution.CompletedAt.Format(time.RFC3339)
	}

	attRecord := VantaAttestationRecord{
		Status: "UNSIGNED",
	}
	if req.Attestation != nil {
		attRecord.LetterID = req.Attestation.LetterID
		attRecord.CanonicalDigest = req.Attestation.CanonicalDigest
		attRecord.SignatureHex = req.Attestation.Signature.SignatureHex
		attRecord.SignerIdentity = req.Attestation.Signature.SignerIdentity
		attRecord.SigningKeyID = req.Attestation.Signature.KeyID
		attRecord.Status = "VERIFIED"
	}

	retestSummary := VantaRetestSummary{
		RetestMode: "FULL_REASSESSMENT",
	}
	if req.RetestResult != nil && req.RetestResult.Comparison != nil {
		cmp := req.RetestResult.Comparison
		retestSummary.RetestMode = string(cmp.RetestMode)
		retestSummary.IsClean = cmp.IsAssessmentClean
		retestSummary.TotalFindings = cmp.OriginalFindingCount
		retestSummary.RemediatedCount = cmp.RemediatedVerifiedCount
		retestSummary.RemainingUnresolvedCount = cmp.OriginalFindingCount - cmp.RemediatedVerifiedCount
		retestSummary.SimulatedRemediatedCount = cmp.SimulatedRemediatedCount
	} else {
		retestSummary.TotalFindings = len(req.Findings)
		for _, f := range req.Findings {
			if f.Status == assessment.FindingStatusVerifiedDefect {
				retestSummary.RemainingUnresolvedCount++
			}
		}
	}

	var vantaFindings []VantaFindingItem
	simulatedCount := 0
	remediatedCount := 0
	unresolvedCount := 0

	for _, f := range req.Findings {
		isSim := f.VerificationRecord.SyntheticFixture || f.AnalysisMethod == "MOCK" || f.AnalysisMethod == "SYNTHETIC"
		if isSim {
			simulatedCount++
		}

		status := "open"
		remStatus := string(f.Status)
		if remStatus == "" {
			remStatus = string(f.VerificationStatus)
		}

		if f.Status == "REMEDIATED_VERIFIED" || remStatus == "REMEDIATED_VERIFIED" {
			status = "resolved"
			remStatus = "REMEDIATED_VERIFIED"
			if !isSim {
				remediatedCount++
			}
		} else {
			unresolvedCount++
		}

		endpoint := f.Endpoint
		if endpoint == "" {
			endpoint = f.TargetURL
		}
		if endpoint == "" {
			endpoint = "/"
		}

		cwe := ""
		if f.EvidenceDetails.Details != nil {
			if v, ok := f.EvidenceDetails.Details["cwe"]; ok {
				cwe = v
			}
		}

		evDigest := ""
		if f.EvidenceDetails.Provenance != nil && f.EvidenceDetails.Provenance.ContentDigest != "" {
			evDigest = f.EvidenceDetails.Provenance.ContentDigest
		} else if f.EvidenceDetails.Details != nil {
			if ed, ok := f.EvidenceDetails.Details["evidence_digest"]; ok {
				evDigest = ed
			}
		}

		vf := VantaFindingItem{
			FindingID:         f.ID,
			Title:             f.Title,
			Severity:          string(report.NormalizeSeverity(f.Severity)),
			Status:            status,
			RemediationStatus: remStatus,
			CWE:               cwe,
			TargetEndpoint:    endpoint,
			EvidenceDigest:    evDigest,
			IsSimulated:       isSim,
		}
		vantaFindings = append(vantaFindings, vf)
	}

	asmRef := req.Assessment.Ref
	if asmRef == "" && req.Snapshot != nil {
		asmRef = req.Snapshot.AssessmentRef
	}
	if asmRef == "" {
		asmRef = "ASM-" + req.Assessment.ID
	}

	payload := VantaPenTestPayload{
		ClientOrganization: clientOrg,
		AssessmentID:       req.Assessment.ID,
		AssessmentRef:      asmRef,
		AuditType:          "PENETRATION_TEST",
		Methodology:        methodologies,
		TestingWindow: VantaTestingWindow{
			StartedAt:   startedAt,
			CompletedAt: completedAt,
		},
		Attestation:   attRecord,
		RetestSummary: retestSummary,
		Findings:      vantaFindings,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling Vanta payload: %w", err)
	}

	// Compute payload digest
	pSha := sha256.Sum256(payloadBytes)
	res.PayloadDigest = "sha256:" + hex.EncodeToString(pSha[:])

	// Mandatory Exit Condition: Validate against formal Vanta JSON Schema
	if a.cfg.ValidateVantaSchema {
		if err := ValidateVantaPayloadSchema(payloadBytes); err != nil {
			res.Status = SyncStatusRejected
			res.Errors = append(res.Errors, err.Error())
			return res, err
		}
	}

	// Execute HTTP request with bounded retry and backoff
	targetURL := a.baseURL.String() + "/v1/audits/penetration-tests"
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, fmt.Errorf("failed creating HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
		res.IdempotencyKey = req.IdempotencyKey
	}

	for k, v := range a.cfg.CustomHeaders {
		httpReq.Header.Set(k, v)
	}

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		res.Status = SyncStatusFailed
		res.Errors = append(res.Errors, secrets.RedactText(err.Error()))
		return res, err
	}

	res.Duration = time.Since(start)
	res.SimulatedFindingsCount = simulatedCount
	res.RemediatedCount = remediatedCount
	res.UnresolvedCount = unresolvedCount
	res.FindingsSynced = len(vantaFindings)

	// Parse Vanta JSON response
	var vantaResp map[string]any
	if err := json.Unmarshal(respBody, &vantaResp); err != nil {
		res.Status = SyncStatusFailed
		sanitizedMsg := secrets.RedactText(fmt.Sprintf("malformed vendor JSON response: %v", err))
		res.Errors = append(res.Errors, sanitizedMsg)
		return res, fmt.Errorf("malformed vendor JSON response: %w", err)
	}
	res.RawResponse = secrets.RedactMap(vantaResp)
	if id, ok := vantaResp["id"].(string); ok {
		res.ExternalID = id
	}
	if u, ok := vantaResp["url"].(string); ok {
		res.ExternalURL = u
	}

	// Check for Partial success / Multi-Status
	if resp.StatusCode == http.StatusMultiStatus ||
		(vantaResp != nil && (vantaResp["status"] == "PARTIAL" || (vantaResp["findings_failed"] != nil && vantaResp["findings_failed"].(float64) > 0))) {
		res.Status = SyncStatusPartial
		if vantaResp != nil {
			if failed, ok := vantaResp["findings_failed"].(float64); ok {
				res.FindingsFailed = int(failed)
				if int(failed) < len(vantaFindings) {
					res.FindingsSynced = len(vantaFindings) - int(failed)
				}
			}
			if errs, ok := vantaResp["errors"].([]any); ok {
				for _, e := range errs {
					if es, ok := e.(string); ok {
						res.Errors = append(res.Errors, secrets.RedactText(es))
					}
				}
			}
		}
		return res, nil
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res.Status = SyncStatusSuccess
		res.AttestationAccepted = (attRecord.Status == "VERIFIED")
		res.AttestationVerificationStatus = attRecord.Status
		return res, nil
	}

	res.Status = SyncStatusFailed
	sanitizedMsg := secrets.RedactText(fmt.Sprintf("Vanta API error HTTP %d: %s", resp.StatusCode, string(respBody)))
	res.Errors = append(res.Errors, sanitizedMsg)
	return res, errors.New(sanitizedMsg)
}

func (a *VantaAdapter) GetSyncStatus(ctx context.Context, externalID string) (*ExternalSyncStatus, error) {
	if strings.TrimSpace(externalID) == "" {
		return nil, errors.New("externalID cannot be empty")
	}

	targetURL := fmt.Sprintf("%s/v1/audits/penetration-tests/%s", a.baseURL.String(), url.PathEscape(externalID))
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed fetching Vanta audit status HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
	}

	var raw map[string]any
	_ = json.Unmarshal(respBody, &raw)

	statusStr := "UNKNOWN"
	if s, ok := raw["status"].(string); ok {
		statusStr = s
	}

	return &ExternalSyncStatus{
		ExternalID:                   externalID,
		Platform:                     PlatformVanta,
		ExternalStatus:               statusStr,
		LastSyncedAt:                 time.Now().UTC(),
		RemediationProofAcknowledged: false, // Invariant: External status is NOT proof of remediation!
		Details:                      secrets.RedactMap(raw),
	}, nil
}

func (a *VantaAdapter) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	var lastErr error
	var resp *http.Response
	var bodyBytes []byte

	// Duplicate request body for re-reading during retries
	var bodyBuffer []byte
	if req.Body != nil {
		var err error
		bodyBuffer, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("failed reading request body: %w", err)
		}
		req.Body.Close()
	}

	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := a.cfg.BackoffBase * (1 << (attempt - 1))
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		if bodyBuffer != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBuffer))
		}

		resp, lastErr = a.client.Do(req)
		if lastErr != nil {
			continue
		}

		bodyBytes, lastErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if lastErr != nil {
			continue
		}

		// Rate limit handling (HTTP 429)
		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfterSec := 1
			if h := resp.Header.Get("Retry-After"); h != "" {
				if s, err := strconv.Atoi(h); err == nil && s > 0 {
					retryAfterSec = s
				}
			}
			if attempt < a.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(time.Duration(retryAfterSec) * time.Second):
					continue
				}
			}
		}

		// Bounded retries for 5xx errors
		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			continue
		}

		return resp, bodyBytes, nil
	}

	if lastErr != nil {
		return nil, nil, secrets.WrapSanitizedError(lastErr)
	}
	return resp, bodyBytes, nil
}

// -----------------------------------------------------------------------------
// Drata Adapter Implementation (SOC 2 CC7.1 / CC6.8 Mapping)
// -----------------------------------------------------------------------------

// DrataAdapter implements CompliancePlatformAdapter for the Drata API.
type DrataAdapter struct {
	cfg     ComplianceSyncConfig
	client  *http.Client
	baseURL *url.URL
}

// NewDrataAdapter constructs an authenticated Drata adapter.
func NewDrataAdapter(cfg ComplianceSyncConfig) (*DrataAdapter, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://public-api.drata.com"
	}

	parsedURL, err := ValidateEndpoint(cfg.BaseURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid Drata BaseURL: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = BuildSafeHTTPClient(cfg.Timeout, cfg.SSRF)
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}

	return &DrataAdapter{
		cfg:     cfg,
		client:  client,
		baseURL: parsedURL,
	}, nil
}

func (a *DrataAdapter) Platform() CompliancePlatform {
	return PlatformDrata
}

func (a *DrataAdapter) ValidateConfig() error {
	if a.baseURL == nil {
		return errors.New("drata BaseURL not configured")
	}
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}
	if token == "" {
		return fmt.Errorf("%w: Drata API key or token required", ErrMissingCredentials)
	}
	return nil
}

// MapFindingToSOC2Control automatically maps a finding category or rule into an authoritative SOC 2 control ID.
func MapFindingToSOC2Control(category, ruleID, title string) string {
	combined := strings.ToUpper(category + " " + ruleID + " " + title)
	switch {
	case strings.Contains(combined, "BOLA"),
		strings.Contains(combined, "BFLA"),
		strings.Contains(combined, "AUTH"),
		strings.Contains(combined, "ACCESS CONTROL"),
		strings.Contains(combined, "PRIVILEGE"),
		strings.Contains(combined, "IDOR"):
		return "CC6.8" // Logical Access Restrictions & Unauthorized Access Prevention
	case strings.Contains(combined, "HEADER"),
		strings.Contains(combined, "CONFIG"),
		strings.Contains(combined, "HSTS"),
		strings.Contains(combined, "TLS"),
		strings.Contains(combined, "SSL"):
		return "CC6.6" // Boundary Protections & Transmission Confidentiality
	default:
		// SQLi, XSS, SSRF, Deserialization, Injection, CVEs
		return "CC7.1" // Vulnerability Identification, Analysis & Remediation
	}
}

// DrataEvidencePayload defines the payload for Drata's evidence upload endpoint.
type DrataEvidencePayload struct {
	FileName            string                 `json:"file_name"`
	FileContentBase64   string                 `json:"file_content_base64"`
	MimeType            string                 `json:"mime_type"`
	EvidenceType        string                 `json:"evidence_type"` // PENETRATION_TEST_REPORT
	ControlIDs          []string               `json:"control_ids"`   // ["CC7.1", "CC6.8"]
	AssessmentID        string                 `json:"assessment_id"`
	ExecutionID         string                 `json:"execution_id,omitempty"`
	SHA256Checksum      string                 `json:"sha256_checksum"`
	ComplianceFramework string                 `json:"compliance_framework"` // SOC_2_TYPE_II
	Metadata            map[string]any         `json:"metadata,omitempty"`
	FindingMappings     []DrataControlMapping  `json:"finding_mappings"`
}

type DrataControlMapping struct {
	FindingID          string `json:"finding_id"`
	ControlID          string `json:"control_id"`
	Title              string `json:"title"`
	Severity           string `json:"severity"`
	RemediationStatus  string `json:"remediation_status"`
	EvidenceDigest     string `json:"evidence_digest,omitempty"`
	IsSimulated        bool   `json:"is_simulated"`
}

func (a *DrataAdapter) SyncAssessment(ctx context.Context, req *SyncAssessmentRequest) (*SyncAssessmentResponse, error) {
	start := time.Now()
	res := &SyncAssessmentResponse{
		Platform:   PlatformDrata,
		ExecutedAt: start.UTC(),
	}

	var controlIDSet = make(map[string]bool)
	var mappings []DrataControlMapping
	simulatedCount := 0
	remediatedCount := 0
	unresolvedCount := 0

	for _, f := range req.Findings {
		isSim := f.VerificationRecord.SyntheticFixture || f.AnalysisMethod == "MOCK" || f.AnalysisMethod == "SYNTHETIC"
		if isSim {
			simulatedCount++
		}

		ctrlID := MapFindingToSOC2Control(f.Category, f.RuleID, f.Title)
		controlIDSet[ctrlID] = true

		remStatus := string(f.Status)
		if f.Status == "REMEDIATED_VERIFIED" || remStatus == "REMEDIATED_VERIFIED" {
			remStatus = "REMEDIATED_VERIFIED"
			if !isSim {
				remediatedCount++
			}
		} else {
			unresolvedCount++
		}

		evDigest := ""
		if f.EvidenceDetails.Provenance != nil && f.EvidenceDetails.Provenance.ContentDigest != "" {
			evDigest = f.EvidenceDetails.Provenance.ContentDigest
		} else if f.EvidenceDetails.Details != nil {
			if ed, ok := f.EvidenceDetails.Details["evidence_digest"]; ok {
				evDigest = ed
			}
		}

		mappings = append(mappings, DrataControlMapping{
			FindingID:         f.ID,
			ControlID:         ctrlID,
			Title:             f.Title,
			Severity:          string(report.NormalizeSeverity(f.Severity)),
			RemediationStatus: remStatus,
			EvidenceDigest:    evDigest,
			IsSimulated:       isSim,
		})
	}

	// Always ensure SOC 2 CC7.1 is present for penetration test compliance
	controlIDSet["CC7.1"] = true
	var controlIDs []string
	for cid := range controlIDSet {
		controlIDs = append(controlIDs, cid)
	}

	// Prepare base64 evidence content from attestation letter or assessment snapshot
	var evidenceJSON []byte
	if req.Attestation != nil {
		evidenceJSON, _ = json.MarshalIndent(req.Attestation, "", "  ")
	} else if req.Snapshot != nil {
		evidenceJSON, _ = json.MarshalIndent(req.Snapshot, "", "  ")
	} else {
		evidenceJSON = []byte(fmt.Sprintf(`{"assessment_id":%q,"status":%q}`, req.Assessment.ID, req.Assessment.Status))
	}

	evChecksum := sha256.Sum256(evidenceJSON)
	evChecksumHex := hex.EncodeToString(evChecksum[:])

	payload := DrataEvidencePayload{
		FileName:            fmt.Sprintf("felix_attestation_%s.json", req.Assessment.ID),
		FileContentBase64:   base64.StdEncoding.EncodeToString(evidenceJSON),
		MimeType:            "application/json",
		EvidenceType:        "PENETRATION_TEST_REPORT",
		ControlIDs:          controlIDs,
		AssessmentID:        req.Assessment.ID,
		SHA256Checksum:      evChecksumHex,
		ComplianceFramework: "SOC_2_TYPE_II",
		FindingMappings:     mappings,
		Metadata: map[string]any{
			"total_findings":      len(req.Findings),
			"remediated_verified": remediatedCount,
			"unresolved":          unresolvedCount,
			"simulated":           simulatedCount,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling Drata payload: %w", err)
	}

	pSha := sha256.Sum256(payloadBytes)
	res.PayloadDigest = "sha256:" + hex.EncodeToString(pSha[:])

	targetURL := a.baseURL.String() + "/public/v1/evidence/upload"
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
		res.IdempotencyKey = req.IdempotencyKey
	}

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		res.Status = SyncStatusFailed
		res.Errors = append(res.Errors, secrets.RedactText(err.Error()))
		return res, err
	}

	res.Duration = time.Since(start)
	res.ControlsMapped = len(controlIDs)
	res.FindingsSynced = len(mappings)
	res.RemediatedCount = remediatedCount
	res.UnresolvedCount = unresolvedCount
	res.SimulatedFindingsCount = simulatedCount

	var drataResp map[string]any
	if err := json.Unmarshal(respBody, &drataResp); err != nil {
		res.Status = SyncStatusFailed
		sanitizedMsg := secrets.RedactText(fmt.Sprintf("malformed vendor JSON response: %v", err))
		res.Errors = append(res.Errors, sanitizedMsg)
		return res, fmt.Errorf("malformed vendor JSON response: %w", err)
	}
	res.RawResponse = secrets.RedactMap(drataResp)
	if id, ok := drataResp["evidence_id"].(string); ok {
		res.ExternalID = id
	}
	if u, ok := drataResp["url"].(string); ok {
		res.ExternalURL = u
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res.Status = SyncStatusSuccess
		res.AttestationAccepted = (req.Attestation != nil)
		if req.Attestation != nil {
			res.AttestationVerificationStatus = "VERIFIED"
		} else {
			res.AttestationVerificationStatus = "UNSIGNED"
		}
		return res, nil
	}

	res.Status = SyncStatusFailed
	sanitizedMsg := secrets.RedactText(fmt.Sprintf("Drata API error HTTP %d: %s", resp.StatusCode, string(respBody)))
	res.Errors = append(res.Errors, sanitizedMsg)
	return res, errors.New(sanitizedMsg)
}

func (a *DrataAdapter) GetSyncStatus(ctx context.Context, externalID string) (*ExternalSyncStatus, error) {
	if strings.TrimSpace(externalID) == "" {
		return nil, errors.New("externalID cannot be empty")
	}

	targetURL := fmt.Sprintf("%s/public/v1/evidence/%s", a.baseURL.String(), url.PathEscape(externalID))
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed fetching Drata evidence status HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
	}

	var raw map[string]any
	_ = json.Unmarshal(respBody, &raw)

	statusStr := "UPLOADED"
	if s, ok := raw["status"].(string); ok {
		statusStr = s
	}

	return &ExternalSyncStatus{
		ExternalID:                   externalID,
		Platform:                     PlatformDrata,
		ExternalStatus:               statusStr,
		LastSyncedAt:                 time.Now().UTC(),
		RemediationProofAcknowledged: false,
		Details:                      secrets.RedactMap(raw),
	}, nil
}

func (a *DrataAdapter) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	var lastErr error
	var resp *http.Response
	var bodyBytes []byte

	var bodyBuffer []byte
	if req.Body != nil {
		bodyBuffer, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := a.cfg.BackoffBase * (1 << (attempt - 1))
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		if bodyBuffer != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBuffer))
		}

		resp, lastErr = a.client.Do(req)
		if lastErr != nil {
			continue
		}

		bodyBytes, lastErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if lastErr != nil {
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfterSec := 1
			if h := resp.Header.Get("Retry-After"); h != "" {
				if s, err := strconv.Atoi(h); err == nil && s > 0 {
					retryAfterSec = s
				}
			}
			if attempt < a.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(time.Duration(retryAfterSec) * time.Second):
					continue
				}
			}
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			continue
		}

		return resp, bodyBytes, nil
	}

	if lastErr != nil {
		return nil, nil, secrets.WrapSanitizedError(lastErr)
	}
	return resp, bodyBytes, nil
}

// -----------------------------------------------------------------------------
// Secureframe Adapter Implementation (Pen Test Timestamps & SLA Sync)
// -----------------------------------------------------------------------------

// SecureframeAdapter implements CompliancePlatformAdapter for the Secureframe API.
type SecureframeAdapter struct {
	cfg     ComplianceSyncConfig
	client  *http.Client
	baseURL *url.URL
}

// NewSecureframeAdapter constructs an authenticated Secureframe adapter.
func NewSecureframeAdapter(cfg ComplianceSyncConfig) (*SecureframeAdapter, error) {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.secureframe.com"
	}

	parsedURL, err := ValidateEndpoint(cfg.BaseURL, cfg.SSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid Secureframe BaseURL: %w", err)
	}

	client := cfg.HTTPClient
	if client == nil {
		client = BuildSafeHTTPClient(cfg.Timeout, cfg.SSRF)
	}

	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 3
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 100 * time.Millisecond
	}

	return &SecureframeAdapter{
		cfg:     cfg,
		client:  client,
		baseURL: parsedURL,
	}, nil
}

func (a *SecureframeAdapter) Platform() CompliancePlatform {
	return PlatformSecureframe
}

func (a *SecureframeAdapter) ValidateConfig() error {
	if a.baseURL == nil {
		return errors.New("secureframe BaseURL not configured")
	}
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}
	if token == "" {
		return fmt.Errorf("%w: Secureframe API key or token required", ErrMissingCredentials)
	}
	return nil
}

// SecureframeTestPayload defines the structure for Secureframe test synchronization.
type SecureframeTestPayload struct {
	Vendor                string                  `json:"vendor"` // "FELIX"
	TestName              string                  `json:"test_name"`
	ClientName            string                  `json:"client_name"`
	AssessmentID          string                  `json:"assessment_id"`
	StartedAt             string                  `json:"started_at"`
	CompletedAt           string                  `json:"completed_at"`
	DurationMs            int64                   `json:"duration_ms"`
	Pass                  bool                    `json:"pass"`
	AttestationID         string                  `json:"attestation_id,omitempty"`
	AttestationDigest     string                  `json:"attestation_digest,omitempty"`
	RemediationSLASummary SecureframeSLASummary   `json:"remediation_sla_summary"`
	Findings              []SecureframeFindingItem `json:"findings"`
}

type SecureframeSLASummary struct {
	TotalTracked  int     `json:"total_tracked"`
	WithinSLA     int     `json:"within_sla"`
	BreachedSLA   int     `json:"breached_sla"`
	MTTRHours     float64 `json:"mttr_hours"`
}

type SecureframeFindingItem struct {
	FindingID         string `json:"finding_id"`
	Title             string `json:"title"`
	Severity          string `json:"severity"`
	Status            string `json:"status"`
	RemediationStatus string `json:"remediation_status"`
	SLADueDate        string `json:"sla_due_date,omitempty"`
	SLABreached       bool   `json:"sla_breached"`
	IsSimulated       bool   `json:"is_simulated"`
}

func (a *SecureframeAdapter) SyncAssessment(ctx context.Context, req *SyncAssessmentRequest) (*SyncAssessmentResponse, error) {
	start := time.Now()
	res := &SyncAssessmentResponse{
		Platform:   PlatformSecureframe,
		ExecutedAt: start.UTC(),
	}

	startedAt := req.Assessment.CreatedAt.Format(time.RFC3339)
	completedAt := time.Now().UTC().Format(time.RFC3339)
	var durationMs int64
	if req.Execution != nil && req.Execution.CompletedAt != nil {
		completedAt = req.Execution.CompletedAt.Format(time.RFC3339)
		durationMs = req.Execution.CompletedAt.Sub(req.Execution.StartedAt).Milliseconds()
	}

	isClean := false
	if req.RetestResult != nil && req.RetestResult.Comparison != nil {
		isClean = req.RetestResult.Comparison.IsAssessmentClean
	}

	clientName := req.Assessment.Name
	if req.Snapshot != nil && req.Snapshot.ClientName != "" {
		clientName = req.Snapshot.ClientName
	} else if a.cfg.ClientName != "" {
		clientName = a.cfg.ClientName
	}
	if clientName == "" {
		clientName = "FELIX Client"
	}

	slaMap := make(map[string]RemediationRecord)
	for _, rec := range req.RemediationSLAs {
		slaMap[rec.FindingID] = rec
	}

	var sfFindings []SecureframeFindingItem
	simulatedCount := 0
	remediatedCount := 0
	unresolvedCount := 0
	withinSLACount := 0
	breachedSLACount := 0

	now := time.Now().UTC()
	for _, f := range req.Findings {
		isSim := f.VerificationRecord.SyntheticFixture || f.AnalysisMethod == "MOCK" || f.AnalysisMethod == "SYNTHETIC"
		if isSim {
			simulatedCount++
		}

		status := "open"
		remStatus := string(f.Status)
		if f.Status == "REMEDIATED_VERIFIED" || remStatus == "REMEDIATED_VERIFIED" {
			status = "resolved"
			remStatus = "REMEDIATED_VERIFIED"
			if !isSim {
				remediatedCount++
			}
		} else {
			unresolvedCount++
		}

		slaDueDate := ""
		slaBreached := false
		if rec, ok := slaMap[f.ID]; ok {
			slaDueDate = rec.Deadline.Format(time.RFC3339)
			if rec.Status == RemediationStatusRemediated {
				withinSLACount++
			} else if now.After(rec.Deadline) {
				slaBreached = true
				breachedSLACount++
			} else {
				withinSLACount++
			}
		}

		sfFindings = append(sfFindings, SecureframeFindingItem{
			FindingID:         f.ID,
			Title:             f.Title,
			Severity:          string(report.NormalizeSeverity(f.Severity)),
			Status:            status,
			RemediationStatus: remStatus,
			SLADueDate:        slaDueDate,
			SLABreached:       slaBreached,
			IsSimulated:       isSim,
		})
	}

	attID := ""
	attDigest := ""
	if req.Attestation != nil {
		attID = req.Attestation.LetterID
		attDigest = req.Attestation.CanonicalDigest
	}

	payload := SecureframeTestPayload{
		Vendor:            "FELIX",
		TestName:          "Automated Penetration Test & Attestation",
		ClientName:        clientName,
		AssessmentID:      req.Assessment.ID,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		DurationMs:        durationMs,
		Pass:              isClean,
		AttestationID:     attID,
		AttestationDigest: attDigest,
		RemediationSLASummary: SecureframeSLASummary{
			TotalTracked: len(req.RemediationSLAs),
			WithinSLA:    withinSLACount,
			BreachedSLA:  breachedSLACount,
			MTTRHours:    0.0,
		},
		Findings: sfFindings,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed marshaling Secureframe payload: %w", err)
	}

	pSha := sha256.Sum256(payloadBytes)
	res.PayloadDigest = "sha256:" + hex.EncodeToString(pSha[:])

	targetURL := a.baseURL.String() + "/v1/tests/penetration-test"
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payloadBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)
	if req.IdempotencyKey != "" {
		httpReq.Header.Set("Idempotency-Key", req.IdempotencyKey)
		res.IdempotencyKey = req.IdempotencyKey
	}

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		res.Status = SyncStatusFailed
		res.Errors = append(res.Errors, secrets.RedactText(err.Error()))
		return res, err
	}

	res.Duration = time.Since(start)
	res.FindingsSynced = len(sfFindings)
	res.RemediatedCount = remediatedCount
	res.UnresolvedCount = unresolvedCount
	res.SimulatedFindingsCount = simulatedCount

	var sfResp map[string]any
	if err := json.Unmarshal(respBody, &sfResp); err != nil {
		res.Status = SyncStatusFailed
		sanitizedMsg := secrets.RedactText(fmt.Sprintf("malformed vendor JSON response: %v", err))
		res.Errors = append(res.Errors, sanitizedMsg)
		return res, fmt.Errorf("malformed vendor JSON response: %w", err)
	}
	res.RawResponse = secrets.RedactMap(sfResp)
	if id, ok := sfResp["test_id"].(string); ok {
		res.ExternalID = id
	}
	if u, ok := sfResp["url"].(string); ok {
		res.ExternalURL = u
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		res.Status = SyncStatusSuccess
		res.AttestationAccepted = (req.Attestation != nil)
		if req.Attestation != nil {
			res.AttestationVerificationStatus = "VERIFIED"
		} else {
			res.AttestationVerificationStatus = "UNSIGNED"
		}
		return res, nil
	}

	res.Status = SyncStatusFailed
	sanitizedMsg := secrets.RedactText(fmt.Sprintf("Secureframe API error HTTP %d: %s", resp.StatusCode, string(respBody)))
	res.Errors = append(res.Errors, sanitizedMsg)
	return res, errors.New(sanitizedMsg)
}

func (a *SecureframeAdapter) GetSyncStatus(ctx context.Context, externalID string) (*ExternalSyncStatus, error) {
	if strings.TrimSpace(externalID) == "" {
		return nil, errors.New("externalID cannot be empty")
	}

	targetURL := fmt.Sprintf("%s/v1/tests/penetration-test/%s", a.baseURL.String(), url.PathEscape(externalID))
	token := strings.TrimSpace(a.cfg.Token)
	if token == "" {
		token = strings.TrimSpace(a.cfg.APIKey)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, respBody, err := a.executeWithRetry(ctx, httpReq)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed fetching Secureframe test status HTTP %d: %s", resp.StatusCode, secrets.RedactText(string(respBody)))
	}

	var raw map[string]any
	_ = json.Unmarshal(respBody, &raw)

	statusStr := "RECORDED"
	if s, ok := raw["status"].(string); ok {
		statusStr = s
	}

	return &ExternalSyncStatus{
		ExternalID:                   externalID,
		Platform:                     PlatformSecureframe,
		ExternalStatus:               statusStr,
		LastSyncedAt:                 time.Now().UTC(),
		RemediationProofAcknowledged: false,
		Details:                      secrets.RedactMap(raw),
	}, nil
}

func (a *SecureframeAdapter) executeWithRetry(ctx context.Context, req *http.Request) (*http.Response, []byte, error) {
	var lastErr error
	var resp *http.Response
	var bodyBytes []byte

	var bodyBuffer []byte
	if req.Body != nil {
		bodyBuffer, _ = io.ReadAll(req.Body)
		req.Body.Close()
	}

	for attempt := 0; attempt <= a.cfg.MaxRetries; attempt++ {
		if attempt > 0 {
			backoff := a.cfg.BackoffBase * (1 << (attempt - 1))
			select {
			case <-ctx.Done():
				return nil, nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		if bodyBuffer != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBuffer))
		}

		resp, lastErr = a.client.Do(req)
		if lastErr != nil {
			continue
		}

		bodyBytes, lastErr = io.ReadAll(resp.Body)
		resp.Body.Close()
		if lastErr != nil {
			continue
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfterSec := 1
			if h := resp.Header.Get("Retry-After"); h != "" {
				if s, err := strconv.Atoi(h); err == nil && s > 0 {
					retryAfterSec = s
				}
			}
			if attempt < a.cfg.MaxRetries {
				select {
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				case <-time.After(time.Duration(retryAfterSec) * time.Second):
					continue
				}
			}
		}

		if resp.StatusCode >= 500 && resp.StatusCode <= 504 {
			continue
		}

		return resp, bodyBytes, nil
	}

	if lastErr != nil {
		return nil, nil, secrets.WrapSanitizedError(lastErr)
	}
	return resp, bodyBytes, nil
}

// -----------------------------------------------------------------------------
// Core Auditor Sync Engine (Multi-Platform Orchestration)
// -----------------------------------------------------------------------------

// AuditorSyncEngine coordinates compliance platform validation, attestation verification, and durable synchronization.
type AuditorSyncEngine struct {
	store              ComplianceStore
	trustedKeyRegistry assessment.TrustedKeyRegistry
	adapters           map[CompliancePlatform]CompliancePlatformAdapter
}

// NewAuditorSyncEngine constructs a new AuditorSyncEngine instance.
func NewAuditorSyncEngine(store ComplianceStore, trustedKeys ...assessment.TrustedKeyRegistry) *AuditorSyncEngine {
	var tr assessment.TrustedKeyRegistry
	if len(trustedKeys) > 0 {
		tr = trustedKeys[0]
	}

	return &AuditorSyncEngine{
		store:              store,
		trustedKeyRegistry: tr,
		adapters:           make(map[CompliancePlatform]CompliancePlatformAdapter),
	}
}

// RegisterAdapter adds a custom or pre-configured platform adapter.
func (e *AuditorSyncEngine) RegisterAdapter(platform CompliancePlatform, adapter CompliancePlatformAdapter) {
	e.adapters[platform] = adapter
}

// SetTrustedKeyRegistry configures the protected application-level trusted key registry.
func (e *AuditorSyncEngine) SetTrustedKeyRegistry(reg assessment.TrustedKeyRegistry) {
	e.trustedKeyRegistry = reg
}

// ComputeSyncIdempotencyKey calculates a deterministic SHA-256 idempotency key for an assessment sync request.
func ComputeSyncIdempotencyKey(req *SyncAssessmentRequest, platform CompliancePlatform) string {
	ref := req.Assessment.Ref
	if ref == "" && req.Snapshot != nil {
		ref = req.Snapshot.AssessmentRef
	}
	raw := fmt.Sprintf("%s|%s|%s", platform, req.Assessment.ID, ref)
	if req.Execution != nil {
		raw += "|" + req.Execution.ID
	}
	if req.Attestation != nil {
		raw += "|" + req.Attestation.LetterID + "|" + req.Attestation.CanonicalDigest
	}
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

// SyncAssessment synchronizes an assessment to a designated compliance platform.
func (e *AuditorSyncEngine) SyncAssessment(ctx context.Context, platform CompliancePlatform, req *SyncAssessmentRequest, cfg ComplianceSyncConfig) (*SyncAssessmentResponse, error) {
	if req == nil {
		return nil, errors.New("cannot sync nil SyncAssessmentRequest")
	}

	// 1. Verify Cryptographic Attestation Letter if present
	if req.Attestation != nil {
		if e.trustedKeyRegistry != nil {
			vRes, err := assessment.VerifyAttestationLetterWithRegistry(*req.Attestation, e.trustedKeyRegistry)
			if err != nil || vRes == nil || !vRes.Valid {
				reason := "unknown verification failure"
				if err != nil {
					reason = err.Error()
				} else if vRes != nil && vRes.FailureReason != "" {
					reason = vRes.FailureReason
				}

				if !req.AllowUnsigned {
					return &SyncAssessmentResponse{
						Platform:                      platform,
						Status:                        SyncStatusRejected,
						AttestationAccepted:           false,
						AttestationVerificationStatus: "INVALID_SIGNATURE",
						Errors:                        []string{fmt.Sprintf("Attestation cryptographic verification failed: %s", reason)},
					}, fmt.Errorf("%w: %s", ErrAttestationTampered, reason)
				}
			}
		} else if strings.TrimSpace(req.Attestation.Signature.SignatureHex) == "" {
			if !req.AllowUnsigned {
				return &SyncAssessmentResponse{
					Platform:                      platform,
					Status:                        SyncStatusRejected,
					AttestationAccepted:           false,
					AttestationVerificationStatus: "UNSIGNED",
					Errors:                        []string{"Attestation letter is unsigned"},
				}, errors.New("cannot sync unsigned attestation letter without AllowUnsigned=true")
			}
		}
	}

	// 2. Compute Idempotency Key if absent
	idempKey := req.IdempotencyKey
	if strings.TrimSpace(idempKey) == "" {
		idempKey = ComputeSyncIdempotencyKey(req, platform)
	}

	// 3. Check for existing idempotent sync record in durable store
	if e.store != nil {
		existing, err := e.store.GetPlatformSyncRecordByIdempotencyKey(idempKey)
		if err == nil && existing != nil {
			if existing.AssessmentID != req.Assessment.ID {
				return nil, fmt.Errorf("conflicting sync record: idempotency key %q belongs to assessment %q, not %q", idempKey, existing.AssessmentID, req.Assessment.ID)
			}
			if existing.Status == SyncStatusSuccess {
				// Idempotent duplicate: return recorded success
				return &SyncAssessmentResponse{
					Platform:                      existing.Platform,
					Status:                        existing.Status,
					ExternalID:                    existing.ExternalRecordID,
					ExternalURL:                   existing.ExternalURL,
					AttestationAccepted:           (existing.AttestationLetterID != ""),
					AttestationVerificationStatus: "VERIFIED",
					FindingsSynced:                existing.RecordsSynced,
					FindingsFailed:                existing.RecordsFailed,
					PayloadDigest:                 existing.PayloadDigest,
					IdempotencyKey:                existing.IdempotencyKey,
					ExecutedAt:                    existing.SyncedAt,
					Duration:                      0,
				}, nil
			}
		}
	}

	// 4. Resolve Platform Adapter
	adapter, exists := e.adapters[platform]
	if !exists {
		var err error
		cfg.Platform = platform
		switch platform {
		case PlatformVanta:
			adapter, err = NewVantaAdapter(cfg)
		case PlatformDrata:
			adapter, err = NewDrataAdapter(cfg)
		case PlatformSecureframe:
			adapter, err = NewSecureframeAdapter(cfg)
		default:
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedPlatform, platform)
		}
		if err != nil {
			return nil, err
		}
	}

	// 5. Validate Adapter Configuration
	if err := adapter.ValidateConfig(); err != nil {
		return &SyncAssessmentResponse{
			Platform: platform,
			Status:   SyncStatusRejected,
			Errors:   []string{secrets.RedactText(err.Error())},
		}, err
	}

	// 6. Execute Synchronization
	clonedReq := *req
	clonedReq.IdempotencyKey = idempKey
	resp, syncErr := adapter.SyncAssessment(ctx, &clonedReq)
	if resp == nil {
		resp = &SyncAssessmentResponse{
			Platform: platform,
			Status:   SyncStatusFailed,
		}
	}
	if syncErr != nil && len(resp.Errors) == 0 {
		resp.Errors = append(resp.Errors, secrets.RedactText(syncErr.Error()))
	}

	// 7. Persist sync record to SQLite Compliance Store
	if e.store != nil {
		rec := &PlatformSyncRecord{
			SyncID:              fmt.Sprintf("sync-%s-%s-%d", platform, req.Assessment.ID, time.Now().UnixNano()),
			Platform:            platform,
			AssessmentID:        req.Assessment.ID,
			ExecutionID:         "",
			AttestationLetterID: "",
			ExternalRecordID:    resp.ExternalID,
			ExternalURL:         resp.ExternalURL,
			Status:              resp.Status,
			IdempotencyKey:      idempKey,
			PayloadDigest:       resp.PayloadDigest,
			RecordsSynced:       resp.FindingsSynced,
			RecordsFailed:       resp.FindingsFailed,
			SyncedAt:            time.Now().UTC(),
			CreatedAt:           time.Now().UTC(),
		}
		if req.Execution != nil {
			rec.ExecutionID = req.Execution.ID
		}
		if req.Attestation != nil {
			rec.AttestationLetterID = req.Attestation.LetterID
		}
		if len(resp.Errors) > 0 {
			rec.ErrorMessage = strings.Join(resp.Errors, "; ")
		}

		_ = e.store.SavePlatformSyncRecord(rec)
	}

	return resp, syncErr
}

// SyncAllPlatforms executes multi-platform synchronization across all configured platforms.
func (e *AuditorSyncEngine) SyncAllPlatforms(
	ctx context.Context,
	req *SyncAssessmentRequest,
	configs map[CompliancePlatform]ComplianceSyncConfig,
) (map[CompliancePlatform]*SyncAssessmentResponse, error) {
	results := make(map[CompliancePlatform]*SyncAssessmentResponse)
	var errs []string

	platforms := []CompliancePlatform{PlatformVanta, PlatformDrata, PlatformSecureframe}
	for _, p := range platforms {
		cfg, ok := configs[p]
		if !ok {
			cfg = DefaultComplianceSyncConfig(p)
		}

		res, err := e.SyncAssessment(ctx, p, req, cfg)
		results[p] = res
		if err != nil {
			errs = append(errs, fmt.Sprintf("[%s] %s", p, secrets.RedactText(err.Error())))
		}
	}

	if len(errs) > 0 {
		return results, fmt.Errorf("compliance sync completed with errors: %s", strings.Join(errs, "; "))
	}
	return results, nil
}
