package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// ProbeClassification defines the evidence-based live validation outcome for an API endpoint.
type ProbeClassification string

const (
	ClassificationReachable                      ProbeClassification = "REACHABLE"
	ClassificationReachableWithMetadata          ProbeClassification = "REACHABLE_WITH_METADATA"
	ClassificationAuthenticationRequired         ProbeClassification = "AUTHENTICATION_REQUIRED"
	ClassificationAuthorizationBoundaryObserved   ProbeClassification = "AUTHORIZATION_BOUNDARY_OBSERVED"
	ClassificationNotFoundResponse               ProbeClassification = "NOT_FOUND_RESPONSE"
	ClassificationUpstreamFailure                ProbeClassification = "UPSTREAM_FAILURE"
	ClassificationRateLimited                    ProbeClassification = "RATE_LIMITED"
	ClassificationTransportFailure               ProbeClassification = "TRANSPORT_FAILURE"
	ClassificationScopeBlocked                   ProbeClassification = "SCOPE_BLOCKED"
	ClassificationSafeProbeSkipped               ProbeClassification = "SAFE_PROBE_SKIPPED"
	ClassificationInconclusive                   ProbeClassification = "INCONCLUSIVE"
)

// ProbeReachability categorizes whether the route's live network reachability was empirically confirmed.
type ProbeReachability string

const (
	ProbeReachabilityConfirmed    ProbeReachability = "CONFIRMED"
	ProbeReachabilityUnconfirmed  ProbeReachability = "UNCONFIRMED"
	ProbeReachabilityInconclusive ProbeReachability = "INCONCLUSIVE"

	ReachabilityConfirmed   = ProbeReachabilityConfirmed
	ReachabilityUnconfirmed = ProbeReachabilityUnconfirmed
)

// ProbeResult captures the full audit trail and observable behavior for a single candidate probe.
type ProbeResult struct {
	CandidateID                  string              `json:"candidate_id"`
	TargetURL                    string              `json:"target_url"`
	NormalizedRoute              string              `json:"normalized_route"`
	CanonicalPath                string              `json:"canonical_path"`
	OriginalMethod               string              `json:"original_method"`
	ProbeMethod                  string              `json:"probe_method"`
	ProbeTimestamp               time.Time           `json:"probe_timestamp"`
	IsEligible                   bool                `json:"is_eligible"`
	IneligibilityReason          string              `json:"ineligibility_reason,omitempty"`
	StatusCode                   int                 `json:"status_code,omitempty"`
	Classification               ProbeClassification `json:"classification"`
	Reachability                 ProbeReachability   `json:"reachability"`
	Rationale                    string              `json:"rationale"`
	SafeResponseHeaders          map[string]string   `json:"safe_response_headers,omitempty"`
	RedirectInfo                 *ProbeRedirectInfo  `json:"redirect_info,omitempty"`
	ResponseEvidence             string              `json:"response_evidence,omitempty"`
	HasStructuredMetadata        bool                `json:"has_structured_metadata"`
	StructuredMetadataType       string              `json:"structured_metadata_type,omitempty"`
	TransportErrorCategory       string              `json:"transport_error_category,omitempty"`
	TransportErrorDetails        string              `json:"transport_error_details,omitempty"`
	ManualVerificationRecommended bool                `json:"manual_verification_recommended"`
	Warnings                     []string            `json:"warnings,omitempty"`
}

// ProbeRedirectInfo tracks safe redirect metadata without escaping destination scope.
type ProbeRedirectInfo struct {
	InitialStatusCode int    `json:"initial_status_code"`
	RedirectURL       string `json:"redirect_url"`
	RedirectHost      string `json:"redirect_host"`
	IsInScope         bool   `json:"is_in_scope"`
}

// ProberOptions configures live validation safety controls, rate limits, and allowed methods.
type ProberOptions struct {
	Timeout                      time.Duration `json:"timeout"`
	MaxResponseSize              int64         `json:"max_response_size"`
	MaxConcurrency               int           `json:"max_concurrency"`
	RateLimit                    float64       `json:"rate_limit"`
	UserAgent                    string        `json:"user_agent"`
	CustomProbeHeader            string        `json:"custom_probe_header"`
	EnableSafeGET                bool          `json:"enable_safe_get"`
	EnableOPTIONS                bool          `json:"enable_options"`
	EnableHEAD                   bool          `json:"enable_head"`
	AllowLoopback                bool          `json:"allow_loopback"`
	AllowPrivateIPs              bool          `json:"allow_private_ips"`
	ScopeHost                    string        `json:"scope_host"`
	IsAllowed                    func(string) bool `json:"-"`
	IsExcluded                   func(string) bool `json:"-"`
}

// DefaultProberOptions provides conservative non-destructive validation defaults.
func DefaultProberOptions() ProberOptions {
	return ProberOptions{
		Timeout:           6 * time.Second,
		MaxResponseSize:   512 * 1024, // 512 KiB limit for safe error/metadata inspection
		MaxConcurrency:    5,
		RateLimit:         10.0,
		UserAgent:         "Felix/0.1 (Live Exploitability Prober; Defensive)",
		CustomProbeHeader: "LiveExploitabilityValidator/P14.3",
		EnableSafeGET:     true,
		EnableOPTIONS:     true,
		EnableHEAD:        true,
		AllowLoopback:     false,
		AllowPrivateIPs:   false,
	}
}

// ProberReport summarizes the aggregate live validation outcome across all evaluated candidates.
type ProberReport struct {
	TotalCandidatesEvaluated     int           `json:"total_candidates_evaluated"`
	TotalProbesAttempted         int           `json:"total_probes_attempted"`
	TotalReachable               int           `json:"total_reachable"`
	TotalReachableWithMetadata   int           `json:"total_reachable_with_metadata"`
	TotalAuthenticationRequired  int           `json:"total_authentication_required"`
	TotalAuthorizationDenied     int           `json:"total_authorization_denied"`
	TotalNotFound                int           `json:"total_not_found"`
	TotalUpstreamFailures        int           `json:"total_upstream_failures"`
	TotalRateLimited             int           `json:"total_rate_limited"`
	TotalTransportFailures       int           `json:"total_transport_failures"`
	TotalScopeBlocked            int           `json:"total_scope_blocked"`
	TotalSafeProbeSkipped        int           `json:"total_safe_probe_skipped"`
	TotalInconclusive            int           `json:"total_inconclusive"`
	ManualVerificationCandidates int           `json:"manual_verification_candidates"`
	Results                      []ProbeResult `json:"results"`
	Warnings                     []string      `json:"warnings,omitempty"`
}

// GenerateProbeResultID generates a deterministic identifier for a probe result record.
func GenerateProbeResultID(candidateID, probeMethod, targetURL string) string {
	raw := fmt.Sprintf("%s|%s|%s", candidateID, strings.ToUpper(probeMethod), targetURL)
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("PROBE-%s", hex.EncodeToString(h[:8]))
}
