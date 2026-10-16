package report

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/discovery"
	"felix/pkg/secrets"
)

// Standard Severity levels.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
	SeverityUnknown  = "UNKNOWN"
)

// Standard Confidence levels.
const (
	ConfidenceHigh    = "HIGH"
	ConfidenceMedium  = "MEDIUM"
	ConfidenceLow     = "LOW"
	ConfidenceUnknown = "UNKNOWN"
)

// FindingStatus represents the operational verification or evaluation state of a finding.
type FindingStatus string

const (
	FindingStatusConfirmed    FindingStatus = "CONFIRMED"
	FindingStatusSuspected    FindingStatus = "SUSPECTED"
	FindingStatusInconclusive FindingStatus = "INCONCLUSIVE"
	FindingStatusNotTested    FindingStatus = "NOT_TESTED"
	FindingStatusError        FindingStatus = "ERROR"
)

// IsValidFindingStatus returns true if the status is one of the five canonical states.
func IsValidFindingStatus(s FindingStatus) bool {
	switch s {
	case FindingStatusConfirmed, FindingStatusSuspected, FindingStatusInconclusive, FindingStatusNotTested, FindingStatusError:
		return true
	default:
		return false
	}
}

// ValidateFindingStatus returns an error if the status is not one of the five canonical states.
func ValidateFindingStatus(s FindingStatus) error {
	if IsValidFindingStatus(s) {
		return nil
	}
	return fmt.Errorf("invalid finding status %q: must be one of CONFIRMED, SUSPECTED, INCONCLUSIVE, NOT_TESTED, ERROR", s)
}

// IsValidFindingStatusTransition checks whether transitioning from one status to another is valid.
// In the FELIX honest finding model:
// - A CONFIRMED finding cannot be downgraded to SUSPECTED, INCONCLUSIVE, NOT_TESTED, or ERROR (verified proof cannot be silently erased).
// - Unverified states (NOT_TESTED, SUSPECTED, INCONCLUSIVE, ERROR) may transition through progressive evaluation or re-testing.
func IsValidFindingStatusTransition(from, to FindingStatus) bool {
	if !IsValidFindingStatus(from) || !IsValidFindingStatus(to) {
		return false
	}
	if from == to {
		return true
	}
	if from == FindingStatusConfirmed {
		return false
	}
	return true
}

// AnalysisMethod distinguishes how a security claim or artifact was analyzed.
type AnalysisMethod string

const (
	AnalysisMethodStatic AnalysisMethod = "STATIC_ANALYSIS"
	AnalysisMethodActive AnalysisMethod = "ACTIVE_VERIFICATION"
	AnalysisMethodManual AnalysisMethod = "MANUAL_REVIEW"
)

// NormalizeAnalysisMethod standardizes the analysis method to a canonical enum value.
func NormalizeAnalysisMethod(m AnalysisMethod) AnalysisMethod {
	clean := strings.ToUpper(strings.TrimSpace(string(m)))
	switch AnalysisMethod(clean) {
	case AnalysisMethodStatic, "STATIC", "STATIC_CODE_ANALYSIS":
		return AnalysisMethodStatic
	case AnalysisMethodActive, "ACTIVE", "ACTIVE_PROBE", "DYNAMIC":
		return AnalysisMethodActive
	case AnalysisMethodManual, "MANUAL":
		return AnalysisMethodManual
	default:
		return AnalysisMethodStatic
	}
}

// Finding Sources.
const (
	SourceCrawler    = "crawler"
	SourceSecrets    = "secrets"
	SourceCloud      = "cloud"
	SourceAPI        = "api"
	SourceCorrelated = "correlated"
)

// VerificationStatus defines the empirical verification level of a finding.
type VerificationStatus string

const (
	VerificationObserved    VerificationStatus = "OBSERVED"
	VerificationDetected    VerificationStatus = "DETECTED"
	VerificationVerified    VerificationStatus = "VERIFIED"
	VerificationNotVerified VerificationStatus = "NOT_VERIFIED"
	VerificationNotExposed  VerificationStatus = "NOT_EXPOSED"
)

// VerificationRecord encapsulates the empirical verification state, result, and rationale.
type VerificationRecord struct {
	Status             VerificationStatus `json:"status"`
	DetectionStatus    string             `json:"detection_status,omitempty"`
	Result             string             `json:"result"`
	Rationale          string             `json:"rationale,omitempty"`
	PolicyID           string             `json:"policy_id,omitempty"`
	VerificationMethod string             `json:"verification_method,omitempty"`
	AnalysisMethod     AnalysisMethod     `json:"analysis_method,omitempty"`
	ConfidenceScore    int                `json:"confidence_score,omitempty"`
	ReproductionSteps  []string           `json:"reproduction_steps,omitempty"`
	SafeCurlCommand    string             `json:"safe_curl_command,omitempty"`
	Limitations        []string           `json:"limitations,omitempty"`
	SyntheticFixture   bool               `json:"synthetic_fixture,omitempty"`
}

// EvidenceProvenance captures the lineage, collection context, and integrity of a piece of security evidence.
type EvidenceProvenance struct {
	EvidenceID          string         `json:"evidence_id,omitempty"`
	EvidenceType        string         `json:"evidence_type,omitempty"`        // e.g. "http_response", "source_code", "config_file", "dns_record", "api_spec", "token_artifact"
	SourceEngine        string         `json:"source_engine,omitempty"`        // e.g. "crawler", "secrets", "cloud", "api", "auth", "verification"
	RuleID              string         `json:"rule_id,omitempty"`              // rule or check identifier
	FindingID           string         `json:"finding_id,omitempty"`           // associated finding ID
	AssetID             string         `json:"asset_id,omitempty"`             // affected asset ID (ast_<hex>)
	AssessmentID        string         `json:"assessment_id,omitempty"`        // assessment project ID
	ExecutionID         string         `json:"execution_id,omitempty"`         // scan execution ID
	TargetID            string         `json:"target_id,omitempty"`            // assessment target ID
	CollectedAt         time.Time      `json:"collected_at,omitempty"`         // collection timestamp
	Location            string         `json:"location,omitempty"`             // URL, file path, line number, config path
	CollectionMethod    string         `json:"collection_method,omitempty"`    // "passive_crawl", "static_pattern_analysis", "active_probe", etc.
	AnalysisMethod      AnalysisMethod `json:"analysis_method,omitempty"`      // STATIC_ANALYSIS, ACTIVE_VERIFICATION, MANUAL_REVIEW
	VerificationContext string         `json:"verification_context,omitempty"` // verification test or condition
	ContentDigest       string         `json:"content_digest,omitempty"`       // SHA-256 digest of sanitized evidence content (sha256:<hex>)
}

// EvidenceDetails provides structured, machine-readable evidence for a finding.
type EvidenceDetails struct {
	Observation      string              `json:"observation"`
	Location         string              `json:"location"`
	HTTPMethod       string              `json:"http_method,omitempty"`
	HTTPStatus       int                 `json:"http_status,omitempty"`
	ContentType      string              `json:"content_type,omitempty"`
	DetectionMethod  string              `json:"detection_method"`
	DetectionStatus  string              `json:"detection_status,omitempty"`
	NegativeEvidence string              `json:"negative_evidence,omitempty"`
	Details          map[string]string   `json:"details,omitempty"`
	Provenance       *EvidenceProvenance `json:"provenance,omitempty"`
}

// RemediationAdvice provides structured, actionable guidance for finding mitigation.
type RemediationAdvice struct {
	Summary     string   `json:"summary"`
	Steps       []string `json:"steps,omitempty"`
	References  []string `json:"references,omitempty"`
	CodeSnippet string   `json:"code_snippet,omitempty"`
}

// Finding represents a normalized, deduplicated security observation or exposure.
type Finding struct {
	ID                string              `json:"id"`
	RuleID            string              `json:"rule_id,omitempty"`
	Status            FindingStatus       `json:"status,omitempty"`
	AnalysisMethod    AnalysisMethod      `json:"analysis_method,omitempty"`
	PrimaryAssetID    string              `json:"primary_asset_id,omitempty"`
	AffectedAssetIDs  []string            `json:"affected_asset_ids,omitempty"`
	Title             string              `json:"title"`
	Category          string              `json:"category"`
	Severity          string              `json:"severity"`
	Confidence        string              `json:"confidence"`
	Target            string              `json:"target"`
	Endpoint          string              `json:"endpoint"`
	Method            string              `json:"method"`
	Description       string              `json:"description"`
	Evidence          string              `json:"evidence_summary,omitempty"`
	EvidenceDetails   EvidenceDetails     `json:"evidence"`
	Verification      VerificationRecord  `json:"verification"`
	Remediation       string              `json:"remediation"`
	RemediationAdvice *RemediationAdvice  `json:"remediation_advice,omitempty"`
	Provenance        *EvidenceProvenance `json:"provenance,omitempty"`
	Source            string              `json:"source"`
	Fingerprint       string              `json:"fingerprint"`
	Score             int                 `json:"score"`
	Timestamp         time.Time           `json:"timestamp,omitempty"`
}

// SecurityStory represents a correlated relationship between multiple findings.
type SecurityStory struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Summary          string   `json:"summary,omitempty"`
	Description      string   `json:"description"`
	Evidence         []string `json:"evidence"`
	Impact           string   `json:"impact"`
	Severity         string   `json:"severity"`
	Confidence       string   `json:"confidence"`
	RiskContribution int      `json:"risk_contribution,omitempty"`
	InvestigateFirst string   `json:"investigate_first,omitempty"`
	Remediation      string   `json:"remediation"`
	RelatedIDs       []string `json:"related_finding_ids"`
}

// AttackPathSummary represents an evidence-backed correlated attack path in client-facing reports.
type AttackPathSummary struct {
	ID                string   `json:"id"`
	Title             string   `json:"title"`
	Status            string   `json:"status"`
	Confidence        string   `json:"confidence"`
	CombinedRiskLevel string   `json:"combined_risk_level"`
	CombinedRiskScore int      `json:"combined_risk_score"`
	RiskRationale     string   `json:"risk_rationale,omitempty"`
	EntryPoint        string   `json:"entry_point,omitempty"`
	TargetAsset       string   `json:"target_asset"`
	PrimaryWeakness   string   `json:"primary_weakness"`
	TerminalImpact    string   `json:"terminal_impact"`
	Transitions       []string `json:"transitions,omitempty"`
	Assumptions       []string `json:"assumptions,omitempty"`
	MissingEvidence   []string `json:"missing_evidence,omitempty"`
	Remediation       string   `json:"remediation,omitempty"`
	NodeIDs           []string `json:"node_ids"`
	SyntheticFixture  bool     `json:"synthetic_fixture,omitempty"`
}

// Summary provides a statistical breakdown of findings.
type Summary struct {
	TotalFindings             int            `json:"total_findings"`
	CriticalCount             int            `json:"critical_count"`
	HighCount                 int            `json:"high_count"`
	MediumCount               int            `json:"medium_count"`
	LowCount                  int            `json:"low_count"`
	InfoCount                 int            `json:"info_count"`
	VerifiedCount             int            `json:"verified_count"`
	DetectedCount             int            `json:"detected_count"`
	ObservedCount             int            `json:"observed_count"`
	NotVerifiedCount          int            `json:"not_verified_count"`
	NotExposedCount           int            `json:"not_exposed_count"`
	AttemptedCount            int            `json:"attempted_count,omitempty"`
	BlockedCount              int            `json:"blocked_count,omitempty"`
	InconclusiveCount         int            `json:"inconclusive_count,omitempty"`
	SyntheticCount            int            `json:"synthetic_count,omitempty"`
	VerificationRateAttempted float64               `json:"verification_rate_attempted,omitempty"`
	VerificationRateTotal     float64               `json:"verification_rate_total,omitempty"`
	ConfirmedCount            int                   `json:"confirmed_count"`
	SuspectedCount            int                   `json:"suspected_count"`
	InconclusiveStatusCount   int                   `json:"inconclusive_status_count,omitempty"`
	NotTestedCount            int                   `json:"not_tested_count"`
	ErrorCount                int                   `json:"error_count"`
	ByStatus                  map[FindingStatus]int `json:"by_status,omitempty"`
	ScoreAvailable            bool                  `json:"score_available"`
	BySource                  map[string]int        `json:"by_source"`
}

// Report represents the complete audit results ready for presentation or export.
type Report struct {
	Version             string              `json:"version"`
	Target              string              `json:"target"`
	Targets             []string            `json:"targets,omitempty"`
	Timestamp           string              `json:"timestamp"`
	Duration            string              `json:"duration,omitempty"`
	DurationMs          int64               `json:"duration_ms,omitempty"`
	RequestCount        int                 `json:"request_count,omitempty"`
	CompletionStatus    string              `json:"completion_status,omitempty"`
	RiskScoreAvailable  bool                `json:"risk_score_available"`
	RiskScore           int                 `json:"risk_score"`
	RiskLevel           string              `json:"risk_level"`
	Summary             Summary             `json:"summary"`
	TopPriorities       []Finding           `json:"top_priorities"`
	Findings            []Finding           `json:"findings"`
	SecurityStories     []SecurityStory     `json:"security_stories"`
	AttackPaths         []AttackPathSummary `json:"attack_paths,omitempty"`
	VerificationSummary map[string]any      `json:"verification_summary,omitempty"`
	CommercialReport    *CommercialReport   `json:"commercial_report,omitempty"`
	Metadata            map[string]any      `json:"metadata,omitempty"`
}

// FromSecretFinding converts an Engine 2 secret finding to the unified model.
func FromSecretFinding(target string, f secrets.SecretFinding) Finding {
	endpoint := f.FileOrigin
	if endpoint == "" {
		endpoint = target
	}
	desc := f.Title
	if desc == "" {
		desc = fmt.Sprintf("%s pattern identified in client asset", f.Type)
	}

	loc := endpoint
	if f.LineNumber > 0 {
		loc = fmt.Sprintf("%s:%d", endpoint, f.LineNumber)
	}

	detMethod := "static_pattern_signature"
	if f.Type == secrets.SecretHighEntropy {
		detMethod = "shannon_entropy_heuristic"
	}

	evDetails := EvidenceDetails{
		Observation:      fmt.Sprintf("Observed %s pattern matching credential format (%s)", f.Title, f.Redacted),
		Location:         loc,
		HTTPMethod:       "GET",
		DetectionMethod:  detMethod,
		DetectionStatus:  "DETECTED",
		NegativeEvidence: "Static code analysis only; candidate was not submitted to provider endpoints or verified as an active live credential.",
		Details: map[string]string{
			"secret_type":    string(f.Type),
			"redacted_value": f.Redacted,
			"source_asset":   endpoint,
		},
	}
	if f.LineNumber > 0 {
		evDetails.Details["line_number"] = strconv.Itoa(f.LineNumber)
	}

	ver := VerificationRecord{
		Status:          VerificationNotVerified,
		DetectionStatus: "DETECTED",
		AnalysisMethod:  AnalysisMethodStatic,
		Result:          fmt.Sprintf("Discovered in client bundle (%s); live credential validity was not tested.", loc),
		Rationale:       "Live credential testing is intentionally avoided to eliminate risk of account lockout, quota consumption, or security policy violations.",
	}

	evidenceSummary := f.Evidence
	if evidenceSummary == "" && f.Redacted != "" {
		evidenceSummary = fmt.Sprintf("Observed %s in %s (line %d): %s", f.Type, endpoint, f.LineNumber, f.Redacted)
	}

	ruleID := fmt.Sprintf("SEC-%s", strings.ToUpper(strings.ReplaceAll(string(f.Type), "_", "-")))
	finding := Finding{
		ID:              fmt.Sprintf("SEC-%s", shortHash(f.Fingerprint)),
		RuleID:          ruleID,
		Status:          FindingStatusSuspected,
		AnalysisMethod:  AnalysisMethodStatic,
		Title:           f.Title,
		Category:        string(f.Type),
		Severity:        NormalizeSeverity(f.Severity),
		Confidence:      NormalizeConfidence(f.Confidence),
		Target:          target,
		Endpoint:        endpoint,
		Method:          "GET",
		Description:     desc,
		Evidence:        evidenceSummary,
		EvidenceDetails: evDetails,
		Verification:    ver,
		Source:          SourceSecrets,
		Fingerprint:     f.Fingerprint,
	}

	prov := NewEvidenceProvenance(
		SourceSecrets,
		ruleID,
		finding.ID,
		"",
		"secret_pattern",
		loc,
		detMethod,
		evidenceSummary,
	)
	prov.AnalysisMethod = AnalysisMethodStatic
	finding.Provenance = &prov
	finding.EvidenceDetails.Provenance = &prov

	return NormalizeFinding(finding)
}

// FromCloudFinding converts an Engine 3 cloud finding to the unified model.
func FromCloudFinding(target string, f cloud.CloudFinding) Finding {
	title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Provider)), f.Category)
	if f.Description != "" {
		title = f.Description
	}

	detMethod := "active_probe"
	detStatus := "OBSERVED"
	verStatus := VerificationVerified
	verResult := f.Description
	negEvidence := ""
	httpStatus := 200

	catLower := strings.ToLower(NormalizeCategory(f.Category))
	switch {
	case strings.Contains(catLower, "connection-indicator") || strings.Contains(catLower, "connection indicator") ||
		f.Details["analysis_method"] == "STATIC_ANALYSIS" || f.Details["indicator_type"] != "":
		detMethod = "static_analysis"
		detStatus = "INDICATOR_DETECTED"
		verStatus = VerificationNotVerified
		verResult = "Static connection indicator detected; service connectivity and access not verified."
		negEvidence = "Static analysis only. Zero active network connections or DNS queries were made. Service reachability, credential validity, and resource exposure remain unverified."
		httpStatus = 0

	case strings.Contains(catLower, "privileged"):
		detMethod = "static_analysis"
		detStatus = "DETECTED"
		verStatus = VerificationNotVerified
		verResult = "Privileged token detected in client asset; live administrative API calls were not executed."
		negEvidence = "Privileged credentials were strictly NOT used to probe live cloud infrastructure."
		httpStatus = 0

	case strings.Contains(catLower, "client-configuration") || strings.Contains(catLower, "anon-key") ||
		strings.Contains(catLower, "anon_key") || catLower == "anon":
		detMethod = "configuration_discovery"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Observed standard publishable client-side key; access permissions governed by Row Level Security."
		negEvidence = "No privileged credential exposure or unauthorized data access demonstrated."

	case strings.Contains(catLower, "endpoint-discovered") || strings.Contains(catLower, "provider-discovered") ||
		strings.Contains(catLower, "cloud-provider"):
		detMethod = "static_analysis"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Cloud infrastructure component identified in client assets."
		negEvidence = "Reference only; no unauthorized data access demonstrated."
		httpStatus = 0

	case strings.Contains(catLower, "access-denied") || strings.Contains(catLower, "rls-enforced") ||
		strings.Contains(catLower, "401") || strings.Contains(catLower, "403"):
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationNotExposed
		verResult = "Probe confirmed authorization boundary: access denied by Row Level Security (RLS) / API authentication (HTTP 401/403)."
		negEvidence = "HTTP 401/403 response received; no unauthorized data exposure demonstrated."

	case strings.Contains(catLower, "public-endpoint") || strings.Contains(catLower, "normal-response"):
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationVerified
		verResult = "HTTP 200 OK returned non-sensitive or public data; no unauthorized data exposure demonstrated."
		negEvidence = "No unauthorized sensitive database records observed."

	case strings.Contains(catLower, "unauthorized-data-exposure") || strings.Contains(catLower, "unauthorized data exposure"):
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request returned live database records with HTTP 200 OK."

	case strings.Contains(catLower, "database-access") || strings.Contains(catLower, "database access"):
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to database endpoint returned live data with HTTP 200 OK."

	case strings.Contains(catLower, "bucket-listing") || strings.Contains(catLower, "bucket listing"):
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Anonymous GET request returned XML ListBucketResult with bucket contents."
		negEvidence = "Bucket contents were not downloaded."
	}

	if f.HTTPStatus > 0 {
		httpStatus = f.HTTPStatus
	}
	if f.NegativeEvidence != "" {
		negEvidence = f.NegativeEvidence
	}
	cldDetails := map[string]string{
		"provider": string(f.Provider),
		"category": f.Category,
	}
	for k, v := range f.Details {
		cldDetails[k] = v
	}

	evDetails := EvidenceDetails{
		Observation:      f.Evidence,
		Location:         f.Endpoint,
		HTTPMethod:       "GET",
		HTTPStatus:       httpStatus,
		DetectionMethod:  detMethod,
		DetectionStatus:  detStatus,
		NegativeEvidence: negEvidence,
		Details:          cldDetails,
	}

	aMethod := AnalysisMethodStatic
	if detMethod == "active_probe" {
		aMethod = AnalysisMethodActive
	}

	ver := VerificationRecord{
		Status:          verStatus,
		DetectionStatus: detStatus,
		AnalysisMethod:  aMethod,
		Result:          verResult,
	}

	ruleID := fmt.Sprintf("CLD-%s-%s", strings.ToUpper(string(f.Provider)), strings.ToUpper(strings.ReplaceAll(f.Category, "_", "-")))
	fStatus := FindingStatusSuspected
	if verStatus == VerificationVerified || verStatus == VerificationObserved {
		fStatus = FindingStatusConfirmed
	} else if verStatus == VerificationNotExposed {
		fStatus = FindingStatusInconclusive
	}

	finding := Finding{
		ID:              fmt.Sprintf("CLD-%s", shortHash(f.Fingerprint)),
		RuleID:          ruleID,
		Status:          fStatus,
		AnalysisMethod:  aMethod,
		Title:           title,
		Category:        f.Category,
		Severity:        NormalizeSeverity(f.Severity),
		Confidence:      NormalizeConfidence(f.Confidence),
		Target:          target,
		Endpoint:        f.Endpoint,
		Method:          "GET",
		Description:     f.Description,
		Evidence:        f.Evidence,
		EvidenceDetails: evDetails,
		Verification:    ver,
		Source:          SourceCloud,
		Fingerprint:     f.Fingerprint,
	}

	prov := NewEvidenceProvenance(
		SourceCloud,
		ruleID,
		finding.ID,
		"",
		"cloud_resource",
		f.Endpoint,
		detMethod,
		f.Evidence,
	)
	prov.AnalysisMethod = aMethod
	finding.Provenance = &prov
	finding.EvidenceDetails.Provenance = &prov

	return NormalizeFinding(finding)
}

// FromAPIFinding converts an Engine 4 API finding to the unified model.
func FromAPIFinding(target string, f api.APIFinding) Finding {
	title := f.Description
	if title == "" {
		title = fmt.Sprintf("API observation: %s", f.Category)
	}

	cat := NormalizeCategory(f.Category)
	detMethod := "active_probe"
	detStatus := "OBSERVED"
	verStatus := VerificationVerified
	verResult := f.Description
	negEvidence := ""
	httpStatus := 200

	switch {
	case cat == "cors-wildcard":
		detMethod = "header_inspection"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Wildcard CORS origin observed on public endpoint; credential reflection not present."
		negEvidence = "Access-Control-Allow-Credentials header was absent. Credentialed cross-origin exposure was not demonstrated."

	case cat == "cors-origin-reflection":
		if f.Severity == api.SeverityHigh {
			detStatus = "DETECTED"
			verStatus = VerificationVerified
			verResult = "Arbitrary-origin reflection with Access-Control-Allow-Credentials: true confirmed."
		} else {
			detStatus = "OBSERVED"
			verStatus = VerificationObserved
			verResult = "Arbitrary origin reflected without credentials allowed."
			negEvidence = "Access-Control-Allow-Credentials header was absent or false; credentials cannot be sent."
		}

	case cat == "graphql-endpoint-discovered":
		detMethod = "asset_ingestion"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "GraphQL route identified in client assets; schema introspection not yet confirmed."
		negEvidence = "Route discovered; introspection query not yet confirmed."
		httpStatus = 0

	case cat == "graphql-introspection-denied":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationNotExposed
		verResult = "GraphQL schema introspection disabled or requires authentication."
		negEvidence = "Introspection query was rejected; schema metadata not accessible."

	case cat == "graphql-introspection":
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "GraphQL schema introspection query executed successfully and returned types."
		negEvidence = "Full schema dump omitted to preserve audit bounds."

	case strings.HasPrefix(cat, "missing-"):
		detMethod = "header_inspection"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = fmt.Sprintf("Evaluated server HTTP response headers; confirmed absence of %s defense-in-depth header (configuration state, not an independently exploitable vulnerability).", cat)
		negEvidence = "No defense-in-depth security header was returned by the web server."

	case strings.HasPrefix(cat, "weak-"):
		detMethod = "header_inspection"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = fmt.Sprintf("Evaluated server HTTP response headers; weak configuration detected in %s (configuration state, not an independently exploitable vulnerability).", cat)
		negEvidence = "Defense-in-depth posture observation; exploitability requires an independent injection vector."

	case cat == "api-docs-exposure":
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Public OpenAPI / Swagger specification discovered and accessible."
		negEvidence = "Informational API documentation disclosure; no unauthorized endpoints or administrative bypass demonstrated."

	case cat == "health-endpoint", cat == "metrics-exposure":
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Operational monitoring telemetry endpoint responded with HTTP 200 OK."
		negEvidence = "Standard service health/metrics data; no administrative credential access demonstrated."

	case cat == "actuator-health-detailed":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Spring Boot Actuator health endpoint exposed internal component and infrastructure telemetry."
		negEvidence = "Component telemetry observed; administrative credential access not verified."

	case cat == "actuator-env-exposure":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Spring Boot Actuator environment endpoint exposed configuration properties."
		negEvidence = "All environment property values were bounded and redacted."

	case cat == "actuator-mappings-exposure":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Spring Boot Actuator mappings endpoint exposed internal application route definitions."
		negEvidence = "Route patterns cataloged without recursive probe requests."

	case cat == "actuator-endpoint-restricted":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationNotExposed
		verResult = "Spring Boot Actuator endpoint is protected by authentication or access controls (HTTP 401/403)."
		negEvidence = "Authentication challenge or authorization refusal active."

	case cat == "django-debug-mode":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Django technical 500 debug page confirmed (DEBUG=True). Detailed traceback and environment data exposed."
		negEvidence = "All traceback paths and settings values were bounded and redacted."

	case cat == "django-urlconf-disclosure":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Django technical 404 page exposed application URLconf routing patterns."
		negEvidence = "URL patterns cataloged without recursive probing."

	case cat == "django-browsable-api":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Django REST Framework browsable API interface is publicly accessible."
		negEvidence = "Browsable API observed on endpoint; authorization checks apply to individual API operations."

	case cat == "fastapi-docs-exposure":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationObserved
		verResult = "Public FastAPI / OpenAPI documentation discovered and accessible."
		negEvidence = "Informational API documentation disclosure; no internal administrative routes or credentials observed."

	case cat == "fastapi-sensitive-paths":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "FastAPI OpenAPI specification revealed sensitive internal or administrative route paths."
		negEvidence = "Disclosed route patterns cataloged without recursive probing."

	case cat == "fastapi-sensitive-schema":
		detMethod = "active_probe"
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "FastAPI OpenAPI specification contains embedded credentials, tokens, or sensitive default values."
		negEvidence = "All discovered secret values were redacted from output."

	case cat == "sensitive-endpoint-protected":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationNotExposed
		verResult = "Probe confirmed endpoint is protected or non-existent (HTTP 404/401/403). No exposure demonstrated."
		negEvidence = "Endpoint access was denied or path is not present."

	case cat == "sensitive-endpoint-normal":
		detMethod = "active_probe"
		detStatus = "OBSERVED"
		verStatus = VerificationVerified
		verResult = "HTTP 200 OK returned standard public or application shell content; no sensitive configuration exposed."
		negEvidence = "Response returned normal content; no sensitive keys or configurations observed."

	case cat == "env-exposure":
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to environment file returned HTTP 200 OK with configuration keys."
		negEvidence = "Secret values were redacted from output."

	case cat == "endpoint-discovered":
		detMethod = f.Mechanism
		if detMethod == "" {
			detMethod = "static_analysis"
		}
		detStatus = "OBSERVED"
		switch f.AuthState {
		case api.AuthStateAuthRequired, api.AuthStateForbidden, api.AuthStateNotFound:
			verStatus = VerificationNotExposed
			negEvidence = fmt.Sprintf("Authentication or authorization barrier active (%s); unauthenticated access not permitted.", f.AuthState)
		default:
			verStatus = VerificationObserved
			negEvidence = "Informational endpoint inventory observation; no vulnerability or unauthorized exposure."
		}
		verResult = fmt.Sprintf("Endpoint %s (%s) discovered in client assets [%s].", f.Endpoint, f.Method, f.Classification)

	case cat == "git-metadata-exposure":
		detStatus = "DETECTED"
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to /.git/HEAD returned valid Git HEAD branch reference."
	}

	details := map[string]string{
		"category": cat,
	}
	if f.Classification != "" {
		details["classification"] = string(f.Classification)
	}
	if f.AuthState != "" {
		details["auth_state"] = string(f.AuthState)
	}
	if f.SourceAsset != "" {
		details["source_asset"] = f.SourceAsset
	}
	if f.Mechanism != "" {
		details["mechanism"] = f.Mechanism
	}
	if f.LineNumber > 0 {
		details["line_number"] = strconv.Itoa(f.LineNumber)
	}
	for k, v := range f.Details {
		details[k] = v
	}

	if f.NegativeEvidence != "" {
		negEvidence = f.NegativeEvidence
	}
	if f.HTTPStatus > 0 {
		httpStatus = f.HTTPStatus
	}

	evDetails := EvidenceDetails{
		Observation:      f.Evidence,
		Location:         f.Endpoint,
		HTTPMethod:       NormalizeMethod(f.Method),
		HTTPStatus:       httpStatus,
		DetectionMethod:  detMethod,
		DetectionStatus:  detStatus,
		NegativeEvidence: negEvidence,
		Details:          details,
	}

	aMethod := AnalysisMethodStatic
	if detMethod == "active_probe" {
		aMethod = AnalysisMethodActive
	}

	ver := VerificationRecord{
		Status:          verStatus,
		DetectionStatus: detStatus,
		AnalysisMethod:  aMethod,
		Result:          verResult,
	}

	ruleID := fmt.Sprintf("API-%s", strings.ToUpper(strings.ReplaceAll(f.Category, "_", "-")))
	fStatus := FindingStatusSuspected
	if verStatus == VerificationVerified || verStatus == VerificationObserved {
		fStatus = FindingStatusConfirmed
	} else if verStatus == VerificationNotExposed {
		fStatus = FindingStatusInconclusive
	}

	finding := Finding{
		ID:              fmt.Sprintf("API-%s", shortHash(f.Fingerprint)),
		RuleID:          ruleID,
		Status:          fStatus,
		AnalysisMethod:  aMethod,
		Title:           title,
		Category:        f.Category,
		Severity:        NormalizeSeverity(f.Severity),
		Confidence:      NormalizeConfidence(f.Confidence),
		Target:          target,
		Endpoint:        f.Endpoint,
		Method:          NormalizeMethod(f.Method),
		Description:     f.Description,
		Evidence:        f.Evidence,
		EvidenceDetails: evDetails,
		Verification:    ver,
		Source:          SourceAPI,
		Fingerprint:     f.Fingerprint,
	}

	prov := NewEvidenceProvenance(
		SourceAPI,
		ruleID,
		finding.ID,
		"",
		"http_response",
		f.Endpoint,
		detMethod,
		f.Evidence,
	)
	prov.AnalysisMethod = aMethod
	finding.Provenance = &prov
	finding.EvidenceDetails.Provenance = &prov

	return NormalizeFinding(finding)
}

// FromCrawlerAsset converts an Engine 1 asset to a finding if it exposes sensitive client artifacts.
func FromCrawlerAsset(target string, a crawler.Asset) (Finding, bool) {
	if a.IsSourceMap || a.Type == crawler.AssetSourceMap {
		evDetails := EvidenceDetails{
			Observation:      fmt.Sprintf("Production source map file (.map) publicly accessible at %s (%d bytes).", a.URL, a.Size),
			Location:         a.URL,
			HTTPMethod:       "GET",
			HTTPStatus:       200,
			DetectionMethod:  "asset_ingestion",
			DetectionStatus:  "OBSERVED",
			NegativeEvidence: "Client source reconstruction asset; no active credential compromise or backend exposure demonstrated.",
			Details: map[string]string{
				"asset_type": "source-map",
				"size_bytes": strconv.FormatInt(a.Size, 10),
			},
		}

		ver := VerificationRecord{
			Status:          VerificationObserved,
			DetectionStatus: "OBSERVED",
			AnalysisMethod:  AnalysisMethodStatic,
			Result:          fmt.Sprintf("Source map asset (.map) was successfully downloaded during crawl (%d bytes).", a.Size),
		}

		f := Finding{
			ID:              fmt.Sprintf("CRW-%s", shortHash(a.URL)),
			RuleID:          "CRW-SOURCE-MAP",
			Status:          FindingStatusConfirmed,
			AnalysisMethod:  AnalysisMethodStatic,
			Title:           "Public JavaScript Source Map Discovered",
			Category:        "source-map-discovered",
			Severity:        SeverityInfo,
			Confidence:      ConfidenceHigh,
			Target:          target,
			Endpoint:        a.URL,
			Method:          "GET",
			Description:     "Production source map file (.map) is publicly downloadable, reconstructing original source code structure.",
			Evidence:        fmt.Sprintf("Source map asset accessible at %s (%d bytes)", a.URL, a.Size),
			EvidenceDetails: evDetails,
			Verification:    ver,
			Source:          SourceCrawler,
		}
		prov := NewEvidenceProvenance(
			SourceCrawler,
			f.RuleID,
			f.ID,
			"",
			"client_asset",
			a.URL,
			"asset_ingestion",
			f.Evidence,
		)
		prov.AnalysisMethod = AnalysisMethodStatic
		f.Provenance = &prov
		f.EvidenceDetails.Provenance = &prov
		return NormalizeFinding(f), true
	}
	return Finding{}, false
}

// FromCrawlerDiscovery converts any discovered crawler asset to an inventory observation finding.
func FromCrawlerDiscovery(target string, a crawler.Asset) Finding {
	evDetails := EvidenceDetails{
		Observation:      fmt.Sprintf("%s asset discovered at %s (%d bytes).", a.Type, a.URL, a.Size),
		Location:         a.URL,
		HTTPMethod:       "GET",
		HTTPStatus:       200,
		DetectionMethod:  "asset_ingestion",
		DetectionStatus:  "OBSERVED",
		NegativeEvidence: "Standard client asset; no vulnerability or security exposure.",
		Details: map[string]string{
			"asset_type": string(a.Type),
			"size_bytes": strconv.FormatInt(a.Size, 10),
		},
	}

	ver := VerificationRecord{
		Status:          VerificationObserved,
		DetectionStatus: "OBSERVED",
		AnalysisMethod:  AnalysisMethodStatic,
		Result:          fmt.Sprintf("Asset observed during crawl of %s.", target),
	}

	f := Finding{
		ID:              fmt.Sprintf("CRW-%s", shortHash(a.URL)),
		RuleID:          fmt.Sprintf("CRW-ASSET-%s", strings.ToUpper(string(a.Type))),
		Status:          FindingStatusConfirmed,
		AnalysisMethod:  AnalysisMethodStatic,
		Title:           fmt.Sprintf("Client Asset Observed: %s", a.Type),
		Category:        fmt.Sprintf("asset-%s", a.Type),
		Severity:        SeverityInfo,
		Confidence:      ConfidenceHigh,
		Target:          target,
		Endpoint:        a.URL,
		Method:          "GET",
		Description:     fmt.Sprintf("Public client-side %s asset observed during site crawling.", a.Type),
		Evidence:        fmt.Sprintf("Asset accessible at %s (%d bytes)", a.URL, a.Size),
		EvidenceDetails: evDetails,
		Verification:    ver,
		Source:          SourceCrawler,
	}
	prov := NewEvidenceProvenance(
		SourceCrawler,
		f.RuleID,
		f.ID,
		"",
		"client_asset",
		a.URL,
		"asset_ingestion",
		f.Evidence,
	)
	prov.AnalysisMethod = AnalysisMethodStatic
	f.Provenance = &prov
	f.EvidenceDetails.Provenance = &prov
	return NormalizeFinding(f)
}

func shortHash(s string) string {
	clean := strings.TrimSpace(s)
	if len(clean) >= 8 {
		return clean[:8]
	}
	if len(clean) > 0 {
		return clean
	}
	return fmt.Sprintf("%x", time.Now().UnixNano())[:8]
}

// AddAffectedAsset appends a unique asset ID to AffectedAssetIDs and sets PrimaryAssetID if empty.
// Returns true if the asset ID was added, or false if already present or invalid.
func (f *Finding) AddAffectedAsset(assetID string) bool {
	clean := strings.TrimSpace(assetID)
	if clean == "" {
		return false
	}
	for _, id := range f.AffectedAssetIDs {
		if id == clean {
			return false
		}
	}
	f.AffectedAssetIDs = append(f.AffectedAssetIDs, clean)
	if f.PrimaryAssetID == "" {
		f.PrimaryAssetID = clean
	}
	return true
}

// ResolveAssetIDs matches finding attributes against the discovery inventory to associate
// relevant asset IDs (e.g. endpoints, services, storage, databases, hosts, and applications).
func (f *Finding) ResolveAssetIDs(inv *discovery.Inventory) {
	if inv == nil || len(inv.Assets) == 0 {
		return
	}

	normTarget := NormalizeURL(f.Target)
	normEndpoint := NormalizeURL(f.Endpoint)

	// 1. Match specific Endpoint assets first
	if normEndpoint != "" {
		for _, a := range inv.Assets {
			if a.Type == discovery.AssetTypeEndpoint {
				if a.Endpoint != nil && (NormalizeURL(a.Endpoint.URL) == normEndpoint || NormalizeURL(a.Endpoint.Path) == normEndpoint) {
					f.AddAffectedAsset(a.ID)
				} else if NormalizeURL(a.CanonicalID) == normEndpoint {
					f.AddAffectedAsset(a.ID)
				}
			}
		}
	}

	// 2. Match Service, Database, Storage, and CloudService assets
	for _, a := range inv.Assets {
		epLower := strings.ToLower(f.Endpoint)
		canID := strings.ToLower(strings.TrimSpace(a.CanonicalID))
		disp := strings.ToLower(strings.TrimSpace(a.DisplayName))

		switch a.Type {
		case discovery.AssetTypeStorage:
			var bkt string
			if a.Storage != nil {
				bkt = strings.ToLower(strings.TrimSpace(a.Storage.BucketName))
			}
			if (canID != "" && strings.Contains(epLower, canID)) || (disp != "" && strings.Contains(epLower, disp)) || (bkt != "" && strings.Contains(epLower, bkt)) {
				f.AddAffectedAsset(a.ID)
			}
		case discovery.AssetTypeDatabase:
			var dbName, dbHost string
			if a.Database != nil {
				dbName = strings.ToLower(strings.TrimSpace(a.Database.InstanceName))
				dbHost = strings.ToLower(strings.TrimSpace(a.Database.Host))
			}
			if (canID != "" && strings.Contains(epLower, canID)) || (disp != "" && strings.Contains(epLower, disp)) || (dbName != "" && strings.Contains(epLower, dbName)) || (dbHost != "" && strings.Contains(epLower, dbHost)) {
				f.AddAffectedAsset(a.ID)
			}
		case discovery.AssetTypeService, discovery.AssetTypeCloudService, discovery.AssetTypeWebService, discovery.AssetTypeAPIService:
			if (canID != "" && strings.Contains(epLower, canID)) || (disp != "" && strings.Contains(epLower, disp)) {
				f.AddAffectedAsset(a.ID)
			}
		}
	}

	// 3. Match Host and Domain assets
	for _, a := range inv.Assets {
		if a.Type == discovery.AssetTypeHost || a.Type == discovery.AssetTypeDomain || a.Type == discovery.AssetTypeSubdomain {
			canID := strings.ToLower(strings.TrimSpace(a.CanonicalID))
			if canID != "" && (strings.Contains(normEndpoint, canID) || strings.Contains(normTarget, canID)) {
				f.AddAffectedAsset(a.ID)
			}
		}
	}

	// 4. Match Application root asset
	for _, a := range inv.Assets {
		if a.Type == discovery.AssetTypeApplication {
			if a.Application != nil && NormalizeURL(a.Application.RootURL) == normTarget {
				f.AddAffectedAsset(a.ID)
			} else if NormalizeURL(a.CanonicalID) == normTarget {
				f.AddAffectedAsset(a.ID)
			}
		}
	}

	if f.PrimaryAssetID != "" {
		if f.Provenance != nil && f.Provenance.AssetID == "" {
			f.Provenance.AssetID = f.PrimaryAssetID
		}
		if f.EvidenceDetails.Provenance != nil && f.EvidenceDetails.Provenance.AssetID == "" {
			f.EvidenceDetails.Provenance.AssetID = f.PrimaryAssetID
		}
	}
}

// ValidateFinding validates that required attributes are present and values conform to specification.
func ValidateFinding(f Finding) error {
	if strings.TrimSpace(f.ID) == "" {
		return errors.New("finding ID cannot be empty")
	}
	if strings.TrimSpace(f.Category) == "" {
		return errors.New("finding Category cannot be empty")
	}
	if strings.TrimSpace(f.Target) == "" {
		return errors.New("finding Target cannot be empty")
	}
	if strings.TrimSpace(f.Endpoint) == "" {
		return errors.New("finding Endpoint cannot be empty")
	}

	// Validate Severity
	normSev := NormalizeSeverity(f.Severity)
	switch normSev {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo, SeverityUnknown:
		// Valid
	default:
		return fmt.Errorf("invalid finding severity: %s", f.Severity)
	}

	// Validate Confidence
	normConf := NormalizeConfidence(f.Confidence)
	switch normConf {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow, ConfidenceUnknown:
		// Valid
	default:
		return fmt.Errorf("invalid finding confidence: %s", f.Confidence)
	}

	// Validate Status
	if f.Status != "" {
		if _, err := ParseFindingStatus(string(f.Status)); err != nil {
			return fmt.Errorf("invalid finding status %q: %w", f.Status, err)
		}
	}

	// Validate AffectedAssetIDs uniqueness
	seenAssets := make(map[string]struct{}, len(f.AffectedAssetIDs))
	for _, id := range f.AffectedAssetIDs {
		clean := strings.TrimSpace(id)
		if clean == "" {
			return errors.New("affected asset ID cannot be empty")
		}
		if _, exists := seenAssets[clean]; exists {
			return fmt.Errorf("duplicate affected asset ID: %s", clean)
		}
		seenAssets[clean] = struct{}{}
	}

	return nil
}

// ValidateAffectedAssets verifies that all associated asset IDs exist in the provided inventory.
func ValidateAffectedAssets(f Finding, inv *discovery.Inventory) error {
	if inv == nil {
		return nil
	}
	if f.PrimaryAssetID != "" {
		if inv.FindByID(f.PrimaryAssetID) == nil {
			return fmt.Errorf("primary asset ID %q not found in inventory", f.PrimaryAssetID)
		}
	}
	for _, id := range f.AffectedAssetIDs {
		if inv.FindByID(id) == nil {
			return fmt.Errorf("affected asset ID %q not found in inventory", id)
		}
	}
	return nil
}

// ComputeEvidenceID generates a deterministic evidence identifier (ev_<24-hex>).
func ComputeEvidenceID(sourceEngine, ruleID, findingID, location, evidenceType string) string {
	h := sha256.New()
	cleanSource := strings.ToLower(strings.TrimSpace(sourceEngine))
	cleanRule := strings.ToUpper(strings.TrimSpace(ruleID))
	cleanFinding := strings.TrimSpace(findingID)
	cleanLocation := strings.TrimSpace(location)
	cleanType := strings.ToLower(strings.TrimSpace(evidenceType))

	payload := fmt.Sprintf("%s|%s|%s|%s|%s", cleanSource, cleanRule, cleanFinding, cleanLocation, cleanType)
	h.Write([]byte(payload))
	sum := h.Sum(nil)
	return fmt.Sprintf("ev_%s", hex.EncodeToString(sum[:12])) // 24 hex characters
}

// ComputeContentDigest calculates a safe SHA-256 digest of sanitized evidence content.
// Secrets MUST NOT be hashed or leaked via digest dictionaries.
// Therefore, any raw text is sanitized prior to computing the content digest.
func ComputeContentDigest(sanitizedContent string) string {
	clean := secrets.RedactText(strings.TrimSpace(sanitizedContent))
	if clean == "" {
		return ""
	}
	h := sha256.Sum256([]byte(clean))
	return fmt.Sprintf("sha256:%x", h)
}

// DefaultEvidenceType returns the canonical evidence type for a given source engine.
func DefaultEvidenceType(sourceEngine string) string {
	switch strings.ToLower(strings.TrimSpace(sourceEngine)) {
	case SourceCrawler:
		return "client_asset"
	case SourceSecrets:
		return "secret_pattern"
	case SourceCloud:
		return "cloud_resource"
	case SourceAPI:
		return "http_response"
	case "auth":
		return "token_artifact"
	case "verification":
		return "reproduction_payload"
	default:
		return "text_observation"
	}
}

// DefaultCollectionMethod returns the canonical collection method for a given source engine.
func DefaultCollectionMethod(sourceEngine string) string {
	switch strings.ToLower(strings.TrimSpace(sourceEngine)) {
	case SourceCrawler:
		return "asset_ingestion"
	case SourceSecrets:
		return "static_pattern_analysis"
	case SourceCloud:
		return "active_probe"
	case SourceAPI:
		return "active_probe"
	case "auth":
		return "static_jwt_header_analysis"
	case "verification":
		return "active_probe"
	default:
		return "passive_observation"
	}
}

// DefaultAnalysisMethod returns the canonical analysis method for a given source engine and collection method.
func DefaultAnalysisMethod(sourceEngine, collectionMethod string) AnalysisMethod {
	cm := strings.ToLower(strings.TrimSpace(collectionMethod))
	if strings.Contains(cm, "active") || strings.Contains(cm, "probe") {
		return AnalysisMethodActive
	}
	if strings.Contains(cm, "manual") {
		return AnalysisMethodManual
	}
	src := strings.ToLower(strings.TrimSpace(sourceEngine))
	switch src {
	case "api_security_engine", "apisec", "api_auditor", "webvuln", "web_vulnerability_engine", "felix-webvuln", "authz", "api_authz", "businesslogic", "business_logic_security_engine", "sessionsec", "session_identity_engine", "verification", "felix-verification":
		return AnalysisMethodActive
	default:
		return AnalysisMethodStatic
	}
}

// NewEvidenceProvenance constructs a valid EvidenceProvenance instance with sanitized digest.
func NewEvidenceProvenance(sourceEngine, ruleID, findingID, assetID, evidenceType, location, collectionMethod, rawEvidence string) EvidenceProvenance {
	src := NormalizeSource(sourceEngine)
	if evidenceType == "" {
		evidenceType = DefaultEvidenceType(src)
	}
	if collectionMethod == "" {
		collectionMethod = DefaultCollectionMethod(src)
	}
	cleanLoc := secrets.SanitizeURL(location)
	evID := ComputeEvidenceID(src, ruleID, findingID, cleanLoc, evidenceType)
	digest := ComputeContentDigest(rawEvidence)
	aMethod := DefaultAnalysisMethod(src, collectionMethod)

	return EvidenceProvenance{
		EvidenceID:       evID,
		EvidenceType:     evidenceType,
		SourceEngine:     src,
		RuleID:           ruleID,
		FindingID:        findingID,
		AssetID:          assetID,
		Location:         cleanLoc,
		CollectionMethod: collectionMethod,
		AnalysisMethod:   aMethod,
		ContentDigest:    digest,
	}
}

// ValidateEvidenceProvenance ensures that the provenance contains valid required fields.
func ValidateEvidenceProvenance(p EvidenceProvenance) error {
	if strings.TrimSpace(p.EvidenceID) == "" {
		return errors.New("evidence ID cannot be empty")
	}
	if strings.TrimSpace(p.SourceEngine) == "" {
		return errors.New("source engine cannot be empty")
	}
	if p.ContentDigest != "" && !strings.HasPrefix(p.ContentDigest, "sha256:") {
		return fmt.Errorf("content digest must start with 'sha256:', got: %s", p.ContentDigest)
	}
	return nil
}

// SanitizeEvidenceProvenance scrubs credentials from provenance fields (Location, VerificationContext)
// and preserves safe content digest.
func SanitizeEvidenceProvenance(p EvidenceProvenance) EvidenceProvenance {
	cleanP := p
	cleanP.Location = secrets.SanitizeURL(p.Location)
	cleanP.Location = secrets.RedactText(cleanP.Location)
	if p.VerificationContext != "" {
		cleanP.VerificationContext = secrets.RedactText(p.VerificationContext)
	}
	return cleanP
}
