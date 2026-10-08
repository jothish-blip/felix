package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

// Standard Severity levels.
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// Standard Confidence levels.
const (
	ConfidenceHigh   = "HIGH"
	ConfidenceMedium = "MEDIUM"
	ConfidenceLow    = "LOW"
)

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
	Status    VerificationStatus `json:"status"`
	Result    string             `json:"result"`
	Rationale string             `json:"rationale,omitempty"`
}

// EvidenceDetails provides structured, machine-readable evidence for a finding.
type EvidenceDetails struct {
	Observation      string            `json:"observation"`
	Location         string            `json:"location"`
	HTTPMethod       string            `json:"http_method,omitempty"`
	HTTPStatus       int               `json:"http_status,omitempty"`
	ContentType      string            `json:"content_type,omitempty"`
	DetectionMethod  string            `json:"detection_method"`
	NegativeEvidence string            `json:"negative_evidence,omitempty"`
	Details          map[string]string `json:"details,omitempty"`
}

// Finding represents a normalized, deduplicated security observation or exposure.
type Finding struct {
	ID              string             `json:"id"`
	Title           string             `json:"title"`
	Category        string             `json:"category"`
	Severity        string             `json:"severity"`
	Confidence      string             `json:"confidence"`
	Target          string             `json:"target"`
	Endpoint        string             `json:"endpoint"`
	Method          string             `json:"method"`
	Description     string             `json:"description"`
	Evidence        string             `json:"evidence_summary,omitempty"`
	EvidenceDetails EvidenceDetails    `json:"evidence"`
	Verification    VerificationRecord `json:"verification"`
	Remediation     string             `json:"remediation"`
	Source          string             `json:"source"`
	Fingerprint     string             `json:"fingerprint"`
	Score           int                `json:"score"`
}

// SecurityStory represents a correlated relationship between multiple findings.
type SecurityStory struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
	Impact      string   `json:"impact"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Remediation string   `json:"remediation"`
	RelatedIDs  []string `json:"related_finding_ids"`
}

// Summary provides a statistical breakdown of findings.
type Summary struct {
	TotalFindings int            `json:"total_findings"`
	CriticalCount int            `json:"critical_count"`
	HighCount     int            `json:"high_count"`
	MediumCount   int            `json:"medium_count"`
	LowCount      int            `json:"low_count"`
	InfoCount     int            `json:"info_count"`
	BySource      map[string]int `json:"by_source"`
}

// Report represents the complete audit results ready for presentation or export.
type Report struct {
	Version         string          `json:"version"`
	Target          string          `json:"target"`
	Targets         []string        `json:"targets,omitempty"`
	Timestamp       string          `json:"timestamp"`
	RiskScore       int             `json:"risk_score"`
	RiskLevel       string          `json:"risk_level"`
	Summary         Summary         `json:"summary"`
	TopPriorities   []Finding       `json:"top_priorities"`
	Findings        []Finding       `json:"findings"`
	SecurityStories []SecurityStory `json:"security_stories"`
	Metadata        map[string]any  `json:"metadata,omitempty"`
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
		Status:    VerificationNotVerified,
		Result:    fmt.Sprintf("Discovered in client bundle (%s); live credential validity was not tested.", loc),
		Rationale: "Live credential testing is intentionally avoided to eliminate risk of account lockout, quota consumption, or security policy violations.",
	}

	evidenceSummary := f.Evidence
	if evidenceSummary == "" && f.Redacted != "" {
		evidenceSummary = fmt.Sprintf("Observed %s in %s (line %d): %s", f.Type, endpoint, f.LineNumber, f.Redacted)
	}

	finding := Finding{
		ID:              fmt.Sprintf("SEC-%s", shortHash(f.Fingerprint)),
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

	return NormalizeFinding(finding)
}

// FromCloudFinding converts an Engine 3 cloud finding to the unified model.
func FromCloudFinding(target string, f cloud.CloudFinding) Finding {
	title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Provider)), f.Category)
	if f.Description != "" {
		title = f.Description
	}

	detMethod := "active_probe"
	verStatus := VerificationVerified
	verResult := f.Description
	negEvidence := ""
	httpStatus := 200

	catLower := strings.ToLower(f.Category)
	switch {
	case strings.Contains(catLower, "privileged"):
		detMethod = "static_analysis"
		verStatus = VerificationNotVerified
		verResult = "Privileged token detected in client asset; live administrative API calls were not executed."
		negEvidence = "Privileged credentials were strictly NOT used to probe live cloud infrastructure."
		httpStatus = 0

	case strings.Contains(catLower, "client configuration") || strings.Contains(catLower, "anon"):
		detMethod = "configuration_discovery"
		verStatus = VerificationObserved
		verResult = "Observed standard publishable client-side key; access permissions governed by Row Level Security."
		negEvidence = "No privileged credential exposure or unauthorized data access demonstrated."

	case strings.Contains(catLower, "unauthorized data exposure"):
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request returned live database records with HTTP 200 OK."

	case strings.Contains(catLower, "database access"):
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to database endpoint returned live data with HTTP 200 OK."

	case strings.Contains(catLower, "bucket listing"):
		verStatus = VerificationVerified
		verResult = "Anonymous GET request returned XML ListBucketResult with bucket contents."
		negEvidence = "Bucket contents were not downloaded."
	}

	evDetails := EvidenceDetails{
		Observation:      f.Evidence,
		Location:         f.Endpoint,
		HTTPMethod:       "GET",
		HTTPStatus:       httpStatus,
		DetectionMethod:  detMethod,
		NegativeEvidence: negEvidence,
		Details: map[string]string{
			"provider": string(f.Provider),
			"category": f.Category,
		},
	}

	ver := VerificationRecord{
		Status: verStatus,
		Result: verResult,
	}

	finding := Finding{
		ID:              fmt.Sprintf("CLD-%s", shortHash(f.Fingerprint)),
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
	verStatus := VerificationVerified
	verResult := f.Description
	negEvidence := ""
	httpStatus := 200

	switch {
	case cat == "cors-wildcard":
		detMethod = "header_inspection"
		verStatus = VerificationObserved
		verResult = "Wildcard CORS origin observed on public endpoint; credential reflection not present."
		negEvidence = "Access-Control-Allow-Credentials header was absent. Credentialed cross-origin exposure was not demonstrated."

	case cat == "cors-origin-reflection":
		if f.Severity == api.SeverityHigh {
			verStatus = VerificationVerified
			verResult = "Arbitrary-origin reflection with Access-Control-Allow-Credentials: true confirmed."
		} else {
			verStatus = VerificationObserved
			verResult = "Arbitrary origin reflected without credentials allowed."
			negEvidence = "Access-Control-Allow-Credentials header was absent or false; credentials cannot be sent."
		}

	case cat == "graphql-introspection":
		verStatus = VerificationVerified
		verResult = "GraphQL schema introspection query executed successfully and returned types."
		negEvidence = "Full schema dump omitted to preserve audit bounds."

	case strings.HasPrefix(cat, "missing-"):
		detMethod = "header_inspection"
		verStatus = VerificationVerified
		verResult = fmt.Sprintf("Evaluated server HTTP response headers; %s defense-in-depth header was not present.", cat)
		negEvidence = "No defense-in-depth security header was returned by the web server."

	case cat == "api-docs-exposure":
		verStatus = VerificationObserved
		verResult = "Public OpenAPI / Swagger specification discovered and accessible."
		negEvidence = "Informational API documentation disclosure; no unauthorized endpoints or administrative bypass demonstrated."

	case cat == "health-endpoint", cat == "metrics-exposure":
		verStatus = VerificationObserved
		verResult = "Operational monitoring telemetry endpoint responded with HTTP 200 OK."
		negEvidence = "Standard service health/metrics data; no administrative credential access demonstrated."

	case cat == "env-exposure":
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to environment file returned HTTP 200 OK with configuration keys."
		negEvidence = "Secret values were redacted from output."

	case cat == "git-metadata-exposure":
		verStatus = VerificationVerified
		verResult = "Unauthenticated GET request to /.git/HEAD returned valid Git HEAD branch reference."
	}

	evDetails := EvidenceDetails{
		Observation:      f.Evidence,
		Location:         f.Endpoint,
		HTTPMethod:       NormalizeMethod(f.Method),
		HTTPStatus:       httpStatus,
		DetectionMethod:  detMethod,
		NegativeEvidence: negEvidence,
		Details: map[string]string{
			"category": cat,
		},
	}

	ver := VerificationRecord{
		Status: verStatus,
		Result: verResult,
	}

	finding := Finding{
		ID:              fmt.Sprintf("API-%s", shortHash(f.Fingerprint)),
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
			NegativeEvidence: "Source code disclosure; no direct credential compromise demonstrated.",
			Details: map[string]string{
				"asset_type": "source-map",
				"size_bytes": strconv.FormatInt(a.Size, 10),
			},
		}

		ver := VerificationRecord{
			Status: VerificationObserved,
			Result: fmt.Sprintf("Source map asset (.map) was successfully downloaded during crawl (%d bytes).", a.Size),
		}

		f := Finding{
			ID:              fmt.Sprintf("CRW-%s", shortHash(a.URL)),
			Title:           "Public JavaScript Source Map Exposed",
			Category:        "source-map-exposure",
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
		return NormalizeFinding(f), true
	}
	return Finding{}, false
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
