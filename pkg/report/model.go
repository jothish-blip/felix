package report

import (
	"fmt"
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

// Finding represents a normalized, deduplicated security observation or exposure.
type Finding struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Target      string `json:"target"`
	Endpoint    string `json:"endpoint"`
	Method      string `json:"method"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Remediation string `json:"remediation"`
	Source      string `json:"source"`
	Fingerprint string `json:"fingerprint"`
	Score       int    `json:"score"`
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
		desc = fmt.Sprintf("Exposed %s detected in client asset", f.Type)
	}

	finding := Finding{
		ID:          fmt.Sprintf("SEC-%s", shortHash(f.Fingerprint)),
		Title:       f.Title,
		Category:    string(f.Type),
		Severity:    NormalizeSeverity(f.Severity),
		Confidence:  NormalizeConfidence(f.Confidence),
		Target:      target,
		Endpoint:    endpoint,
		Method:      "GET",
		Description: desc,
		Evidence:    f.Evidence,
		Source:      SourceSecrets,
		Fingerprint: f.Fingerprint,
	}

	if finding.Evidence == "" && f.Redacted != "" {
		origin := f.FileOrigin
		if origin == "" {
			origin = target
		}
		finding.Evidence = fmt.Sprintf("Observed %s in %s (line %d): %s", f.Type, origin, f.LineNumber, f.Redacted)
	}

	return NormalizeFinding(finding)
}

// FromCloudFinding converts an Engine 3 cloud finding to the unified model.
func FromCloudFinding(target string, f cloud.CloudFinding) Finding {
	title := fmt.Sprintf("[%s] %s", strings.ToUpper(string(f.Provider)), f.Category)
	if f.Description != "" {
		title = f.Description
	}

	finding := Finding{
		ID:          fmt.Sprintf("CLD-%s", shortHash(f.Fingerprint)),
		Title:       title,
		Category:    f.Category,
		Severity:    NormalizeSeverity(f.Severity),
		Confidence:  NormalizeConfidence(f.Confidence),
		Target:      target,
		Endpoint:    f.Endpoint,
		Method:      "GET",
		Description: f.Description,
		Evidence:    f.Evidence,
		Source:      SourceCloud,
		Fingerprint: f.Fingerprint,
	}

	return NormalizeFinding(finding)
}

// FromAPIFinding converts an Engine 4 API finding to the unified model.
func FromAPIFinding(target string, f api.APIFinding) Finding {
	title := f.Description
	if title == "" {
		title = fmt.Sprintf("API observation: %s", f.Category)
	}

	finding := Finding{
		ID:          fmt.Sprintf("API-%s", shortHash(f.Fingerprint)),
		Title:       title,
		Category:    f.Category,
		Severity:    NormalizeSeverity(f.Severity),
		Confidence:  NormalizeConfidence(f.Confidence),
		Target:      target,
		Endpoint:    f.Endpoint,
		Method:      NormalizeMethod(f.Method),
		Description: f.Description,
		Evidence:    f.Evidence,
		Source:      SourceAPI,
		Fingerprint: f.Fingerprint,
	}

	return NormalizeFinding(finding)
}

// FromCrawlerAsset converts an Engine 1 asset to a finding if it exposes sensitive client artifacts.
func FromCrawlerAsset(target string, a crawler.Asset) (Finding, bool) {
	if a.IsSourceMap || a.Type == crawler.AssetSourceMap {
		f := Finding{
			ID:          fmt.Sprintf("CRW-%s", shortHash(a.URL)),
			Title:       "Public JavaScript Source Map Exposed",
			Category:    "source-map-exposure",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceHigh,
			Target:      target,
			Endpoint:    a.URL,
			Method:      "GET",
			Description: "Production source map file (.map) is publicly downloadable, reconstructing original source code structure.",
			Evidence:    fmt.Sprintf("Source map asset accessible at %s (%d bytes)", a.URL, a.Size),
			Source:      SourceCrawler,
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
