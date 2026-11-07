package mobile

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
)

// Platform represents the target mobile OS.
type Platform string

const (
	PlatformAndroid Platform = "android"
	PlatformIOS     Platform = "ios"
	PlatformUnknown Platform = "unknown"
)

// ComponentType distinguishes Android application component categories.
type ComponentType string

const (
	ComponentActivity ComponentType = "activity"
	ComponentService  ComponentType = "service"
	ComponentReceiver ComponentType = "receiver"
	ComponentProvider ComponentType = "provider"
)

// FindingClassification categorizes finding certainty.
type FindingClassification string

const (
	ClassificationConfirmed    FindingClassification = "CONFIRMED"
	ClassificationPotential    FindingClassification = "POTENTIAL"
	ClassificationInfo         FindingClassification = "INFO"
	ClassificationInconclusive FindingClassification = "INCONCLUSIVE"
)

// IntentFilter represents intent matching rules declared for an Android component.
type IntentFilter struct {
	Actions     []string `json:"actions,omitempty"`
	Categories  []string `json:"categories,omitempty"`
	DataSchemes []string `json:"data_schemes,omitempty"`
}

// AndroidComponent models an extracted Android activity, service, receiver, or content provider.
type AndroidComponent struct {
	Type               ComponentType  `json:"type"`
	Name               string         `json:"name"`
	Exported           bool           `json:"exported"`
	ExplicitExported   bool           `json:"explicit_exported"` // true if android:exported was explicitly declared in XML
	Permission         string         `json:"permission,omitempty"`
	ReadPermission     string         `json:"read_permission,omitempty"`  // specific to content providers
	WritePermission    string         `json:"write_permission,omitempty"` // specific to content providers
	Enabled            bool           `json:"enabled"`
	IntentFilters      []IntentFilter `json:"intent_filters,omitempty"`
	HasLauncherIntent  bool           `json:"has_launcher_intent,omitempty"`
}

// AndroidMetadata holds parsed metadata from AndroidManifest.xml.
type AndroidMetadata struct {
	PackageName           string             `json:"package_name"`
	VersionCode           int                `json:"version_code"`
	VersionName           string             `json:"version_name"`
	MinSDK                int                `json:"min_sdk"`
	TargetSDK             int                `json:"target_sdk"`
	MaxSDK                int                `json:"max_sdk,omitempty"`
	Debuggable            bool               `json:"debuggable"`
	ExplicitDebuggable    bool               `json:"explicit_debuggable"`
	AllowBackup           bool               `json:"allow_backup"`
	ExplicitAllowBackup   bool               `json:"explicit_allow_backup"`
	UsesCleartextTraffic  bool               `json:"uses_cleartext_traffic"`
	ExplicitCleartext     bool               `json:"explicit_cleartext"`
	NetworkSecurityConfig string             `json:"network_security_config,omitempty"`
	ApplicationPermission string             `json:"application_permission,omitempty"`
	PermissionsRequested  []string           `json:"permissions_requested,omitempty"`
	PermissionsDeclared   []string           `json:"permissions_declared,omitempty"`
	Components            []AndroidComponent `json:"components,omitempty"`
}

// ATSDomainException represents domain-level App Transport Security exceptions in iOS Info.plist.
type ATSDomainException struct {
	DomainName                    string `json:"domain_name"`
	IncludesSubdomains            bool   `json:"includes_subdomains"`
	AllowsInsecureHTTPLoads       bool   `json:"allows_insecure_http_loads"`
	MinimumTLSVersion             string `json:"minimum_tls_version,omitempty"`
	AllowsArbitraryLoadsInMedia   bool   `json:"allows_arbitrary_loads_in_media,omitempty"`
	RequiresForwardSecrecy        *bool  `json:"requires_forward_secrecy,omitempty"`
}

// ATSConfig holds parsed NSAppTransportSecurity settings from Info.plist.
type ATSConfig struct {
	Present                         bool                 `json:"present"`
	AllowsArbitraryLoads            bool                 `json:"allows_arbitrary_loads"`
	AllowsArbitraryLoadsInWebContent bool                `json:"allows_arbitrary_loads_in_web_content"`
	AllowsLocalNetworking           bool                 `json:"allows_local_networking"`
	ExceptionDomains                []ATSDomainException `json:"exception_domains,omitempty"`
}

// IOSMetadata holds parsed metadata from an iOS Info.plist.
type IOSMetadata struct {
	BundleIdentifier string     `json:"bundle_identifier"`
	BundleName       string     `json:"bundle_name"`
	DisplayName      string     `json:"display_name,omitempty"`
	VersionString    string     `json:"version_string"`
	BuildNumber      string     `json:"build_number"`
	MinimumOSVersion string     `json:"minimum_os_version,omitempty"`
	URLSchemes       []string   `json:"url_schemes,omitempty"`
	ATS              ATSConfig  `json:"ats"`
}

// MobileFinding represents a security finding identified during static package analysis.
type MobileFinding struct {
	ID             string                `json:"id"`
	RuleID         string                `json:"rule_id"`
	Title          string                `json:"title"`
	Platform       Platform              `json:"platform"`
	PackageID      string                `json:"package_id"`
	ComponentOrKey string                `json:"component_or_key"`
	ObservedValue  string                `json:"observed_value"`
	ExpectedValue  string                `json:"expected_value"`
	Severity       string                `json:"severity"` // CRITICAL, HIGH, MEDIUM, LOW, INFO
	Confidence     string                `json:"confidence"` // HIGH, MEDIUM, LOW
	Classification FindingClassification `json:"classification"`
	EvidenceSource string                `json:"evidence_source"`
	Explanation    string                `json:"explanation"`
	Remediation    string                `json:"remediation"`
}

// ToFinding converts a MobileFinding into a standardized FELIX report.Finding.
func (f *MobileFinding) ToFinding() *report.Finding {
	if f == nil {
		return nil
	}
	return &report.Finding{
		ID:          f.ID,
		RuleID:      f.RuleID,
		Title:       f.Title,
		Category:    fmt.Sprintf("MOBILE-%s", strings.ToUpper(string(f.Platform))),
		Severity:    f.Severity,
		Confidence:  f.Confidence,
		Target:      f.PackageID,
		Endpoint:    f.ComponentOrKey,
		Method:      "STATIC_MANIFEST_ANALYSIS",
		Description: f.Explanation,
		Evidence:    fmt.Sprintf("Observed: %s | Expected: %s | Source: %s", f.ObservedValue, f.ExpectedValue, f.EvidenceSource),
		EvidenceDetails: report.EvidenceDetails{
			Location:         f.ComponentOrKey,
			Observation:      f.ObservedValue,
			ExpectedBehavior: f.ExpectedValue,
			ObservedBehavior: f.ObservedValue,
			DetectionMethod:  "STATIC_MANIFEST_ANALYSIS",
		},
		Remediation: f.Remediation,
	}
}

// PackageInspectionResult contains the full analysis output for an APK or IPA archive.
type PackageInspectionResult struct {
	Platform        Platform          `json:"platform"`
	PackagePath     string            `json:"package_path"`
	PackageSHA256   string            `json:"package_sha256"`
	PackageSizeBytes int64            `json:"package_size_bytes"`
	AnalyzedAt      time.Time         `json:"analyzed_at"`
	Android         *AndroidMetadata  `json:"android,omitempty"`
	IOS             *IOSMetadata      `json:"ios,omitempty"`
	Findings        []MobileFinding   `json:"findings"`
	Stats           InspectionStats   `json:"stats"`
	Errors          []string          `json:"errors,omitempty"`
}

// InspectionStats aggregates counts from package inspection.
type InspectionStats struct {
	TotalEntriesScanned int `json:"total_entries_scanned"`
	TotalComponents     int `json:"total_components"`
	ExportedComponents  int `json:"exported_components"`
	UnprotectedExported int `json:"unprotected_exported"`
	ProtectedExported   int `json:"protected_exported"`
	ActivitiesCount     int `json:"activities_count"`
	ServicesCount       int `json:"services_count"`
	ReceiversCount      int `json:"receivers_count"`
	ProvidersCount      int `json:"providers_count"`
	URLSchemesCount     int `json:"url_schemes_count"`
	ConfirmedFindings   int `json:"confirmed_findings"`
	PotentialFindings   int `json:"potential_findings"`
	InfoFindings        int `json:"info_findings"`
	InconclusiveFindings int `json:"inconclusive_findings"`
}

// ComputeDeterministicFindingID derives a stable hash-based ID for deduplication.
func ComputeDeterministicFindingID(platform Platform, packageID, ruleID, componentOrKey string) string {
	raw := fmt.Sprintf("%s:%s:%s:%s", platform, packageID, ruleID, componentOrKey)
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:16]) // 32 hex chars
}

// SortFindings deterministically sorts findings by Severity, Classification, RuleID, and Component.
func SortFindings(findings []MobileFinding) {
	severityWeight := map[string]int{
		"CRITICAL": 5,
		"HIGH":     4,
		"MEDIUM":   3,
		"LOW":      2,
		"INFO":     1,
	}
	sort.Slice(findings, func(i, j int) bool {
		si := severityWeight[strings.ToUpper(findings[i].Severity)]
		sj := severityWeight[strings.ToUpper(findings[j].Severity)]
		if si != sj {
			return si > sj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ComponentOrKey < findings[j].ComponentOrKey
	})
}
