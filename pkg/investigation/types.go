package investigation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"felix/pkg/report"
)

// ValidationStatus defines the empirical proof level of a vulnerability finding.
type ValidationStatus string

const (
	// StatusConfirmed indicates reproducible evidence empirically demonstrates the vulnerability.
	StatusConfirmed ValidationStatus = "CONFIRMED"

	// StatusHighConfidence indicates strong evidence exists, but complete impact validation is unavailable.
	StatusHighConfidence ValidationStatus = "HIGH CONFIDENCE"

	// StatusPotential indicates detection suggests a vulnerability but proof is insufficient.
	StatusPotential ValidationStatus = "POTENTIAL"

	// StatusNotValidated indicates validation could not safely or reliably be completed.
	StatusNotValidated ValidationStatus = "NOT VALIDATED"

	// StatusNotTested indicates no applicable validation procedure exists for this finding.
	StatusNotTested ValidationStatus = "NOT TESTED"
)

// RetestStatus defines the verdict of retesting a previously investigated finding.
type RetestStatus string

const (
	RetestFixDetected           RetestStatus = "FIX DETECTED"
	RetestVulnerabilityPresent   RetestStatus = "VULNERABILITY STILL PRESENT"
	RetestRegressionDetected    RetestStatus = "REGRESSION DETECTED"
	RetestInconclusive          RetestStatus = "RETEST INCONCLUSIVE"
	RetestPreviouslyConfirmed   RetestStatus = "PREVIOUSLY CONFIRMED"
	RetestValidationPassed      RetestStatus = "VALIDATION PASSED"
)

// RemediationPriority ranks recommended fixes for operator and developer action.
type RemediationPriority string

const (
	PriorityCritical RemediationPriority = "CRITICAL (P1)"
	PriorityHigh     RemediationPriority = "HIGH (P2)"
	PriorityMedium   RemediationPriority = "MEDIUM (P3)"
	PriorityLow      RemediationPriority = "LOW (P4)"
	PriorityInfo     RemediationPriority = "INFORMATIONAL (P5)"
)

// EvidenceBundle preserves the sanitized, auditable proof artifacts for a finding.
type EvidenceBundle struct {
	ID                 string    `json:"id"`
	FindingID          string    `json:"finding_id"`
	AssessmentID       string    `json:"assessment_id,omitempty"`
	ModuleID           string    `json:"module_id"`
	TestIdentifier     string    `json:"test_identifier"`
	ValidationTime     time.Time `json:"validation_time"`
	SanitizedRequest   string    `json:"sanitized_request"`
	SanitizedResponse  string    `json:"sanitized_response"`
	ReproductionSteps  []string  `json:"reproduction_steps"`
	SafeCurlCommand    string    `json:"safe_curl_command,omitempty"`
	BrowserEvidence    string    `json:"browser_evidence,omitempty"`
	EvidenceHash       string    `json:"evidence_hash"` // SHA-256 of sanitized evidence content
	ProofSummary       string    `json:"proof_summary"`
	CanaryUsed         string    `json:"canary_used,omitempty"`
	LeastInvasiveMethod string   `json:"least_invasive_method"`
}

// AttackStep represents a single discrete action or transition in an attack path.
type AttackStep struct {
	StepNumber       int    `json:"step_number"`
	Action           string `json:"action"`
	Description      string `json:"description"`
	Endpoint         string `json:"endpoint,omitempty"`
	Parameter        string `json:"parameter,omitempty"`
	RequiredRole     string `json:"required_role,omitempty"`
	SecurityControl  string `json:"security_control_failed,omitempty"`
	ObservedBehavior string `json:"observed_behavior"`
	IsDemonstrated   bool   `json:"is_demonstrated"` // True if proven by live probe; false if inferred
	Classification   string `json:"classification"`  // "DEMONSTRATED", "INFERRED", or "NOT_VALIDATED"
}

// AttackPath models the step-by-step exploitation sequence for a confirmed finding.
type AttackPath struct {
	FindingID          string       `json:"finding_id"`
	Title              string       `json:"title"`
	InitialEntryPoint  string       `json:"initial_entry_point"`
	RequiredAuthState  string       `json:"required_auth_state"`
	UserRole           string       `json:"user_role"`
	AffectedEndpoint   string       `json:"affected_endpoint"`
	RelevantParameters []string     `json:"relevant_parameters,omitempty"`
	FailedControl      string       `json:"failed_control"`
	ObservedBehavior   string       `json:"observed_behavior"`
	DemonstratedImpact string       `json:"demonstrated_impact"`
	Preconditions      []string     `json:"preconditions,omitempty"`
	ReproductionSteps  []string     `json:"reproduction_steps"`
	Steps              []AttackStep `json:"steps"`
	GraphVisual        string       `json:"graph_visual,omitempty"`
	IsConfirmed        bool         `json:"is_confirmed"`
}

// AttackChainLink models a proven dependency between two distinct findings in a multi-hop chain.
type AttackChainLink struct {
	FromFindingID        string `json:"from_finding_id"`
	FromTitle            string `json:"from_title"`
	ToFindingID          string `json:"to_finding_id"`
	ToTitle              string `json:"to_title"`
	DependencyType       string `json:"dependency_type"` // e.g. "CREDENTIAL_FEED", "PRIVILEGE_PIVOT", "BOUNDARY_BYPASS"
	DemonstratedLink     bool   `json:"demonstrated_link"`
	Explanation          string `json:"explanation"`
}

// AttackChain models a multi-vulnerability exploit sequence connecting discrete findings.
type AttackChain struct {
	ID               string            `json:"id"`
	Title            string            `json:"title"`
	Status           ValidationStatus  `json:"status"` // CONFIRMED only if all links demonstrated; else POTENTIAL
	Summary          string            `json:"summary"`
	FindingIDs       []string          `json:"finding_ids"`
	Links            []AttackChainLink `json:"links"`
	DemonstratedPath string            `json:"demonstrated_path"`
}

// RemediationIntelligence provides immediately actionable fixing guidance for a finding.
type RemediationIntelligence struct {
	FindingID               string              `json:"finding_id"`
	RootCause               string              `json:"root_cause"`
	RecommendedFix          string              `json:"recommended_fix"`
	ImplementationGuidance  string              `json:"implementation_guidance"`
	ConfigurationChanges    []string            `json:"configuration_changes,omitempty"`
	Priority                RemediationPriority `json:"priority"`
	DeveloperVerification   string              `json:"developer_verification"`
	RetestInstructions      string              `json:"retest_instructions"`
	TargetTechnology        string              `json:"target_technology,omitempty"`
	FrameworkRecommendations []string           `json:"framework_recommendations,omitempty"`
	CodeSnippet             string              `json:"code_snippet,omitempty"`
}

// RemediationRoadmapItem represents an entry in the prioritized remediation plan.
type RemediationRoadmapItem struct {
	FixOrder     int                 `json:"fix_order"`
	FindingID    string              `json:"finding_id"`
	Title        string              `json:"title"`
	Severity     string              `json:"severity"`
	Endpoint     string              `json:"endpoint"`
	RootCause    string              `json:"root_cause"`
	Action       string              `json:"action"`
	Priority     RemediationPriority `json:"priority"`
	Dependencies []string            `json:"dependencies,omitempty"`
}

// RemediationRoadmap groups and orders remediation actions across an assessment.
type RemediationRoadmap struct {
	TotalActions     int                      `json:"total_actions"`
	CriticalCount    int                      `json:"critical_count"`
	HighCount        int                      `json:"high_count"`
	MediumCount      int                      `json:"medium_count"`
	LowCount         int                      `json:"low_count"`
	InfoCount        int                      `json:"info_count"`
	Items            []RemediationRoadmapItem `json:"items"`
}

// RetestVerdict records the result of retesting a previously investigated finding.
type RetestVerdict struct {
	FindingID              string       `json:"finding_id"`
	TargetURL              string       `json:"target_url"`
	OriginalStatus         ValidationStatus `json:"original_status"`
	RetestStatus           RetestStatus `json:"retest_status"`
	OriginalEvidenceHash   string       `json:"original_evidence_hash"`
	RetestEvidenceHash     string       `json:"retest_evidence_hash"`
	RetestTimestamp        time.Time    `json:"retest_timestamp"`
	Explanation            string       `json:"explanation"`
	RegressionDetected     bool         `json:"regression_detected"`
	SanitizedRetestResponse string      `json:"sanitized_retest_response,omitempty"`
}

// InvestigatedFinding wraps a Finding with its instant proof, attack path, and remediation intelligence.
type InvestigatedFinding struct {
	Finding          report.Finding           `json:"finding"`
	ValidationStatus ValidationStatus         `json:"validation_status"`
	EvidenceBundle   *EvidenceBundle          `json:"evidence_bundle,omitempty"`
	AttackPath       *AttackPath              `json:"attack_path,omitempty"`
	Remediation      *RemediationIntelligence `json:"remediation,omitempty"`
	RetestVerdict    *RetestVerdict           `json:"retest_verdict,omitempty"`
	InvestigatedAt   time.Time                `json:"investigated_at"`
}

// ComputeEvidenceHash computes a deterministic SHA-256 integrity hash over evidence content.
func ComputeEvidenceHash(req, resp, steps string) string {
	h := sha256.New()
	h.Write([]byte(strings.TrimSpace(req)))
	h.Write([]byte("\n---\n"))
	h.Write([]byte(strings.TrimSpace(resp)))
	h.Write([]byte("\n---\n"))
	h.Write([]byte(strings.TrimSpace(steps)))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// SanitizeHTTPContent masks passwords, session tokens, cookies, and sensitive content.
func SanitizeHTTPContent(content string) string {
	if content == "" {
		return ""
	}
	s := content
	// Mask bearer tokens
	for _, prefix := range []string{"Bearer ", "bearer ", "token=", "Token "} {
		idx := strings.Index(s, prefix)
		for idx != -1 {
			start := idx + len(prefix)
			end := start
			for end < len(s) && s[end] != ' ' && s[end] != '\r' && s[end] != '\n' && s[end] != '&' && s[end] != ';' && s[end] != '"' {
				end++
			}
			token := s[start:end]
			if len(token) > 8 {
				masked := token[:4] + strings.Repeat("*", len(token)-8) + token[len(token)-4:]
				s = s[:start] + masked + s[end:]
			}
			idx = strings.Index(s[start:], prefix)
			if idx != -1 {
				idx += start
			}
		}
	}
	// Mask passwords in JSON or query strings
	sensitiveKeys := []string{"password", "passwd", "secret", "api_key", "apikey", "access_token"}
	for _, key := range sensitiveKeys {
		patterns := []string{fmt.Sprintf("\"%s\":\"", key), fmt.Sprintf("\"%s\": \"", key), fmt.Sprintf("%s=", key)}
		for _, pat := range patterns {
			idx := strings.Index(strings.ToLower(s), pat)
			for idx != -1 {
				start := idx + len(pat)
				end := start
				for end < len(s) && s[end] != '"' && s[end] != '&' && s[end] != '\r' && s[end] != '\n' {
					end++
				}
				val := s[start:end]
				if len(val) > 0 {
					masked := "[REDACTED]"
					s = s[:start] + masked + s[end:]
				}
				next := strings.Index(strings.ToLower(s[start:]), pat)
				if next != -1 {
					idx = start + next
				} else {
					idx = -1
				}
			}
		}
	}
	return s
}

// FormatSafeCurl generates a deterministic, safe cURL command for reproducing an HTTP finding.
func FormatSafeCurl(method, urlStr string, headers http.Header, body string) string {
	var parts []string
	parts = append(parts, "curl", "-i", "-s", "-X", method)
	if headers != nil {
		for k, vv := range headers {
			if strings.EqualFold(k, "Authorization") || strings.EqualFold(k, "Cookie") {
				parts = append(parts, "-H", fmt.Sprintf("%q", k+": [REDACTED_AUTH]"))
			} else {
				for _, v := range vv {
					parts = append(parts, "-H", fmt.Sprintf("%q", k+": "+v))
				}
			}
		}
	}
	if body != "" {
		sanBody := SanitizeHTTPContent(body)
		if len(sanBody) > 200 {
			sanBody = sanBody[:200] + "...[truncated]"
		}
		parts = append(parts, "--data", fmt.Sprintf("%q", sanBody))
	}
	parts = append(parts, fmt.Sprintf("%q", urlStr))
	return strings.Join(parts, " ")
}
