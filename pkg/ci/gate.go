package ci

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"felix/pkg/report"
)

// GateDecision represents the qualitative outcome of a gate policy evaluation.
type GateDecision string

const (
	DecisionPass  GateDecision = "PASS"
	DecisionFail  GateDecision = "FAIL"
	DecisionError GateDecision = "ERROR"
)

// Process exit codes conforming to the FELIX CI/CD gating contract.
const (
	ExitCodePass  = 0
	ExitCodeFail  = 1
	ExitCodeError = 2
)

// PolicyConfig defines the configurable security gate rules.
type PolicyConfig struct {
	FailOnSeverities []string `json:"fail_on_severities"` // e.g. ["HIGH", "CRITICAL"]
	MaxCVSS          float64  `json:"max_cvss"`           // e.g. 7.0 (>= MaxCVSS fails)
	AllowUnverified  bool     `json:"allow_unverified"`   // default true; strict mode (false) fails closed on unauthenticated findings
	RequireCVSS      bool     `json:"require_cvss"`       // default false (when true, missing CVSS fails gate)
	Target           string   `json:"target,omitempty"`
}

// DefaultPolicyConfig returns the recommended baseline security gate policy.
// In Phase 8.2, AllowUnverified defaults to true because cryptographic execution attestation
// is scheduled for Phase 9.1; strict mode (AllowUnverified: false) is an explicit opt-in policy
// that fails closed against all unauthenticated caller-supplied findings.
func DefaultPolicyConfig() PolicyConfig {
	return PolicyConfig{
		FailOnSeverities: []string{report.SeverityHigh, report.SeverityCritical},
		MaxCVSS:          7.0,
		AllowUnverified:  true,
		RequireCVSS:      false,
	}
}

// PolicyViolation details a specific finding and reason that triggered a gate failure.
type PolicyViolation struct {
	FindingID string  `json:"finding_id"`
	RuleID    string  `json:"rule_id"`
	Title     string  `json:"title"`
	Severity  string  `json:"severity"`
	CVSS      float64 `json:"cvss"`
	Verified  bool    `json:"verified"`
	Reason    string  `json:"reason"`
}

// GateResult captures the outcome of evaluating an assessment against a PolicyConfig.
type GateResult struct {
	Decision       GateDecision      `json:"decision"`
	ExitCode       int               `json:"exit_code"`
	Violations     []PolicyViolation `json:"violations"`
	TotalFindings  int               `json:"total_findings"`
	SeverityCounts map[string]int    `json:"severity_counts"`
	SummaryMessage string            `json:"summary_message"`
	ExecutedAt     time.Time         `json:"executed_at"`
	Policy         PolicyConfig      `json:"policy"`
}

// IsPassing returns true if the gate evaluation succeeded with zero violations.
func (r GateResult) IsPassing() bool {
	return r.Decision == DecisionPass && r.ExitCode == ExitCodePass
}

// IsFailing returns true if the gate evaluation detected policy threshold violations.
func (r GateResult) IsFailing() bool {
	return r.Decision == DecisionFail && r.ExitCode == ExitCodeFail
}

// IsError returns true if an operational error occurred during evaluation.
func (r GateResult) IsError() bool {
	return r.Decision == DecisionError || r.ExitCode == ExitCodeError
}

// CanonicalSeverities lists standard severity identifiers.
var CanonicalSeverities = []string{
	report.SeverityCritical,
	report.SeverityHigh,
	report.SeverityMedium,
	report.SeverityLow,
	report.SeverityInfo,
}

// SeverityPriority returns numeric ranking for deterministic sorting (lower is higher severity).
func SeverityPriority(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case report.SeverityCritical:
		return 0
	case report.SeverityHigh:
		return 1
	case report.SeverityMedium:
		return 2
	case report.SeverityLow:
		return 3
	case report.SeverityInfo:
		return 4
	default:
		return 5
	}
}

// NormalizeSeverity returns the normalized uppercase trimmed severity string.
func NormalizeSeverity(s string) string {
	clean := strings.ToUpper(strings.TrimSpace(s))
	if clean == "" {
		return report.SeverityUnknown
	}
	return clean
}

// CVSSStatus distinguishes the parsing classification of a finding's CVSS score.
type CVSSStatus string

const (
	CVSSStatusValid   CVSSStatus = "VALID"
	CVSSStatusMissing CVSSStatus = "MISSING"
	CVSSStatusInvalid CVSSStatus = "INVALID"
)

// CVSSParseResult encapsulates the structured evaluation of a finding's CVSS score.
type CVSSParseResult struct {
	Status   CVSSStatus `json:"status"`
	Score    float64    `json:"score"`
	RawValue string     `json:"raw_value,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// ParseCVSS deterministically parses and validates the CVSS score for a finding.
// It explicitly distinguishes genuine policy passes, missing metrics, and invalid assessment data.
func ParseCVSS(f report.Finding) CVSSParseResult {
	var rawVal string
	found := false

	// 1. Inspect EvidenceDetails.Details
	if f.EvidenceDetails.Details != nil {
		for _, key := range []string{"cvss", "cvss_score", "cvss-score", "cvss_v3", "cvssScore"} {
			if val, ok := f.EvidenceDetails.Details[key]; ok {
				rawVal = val
				found = true
				break
			}
		}
	}

	// 2. Inspect ScoreExplanation if no details key found
	if !found && f.ScoreExplanation != nil {
		if f.ScoreExplanation.BaseScore != 0 {
			rawVal = fmt.Sprintf("%.1f", f.ScoreExplanation.BaseScore)
			found = true
		}
	}

	if !found {
		return CVSSParseResult{
			Status: CVSSStatusMissing,
			Score:  0.0,
			Reason: "no CVSS score specified",
		}
	}

	trimmed := strings.TrimSpace(rawVal)
	if trimmed == "" || strings.EqualFold(trimmed, "n/a") || strings.EqualFold(trimmed, "none") || strings.EqualFold(trimmed, "null") {
		return CVSSParseResult{
			Status:   CVSSStatusMissing,
			Score:    0.0,
			RawValue: rawVal,
			Reason:   fmt.Sprintf("explicit absence token %q", trimmed),
		}
	}

	score, err := strconv.ParseFloat(trimmed, 64)
	if err != nil || math.IsNaN(score) || math.IsInf(score, 0) {
		return CVSSParseResult{
			Status:   CVSSStatusInvalid,
			Score:    0.0,
			RawValue: rawVal,
			Reason:   fmt.Sprintf("non-numeric CVSS value %q", rawVal),
		}
	}

	if score < 0.0 || score > 10.0 {
		return CVSSParseResult{
			Status:   CVSSStatusInvalid,
			Score:    score,
			RawValue: rawVal,
			Reason:   fmt.Sprintf("CVSS value %.1f outside valid range [0.0, 10.0]", score),
		}
	}

	return CVSSParseResult{
		Status:   CVSSStatusValid,
		Score:    score,
		RawValue: rawVal,
	}
}

// ExtractCVSS maintains backward compatibility, returning the score and true if valid.
func ExtractCVSS(f report.Finding) (float64, bool) {
	res := ParseCVSS(f)
	if res.Status == CVSSStatusValid {
		return res.Score, true
	}
	return 0.0, false
}

var knownVerificationPolicies = map[string]bool{
	"POL-DISC-01":    true,
	"POL-AUTH-01":    true,
	"POL-AUTHZ-01":   true,
	"POL-API-01":     true,
	"POL-WEBVULN-01": true,
	"POL-CLOUD-01":   true,
	"POL-BIZ-01":     true,
	"POL-GENERIC-01": true,
}

func isKnownVerificationPolicy(policyID string) bool {
	pid := strings.ToUpper(strings.TrimSpace(policyID))
	return knownVerificationPolicies[pid]
}

func isKnownSourceEngine(engine string) bool {
	eng := strings.ToLower(strings.TrimSpace(engine))
	switch eng {
	case report.SourceCrawler, report.SourceSecrets, report.SourceCloud,
		report.SourceAPI, report.SourceCorrelated, report.SourceAPK, report.SourceMobile,
		"verification", "active_verification_engine", "active_probe", "webvuln", "authz":
		return true
	default:
		return false
	}
}

// IsFindingVerified evaluates whether a finding has authentic, trusted empirical verification.
//
// Verification Authenticity & Execution Attestation Trust Boundary (Phase 8.2):
// 1. SHA-256 content integrity verifies data integrity only; it does not prove evidence authenticity.
// 2. Recognized policy IDs and confidence scores do not establish proof that the verification engine was executed.
// 3. Mutable caller-supplied fields in Go memory are not authenticated attestations.
// 4. In Phase 8.2, the verification engine (pkg/verification) does not emit an independently verifiable
//    cryptographic execution attestation (scheduled for Phase 9.1).
// 5. In the absence of an authentic, tamper-evident execution attestation bound to the finding ID,
//    evidence digest, verification policy, execution method, and verification result, caller-supplied
//    provenance cannot be treated as authenticated proof.
// 6. Therefore, in Phase 8.2, IsFindingVerified fails closed. Under allow-unverified=false,
//    unauthenticated caller-supplied findings are rejected.
func IsFindingVerified(f report.Finding) bool {
	// 1. Syntactic & structural invariant checks:
	// A finding failing baseline structural invariants cannot claim verification under any circumstance.
	if f.Verification.Status != report.VerificationVerified {
		return false
	}
	if f.Status != report.FindingStatusConfirmed {
		return false
	}
	if f.AnalysisMethod != report.AnalysisMethodActive && f.Verification.AnalysisMethod != report.AnalysisMethodActive {
		return false
	}
	if !f.Verification.Attempted {
		return false
	}
	if f.Verification.SyntheticFixture || strings.Contains(f.Evidence, "[SYNTHETIC FIXTURE]") {
		return false
	}
	if !isKnownVerificationPolicy(f.Verification.PolicyID) {
		return false
	}
	if f.Verification.ConfidenceScore > 0 && f.Verification.ConfidenceScore < 75 {
		return false
	}
	if strings.TrimSpace(f.Verification.Result) == "" {
		return false
	}
	hasReplayProof := len(f.Verification.ReproductionSteps) > 0 ||
		strings.TrimSpace(f.Verification.SafeCurlCommand) != ""
	if !hasReplayProof {
		return false
	}

	prov := f.Provenance
	if prov == nil {
		prov = f.EvidenceDetails.Provenance
	}
	if prov == nil {
		return false // Unauthenticated caller-supplied strings without evidence provenance rejected
	}
	if err := report.ValidateEvidenceProvenance(*prov); err != nil {
		return false
	}
	if !isKnownSourceEngine(prov.SourceEngine) {
		return false
	}

	rawEvidence := f.Evidence
	if rawEvidence == "" {
		rawEvidence = f.EvidenceDetails.Observation
	}
	if strings.TrimSpace(rawEvidence) == "" {
		return false
	}
	expectedDigest := report.ComputeContentDigest(rawEvidence)
	if expectedDigest == "" || prov.ContentDigest != expectedDigest {
		return false // Mismatched digest rejected
	}

	if f.EvidenceDetails.Provenance != nil && f.EvidenceDetails.Provenance != prov {
		if err := report.ValidateEvidenceProvenance(*f.EvidenceDetails.Provenance); err != nil {
			return false
		}
		if f.EvidenceDetails.Provenance.ContentDigest != "" {
			edRaw := f.EvidenceDetails.Observation
			if edRaw == "" {
				edRaw = f.Evidence
			}
			if edRaw != "" && f.EvidenceDetails.Provenance.ContentDigest != report.ComputeContentDigest(edRaw) {
				return false
			}
		}
	}

	// 2. Cryptographic Execution Attestation Trust Boundary:
	// Even when all syntactic, structural, and SHA-256 integrity checks pass, content integrity
	// is not evidence authenticity, recognized policy IDs are not proof of execution, and caller-supplied
	// fields are not authenticated attestations.
	// In Phase 8.2, no protected verification authority or cryptographic execution attestation exists
	// (scheduled for Phase 9.1). An arbitrary in-process caller can construct all of the above fields in memory.
	// In the absence of an authentic, independently verifiable execution attestation bound to:
	//   1. Finding ID
	//   2. Evidence digest
	//   3. Verification policy
	//   4. Execution method
	//   5. Verification result
	// FELIX fails closed rather than treating caller-supplied provenance as authenticated proof.
	return false
}

// EvaluateGate evaluates a security report against a PolicyConfig.
// It returns a deterministic GateResult with ExitCode 0 (PASS) or 1 (FAIL).
func EvaluateGate(rep report.Report, cfg PolicyConfig) GateResult {
	return EvaluateGateWithStatus(rep, cfg, nil)
}

// EvaluateGateWithStatus evaluates a security report against a PolicyConfig,
// with support for operational error propagation (ExitCode 2).
func EvaluateGateWithStatus(rep report.Report, cfg PolicyConfig, opErr error) GateResult {
	now := time.Now().UTC()
	if opErr != nil {
		return GateResult{
			Decision:       DecisionError,
			ExitCode:       ExitCodeError,
			Violations:     nil,
			TotalFindings:  len(rep.Findings),
			SeverityCounts: make(map[string]int),
			SummaryMessage: fmt.Sprintf("Gating evaluation aborted due to operational error: %v", opErr),
			ExecutedAt:     now,
			Policy:         cfg,
		}
	}

	counts := map[string]int{
		report.SeverityCritical: 0,
		report.SeverityHigh:     0,
		report.SeverityMedium:   0,
		report.SeverityLow:      0,
		report.SeverityInfo:     0,
		report.SeverityUnknown:  0,
	}

	// Normalize fail-on severities set
	failOnMap := make(map[string]bool, len(cfg.FailOnSeverities))
	for _, s := range cfg.FailOnSeverities {
		clean := NormalizeSeverity(s)
		if clean != "" {
			failOnMap[clean] = true
		}
	}

	var violations []PolicyViolation

	for i := range rep.Findings {
		f := &rep.Findings[i]
		normSev := NormalizeSeverity(f.Severity)
		if _, known := counts[normSev]; known {
			counts[normSev]++
		} else {
			counts[normSev]++
		}

		cvssRes := ParseCVSS(*f)
		var verified bool
		if !cfg.AllowUnverified {
			verified = IsFindingVerified(*f)
		}

		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.ID
		}
		if ruleID == "" {
			ruleID = "UNKNOWN-RULE"
		}

		// 1. Check severity match
		if failOnMap[normSev] {
			violations = append(violations, PolicyViolation{
				FindingID: f.ID,
				RuleID:    ruleID,
				Title:     f.Title,
				Severity:  normSev,
				CVSS:      cvssRes.Score,
				Verified:  verified,
				Reason:    fmt.Sprintf("Finding severity %s matches fail-on policy threshold", normSev),
			})
		}

		// 2. Check CVSS threshold & requirement
		if cfg.RequireCVSS || cfg.MaxCVSS > 0 {
			switch cvssRes.Status {
			case CVSSStatusValid:
				if cfg.MaxCVSS > 0 && cvssRes.Score >= cfg.MaxCVSS {
					violations = append(violations, PolicyViolation{
						FindingID: f.ID,
						RuleID:    ruleID,
						Title:     f.Title,
						Severity:  normSev,
						CVSS:      cvssRes.Score,
						Verified:  verified,
						Reason:    fmt.Sprintf("Finding CVSS score %.1f exceeds threshold %.1f", cvssRes.Score, cfg.MaxCVSS),
					})
				}
			case CVSSStatusInvalid:
				// Malformed CVSS values cannot silently pass when CVSS is required or threshold is evaluated.
				violations = append(violations, PolicyViolation{
					FindingID: f.ID,
					RuleID:    ruleID,
					Title:     f.Title,
					Severity:  normSev,
					CVSS:      cvssRes.Score,
					Verified:  verified,
					Reason:    fmt.Sprintf("Invalid assessment data: malformed CVSS value %q (%s)", cvssRes.RawValue, cvssRes.Reason),
				})
			case CVSSStatusMissing:
				if cfg.RequireCVSS {
					violations = append(violations, PolicyViolation{
						FindingID: f.ID,
						RuleID:    ruleID,
						Title:     f.Title,
						Severity:  normSev,
						CVSS:      0.0,
						Verified:  verified,
						Reason:    "Missing required CVSS score on finding (require-cvss: true)",
					})
				}
			}
		}

		// 3. Check allow-unverified requirement
		if !cfg.AllowUnverified && !verified {
			violations = append(violations, PolicyViolation{
				FindingID: f.ID,
				RuleID:    ruleID,
				Title:     f.Title,
				Severity:  normSev,
				CVSS:      cvssRes.Score,
				Verified:  verified,
				Reason:    "Unverified finding disallowed under gating policy (allow-unverified: false)",
			})
		}
	}

	// Sort violations deterministically: Severity priority, CVSS desc, FindingID asc, Reason asc
	sort.SliceStable(violations, func(i, j int) bool {
		pi := SeverityPriority(violations[i].Severity)
		pj := SeverityPriority(violations[j].Severity)
		if pi != pj {
			return pi < pj
		}
		if violations[i].CVSS != violations[j].CVSS {
			return violations[i].CVSS > violations[j].CVSS
		}
		if violations[i].FindingID != violations[j].FindingID {
			return violations[i].FindingID < violations[j].FindingID
		}
		return violations[i].Reason < violations[j].Reason
	})

	if len(violations) > 0 {
		return GateResult{
			Decision:       DecisionFail,
			ExitCode:       ExitCodeFail,
			Violations:     violations,
			TotalFindings:  len(rep.Findings),
			SeverityCounts: counts,
			SummaryMessage: fmt.Sprintf("Gating policy failed: %d violation(s) identified across %d total finding(s)", len(violations), len(rep.Findings)),
			ExecutedAt:     now,
			Policy:         cfg,
		}
	}

	return GateResult{
		Decision:       DecisionPass,
		ExitCode:       ExitCodePass,
		Violations:     violations,
		TotalFindings:  len(rep.Findings),
		SeverityCounts: counts,
		SummaryMessage: fmt.Sprintf("Gating policy passed: 0 violations across %d total finding(s)", len(rep.Findings)),
		ExecutedAt:     now,
		Policy:         cfg,
	}
}
