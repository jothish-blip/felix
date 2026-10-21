package policy

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"felix/pkg/clierror"
	"felix/pkg/report"
)

// EvaluationContext encapsulates the operational and security boundary metadata
// required to evaluate a policy reliably.
type EvaluationContext struct {
	AssessmentID       string                `json:"assessment_id,omitempty"`
	ClientID           string                `json:"client_id,omitempty"`
	TenantID           string                `json:"tenant_id,omitempty"`
	AssessmentType     string                `json:"assessment_type,omitempty"`
	Status             string                `json:"status,omitempty"`
	ExecutionError     error                 `json:"-"`
	TargetScope        []string              `json:"target_scope,omitempty"`
	BaselineComparison *report.ChangeSummary `json:"baseline_comparison,omitempty"`
}

// ThresholdViolation records an observed finding count that exceeded a policy-defined limit.
type ThresholdViolation struct {
	Severity      string `json:"severity"`
	ObservedCount int    `json:"observed_count"`
	AllowedLimit  int    `json:"allowed_limit"`
	Message       string `json:"message"`
}

// UnrecognizedFinding details a finding whose severity could not be classified into canonical tiers.
type UnrecognizedFinding struct {
	ID          string `json:"id"`
	RawSeverity string `json:"raw_severity"`
	Reason      string `json:"reason"`
}

// EvaluationDecision represents the structured, machine-readable verdict of a security threshold evaluation.
type EvaluationDecision struct {
	Evaluated            bool                  `json:"evaluated"`
	Reliable             bool                  `json:"reliable"`
	Passed               bool                  `json:"passed"`
	PolicyVersion        string                `json:"policy_version,omitempty"`
	PolicyName           string                `json:"policy_name,omitempty"`
	PolicyDigest         string                `json:"policy_digest,omitempty"`
	ObservedCounts       map[string]int        `json:"observed_counts"`
	AllowedLimits        map[string]*int       `json:"allowed_limits"`
	Violations           []ThresholdViolation  `json:"violations"`
	UnrecognizedFindings []UnrecognizedFinding `json:"unrecognized_findings,omitempty"`
	Explanation          string                `json:"explanation"`
}

// ExitCode maps the evaluation decision directly to the FELIX CI/CD exit-code contract:
// - ExitSuccess (0): Assessment was reliable and all configured thresholds passed.
// - ExitSecurityFail (1): Assessment was reliable and at least one configured threshold was violated.
// - ExitOperational (2): Assessment was incomplete, untrustworthy, failed operationally, or policy was invalid.
func (d *EvaluationDecision) ExitCode() int {
	if d == nil || !d.Reliable {
		return clierror.ExitOperational
	}
	if !d.Passed {
		return clierror.ExitSecurityFail
	}
	return clierror.ExitSuccess
}

// isUntrustworthyStatus returns true for assessment completion statuses that represent
// operational failures, cancellations, or partial coverage.
func isUntrustworthyStatus(status string) bool {
	norm := strings.ToUpper(strings.TrimSpace(status))
	switch norm {
	case "FAILED", "CANCELLED", "INTERRUPTED", "COMPLETED_WITH_ERRORS",
		"PARTIAL", "INSUFFICIENT_COVERAGE", "INCOMPLETE", "BLOCKED", "ERROR":
		return true
	default:
		return false
	}
}

// EvaluatePolicy evaluates a validated threshold policy against a set of findings and assessment context.
func EvaluatePolicy(policy *ThresholdPolicy, findings []report.Finding, ctx EvaluationContext) (*EvaluationDecision, error) {
	decision := &EvaluationDecision{
		Evaluated:      false,
		Reliable:       false,
		Passed:         false,
		ObservedCounts: make(map[string]int),
		AllowedLimits:  make(map[string]*int),
		Violations:     make([]ThresholdViolation, 0),
	}

	// Initialize standard severity tiers in observed counts
	for _, sev := range []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
		report.SeverityInfo,
		report.SeverityUnknown,
	} {
		decision.ObservedCounts[sev] = 0
	}

	// 1. Safeguard: Operational Assessment Failures
	// An interrupted, failed, cancelled, or partial assessment must NEVER pass merely because
	// zero or few findings were collected before the failure occurred.
	if ctx.ExecutionError != nil {
		decision.Explanation = fmt.Sprintf("Assessment encountered operational execution error: %v; policy evaluation cannot certify failed outcomes", ctx.ExecutionError)
		return decision, nil
	}

	if isUntrustworthyStatus(ctx.Status) {
		decision.Explanation = fmt.Sprintf("Assessment execution completed with untrustworthy status %q; incomplete results cannot satisfy security thresholds", ctx.Status)
		return decision, nil
	}

	// Validate policy upfront
	if policy == nil {
		return nil, fmt.Errorf("cannot evaluate nil security threshold policy")
	}
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}

	decision.PolicyVersion = policy.Version
	decision.PolicyName = policy.Name
	decision.PolicyDigest = policy.Digest()

	// 2. Finding Deduplication
	// Ensure findings are deduplicated according to the canonical FELIX data model
	// to avoid double-counting duplicate exposures, while preserving original raw severity labels.
	rawSeverities := make(map[string]string, len(findings))
	for _, f := range findings {
		if f.ID != "" {
			rawSeverities[f.ID] = f.Severity
		}
	}

	cleanFindings := report.DeduplicateFindings(findings)

	// 3. Tenant & Assessment Isolation Enforcement
	// Verify that findings from unrelated assessments, tenants, or out-of-scope targets cannot enter decision.
	for _, f := range cleanFindings {
		// Verify Assessment ID boundary
		if ctx.AssessmentID != "" {
			if asmID := extractAssessmentID(f); asmID != "" && asmID != ctx.AssessmentID {
				decision.Explanation = fmt.Sprintf("Tenant/Assessment isolation violation: finding %q belongs to assessment %q, mismatched with context assessment %q", f.ID, asmID, ctx.AssessmentID)
				return decision, fmt.Errorf("%s", decision.Explanation)
			}
		}

		// Verify Client/Tenant boundary
		expectedTenant := ctx.ClientID
		if expectedTenant == "" {
			expectedTenant = ctx.TenantID
		}
		if expectedTenant != "" {
			if tenantID := extractTenantID(f); tenantID != "" && tenantID != expectedTenant {
				decision.Explanation = fmt.Sprintf("Tenant isolation violation: finding %q belongs to tenant %q, mismatched with context tenant %q", f.ID, tenantID, expectedTenant)
				return decision, fmt.Errorf("%s", decision.Explanation)
			}
		}

		// Verify Target Scope boundary if target scope is explicitly provided
		if len(ctx.TargetScope) > 0 && !isFindingInScope(f, ctx.TargetScope) {
			decision.Explanation = fmt.Sprintf("Scope isolation violation: finding %q target %q is outside authorized assessment scope", f.ID, f.Target)
			return decision, fmt.Errorf("%s", decision.Explanation)
		}
	}

	// 3.5 Baseline-Relative Scope Filtering (Phase 8.4)
	evalScope := policy.GetEvaluationScope()
	if evalScope == "new" || evalScope == "new_and_regressed" {
		if ctx.BaselineComparison != nil {
			if !ctx.BaselineComparison.IsReliable {
				decision.Reliable = false
				decision.Explanation = fmt.Sprintf("Baseline comparison is unreliable (%s); baseline-relative policy cannot certify outcome", ctx.BaselineComparison.ReliabilityReason)
				return decision, nil
			}
			deltaMap := make(map[string]string)
			for _, item := range ctx.BaselineComparison.ImportantChanges {
				if item.FindingID != "" {
					deltaMap[item.FindingID] = strings.ToUpper(item.Classification)
				}
				if item.Fingerprint != "" {
					deltaMap[item.Fingerprint] = strings.ToUpper(item.Classification)
				}
			}
			var scopeFiltered []report.Finding
			for _, f := range cleanFindings {
				cls := ""
				if c, ok := deltaMap[f.ID]; ok {
					cls = c
				} else if c, ok := deltaMap[f.Fingerprint]; ok {
					cls = c
				} else if f.LifecycleStatus != "" {
					cls = strings.ToUpper(f.LifecycleStatus)
				}
				if evalScope == "new" {
					if cls == "NEW" {
						scopeFiltered = append(scopeFiltered, f)
					}
				} else if evalScope == "new_and_regressed" {
					if cls == "NEW" || cls == "REGRESSED" {
						scopeFiltered = append(scopeFiltered, f)
					}
				}
			}
			cleanFindings = scopeFiltered
		} else {
			// If no baseline comparison was provided, filter by finding lifecycle status if available
			hasAnyStatus := false
			for _, f := range cleanFindings {
				if f.LifecycleStatus != "" {
					hasAnyStatus = true
					break
				}
			}
			if hasAnyStatus {
				var scopeFiltered []report.Finding
				for _, f := range cleanFindings {
					cls := strings.ToUpper(f.LifecycleStatus)
					if evalScope == "new" && cls == "NEW" {
						scopeFiltered = append(scopeFiltered, f)
					} else if evalScope == "new_and_regressed" && (cls == "NEW" || cls == "REGRESSED") {
						scopeFiltered = append(scopeFiltered, f)
					}
				}
				cleanFindings = scopeFiltered
			}
		}
	}

	// 4. Severity Tallying & Honest Classification
	for _, f := range cleanFindings {
		rawSev := f.Severity
		if orig, ok := rawSeverities[f.ID]; ok && orig != "" {
			rawSev = orig
		}

		canonSev, recognized := ParseSeverity(rawSev)
		if !recognized {
			decision.ObservedCounts[report.SeverityUnknown]++
			decision.UnrecognizedFindings = append(decision.UnrecognizedFindings, UnrecognizedFinding{
				ID:          f.ID,
				RawSeverity: rawSev,
				Reason:      fmt.Sprintf("Finding has unclassified/unrecognized severity %q", rawSev),
			})
		} else {
			decision.ObservedCounts[canonSev]++
		}
	}

	// Sort unrecognized findings by ID for deterministic serialization
	sort.Slice(decision.UnrecognizedFindings, func(i, j int) bool {
		return decision.UnrecognizedFindings[i].ID < decision.UnrecognizedFindings[j].ID
	})

	// 5. Threshold Evaluation: violation = observed_count > allowed_maximum
	standardTiers := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
	}

	for _, sev := range standardTiers {
		if limit, configured := policy.GetThreshold(sev); configured {
			val := limit
			decision.AllowedLimits[sev] = &val

			observed := decision.ObservedCounts[sev]
			if observed > limit {
				decision.Violations = append(decision.Violations, ThresholdViolation{
					Severity:      sev,
					ObservedCount: observed,
					AllowedLimit:  limit,
					Message:       fmt.Sprintf("Severity %s count %d exceeds allowed maximum %d", sev, observed, limit),
				})
			}
		} else {
			decision.AllowedLimits[sev] = nil
		}
	}

	// Check UNKNOWN severity threshold if configured
	if limit, configured := policy.GetThreshold(report.SeverityUnknown); configured {
		val := limit
		decision.AllowedLimits[report.SeverityUnknown] = &val
		observed := decision.ObservedCounts[report.SeverityUnknown]
		if observed > limit {
			decision.Violations = append(decision.Violations, ThresholdViolation{
				Severity:      report.SeverityUnknown,
				ObservedCount: observed,
				AllowedLimit:  limit,
				Message:       fmt.Sprintf("Severity UNKNOWN count %d exceeds allowed maximum %d", observed, limit),
			})
		}
	} else if policy.ShouldFailOnUnknown() && decision.ObservedCounts[report.SeverityUnknown] > 0 {
		zero := 0
		decision.AllowedLimits[report.SeverityUnknown] = &zero
		decision.Violations = append(decision.Violations, ThresholdViolation{
			Severity:      report.SeverityUnknown,
			ObservedCount: decision.ObservedCounts[report.SeverityUnknown],
			AllowedLimit:  0,
			Message:       fmt.Sprintf("%d finding(s) with unrecognized severity observed; policy fails on unclassified severities", decision.ObservedCounts[report.SeverityUnknown]),
		})
	}

	// Sort violations by severity rank deterministically (CRITICAL first, then HIGH, MEDIUM, LOW, UNKNOWN)
	sort.Slice(decision.Violations, func(i, j int) bool {
		ri := report.SeverityRank(decision.Violations[i].Severity)
		rj := report.SeverityRank(decision.Violations[j].Severity)
		if ri != rj {
			return ri > rj
		}
		return decision.Violations[i].Severity < decision.Violations[j].Severity
	})

	decision.Evaluated = true
	decision.Reliable = true

	// 6. Decision Resolution
	if len(decision.Violations) > 0 && policy.ShouldFailOnViolation() {
		decision.Passed = false
		decision.Explanation = fmt.Sprintf("Security threshold policy failed: %d violation(s) detected", len(decision.Violations))
	} else {
		decision.Passed = true
		if len(decision.Violations) > 0 {
			decision.Explanation = fmt.Sprintf("Security policy passed: %d violation(s) detected but fail_on_violation is false", len(decision.Violations))
		} else {
			decision.Explanation = "Security policy passed: all configured thresholds satisfied"
		}
	}

	return decision, nil
}

// EvaluateReport evaluates a validated policy against a completed report.Report.
func EvaluateReport(policy *ThresholdPolicy, rep *report.Report, ctx EvaluationContext) (*EvaluationDecision, error) {
	if rep == nil {
		return nil, fmt.Errorf("cannot evaluate policy on nil report")
	}

	// Use report's completion status if context status was not explicitly supplied
	if ctx.Status == "" {
		ctx.Status = rep.CompletionStatus
	}

	return EvaluatePolicy(policy, rep.Findings, ctx)
}

// Helper boundary extractors
func extractAssessmentID(f report.Finding) string {
	if f.EvidenceDetails.Details != nil {
		if id, ok := f.EvidenceDetails.Details["assessment_id"]; ok && id != "" {
			return id
		}
	}
	return ""
}

func extractTenantID(f report.Finding) string {
	if f.EvidenceDetails.Details != nil {
		if id, ok := f.EvidenceDetails.Details["tenant_id"]; ok && id != "" {
			return id
		}
		if id, ok := f.EvidenceDetails.Details["client_id"]; ok && id != "" {
			return id
		}
	}
	return ""
}

func isFindingInScope(f report.Finding, scopeTargets []string) bool {
	if len(scopeTargets) == 0 {
		return true
	}
	findingTarget := strings.TrimSpace(f.Target)
	if findingTarget == "" {
		findingTarget = strings.TrimSpace(f.Endpoint)
	}
	if findingTarget == "" {
		findingTarget = strings.TrimSpace(f.EvidenceDetails.Location)
	}
	// Missing scope metadata cannot silently establish a trustworthy policy pass
	if findingTarget == "" {
		return false
	}

	findingURL, err := url.Parse(findingTarget)
	if err != nil {
		// Fallback exact match or prefix match
		for _, s := range scopeTargets {
			sClean := strings.TrimSpace(s)
			if strings.EqualFold(findingTarget, sClean) || strings.HasPrefix(findingTarget, sClean) {
				return true
			}
		}
		return false
	}

	for _, s := range scopeTargets {
		sClean := strings.TrimSpace(s)
		if strings.EqualFold(findingTarget, sClean) || strings.HasPrefix(findingTarget, sClean) {
			return true
		}
		sURL, err := url.Parse(sClean)
		if err == nil {
			if findingURL.Host != "" && sURL.Host != "" && strings.EqualFold(findingURL.Host, sURL.Host) {
				return true
			}
		}
	}
	return false
}

// FormatDecisionSummary formats the evaluation decision into a clean, human-readable terminal block.
func FormatDecisionSummary(d *EvaluationDecision) string {
	if d == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("\n===========================================================\n")
	sb.WriteString("  SECURITY POLICY EVALUATION\n")
	sb.WriteString("===========================================================\n")

	name := d.PolicyName
	if name == "" {
		name = "unnamed-policy"
	}
	sb.WriteString(fmt.Sprintf("  Policy:       %s (v%s)\n", name, d.PolicyVersion))
	if d.PolicyDigest != "" {
		shortDigest := d.PolicyDigest
		if len(shortDigest) > 16 {
			shortDigest = shortDigest[:16] + "..."
		}
		sb.WriteString(fmt.Sprintf("  Digest:       %s\n", shortDigest))
	}

	verdict := "PASSED"
	if !d.Reliable {
		verdict = "INCOMPLETE / UNRELIABLE (Operational Error)"
	} else if !d.Passed {
		verdict = "FAILED (Threshold Exceeded)"
	}
	sb.WriteString(fmt.Sprintf("  Verdict:      %s\n", verdict))
	sb.WriteString(fmt.Sprintf("  Explanation:  %s\n", d.Explanation))
	sb.WriteString("\n  Thresholds:\n")

	displayTiers := []string{
		report.SeverityCritical,
		report.SeverityHigh,
		report.SeverityMedium,
		report.SeverityLow,
	}

	for _, sev := range displayTiers {
		observed := d.ObservedCounts[sev]
		limitPtr, configured := d.AllowedLimits[sev]
		if !configured || limitPtr == nil {
			sb.WriteString(fmt.Sprintf("    %-10s  Observed: %-4d  Allowed: --    [NOT CONFIGURED]\n", sev+":", observed))
		} else {
			limit := *limitPtr
			status := "[PASSED]"
			if observed > limit {
				status = "[VIOLATION]"
			}
			sb.WriteString(fmt.Sprintf("    %-10s  Observed: %-4d  Allowed: %-4d  %s\n", sev+":", observed, limit, status))
		}
	}

	// Informational findings (never count as Low)
	sb.WriteString(fmt.Sprintf("    %-10s  Observed: %-4d  Allowed: --    [INFO ONLY]\n", "INFO:", d.ObservedCounts[report.SeverityInfo]))

	// Display UNKNOWN tier if observed or configured
	if d.ObservedCounts[report.SeverityUnknown] > 0 || d.AllowedLimits[report.SeverityUnknown] != nil {
		observed := d.ObservedCounts[report.SeverityUnknown]
		limitPtr, configured := d.AllowedLimits[report.SeverityUnknown]
		if configured && limitPtr != nil {
			status := "[PASSED]"
			if observed > *limitPtr {
				status = "[VIOLATION]"
			}
			sb.WriteString(fmt.Sprintf("    %-10s  Observed: %-4d  Allowed: %-4d  %s\n", "UNKNOWN:", observed, *limitPtr, status))
		} else {
			sb.WriteString(fmt.Sprintf("    %-10s  Observed: %-4d  Allowed: --    [UNCLASSIFIED]\n", "UNKNOWN:", observed))
		}
	}

	if len(d.Violations) > 0 {
		sb.WriteString(fmt.Sprintf("\n  Violations (%d):\n", len(d.Violations)))
		for _, v := range d.Violations {
			sb.WriteString(fmt.Sprintf("    [!] %s\n", v.Message))
		}
	}

	if len(d.UnrecognizedFindings) > 0 {
		sb.WriteString(fmt.Sprintf("\n  Unrecognized Severities (%d):\n", len(d.UnrecognizedFindings)))
		for _, uf := range d.UnrecognizedFindings {
			sb.WriteString(fmt.Sprintf("    [?] Finding %q: raw severity %q (%s)\n", uf.ID, uf.RawSeverity, uf.Reason))
		}
	}

	sb.WriteString("===========================================================\n")
	return sb.String()
}
