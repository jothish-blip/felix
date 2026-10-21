package report

import (
	"math"
	"sort"
	"strings"
	"time"
)

// Summarize counts findings across severity tiers, verification states, sources, and finding statuses.
func Summarize(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
		BySource:      make(map[string]int),
		ByStatus:      make(map[FindingStatus]int),
	}

	for _, f := range findings {
		switch NormalizeSeverity(f.Severity) {
		case SeverityCritical:
			s.CriticalCount++
		case SeverityHigh:
			s.HighCount++
		case SeverityMedium:
			s.MediumCount++
		case SeverityLow:
			s.LowCount++
		case SeverityInfo:
			s.InfoCount++
		}

		switch NormalizeVerificationStatus(f.Verification.Status) {
		case VerificationVerified:
			s.VerifiedCount++
			s.AttemptedCount++
		case VerificationDetected:
			s.DetectedCount++
			s.AttemptedCount++
		case VerificationNotVerified:
			s.NotVerifiedCount++
		case VerificationObserved:
			s.ObservedCount++
		case VerificationNotExposed:
			s.NotExposedCount++
			s.AttemptedCount++
		}

		st := f.Status
		if st == "" {
			st = FindingStatusFromVerification(f.Verification.Status)
		}
		st = NormalizeFindingStatus(st)
		s.ByStatus[st]++
		switch st {
		case FindingStatusConfirmed:
			s.ConfirmedCount++
		case FindingStatusSuspected:
			s.SuspectedCount++
		case FindingStatusInconclusive:
			s.InconclusiveStatusCount++
			s.InconclusiveCount++
		case FindingStatusNotTested:
			s.NotTestedCount++
		case FindingStatusError:
			s.ErrorCount++
		}

		if f.Verification.SyntheticFixture {
			s.SyntheticCount++
		}
		if strings.Contains(strings.ToLower(f.Verification.Result), "blocked") {
			s.BlockedCount++
		}

		src := NormalizeSource(f.Source)
		s.BySource[src]++

		switch strings.ToUpper(strings.TrimSpace(f.LifecycleStatus)) {
		case "NEW":
			s.NewCount++
		case "ACTIVE", "RECURRING":
			s.ActiveCount++
		case "RESOLVED":
			s.ResolvedCount++
		case "REGRESSED":
			s.RegressedCount++
		case "UNASSESSED":
			s.UnassessedCount++
		}
	}

	if s.AttemptedCount > 0 {
		s.VerificationRateAttempted = math.Round(float64(s.VerifiedCount)/float64(s.AttemptedCount)*1000) / 10
	}
	if s.TotalFindings > 0 {
		s.VerificationRateTotal = math.Round(float64(s.VerifiedCount)/float64(s.TotalFindings)*1000) / 10
	}

	return s
}

// Prioritize deterministically sorts findings by:
// 1. Finding status rank (CONFIRMED > SUSPECTED > INCONCLUSIVE > NOT_TESTED > ERROR)
// 2. Verification rank (VERIFIED -> DETECTED -> NOT_VERIFIED -> OBSERVED -> NOT_EXPOSED)
// 3. Severity rank (CRITICAL -> INFO)
// 4. Confidence rank (HIGH -> LOW)
// 5. Risk score (descending)
// 6. Category (alphabetical)
// 7. Endpoint (alphabetical)
func Prioritize(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.SliceStable(sorted, func(i, j int) bool {
		fi := sorted[i]
		fj := sorted[j]

		// 1. Finding status rank
		stI := fi.Status
		if stI == "" {
			stI = FindingStatusFromVerification(fi.Verification.Status)
		}
		stJ := fj.Status
		if stJ == "" {
			stJ = FindingStatusFromVerification(fj.Verification.Status)
		}
		siStatus := FindingStatusRank(stI)
		sjStatus := FindingStatusRank(stJ)
		if siStatus != sjStatus {
			return siStatus > sjStatus
		}

		// 2. Verification rank
		vi := VerificationRank(fi.Verification.Status)
		vj := VerificationRank(fj.Verification.Status)
		if vi != vj {
			return vi > vj
		}

		// 3. Severity rank
		si := SeverityRank(fi.Severity)
		sj := SeverityRank(fj.Severity)
		if si != sj {
			return si > sj
		}

		// 4. Confidence rank
		ci := ConfidenceRank(fi.Confidence)
		cj := ConfidenceRank(fj.Confidence)
		if ci != cj {
			return ci > cj
		}

		// 5. Risk score
		if fi.Score != fj.Score {
			return fi.Score > fj.Score
		}

		// 6. Category
		cati := strings.ToLower(fi.Category)
		catj := strings.ToLower(fj.Category)
		if cati != catj {
			return cati < catj
		}

		// 7. Endpoint
		epi := strings.ToLower(fi.Endpoint)
		epj := strings.ToLower(fj.Endpoint)
		if epi != epj {
			return epi < epj
		}

		// 8. Deterministic tie-breaker
		if fi.ID != fj.ID {
			return fi.ID < fj.ID
		}
		return fi.Fingerprint < fj.Fingerprint
	})

	return sorted
}

// BuildReport assembles a complete audit report from raw findings.
func BuildReport(target string, rawFindings []Finding) Report {
	return BuildMultiTargetReport([]string{target}, rawFindings)
}

// BuildMultiTargetReport assembles an audit report spanning one or more targets.
func BuildMultiTargetReport(targets []string, rawFindings []Finding) Report {
	primaryTarget := ""
	if len(targets) > 0 {
		primaryTarget = targets[0]
	}

	// 1. Deduplicate
	deduped := DeduplicateFindings(rawFindings)

	// 2. Correlate
	correlated, stories := Correlate(primaryTarget, deduped)

	// 3. Prioritize
	prioritized := Prioritize(correlated)

	// 4. Top priorities (top 5 or critical/high)
	topCount := 5
	if len(prioritized) < topCount {
		topCount = len(prioritized)
	}
	topPriorities := make([]Finding, topCount)
	copy(topPriorities, prioritized[:topCount])

	// 5. Calculate Risk
	riskScore, riskLevel := CalculateReportRisk(prioritized, stories)

	// 6. Summary
	summary := Summarize(prioritized)

	rep := Report{
		Version:         "2.0.0",
		Target:          primaryTarget,
		Targets:         targets,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		RiskScore:       riskScore,
		RiskLevel:       riskLevel,
		Summary:         summary,
		TopPriorities:   topPriorities,
		Findings:        prioritized,
		SecurityStories: stories,
		Metadata: map[string]any{
			"scanner":        "Felix",
			"engine_version": "5.0.0",
			"engines": []string{
				"felix-crawler",
				"felix-secrets",
				"felix-cloud",
				"felix-api",
				"felix-report",
			},
		},
	}
	rep.RiskScoreAvailable = true
	rep.Summary.ScoreAvailable = true
	cr := BuildCommercialReport(rep, WithCompletionStatus("COMPLETED"))
	rep.CommercialReport = &cr
	return rep
}

// RecalculateReportRisk reconciles and recomputes the report's risk score, risk level,
// and commercial presentation model using the authoritative deterministic scoring engine.
// It is strictly idempotent, preserves verified attack path escalation, prevents unverified
// candidate inflation, and guarantees scan-time and report-time calculations perfectly agree.
func RecalculateReportRisk(rep *Report) {
	if rep == nil {
		return
	}

	if rep.CompletionStatus == "BLOCKED" || rep.CompletionStatus == "FAILED" || rep.RiskLevel == "UNAVAILABLE" {
		rep.RiskScore = 0
		rep.RiskLevel = "UNAVAILABLE"
		rep.RiskScoreAvailable = false
		rep.Summary.ScoreAvailable = false
		cr := BuildCommercialReport(*rep, WithCompletionStatus(rep.CompletionStatus))
		rep.CommercialReport = &cr
		return
	}

	rep.RiskScoreAvailable = true
	rep.Summary.ScoreAvailable = true

	score, level := CalculateReportRisk(rep.Findings, rep.SecurityStories)
	rep.RiskScore = score
	rep.RiskLevel = level

	// Only verified attack paths with non-low confidence are eligible to escalate risk.
	// Candidate or hypothesis paths contribute zero unverified risk to primary score.
	for _, p := range rep.AttackPaths {
		if !strings.EqualFold(p.Status, "VERIFIED") || NormalizeConfidence(p.Confidence) == ConfidenceLow {
			continue
		}

		// Validate, sanitize, and clamp attack path score to valid [0, 100] bounds.
		// Malformed saved reports cannot inflate numerical scores beyond the model ceiling.
		pathScore := p.CombinedRiskScore
		if pathScore < 0 {
			pathScore = 0
		} else if pathScore > 100 {
			pathScore = 100
		}

		if pathScore > rep.RiskScore {
			rep.RiskScore = pathScore
		}

		// Sanitize attack path risk level to prevent malformed saved report strings from inflating category
		pathLevel := NormalizeSeverity(p.CombinedRiskLevel)
		scoreBand := RiskLevelBand(pathScore)
		// If level was omitted, unrecognized non-informational string, or inflated beyond the score band, clamp to scoreBand
		if p.CombinedRiskLevel == "" || (pathLevel == SeverityInfo && !isExplicitInfoLevel(p.CombinedRiskLevel)) || SeverityRank(pathLevel) > SeverityRank(scoreBand) {
			pathLevel = scoreBand
		}

		if SeverityRank(pathLevel) > SeverityRank(rep.RiskLevel) {
			rep.RiskLevel = pathLevel
		}
	}

	// Final bounds check on assessment risk score
	if rep.RiskScore > 100 {
		rep.RiskScore = 100
	} else if rep.RiskScore < 0 {
		rep.RiskScore = 0
	}

	statusOpt := WithCompletionStatus(rep.CompletionStatus)
	if rep.CompletionStatus == "" {
		statusOpt = WithCompletionStatus("COMPLETED")
	}
	cr := BuildCommercialReport(*rep, statusOpt)
	rep.CommercialReport = &cr
}

func isExplicitInfoLevel(raw string) bool {
	s := strings.ToUpper(strings.TrimSpace(raw))
	return s == SeverityInfo || s == "INFORMATIONAL" || s == "NOTE"
}

// AttachAttackPaths associates correlated attack paths with the audit report,
// updating the report's risk level if any path represents a higher verified risk.
func AttachAttackPaths(rep *Report, paths []AttackPathSummary) {
	if rep == nil || len(paths) == 0 {
		return
	}
	rep.AttackPaths = paths
	RecalculateReportRisk(rep)
}

// AttachSecurityStories replaces correlated security stories on the report.
func AttachSecurityStories(rep *Report, stories []SecurityStory) {
	if rep == nil || len(stories) == 0 {
		return
	}
	rep.SecurityStories = stories
	RecalculateReportRisk(rep)
}
