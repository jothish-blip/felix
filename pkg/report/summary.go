package report

import (
	"math"
	"sort"
	"strings"
	"time"
)

// Summarize counts findings across severity tiers, verification states, and sources.
func Summarize(findings []Finding) Summary {
	s := Summary{
		TotalFindings: len(findings),
		BySource:      make(map[string]int),
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

		if f.Verification.SyntheticFixture {
			s.SyntheticCount++
		}
		if strings.Contains(strings.ToLower(f.Verification.Result), "blocked") {
			s.BlockedCount++
		}

		src := NormalizeSource(f.Source)
		s.BySource[src]++
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
// 1. Verification rank (VERIFIED -> DETECTED -> NOT_VERIFIED -> OBSERVED -> NOT_EXPOSED)
// 2. Severity rank (CRITICAL -> INFO)
// 3. Confidence rank (HIGH -> LOW)
// 4. Risk score (descending)
// 5. Category (alphabetical)
// 6. Endpoint (alphabetical)
func Prioritize(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.SliceStable(sorted, func(i, j int) bool {
		fi := sorted[i]
		fj := sorted[j]

		// 1. Verification rank
		vi := VerificationRank(fi.Verification.Status)
		vj := VerificationRank(fj.Verification.Status)
		if vi != vj {
			return vi > vj
		}

		// 2. Severity rank
		si := SeverityRank(fi.Severity)
		sj := SeverityRank(fj.Severity)
		if si != sj {
			return si > sj
		}

		// 3. Confidence rank
		ci := ConfidenceRank(fi.Confidence)
		cj := ConfidenceRank(fj.Confidence)
		if ci != cj {
			return ci > cj
		}

		// 4. Risk score
		if fi.Score != fj.Score {
			return fi.Score > fj.Score
		}

		// 5. Category
		cati := strings.ToLower(fi.Category)
		catj := strings.ToLower(fj.Category)
		if cati != catj {
			return cati < catj
		}

		// 6. Endpoint
		epi := strings.ToLower(fi.Endpoint)
		epj := strings.ToLower(fj.Endpoint)
		return epi < epj
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
		Version:         "1.0.0",
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
	cr := BuildCommercialReport(rep)
	rep.CommercialReport = &cr
	return rep
}

// AttachAttackPaths associates correlated attack paths with the audit report,
// updating the report's risk level if any path represents a higher verified risk.
func AttachAttackPaths(rep *Report, paths []AttackPathSummary) {
	if rep == nil || len(paths) == 0 {
		return
	}
	rep.AttackPaths = paths

	// Check if any attack path reflects higher combined risk
	maxPathScore := rep.RiskScore
	maxPathLevel := rep.RiskLevel
	for _, p := range paths {
		if p.CombinedRiskScore > maxPathScore {
			maxPathScore = p.CombinedRiskScore
			maxPathLevel = p.CombinedRiskLevel
		}
	}
	if maxPathScore > rep.RiskScore {
		rep.RiskScore = maxPathScore
		rep.RiskLevel = maxPathLevel
	}
	cr := BuildCommercialReport(*rep)
	rep.CommercialReport = &cr
}

// AttachSecurityStories replaces correlated security stories on the report.
func AttachSecurityStories(rep *Report, stories []SecurityStory) {
	if rep == nil || len(stories) == 0 {
		return
	}
	rep.SecurityStories = stories
	cr := BuildCommercialReport(*rep)
	rep.CommercialReport = &cr
}
