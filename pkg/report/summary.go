package report

import (
	"sort"
	"strings"
	"time"
)

// Summarize counts findings across severity tiers and sources.
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

		src := NormalizeSource(f.Source)
		s.BySource[src]++
	}

	return s
}

// Prioritize deterministically sorts findings by:
// 1. Severity rank (CRITICAL -> INFO)
// 2. Confidence rank (HIGH -> LOW)
// 3. Risk score (descending)
// 4. Category (alphabetical)
// 5. Endpoint (alphabetical)
func Prioritize(findings []Finding) []Finding {
	if len(findings) == 0 {
		return nil
	}

	sorted := make([]Finding, len(findings))
	copy(sorted, findings)

	sort.SliceStable(sorted, func(i, j int) bool {
		fi := sorted[i]
		fj := sorted[j]

		// 1. Severity rank
		si := SeverityRank(fi.Severity)
		sj := SeverityRank(fj.Severity)
		if si != sj {
			return si > sj
		}

		// 2. Confidence rank
		ci := ConfidenceRank(fi.Confidence)
		cj := ConfidenceRank(fj.Confidence)
		if ci != cj {
			return ci > cj
		}

		// 3. Risk score
		if fi.Score != fj.Score {
			return fi.Score > fj.Score
		}

		// 4. Category
		cati := strings.ToLower(fi.Category)
		catj := strings.ToLower(fj.Category)
		if cati != catj {
			return cati < catj
		}

		// 5. Endpoint
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

	return Report{
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
}
