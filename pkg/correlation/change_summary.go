package correlation

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"felix/pkg/report"
)

// ChangeSummaryOptions provides execution context when building a change summary.
type ChangeSummaryOptions struct {
	AssessmentID          string
	BaselineExecutionID   string
	ComparisonExecutionID string
	BaselineSnapshotID    string
	ComparisonSnapshotID  string
	BaselineTimestamp     *time.Time
	ComparisonTimestamp   time.Time
	BaselineStatus        string
	ComparisonStatus      string
	IsReliable            bool
	ReliabilityReason     string
}

// BuildChangeSummary constructs a comprehensive, evidence-grounded ChangeSummary
// from an AssessmentComparison result.
func BuildChangeSummary(cmp *AssessmentComparison, opts ChangeSummaryOptions) *report.ChangeSummary {
	if cmp == nil {
		cmp = &AssessmentComparison{}
	}

	summary := &report.ChangeSummary{
		AssessmentID:          opts.AssessmentID,
		BaselineExecutionID:   opts.BaselineExecutionID,
		ComparisonExecutionID: opts.ComparisonExecutionID,
		BaselineSnapshotID:    opts.BaselineSnapshotID,
		ComparisonSnapshotID:  opts.ComparisonSnapshotID,
		BaselineTimestamp:     opts.BaselineTimestamp,
		ComparisonTimestamp:   opts.ComparisonTimestamp,
		BaselineStatus:        opts.BaselineStatus,
		ComparisonStatus:      opts.ComparisonStatus,
		IsReliable:            opts.IsReliable,
		ReliabilityReason:     opts.ReliabilityReason,
		NetRiskScoreDelta:     cmp.NetRiskScoreDelta,
	}

	if summary.ComparisonTimestamp.IsZero() {
		summary.ComparisonTimestamp = time.Now().UTC()
	}

	// 1. Calculate classification counts directly from comparison items
	var counts report.ChangeClassificationCounts
	counts.TotalBaseline = cmp.BaselineCount
	counts.TotalComparison = cmp.CurrentCount

	var (
		reappearedCount int
		worsenedCount   int
	)

	items := make([]report.ChangeFindingItem, 0, len(cmp.Items))

	for _, it := range cmp.Items {
		switch it.Classification {
		case DeltaNew:
			counts.New++
		case DeltaResolved:
			counts.Resolved++
		case DeltaPersistent:
			counts.Persistent++
		case DeltaRegressed:
			counts.Regressed++
			if it.RegressionReason == RegressionReappeared {
				reappearedCount++
			} else if it.RegressionReason == RegressionSeverityWorsened {
				worsenedCount++
			}
		case DeltaChanged:
			counts.Changed++
		case DeltaUnverified:
			counts.Unverified++
		default:
			// Fallback: if unclassified or active
			if it.LifecycleStatus == LifecycleActive {
				counts.Persistent++
			} else {
				counts.New++
			}
		}

		findingID := ""
		originalID := ""
		targetURL := it.TargetEndpoint
		httpMethod := "GET"

		if it.CurrentFinding != nil {
			findingID = it.CurrentFinding.ID
			if targetURL == "" {
				targetURL = it.CurrentFinding.Target
			}
			if it.CurrentFinding.EvidenceDetails.HTTPMethod != "" {
				httpMethod = it.CurrentFinding.EvidenceDetails.HTTPMethod
			}
		} else if it.BaselineFinding != nil {
			findingID = it.BaselineFinding.ID
			if targetURL == "" {
				targetURL = it.BaselineFinding.Target
			}
			if it.BaselineFinding.EvidenceDetails.HTTPMethod != "" {
				httpMethod = it.BaselineFinding.EvidenceDetails.HTTPMethod
			}
		}

		reason := it.RegressionReason
		if reason == "" {
			reason = it.ChangeReason
		}

		explanation := it.Explanation
		if explanation == "" {
			explanation = buildDefaultExplanation(it)
		}

		items = append(items, report.ChangeFindingItem{
			FindingID:      findingID,
			OriginalID:     originalID,
			Fingerprint:    it.Fingerprint,
			Title:          it.Title,
			Severity:       report.NormalizeSeverity(it.Severity),
			Category:       it.Category,
			TargetURL:      targetURL,
			Endpoint:       it.TargetEndpoint,
			HTTPMethod:     httpMethod,
			Classification: string(it.Classification),
			Reason:         reason,
			SeverityChange: it.SeverityChange,
			Explanation:    explanation,
		})
	}

	summary.Counts = counts

	// 2. Prioritize Important Changes (Section 3.C)
	// Primary: Severity Rank (CRITICAL > HIGH > MEDIUM > LOW > INFO)
	// Secondary: Delta Classification Priority (REGRESSED > NEW > CHANGED > RESOLVED > PERSISTENT > UNVERIFIED)
	// Tertiary: Fingerprint (deterministic stability)
	sort.SliceStable(items, func(i, j int) bool {
		si := report.SeverityRank(items[i].Severity)
		sj := report.SeverityRank(items[j].Severity)
		if si != sj {
			return si > sj
		}
		pi := deltaClassificationPriority(DeltaClassification(items[i].Classification))
		pj := deltaClassificationPriority(DeltaClassification(items[j].Classification))
		if pi != pj {
			return pi > pj
		}
		return items[i].Fingerprint < items[j].Fingerprint
	})
	summary.ImportantChanges = items

	// 3. Generate Evidence-Backed Narrative & Headline (Section 3.B & 3.D)
	narratives := make([]string, 0, 8)

	if summary.BaselineExecutionID == "" {
		narratives = append(narratives, "Initial assessment execution; baseline established for continuous monitoring.")
		summary.Headline = fmt.Sprintf("Baseline established with %d initial findings.", counts.TotalComparison)
	} else {
		// New findings
		if counts.New > 0 {
			narratives = append(narratives, fmt.Sprintf("%d new finding%s detected in this assessment.", counts.New, plural(counts.New)))
		}

		// Regressed findings
		if counts.Regressed > 0 {
			if reappearedCount > 0 && worsenedCount > 0 {
				narratives = append(narratives, fmt.Sprintf("%d finding%s regressed (%d reappeared after verified resolution, %d worsened in severity).",
					counts.Regressed, plural(counts.Regressed), reappearedCount, worsenedCount))
			} else if reappearedCount > 0 {
				narratives = append(narratives, fmt.Sprintf("%d finding%s reappeared after verified earlier resolution.", reappearedCount, plural(reappearedCount)))
			} else if worsenedCount > 0 {
				narratives = append(narratives, fmt.Sprintf("%d finding%s worsened in severity compared to baseline.", worsenedCount, plural(worsenedCount)))
			} else {
				narratives = append(narratives, fmt.Sprintf("%d finding%s regressed compared to baseline.", counts.Regressed, plural(counts.Regressed)))
			}
		}

		// Changed findings
		if counts.Changed > 0 {
			narratives = append(narratives, fmt.Sprintf("%d finding%s changed materially compared with the baseline.", counts.Changed, plural(counts.Changed)))
		}

		// Resolved findings
		if counts.Resolved > 0 {
			narratives = append(narratives, fmt.Sprintf("%d finding%s verified as resolved in this assessment.", counts.Resolved, plural(counts.Resolved)))
		}

		// Persistent findings
		if counts.Persistent > 0 {
			narratives = append(narratives, fmt.Sprintf("%d previously identified finding%s remain present.", counts.Persistent, plural(counts.Persistent)))
		}

		// Unverified findings
		if counts.Unverified > 0 {
			if !summary.IsReliable {
				reasonText := summary.ReliabilityReason
				if reasonText == "" {
					reasonText = fmt.Sprintf("status is %s", summary.ComparisonStatus)
				}
				narratives = append(narratives, fmt.Sprintf("%d baseline finding%s could not be confirmed as resolved because the new assessment was incomplete (%s).",
					counts.Unverified, plural(counts.Unverified), reasonText))
			} else {
				narratives = append(narratives, fmt.Sprintf("%d baseline finding%s unverified due to scope or target coverage limits.",
					counts.Unverified, plural(counts.Unverified)))
			}
		}

		// If zero changes
		if counts.New == 0 && counts.Regressed == 0 && counts.Changed == 0 && counts.Resolved == 0 {
			if counts.Persistent > 0 {
				narratives = append(narratives, "No security finding deltas detected; all findings remain unchanged.")
			} else if counts.TotalBaseline == 0 && counts.TotalComparison == 0 {
				narratives = append(narratives, "No findings detected in baseline or comparison assessment.")
			}
		}

		// Generate Headline
		summary.Headline = generateHeadline(counts, summary.IsReliable, summary.ReliabilityReason)
	}

	summary.Narrative = narratives
	return summary
}

func deltaClassificationPriority(c DeltaClassification) int {
	switch c {
	case DeltaRegressed:
		return 60
	case DeltaNew:
		return 50
	case DeltaChanged:
		return 40
	case DeltaResolved:
		return 30
	case DeltaPersistent:
		return 20
	case DeltaUnverified:
		return 10
	default:
		return 0
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func generateHeadline(c report.ChangeClassificationCounts, reliable bool, reason string) string {
	if !reliable {
		if reason != "" {
			return fmt.Sprintf("Comparison is incomplete: %s", reason)
		}
		return "Comparison is incomplete; resolution cannot be verified"
	}

	parts := make([]string, 0, 4)
	if c.New > 0 {
		parts = append(parts, fmt.Sprintf("%d new", c.New))
	}
	if c.Regressed > 0 {
		parts = append(parts, fmt.Sprintf("%d regressed", c.Regressed))
	}
	if c.Changed > 0 {
		parts = append(parts, fmt.Sprintf("%d changed", c.Changed))
	}
	if c.Resolved > 0 {
		parts = append(parts, fmt.Sprintf("%d resolved", c.Resolved))
	}

	if len(parts) > 0 {
		return strings.Join(parts, ", ") + fmt.Sprintf(" (%d persistent)", c.Persistent)
	}
	if c.Persistent > 0 {
		return fmt.Sprintf("Posture unchanged: %d persistent finding%s", c.Persistent, plural(c.Persistent))
	}
	return "No security finding changes detected"
}

func buildDefaultExplanation(it FindingComparisonItem) string {
	switch it.Classification {
	case DeltaNew:
		return fmt.Sprintf("New %s exposure detected on %s", it.Severity, it.TargetEndpoint)
	case DeltaResolved:
		return fmt.Sprintf("Previously identified %s exposure resolved and verified", it.Severity)
	case DeltaPersistent:
		return fmt.Sprintf("Persistent %s finding observed in baseline and comparison", it.Severity)
	case DeltaRegressed:
		if it.RegressionReason != "" {
			return fmt.Sprintf("Regression (%s): %s finding on %s", it.RegressionReason, it.Severity, it.TargetEndpoint)
		}
		return fmt.Sprintf("Regression: %s finding worsened or reappeared", it.Severity)
	case DeltaChanged:
		if it.ChangeReason != "" {
			return fmt.Sprintf("Material change (%s): %s", it.ChangeReason, it.Severity)
		}
		return fmt.Sprintf("Material finding characteristics modified")
	case DeltaUnverified:
		return "Unverified: insufficient coverage in comparison assessment to confirm resolution"
	default:
		return it.Title
	}
}
