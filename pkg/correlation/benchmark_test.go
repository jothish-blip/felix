package correlation

import (
	"fmt"
	"testing"
	"time"

	"felix/pkg/report"
)

// generateBenchmarkFindings constructs a reproducible fixture slice of findings.
func generateBenchmarkFindings(count int, duplicateRate float64) []report.Finding {
	categories := []string{"sql-injection", "broken-auth", "idor", "ssrf", "xss", "security-headers", "cors-misconfig"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	uniqueCount := count
	if duplicateRate > 0 && duplicateRate < 1.0 {
		uniqueCount = int(float64(count) * (1.0 - duplicateRate))
		if uniqueCount < 1 {
			uniqueCount = 1
		}
	}

	findings := make([]report.Finding, count)
	for i := 0; i < count; i++ {
		idx := i % uniqueCount
		cat := categories[idx%len(categories)]
		sev := severities[idx%len(severities)]
		method := methods[idx%len(methods)]
		endpoint := fmt.Sprintf("/api/v1/resource/%d", idx%100)
		target := fmt.Sprintf("https://target-%d.example.com", (idx/10)%20)

		f := report.Finding{
			ID:          fmt.Sprintf("FND-%06d", i),
			Title:       fmt.Sprintf("Vulnerability in resource %d", idx),
			Category:    cat,
			Severity:    sev,
			Confidence:  "HIGH",
			Target:      target,
			Endpoint:    endpoint,
			Method:      method,
			Description: fmt.Sprintf("Synthetic benchmark finding description for item %d with security context.", idx),
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
			},
			EvidenceDetails: report.EvidenceDetails{
				Details: map[string]string{
					"param":       fmt.Sprintf("param_%d", idx%10),
					"route":       endpoint,
					"target_host": fmt.Sprintf("target-%d.example.com", (idx/10)%20),
				},
			},
			Source:    "sast",
			Timestamp: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC),
		}
		f.Fingerprint = ComputeStableFingerprint(f)
		findings[i] = f
	}
	return findings
}

// generateBaselineAndCurrent creates paired datasets for lifecycle comparison benchmarking.
func generateBaselineAndCurrent(count int) ([]report.Finding, []report.Finding) {
	baseline := generateBenchmarkFindings(count, 0)
	current := make([]report.Finding, count)

	for i := 0; i < count; i++ {
		switch {
		case i < count*7/10:
			// 70% Unchanged / Persistent
			current[i] = baseline[i]
		case i < count*85/100:
			// 15% Regressed / Modified Severity
			mod := baseline[i]
			if mod.Severity == "LOW" {
				mod.Severity = "HIGH"
			} else {
				mod.Severity = "CRITICAL"
			}
			mod.Score = report.CalculateFindingScore(mod)
			current[i] = mod
		default:
			// 15% Brand New
			newIdx := count + i
			cat := "business-logic"
			endpoint := fmt.Sprintf("/api/v2/fresh/%d", newIdx)
			target := "https://target-new.example.com"
			f := report.Finding{
				ID:          fmt.Sprintf("FND-NEW-%06d", newIdx),
				Title:       fmt.Sprintf("New vulnerability %d", newIdx),
				Category:    cat,
				Severity:    "HIGH",
				Confidence:  "HIGH",
				Target:      target,
				Endpoint:    endpoint,
				Method:      "POST",
				Description: "Brand new finding discovered in current assessment",
				Verification: report.VerificationRecord{
					Status: report.VerificationVerified,
				},
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"route": endpoint,
					},
				},
				Source:    "sast",
				Timestamp: time.Date(2026, 10, 22, 11, 0, 0, 0, time.UTC),
			}
			f.Fingerprint = ComputeStableFingerprint(f)
			current[i] = f
		}
	}
	return baseline, current
}

// -----------------------------------------------------------------------------
// Stage C: Finding Fingerprint Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkFindingFingerprint_Single(b *testing.B) {
	fixture := generateBenchmarkFindings(1, 0)[0]
	fixture.Fingerprint = ""

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ComputeStableFingerprint(fixture)
	}
}

func BenchmarkFindingFingerprint_Batch(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			fixtures := generateBenchmarkFindings(sc.count, 0)
			for i := range fixtures {
				fixtures[i].Fingerprint = ""
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				for j := range fixtures {
					_ = ComputeStableFingerprint(fixtures[j])
				}
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage C: Finding Normalization Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkFindingNormalization(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			fixtures := generateBenchmarkFindings(sc.count, 0)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = NormalizeFindings(fixtures)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage C: Finding Deduplication Benchmarks (Unique vs Duplicate Rates)
// -----------------------------------------------------------------------------

func BenchmarkFindingDeduplication_Unique(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			fixtures := generateBenchmarkFindings(sc.count, 0.0)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = DeduplicateFindings(fixtures)
			}
		})
	}
}

func BenchmarkFindingDeduplication_Duplicates(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			fixtures := generateBenchmarkFindings(sc.count, 0.5)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = DeduplicateFindings(fixtures)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage C: Lifecycle Comparison Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkLifecycleComparison(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	opts := ComparisonOptions{
		CurrentCompleted: true,
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			baseline, current := generateBaselineAndCurrent(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = CompareFindingsWithOptions(baseline, current, opts)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage C: Change Summary Generation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBuildChangeSummary(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_1000", 1000},
		{"Large_10000", 10000},
	}

	now := time.Now().UTC()
	opts := ComparisonOptions{CurrentCompleted: true}
	summaryOpts := ChangeSummaryOptions{
		AssessmentID:        "asm-bench",
		BaselineStatus:      "COMPLETED",
		ComparisonStatus:    "COMPLETED",
		IsReliable:          true,
		ComparisonTimestamp: now,
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			baseline, current := generateBaselineAndCurrent(sc.count)
			cmp := CompareFindingsWithOptions(baseline, current, opts)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = BuildChangeSummary(&cmp, summaryOpts)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage C: Multi-Finding Correlation Rules Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkCorrelationEvaluateRules(b *testing.B) {
	scales := []struct {
		name  string
		count int
	}{
		{"Small_10", 10},
		{"Medium_100", 100},
		{"Large_1000", 1000},
	}

	cfg := DefaultConfig()

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			fixtures := generateBenchmarkFindings(sc.count, 0)
			norm := NormalizeFindings(fixtures)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = EvaluateRules(norm, cfg)
			}
		})
	}
}
