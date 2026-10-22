package report

import (
	"fmt"
	"testing"
	"time"
)

// generateBenchmarkFindings constructs a reproducible slice of findings for report benchmarking.
func generateBenchmarkFindings(count int) []Finding {
	categories := []string{"sql-injection", "broken-auth", "idor", "ssrf", "xss", "security-headers", "cors-misconfig"}
	severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
	methods := []string{"GET", "POST", "PUT", "DELETE"}

	findings := make([]Finding, count)
	for i := 0; i < count; i++ {
		cat := categories[i%len(categories)]
		sev := severities[i%len(severities)]
		method := methods[i%len(methods)]
		endpoint := fmt.Sprintf("/api/v1/resource/%d", i%100)
		target := fmt.Sprintf("https://target-%d.example.com", (i/10)%20)

		f := Finding{
			ID:          fmt.Sprintf("FND-%06d", i),
			Title:       fmt.Sprintf("Vulnerability in resource %d", i),
			Category:    cat,
			Severity:    sev,
			Confidence:  "HIGH",
			Target:      target,
			Endpoint:    endpoint,
			Method:      method,
			Description: fmt.Sprintf("Synthetic benchmark finding description for item %d with security context.", i),
			Verification: VerificationRecord{
				Status: VerificationVerified,
			},
			EvidenceDetails: EvidenceDetails{
				Details: map[string]string{
					"param":       fmt.Sprintf("param_%d", i%10),
					"route":       endpoint,
					"target_host": fmt.Sprintf("target-%d.example.com", (i/10)%20),
				},
			},
			Source:    "sast",
			Timestamp: time.Date(2026, 10, 22, 10, 0, 0, 0, time.UTC),
		}
		f.Fingerprint = fmt.Sprintf("fp-%06d", i)
		f.Score = CalculateFindingScore(f)
		findings[i] = f
	}
	return findings
}

// generateBenchmarkReport constructs a complete Report fixture for report serialization benchmarks.
func generateBenchmarkReport(findingCount int) Report {
	rawFindings := generateBenchmarkFindings(findingCount)

	targetCount := 1
	if findingCount >= 1000 {
		targetCount = 10
	}
	if findingCount >= 10000 {
		targetCount = 100
	}

	targets := make([]string, targetCount)
	for t := 0; t < targetCount; t++ {
		targets[t] = fmt.Sprintf("https://target-%d.example.com", t)
	}

	rep := BuildMultiTargetReport(targets, rawFindings)
	rep.CompletionStatus = "COMPLETED"
	return rep
}

// -----------------------------------------------------------------------------
// Stage E: Report Synthesis & Summary Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBuildMultiTargetReport(b *testing.B) {
	scales := []struct {
		name         string
		findingCount int
		targets      int
	}{
		{"Small_10", 10, 1},
		{"Medium_1000", 1000, 10},
		{"Large_10000", 10000, 100},
	}

	for _, sc := range scales {
		b.Run(sc.name, func(b *testing.B) {
			raw := generateBenchmarkFindings(sc.findingCount)
			targets := make([]string, sc.targets)
			for t := 0; t < sc.targets; t++ {
				targets[t] = fmt.Sprintf("https://target-%d.example.com", t)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = BuildMultiTargetReport(targets, raw)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage E: Report JSON Generation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkGenerateJSON(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = GenerateJSON(rep)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage E: Report HTML Generation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkGenerateHTML(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = GenerateHTML(rep)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage E: Report SARIF Serialization & Validation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkGenerateSARIF(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = GenerateSARIF(rep)
			}
		})
	}
}

func BenchmarkValidateSARIF(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)
			sarifBytes, err := GenerateSARIF(rep)
			if err != nil {
				b.Fatalf("failed to generate SARIF: %v", err)
			}

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = ValidateSARIF(sarifBytes)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage E: Commercial Report Assembly & JSON Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkBuildCommercialReport(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = BuildCommercialReport(rep)
			}
		})
	}
}

func BenchmarkGenerateCommercialJSON(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)
			comm := BuildCommercialReport(rep)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, _ = GenerateCommercialJSON(comm)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// Stage E: Report Integrity Validation Benchmarks
// -----------------------------------------------------------------------------

func BenchmarkValidateReportIntegrity(b *testing.B) {
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
			rep := generateBenchmarkReport(sc.count)

			b.ReportAllocs()
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_ = ValidateReportIntegrity(rep)
			}
		})
	}
}
