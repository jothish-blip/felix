package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// MetricDelta represents a comparison between two values.
type MetricDelta struct {
	Metric   string
	Previous string
	Current  string
	Delta    string
	Flag     string // "", "WARNING", "REGRESSION"
}

// CompareBenchmarks reads two benchmark result JSON files and prints a formatted comparison table.
func CompareBenchmarks(prevPath, currPath string) (string, error) {
	prevData, err := os.ReadFile(prevPath)
	if err != nil {
		return "", fmt.Errorf("failed to read previous benchmark file %s: %w", prevPath, err)
	}
	var prev BenchmarkResult
	if err := json.Unmarshal(prevData, &prev); err != nil {
		return "", fmt.Errorf("failed to parse previous benchmark JSON: %w", err)
	}

	currData, err := os.ReadFile(currPath)
	if err != nil {
		return "", fmt.Errorf("failed to read current benchmark file %s: %w", currPath, err)
	}
	var curr BenchmarkResult
	if err := json.Unmarshal(currData, &curr); err != nil {
		return "", fmt.Errorf("failed to parse current benchmark JSON: %w", err)
	}

	// Calculate aggregated metrics
	prevReq := prev.Summary.TotalRequests
	currReq := curr.Summary.TotalRequests
	reqDelta := currReq - prevReq
	reqPercent := 0.0
	if prevReq > 0 {
		reqPercent = float64(reqDelta) / float64(prevReq) * 100.0
	}

	prevDur := time.Duration(prev.Summary.TotalDurationMs) * time.Millisecond
	currDur := time.Duration(curr.Summary.TotalDurationMs) * time.Millisecond
	durDeltaMs := curr.Summary.TotalDurationMs - prev.Summary.TotalDurationMs
	durPercent := 0.0
	if prev.Summary.TotalDurationMs > 0 {
		durPercent = float64(durDeltaMs) / float64(prev.Summary.TotalDurationMs) * 100.0
	}

	prevAssets, currAssets := 0, 0
	prevEndpoints, currEndpoints := 0, 0
	prevFindings, currFindings := 0, 0
	prevVerified, currVerified := 0, 0
	prevRisk, currRisk := 0, 0

	for _, t := range prev.Targets {
		prevAssets += t.Assets
		prevEndpoints += t.Endpoints
		prevFindings += t.Findings
		prevVerified += t.VerifiedCount
		prevRisk += t.RiskScore
	}
	for _, t := range curr.Targets {
		currAssets += t.Assets
		currEndpoints += t.Endpoints
		currFindings += t.Findings
		currVerified += t.VerifiedCount
		currRisk += t.RiskScore
	}

	overallOutcome := "PASS"
	if curr.Status == "REGRESSION" || curr.FalsePositiveCorpus.FalsePositives > prev.FalsePositiveCorpus.FalsePositives ||
		curr.FalseNegativeCorpus.FalseNegatives > prev.FalseNegativeCorpus.FalseNegatives {
		overallOutcome = "REGRESSION"
	} else if curr.Status == "WARNING" || reqPercent > 50.0 {
		overallOutcome = "WARNING"
	}

	// Build rows
	rows := []MetricDelta{
		{
			Metric:   "Requests",
			Previous: fmt.Sprintf("%d", prevReq),
			Current:  fmt.Sprintf("%d", currReq),
			Delta:    formatIntDelta(reqDelta, reqPercent),
			Flag:     checkReqFlag(reqPercent),
		},
		{
			Metric:   "Duration",
			Previous: prevDur.Round(time.Millisecond).String(),
			Current:  currDur.Round(time.Millisecond).String(),
			Delta:    formatDurDelta(durDeltaMs, durPercent),
			Flag:     "",
		},
		{
			Metric:   "Assets",
			Previous: fmt.Sprintf("%d", prevAssets),
			Current:  fmt.Sprintf("%d", currAssets),
			Delta:    formatSimpleIntDelta(currAssets - prevAssets),
			Flag:     "",
		},
		{
			Metric:   "Endpoints",
			Previous: fmt.Sprintf("%d", prevEndpoints),
			Current:  fmt.Sprintf("%d", currEndpoints),
			Delta:    formatSimpleIntDelta(currEndpoints - prevEndpoints),
			Flag:     "",
		},
		{
			Metric:   "Findings",
			Previous: fmt.Sprintf("%d", prevFindings),
			Current:  fmt.Sprintf("%d", currFindings),
			Delta:    formatSimpleIntDelta(currFindings - prevFindings),
			Flag:     "",
		},
		{
			Metric:   "Verified",
			Previous: fmt.Sprintf("%d", prevVerified),
			Current:  fmt.Sprintf("%d", currVerified),
			Delta:    formatSimpleIntDelta(currVerified - prevVerified),
			Flag:     "",
		},
		{
			Metric:   "Risk Score",
			Previous: fmt.Sprintf("%d", prevRisk),
			Current:  fmt.Sprintf("%d", currRisk),
			Delta:    formatSimpleIntDelta(currRisk - prevRisk),
			Flag:     "",
		},
		{
			Metric:   "False Positives",
			Previous: fmt.Sprintf("%d", prev.FalsePositiveCorpus.FalsePositives),
			Current:  fmt.Sprintf("%d", curr.FalsePositiveCorpus.FalsePositives),
			Delta:    formatSimpleIntDelta(curr.FalsePositiveCorpus.FalsePositives - prev.FalsePositiveCorpus.FalsePositives),
			Flag:     checkFPFlag(curr.FalsePositiveCorpus.FalsePositives - prev.FalsePositiveCorpus.FalsePositives),
		},
		{
			Metric:   "False Negatives",
			Previous: fmt.Sprintf("%d", prev.FalseNegativeCorpus.FalseNegatives),
			Current:  fmt.Sprintf("%d", curr.FalseNegativeCorpus.FalseNegatives),
			Delta:    formatSimpleIntDelta(curr.FalseNegativeCorpus.FalseNegatives - prev.FalseNegativeCorpus.FalseNegatives),
			Flag:     checkFNFlag(curr.FalseNegativeCorpus.FalseNegatives - prev.FalseNegativeCorpus.FalseNegatives),
		},
		{
			Metric:   "Status",
			Previous: prev.Status,
			Current:  curr.Status,
			Delta:    "—",
			Flag:     overallOutcome,
		},
	}

	// Print comparison table
	fmt.Println("\n===================================================================")
	fmt.Printf("FELIX BENCHMARK COMPARISON\n")
	fmt.Printf("Previous: %s (%s) | Current: %s (%s)\n",
		filepath.Base(prevPath), prev.GitCommit, filepath.Base(currPath), curr.GitCommit)
	fmt.Println("===================================================================")
	fmt.Printf("%-18s %-12s %-12s %-15s %s\n", "Metric", "Previous", "Current", "Delta", "Assessment")
	fmt.Println("-------------------------------------------------------------------")
	for _, r := range rows {
		fmt.Printf("%-18s %-12s %-12s %-15s %s\n", r.Metric, r.Previous, r.Current, r.Delta, r.Flag)
	}
	fmt.Println("-------------------------------------------------------------------")
	fmt.Printf("Benchmark Comparison Outcome: %s\n", overallOutcome)
	fmt.Println("===================================================================")

	return overallOutcome, nil
}

func formatIntDelta(delta int, pct float64) string {
	if delta == 0 {
		return "0 (0.0%)"
	}
	if delta > 0 {
		return fmt.Sprintf("+%d (+%.1f%%)", delta, pct)
	}
	return fmt.Sprintf("%d (%.1f%%)", delta, pct)
}

func formatDurDelta(deltaMs int64, pct float64) string {
	d := time.Duration(deltaMs) * time.Millisecond
	if deltaMs == 0 {
		return "0s (0.0%)"
	}
	if deltaMs > 0 {
		return fmt.Sprintf("+%s (+%.1f%%)", d.Round(time.Millisecond), pct)
	}
	return fmt.Sprintf("%s (%.1f%%)", d.Round(time.Millisecond), pct)
}

func formatSimpleIntDelta(delta int) string {
	if delta == 0 {
		return "0"
	}
	if delta > 0 {
		return fmt.Sprintf("+%d", delta)
	}
	return fmt.Sprintf("%d", delta)
}

func checkReqFlag(pct float64) string {
	if pct > 100.0 {
		return "REGRESSION (Scan Explosion)"
	}
	if pct > 50.0 {
		return "WARNING"
	}
	return "OK"
}

func checkFPFlag(delta int) string {
	if delta > 0 {
		return "REGRESSION (New False Positives)"
	}
	return "OK"
}

func checkFNFlag(delta int) string {
	if delta > 0 {
		return "REGRESSION (Missed Detections)"
	}
	return "OK"
}
