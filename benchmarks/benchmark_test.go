package main

import (
	"path/filepath"
	"testing"
)

func TestBenchmark_SyntheticCertification(t *testing.T) {
	cfg := RunnerConfig{
		SyntheticOnly: true,
		Quiet:         true,
	}

	result, code := RunBenchmarkSuite(cfg)
	if code != 0 {
		t.Fatalf("expected exit code 0 from synthetic benchmark, got %d", code)
	}
	if result == nil {
		t.Fatalf("expected non-nil benchmark result")
	}

	if result.Status != "PASS" {
		t.Errorf("expected PASS status, got %s", result.Status)
	}

	if !result.Certification.Certified {
		t.Errorf("expected certification to be true, got false. Rationale: %s", result.Certification.Rationale)
	}

	if result.Summary.HardAssertionsPassed != result.Summary.HardAssertionsTotal {
		t.Errorf("expected all %d hard assertions to pass, but %d passed",
			result.Summary.HardAssertionsTotal, result.Summary.HardAssertionsPassed)
	}

	if result.FalsePositiveCorpus.FalsePositives != 0 {
		t.Errorf("expected 0 false positives, got %d", result.FalsePositiveCorpus.FalsePositives)
	}

	if result.FalseNegativeCorpus.FalseNegatives != 0 {
		t.Errorf("expected 0 false negatives, got %d", result.FalseNegativeCorpus.FalseNegatives)
	}
}

func TestBenchmark_ComparisonTool(t *testing.T) {
	repoRoot := findRepoRoot()
	baselinePath := filepath.Join(repoRoot, "benchmarks", "results", "baseline.json")
	latestPath := filepath.Join(repoRoot, "benchmarks", "results", "latest.json")

	outcome, err := CompareBenchmarks(baselinePath, latestPath)
	if err != nil {
		t.Fatalf("CompareBenchmarks failed: %v", err)
	}

	if outcome != "PASS" {
		t.Errorf("expected comparison outcome PASS, got %s", outcome)
	}
}

func TestBenchmark_MetadataIntegrity(t *testing.T) {
	repoRoot := findRepoRoot()
	targetIDs := []string{"synthetic", "webjothishanalyst", "nexspace", "example"}

	for _, id := range targetIDs {
		meta, err := loadTargetMeta(repoRoot, id)
		if err != nil {
			t.Errorf("failed to load target metadata for %s: %v", id, err)
		}
		if meta.ID != id {
			t.Errorf("target metadata ID mismatch for %s: got %s", id, meta.ID)
		}

		expected, err := loadTargetExpected(repoRoot, id)
		if err != nil {
			t.Errorf("failed to load expected assertions for %s: %v", id, err)
		}
		if expected.TargetID != id {
			t.Errorf("expected target ID mismatch for %s: got %s", id, expected.TargetID)
		}
		if len(expected.HardAssertions) == 0 {
			t.Errorf("target %s has 0 hard assertions", id)
		}
	}
}
