package intelligence

import (
	"testing"
	"time"

	"felix/pkg/report"
)

func TestMasterVulnerabilityCatalogueIntegrity(t *testing.T) {
	cats := GetCatalogueCategories()
	if len(cats) < 10 {
		t.Fatalf("expected at least 10 categories, got %d", len(cats))
	}

	full := GetMasterCatalogue()
	if len(full) < 20 {
		t.Fatalf("expected at least 20 vulnerability classes, got %d", len(full))
	}

	seenIDs := make(map[string]bool)
	for _, v := range full {
		if v.ID == "" {
			t.Errorf("empty ID found in catalog")
		}
		if seenIDs[v.ID] {
			t.Errorf("duplicate ID %s found in catalog", v.ID)
		}
		seenIDs[v.ID] = true

		if v.Name == "" || v.Category == "" || v.OWASP == "" || v.CWE == "" || v.Severity == "" {
			t.Errorf("incomplete metadata for %s", v.ID)
		}
		if v.Status == "" || v.DetectionStrategy == "" || len(v.Prerequisites) == 0 {
			t.Errorf("incomplete execution strategy for %s", v.ID)
		}
	}

	sqli := FindVulnerabilityByID("VULN-SQLI-001")
	if sqli == nil {
		t.Fatalf("expected VULN-SQLI-001 to exist")
	}
	if sqli.CWE != "CWE-89" {
		t.Errorf("expected CWE-89 for SQLi, got %s", sqli.CWE)
	}

	inj := FilterCatalogueByCategory("Injection Vulnerabilities")
	if len(inj) == 0 {
		t.Fatalf("expected non-empty injection category")
	}
}

func TestCoverageTrackerAndMatrix(t *testing.T) {
	tracker := NewCoverageTracker("https://example.com")
	ast1 := tracker.RecordDiscoveredAsset("ENDPOINT", "https://example.com/login", "HTML_CRAWL", true)
	ast2 := tracker.RecordDiscoveredAsset("API_ROUTE", "https://example.com/api/v1/users", "JS_BUNDLE", true)

	if ast1 == "" || ast2 == "" || ast1 == ast2 {
		t.Fatalf("asset registration failed: ast1=%s, ast2=%s", ast1, ast2)
	}

	tracker.RecordTest(ast1, "https://example.com/login", "VULN-AUTH-BRUTE-001", StrategyDifferentialBehavior, OutcomePassed, "Rate limit active", 45)
	tracker.RecordTest(ast2, "https://example.com/api/v1/users", "VULN-BOLA-001", StrategyDifferentialBehavior, OutcomeVulnerable, "Cross-user ID read succeeded", 60)
	tracker.RecordTest(ast2, "https://example.com/api/v1/users", "VULN-BFLA-001", StrategyDifferentialBehavior, OutcomeSkippedMissingMultiRole, "Requires admin token", 0)

	matrix := tracker.BuildCoverageMatrix()
	if matrix.TotalDiscoveredAssets != 2 {
		t.Errorf("expected 2 discovered assets, got %d", matrix.TotalDiscoveredAssets)
	}
	if matrix.TotalTestedAssets != 2 {
		t.Errorf("expected 2 tested assets, got %d", matrix.TotalTestedAssets)
	}
	if matrix.VulnerableCount != 1 {
		t.Errorf("expected 1 vulnerable count, got %d", matrix.VulnerableCount)
	}
	if matrix.PassedCount != 1 {
		t.Errorf("expected 1 passed count, got %d", matrix.PassedCount)
	}
	if matrix.SkippedMissingRolesCount != 1 {
		t.Errorf("expected 1 skipped roles count, got %d", matrix.SkippedMissingRolesCount)
	}
	if len(matrix.UntestedAreas) == 0 {
		t.Errorf("expected untested areas to record missing role gap")
	}

	summary := matrix.RenderTerminalSummary()
	if len(summary) == 0 {
		t.Errorf("expected rendered summary to have content")
	}
}

func TestRemediationRoadmapGeneration(t *testing.T) {
	findings := []report.Finding{
		{
			ID:          "F-SQLI-01",
			Category:    "Injection Vulnerabilities",
			Title:       "SQL Injection on /search",
			Severity:    "Critical",
			Confidence:  "High",
			Target:      "https://example.com/search?q=1",
			Endpoint:    "/search",
			Description: "Boolean differential verified",
			Timestamp:   time.Now().UTC(),
		},
		{
			ID:          "F-HDR-01",
			Category:    "Missing Security Header",
			Title:       "Missing Content-Security-Policy",
			Severity:    "Low",
			Confidence:  "High",
			Target:      "https://example.com",
			Description: "CSP header is not set",
			Timestamp:   time.Now().UTC(),
		},
	}

	roadmap := GenerateRoadmap(findings, "https://example.com")
	if roadmap.TotalTasks != 2 {
		t.Fatalf("expected 2 tasks, got %d", roadmap.TotalTasks)
	}
	if roadmap.P1Count != 1 {
		t.Errorf("expected 1 P1 task, got %d", roadmap.P1Count)
	}
	if roadmap.P4Count != 1 {
		t.Errorf("expected 1 P4 task, got %d", roadmap.P4Count)
	}

	rendered := roadmap.RenderTerminalSummary()
	if len(rendered) == 0 {
		t.Errorf("expected non-empty roadmap terminal summary")
	}
}
