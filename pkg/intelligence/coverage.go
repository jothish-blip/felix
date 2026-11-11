package intelligence

import (
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
)

// TestOutcome indicates the result of an attempted or skipped vulnerability test.
type TestOutcome string

const (
	OutcomePassed                 TestOutcome = "PASSED"                  // Tested, no vulnerability detected
	OutcomeVulnerable             TestOutcome = "VULNERABLE"              // Tested, verified vulnerability detected
	OutcomeInconclusive           TestOutcome = "INCONCLUSIVE"            // Candidate or ambiguous response requiring manual review
	OutcomeSkippedMissingAuth     TestOutcome = "SKIPPED_MISSING_AUTH"    // Skipped because test requires an authenticated session
	OutcomeSkippedMissingMultiRole TestOutcome = "SKIPPED_MISSING_ROLES"  // Skipped because test requires multi-persona/admin tokens
	OutcomeSkippedSafeMode        TestOutcome = "SKIPPED_SAFE_MODE"       // Skipped because active mutation is disallowed in safe mode
	OutcomeSkippedOutOfScope      TestOutcome = "SKIPPED_OUT_OF_SCOPE"    // Skipped because destination endpoint is out of authorized scope
	OutcomeUnsupported           TestOutcome = "UNSUPPORTED"             // Vulnerability class not supported on current platform/runtime
)

// DiscoveredAsset represents an asset, endpoint, or parameter identified during reconnaissance.
type DiscoveredAsset struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"` // e.g. "HOST", "ENDPOINT", "FORM", "PARAMETER", "API_ROUTE", "HEADER"
	Identifier     string    `json:"identifier"`
	DiscoveredVia  string    `json:"discovered_via"` // e.g. "SEED", "HTML_CRAWL", "JS_BUNDLE", "OPENAPI"
	InScope        bool      `json:"in_scope"`
	FirstObservedAt time.Time `json:"first_observed_at"`
}

// TestExecutionRecord tracks the outcome of evaluating a specific vulnerability class against an asset.
type TestExecutionRecord struct {
	AssetID       string            `json:"asset_id"`
	AssetURL      string            `json:"asset_url"`
	VulnClassID   string            `json:"vuln_class_id"`
	VulnName      string            `json:"vuln_name"`
	Category      string            `json:"category"`
	Technique     DetectionStrategy `json:"technique"`
	Outcome       TestOutcome       `json:"outcome"`
	Reason        string            `json:"reason,omitempty"`
	DurationMs    int64             `json:"duration_ms"`
	Timestamp     time.Time         `json:"timestamp"`
}

// CategoryCoverageSummary provides category-level metrics.
type CategoryCoverageSummary struct {
	Category        string `json:"category"`
	TotalApplicable int    `json:"total_applicable"`
	Attempted       int    `json:"attempted"`
	Passed          int    `json:"passed"`
	Vulnerable      int    `json:"vulnerable"`
	SkippedAuth     int    `json:"skipped_auth"`
	SkippedRoles    int    `json:"skipped_roles"`
	SkippedSafe     int    `json:"skipped_safe"`
	CoveragePercent float64 `json:"coverage_percent"`
}

// CoverageMatrix is the comprehensive, transparent assessment coverage report.
type CoverageMatrix struct {
	TargetURL                 string                             `json:"target_url"`
	AssessmentTimestamp       time.Time                          `json:"assessment_timestamp"`
	TotalDiscoveredAssets     int                                `json:"total_discovered_assets"`
	InScopeAssetsCount        int                                `json:"in_scope_assets_count"`
	TotalTestedAssets         int                                `json:"total_tested_assets"`
	TotalApplicableVulnClasses int                               `json:"total_applicable_vuln_classes"`
	TotalTestsAttempted       int                                `json:"total_tests_attempted"`
	PassedCount               int                                `json:"passed_count"`
	VulnerableCount           int                                `json:"vulnerable_count"`
	InconclusiveCount         int                                `json:"inconclusive_count"`
	SkippedMissingAuthCount   int                                `json:"skipped_missing_auth_count"`
	SkippedMissingRolesCount  int                                `json:"skipped_missing_roles_count"`
	SkippedSafeModeCount      int                                `json:"skipped_safe_mode_count"`
	SkippedOutOfScopeCount    int                                `json:"skipped_out_of_scope_count"`
	UnsupportedCount          int                                `json:"unsupported_count"`
	OverallCoveragePercent    float64                            `json:"overall_coverage_percent"`
	CategoryBreakdown         map[string]CategoryCoverageSummary `json:"category_breakdown"`
	DiscoveredAssets          []DiscoveredAsset                  `json:"discovered_assets"`
	TestRecords               []TestExecutionRecord              `json:"test_records"`
	UntestedAreas             []string                           `json:"untested_areas"`
}

// CoverageTracker manages thread-safe asset discovery and test execution accounting.
type CoverageTracker struct {
	mu           sync.RWMutex
	targetURL    string
	assets       map[string]DiscoveredAsset
	assetSeq     int
	testRecords  []TestExecutionRecord
	testedAssets map[string]bool
	startTime    time.Time
}

// NewCoverageTracker initializes a new assessment coverage tracker.
func NewCoverageTracker(targetURL string) *CoverageTracker {
	return &CoverageTracker{
		targetURL:    targetURL,
		assets:       make(map[string]DiscoveredAsset),
		testedAssets: make(map[string]bool),
		startTime:    time.Now().UTC(),
	}
}

// RecordDiscoveredAsset adds an observed asset to the tracker and returns its unique ID.
func (ct *CoverageTracker) RecordDiscoveredAsset(assetType, identifier, discoveredVia string, inScope bool) string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	// Normalize identifier key
	key := fmt.Sprintf("%s:%s", assetType, strings.TrimSpace(identifier))
	if existing, found := ct.assets[key]; found {
		return existing.ID
	}

	ct.assetSeq++
	id := fmt.Sprintf("AST-%04d", ct.assetSeq)
	asset := DiscoveredAsset{
		ID:              id,
		Type:            assetType,
		Identifier:      identifier,
		DiscoveredVia:   discoveredVia,
		InScope:         inScope,
		FirstObservedAt: time.Now().UTC(),
	}
	ct.assets[key] = asset
	return id
}

// RecordTest logs the execution outcome for a specific vulnerability class against an asset.
func (ct *CoverageTracker) RecordTest(assetID, assetURL, vulnClassID string, technique DetectionStrategy, outcome TestOutcome, reason string, durationMs int64) {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	vClass := FindVulnerabilityByID(vulnClassID)
	name := vulnClassID
	category := "General"
	if vClass != nil {
		name = vClass.Name
		category = vClass.Category
	}

	record := TestExecutionRecord{
		AssetID:     assetID,
		AssetURL:    assetURL,
		VulnClassID: vulnClassID,
		VulnName:    name,
		Category:    category,
		Technique:   technique,
		Outcome:     outcome,
		Reason:      reason,
		DurationMs:  durationMs,
		Timestamp:   time.Now().UTC(),
	}
	ct.testRecords = append(ct.testRecords, record)
	if outcome == OutcomePassed || outcome == OutcomeVulnerable || outcome == OutcomeInconclusive {
		ct.testedAssets[assetID] = true
	}
}

// BuildCoverageMatrix aggregates all discovery and test records into the final CoverageMatrix deliverable.
func (ct *CoverageTracker) BuildCoverageMatrix() *CoverageMatrix {
	ct.mu.RLock()
	defer ct.mu.RUnlock()

	matrix := &CoverageMatrix{
		TargetURL:                  ct.targetURL,
		AssessmentTimestamp:        time.Now().UTC(),
		CategoryBreakdown:          make(map[string]CategoryCoverageSummary),
		DiscoveredAssets:           make([]DiscoveredAsset, 0, len(ct.assets)),
		TestRecords:                make([]TestExecutionRecord, len(ct.testRecords)),
		TotalApplicableVulnClasses: len(MasterVulnerabilityCatalogue),
	}
	copy(matrix.TestRecords, ct.testRecords)

	for _, a := range ct.assets {
		matrix.DiscoveredAssets = append(matrix.DiscoveredAssets, a)
		matrix.TotalDiscoveredAssets++
		if a.InScope {
			matrix.InScopeAssetsCount++
		}
	}
	matrix.TotalTestedAssets = len(ct.testedAssets)

	// Initialize category summaries
	categories := GetCatalogueCategories()
	for _, c := range categories {
		classes := FilterCatalogueByCategory(c)
		matrix.CategoryBreakdown[c] = CategoryCoverageSummary{
			Category:        c,
			TotalApplicable: len(classes),
		}
	}

	for _, r := range ct.testRecords {
		sum := matrix.CategoryBreakdown[r.Category]

		switch r.Outcome {
		case OutcomePassed:
			matrix.TotalTestsAttempted++
			matrix.PassedCount++
			sum.Attempted++
			sum.Passed++
		case OutcomeVulnerable:
			matrix.TotalTestsAttempted++
			matrix.VulnerableCount++
			sum.Attempted++
			sum.Vulnerable++
		case OutcomeInconclusive:
			matrix.TotalTestsAttempted++
			matrix.InconclusiveCount++
			sum.Attempted++
		case OutcomeSkippedMissingAuth:
			matrix.SkippedMissingAuthCount++
			sum.SkippedAuth++
		case OutcomeSkippedMissingMultiRole:
			matrix.SkippedMissingRolesCount++
			sum.SkippedRoles++
		case OutcomeSkippedSafeMode:
			matrix.SkippedSafeModeCount++
			sum.SkippedSafe++
		case OutcomeSkippedOutOfScope:
			matrix.SkippedOutOfScopeCount++
		case OutcomeUnsupported:
			matrix.UnsupportedCount++
		}

		matrix.CategoryBreakdown[r.Category] = sum
	}

	// Calculate coverage percentages
	for c, sum := range matrix.CategoryBreakdown {
		if sum.TotalApplicable > 0 {
			pct := (float64(sum.Attempted) / float64(sum.TotalApplicable)) * 100.0
			if pct > 100.0 {
				pct = 100.0
			}
			sum.CoveragePercent = math.Round(pct*10) / 10
			matrix.CategoryBreakdown[c] = sum
		}
	}

	// Overall coverage accounting
	if matrix.TotalApplicableVulnClasses > 0 {
		attemptedDistinct := make(map[string]bool)
		for _, r := range ct.testRecords {
			if r.Outcome == OutcomePassed || r.Outcome == OutcomeVulnerable || r.Outcome == OutcomeInconclusive {
				attemptedDistinct[r.VulnClassID] = true
			}
		}
		pct := (float64(len(attemptedDistinct)) / float64(matrix.TotalApplicableVulnClasses)) * 100.0
		matrix.OverallCoveragePercent = math.Round(pct*10) / 10
	}

	// Identify explicitly untested areas
	if matrix.SkippedMissingAuthCount > 0 {
		matrix.UntestedAreas = append(matrix.UntestedAreas, fmt.Sprintf("%d test(s) skipped: Requires authenticated session (--auth)", matrix.SkippedMissingAuthCount))
	}
	if matrix.SkippedMissingRolesCount > 0 {
		matrix.UntestedAreas = append(matrix.UntestedAreas, fmt.Sprintf("%d test(s) skipped: Requires multi-role credentials (User A & User B / Admin)", matrix.SkippedMissingRolesCount))
	}
	if matrix.SkippedSafeModeCount > 0 {
		matrix.UntestedAreas = append(matrix.UntestedAreas, fmt.Sprintf("%d active injection test(s) skipped: Safe mode enabled (--safe)", matrix.SkippedSafeModeCount))
	}

	return matrix
}

// RenderTerminalSummary returns a formatted CLI report string of the coverage metrics.
func (cm *CoverageMatrix) RenderTerminalSummary() string {
	var sb strings.Builder
	sb.WriteString("\n===========================================================\n")
	sb.WriteString("  FELIX :: ASSESSMENT COVERAGE INTELLIGENCE MATRIX\n")
	sb.WriteString("===========================================================\n")
	sb.WriteString(fmt.Sprintf("  Target Base:            %s\n", cm.TargetURL))
	sb.WriteString(fmt.Sprintf("  Discovered Assets:      %d total (%d in-scope)\n", cm.TotalDiscoveredAssets, cm.InScopeAssetsCount))
	sb.WriteString(fmt.Sprintf("  Tested Assets:          %d\n", cm.TotalTestedAssets))
	attemptedDistinct := 0
	for _, sum := range cm.CategoryBreakdown {
		attemptedDistinct += sum.Attempted
	}
	sb.WriteString(fmt.Sprintf("  Registered Classes:     %d catalogue classes across %d categories\n", cm.TotalApplicableVulnClasses, len(cm.CategoryBreakdown)))
	sb.WriteString(fmt.Sprintf("  Actively Tested Classes:%d / %d (%.1f%% catalogue execution rate; NOT detection accuracy)\n",
		attemptedDistinct, cm.TotalApplicableVulnClasses, cm.OverallCoveragePercent))
	sb.WriteString(fmt.Sprintf("  Total Tests Dispatched: %d (Passed: %d | Vulnerable: %d | Inconclusive: %d)\n",
		cm.TotalTestsAttempted, cm.PassedCount, cm.VulnerableCount, cm.InconclusiveCount))
	sb.WriteString(fmt.Sprintf("  Skipped (Prereq Gaps):  %d (Missing Auth: %d | Missing Roles: %d | Safe Mode: %d)\n",
		cm.SkippedMissingAuthCount+cm.SkippedMissingRolesCount+cm.SkippedSafeModeCount,
		cm.SkippedMissingAuthCount, cm.SkippedMissingRolesCount, cm.SkippedSafeModeCount))
	sb.WriteString("-----------------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("%-32s  %-10s  %-8s  %-8s  %-8s\n", "CATEGORY", "REGISTERED", "TESTED", "SKIPPED", "COVERAGE"))
	sb.WriteString("-----------------------------------------------------------\n")

	for _, c := range GetCatalogueCategories() {
		sum, ok := cm.CategoryBreakdown[c]
		if !ok {
			continue
		}
		skipped := sum.SkippedAuth + sum.SkippedRoles + sum.SkippedSafe
		sb.WriteString(fmt.Sprintf("%-32s  %-10d  %-8d  %-8d  %5.1f%%\n",
			truncate(c, 32), sum.TotalApplicable, sum.Attempted, skipped, sum.CoveragePercent))
	}
	sb.WriteString("-----------------------------------------------------------\n")

	if len(cm.UntestedAreas) > 0 {
		sb.WriteString("UNTESTED AREAS & PREREQUISITES GAP:\n")
		for _, u := range cm.UntestedAreas {
			sb.WriteString(fmt.Sprintf("  [!] %s\n", u))
		}
		sb.WriteString("-----------------------------------------------------------\n")
	}

	return sb.String()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
