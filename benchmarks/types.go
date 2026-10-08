package main

import "time"

// TargetMeta defines the metadata for a benchmark target.
type TargetMeta struct {
	Name              string `json:"name"`
	ID                string `json:"id"`
	URL               string `json:"url"`
	Scope             string `json:"scope"`
	BenchmarkType     string `json:"benchmark_type"` // "DETERMINISTIC" or "LIVE"
	Purpose           string `json:"purpose"`
	AuthorizationNote string `json:"authorization_note"`
	Environment       string `json:"environment"`
}

// HardAssertion defines a non-negotiable security invariant.
type HardAssertion struct {
	ID                        string `json:"id"`
	Category                  string `json:"category"`
	Description               string `json:"description"`
	Pattern                   string `json:"pattern,omitempty"`
	ExpectedSeverity          string `json:"expected_severity,omitempty"`
	ExpectedVerification      string `json:"expected_verification,omitempty"`
	EndpointContains          string `json:"endpoint_contains,omitempty"`
	ExpectedFalsePositives    *int   `json:"expected_false_positives,omitempty"`
	MustNotVerifyCredentials  bool   `json:"must_not_verify_credentials,omitempty"`
	MustSucceed               bool   `json:"must_succeed,omitempty"`
	MinAssets                 int    `json:"min_assets,omitempty"`
	MaxCriticalFindings       *int   `json:"max_critical_findings,omitempty"`
	ScopeEnforced             bool   `json:"scope_enforced,omitempty"`
	DestructiveMethodsUsed    *int   `json:"destructive_methods_used,omitempty"`
}

// MetricBound specifies acceptable numerical limits for a metric.
type MetricBound struct {
	Min              int     `json:"min,omitempty"`
	Max              int     `json:"max,omitempty"`
	MaxGrowthPercent float64 `json:"max_growth_percent,omitempty"`
}

// BehavioralBounds defines acceptable variance ranges for operational metrics.
type BehavioralBounds struct {
	Requests   MetricBound `json:"requests"`
	DurationMs MetricBound `json:"duration_ms"`
	Assets     MetricBound `json:"assets"`
	Endpoints  MetricBound `json:"endpoints,omitempty"`
	Findings   MetricBound `json:"findings"`
}

// TargetExpected defines the complete expected specification for a benchmark target.
type TargetExpected struct {
	TargetID             string           `json:"target_id"`
	Name                 string           `json:"name"`
	BenchmarkType        string           `json:"benchmark_type"`
	HardAssertions       []HardAssertion  `json:"hard_assertions"`
	BehavioralBounds     BehavioralBounds `json:"behavioral_bounds"`
	ObservationalMetrics []string         `json:"observational_metrics"`
}

// AssertionResult records the outcome of a single benchmark assertion.
type AssertionResult struct {
	AssertionID string `json:"assertion_id"`
	Category    string `json:"category"`
	Passed      bool   `json:"passed"`
	Description string `json:"description"`
	Details     string `json:"details,omitempty"`
}

// TargetResult holds the detailed benchmark execution results for a single target.
type TargetResult struct {
	Name             string            `json:"name"`
	TargetID         string            `json:"target_id"`
	URL              string            `json:"url"`
	BenchmarkType    string            `json:"benchmark_type"` // "DETERMINISTIC" or "LIVE"
	Status           string            `json:"status"`         // "PASS", "WARNING", "REGRESSION"
	DurationMs       int64             `json:"duration_ms"`
	Duration         string            `json:"duration"`
	Requests         int               `json:"requests"`
	Assets           int               `json:"assets"`
	Endpoints        int               `json:"endpoints"`
	Findings         int               `json:"findings"`
	VerifiedCount    int               `json:"verified_count"`
	DetectedCount    int               `json:"detected_count"`
	ObservedCount    int               `json:"observed_count"`
	NotVerifiedCount int               `json:"not_verified_count"`
	NotExposedCount  int               `json:"not_exposed_count"`
	RiskScore        int               `json:"risk_score"`
	RiskLevel        string            `json:"risk_level"`
	AssertionsPassed int               `json:"assertions_passed"`
	AssertionsFailed int               `json:"assertions_failed"`
	FalsePositives   int               `json:"false_positives"`
	FalseNegatives   int               `json:"false_negatives"`
	BoundsChecked    int               `json:"bounds_checked"`
	BoundsPassed     int               `json:"bounds_passed"`
	Regressions      []string          `json:"regressions,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	AssertionDetails []AssertionResult `json:"assertion_details,omitempty"`
}

// EnvironmentInfo captures the test execution host environment.
type EnvironmentInfo struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	GoVersion string `json:"go_version"`
}

// CorpusSummary tracks metrics for a specific verification corpus.
type CorpusSummary struct {
	Evaluated      int    `json:"evaluated"`
	PassedCount    int    `json:"passed_count"`
	FailedCount    int    `json:"failed_count"`
	FalsePositives int    `json:"false_positives,omitempty"`
	FalseNegatives int    `json:"false_negatives,omitempty"`
	Status         string `json:"status"` // "PASS" or "REGRESSION"
}

// PerformanceSummary records aggregate runtime and network load.
type PerformanceSummary struct {
	TotalRequests   int    `json:"total_requests"`
	TotalDurationMs int64  `json:"total_duration_ms"`
	TotalDuration   string `json:"total_duration"`
	Regression      string `json:"regression"` // "NONE", "WARNING", "REGRESSION"
}

// CertificationSummary records whether the Felix build meets all release criteria.
type CertificationSummary struct {
	Certified bool   `json:"certified"`
	Grade     string `json:"grade"` // "PASS", "WARNING", "REGRESSION"
	Rationale string `json:"rationale"`
}

// OverallSummary aggregates counts across all executed targets.
type OverallSummary struct {
	TotalTargets         int  `json:"total_targets"`
	DeterministicPassed  bool `json:"deterministic_passed"`
	LivePassed           bool `json:"live_passed"`
	HardAssertionsTotal  int  `json:"hard_assertions_total"`
	HardAssertionsPassed int  `json:"hard_assertions_passed"`
	BoundsChecked        int  `json:"bounds_checked"`
	BoundsPassed         int  `json:"bounds_passed"`
	FalsePositivesCount  int  `json:"false_positives_count"`
	FalseNegativesCount  int  `json:"false_negatives_count"`
	TotalRequests        int  `json:"total_requests"`
	TotalDurationMs      int64 `json:"total_duration_ms"`
}

// BenchmarkResult represents the machine-readable output saved to latest.json.
type BenchmarkResult struct {
	Timestamp           time.Time            `json:"timestamp"`
	FelixVersion        string               `json:"felix_version"`
	GitCommit           string               `json:"git_commit"`
	Environment         EnvironmentInfo      `json:"environment"`
	Status              string               `json:"status"` // "PASS", "WARNING", "REGRESSION"
	Summary             OverallSummary       `json:"summary"`
	Targets             []TargetResult       `json:"targets"`
	FalsePositiveCorpus CorpusSummary        `json:"false_positive_corpus"`
	FalseNegativeCorpus CorpusSummary        `json:"false_negative_corpus"`
	Performance         PerformanceSummary   `json:"performance"`
	Certification       CertificationSummary `json:"certification"`
}
