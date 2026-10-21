package compliance

import (
	"fmt"
	"strings"
	"time"
)

// MTTRDateBasis determines which timestamp is used when applying date range filters.
type MTTRDateBasis string

const (
	DateBasisCompletion MTTRDateBasis = "completion"
	DateBasisStart      MTTRDateBasis = "start"
)

// MTTRFilter defines query and filtering criteria for MTTR calculations.
type MTTRFilter struct {
	From            *time.Time    `json:"from,omitempty"`
	To              *time.Time    `json:"to,omitempty"`
	DateBasis       MTTRDateBasis `json:"date_basis,omitempty"` // "completion" (default) or "start"
	Severity        string        `json:"severity,omitempty"`
	FindingCategory string        `json:"finding_category,omitempty"`
	FindingSource   string        `json:"finding_source,omitempty"`
	AssessmentID    string        `json:"assessment_id,omitempty"`
	ControlID       string        `json:"control_id,omitempty"`
	PolicyID        string        `json:"policy_id,omitempty"`
	PolicyVersion   string        `json:"policy_version,omitempty"`
	StrictIntegrity bool          `json:"strict_integrity,omitempty"`
	KeyProvider     KeyProvider   `json:"-"`
}

// RemediationEpisode represents a single, verified, completed remediation lifecycle cycle.
type RemediationEpisode struct {
	RemediationID   string        `json:"remediation_id"`
	FindingID       string        `json:"finding_id"`
	FindingTitle    string        `json:"finding_title,omitempty"`
	FindingSource   string        `json:"finding_source,omitempty"`
	FindingCategory string        `json:"finding_category,omitempty"`
	AssessmentID    string        `json:"assessment_id,omitempty"`
	CatalogID       string        `json:"catalog_id,omitempty"`
	ControlID       string        `json:"control_id,omitempty"`
	Severity        string        `json:"severity"`
	PolicyID        string        `json:"policy_id,omitempty"`
	PolicyVersion   string        `json:"policy_version,omitempty"`
	Cycle           int           `json:"cycle"` // 0 for initial cycle, 1 for first reopen, etc.
	StartTime       time.Time     `json:"start_time"`
	CompletionTime  time.Time     `json:"completion_time"`
	Duration        time.Duration `json:"duration"`
	DurationString  string        `json:"duration_string"`
	Deadline        *time.Time    `json:"deadline,omitempty"`
	MetSLA          *bool         `json:"met_sla,omitempty"` // nil if no verifiable deadline
}

// MTTRExclusions tracks categorized records excluded from completed MTTR calculation.
type MTTRExclusions struct {
	MissingHistory       int      `json:"missing_history"`
	InvalidTimestamps    int      `json:"invalid_timestamps"`
	IntegrityFailures    int      `json:"integrity_failures"`
	UnverifiedLegacy     int      `json:"unverified_legacy"`
	OpenOrInProgress     int      `json:"open_or_in_progress"`
	AcceptedRisk         int      `json:"accepted_risk"`
	TotalExcludedRecords int      `json:"total_excluded_records"`
	Warnings             []string `json:"warnings,omitempty"`
}

// SLAPerformanceMetrics tracks deadline-compliance metrics across eligible completed episodes.
type SLAPerformanceMetrics struct {
	VerifiableEpisodes      int     `json:"verifiable_episodes"` // denominator for SLA on-time rate
	CompletedOnTime         int     `json:"completed_on_time"`
	CompletedLate           int     `json:"completed_late"`
	OnTimeRate              float64 `json:"on_time_rate"` // e.g. 85.5%
	MissingDeadlineEpisodes int     `json:"missing_deadline_episodes"`
	CurrentOpenOverdue      int     `json:"current_open_overdue"`
}

// MTTRResult encapsulates the comprehensive Mean Time to Remediation metrics.
type MTTRResult struct {
	HasData              bool                   `json:"has_data"`
	MTTR                 time.Duration          `json:"mttr"`
	MTTRString           string                 `json:"mttr_string"`
	CompletedEpisodes    int                    `json:"completed_episodes"`
	UniqueFindings       int                    `json:"unique_findings"`
	TotalDuration        time.Duration          `json:"total_duration"`
	TotalDurationString  string                 `json:"total_duration_string"`
	MinDuration          *time.Duration         `json:"min_duration,omitempty"`
	MinDurationString    string                 `json:"min_duration_string,omitempty"`
	MaxDuration          *time.Duration         `json:"max_duration,omitempty"`
	MaxDurationString    string                 `json:"max_duration_string,omitempty"`
	MedianDuration       *time.Duration         `json:"median_duration,omitempty"`
	MedianDurationString string                 `json:"median_duration_string,omitempty"`
	CoverageStatus       string                 `json:"coverage_status"` // "COMPLETE", "PARTIAL", "NO_DATA"
	FilterApplied        MTTRFilter             `json:"filter_applied"`
	Exclusions           MTTRExclusions         `json:"exclusions"`
	SLAPerformance       *SLAPerformanceMetrics `json:"sla_performance,omitempty"`
	Episodes             []RemediationEpisode   `json:"episodes,omitempty"`
}

// FormatDurationHuman formats a time.Duration into a concise human-readable string.
func FormatDurationHuman(d time.Duration) string {
	if d <= 0 {
		return "0s"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	days := int(d / (24 * time.Hour))
	remaining := d % (24 * time.Hour)
	hours := int(remaining / time.Hour)
	remaining = remaining % time.Hour
	minutes := int(remaining / time.Minute)

	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 || (days > 0 && minutes > 0) {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}

	return strings.Join(parts, " ")
}
