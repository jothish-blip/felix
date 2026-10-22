package report

import (
	"fmt"
	"strings"
	"time"
)

// ChangeSummary represents the concise, machine-readable explanation of changes
// between two assessment executions.
type ChangeSummary struct {
	AssessmentID          string                     `json:"assessment_id"`
	ComparisonExecutionID string                     `json:"comparison_execution_id"`
	BaselineExecutionID   string                     `json:"baseline_execution_id,omitempty"`
	ComparisonSnapshotID  string                     `json:"comparison_snapshot_id,omitempty"`
	BaselineSnapshotID    string                     `json:"baseline_snapshot_id,omitempty"`
	ComparisonTimestamp   time.Time                  `json:"comparison_timestamp"`
	BaselineTimestamp     *time.Time                 `json:"baseline_timestamp,omitempty"`
	BaselineStatus        string                     `json:"baseline_status,omitempty"`
	ComparisonStatus      string                     `json:"comparison_status"` // e.g. "COMPLETED", "FAILED", "INCOMPLETE"
	IsReliable            bool                       `json:"is_reliable"`       // True if comparison is complete and reliable
	ReliabilityReason     string                     `json:"reliability_reason,omitempty"`
	Counts                ChangeClassificationCounts `json:"counts"`
	Headline              string                     `json:"headline"`          // Concise human-readable headline
	Narrative             []string                   `json:"narrative"`         // Grounded, evidence-backed narrative statements
	ImportantChanges      []ChangeFindingItem        `json:"important_changes"` // Prioritized list of notable changes
	NetRiskScoreDelta     int                        `json:"net_risk_score_delta"`
}

// ChangeClassificationCounts details the count of findings by delta classification.
type ChangeClassificationCounts struct {
	TotalBaseline     int `json:"total_baseline"`
	TotalComparison   int `json:"total_comparison"`
	New               int `json:"new"`
	Resolved          int `json:"resolved"`
	Persistent        int `json:"persistent"`
	Regressed         int `json:"regressed"`
	Changed           int `json:"changed"`
	Unverified        int `json:"unverified"`
	SeverityIncreased int `json:"severity_increased"`
	SeverityDecreased int `json:"severity_decreased"`
	Unchanged         int `json:"unchanged"`
	Unknown           int `json:"unknown"`
}

// ChangeFindingItem captures essential finding identity, classification, and change context.
type ChangeFindingItem struct {
	FindingID        string   `json:"finding_id,omitempty"`
	OriginalID       string   `json:"original_id,omitempty"`
	Fingerprint      string   `json:"fingerprint"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	Category         string   `json:"category"`
	TargetURL        string   `json:"target_url"`
	Endpoint         string   `json:"endpoint"`
	HTTPMethod       string   `json:"http_method"`
	Classification   string   `json:"classification"` // NEW, RESOLVED, PERSISTENT, REGRESSED, CHANGED, UNVERIFIED
	CanonicalDelta   string   `json:"canonical_delta,omitempty"`
	SeverityDelta    string   `json:"severity_delta,omitempty"`
	AttributeChanges []string `json:"attribute_changes,omitempty"`
	Reason           string   `json:"reason,omitempty"`         // Regression or change reason
	SeverityChange   string   `json:"severity_change,omitempty"` // e.g. "MEDIUM -> HIGH"
	Explanation      string   `json:"explanation"`
}

// FormatText generates a clean, readable terminal text summary.
func (cs *ChangeSummary) FormatText() string {
	var sb strings.Builder

	sb.WriteString("================================================================================\n")
	sb.WriteString("FELIX ASSESSMENT CHANGE SUMMARY\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("Assessment ID:        %s\n", cs.AssessmentID))
	if cs.BaselineExecutionID != "" {
		sb.WriteString(fmt.Sprintf("Baseline Execution:   %s", cs.BaselineExecutionID))
		if cs.BaselineStatus != "" {
			sb.WriteString(fmt.Sprintf(" (Status: %s)", cs.BaselineStatus))
		}
		sb.WriteString("\n")
	} else {
		sb.WriteString("Baseline Execution:   [NONE - Initial Execution]\n")
	}
	sb.WriteString(fmt.Sprintf("Comparison Execution: %s (Status: %s)\n", cs.ComparisonExecutionID, cs.ComparisonStatus))
	if cs.IsReliable {
		sb.WriteString("Comparison Integrity: COMPLETE & RELIABLE\n")
	} else {
		sb.WriteString(fmt.Sprintf("Comparison Integrity: PARTIAL / UNCERTAIN (%s)\n", cs.ReliabilityReason))
	}

	sb.WriteString("\nCLASSIFICATION COUNTS:\n")
	sb.WriteString(fmt.Sprintf("  Baseline Findings:   %d\n", cs.Counts.TotalBaseline))
	sb.WriteString(fmt.Sprintf("  Current Findings:    %d\n", cs.Counts.TotalComparison))
	sb.WriteString(fmt.Sprintf("  New Findings:        %d\n", cs.Counts.New))
	sb.WriteString(fmt.Sprintf("  Regressed Findings:  %d\n", cs.Counts.Regressed))
	sb.WriteString(fmt.Sprintf("  Changed Findings:    %d\n", cs.Counts.Changed))
	sb.WriteString(fmt.Sprintf("  Resolved Findings:   %d\n", cs.Counts.Resolved))
	sb.WriteString(fmt.Sprintf("  Persistent Findings: %d\n", cs.Counts.Persistent))
	sb.WriteString(fmt.Sprintf("  Unverified/Pending:  %d\n", cs.Counts.Unverified))
	if cs.BaselineExecutionID != "" {
		sign := ""
		if cs.NetRiskScoreDelta > 0 {
			sign = "+"
		}
		sb.WriteString(fmt.Sprintf("  Net Risk Delta:      %s%d\n", sign, cs.NetRiskScoreDelta))
	}

	sb.WriteString("\nEXECUTIVE NARRATIVE:\n")
	if len(cs.Narrative) == 0 {
		sb.WriteString(fmt.Sprintf("  %s\n", cs.Headline))
	} else {
		for _, stmt := range cs.Narrative {
			sb.WriteString(fmt.Sprintf("  * %s\n", stmt))
		}
	}

	if len(cs.ImportantChanges) > 0 {
		sb.WriteString("\nKEY FINDING CHANGES:\n")
		sb.WriteString(fmt.Sprintf("  %-12s %-10s %-32s %-25s\n", "CHANGE", "SEVERITY", "TITLE", "DETAILS"))
		sb.WriteString(fmt.Sprintf("  %-12s %-10s %-32s %-25s\n", "------", "--------", "-----", "-------"))
		for _, item := range cs.ImportantChanges {
			title := item.Title
			if len(title) > 30 {
				title = title[:27] + "..."
			}
			details := item.Reason
			if details == "" {
				details = item.Explanation
			}
			if len(details) > 25 {
				details = details[:22] + "..."
			}
			sb.WriteString(fmt.Sprintf("  %-12s %-10s %-32s %-25s\n",
				item.Classification, item.Severity, title, details))
		}
	}

	return sb.String()
}
