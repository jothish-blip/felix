package compliance

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

// GenerateRemediationEventID generates a collision-resistant unique history event ID.
func GenerateRemediationEventID(remID string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("evthist:%s:%d-%s", remID, time.Now().UTC().UnixNano(), hex.EncodeToString(b))
}

var (
	// ErrInvalidRemediationTransition is returned when an illegal lifecycle state transition is attempted.
	ErrInvalidRemediationTransition = errors.New("invalid remediation lifecycle status transition")

	// ErrRiskAcceptanceIncomplete is returned when risk acceptance lacks required rationale or author.
	ErrRiskAcceptanceIncomplete = errors.New("risk acceptance requires non-empty rationale and author")
)

// RemediationLifecycleStatus represents the explicit workflow state of a remediation item.
// Invariant: Represents remediation lifecycle separately from original compliance evaluation states.
type RemediationLifecycleStatus string

const (
	// RemediationStatusOpen: Remediation is required and work has not started.
	RemediationStatusOpen RemediationLifecycleStatus = "open"

	// RemediationStatusInProgress: Remediation work has begun.
	RemediationStatusInProgress RemediationLifecycleStatus = "in_progress"

	// RemediationStatusRemediated: Remediation is reported as completed.
	RemediationStatusRemediated RemediationLifecycleStatus = "remediated"

	// RemediationStatusAcceptedRisk: An authorized, documented risk acceptance exists.
	RemediationStatusAcceptedRisk RemediationLifecycleStatus = "accepted_risk"

	// RemediationStatusReopened: A previously remediated item requires remediation again.
	RemediationStatusReopened RemediationLifecycleStatus = "reopened"
)

// ComputedSLAStatus represents the calculated SLA compliance state evaluated at a specific point in time.
type ComputedSLAStatus string

const (
	// SLAStatusNotDue: Current time is comfortably before the deadline.
	SLAStatusNotDue ComputedSLAStatus = "not_due"

	// SLAStatusApproachingDeadline: Current time is before the deadline but within the configured warning window.
	SLAStatusApproachingDeadline ComputedSLAStatus = "approaching_deadline"

	// SLAStatusOverdue: Item is open, in progress, or reopened, and current time is strictly after the deadline.
	SLAStatusOverdue ComputedSLAStatus = "overdue"

	// SLAStatusRemediatedOnTime: Remediation completed at or before the assigned deadline.
	SLAStatusRemediatedOnTime ComputedSLAStatus = "remediated_on_time"

	// SLAStatusRemediatedLate: Remediation completed after the assigned deadline.
	SLAStatusRemediatedLate ComputedSLAStatus = "remediated_late"

	// SLAStatusAcceptedRisk: An authorized risk acceptance is active.
	SLAStatusAcceptedRisk ComputedSLAStatus = "accepted_risk"
)

// ValidateRemediationLifecycleStatus validates whether a status string is one of the 5 canonical lifecycle states.
func ValidateRemediationLifecycleStatus(s RemediationLifecycleStatus) error {
	switch s {
	case RemediationStatusOpen, RemediationStatusInProgress, RemediationStatusRemediated,
		RemediationStatusAcceptedRisk, RemediationStatusReopened:
		return nil
	default:
		return fmt.Errorf("invalid remediation lifecycle status %q; must be one of: open, in_progress, remediated, accepted_risk, reopened", s)
	}
}

// ValidateRemediationTransition enforces legitimate lifecycle transitions.
// Transition Rules:
// - Open -> InProgress, Remediated, AcceptedRisk
// - InProgress -> Remediated, Open, AcceptedRisk
// - Remediated -> Reopened
// - Reopened -> InProgress, Remediated, AcceptedRisk
// - AcceptedRisk -> Open, InProgress (revocation of risk acceptance)
// Self-transitions are permitted as no-ops.
func ValidateRemediationTransition(from, to RemediationLifecycleStatus) error {
	if err := ValidateRemediationLifecycleStatus(from); err != nil {
		return err
	}
	if err := ValidateRemediationLifecycleStatus(to); err != nil {
		return err
	}
	if from == to {
		return nil
	}

	switch from {
	case RemediationStatusOpen:
		if to == RemediationStatusInProgress || to == RemediationStatusRemediated || to == RemediationStatusAcceptedRisk {
			return nil
		}
	case RemediationStatusInProgress:
		if to == RemediationStatusRemediated || to == RemediationStatusOpen || to == RemediationStatusAcceptedRisk {
			return nil
		}
	case RemediationStatusRemediated:
		if to == RemediationStatusReopened {
			return nil
		}
	case RemediationStatusReopened:
		if to == RemediationStatusInProgress || to == RemediationStatusRemediated || to == RemediationStatusAcceptedRisk {
			return nil
		}
	case RemediationStatusAcceptedRisk:
		if to == RemediationStatusOpen || to == RemediationStatusInProgress {
			return nil
		}
	}

	return fmt.Errorf("%w: cannot transition from %q to %q", ErrInvalidRemediationTransition, from, to)
}

// RiskAcceptanceRecord captures the formal authorization, rationale, and validity window for accepted risks.
type RiskAcceptanceRecord struct {
	Rationale  string     `json:"rationale"`
	Author     string     `json:"author"`
	AcceptedAt time.Time  `json:"accepted_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	Context    string     `json:"context,omitempty"`
}

// Validate ensures risk acceptance contains mandatory rationale and author fields.
func (r *RiskAcceptanceRecord) Validate() error {
	if r == nil {
		return ErrRiskAcceptanceIncomplete
	}
	if strings.TrimSpace(r.Rationale) == "" {
		return fmt.Errorf("%w: rationale cannot be empty", ErrRiskAcceptanceIncomplete)
	}
	if strings.TrimSpace(r.Author) == "" {
		return fmt.Errorf("%w: author cannot be empty", ErrRiskAcceptanceIncomplete)
	}
	return nil
}

// RemediationRecord represents the full, auditable remediation lifecycle tracking for an identified security finding.
type RemediationRecord struct {
	ID                 string                     `json:"id"`
	FindingID          string                     `json:"finding_id"`
	FindingSource      string                     `json:"finding_source"`
	FindingTitle       string                     `json:"finding_title,omitempty"`
	FindingCategory    string                     `json:"finding_category,omitempty"`
	AssessmentID       string                     `json:"assessment_id,omitempty"`
	CatalogID          string                     `json:"catalog_id,omitempty"`
	ControlID          string                     `json:"control_id,omitempty"`
	EvaluationID       string                     `json:"evaluation_id,omitempty"`
	Severity           string                     `json:"severity"`
	SeveritySource     string                     `json:"severity_source"` // e.g. "finding", "operator_override"
	PolicyID           string                     `json:"policy_id"`
	PolicyVersion      string                     `json:"policy_version"`
	PolicyRuleMatched  string                     `json:"policy_rule_matched,omitempty"`
	AssignedAt         time.Time                  `json:"assigned_at"`
	SLAStartTime       time.Time                  `json:"sla_start_time"`
	Deadline           time.Time                  `json:"deadline"`
	TimeBasis          string                     `json:"time_basis"` // "ELAPSED_TIME"
	Status             RemediationLifecycleStatus `json:"status"`
	CompletedAt        *time.Time                 `json:"completed_at,omitempty"`
	RiskAcceptance     *RiskAcceptanceRecord      `json:"risk_acceptance,omitempty"`
	ReopenCount        int                        `json:"reopen_count"`
	ReopenedAt         *time.Time                 `json:"reopened_at,omitempty"`
	EvidenceReferences []string                   `json:"evidence_references,omitempty"`
	IntegrityVersion   string                     `json:"integrity_version,omitempty"`
	CreatedAt          time.Time                  `json:"created_at"`
	UpdatedAt          time.Time                  `json:"updated_at"`

	// Computed on retrieval (not stored directly)
	ComputedSLAStatus ComputedSLAStatus `json:"computed_sla_status,omitempty"`
	TimeRemaining     time.Duration     `json:"time_remaining,omitempty"`
	IsOverdue         bool              `json:"is_overdue"`
}

// RemediationHistoryEventType identifies the class of remediation event.
type RemediationHistoryEventType string

const (
	HistoryEventAssigned             RemediationHistoryEventType = "ASSIGNED"
	HistoryEventStatusChanged        RemediationHistoryEventType = "STATUS_CHANGED"
	HistoryEventDeadlineRecalculated RemediationHistoryEventType = "DEADLINE_RECALCULATED"
	HistoryEventRiskAccepted         RemediationHistoryEventType = "RISK_ACCEPTED"
	HistoryEventRiskRevoked          RemediationHistoryEventType = "RISK_REVOKED"
	HistoryEventReopened             RemediationHistoryEventType = "REOPENED"
)

// RemediationHistoryEvent captures an immutable audit record of every state transition or deadline modification.
type RemediationHistoryEvent struct {
	ID            string                      `json:"id"`
	RemediationID string                      `json:"remediation_id"`
	EventType     RemediationHistoryEventType `json:"event_type"`
	FromStatus    RemediationLifecycleStatus  `json:"from_status,omitempty"`
	ToStatus      RemediationLifecycleStatus  `json:"to_status,omitempty"`
	Actor         string                      `json:"actor,omitempty"`
	Reason        string                      `json:"reason,omitempty"`
	DetailsJSON   string                      `json:"details_json,omitempty"`
	Timestamp     time.Time                   `json:"timestamp"`
}

// RemediationFilter specifies query criteria for searching remediation records.
type RemediationFilter struct {
	FindingID    string                     `json:"finding_id,omitempty"`
	AssessmentID string                     `json:"assessment_id,omitempty"`
	ControlID    string                     `json:"control_id,omitempty"`
	Severity     string                     `json:"severity,omitempty"`
	Status       RemediationLifecycleStatus `json:"status,omitempty"`
	PolicyID     string                     `json:"policy_id,omitempty"`
	OnlyOverdue  bool                       `json:"only_overdue,omitempty"`
	Limit        int                        `json:"limit,omitempty"`
	Offset       int                        `json:"offset,omitempty"`
}
