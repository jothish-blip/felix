package assessment

import (
	"fmt"
	"time"
)

// ReviewStatus represents the operator's business review decision for a finding.
// Invariant: This is strictly an editorial decision for report inclusion and
// NEVER mutates or overrides the technical VerificationStatus.
type ReviewStatus string

const (
	ReviewStatusPending  ReviewStatus = "PENDING"
	ReviewStatusApproved ReviewStatus = "APPROVED_FOR_REPORT"
	ReviewStatusRejected ReviewStatus = "REJECTED"
)

// IsValid checks if a review status is recognized.
func (r ReviewStatus) IsValid() bool {
	switch r {
	case ReviewStatusPending, ReviewStatusApproved, ReviewStatusRejected:
		return true
	default:
		return false
	}
}

// FindingReview encapsulates the operator's review record for a single finding.
type FindingReview struct {
	ID           string       `json:"id"`
	AssessmentID string       `json:"assessment_id"`
	FindingID    string       `json:"finding_id"` // Matches AssessmentFinding.OriginalFindingID or ID
	ReviewStatus ReviewStatus `json:"review_status"`
	ReviewedBy   string       `json:"reviewed_by"`
	ReviewedAt   time.Time    `json:"reviewed_at"`
	Notes        string       `json:"notes,omitempty"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
}

// DeliveryStatus represents the lifecycle of report delivery to the client.
type DeliveryStatus string

const (
	DeliveryStatusGenerated  DeliveryStatus = "GENERATED"
	DeliveryStatusPrepared   DeliveryStatus = "PREPARED_FOR_DELIVERY"
	DeliveryStatusDispatched DeliveryStatus = "DISPATCHED"
	DeliveryStatusConfirmed  DeliveryStatus = "DELIVERY_CONFIRMED"
	DeliveryStatusCancelled  DeliveryStatus = "CANCELLED"
)

// IsValid checks if a delivery status is recognized.
func (d DeliveryStatus) IsValid() bool {
	switch d {
	case DeliveryStatusGenerated, DeliveryStatusPrepared, DeliveryStatusDispatched,
		DeliveryStatusConfirmed, DeliveryStatusCancelled:
		return true
	default:
		return false
	}
}

// DeliveryMethod specifies the transmission medium for report delivery.
type DeliveryMethod string

const (
	DeliveryMethodSecureDownload DeliveryMethod = "SECURE_DOWNLOAD"
	DeliveryMethodEmail          DeliveryMethod = "ENCRYPTED_EMAIL"
	DeliveryMethodPortal         DeliveryMethod = "CLIENT_PORTAL"
	DeliveryMethodInPerson       DeliveryMethod = "IN_PERSON"
)

// ReportDelivery models the formal handover and tracking of an assessment report.
type ReportDelivery struct {
	ID                string         `json:"id"`
	AssessmentID      string         `json:"assessment_id"`
	ReportID          string         `json:"report_id"`
	DeliveryStatus    DeliveryStatus `json:"delivery_status"`
	RecipientName     string         `json:"recipient_name"`
	RecipientEmail    string         `json:"recipient_email"`
	DeliveryMethod    DeliveryMethod `json:"delivery_method"`
	TrackingReference string         `json:"tracking_reference,omitempty"`
	Notes             string         `json:"notes,omitempty"`
	DispatchedAt      *time.Time     `json:"dispatched_at,omitempty"`
	DeliveredAt       *time.Time     `json:"delivered_at,omitempty"`
	OperatorID        string         `json:"operator_id"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// Validate ensures delivery state invariants are strictly preserved.
func (d *ReportDelivery) Validate() error {
	if d.AssessmentID == "" {
		return fmt.Errorf("assessment_id is required")
	}
	if d.ReportID == "" {
		return fmt.Errorf("report_id is required")
	}
	if !d.DeliveryStatus.IsValid() {
		return fmt.Errorf("invalid delivery status: %s", d.DeliveryStatus)
	}
	if d.RecipientName == "" {
		return fmt.Errorf("recipient_name is required")
	}
	if d.OperatorID == "" {
		return fmt.Errorf("operator_id is required")
	}
	// Invariant: DeliveryConfirmed MUST have delivered_at timestamp
	if d.DeliveryStatus == DeliveryStatusConfirmed && d.DeliveredAt == nil {
		return fmt.Errorf("delivery confirmed status requires confirmed delivered_at timestamp")
	}
	// Invariant: Dispatched MUST have dispatched_at timestamp
	if d.DeliveryStatus == DeliveryStatusDispatched && d.DispatchedAt == nil {
		return fmt.Errorf("dispatched status requires dispatched_at timestamp")
	}
	return nil
}

// AuditEvent represents an immutable record of an operator or system action.
type AuditEvent struct {
	ID           string    `json:"id"`
	AssessmentID string    `json:"assessment_id,omitempty"` // Nullable: system-level or client-level actions
	OperatorID   string    `json:"operator_id"`
	ActionType   string    `json:"action_type"`
	EntityType   string    `json:"entity_type"`
	EntityID     string    `json:"entity_id"`
	DetailsJSON  string    `json:"details_json,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// ScanJobLease coordinates execution leases to prevent concurrent scans
// on the same assessment across processes or restarts.
type ScanJobLease struct {
	ID              string    `json:"id"` // AssessmentID (1:1 lock)
	ExecutionID     string    `json:"execution_id"`
	OperatorID      string    `json:"operator_id"`
	AcquiredAt      time.Time `json:"acquired_at"`
	HeartbeatAt     time.Time `json:"heartbeat_at"`
	Status          string    `json:"status"` // QUEUED, RUNNING, COMPLETED, FAILED, CANCELLED
	ErrorMessage    string    `json:"error_message,omitempty"`
	ProgressMessage string    `json:"progress_message,omitempty"`
}
