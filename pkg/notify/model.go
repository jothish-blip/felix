package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"felix/pkg/secrets"
)

// Event types supported by Felix notification subsystem.
const (
	// Assessment lifecycle events
	EventAssessmentCompleted           = "assessment.completed"
	EventAssessmentCompletedWithErrors = "assessment.completed_with_errors"
	EventAssessmentPartial             = "assessment.partial"
	EventAssessmentBlocked             = "assessment.blocked"
	EventAssessmentFailed              = "assessment.failed"
	EventAssessmentCancelled           = "assessment.cancelled"
	EventAssessmentInterrupted         = "assessment.interrupted"
	EventAssessmentRecoveryFailed      = "assessment.recovery_failed"

	// Security change / delta events
	EventSecurityFindingNew        = "security.finding.new"
	EventSecurityFindingCritical   = "security.finding.critical"
	EventSecurityFindingRegressed  = "security.finding.regressed"
	EventSecurityFindingChanged    = "security.finding.changed"
	EventSecurityFindingResolved   = "security.finding.resolved"
	EventSecurityFindingPersistent = "security.finding.persistent"
	EventSecuritySummaryIncomplete = "security.summary.incomplete"

	// Operational events
	EventNotificationDeliveryFailed = "notification.delivery_failed"
	EventSchedulerRecoveryFailed    = "scheduler.recovery_failed"

	// Explicit on-demand test ping
	EventNotificationTest = "notification.test"
)

// Delivery statuses
const (
	DeliveryStatusPending   = "PENDING"
	DeliveryStatusDelivered = "DELIVERED"
	DeliveryStatusFailed    = "FAILED"
	DeliveryStatusRetrying  = "RETRYING"
)

// Severity levels
const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

// SeverityRank maps severity string to numeric weight (CRITICAL highest).
func SeverityRank(sev string) int {
	switch strings.ToUpper(strings.TrimSpace(sev)) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// MeetsSeverityThreshold returns true if eventSeverity meets or exceeds minSeverity.
func MeetsSeverityThreshold(eventSeverity, minSeverity string) bool {
	if minSeverity == "" {
		return true
	}
	return SeverityRank(eventSeverity) >= SeverityRank(minSeverity)
}

// Notification represents a durable notification record in the outbox.
type Notification struct {
	ID                  string     `json:"id"`
	TenantID            string     `json:"tenant_id"`
	AccountID           string     `json:"account_id,omitempty"`
	AssessmentID        string     `json:"assessment_id,omitempty"`
	ExecutionID         string     `json:"execution_id,omitempty"`
	BaselineExecutionID string     `json:"baseline_execution_id,omitempty"`
	EventType           string     `json:"event_type"`
	Severity            string     `json:"severity"`
	Title               string     `json:"title"`
	Message             string     `json:"message"`
	FindingIDs          []string   `json:"finding_ids,omitempty"`
	Classification      string     `json:"classification,omitempty"`
	DedupKey            string     `json:"dedup_key"`
	DeliveryStatus      string     `json:"delivery_status"`
	AttemptCount        int        `json:"attempt_count"`
	MaxAttempts         int        `json:"max_attempts"`
	NextRetryAt         *time.Time `json:"next_retry_at,omitempty"`
	LastError           string     `json:"last_error,omitempty"`
	LeasedBy            string     `json:"leased_by,omitempty"`
	LeaseExpiresAt      *time.Time `json:"lease_expires_at,omitempty"`
	PayloadJSON         string     `json:"payload_json,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// FindingIDsJSON returns FindingIDs serialized as JSON string.
func (n *Notification) FindingIDsJSON() string {
	if len(n.FindingIDs) == 0 {
		return "[]"
	}
	b, err := json.Marshal(n.FindingIDs)
	if err != nil {
		return "[]"
	}
	return string(b)
}

// SetFindingIDsFromJSON deserializes JSON string into FindingIDs slice.
func (n *Notification) SetFindingIDsFromJSON(raw string) {
	if strings.TrimSpace(raw) == "" || raw == "[]" {
		n.FindingIDs = nil
		return
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw), &ids); err == nil {
		n.FindingIDs = ids
	}
}

// WebhookPayload represents the structured JSON payload sent to external notification webhooks.
// Sensitive data (e.g. passwords, bearer tokens, full HTTP headers) is strictly excluded.
type WebhookPayload struct {
	NotificationID      string                 `json:"notification_id"`
	EventType           string                 `json:"event_type"`
	Severity            string                 `json:"severity"`
	Title               string                 `json:"title"`
	Message             string                 `json:"message"`
	TenantID            string                 `json:"tenant_id,omitempty"`
	AssessmentID        string                 `json:"assessment_id,omitempty"`
	ExecutionID         string                 `json:"execution_id,omitempty"`
	BaselineExecutionID string                 `json:"baseline_execution_id,omitempty"`
	Classification      string                 `json:"classification,omitempty"`
	FindingCount        int                    `json:"finding_count,omitempty"`
	FindingIDs          []string               `json:"finding_ids,omitempty"`
	Timestamp           string                 `json:"timestamp"`
	Metadata            map[string]interface{} `json:"metadata,omitempty"`
}

// ToWebhookPayload converts a Notification to a safe WebhookPayload with secrets redacted.
func (n *Notification) ToWebhookPayload() WebhookPayload {
	meta := make(map[string]interface{})
	if strings.TrimSpace(n.PayloadJSON) != "" && n.PayloadJSON != "{}" {
		_ = json.Unmarshal([]byte(n.PayloadJSON), &meta)
	}

	return WebhookPayload{
		NotificationID:      n.ID,
		EventType:           n.EventType,
		Severity:            n.Severity,
		Title:               secrets.RedactText(n.Title),
		Message:             secrets.RedactText(n.Message),
		TenantID:            n.TenantID,
		AssessmentID:        n.AssessmentID,
		ExecutionID:         n.ExecutionID,
		BaselineExecutionID: n.BaselineExecutionID,
		Classification:      n.Classification,
		FindingCount:        len(n.FindingIDs),
		FindingIDs:          n.FindingIDs,
		Timestamp:           n.CreatedAt.UTC().Format(time.RFC3339),
		Metadata:            meta,
	}
}

// NotificationFilter specifies criteria for listing notifications.
type NotificationFilter struct {
	TenantID       string
	AccountID      string
	AssessmentID   string
	ExecutionID    string
	EventType      string
	DeliveryStatus string
	Limit          int
	Offset         int
}

// SubsystemStats aggregates delivery statistics for health checks and status views.
type SubsystemStats struct {
	TotalNotifications int       `json:"total_notifications"`
	PendingCount       int       `json:"pending_count"`
	DeliveredCount     int       `json:"delivered_count"`
	FailedCount        int       `json:"failed_count"`
	RetryingCount      int       `json:"retrying_count"`
	OldestPendingAt    *time.Time `json:"oldest_pending_at,omitempty"`
	LastDeliveredAt    *time.Time `json:"last_delivered_at,omitempty"`
	LastFailedAt       *time.Time `json:"last_failed_at,omitempty"`
	SubsystemHealthy   bool      `json:"subsystem_healthy"`
}

// ComputeDedupKey generates a deterministic deduplication key for a logical notification event.
func ComputeDedupKey(prefix, scope, eventType, identifier string) string {
	parts := []string{prefix}
	if scope != "" {
		parts = append(parts, scope)
	}
	if eventType != "" {
		parts = append(parts, eventType)
	}
	if identifier != "" {
		parts = append(parts, identifier)
	}
	return strings.Join(parts, ":")
}

// FormatNotificationID generates a unique notification ID.
func FormatNotificationID(tenantID, dedupKey string, timestamp time.Time) string {
	cleanKey := strings.ReplaceAll(dedupKey, " ", "_")
	if len(cleanKey) > 48 {
		cleanKey = cleanKey[:48]
	}
	cleanTenant := strings.ReplaceAll(tenantID, " ", "_")
	if len(cleanTenant) > 24 {
		cleanTenant = cleanTenant[:24]
	}
	if cleanTenant == "" {
		cleanTenant = "default"
	}
	return fmt.Sprintf("ntf_%s_%d_%s", cleanTenant, timestamp.UnixNano(), cleanKey)
}
