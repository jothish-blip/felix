package notify

import (
	"encoding/json"
	"fmt"
	"time"

	"felix/pkg/report"
)

// BuildLifecycleNotification creates a persistent notification for assessment execution terminal states.
func BuildLifecycleNotification(
	tenantID, accountID, assessmentID, assessmentRef, executionID string,
	status string, findingCount int, duration time.Duration, errMsg string, now time.Time,
) *Notification {
	eventType := EventAssessmentCompleted
	severity := SeverityInfo
	title := fmt.Sprintf("Assessment %s Completed", assessmentRef)
	msg := fmt.Sprintf("Assessment %s execution %s completed successfully in %s with %d security findings.",
		assessmentRef, executionID, duration.Round(time.Millisecond), findingCount)

	switch status {
	case "COMPLETED_WITH_ERRORS":
		eventType = EventAssessmentCompletedWithErrors
		severity = SeverityMedium
		title = fmt.Sprintf("Assessment %s Completed With Errors", assessmentRef)
		msg = fmt.Sprintf("Assessment %s execution %s completed with warnings/errors in %s (%d findings): %s",
			assessmentRef, executionID, duration.Round(time.Millisecond), findingCount, errMsg)
	case "FAILED":
		eventType = EventAssessmentFailed
		severity = SeverityHigh
		title = fmt.Sprintf("Assessment %s Failed", assessmentRef)
		msg = fmt.Sprintf("Assessment %s execution %s failed after %s: %s",
			assessmentRef, executionID, duration.Round(time.Millisecond), errMsg)
	case "CANCELLED":
		eventType = EventAssessmentCancelled
		severity = SeverityInfo
		title = fmt.Sprintf("Assessment %s Cancelled", assessmentRef)
		msg = fmt.Sprintf("Assessment %s execution %s was cancelled by operator.", assessmentRef, executionID)
	case "INTERRUPTED":
		eventType = EventAssessmentInterrupted
		severity = SeverityHigh
		title = fmt.Sprintf("Assessment %s Interrupted", assessmentRef)
		msg = fmt.Sprintf("Assessment %s execution %s was interrupted or abandoned and finalized by recovery: %s",
			assessmentRef, executionID, errMsg)
	}

	dedupKey := ComputeDedupKey("lifecycle", executionID, eventType, "")
	id := FormatNotificationID(tenantID, dedupKey, now)

	payloadMeta := map[string]interface{}{
		"assessment_ref": assessmentRef,
		"status":         status,
		"duration_ms":    duration.Milliseconds(),
		"finding_count":  findingCount,
		"error_message":  errMsg,
	}
	payloadBytes, _ := json.Marshal(payloadMeta)

	return &Notification{
		ID:             id,
		TenantID:       tenantID,
		AccountID:      accountID,
		AssessmentID:   assessmentID,
		ExecutionID:    executionID,
		EventType:      eventType,
		Severity:       severity,
		Title:          title,
		Message:        msg,
		DedupKey:       dedupKey,
		DeliveryStatus: DeliveryStatusPending,
		MaxAttempts:    3,
		PayloadJSON:    string(payloadBytes),
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
}

// BuildDeltaNotification creates a notification for a security finding delta (NEW, REGRESSED, CHANGED, RESOLVED).
func BuildDeltaNotification(
	tenantID, accountID, assessmentID, assessmentRef, executionID, baselineExecID string,
	classification string, item report.ChangeFindingItem, now time.Time,
) *Notification {
	eventType := EventSecurityFindingNew
	severity := item.Severity
	if severity == "" {
		severity = SeverityMedium
	}

	title := fmt.Sprintf("[%s] %s: %s", classification, item.Severity, item.Title)
	msg := item.Reason

	switch classification {
	case "REGRESSED":
		eventType = EventSecurityFindingRegressed
		title = fmt.Sprintf("[REGRESSION] %s: %s", item.Severity, item.Title)
	case "CHANGED":
		eventType = EventSecurityFindingChanged
		title = fmt.Sprintf("[CHANGED] %s: %s", item.Severity, item.Title)
	case "RESOLVED":
		eventType = EventSecurityFindingResolved
		title = fmt.Sprintf("[RESOLVED] %s: %s", item.Severity, item.Title)
		// Resolutions are positive operational improvements; default severity Info unless overridden
		severity = SeverityInfo
	case "PERSISTENT":
		eventType = EventSecurityFindingPersistent
		title = fmt.Sprintf("[PERSISTENT] %s: %s", item.Severity, item.Title)
	}

	findingIDs := []string{}
	if item.FindingID != "" {
		findingIDs = append(findingIDs, item.FindingID)
	}

	dedupKey := ComputeDedupKey("delta", executionID, eventType, item.Fingerprint)
	id := FormatNotificationID(tenantID, dedupKey, now)

	payloadMeta := map[string]interface{}{
		"assessment_ref":  assessmentRef,
		"finding_id":      item.FindingID,
		"fingerprint":     item.Fingerprint,
		"classification":  classification,
		"severity":        item.Severity,
		"category":        item.Category,
		"target_url":      item.TargetURL,
		"endpoint":        item.Endpoint,
		"http_method":     item.HTTPMethod,
		"severity_change": item.SeverityChange,
		"explanation":     item.Explanation,
	}
	payloadBytes, _ := json.Marshal(payloadMeta)

	return &Notification{
		ID:                  id,
		TenantID:            tenantID,
		AccountID:           accountID,
		AssessmentID:        assessmentID,
		ExecutionID:         executionID,
		BaselineExecutionID: baselineExecID,
		EventType:           eventType,
		Severity:            severity,
		Title:               title,
		Message:             msg,
		FindingIDs:          findingIDs,
		Classification:      classification,
		DedupKey:            dedupKey,
		DeliveryStatus:      DeliveryStatusPending,
		MaxAttempts:         3,
		PayloadJSON:         string(payloadBytes),
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
	}
}

// BuildIncompleteSummaryNotification creates a notification when an assessment cannot reliably verify resolutions.
func BuildIncompleteSummaryNotification(
	tenantID, accountID, assessmentID, assessmentRef, executionID, baselineExecID string,
	reason string, unverifiedCount int, now time.Time,
) *Notification {
	eventType := EventSecuritySummaryIncomplete
	severity := SeverityMedium
	title := fmt.Sprintf("Assessment %s Comparison Incomplete", assessmentRef)
	msg := fmt.Sprintf("Assessment %s comparison with baseline %s is inconclusive: %d finding(s) cannot be confirmed resolved due to incomplete coverage: %s",
		assessmentRef, baselineExecID, unverifiedCount, reason)

	dedupKey := ComputeDedupKey("summary", executionID, eventType, "")
	id := FormatNotificationID(tenantID, dedupKey, now)

	payloadMeta := map[string]interface{}{
		"assessment_ref":   assessmentRef,
		"unverified_count": unverifiedCount,
		"reason":           reason,
	}
	payloadBytes, _ := json.Marshal(payloadMeta)

	return &Notification{
		ID:                  id,
		TenantID:            tenantID,
		AccountID:           accountID,
		AssessmentID:        assessmentID,
		ExecutionID:         executionID,
		BaselineExecutionID: baselineExecID,
		EventType:           eventType,
		Severity:            severity,
		Title:               title,
		Message:             msg,
		DedupKey:            dedupKey,
		DeliveryStatus:      DeliveryStatusPending,
		MaxAttempts:         3,
		PayloadJSON:         string(payloadBytes),
		CreatedAt:           now.UTC(),
		UpdatedAt:           now.UTC(),
	}
}

// BuildTestNotification creates an explicit on-demand test notification.
func BuildTestNotification(tenantID, destinationURL string, now time.Time) *Notification {
	dedupKey := ComputeDedupKey("test", tenantID, fmt.Sprintf("%d", now.UnixNano()), "")
	id := FormatNotificationID(tenantID, dedupKey, now)

	payloadMeta := map[string]interface{}{
		"test_ping":       true,
		"destination_url": destinationURL,
	}
	payloadBytes, _ := json.Marshal(payloadMeta)

	return &Notification{
		ID:             id,
		TenantID:       tenantID,
		EventType:      EventNotificationTest,
		Severity:       SeverityInfo,
		Title:          "Felix Notification Channel Verification",
		Message:        "This is an automated test ping verifying outbound webhook delivery, TLS handshake, and HMAC signature integrity.",
		DedupKey:       dedupKey,
		DeliveryStatus: DeliveryStatusPending,
		MaxAttempts:    1, // Test ping does not retry repeatedly
		PayloadJSON:    string(payloadBytes),
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
}
