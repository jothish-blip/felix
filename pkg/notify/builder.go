package notify

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"felix/pkg/report"
	"felix/pkg/secrets"
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

// BuildReportNotification creates an accurate, evidence-backed notification directly from a canonical Report.
func BuildReportNotification(
	rep report.Report, assessmentRef, executionID string, now time.Time,
) *Notification {
	ref := strings.TrimSpace(assessmentRef)
	if ref == "" {
		ref = rep.ReportID()
		if ref == "" {
			ref = secrets.SanitizeURL(rep.Target)
		}
	}
	execID := strings.TrimSpace(executionID)
	if execID == "" {
		execID = fmt.Sprintf("exec_%d", now.UnixNano())
	}

	status := rep.CompletionStatus
	if status == "" {
		status = "COMPLETED"
	}

	sanitizedTarget := secrets.SanitizeURL(rep.Target)
	findingCount := len(rep.Findings)

	var (
		eventType string
		severity  string
		title     string
		msg       string
	)

	switch status {
	case "FAILED":
		eventType = EventAssessmentFailed
		severity = SeverityHigh
		title = fmt.Sprintf("Assessment %s Failed", ref)
		msg = fmt.Sprintf("Assessment against %s failed due to connectivity or execution errors. Target security posture could not be evaluated.", sanitizedTarget)

	case "BLOCKED":
		eventType = EventAssessmentBlocked
		severity = SeverityHigh
		title = fmt.Sprintf("Assessment %s Blocked", ref)
		msg = fmt.Sprintf("Assessment against %s was halted because the target presented access barriers (HTTP 403 Forbidden). Security posture could not be evaluated.", sanitizedTarget)

	case "PARTIAL", "INCOMPLETE":
		eventType = EventAssessmentPartial
		severity = SeverityMedium
		title = fmt.Sprintf("Assessment %s Partial / Incomplete", ref)
		msg = fmt.Sprintf("Assessment against %s completed with partial coverage (%d findings). Some checks or targets were interrupted.", sanitizedTarget, findingCount)

	case "CANCELLED":
		eventType = EventAssessmentCancelled
		severity = SeverityInfo
		title = fmt.Sprintf("Assessment %s Cancelled", ref)
		msg = fmt.Sprintf("Assessment against %s was cancelled by operator.", sanitizedTarget)

	default: // COMPLETED
		if rep.Summary.CriticalCount > 0 {
			eventType = EventAssessmentCompletedWithErrors
			severity = SeverityCritical
		} else if rep.Summary.HighCount > 0 {
			eventType = EventAssessmentCompletedWithErrors
			severity = SeverityHigh
		} else if rep.Summary.MediumCount > 0 {
			eventType = EventAssessmentCompleted
			severity = SeverityMedium
		} else if rep.Summary.LowCount > 0 {
			eventType = EventAssessmentCompleted
			severity = SeverityLow
		} else {
			eventType = EventAssessmentCompleted
			severity = SeverityInfo
		}

		if findingCount == 0 {
			title = fmt.Sprintf("Assessment %s Completed (0 Findings)", ref)
			msg = fmt.Sprintf("Assessment against %s completed successfully with 0 findings in %s. Note: Zero findings does not guarantee that the target is completely secure; automated defensive audits do not evaluate unassessed or offline components.", sanitizedTarget, rep.Duration)
		} else {
			title = fmt.Sprintf("Assessment %s Completed (%d Findings)", ref, findingCount)
			msg = fmt.Sprintf("Assessment against %s completed in %s with %d security finding(s) (Critical: %d, High: %d, Medium: %d, Low: %d, Info: %d). Overall risk score: %d/100 (%s).",
				sanitizedTarget, rep.Duration, findingCount,
				rep.Summary.CriticalCount, rep.Summary.HighCount, rep.Summary.MediumCount, rep.Summary.LowCount, rep.Summary.InfoCount,
				rep.RiskScore, rep.RiskLevel)
		}
	}

	// Extract finding IDs (up to 25)
	var findingIDs []string
	var topFindings []map[string]interface{}
	verifiedCount := 0
	unverifiedCount := 0

	for i, f := range rep.Findings {
		if i < 25 && f.ID != "" {
			findingIDs = append(findingIDs, f.ID)
		}
		if f.Verification.Status == report.VerificationVerified {
			verifiedCount++
		} else {
			unverifiedCount++
		}
		if len(topFindings) < 5 && (f.Severity == report.SeverityCritical || f.Severity == report.SeverityHigh || f.Severity == report.SeverityMedium) {
			topFindings = append(topFindings, map[string]interface{}{
				"id":       f.ID,
				"title":    secrets.RedactText(f.Title),
				"severity": f.Severity,
				"endpoint": secrets.SanitizeURL(f.Endpoint),
				"status":   string(f.Status),
			})
		}
	}

	dedupKey := ComputeDedupKey("report", execID, eventType, sanitizedTarget)
	id := FormatNotificationID("default", dedupKey, now)

	payloadMeta := map[string]interface{}{
		"target":            sanitizedTarget,
		"completion_status": status,
		"duration":          rep.Duration,
		"finding_count":     findingCount,
		"verified_count":    verifiedCount,
		"unverified_count":  unverifiedCount,
		"risk_score":        rep.RiskScore,
		"risk_level":        rep.RiskLevel,
		"severity_counts": map[string]int{
			"CRITICAL": rep.Summary.CriticalCount,
			"HIGH":     rep.Summary.HighCount,
			"MEDIUM":   rep.Summary.MediumCount,
			"LOW":      rep.Summary.LowCount,
			"INFO":     rep.Summary.InfoCount,
		},
		"top_findings": topFindings,
		"report_id":    rep.ReportID(),
	}
	if rep.Metadata != nil {
		if lims, ok := rep.Metadata["limitations"].([]string); ok && len(lims) > 0 {
			payloadMeta["limitations"] = lims
		}
	}
	if mobLims := rep.MobileLimitations(); len(mobLims) > 0 {
		payloadMeta["limitations"] = mobLims
	}

	payloadBytes, _ := json.Marshal(payloadMeta)

	return &Notification{
		ID:             id,
		TenantID:       "default",
		ExecutionID:    execID,
		EventType:      eventType,
		Severity:       severity,
		Title:          title,
		Message:        msg,
		FindingIDs:     findingIDs,
		DedupKey:       dedupKey,
		DeliveryStatus: DeliveryStatusPending,
		MaxAttempts:    3,
		PayloadJSON:    string(payloadBytes),
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
}

// BuildCriticalFindingNotification creates an immediate high-priority alert for a critical vulnerability finding.
func BuildCriticalFindingNotification(
	tenantID, accountID, assessmentID, assessmentRef, executionID string,
	f report.Finding, now time.Time,
) *Notification {
	eventType := EventSecurityFindingCritical
	severity := SeverityCritical
	title := fmt.Sprintf("[CRITICAL] %s: %s", f.RuleID, secrets.RedactText(f.Title))
	msg := fmt.Sprintf("Critical security vulnerability detected at %s: %s",
		secrets.SanitizeURL(f.Endpoint), secrets.RedactText(f.Description))

	dedupKey := ComputeDedupKey("finding.critical", executionID, eventType, f.Fingerprint)
	id := FormatNotificationID(tenantID, dedupKey, now)

	payloadMeta := map[string]interface{}{
		"finding_id":   f.ID,
		"rule_id":      f.RuleID,
		"title":        secrets.RedactText(f.Title),
		"severity":     f.Severity,
		"endpoint":     secrets.SanitizeURL(f.Endpoint),
		"confidence":   f.Confidence,
		"verification": f.Verification.Status,
		"remediation":  secrets.RedactText(f.Remediation),
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
		FindingIDs:     []string{f.ID},
		DedupKey:       dedupKey,
		DeliveryStatus: DeliveryStatusPending,
		MaxAttempts:    3,
		PayloadJSON:    string(payloadBytes),
		CreatedAt:      now.UTC(),
		UpdatedAt:      now.UTC(),
	}
}
