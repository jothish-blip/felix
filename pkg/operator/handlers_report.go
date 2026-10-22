package operator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"felix/pkg/assessment"
	"felix/pkg/report"
	"github.com/google/uuid"
)

type generateReportRequest struct {
	AllowDraft  bool   `json:"allow_draft"`
	ExecutionID string `json:"execution_id,omitempty"`
}

type recordDeliveryRequest struct {
	RecipientName  string `json:"recipient_name"`
	RecipientEmail string `json:"recipient_email,omitempty"`
	DeliveryMethod string `json:"delivery_method"` // ENCRYPTED_EMAIL, SECURE_DOWNLOAD, CLIENT_PORTAL, IN_PERSON
	Notes          string `json:"notes,omitempty"`
	Confirmed      bool   `json:"confirmed"` // If true, sets status to DELIVERY_CONFIRMED
}

func (s *Server) handleGenerateReport(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireRole(w, r, RoleAdmin, RoleOperator)
	if !ok {
		return
	}

	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	var req generateReportRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	opts := assessment.CuratedReportOptions{
		AllowDraft:   req.AllowDraft,
		ExecutionID:  req.ExecutionID,
		FelixVersion: s.cfg.Version,
	}

	opID := s.cfg.OperatorID
	if sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	res, err := assessment.GenerateCuratedCommercialReport(s.store, asm.ID, opID, opts)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "report generation blocked") {
			s.respondError(w, http.StatusBadRequest, errMsg)
			return
		}
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate commercial report: %v", err))
		return
	}

	// Security Invariant: Internal filesystem paths (e.g. res.HTMLPath, res.JSONPath) are redacted
	// from responses to prevent local path disclosure. Relative safe API download URLs are returned instead.
	s.respondJSON(w, http.StatusCreated, map[string]any{
		"assessment_id":    asm.ID,
		"report_record_id": res.ReportRecordID,
		"is_draft":         res.IsDraft,
		"html_url":         fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html", asm.ID, res.ReportRecordID),
		"json_url":         fmt.Sprintf("/api/v1/assessments/%s/reports/%s/json", asm.ID, res.ReportRecordID),
		"summary": map[string]int{
			"total_findings":    res.TotalFindings,
			"approved_findings": res.ApprovedCount,
			"rejected_findings": res.RejectedCount,
			"pending_findings":  res.PendingCount,
		},
		"risk_overview": res.CommercialReport.RiskOverview,
		"message":       "commercial report successfully compiled",
	})
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	reports, err := s.store.GetReports(asm.ID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to fetch reports: %v", err))
		return
	}
	if reports == nil {
		reports = []assessment.ReportRecord{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"reports": reports,
		"count":   len(reports),
	})
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil || rep.AssessmentID != asm.ID {
		s.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	s.respondJSON(w, http.StatusOK, rep)
}

func (s *Server) handleDownloadReportHTML(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil || rep.AssessmentID != asm.ID {
		s.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	// If request authenticated via DownloadToken, verify token scope matches this assessment, report, format, and client
	if dt := DownloadTokenFromContext(r.Context()); dt != nil {
		if !dt.Authorizes(asm.ID, rep.ID, "HTML", asm.ClientID) {
			s.respondError(w, http.StatusForbidden, "forbidden: download token not scoped to this report")
			return
		}
	}

	// Security Invariant: Verify filesystem containment to prevent arbitrary file disclosure or traversal escapes
	containedPath, err := s.validateReportPathContainment(rep.FilePath)
	if err != nil {
		s.respondError(w, http.StatusForbidden, "forbidden: report path is outside allowed storage directory")
		return
	}

	content, err := os.ReadFile(containedPath)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "report file could not be read")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleDownloadReportJSON(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil || rep.AssessmentID != asm.ID {
		s.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	// If request authenticated via DownloadToken, verify token scope matches this assessment, report, format, and client
	if dt := DownloadTokenFromContext(r.Context()); dt != nil {
		if !dt.Authorizes(asm.ID, rep.ID, "JSON", asm.ClientID) {
			s.respondError(w, http.StatusForbidden, "forbidden: download token not scoped to this report")
			return
		}
	}

	// Security Invariant: Verify filesystem containment to prevent arbitrary file disclosure or traversal escapes
	containedPath, err := s.validateReportPathContainment(rep.FilePath)
	if err != nil {
		s.respondError(w, http.StatusForbidden, "forbidden: report path is outside allowed storage directory")
		return
	}

	content, err := os.ReadFile(containedPath)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "report file could not be read")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, private")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleIssueDownloadToken(w http.ResponseWriter, r *http.Request) {
	// Any authenticated role (admin, operator, viewer) with assessment access can generate a download token
	_, ok := s.requireRole(w, r, RoleAdmin, RoleOperator, RoleViewer)
	if !ok {
		return
	}

	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil || rep.AssessmentID != asm.ID {
		s.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = rep.Format
	}

	dt, err := s.IssueDownloadToken(asm.ID, rep.ID, format, asm.ClientID, 5*time.Minute)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to issue download token: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"download_token":     dt.Token,
		"expires_at":         dt.ExpiresAt.Format(time.RFC3339),
		"expires_in_seconds": 300,
		"format":             dt.Format,
		"html_url":           fmt.Sprintf("/api/v1/assessments/%s/reports/%s/html?download_token=%s", asm.ID, rep.ID, dt.Token),
		"json_url":           fmt.Sprintf("/api/v1/assessments/%s/reports/%s/json?download_token=%s", asm.ID, rep.ID, dt.Token),
	})
}

func (s *Server) handleCreateDelivery(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireRole(w, r, RoleAdmin, RoleOperator)
	if !ok {
		return
	}

	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil || rep.AssessmentID != asm.ID {
		s.respondError(w, http.StatusNotFound, "report not found")
		return
	}

	var req recordDeliveryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	recipient := strings.TrimSpace(req.RecipientName)
	if recipient == "" {
		s.respondError(w, http.StatusBadRequest, "recipient_name is required")
		return
	}

	method := assessment.DeliveryMethod(strings.ToUpper(strings.TrimSpace(req.DeliveryMethod)))
	if method == "" {
		method = assessment.DeliveryMethodEmail
	}

	now := time.Now().UTC()
	status := assessment.DeliveryStatusDispatched
	var dispatchedAt, deliveredAt *time.Time
	dispatchedAt = &now

	if req.Confirmed {
		status = assessment.DeliveryStatusConfirmed
		deliveredAt = &now
	}

	opID := s.cfg.OperatorID
	if sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	delivery := &assessment.ReportDelivery{
		ID:             uuid.New().String(),
		AssessmentID:   asm.ID,
		ReportID:       reportID,
		DeliveryStatus: status,
		RecipientName:  recipient,
		RecipientEmail: strings.TrimSpace(req.RecipientEmail),
		DeliveryMethod: method,
		Notes:          strings.TrimSpace(req.Notes),
		DispatchedAt:   dispatchedAt,
		DeliveredAt:    deliveredAt,
		OperatorID:     opID,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := delivery.Validate(); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("delivery validation failed: %v", err))
		return
	}

	if err := s.store.CreateReportDelivery(delivery); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save delivery record: %v", err))
		return
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   opID,
		ActionType:   "REPORT_DELIVERED",
		EntityType:   "DELIVERY",
		EntityID:     delivery.ID,
		DetailsJSON: fmt.Sprintf(
			`{"report_id":%q,"recipient":%q,"method":%q,"status":%q}`,
			reportID, delivery.RecipientName, delivery.DeliveryMethod, delivery.DeliveryStatus,
		),
	})

	s.respondJSON(w, http.StatusCreated, delivery)
}

func (s *Server) handleListDeliveries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	deliveries, err := s.store.ListReportDeliveries(asm.ID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to fetch deliveries: %v", err))
		return
	}
	if deliveries == nil {
		deliveries = []assessment.ReportDelivery{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"deliveries": deliveries,
		"count":      len(deliveries),
	})
}

func (s *Server) handleReconcileAssessmentReport(w http.ResponseWriter, r *http.Request) {
	_, ok := s.requireRole(w, r, RoleAdmin, RoleOperator, RoleViewer)
	if !ok {
		return
	}

	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	authCtx := s.getAuthContext(r)
	snap, err := assessment.LoadAuthoritativeSnapshot(s.store, asm.ID, "", authCtx)
	if err != nil {
		if errors.Is(err, assessment.ErrSnapshotUnauthorized) {
			s.respondError(w, http.StatusNotFound, "assessment not found")
			return
		}
		if errors.Is(err, assessment.ErrUnexecutedAssessment) {
			s.respondError(w, http.StatusConflict, err.Error())
			return
		}
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("failed to load authoritative snapshot: %v", err))
		return
	}

	reports, err := s.store.GetReports(asm.ID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list reports: %v", err))
		return
	}

	if len(reports) == 0 {
		s.respondJSON(w, http.StatusOK, map[string]any{
			"is_valid":                true,
			"assessment_id":           asm.ID,
			"persisted_status":        snap.Status,
			"total_persisted_count":   snap.TotalPersistedCount,
			"unique_persisted_count":  snap.UniqueFindingsCount,
			"approved_findings_count": snap.ReviewCounts["APPROVED"],
			"message":                 "no report records generated yet; persisted facts ready",
		})
		return
	}

	// Pick latest JSON report if available, else latest report
	var targetRep *assessment.ReportRecord
	for i := len(reports) - 1; i >= 0; i-- {
		if strings.EqualFold(reports[i].Format, "JSON") {
			targetRep = &reports[i]
			break
		}
	}
	if targetRep == nil {
		targetRep = &reports[len(reports)-1]
	}

	// Read report from disk and parse
	containedPath, err := s.validateReportPathContainment(targetRep.FilePath)
	if err != nil {
		s.respondError(w, http.StatusForbidden, "forbidden: report path containment failed")
		return
	}

	content, err := os.ReadFile(containedPath)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to read report file")
		return
	}

	// Try parsing as CommercialReport first (since handleGenerateReport writes Commercial JSON)
	var cr report.CommercialReport
	if err := json.Unmarshal(content, &cr); err == nil && (len(cr.VerifiedFindings) > 0 || len(cr.DetectedFindings) > 0 || cr.SchemaVersion != "") {
		var findings []report.Finding
		for _, vf := range cr.VerifiedFindings {
			findings = append(findings, report.Finding{
				ID:       vf.ID,
				Title:    vf.Title,
				Severity: vf.Severity,
				Category: vf.Category,
				Target:   vf.AffectedAsset,
				Endpoint: vf.AssetLocation,
			})
		}
		for _, df := range cr.DetectedFindings {
			findings = append(findings, report.Finding{
				ID:       df.ID,
				Title:    df.Title,
				Severity: df.Severity,
				Category: df.Category,
				Target:   df.AffectedAsset,
				Endpoint: df.AssetLocation,
			})
		}
		rep := report.Report{
			Target:           cr.ExecutiveSummary.Target,
			Targets:          cr.ExecutiveSummary.Targets,
			CompletionStatus: cr.ExecutiveSummary.CompletionStatus,
			Summary:          report.Summarize(findings),
			Findings:         findings,
		}
		reconciled, _ := assessment.ReconcileReport(snap, &rep, true)
		s.respondJSON(w, http.StatusOK, reconciled)
		return
	}

	var stdRep report.Report
	if err := json.Unmarshal(content, &stdRep); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("failed to parse report file: %v", err))
		return
	}

	reconciled, _ := assessment.ReconcileReport(snap, &stdRep, false)
	s.respondJSON(w, http.StatusOK, reconciled)
}
