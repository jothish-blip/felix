package operator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"felix/pkg/assessment"
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
	id := r.PathValue("id")
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
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

	res, err := assessment.GenerateCuratedCommercialReport(s.store, asm.ID, s.cfg.OperatorID, opts)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "report generation blocked") {
			s.respondError(w, http.StatusBadRequest, errMsg)
			return
		}
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate commercial report: %v", err))
		return
	}

	s.respondJSON(w, http.StatusCreated, map[string]any{
		"assessment_id":    asm.ID,
		"report_record_id": res.ReportRecordID,
		"is_draft":         res.IsDraft,
		"html_path":        res.HTMLPath,
		"json_path":        res.JSONPath,
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
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
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
	reportID := r.PathValue("reportId")
	if reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing report id")
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("report not found: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, rep)
}

func (s *Server) handleDownloadReportHTML(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("reportId")
	if reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing report id")
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("report not found: %v", err))
		return
	}

	if rep.FilePath == "" {
		s.respondError(w, http.StatusNotFound, "report file path not recorded")
		return
	}

	content, err := os.ReadFile(rep.FilePath)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("report file could not be read: %v", err))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleDownloadReportJSON(w http.ResponseWriter, r *http.Request) {
	reportID := r.PathValue("reportId")
	if reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing report id")
		return
	}

	rep, err := s.store.GetReport(reportID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("report not found: %v", err))
		return
	}

	if rep.FilePath == "" {
		s.respondError(w, http.StatusNotFound, "report file path not recorded")
		return
	}

	content, err := os.ReadFile(rep.FilePath)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("report file could not be read: %v", err))
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(content)
}

func (s *Server) handleCreateDelivery(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	reportID := r.PathValue("reportId")
	if id == "" || reportID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or report id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
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
		OperatorID:     s.cfg.OperatorID,
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
		OperatorID:   s.cfg.OperatorID,
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
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
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
