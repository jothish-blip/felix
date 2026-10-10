package operator

import (
	"net/http"
	"time"
)

func (s *Server) registerRoutes() {
	// Health & System
	s.mux.HandleFunc("GET /api/v1/health", s.handleHealth)

	// Clients
	s.mux.HandleFunc("GET /api/v1/clients", s.handleListClients)
	s.mux.HandleFunc("POST /api/v1/clients", s.handleCreateClient)
	s.mux.HandleFunc("GET /api/v1/clients/{id}", s.handleGetClient)
	s.mux.HandleFunc("POST /api/v1/clients/{id}/archive", s.handleArchiveClient)

	// Assessments
	s.mux.HandleFunc("GET /api/v1/assessments", s.handleListAssessments)
	s.mux.HandleFunc("POST /api/v1/assessments", s.handleCreateAssessment)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}", s.handleGetAssessment)
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/targets", s.handleAddTarget)
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/authorize", s.handleAuthorize)

	// Scans
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/scan", s.handleStartScan)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/scan/status", s.handleGetScanStatus)
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/scan/cancel", s.handleCancelScan)

	// Findings & Review
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/findings", s.handleListFindings)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/findings/{findingId}", s.handleGetFinding)
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/findings/{findingId}/review", s.handleReviewFinding)

	// Commercial Reports
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/reports/generate", s.handleGenerateReport)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/reports", s.handleListReports)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/reports/{reportId}", s.handleGetReport)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/reports/{reportId}/html", s.handleDownloadReportHTML)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/reports/{reportId}/json", s.handleDownloadReportJSON)

	// Report Delivery
	s.mux.HandleFunc("POST /api/v1/assessments/{id}/reports/{reportId}/deliver", s.handleCreateDelivery)
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/deliveries", s.handleListDeliveries)

	// Audit Trail
	s.mux.HandleFunc("GET /api/v1/assessments/{id}/audit", s.handleGetAssessmentAudit)
	s.mux.HandleFunc("GET /api/v1/audit", s.handleGetGlobalAudit)

	// Embedded Web UI
	s.mux.Handle("/", s.handleWebStatic())
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.respondJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"version":     s.cfg.Version,
		"operator_id": s.cfg.OperatorID,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	})
}
