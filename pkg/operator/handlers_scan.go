package operator

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"felix/pkg/assessment"
)

type startScanRequest struct {
	Concurrency int  `json:"concurrency,omitempty"`
	MaxAssets   int  `json:"max_assets,omitempty"`
	Verbose     bool `json:"verbose,omitempty"`
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
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

	// Invariant: Targets must exist
	targets, _ := s.store.GetTargets(asm.ID)
	if len(targets) == 0 {
		s.respondError(w, http.StatusBadRequest, "cannot start scan: assessment has no targets defined")
		return
	}

	var req startScanRequest
	if r.Body != nil && r.ContentLength > 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	execOpts := assessment.ExecutionOptions{
		Concurrency: req.Concurrency,
		MaxAssets:   req.MaxAssets,
		Verbose:     req.Verbose,
	}

	// Trigger background scan via JobManager
	jobStatus, err := s.jobManager.StartAssessmentScan(context.Background(), asm.ID, s.cfg.OperatorID, execOpts)
	if err != nil {
		errMsg := err.Error()
		if strings.Contains(errMsg, "already active") || strings.Contains(errMsg, "unable to acquire scan lease") {
			s.respondError(w, http.StatusConflict, fmt.Sprintf("scan rejected: %v", err))
			return
		}
		if strings.Contains(errMsg, "authorization") {
			s.respondError(w, http.StatusForbidden, fmt.Sprintf("scan authorization check failed: %v", err))
			return
		}
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to start scan: %v", err))
		return
	}

	s.respondJSON(w, http.StatusAccepted, map[string]any{
		"assessment_id": asm.ID,
		"execution_id":  jobStatus.ExecutionID,
		"status":        jobStatus.State,
		"message":       "assessment scan successfully launched in background",
	})
}

func (s *Server) handleGetScanStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return
	}

	status, err := s.jobManager.GetJobStatus(id)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get scan status: %v", err))
		return
	}
	if status == nil {
		// Fallback check on active SQLite lease
		lease, leaseErr := s.store.GetActiveScanJobLease(id)
		if leaseErr == nil && lease != nil {
			s.respondJSON(w, http.StatusOK, map[string]any{
				"assessment_id":    lease.ID,
				"execution_id":     lease.ExecutionID,
				"operator_id":      lease.OperatorID,
				"state":            lease.Status,
				"started_at":       lease.AcquiredAt,
				"progress_message": lease.ProgressMessage,
				"error_message":    lease.ErrorMessage,
			})
			return
		}
		s.respondError(w, http.StatusNotFound, "no scan job record found for assessment")
		return
	}

	s.respondJSON(w, http.StatusOK, status)
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id")
		return
	}

	if err := s.jobManager.CancelAssessmentScan(id, s.cfg.OperatorID); err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("failed to cancel scan: %v", err))
		return
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"assessment_id": id,
		"status":        "CANCELLED",
		"message":       "scan execution cancellation signaled",
	})
}
