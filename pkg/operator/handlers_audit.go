package operator

import (
	"fmt"
	"net/http"
	"strconv"

	"felix/pkg/assessment"
)

func (s *Server) handleGetAssessmentAudit(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	events, err := s.store.ListAuditEvents(asm.ID, limit)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to fetch audit events: %v", err))
		return
	}
	if events == nil {
		events = []assessment.AuditEvent{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}

func (s *Server) handleGetGlobalAudit(w http.ResponseWriter, r *http.Request) {
	// Security Invariant: Global audit trail access requires verified administrative authority.
	if _, ok := s.requireRole(w, r, RoleAdmin); !ok {
		return
	}

	limit := 100
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 && l <= 500 {
			limit = l
		}
	}

	events, err := s.store.ListAuditEvents("", limit)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to fetch global audit events: %v", err))
		return
	}
	if events == nil {
		events = []assessment.AuditEvent{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"events": events,
		"count":  len(events),
	})
}
