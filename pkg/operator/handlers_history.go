package operator

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"felix/pkg/assessment"
)

func parseIntParam(val string, defaultVal int) int {
	if strings.TrimSpace(val) == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil {
		return defaultVal
	}
	return n
}

func (s *Server) handleGetAssessmentHistory(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	limit := parseIntParam(r.URL.Query().Get("limit"), 20)
	offset := parseIntParam(r.URL.Query().Get("offset"), 0)

	authCtx := s.getAuthContext(r)
	history, total, err := s.store.ListAssessmentHistory(asm.ClientID, asm.ID, authCtx, limit, offset)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to retrieve assessment history: %v", err))
		return
	}

	if history == nil {
		history = []assessment.AssessmentHistoryItem{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"assessment_id": asm.ID,
		"ref":           asm.Ref,
		"client_id":     asm.ClientID,
		"history":       history,
		"count":         len(history),
		"total":         total,
		"limit":         limit,
		"offset":        offset,
	})
}

func (s *Server) handleCompareAssessments(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	curAsm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	authCtx := s.getAuthContext(r)

	baselineID := strings.TrimSpace(r.URL.Query().Get("baseline_id"))
	if baselineID == "" {
		baselineID = strings.TrimSpace(r.URL.Query().Get("baseline_ref"))
	}
	baseExecID := strings.TrimSpace(r.URL.Query().Get("baseline_exec_id"))
	curExecID := strings.TrimSpace(r.URL.Query().Get("current_exec_id"))

	// Automatic baseline resolution if no baseline ID specified
	if baselineID == "" {
		history, _, err := s.store.ListAssessmentHistory(curAsm.ClientID, curAsm.ID, authCtx, 20, 0)
		if err == nil && len(history) > 0 {
			for _, h := range history {
				if h.ID != curAsm.ID && h.IsEligibleBaseline {
					baselineID = h.ID
					break
				}
			}
		}
		if baselineID == "" {
			s.respondError(w, http.StatusBadRequest, "no eligible baseline assessment found for comparison")
			return
		}
	}

	baseAsm, err := s.store.GetAssessment(baselineID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("baseline assessment not found: %v", err))
		return
	}

	// Cross-tenant protection: fail closed with 404 to prevent IDOR existence leaks
	if !authCtx.Authorizes(baseAsm.ClientID, "", "") {
		s.respondError(w, http.StatusNotFound, "baseline assessment not found")
		return
	}

	res, err := s.store.CompareAssessmentsWithExecutions(baseAsm.ID, baseExecID, curAsm.ID, curExecID, authCtx)
	if err != nil {
		if errors.Is(err, assessment.ErrExecutionUnauthorized) {
			s.respondError(w, http.StatusForbidden, err.Error())
			return
		}
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Audit trail logging
	opID := s.cfg.OperatorID
	if sess := s.getSession(r); sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: curAsm.ID,
		OperatorID:   opID,
		ActionType:   "ASSESSMENT_COMPARED",
		EntityType:   "ASSESSMENT",
		EntityID:     curAsm.ID,
		DetailsJSON:  fmt.Sprintf(`{"baseline_id":%q,"baseline_ref":%q,"comparability_status":%q,"new_count":%d,"resolved_count":%d,"persistent_count":%d}`, baseAsm.ID, baseAsm.Ref, res.ComparabilityStatus, res.NewCount, res.ResolvedCount, res.PersistentCount),
	})

	s.respondJSON(w, http.StatusOK, res)
}

func (s *Server) handleDirectCompare(w http.ResponseWriter, r *http.Request) {
	authCtx := s.getAuthContext(r)

	baselineID := strings.TrimSpace(r.URL.Query().Get("baseline_id"))
	if baselineID == "" {
		baselineID = strings.TrimSpace(r.URL.Query().Get("baseline_ref"))
	}
	currentID := strings.TrimSpace(r.URL.Query().Get("current_id"))
	if currentID == "" {
		currentID = strings.TrimSpace(r.URL.Query().Get("current_ref"))
	}

	if baselineID == "" || currentID == "" {
		s.respondError(w, http.StatusBadRequest, "both baseline_id and current_id query parameters are required")
		return
	}

	baseExecID := strings.TrimSpace(r.URL.Query().Get("baseline_exec_id"))
	curExecID := strings.TrimSpace(r.URL.Query().Get("current_exec_id"))

	baseAsm, err := s.store.GetAssessment(baselineID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "baseline assessment not found")
		return
	}
	if !authCtx.Authorizes(baseAsm.ClientID, "", "") {
		s.respondError(w, http.StatusNotFound, "baseline assessment not found")
		return
	}

	curAsm, err := s.store.GetAssessment(currentID)
	if err != nil {
		s.respondError(w, http.StatusNotFound, "current assessment not found")
		return
	}
	if !authCtx.Authorizes(curAsm.ClientID, "", "") {
		s.respondError(w, http.StatusNotFound, "current assessment not found")
		return
	}

	res, err := s.store.CompareAssessmentsWithExecutions(baseAsm.ID, baseExecID, curAsm.ID, curExecID, authCtx)
	if err != nil {
		if errors.Is(err, assessment.ErrExecutionUnauthorized) {
			s.respondError(w, http.StatusForbidden, err.Error())
			return
		}
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	opID := s.cfg.OperatorID
	if sess := s.getSession(r); sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: curAsm.ID,
		OperatorID:   opID,
		ActionType:   "ASSESSMENT_COMPARED",
		EntityType:   "ASSESSMENT",
		EntityID:     curAsm.ID,
		DetailsJSON:  fmt.Sprintf(`{"baseline_id":%q,"baseline_ref":%q,"comparability_status":%q,"new_count":%d,"resolved_count":%d,"persistent_count":%d}`, baseAsm.ID, baseAsm.Ref, res.ComparabilityStatus, res.NewCount, res.ResolvedCount, res.PersistentCount),
	})

	s.respondJSON(w, http.StatusOK, res)
}
