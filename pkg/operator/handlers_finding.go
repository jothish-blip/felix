package operator

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"felix/pkg/assessment"
	"github.com/google/uuid"
)

type reviewFindingRequest struct {
	Status    string `json:"status"` // APPROVED_FOR_REPORT, REJECTED, PENDING
	Notes     string `json:"notes,omitempty"`
	Rationale string `json:"rationale,omitempty"`
}

type enrichedFindingItem struct {
	assessment.AssessmentFinding
	ReviewStatus assessment.ReviewStatus   `json:"review_status"`
	Review       *assessment.FindingReview `json:"review,omitempty"`
}

func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
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

	findings, err := s.store.GetFindings(asm.ID, "")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get findings: %v", err))
		return
	}

	reviews, err := s.store.ListFindingReviews(asm.ID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get finding reviews: %v", err))
		return
	}

	reviewMap := make(map[string]assessment.FindingReview, len(reviews))
	for _, rev := range reviews {
		reviewMap[rev.FindingID] = rev
	}

	var approvedCount, rejectedCount, pendingCount int
	enriched := make([]enrichedFindingItem, len(findings))

	for i, f := range findings {
		rev, exists := reviewMap[f.OriginalFindingID]
		if !exists {
			rev, exists = reviewMap[f.ID]
		}

		st := assessment.ReviewStatusPending
		var revPtr *assessment.FindingReview
		if exists {
			st = rev.ReviewStatus
			revPtr = &rev
		}

		switch st {
		case assessment.ReviewStatusApproved:
			approvedCount++
		case assessment.ReviewStatusRejected:
			rejectedCount++
		default:
			pendingCount++
		}

		enriched[i] = enrichedFindingItem{
			AssessmentFinding: f,
			ReviewStatus:      st,
			Review:            revPtr,
		}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"findings": enriched,
		"summary": map[string]int{
			"total":    len(findings),
			"approved": approvedCount,
			"rejected": rejectedCount,
			"pending":  pendingCount,
		},
	})
}

func (s *Server) handleGetFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	findingID := r.PathValue("findingId")
	if id == "" || findingID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or finding id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
		return
	}

	findings, err := s.store.GetFindings(asm.ID, "")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get findings: %v", err))
		return
	}

	var finding *assessment.AssessmentFinding
	for _, f := range findings {
		if f.ID == findingID || f.OriginalFindingID == findingID {
			finding = &f
			break
		}
	}
	if finding == nil {
		s.respondError(w, http.StatusNotFound, "finding not found in assessment")
		return
	}

	review, _ := s.store.GetFindingReview(asm.ID, finding.OriginalFindingID)
	if review == nil {
		review, _ = s.store.GetFindingReview(asm.ID, finding.ID)
	}

	st := assessment.ReviewStatusPending
	if review != nil {
		st = review.ReviewStatus
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"finding":       finding,
		"review_status": st,
		"review":        review,
	})
}

func (s *Server) handleReviewFinding(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	findingID := r.PathValue("findingId")
	if id == "" || findingID == "" {
		s.respondError(w, http.StatusBadRequest, "missing assessment id or finding id")
		return
	}

	asm, err := s.store.GetAssessment(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("assessment not found: %v", err))
		return
	}

	findings, err := s.store.GetFindings(asm.ID, "")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get findings: %v", err))
		return
	}

	var finding *assessment.AssessmentFinding
	for _, f := range findings {
		if f.ID == findingID || f.OriginalFindingID == findingID {
			finding = &f
			break
		}
	}
	if finding == nil {
		s.respondError(w, http.StatusNotFound, "finding not found in assessment")
		return
	}

	var req reviewFindingRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	status := assessment.ReviewStatus(strings.ToUpper(strings.TrimSpace(req.Status)))
	if !status.IsValid() {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid review status %q: must be APPROVED_FOR_REPORT, REJECTED, or PENDING", req.Status))
		return
	}

	now := time.Now().UTC()
	notes := strings.TrimSpace(req.Notes)
	if notes == "" && strings.TrimSpace(req.Rationale) != "" {
		notes = strings.TrimSpace(req.Rationale)
	}

	targetFindingKey := finding.OriginalFindingID
	if targetFindingKey == "" {
		targetFindingKey = finding.ID
	}

	review := &assessment.FindingReview{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		FindingID:    targetFindingKey,
		ReviewStatus: status,
		ReviewedBy:   s.cfg.OperatorID,
		ReviewedAt:   now,
		Notes:        notes,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Invariant: Save finding review strictly in operator review table.
	// Technical finding status and verification record in AssessmentFinding are NEVER touched!
	if err := s.store.SaveFindingReview(review); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save finding review: %v", err))
		return
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   s.cfg.OperatorID,
		ActionType:   "FINDING_REVIEWED",
		EntityType:   "FINDING",
		EntityID:     targetFindingKey,
		DetailsJSON:  fmt.Sprintf(`{"status":%q,"notes":%q,"reviewed_by":%q}`, status, notes, s.cfg.OperatorID),
	})

	s.respondJSON(w, http.StatusOK, review)
}
