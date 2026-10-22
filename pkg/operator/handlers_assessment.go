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

type createAssessmentRequest struct {
	ClientID       string `json:"client_id"`
	Name           string `json:"name"`
	Description    string `json:"description,omitempty"`
	AssessmentType string `json:"assessment_type"` // e.g. BLACK_BOX_WEB, API_AUDIT, HYBRID
	ScopeMode      string `json:"scope_mode"`      // same-origin, subdomains, explicit
}

type addTargetRequest struct {
	TargetURL  string `json:"target_url"`
	TargetType string `json:"target_type"` // WEBSITE, API_BASE_URL, SUBDOMAIN, ASSET
	Label      string `json:"label,omitempty"`
}

type authorizeRequest struct {
	AuthorizingParty    string `json:"authorizing_party"`
	AuthorizationMethod string `json:"authorization_method"` // WRITTEN_CONTRACT, EMAIL, TICKET, STATEMENT_OF_WORK
	ScopeDocRef         string `json:"scope_doc_ref,omitempty"`
	InternalNotes       string `json:"internal_notes,omitempty"`
	ValidDays           int    `json:"valid_days,omitempty"` // default 30 days
}

func (s *Server) handleListAssessments(w http.ResponseWriter, r *http.Request) {
	authCtx := s.getAuthContext(r)
	clientID := r.URL.Query().Get("client_id")

	if !authCtx.IsAdmin() {
		if clientID != "" && !authCtx.Authorizes(clientID, "", "") {
			s.respondError(w, http.StatusForbidden, "forbidden: cannot list assessments for other clients")
			return
		}
		if clientID == "" {
			clientID = authCtx.ClientID
		}
	}

	asms, err := s.store.ListAssessments(clientID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list assessments: %v", err))
		return
	}
	if asms == nil {
		asms = []assessment.Assessment{}
	}

	// Filter assessments by caller's authorization boundary
	var authorizedAsms []assessment.Assessment
	for _, a := range asms {
		if authCtx.Authorizes(a.ClientID, "", "") {
			authorizedAsms = append(authorizedAsms, a)
		}
	}

	// Attach target count and findings summary to each assessment
	type asmSummaryItem struct {
		assessment.Assessment
		TargetCount int `json:"target_count"`
	}
	items := make([]asmSummaryItem, len(authorizedAsms))
	for i, a := range authorizedAsms {
		targets, _ := s.store.GetTargets(a.ID)
		items[i] = asmSummaryItem{
			Assessment:  a,
			TargetCount: len(targets),
		}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"assessments": items,
		"count":       len(items),
	})
}

func (s *Server) handleCreateAssessment(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireRole(w, r, RoleAdmin, RoleOperator)
	if !ok {
		return
	}

	var req createAssessmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.ClientID = strings.TrimSpace(req.ClientID)
	req.Name = strings.TrimSpace(req.Name)
	if req.ClientID == "" {
		s.respondError(w, http.StatusBadRequest, "client_id is required")
		return
	}
	if req.Name == "" {
		s.respondError(w, http.StatusBadRequest, "assessment name is required")
		return
	}

	authCtx := s.getAuthContext(r)
	if !authCtx.Authorizes(req.ClientID, "", "") {
		s.respondError(w, http.StatusForbidden, "forbidden: cannot create assessment for other client")
		return
	}

	// Verify client exists
	if _, err := s.store.GetClient(req.ClientID); err != nil {
		s.respondError(w, http.StatusBadRequest, "client not found")
		return
	}

	asmType := strings.TrimSpace(req.AssessmentType)
	if asmType == "" {
		asmType = "BLACK_BOX_WEB"
	}
	scopeMode := strings.TrimSpace(req.ScopeMode)
	if scopeMode == "" {
		scopeMode = "same-origin"
	}

	now := time.Now().UTC()
	asm := &assessment.Assessment{
		ID:             uuid.New().String(),
		Ref:            assessment.GenerateAssessmentRef(),
		ClientID:       req.ClientID,
		Name:           req.Name,
		Description:    strings.TrimSpace(req.Description),
		AssessmentType: asmType,
		Status:         assessment.StatusDraft,
		ScopeMode:      scopeMode,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.store.CreateAssessment(asm); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create assessment: %v", err))
		return
	}

	opID := s.cfg.OperatorID
	if sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   opID,
		ActionType:   "ASSESSMENT_CREATED",
		EntityType:   "ASSESSMENT",
		EntityID:     asm.ID,
		DetailsJSON:  fmt.Sprintf(`{"ref":%q,"name":%q,"client_id":%q}`, asm.Ref, asm.Name, asm.ClientID),
	})

	s.respondJSON(w, http.StatusCreated, asm)
}

func (s *Server) handleGetAssessment(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	// Populate targets
	targets, _ := s.store.GetTargets(asm.ID)
	asm.Targets = targets

	// Populate authorization
	authRec, _ := s.store.GetAuthorization(asm.ID)
	asm.Authorization = authRec

	// Populate client details
	client, _ := s.store.GetClient(asm.ClientID)

	// Fetch review summary
	reviews, _ := s.store.ListFindingReviews(asm.ID)
	findings, _ := s.store.GetFindings(asm.ID, "")

	reviewMap := make(map[string]assessment.ReviewStatus)
	for _, rev := range reviews {
		reviewMap[rev.FindingID] = rev.ReviewStatus
	}

	var approved, rejected, pending int
	for _, f := range findings {
		st, ok := reviewMap[f.OriginalFindingID]
		if !ok {
			st, ok = reviewMap[f.ID]
		}
		if !ok {
			st = assessment.ReviewStatusPending
		}
		switch st {
		case assessment.ReviewStatusApproved:
			approved++
		case assessment.ReviewStatusRejected:
			rejected++
		default:
			pending++
		}
	}

	// Check active scan lease
	activeLease, _ := s.store.GetActiveScanJobLease(asm.ID)

	s.respondJSON(w, http.StatusOK, map[string]any{
		"assessment": asm,
		"client":     client,
		"review_summary": map[string]int{
			"total":    len(findings),
			"approved": approved,
			"rejected": rejected,
			"pending":  pending,
		},
		"active_lease": activeLease,
	})
}

func (s *Server) handleAddTarget(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireRole(w, r, RoleAdmin, RoleOperator)
	if !ok {
		return
	}

	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	var req addTargetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	normalizedURL, err := assessment.NormalizeTargetURL(req.TargetURL)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, fmt.Sprintf("invalid target URL: %v", err))
		return
	}

	targetType := assessment.TargetType(strings.ToUpper(strings.TrimSpace(req.TargetType)))
	if targetType == "" {
		targetType = assessment.TargetWebsite
	}

	t := &assessment.AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		TargetURL:    normalizedURL,
		TargetType:   targetType,
		ScopeStatus:  "APPROVED",
		Label:        strings.TrimSpace(req.Label),
		CreatedAt:    time.Now().UTC(),
	}

	if err := s.store.AddTarget(t); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to add target: %v", err))
		return
	}

	opID := s.cfg.OperatorID
	if sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   opID,
		ActionType:   "TARGET_ADDED",
		EntityType:   "TARGET",
		EntityID:     t.ID,
		DetailsJSON:  fmt.Sprintf(`{"target_url":%q,"type":%q}`, t.TargetURL, t.TargetType),
	})

	s.respondJSON(w, http.StatusCreated, t)
}

func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.requireRole(w, r, RoleAdmin, RoleOperator)
	if !ok {
		return
	}

	id := r.PathValue("id")
	asm, ok := s.requireAssessment(w, r, id)
	if !ok {
		return
	}

	var req authorizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	party := strings.TrimSpace(req.AuthorizingParty)
	if party == "" {
		s.respondError(w, http.StatusBadRequest, "authorizing_party is required")
		return
	}

	method := strings.ToUpper(strings.TrimSpace(req.AuthorizationMethod))
	if method == "" {
		method = "WRITTEN_CONTRACT"
	}

	days := req.ValidDays
	if days <= 0 {
		days = 30
	}

	now := time.Now().UTC()
	validUntil := now.Add(time.Duration(days) * 24 * time.Hour)

	authRec := &assessment.AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asm.ID,
		AuthorizingParty:    party,
		AuthorizationMethod: method,
		DateReceived:        now,
		ValidFrom:           &now,
		ValidUntil:          &validUntil,
		ScopeDocRef:         strings.TrimSpace(req.ScopeDocRef),
		InternalNotes:       strings.TrimSpace(req.InternalNotes),
		Status:              assessment.AuthApproved,
		CreatedAt:           now,
		UpdatedAt:           now,
	}

	if err := s.store.SetAuthorization(authRec); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save authorization: %v", err))
		return
	}

	// If assessment is DRAFT, advance it to READY
	if asm.Status == assessment.StatusDraft {
		_ = s.store.UpdateAssessmentStatus(asm.ID, assessment.StatusReady)
	}

	opID := s.cfg.OperatorID
	if sess != nil && sess.OperatorID != "" {
		opID = sess.OperatorID
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		AssessmentID: asm.ID,
		OperatorID:   opID,
		ActionType:   "AUTHORIZATION_GRANTED",
		EntityType:   "AUTHORIZATION",
		EntityID:     authRec.ID,
		DetailsJSON:  fmt.Sprintf(`{"party":%q,"method":%q,"valid_until":%q}`, authRec.AuthorizingParty, authRec.AuthorizationMethod, validUntil.Format(time.RFC3339)),
	})

	s.respondJSON(w, http.StatusOK, authRec)
}
