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

type createClientRequest struct {
	Name         string `json:"name"`
	Organization string `json:"organization,omitempty"`
	ContactName  string `json:"contact_name,omitempty"`
	ContactEmail string `json:"contact_email,omitempty"`
	Notes        string `json:"notes,omitempty"`
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	includeArchived := r.URL.Query().Get("all") == "true"
	clients, err := s.store.ListClients(includeArchived)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list clients: %v", err))
		return
	}
	if clients == nil {
		clients = []assessment.Client{}
	}
	s.respondJSON(w, http.StatusOK, map[string]any{
		"clients": clients,
		"count":   len(clients),
	})
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid request payload")
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		s.respondError(w, http.StatusBadRequest, "client name is required")
		return
	}

	now := time.Now().UTC()
	c := &assessment.Client{
		ID:           uuid.New().String(),
		Name:         req.Name,
		Organization: strings.TrimSpace(req.Organization),
		ContactName:  strings.TrimSpace(req.ContactName),
		ContactEmail: strings.TrimSpace(req.ContactEmail),
		Notes:        strings.TrimSpace(req.Notes),
		CreatedAt:    now,
		UpdatedAt:    now,
		Archived:     false,
	}

	if err := s.store.CreateClient(c); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create client: %v", err))
		return
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		OperatorID:  s.cfg.OperatorID,
		ActionType:  "CLIENT_CREATED",
		EntityType:  "CLIENT",
		EntityID:    c.ID,
		DetailsJSON: fmt.Sprintf(`{"name":%q,"org":%q}`, c.Name, c.Organization),
	})

	s.respondJSON(w, http.StatusCreated, c)
}

func (s *Server) handleGetClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing client id")
		return
	}

	client, err := s.store.GetClient(id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, fmt.Sprintf("client not found: %v", err))
		return
	}

	// Also retrieve assessments for this client
	asms, _ := s.store.ListAssessments(client.ID)
	if asms == nil {
		asms = []assessment.Assessment{}
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"client":      client,
		"assessments": asms,
	})
}

func (s *Server) handleArchiveClient(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "missing client id")
		return
	}

	if err := s.store.ArchiveClient(id); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to archive client: %v", err))
		return
	}

	_ = s.store.RecordAuditEvent(&assessment.AuditEvent{
		OperatorID:  s.cfg.OperatorID,
		ActionType:  "CLIENT_ARCHIVED",
		EntityType:  "CLIENT",
		EntityID:    id,
		DetailsJSON: `{"archived":true}`,
	})

	s.respondJSON(w, http.StatusOK, map[string]any{
		"status":  "archived",
		"message": "client archived successfully",
	})
}
