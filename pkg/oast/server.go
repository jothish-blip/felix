package oast

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Receiver provides a production-ready HTTP handler for out-of-band callbacks.
// Can be mounted directly into any net/http server or router (such as the Felix Operator server or a standalone listener).
type Receiver struct {
	correlator *Correlator
}

// NewReceiver creates a new Receiver backed by the specified Correlator.
func NewReceiver(correlator *Correlator) *Receiver {
	return &Receiver{correlator: correlator}
}

// ServeHTTP handles incoming out-of-band HTTP callbacks.
func (rcv *Receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rcv.handleCallback(w, r)
}

func (rcv *Receiver) handleCallback(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		http.Error(w, `{"error":"missing interaction token"}`, http.StatusBadRequest)
		return
	}

	maxBytes := rcv.correlator.cfg.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}

	lr := io.LimitReader(r.Body, maxBytes+1)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}
	if int64(len(bodyBytes)) > maxBytes {
		http.Error(w, `{"error":"`+ErrPayloadTooLarge.Error()+`"}`, http.StatusRequestEntityTooLarge)
		return
	}

	sanitizedBody := SanitizeInteractionData(string(bodyBytes))

	rawHeaders := make(map[string]string)
	for k, vals := range r.Header {
		if len(vals) > 0 {
			rawHeaders[k] = strings.Join(vals, ", ")
		}
	}
	sanitizedHeaders := SanitizeInteractionHeaders(rawHeaders)

	clientIP := r.RemoteAddr
	if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
		clientIP = clientIP[:idx]
	}
	clientIP = strings.TrimPrefix(strings.TrimSuffix(clientIP, "]"), "[")
	clientIP = SanitizeInteractionData(clientIP)

	sanitizedMethod := sanitizeMethod(r.Method)
	sanitizedPath := SanitizeInteractionData(r.URL.Path)
	if len(sanitizedPath) > 1024 {
		sanitizedPath = sanitizedPath[:1024]
	}

	assessmentID := SanitizeInteractionData(r.Header.Get("X-Felix-Assessment"))

	interaction := Interaction{
		ID:           uuid.New().String(),
		Token:        token,
		AssessmentID: assessmentID,
		Protocol:     ProtocolHTTP,
		ClientIP:     clientIP,
		Method:       sanitizedMethod,
		Path:         sanitizedPath,
		Headers:      sanitizedHeaders,
		Body:         sanitizedBody,
		ReceivedAt:   time.Now().UTC(),
	}

	result, err := rcv.correlator.RecordInteraction(r.Context(), interaction)
	if err != nil {
		switch err {
		case ErrProbeNotFound:
			http.Error(w, `{"error":"probe not found"}`, http.StatusNotFound)
			return
		case ErrProbeExpired:
			http.Error(w, `{"error":"probe expired"}`, http.StatusGone)
			return
		case ErrProbeCancelled:
			http.Error(w, `{"error":"probe cancelled"}`, http.StatusGone)
			return
		case ErrCrossAssessment:
			http.Error(w, `{"error":"cross-assessment isolation violation"}`, http.StatusForbidden)
			return
		case ErrDuplicateCallback:
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":    "duplicate_recorded",
				"duplicate": true,
				"token":     token,
			})
			return
		default:
			http.Error(w, `{"error":"internal error"}`, http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":      "correlated",
		"probe_id":    result.Probe.ID,
		"interaction": result.Interaction.ID,
		"token":       token,
	})
}

func sanitizeMethod(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if len(m) == 0 || len(m) > 16 {
		return "UNKNOWN"
	}
	for _, r := range m {
		if r < 'A' || r > 'Z' {
			return "UNKNOWN"
		}
	}
	return m
}

// LocalSimulator provides an in-process HTTP callback simulator for deterministic OAST verification.
type LocalSimulator struct {
	receiver   *Receiver
	correlator *Correlator
	server     *httptest.Server
	URL        string
}

// NewLocalSimulator starts a local HTTP simulator server backed by the provided Correlator.
func NewLocalSimulator(correlator *Correlator) *LocalSimulator {
	receiver := NewReceiver(correlator)
	sim := &LocalSimulator{
		receiver:   receiver,
		correlator: correlator,
	}

	server := httptest.NewServer(receiver)
	sim.server = server
	sim.URL = server.URL

	// Enable loopback policy for the local simulator
	correlator.SetAllowLoopback(true)
	_ = correlator.SetBaseURL(server.URL)

	return sim
}

// Handler returns the HTTP handler used by the simulator.
func (s *LocalSimulator) Handler() http.Handler {
	return s.receiver
}

func extractToken(r *http.Request) string {
	if q := r.URL.Query().Get("token"); q != "" {
		return strings.TrimSpace(q)
	}

	cleanPath := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(cleanPath, "/")
	if len(parts) >= 2 {
		switch parts[0] {
		case "c", "callback", "notify":
			return strings.TrimSpace(parts[1])
		}
	} else if len(parts) == 1 && len(parts[0]) == 32 {
		return strings.TrimSpace(parts[0])
	}
	return ""
}

// Close terminates the simulator server and closes the underlying correlator.
func (s *LocalSimulator) Close() {
	if s.server != nil {
		s.server.Close()
	}
	if s.correlator != nil {
		s.correlator.Close()
	}
}
