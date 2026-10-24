package monitor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// DeliveryRecord captures the audit proof and timestamp of a notification dispatch attempt.
type DeliveryRecord struct {
	EventID      string    `json:"event_id"`
	WebhookID    string    `json:"webhook_id"`
	Provider     string    `json:"provider"`
	Status       string    `json:"status"` // "DELIVERED", "FAILED", "PERMANENT_FAILURE"
	DeliveredAt  time.Time `json:"delivered_at,omitempty"`
	ReceiptID    string    `json:"receipt_id,omitempty"`
	AttemptCount int       `json:"attempt_count"`
	LastError    string    `json:"last_error,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DeliveryState models the durable delivery history for a target.
type DeliveryState struct {
	TargetID string                    `json:"target_id"`
	Records  map[string]DeliveryRecord `json:"records"` // Key: "webhookID:eventID"
}

// DeliveryStateStore manages atomic persistence of notification delivery state across runs.
type DeliveryStateStore struct {
	statePath string
	mu        sync.RWMutex
	state     DeliveryState
}

// NewDeliveryStateStore initializes or loads the delivery state for a target.
func NewDeliveryStateStore(baseDir, targetID string) (*DeliveryStateStore, error) {
	cleanTarget := SanitizeTargetID(targetID)
	dir := filepath.Join(baseDir, cleanTarget)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create target delivery state dir: %w", err)
	}

	statePath := filepath.Join(dir, "delivery_state.json")
	store := &DeliveryStateStore{
		statePath: statePath,
		state: DeliveryState{
			TargetID: targetID,
			Records:  make(map[string]DeliveryRecord),
		},
	}

	// Load existing state if available
	if data, err := os.ReadFile(statePath); err == nil {
		var loaded DeliveryState
		if err := json.Unmarshal(data, &loaded); err == nil {
			if loaded.Records != nil {
				store.state.Records = loaded.Records
			}
		}
	}

	return store, nil
}

func makeRecordKey(webhookID, eventID string) string {
	return fmt.Sprintf("%s:%s", webhookID, eventID)
}

// IsDelivered returns true if the event has already been successfully delivered to the webhook.
func (s *DeliveryStateStore) IsDelivered(webhookID, eventID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := makeRecordKey(webhookID, eventID)
	rec, exists := s.state.Records[key]
	return exists && rec.Status == "DELIVERED"
}

// RecordDeliverySuccess marks an event as successfully delivered to a webhook and persists state.
func (s *DeliveryStateStore) RecordDeliverySuccess(webhookID, eventID, provider, receiptID string, deliveredAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := makeRecordKey(webhookID, eventID)
	rec := s.state.Records[key]
	rec.EventID = eventID
	rec.WebhookID = webhookID
	rec.Provider = provider
	rec.Status = "DELIVERED"
	rec.ReceiptID = receiptID
	rec.DeliveredAt = deliveredAt
	rec.AttemptCount++
	rec.LastError = ""
	rec.UpdatedAt = time.Now().UTC()

	s.state.Records[key] = rec
	return s.persistUnsafe()
}

// RecordDeliveryFailure records an error for an event dispatch attempt and persists state.
func (s *DeliveryStateStore) RecordDeliveryFailure(webhookID, eventID, provider, errStr string, permanent bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := makeRecordKey(webhookID, eventID)
	rec := s.state.Records[key]
	rec.EventID = eventID
	rec.WebhookID = webhookID
	rec.Provider = provider
	if permanent {
		rec.Status = "PERMANENT_FAILURE"
	} else {
		rec.Status = "FAILED"
	}
	rec.AttemptCount++
	rec.LastError = errStr
	rec.UpdatedAt = time.Now().UTC()

	s.state.Records[key] = rec
	return s.persistUnsafe()
}

// TotalDeliveredCount returns the total number of successfully delivered notifications recorded.
func (s *DeliveryStateStore) TotalDeliveredCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, r := range s.state.Records {
		if r.Status == "DELIVERED" {
			count++
		}
	}
	return count
}

// persistUnsafe atomically writes state to disk. Must hold mu.
func (s *DeliveryStateStore) persistUnsafe() error {
	// Bound total records if exceeded
	if len(s.state.Records) > 5000 {
		// Prune oldest non-delivered records
		for k, r := range s.state.Records {
			if len(s.state.Records) <= 4000 {
				break
			}
			if r.Status != "DELIVERED" {
				delete(s.state.Records, k)
			}
		}
	}

	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicFile(s.statePath, data)
}
