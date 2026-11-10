package notify

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// SyncAuditEntry captures a timestamped history entry for an external issue mapping.
type SyncAuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
}

// SyncRecord represents the persistent binding between a FELIX finding and an external issue.
type SyncRecord struct {
	FindingID               string            `json:"finding_id"`
	Platform                TrackerPlatform   `json:"platform"`
	ExternalIssueID         string            `json:"external_issue_id"`
	ExternalIssueKey        string            `json:"external_issue_key"`
	ExternalURL             string            `json:"external_url"`
	LastSyncedAt            time.Time         `json:"last_synced_at"`
	FindingFingerprint      string            `json:"finding_fingerprint"`
	ExternalStatus          string            `json:"external_status"`
	ExternalState           TrackerIssueState `json:"external_state"`
	ExternalAssignee        string            `json:"external_assignee,omitempty"`
	VulnerabilityRemediated bool              `json:"vulnerability_remediated"` // Invariant: ALWAYS false upon external ticket closure
	AuditTrail              []SyncAuditEntry  `json:"audit_trail,omitempty"`
}

// TrackerSyncStore defines the interface for persisting finding-to-ticket mappings.
type TrackerSyncStore interface {
	Get(findingID string, platform TrackerPlatform) (*SyncRecord, bool)
	Put(rec *SyncRecord) error
	Delete(findingID string, platform TrackerPlatform) error
	List(platform TrackerPlatform) []*SyncRecord
	Save() error
	Load() error
}

// FileTrackerSyncStore provides thread-safe, durable JSON file-backed persistence.
type FileTrackerSyncStore struct {
	mu       sync.RWMutex
	filePath string
	records  map[string]*SyncRecord // key: findingID + ":" + string(platform)
}

// NewFileTrackerSyncStore initializes or loads a persistent sync store from filePath.
func NewFileTrackerSyncStore(filePath string) (*FileTrackerSyncStore, error) {
	if filePath == "" {
		return nil, errors.New("filePath cannot be empty")
	}

	store := &FileTrackerSyncStore{
		filePath: filePath,
		records:  make(map[string]*SyncRecord),
	}

	// If file exists, load existing mappings
	if _, err := os.Stat(filePath); err == nil {
		if err := store.Load(); err != nil {
			return nil, fmt.Errorf("failed loading existing sync store from %s: %w", filePath, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed checking sync store file %s: %w", filePath, err)
	}

	return store, nil
}

func recordKey(findingID string, platform TrackerPlatform) string {
	return fmt.Sprintf("%s:%s", findingID, platform)
}

// Get retrieves a sync record by finding ID and platform.
func (s *FileTrackerSyncStore) Get(findingID string, platform TrackerPlatform) (*SyncRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key := recordKey(findingID, platform)
	rec, ok := s.records[key]
	if !ok || rec == nil {
		return nil, false
	}

	// Return a copy to prevent concurrent mutation
	copyRec := *rec
	copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
	copy(copyRec.AuditTrail, rec.AuditTrail)
	return &copyRec, true
}

// Put saves or updates a sync record and automatically persists to disk.
func (s *FileTrackerSyncStore) Put(rec *SyncRecord) error {
	if rec == nil {
		return errors.New("record cannot be nil")
	}
	if rec.FindingID == "" {
		return errors.New("finding ID cannot be empty")
	}
	if rec.Platform == "" {
		return errors.New("platform cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	key := recordKey(rec.FindingID, rec.Platform)
	copyRec := *rec
	copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
	copy(copyRec.AuditTrail, rec.AuditTrail)
	s.records[key] = &copyRec

	return s.saveLocked()
}

// Delete removes a sync record.
func (s *FileTrackerSyncStore) Delete(findingID string, platform TrackerPlatform) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := recordKey(findingID, platform)
	delete(s.records, key)
	return s.saveLocked()
}

// List returns all records, optionally filtered by platform.
func (s *FileTrackerSyncStore) List(platform TrackerPlatform) []*SyncRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	results := make([]*SyncRecord, 0, len(s.records))
	for _, rec := range s.records {
		if platform == "" || rec.Platform == platform {
			copyRec := *rec
			copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
			copy(copyRec.AuditTrail, rec.AuditTrail)
			results = append(results, &copyRec)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].FindingID != results[j].FindingID {
			return results[i].FindingID < results[j].FindingID
		}
		return results[i].Platform < results[j].Platform
	})
	return results
}

// Save forces persistence to disk.
func (s *FileTrackerSyncStore) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}

func (s *FileTrackerSyncStore) saveLocked() error {
	if s.filePath == "" {
		return nil
	}

	dir := filepath.Dir(s.filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed creating parent directory for sync store: %w", err)
	}

	// Prepare ordered slice for deterministic serialization
	recordsList := make([]*SyncRecord, 0, len(s.records))
	for _, r := range s.records {
		recordsList = append(recordsList, r)
	}
	sort.Slice(recordsList, func(i, j int) bool {
		if recordsList[i].FindingID != recordsList[j].FindingID {
			return recordsList[i].FindingID < recordsList[j].FindingID
		}
		return recordsList[i].Platform < recordsList[j].Platform
	})

	data, err := json.MarshalIndent(recordsList, "", "  ")
	if err != nil {
		return fmt.Errorf("failed marshaling sync store records: %w", err)
	}

	// Atomic write: write to temp file then rename
	tmpFile := fmt.Sprintf("%s.tmp.%d", s.filePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpFile, data, 0644); err != nil {
		return fmt.Errorf("failed writing temporary sync store file: %w", err)
	}

	if err := os.Rename(tmpFile, s.filePath); err != nil {
		// On Windows, if destination exists, os.Rename may fail unless removed first
		_ = os.Remove(s.filePath)
		if err := os.Rename(tmpFile, s.filePath); err != nil {
			_ = os.Remove(tmpFile)
			return fmt.Errorf("failed atomically renaming sync store file to %s: %w", s.filePath, err)
		}
	}

	return nil
}

// Load loads mappings from the backing JSON file.
func (s *FileTrackerSyncStore) Load() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			s.records = make(map[string]*SyncRecord)
			return nil
		}
		return fmt.Errorf("failed reading sync store file %s: %w", s.filePath, err)
	}

	var recordsList []*SyncRecord
	if err := json.Unmarshal(data, &recordsList); err != nil {
		return fmt.Errorf("failed unmarshaling sync store records: %w", err)
	}

	s.records = make(map[string]*SyncRecord, len(recordsList))
	for _, r := range recordsList {
		if r != nil && r.FindingID != "" && r.Platform != "" {
			s.records[recordKey(r.FindingID, r.Platform)] = r
		}
	}

	return nil
}

// MemoryTrackerSyncStore provides an in-memory implementation for lightweight testing.
type MemoryTrackerSyncStore struct {
	mu      sync.RWMutex
	records map[string]*SyncRecord
}

// NewMemoryTrackerSyncStore constructs an in-memory store.
func NewMemoryTrackerSyncStore() *MemoryTrackerSyncStore {
	return &MemoryTrackerSyncStore{
		records: make(map[string]*SyncRecord),
	}
}

func (s *MemoryTrackerSyncStore) Get(findingID string, platform TrackerPlatform) (*SyncRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.records[recordKey(findingID, platform)]
	if !ok || rec == nil {
		return nil, false
	}
	copyRec := *rec
	copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
	copy(copyRec.AuditTrail, rec.AuditTrail)
	return &copyRec, true
}

func (s *MemoryTrackerSyncStore) Put(rec *SyncRecord) error {
	if rec == nil {
		return errors.New("record cannot be nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := recordKey(rec.FindingID, rec.Platform)
	copyRec := *rec
	copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
	copy(copyRec.AuditTrail, rec.AuditTrail)
	s.records[key] = &copyRec
	return nil
}

func (s *MemoryTrackerSyncStore) Delete(findingID string, platform TrackerPlatform) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.records, recordKey(findingID, platform))
	return nil
}

func (s *MemoryTrackerSyncStore) List(platform TrackerPlatform) []*SyncRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	results := make([]*SyncRecord, 0, len(s.records))
	for _, rec := range s.records {
		if platform == "" || rec.Platform == platform {
			copyRec := *rec
			copyRec.AuditTrail = make([]SyncAuditEntry, len(rec.AuditTrail))
			copy(copyRec.AuditTrail, rec.AuditTrail)
			results = append(results, &copyRec)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].FindingID != results[j].FindingID {
			return results[i].FindingID < results[j].FindingID
		}
		return results[i].Platform < results[j].Platform
	})
	return results
}

func (s *MemoryTrackerSyncStore) Save() error { return nil }
func (s *MemoryTrackerSyncStore) Load() error { return nil }
