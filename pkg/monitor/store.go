package monitor

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	ErrBaselineNotFound      = errors.New("no baseline snapshot found for target")
	ErrSnapshotNotFound      = errors.New("snapshot not found")
	ErrCorruptSnapshot       = errors.New("snapshot file is corrupt or unreadable")
	ErrOversizedSnapshot     = errors.New("snapshot exceeds maximum allowed size")
	ErrIncompatibleSnapshot  = errors.New("incompatible snapshot schema version")
	ErrExceededRouteCapacity = errors.New("snapshot exceeds maximum route capacity")
)

// SnapshotStore defines the abstraction for durable storage of API surface snapshots.
type SnapshotStore interface {
	SaveSnapshot(ctx context.Context, snap *Snapshot) error
	GetBaseline(ctx context.Context, targetID string) (*Snapshot, error)
	SetBaseline(ctx context.Context, snap *Snapshot, reason string) error
	GetLatestSnapshot(ctx context.Context, targetID string) (*Snapshot, error)
	ListSnapshots(ctx context.Context, targetID string) ([]SnapshotSummary, error)
	GetSnapshot(ctx context.Context, targetID, snapshotID string) (*Snapshot, error)
	PruneHistory(ctx context.Context, targetID string, maxSnapshots int) (int, error)
}

// BaselineRecord documents an auditable baseline change.
type BaselineRecord struct {
	SnapshotID string    `json:"snapshot_id"`
	TargetID   string    `json:"target_id"`
	Reason     string    `json:"reason"`
	SetAt      time.Time `json:"set_at"`
	RouteCount int       `json:"route_count"`
}

// FileSnapshotStore implements SnapshotStore using atomic, isolated filesystem directories.
type FileSnapshotStore struct {
	baseDir         string
	retainSnapshots int
	mu              sync.RWMutex
}

// NewFileSnapshotStore constructs a FileSnapshotStore bound to baseDir.
func NewFileSnapshotStore(baseDir string, retainSnapshots int) (*FileSnapshotStore, error) {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "./felix-state"
	}
	cleanDir := filepath.Clean(baseDir)
	if err := os.MkdirAll(cleanDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to initialize snapshot state directory %s: %w", cleanDir, err)
	}
	if retainSnapshots <= 0 {
		retainSnapshots = DefaultRetainSnapshots
	}
	return &FileSnapshotStore{
		baseDir:         cleanDir,
		retainSnapshots: retainSnapshots,
	}, nil
}

// targetDir returns the isolated directory path for a specific target.
func (s *FileSnapshotStore) targetDir(targetID string) string {
	cleanTarget := SanitizeTargetID(targetID)
	return filepath.Join(s.baseDir, cleanTarget)
}

// snapshotsDir returns the directory containing historical snapshots for a target.
func (s *FileSnapshotStore) snapshotsDir(targetID string) string {
	return filepath.Join(s.targetDir(targetID), "snapshots")
}

// baselinePath returns the path to the current active baseline snapshot file.
func (s *FileSnapshotStore) baselinePath(targetID string) string {
	return filepath.Join(s.targetDir(targetID), "baseline.json")
}

// baselineHistoryPath returns the path to the baseline changes audit log.
func (s *FileSnapshotStore) baselineHistoryPath(targetID string) string {
	return filepath.Join(s.targetDir(targetID), "baseline_history.jsonl")
}

// writeAtomicFile safely writes data to a temporary file in dest's directory, syncs, and renames.
func writeAtomicFile(destPath string, data []byte) error {
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := hex.EncodeToString(nonceBytes)
	tmpPath := fmt.Sprintf("%s.tmp.%s", destPath, nonce)

	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("failed to create temporary file for atomic write: %w", err)
	}

	writeSuccess := false
	defer func() {
		if !writeSuccess {
			_ = f.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("failed to write data: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync data to disk: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file: %w", err)
	}

	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("failed to atomically commit file to %s: %w", destPath, err)
	}

	writeSuccess = true
	return nil
}

// loadSnapshotFile reads and strictly validates a snapshot JSON file from disk.
func loadSnapshotFile(filePath string) (*Snapshot, error) {
	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSnapshotNotFound
		}
		return nil, fmt.Errorf("failed to stat snapshot file: %w", err)
	}

	if fi.Size() > MaxSnapshotSizeBytes {
		return nil, fmt.Errorf("%w: size %d bytes exceeds %d bytes ceiling", ErrOversizedSnapshot, fi.Size(), MaxSnapshotSizeBytes)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open snapshot file: %w", err)
	}
	defer f.Close()

	var snap Snapshot
	dec := json.NewDecoder(f)
	if err := dec.Decode(&snap); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorruptSnapshot, err)
	}

	if snap.SchemaVersion != CurrentSnapshotSchemaVersion {
		return nil, fmt.Errorf("%w: snapshot has schema version %d (supported: %d)", ErrIncompatibleSnapshot, snap.SchemaVersion, CurrentSnapshotSchemaVersion)
	}
	if len(snap.Routes) > MaxSnapshotRoutes {
		return nil, fmt.Errorf("%w: snapshot contains %d routes (maximum %d)", ErrExceededRouteCapacity, len(snap.Routes), MaxSnapshotRoutes)
	}

	return &snap, nil
}

// SaveSnapshot saves a snapshot to durable disk storage.
// If no baseline exists for this target yet, this snapshot is also atomically established as the initial baseline.
func (s *FileSnapshotStore) SaveSnapshot(ctx context.Context, snap *Snapshot) error {
	if snap == nil {
		return errors.New("snapshot cannot be nil")
	}
	if snap.SchemaVersion == 0 {
		snap.SchemaVersion = CurrentSnapshotSchemaVersion
	}
	if snap.SchemaVersion != CurrentSnapshotSchemaVersion {
		return fmt.Errorf("%w: schema version %d", ErrIncompatibleSnapshot, snap.SchemaVersion)
	}
	if len(snap.Routes) > MaxSnapshotRoutes {
		return fmt.Errorf("%w: %d routes exceed limit of %d", ErrExceededRouteCapacity, len(snap.Routes), MaxSnapshotRoutes)
	}
	if snap.TargetID == "" {
		return errors.New("snapshot.target_id cannot be empty")
	}
	if snap.ID == "" {
		snap.ID = GenerateSnapshotID(snap.TargetID, time.Now().UTC())
	}
	if snap.CollectedAt.IsZero() {
		snap.CollectedAt = time.Now().UTC()
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize snapshot: %w", err)
	}
	if int64(len(data)) > MaxSnapshotSizeBytes {
		return fmt.Errorf("%w: serialized size %d exceeds %d bytes", ErrOversizedSnapshot, len(data), MaxSnapshotSizeBytes)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 1. Write snapshot file to snapshots/ directory
	targetDir := s.targetDir(snap.TargetID)
	snapDir := filepath.Join(targetDir, "snapshots")
	cleanSnapID := SanitizeTargetID(snap.ID)
	destPath := filepath.Join(snapDir, cleanSnapID+".json")

	if err := writeAtomicFile(destPath, data); err != nil {
		return err
	}

	// 2. Check if a baseline already exists. If not, establish this as initial baseline.
	basePath := s.baselinePath(snap.TargetID)
	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		if err := writeAtomicFile(basePath, data); err == nil {
			s.recordBaselineHistoryUnsafe(snap.TargetID, snap.ID, "Initial baseline automatically established upon first discovery", snap.RouteCount())
		}
	}

	// 3. Prune older snapshots if retention limit exceeded
	_, _ = s.pruneHistoryUnsafe(snap.TargetID, s.retainSnapshots)

	return nil
}

// GetBaseline retrieves the currently active baseline snapshot for a target.
func (s *FileSnapshotStore) GetBaseline(ctx context.Context, targetID string) (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	basePath := s.baselinePath(targetID)
	snap, err := loadSnapshotFile(basePath)
	if err != nil {
		if errors.Is(err, ErrSnapshotNotFound) {
			return nil, ErrBaselineNotFound
		}
		return nil, err
	}
	return snap, nil
}

// SetBaseline explicitly updates the baseline snapshot for a target with an audit reason.
func (s *FileSnapshotStore) SetBaseline(ctx context.Context, snap *Snapshot, reason string) error {
	if snap == nil {
		return errors.New("cannot set nil baseline snapshot")
	}
	if snap.TargetID == "" {
		return errors.New("snapshot target_id cannot be empty")
	}
	if strings.TrimSpace(reason) == "" {
		reason = "Operator explicitly established baseline"
	}

	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize baseline: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	basePath := s.baselinePath(snap.TargetID)
	if err := writeAtomicFile(basePath, data); err != nil {
		return fmt.Errorf("failed to atomically write baseline: %w", err)
	}

	s.recordBaselineHistoryUnsafe(snap.TargetID, snap.ID, reason, snap.RouteCount())
	return nil
}

// recordBaselineHistoryUnsafe appends an audit line to baseline_history.jsonl. Must hold lock.
func (s *FileSnapshotStore) recordBaselineHistoryUnsafe(targetID, snapshotID, reason string, routeCount int) {
	histPath := s.baselineHistoryPath(targetID)
	rec := BaselineRecord{
		SnapshotID: snapshotID,
		TargetID:   targetID,
		Reason:     reason,
		SetAt:      time.Now().UTC(),
		RouteCount: routeCount,
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return
	}
	line = append(line, '\n')

	f, err := os.OpenFile(histPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(line)
}

// GetLatestSnapshot returns the most recently collected snapshot for a target.
func (s *FileSnapshotStore) GetLatestSnapshot(ctx context.Context, targetID string) (*Snapshot, error) {
	summaries, err := s.ListSnapshots(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if len(summaries) == 0 {
		return nil, ErrSnapshotNotFound
	}
	// Sort descending by CollectedAt
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].CollectedAt.After(summaries[j].CollectedAt)
	})

	return s.GetSnapshot(ctx, targetID, summaries[0].ID)
}

// GetSnapshot retrieves a specific historical snapshot by ID.
func (s *FileSnapshotStore) GetSnapshot(ctx context.Context, targetID, snapshotID string) (*Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cleanSnapID := SanitizeTargetID(snapshotID)
	snapPath := filepath.Join(s.snapshotsDir(targetID), cleanSnapID+".json")
	return loadSnapshotFile(snapPath)
}

// ListSnapshots returns summaries of all retained snapshots for a target.
func (s *FileSnapshotStore) ListSnapshots(ctx context.Context, targetID string) ([]SnapshotSummary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	snapDir := s.snapshotsDir(targetID)
	entries, err := os.ReadDir(snapDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read snapshots directory: %w", err)
	}

	// Read active baseline ID if present
	baselineSnapID := ""
	if baseSnap, err := loadSnapshotFile(s.baselinePath(targetID)); err == nil && baseSnap != nil {
		baselineSnapID = baseSnap.ID
	}

	var results []SnapshotSummary
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		filePath := filepath.Join(snapDir, entry.Name())
		snap, err := loadSnapshotFile(filePath)
		if err != nil {
			continue // skip corrupt entries during listing
		}
		fi, _ := entry.Info()
		size := int64(0)
		if fi != nil {
			size = fi.Size()
		}

		results = append(results, SnapshotSummary{
			ID:          snap.ID,
			TargetID:    snap.TargetID,
			CollectedAt: snap.CollectedAt,
			RouteCount:  len(snap.Routes),
			IsComplete:  snap.IsComplete,
			IsBaseline:  snap.ID == baselineSnapID,
			SizeBytes:   size,
		})
	}

	// Sort newest first
	sort.Slice(results, func(i, j int) bool {
		return results[i].CollectedAt.After(results[j].CollectedAt)
	})

	return results, nil
}

// PruneHistory removes older snapshots beyond maxSnapshots while strictly preserving the active baseline.
func (s *FileSnapshotStore) PruneHistory(ctx context.Context, targetID string, maxSnapshots int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pruneHistoryUnsafe(targetID, maxSnapshots)
}

// pruneHistoryUnsafe performs retention pruning. Must hold lock.
func (s *FileSnapshotStore) pruneHistoryUnsafe(targetID string, maxSnapshots int) (int, error) {
	if maxSnapshots <= 0 {
		maxSnapshots = s.retainSnapshots
	}

	snapDir := s.snapshotsDir(targetID)
	entries, err := os.ReadDir(snapDir)
	if err != nil || len(entries) <= maxSnapshots {
		return 0, nil
	}

	// Identify active baseline snapshot ID to NEVER delete
	activeBaselineID := ""
	if baseSnap, err := loadSnapshotFile(s.baselinePath(targetID)); err == nil && baseSnap != nil {
		activeBaselineID = SanitizeTargetID(baseSnap.ID)
	}

	type fileMeta struct {
		name    string
		modTime time.Time
	}
	var files []fileMeta
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			if info, err := e.Info(); err == nil {
				files = append(files, fileMeta{name: e.Name(), modTime: info.ModTime()})
			}
		}
	}

	if len(files) <= maxSnapshots {
		return 0, nil
	}

	// Sort oldest first
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.Before(files[j].modTime)
	})

	prunedCount := 0
	candidatesToRemove := len(files) - maxSnapshots
	for _, fm := range files {
		if prunedCount >= candidatesToRemove {
			break
		}
		baseID := strings.TrimSuffix(fm.name, ".json")
		if baseID == activeBaselineID {
			continue // NEVER delete the active baseline!
		}
		toRemove := filepath.Join(snapDir, fm.name)
		if err := os.Remove(toRemove); err == nil {
			prunedCount++
		}
	}

	return prunedCount, nil
}
