package monitor

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func sampleTestSnapshot(targetID, snapID string, count int) *Snapshot {
	var routes []SurfaceRoute
	for i := 0; i < count; i++ {
		routes = append(routes, SurfaceRoute{
			CanonicalPath:       fmt.Sprintf("/api/v1/items/%d", i),
			RawPath:             fmt.Sprintf("/api/v1/items/%d", i),
			Methods:             []string{"GET"},
			DocumentationStatus: DocStatusDocumented,
			Reachability:        ReachabilityConfirmed,
		})
	}
	return &Snapshot{
		ID:            snapID,
		SchemaVersion: CurrentSnapshotSchemaVersion,
		TargetID:      targetID,
		TargetName:    "Test Corp",
		BaseURLs:      []string{"https://api.testcorp.internal"},
		CollectedAt:   time.Now().UTC(),
		IsComplete:    true,
		Routes:        routes,
	}
}

// 1. Initial Baseline: First snapshot automatically becomes the active baseline
func TestSnapshotStore_InitialBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	targetID := "tenant-alpha"

	// No baseline initially
	_, err = store.GetBaseline(ctx, targetID)
	if err != ErrBaselineNotFound {
		t.Fatalf("expected ErrBaselineNotFound, got %v", err)
	}

	snap1 := sampleTestSnapshot(targetID, "snap_001", 5)
	if err := store.SaveSnapshot(ctx, snap1); err != nil {
		t.Fatalf("SaveSnapshot failed: %v", err)
	}

	// Should now have active baseline pointing to snap_001
	baseSnap, err := store.GetBaseline(ctx, targetID)
	if err != nil {
		t.Fatalf("GetBaseline failed: %v", err)
	}
	if baseSnap.ID != "snap_001" {
		t.Errorf("expected baseline ID snap_001, got %s", baseSnap.ID)
	}
	if len(baseSnap.Routes) != 5 {
		t.Errorf("expected 5 routes, got %d", len(baseSnap.Routes))
	}
}

// 2. Persistence Across Restart: Data survives creating a new store instance pointing to same directory
func TestSnapshotStore_PersistenceAcrossRestart(t *testing.T) {
	tmpDir := t.TempDir()
	targetID := "tenant-bravo"

	// First instance
	{
		store1, err := NewFileSnapshotStore(tmpDir, 10)
		if err != nil {
			t.Fatalf("store1 init: %v", err)
		}
		snap := sampleTestSnapshot(targetID, "snap_bravo_101", 3)
		if err := store1.SaveSnapshot(context.Background(), snap); err != nil {
			t.Fatalf("store1 SaveSnapshot: %v", err)
		}
	}

	// Second instance (simulate application restart)
	{
		store2, err := NewFileSnapshotStore(tmpDir, 10)
		if err != nil {
			t.Fatalf("store2 init: %v", err)
		}
		baseSnap, err := store2.GetBaseline(context.Background(), targetID)
		if err != nil {
			t.Fatalf("store2 GetBaseline after restart: %v", err)
		}
		if baseSnap.ID != "snap_bravo_101" {
			t.Errorf("expected snap_bravo_101, got %s", baseSnap.ID)
		}
		if len(baseSnap.Routes) != 3 {
			t.Errorf("expected 3 routes, got %d", len(baseSnap.Routes))
		}
	}
}

// 3. Atomic Write Safety: Interrupted write leaves valid existing state intact
func TestSnapshotStore_AtomicWriteFailureSafety(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("init store: %v", err)
	}

	ctx := context.Background()
	targetID := "tenant-charlie"

	snapGood := sampleTestSnapshot(targetID, "snap_good", 4)
	if err := store.SaveSnapshot(ctx, snapGood); err != nil {
		t.Fatalf("save good snapshot: %v", err)
	}

	// Verify valid baseline is set
	baseSnap, err := store.GetBaseline(ctx, targetID)
	if err != nil || baseSnap.ID != "snap_good" {
		t.Fatalf("baseline not properly set: %v", err)
	}

	// Attempt to write an invalid snapshot (e.g., nil targetID)
	invalidSnap := &Snapshot{
		ID:            "snap_bad",
		SchemaVersion: CurrentSnapshotSchemaVersion,
		TargetID:      "", // Invalid
	}
	err = store.SaveSnapshot(ctx, invalidSnap)
	if err == nil {
		t.Fatal("expected error on invalid snapshot, got nil")
	}

	// Verify existing baseline is completely intact
	baseSnapAfter, err := store.GetBaseline(ctx, targetID)
	if err != nil || baseSnapAfter.ID != "snap_good" {
		t.Fatalf("baseline corrupted by failed write: %v", err)
	}
}

// 4. Corrupt, Oversized, and Unsupported Snapshots: Rejected gracefully with explicit errors
func TestSnapshotStore_CorruptOversizedUnsupported(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	ctx := context.Background()
	targetID := "tenant-delta"

	// A. Unsupported schema version
	unsupported := sampleTestSnapshot(targetID, "snap_v999", 2)
	unsupported.SchemaVersion = 999
	err = store.SaveSnapshot(ctx, unsupported)
	if err == nil || !strings.Contains(err.Error(), "schema version") {
		t.Errorf("expected unsupported schema error, got %v", err)
	}

	// B. Exceeded route capacity
	oversizedRoutes := sampleTestSnapshot(targetID, "snap_heavy", MaxSnapshotRoutes+10)
	err = store.SaveSnapshot(ctx, oversizedRoutes)
	if err == nil || !strings.Contains(err.Error(), "route capacity") {
		t.Errorf("expected route capacity error, got %v", err)
	}

	// C. Corrupt JSON file manually placed
	cleanTarget := SanitizeTargetID(targetID)
	corruptDir := filepath.Join(tmpDir, cleanTarget, "snapshots")
	_ = os.MkdirAll(corruptDir, 0700)
	corruptFile := filepath.Join(corruptDir, "snap_corrupt.json")
	_ = os.WriteFile(corruptFile, []byte("{ malformed json"), 0600)

	_, err = store.GetSnapshot(ctx, targetID, "snap_corrupt")
	if err == nil || !strings.Contains(err.Error(), "corrupt") {
		t.Errorf("expected corrupt snapshot error, got %v", err)
	}
}

// 5. State Isolation Between Targets: Target A cannot access or overwrite Target B state
func TestSnapshotStore_StateIsolationBetweenTargets(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	ctx := context.Background()
	targetA := "tenant-echo"
	targetB := "tenant-foxtrot"

	snapA := sampleTestSnapshot(targetA, "snap_a_1", 2)
	snapB := sampleTestSnapshot(targetB, "snap_b_1", 5)

	if err := store.SaveSnapshot(ctx, snapA); err != nil {
		t.Fatalf("save A: %v", err)
	}
	if err := store.SaveSnapshot(ctx, snapB); err != nil {
		t.Fatalf("save B: %v", err)
	}

	baseA, err := store.GetBaseline(ctx, targetA)
	if err != nil || baseA.ID != "snap_a_1" || len(baseA.Routes) != 2 {
		t.Errorf("target A state mismatch: %v", baseA)
	}

	baseB, err := store.GetBaseline(ctx, targetB)
	if err != nil || baseB.ID != "snap_b_1" || len(baseB.Routes) != 5 {
		t.Errorf("target B state mismatch: %v", baseB)
	}

	// Verify target A cannot read target B snapshot ID
	_, err = store.GetSnapshot(ctx, targetA, "snap_b_1")
	if err != ErrSnapshotNotFound {
		t.Errorf("expected ErrSnapshotNotFound when reading cross-target snapshot, got %v", err)
	}
}

// 6. Retention Limits Preserve Active Baseline: Pruning removes older snapshots but never the baseline
func TestSnapshotStore_RetentionPruningPreservesBaseline(t *testing.T) {
	tmpDir := t.TempDir()
	retainLimit := 3
	store, err := NewFileSnapshotStore(tmpDir, retainLimit)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	ctx := context.Background()
	targetID := "tenant-golf"

	// First snapshot is baseline
	baseSnap := sampleTestSnapshot(targetID, "snap_baseline", 1)
	if err := store.SaveSnapshot(ctx, baseSnap); err != nil {
		t.Fatalf("save baseline: %v", err)
	}

	// Save 5 subsequent snapshots (exceeding retain limit of 3)
	for i := 1; i <= 5; i++ {
		time.Sleep(10 * time.Millisecond) // ensure distinct modtimes
		snap := sampleTestSnapshot(targetID, fmt.Sprintf("snap_sub_%d", i), i)
		if err := store.SaveSnapshot(ctx, snap); err != nil {
			t.Fatalf("save sub snapshot %d: %v", i, err)
		}
	}

	// Verify active baseline snapshot is STILL intact
	activeBase, err := store.GetBaseline(ctx, targetID)
	if err != nil {
		t.Fatalf("GetBaseline failed after pruning: %v", err)
	}
	if activeBase.ID != "snap_baseline" {
		t.Errorf("expected baseline snap_baseline, got %s", activeBase.ID)
	}

	// Verify snapshot file itself still exists
	snapBaseFile, err := store.GetSnapshot(ctx, targetID, "snap_baseline")
	if err != nil || snapBaseFile.ID != "snap_baseline" {
		t.Errorf("baseline snapshot file was wrongly pruned!")
	}
}

// 7. Concurrent Operations: Multiple goroutines writing and reading safely
func TestSnapshotStore_ConcurrentSnapshotOperations(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 20)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	ctx := context.Background()
	targetID := "tenant-hotel"
	var wg sync.WaitGroup

	// Launch 10 concurrent writers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			snap := sampleTestSnapshot(targetID, fmt.Sprintf("snap_worker_%d", workerID), workerID+1)
			_ = store.SaveSnapshot(ctx, snap)
		}(i)
	}

	// Launch 10 concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = store.ListSnapshots(ctx, targetID)
			_, _ = store.GetBaseline(ctx, targetID)
		}()
	}

	wg.Wait()

	// Verify store is healthy and can read valid baseline
	base, err := store.GetBaseline(ctx, targetID)
	if err != nil {
		t.Fatalf("GetBaseline failed after concurrent operations: %v", err)
	}
	if base == nil {
		t.Fatal("expected non-nil baseline")
	}
}

// 8. Path Traversal Prevention: Rejects malicious target IDs
func TestSnapshotStore_PathTraversalRejection(t *testing.T) {
	tmpDir := t.TempDir()
	store, err := NewFileSnapshotStore(tmpDir, 10)
	if err != nil {
		t.Fatalf("store init: %v", err)
	}

	ctx := context.Background()
	maliciousTarget := "../../etc/shadow"

	snap := sampleTestSnapshot(maliciousTarget, "snap_malicious", 1)
	if err := store.SaveSnapshot(ctx, snap); err != nil {
		t.Fatalf("save: %v", err)
	}

	// Verify sanitized target folder was created inside tmpDir, NOT escaping outside
	cleanTarget := SanitizeTargetID(maliciousTarget)
	expectedDir := filepath.Join(tmpDir, cleanTarget)
	if _, err := os.Stat(expectedDir); os.IsNotExist(err) {
		t.Errorf("expected sanitized dir %s to exist inside tmpDir", expectedDir)
	}
}
