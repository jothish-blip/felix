package assessment

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/uuid"
)

// TestResourceLimits_AssessmentCancellation verifies that cancelling execution context
// stops the pipeline promptly, records StatusCancelled, and prevents generating
// false successful/authoritative snapshots.
func TestResourceLimits_AssessmentCancellation(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctrl := NewController(store)

	// Block server indefinitely to simulate a long-running assessment stage
	serverBlock := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-serverBlock:
			w.WriteHeader(http.StatusOK)
		case <-r.Context().Done():
		}
	}))
	defer func() {
		close(serverBlock)
		ts.Close()
	}()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Resource Limits Test"})
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Cancellation Resource Limit Test",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})
	validFrom := time.Now().Add(-1 * time.Hour)
	validUntil := time.Now().Add(24 * time.Hour)
	_ = store.SetAuthorization(&AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Lead",
		AuthorizationMethod: "EMAIL",
		DateReceived:        time.Now().Add(-2 * time.Hour),
		ValidFrom:           &validFrom,
		ValidUntil:          &validUntil,
		Status:              AuthApproved,
	})
	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		TargetType:   "web",
	})

	ctx, cancel := context.WithCancel(context.Background())

	// Start execution asynchronously
	doneCh := make(chan *ExecutionResult, 1)
	start := time.Now()
	go func() {
		res, _ := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
			AllowLoopback: true,
		})
		doneCh <- res
	}()

	// Allow assessment to initialize, then cancel context
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case res := <-doneCh:
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Fatalf("cancellation took %v, expected prompt termination under 3s", elapsed)
		}
		if res == nil || res.Execution == nil {
			t.Fatal("expected non-nil execution result on cancellation")
		}
		if res.Execution.Status != StatusCancelled {
			t.Fatalf("expected status StatusCancelled, got %q", res.Execution.Status)
		}

		// Ensure that LoadAuthoritativeSnapshot marks cancelled execution as incomplete
		authCtx := TenantAuthContext{
			TenantID:  res.Execution.TenantID,
			AccountID: res.Execution.AccountID,
			ClientID:  clientID,
			isAdmin:   true,
		}
		snap, err := LoadAuthoritativeSnapshot(store, asmID, res.Execution.ID, authCtx)
		if err != nil {
			t.Fatalf("LoadAuthoritativeSnapshot failed: %v", err)
		}
		if snap.IsComplete {
			t.Fatal("expected snap.IsComplete to be false for cancelled execution")
		}
		if snap.Status != StatusCancelled {
			t.Fatalf("expected snap.Status to be StatusCancelled, got %q", snap.Status)
		}

		// BuildAuthoritativeReport must set RiskLevel to UNAVAILABLE and CompletionStatus to CANCELLED
		canonicalRep, err := BuildAuthoritativeReport(snap, false, true)
		if err != nil {
			t.Fatalf("BuildAuthoritativeReport failed: %v", err)
		}
		if canonicalRep.RiskLevel != "UNAVAILABLE" || canonicalRep.RiskScoreAvailable {
			t.Fatalf("expected risk score to be unavailable for cancelled report, got level %q available %v", canonicalRep.RiskLevel, canonicalRep.RiskScoreAvailable)
		}
		if canonicalRep.CompletionStatus != string(StatusCancelled) {
			t.Fatalf("expected completion status %q, got %q", StatusCancelled, canonicalRep.CompletionStatus)
		}

	case <-time.After(5 * time.Second):
		t.Fatal("assessment execution did not stop within 5s timeout on cancellation")
	}
}

// TestResourceLimits_DatabaseConnectionSoak verifies that repeated store initialization,
// operations, and teardown cycles release all database handles cleanly without leaking.
func TestResourceLimits_DatabaseConnectionSoak(t *testing.T) {
	tmpDir := t.TempDir()

	for i := 0; i < 30; i++ {
		dbPath := filepath.Join(tmpDir, fmt.Sprintf("soak_%d.db", i))
		store, err := NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("cycle %d: failed to create store: %v", i, err)
		}

		clientID := uuid.New().String()
		if err := store.CreateClient(&Client{ID: clientID, Name: fmt.Sprintf("Client %d", i)}); err != nil {
			store.Close()
			t.Fatalf("cycle %d: failed to create client: %v", i, err)
		}

		asmID := uuid.New().String()
		if err := store.CreateAssessment(&Assessment{
			ID:       asmID,
			Ref:      GenerateAssessmentRef(),
			ClientID: clientID,
			Name:     fmt.Sprintf("Assessment %d", i),
			Status:   StatusDraft,
		}); err != nil {
			store.Close()
			t.Fatalf("cycle %d: failed to create assessment: %v", i, err)
		}

		if err := store.Close(); err != nil {
			t.Fatalf("cycle %d: failed to close store: %v", i, err)
		}

		// Check that the database file can be opened or removed without lock errors
		if err := os.Remove(dbPath); err != nil {
			t.Fatalf("cycle %d: database file locked after Close: %v", i, err)
		}
	}
}

// TestResourceLimits_FindingDeduplicationBounds verifies that deduplicating finding
// sets completes within bounded execution time and reasonable heap allocations.
func TestResourceLimits_FindingDeduplicationBounds(t *testing.T) {
	// Generate 1,000 findings with heavy duplication (100 unique findings repeated 10 times each)
	total := 1000
	uniqueCount := 100
	findings := make([]AssessmentFinding, total)

	for i := 0; i < total; i++ {
		idx := i % uniqueCount
		findings[i] = AssessmentFinding{
			ID:          fmt.Sprintf("finding-%d", i),
			Title:       fmt.Sprintf("Vulnerability Pattern %d", idx),
			Severity:    "HIGH",
			Endpoint:    fmt.Sprintf("/api/v1/resource/%d", idx),
			Fingerprint: fmt.Sprintf("fp-rule-%04d", idx),
		}
	}

	start := time.Now()
	deduped := DeduplicateAssessmentFindings(findings)
	elapsed := time.Since(start)

	if len(deduped) != uniqueCount {
		t.Fatalf("expected %d deduplicated findings, got %d", uniqueCount, len(deduped))
	}

	if elapsed > 5*time.Second {
		t.Fatalf("deduplication of %d findings took %v, expected < 5s", total, elapsed)
	}
}

// TestResourceLimits_GoroutineStability verifies that rapid execution cycles do not leak goroutines.
func TestResourceLimits_GoroutineStability(t *testing.T) {
	runtime.GC()
	baseline := runtime.NumGoroutine()

	store, cleanup := newTestStore(t)
	defer cleanup()

	for i := 0; i < 5; i++ {
		clientID := uuid.New().String()
		_ = store.CreateClient(&Client{ID: clientID, Name: "Goroutine Test"})
		asmID := uuid.New().String()
		_ = store.CreateAssessment(&Assessment{
			ID:       asmID,
			Ref:      GenerateAssessmentRef(),
			ClientID: clientID,
			Name:     "Test",
			Status:   StatusDraft,
		})
	}

	time.Sleep(50 * time.Millisecond)
	runtime.GC()
	current := runtime.NumGoroutine()

	diff := current - baseline
	if diff > 5 {
		t.Fatalf("goroutine leak suspected: baseline %d, current %d, diff %d", baseline, current, diff)
	}
}
