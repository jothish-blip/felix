package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/assessment"
)

// TestLiveExecutionHistory_AllAuthorizedTargets performs live assessment runs against
// all 5 user-authorized target environments, verifying persistent execution history records.
func TestLiveExecutionHistory_AllAuthorizedTargets(t *testing.T) {
	liveOptIn := os.Getenv("FELIX_LIVE_TESTS") == "1" || strings.ToLower(os.Getenv("FELIX_LIVE_TESTS")) == "true"
	if !liveOptIn {
		t.Skip("skipping live website assessment tests by default; set FELIX_LIVE_TESTS=1 to run against authorized live websites")
	}
	if testing.Short() {
		t.Skip("skipping live execution history test in short mode")
	}

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "felix_live_history.db")

	targets := []struct {
		name string
		url  string
	}{
		{name: "NexSpace", url: "https://nexspace.space"},
		{name: "WebJothishAnalyst", url: "https://www.webjothishanalyst.site"},
		{name: "BirthdayGreeting", url: "https://jothish-blip-birthday-for-kiranmai.vercel.app"},
		{name: "SVStackNextJS", url: "https://svstack-po-nextjs.vercel.app/"},
		{name: "HithaOne", url: "https://hithaone.svstack.com/hithaone"},
	}

	var executionIDs []string
	adminAuth := assessment.NewAdminAuthContext()

	// 1. Initial run & verification phase
	{
		store, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to initialize SQLiteStore at %s: %v", dbPath, err)
		}

		_ = store.CreateClient(&assessment.Client{
			ID:        "client-live",
			Name:      "Authorized Live Audit Client",
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		})

		ctrl := assessment.NewController(store)

		for i, tgt := range targets {
			t.Run(tgt.name, func(t *testing.T) {
				asmID := fmt.Sprintf("asm-live-%d", i+1)
				asm := &assessment.Assessment{
					ID:             asmID,
					Ref:            fmt.Sprintf("ASM-LIVE-%03d", i+1),
					ClientID:       "client-live",
					Name:           fmt.Sprintf("Live Assessment for %s", tgt.name),
					AssessmentType: "BLACK_BOX_WEB",
					Status:         assessment.StatusReady,
					ScopeMode:      "same-origin",
				}
				if err := store.CreateAssessment(asm); err != nil {
					t.Fatalf("CreateAssessment failed: %v", err)
				}

				now := time.Now().UTC()
				validFrom := now.Add(-1 * time.Hour)
				validUntil := now.Add(24 * time.Hour)
				if err := store.SetAuthorization(&assessment.AuthorizationRecord{
					ID:                  fmt.Sprintf("auth-live-%d", i+1),
					AssessmentID:        asm.ID,
					AuthorizingParty:    "Security Team (User Authorized)",
					AuthorizationMethod: "WRITTEN_CONTRACT",
					DateReceived:        validFrom,
					ValidFrom:           &validFrom,
					ValidUntil:          &validUntil,
					Status:              assessment.AuthApproved,
				}); err != nil {
					t.Fatalf("SetAuthorization failed: %v", err)
				}

				if err := store.AddTarget(&assessment.AssessmentTarget{
					ID:           fmt.Sprintf("tgt-live-%d", i+1),
					AssessmentID: asm.ID,
					TargetURL:    tgt.url,
					TargetType:   assessment.TargetWebsite,
					ScopeStatus:  "APPROVED",
				}); err != nil {
					t.Fatalf("AddTarget failed: %v", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				startTime := time.Now().UTC()
				opts := assessment.ExecutionOptions{
					TimeoutDuration:    15 * time.Second,
					Concurrency:        2,
					MaxAssets:          10,
					MaxSizeBytes:       1024 * 1024,
					UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Felix-Security-Audit/2.0",
					InsecureSkipVerify: true,
					ActiveVerification: false, // safe non-destructive audit
				}

				res, err := ctrl.RunAssessment(ctx, asm.ID, opts)
				if err != nil {
					t.Fatalf("RunAssessment failed for target %s: %v", tgt.url, err)
				}
				endTime := time.Now().UTC()

				if res.Execution == nil || res.Execution.ID == "" {
					t.Fatalf("expected Execution record in result for %s", tgt.url)
				}
				execID := res.Execution.ID
				executionIDs = append(executionIDs, execID)

				// Verify live execution history record accurately matches real outcome
				rec, err := store.GetExecutionHistory(execID, adminAuth)
				if err != nil {
					t.Fatalf("GetExecutionHistory(%s) failed: %v", execID, err)
				}

				if !assessment.IsTerminalExecutionStatus(rec.Status) {
					t.Errorf("[%s] expected terminal status, got: %s", tgt.name, rec.Status)
				}
				if rec.Status != res.Execution.Status {
					t.Errorf("[%s] record status %s != result status %s", tgt.name, rec.Status, res.Execution.Status)
				}
				if rec.StartedAt.Before(startTime.Add(-2 * time.Second)) {
					t.Errorf("[%s] StartedAt %v is before start time %v", tgt.name, rec.StartedAt, startTime)
				}
				if rec.CompletedAt == nil || rec.CompletedAt.After(endTime.Add(2*time.Second)) {
					t.Errorf("[%s] CompletedAt %v is invalid relative to end time %v", tgt.name, rec.CompletedAt, endTime)
				}
				if rec.DurationMs <= 0 {
					t.Errorf("[%s] expected positive DurationMs, got %d", tgt.name, rec.DurationMs)
				}
				if rec.TargetCount != 1 {
					t.Errorf("[%s] expected TargetCount 1, got %d", tgt.name, rec.TargetCount)
				}
				if rec.SnapshotID == "" {
					t.Errorf("[%s] expected non-empty SnapshotID linking execution record", tgt.name)
				}

				t.Logf("[%s] SUCCESS: ExecID=%s Status=%s Duration=%dms Findings=%d SnapshotID=%s",
					tgt.name, rec.ID, rec.Status, rec.DurationMs, rec.FindingCount, rec.SnapshotID)
			})
		}

		if err := store.Close(); err != nil {
			t.Fatalf("failed to close store: %v", err)
		}
	}

	// 2. Reopen store from disk and verify persistence of all 5 execution records
	{
		store, err := assessment.NewSQLiteStore(dbPath)
		if err != nil {
			t.Fatalf("failed to reopen store: %v", err)
		}
		defer store.Close()

		for i, execID := range executionIDs {
			tgtName := targets[i].name
			rec, err := store.GetExecutionHistory(execID, adminAuth)
			if err != nil {
				t.Fatalf("[%s] failed reading execution %s after DB close/reopen: %v", tgtName, execID, err)
			}

			if rec.ID != execID {
				t.Errorf("[%s] expected ID %s, got %s", tgtName, execID, rec.ID)
			}
			if !assessment.IsTerminalExecutionStatus(rec.Status) {
				t.Errorf("[%s] expected terminal status after reopen, got %s", tgtName, rec.Status)
			}
			if rec.SnapshotID == "" {
				t.Errorf("[%s] SnapshotID empty after reopen", tgtName)
			}
		}

		// Verify ListExecutionHistory returns all 5 records
		records, totalCount, err := store.ListExecutionHistory(assessment.ExecutionListOptions{
			Auth:  adminAuth,
			Limit: 20,
		})
		if err != nil {
			t.Fatalf("ListExecutionHistory failed after reopen: %v", err)
		}
		if totalCount != 5 || len(records) != 5 {
			t.Errorf("expected 5 records in history, got count=%d len=%d", totalCount, len(records))
		}
	}

	// 3. Verify CLI commands against the compiled felix executable
	{
		felixBin := filepath.Join("..", "bin", "felix.exe")
		if _, err := os.Stat(felixBin); err != nil {
			felixBin = filepath.Join("bin", "felix.exe")
		}

		// Test 'felix assessment history list --db ...'
		cmdList := exec.Command(felixBin, "assessment", "history", "list", "--db", dbPath)
		outList, err := cmdList.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI 'felix assessment history list' failed: %v, output: %s", err, string(outList))
		}
		outStr := string(outList)
		if !strings.Contains(outStr, "EXECUTION ID") || !strings.Contains(outStr, "COMPLETED") {
			t.Fatalf("CLI list output missing expected columns: %s", outStr)
		}

		// Test 'felix assessment history show <id> --db ...' for first live execution
		firstExecID := executionIDs[0]
		cmdShow := exec.Command(felixBin, "assessment", "history", "show", firstExecID, "--db", dbPath)
		outShow, err := cmdShow.CombinedOutput()
		if err != nil {
			t.Fatalf("CLI 'felix assessment history show' failed: %v, output: %s", err, string(outShow))
		}
		outShowStr := string(outShow)
		if !strings.Contains(outShowStr, firstExecID) || !strings.Contains(outShowStr, "Snapshot ID:") {
			t.Fatalf("CLI show output missing execution details: %s", outShowStr)
		}
		t.Logf("[CLI] Verified 'felix assessment history list' and 'show' successfully!")
	}
}
