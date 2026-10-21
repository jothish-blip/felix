package compliance

import (
	"context"
	"errors"
	"testing"
	"time"
)

// ============================================================================
// CONCERN 1: EPISODE BOUNDARIES AND LIFECYCLE COMPLETENESS
// ============================================================================

func TestMTTR_Concern1_InitialAssignmentAndStartTimeSelection(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)

	baseTime := clock.Now().UTC()

	// Case A: SLAStartTime is earlier than AssignedAt (e.g. scanner discovery time)
	// Expected: StartTime should be authoritative SLAStartTime.
	earlySLA := baseTime.Add(-2 * time.Hour)
	recA := &RemediationRecord{
		ID:           "rem:start:A",
		FindingID:    "F-START-A",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: earlySLA,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(10 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(recA, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(recA.ID),
		RemediationID: recA.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(recA, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(recA.ID),
		RemediationID: recA.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(10 * time.Hour),
	})

	// Case B: SLAStartTime is zero (unspecified)
	// Expected: StartTime falls back to verified assignment event timestamp.
	recB := &RemediationRecord{
		ID:          "rem:start:B",
		FindingID:   "F-START-B",
		Severity:    "HIGH",
		AssignedAt:  baseTime,
		Deadline:    baseTime.Add(7 * 24 * time.Hour),
		Status:      RemediationStatusRemediated,
		CompletedAt: &[]time.Time{baseTime.Add(10 * time.Hour)}[0],
		CreatedAt:   baseTime,
	}
	_ = store.SaveRemediationRecord(recB, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(recB.ID),
		RemediationID: recB.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(recB, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(recB.ID),
		RemediationID: recB.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(10 * time.Hour),
	})

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if res.CompletedEpisodes != 2 {
		t.Fatalf("expected 2 completed episodes, got %d", res.CompletedEpisodes)
	}

	var epA, epB *RemediationEpisode
	for i := range res.Episodes {
		if res.Episodes[i].FindingID == "F-START-A" {
			epA = &res.Episodes[i]
		}
		if res.Episodes[i].FindingID == "F-START-B" {
			epB = &res.Episodes[i]
		}
	}

	if epA == nil || epB == nil {
		t.Fatalf("missing expected episodes")
	}

	// EpA: from earlySLA (-2h) to +10h = 12h
	if epA.Duration != 12*time.Hour {
		t.Errorf("epA duration expected 12h, got %v", epA.Duration)
	}
	if !epA.StartTime.Equal(earlySLA) {
		t.Errorf("epA start time expected %v, got %v", earlySLA, epA.StartTime)
	}

	// EpB: from baseTime (0h) to +10h = 10h
	if epB.Duration != 10*time.Hour {
		t.Errorf("epB duration expected 10h, got %v", epB.Duration)
	}
	if !epB.StartTime.Equal(baseTime) {
		t.Errorf("epB start time expected %v, got %v", baseTime, epB.StartTime)
	}
}

func TestMTTR_Concern1_MultipleCompletionReopenCycles(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding F-MULTI has 3 non-overlapping remediation cycles:
	// Cycle 0: [0h, 10h] -> duration 10h
	// Cycle 1: Reopened at 20h, remediated at 40h -> duration 20h
	// Cycle 2: Reopened at 60h, remediated at 90h -> duration 30h
	remID := "rem:multi:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-MULTI",
		FindingTitle: "Recurring Insecure Direct Object Reference",
		Severity:     "CRITICAL",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(24 * time.Hour),
		Status:       RemediationStatusRemediated,
		ReopenCount:  2,
		CreatedAt:    baseTime,
	}

	events := []RemediationHistoryEvent{
		// Cycle 0
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(10 * time.Hour),
		},
		// Cycle 1
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventReopened,
			FromStatus:    RemediationStatusRemediated,
			ToStatus:      RemediationStatusReopened,
			Timestamp:     baseTime.Add(20 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusReopened,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(40 * time.Hour),
		},
		// Cycle 2
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventReopened,
			FromStatus:    RemediationStatusRemediated,
			ToStatus:      RemediationStatusReopened,
			Timestamp:     baseTime.Add(60 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusReopened,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(90 * time.Hour),
		},
	}

	for _, e := range events {
		_ = store.SaveRemediationRecord(rec, &e)
	}

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if res.CompletedEpisodes != 3 {
		t.Errorf("expected 3 completed episodes, got %d", res.CompletedEpisodes)
	}
	if res.UniqueFindings != 1 {
		t.Errorf("expected 1 unique finding, got %d", res.UniqueFindings)
	}
	// Total duration: 10h + 20h + 30h = 60h
	if res.TotalDuration != 60*time.Hour {
		t.Errorf("expected 60h total duration, got %v", res.TotalDuration)
	}
	// Mean duration: 60h / 3 = 20h
	if res.MTTR != 20*time.Hour {
		t.Errorf("expected 20h MTTR, got %v", res.MTTR)
	}
	if res.MedianDuration == nil || *res.MedianDuration != 20*time.Hour {
		t.Errorf("expected 20h median duration, got %v", res.MedianDuration)
	}

	// Verify cycles and non-overlapping boundaries
	for i, exp := range []struct {
		cycle    int
		duration time.Duration
	}{
		{0, 10 * time.Hour},
		{1, 20 * time.Hour},
		{2, 30 * time.Hour},
	} {
		if res.Episodes[i].Cycle != exp.cycle {
			t.Errorf("episode %d expected cycle %d, got %d", i, exp.cycle, res.Episodes[i].Cycle)
		}
		if res.Episodes[i].Duration != exp.duration {
			t.Errorf("episode %d expected duration %v, got %v", i, exp.duration, res.Episodes[i].Duration)
		}
	}
}

func TestMTTR_Concern1_AcceptedRisk_Revocation_AndSubsequentRemediation(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding F-RISK-1: Assigned at 0h, RiskAccepted at 10h, RiskRevoked at 40h, Remediated at 55h.
	// The 30h period while risk was accepted MUST NOT count as remediation duration.
	// Only episode [40h, 55h] (duration 15h) is recorded.
	remID := "rem:risk:1"
	rec1 := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-RISK-1",
		Severity:     "MEDIUM",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(30 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events1 := []RemediationHistoryEvent{
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventRiskAccepted,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusAcceptedRisk,
			Timestamp:     baseTime.Add(10 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventRiskRevoked,
			FromStatus:    RemediationStatusAcceptedRisk,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime.Add(40 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(55 * time.Hour),
		},
	}

	for _, e := range events1 {
		_ = store.SaveRemediationRecord(rec1, &e)
	}

	// Finding F-RISK-2: Contradictory event sequence!
	// Risk is accepted, and then transitioned DIRECTLY to Remediated without RiskRevocation.
	// This contradiction must be rejected and tracked as an invalid episode.
	remID2 := "rem:risk:2"
	rec2 := &RemediationRecord{
		ID:           remID2,
		FindingID:    "F-RISK-2",
		Severity:     "LOW",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(90 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events2 := []RemediationHistoryEvent{
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventRiskAccepted,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusAcceptedRisk,
			Timestamp:     baseTime.Add(5 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusAcceptedRisk,
			ToStatus:      RemediationStatusRemediated, // ILLEGAL transition while in risk!
			Timestamp:     baseTime.Add(20 * time.Hour),
		},
	}

	for _, e := range events2 {
		_ = store.SaveRemediationRecord(rec2, &e)
	}

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	// Only F-RISK-1 episode should be included
	if res.CompletedEpisodes != 1 {
		t.Errorf("expected 1 completed episode, got %d", res.CompletedEpisodes)
	}
	if res.Episodes[0].FindingID != "F-RISK-1" {
		t.Errorf("expected finding F-RISK-1, got %s", res.Episodes[0].FindingID)
	}
	if res.Episodes[0].Duration != 15*time.Hour {
		t.Errorf("expected 15h duration, got %v", res.Episodes[0].Duration)
	}

	// F-RISK-2 should be tracked under InvalidTimestamps
	if res.Exclusions.InvalidTimestamps != 1 {
		t.Errorf("expected 1 InvalidTimestamps exclusion for illegal risk->remediated transition, got %d", res.Exclusions.InvalidTimestamps)
	}
}

func TestMTTR_Concern1_ContradictoryLifecycleEvents(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding F-CONTRA-1: Reopened while still Open!
	// Cannot reopen a finding that is already actively open.
	remID1 := "rem:contra:1"
	rec1 := &RemediationRecord{
		ID:           remID1,
		FindingID:    "F-CONTRA-1",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events1 := []RemediationHistoryEvent{
		{
			ID:            GenerateRemediationEventID(remID1),
			RemediationID: remID1,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            GenerateRemediationEventID(remID1),
			RemediationID: remID1,
			EventType:     HistoryEventReopened, // Contradictory: already open!
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusReopened,
			Timestamp:     baseTime.Add(2 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID1),
			RemediationID: remID1,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(10 * time.Hour),
		},
	}

	for _, e := range events1 {
		_ = store.SaveRemediationRecord(rec1, &e)
	}

	// Finding F-CONTRA-2: RiskRevoked when risk was never accepted!
	remID2 := "rem:contra:2"
	rec2 := &RemediationRecord{
		ID:           remID2,
		FindingID:    "F-CONTRA-2",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events2 := []RemediationHistoryEvent{
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventRiskRevoked, // Contradictory: not in risk!
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime.Add(3 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID2),
			RemediationID: remID2,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(12 * time.Hour),
		},
	}

	for _, e := range events2 {
		_ = store.SaveRemediationRecord(rec2, &e)
	}

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	// Both records contain 1 invalid contradictory event each
	if res.Exclusions.InvalidTimestamps != 2 {
		t.Errorf("expected 2 InvalidTimestamps exclusions for contradictory events, got %d", res.Exclusions.InvalidTimestamps)
	}
}

func TestMTTR_Concern1_OutOrder_And_CompletionBeforeStart(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding F-OUT-1: Completion timestamp precedes start timestamp (negative duration!)
	remID1 := "rem:out:1"
	rec1 := &RemediationRecord{
		ID:           remID1,
		FindingID:    "F-OUT-1",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	// Assigned at baseTime, Remediated at baseTime - 5h (completion before start!)
	_ = store.SaveRemediationRecord(rec1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID1),
		RemediationID: remID1,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rec1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID1),
		RemediationID: remID1,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(-5 * time.Hour), // Precedes start!
	})

	// Finding F-OUT-2: Remediated event appears before Assigned event without prior start
	remID2 := "rem:out:2"
	rec2 := &RemediationRecord{
		ID:           remID2,
		FindingID:    "F-OUT-2",
		Severity:     "HIGH",
		AssignedAt:   baseTime.Add(10 * time.Hour),
		SLAStartTime: baseTime.Add(10 * time.Hour),
		Deadline:     baseTime.Add(17 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rec2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID2),
		RemediationID: remID2,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime, // At baseTime, before assignment at baseTime + 10h!
	})

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if res.CompletedEpisodes != 0 {
		t.Errorf("expected 0 completed episodes, got %d", res.CompletedEpisodes)
	}
	if res.Exclusions.InvalidTimestamps != 2 {
		t.Errorf("expected 2 InvalidTimestamps exclusions, got %d", res.Exclusions.InvalidTimestamps)
	}
}

func TestMTTR_Concern1_HistoricalRecordsLackingVerifiedStartEvent(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding F-NOSTART-1: Record has remediated status, but history contains NO start event (only a completion event)
	remID1 := "rem:nostart:1"
	rec1 := &RemediationRecord{
		ID:          remID1,
		FindingID:   "F-NOSTART-1",
		Severity:    "HIGH",
		Status:      RemediationStatusRemediated,
		CompletedAt: &[]time.Time{baseTime.Add(5 * time.Hour)}[0],
		CreatedAt:   baseTime,
	}
	_ = store.SaveRemediationRecord(rec1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID1),
		RemediationID: remID1,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(5 * time.Hour),
	})

	// Finding F-NOSTART-2: History event contains zero timestamp (0001-01-01)
	remID2 := "rem:nostart:2"
	rec2 := &RemediationRecord{
		ID:          remID2,
		FindingID:   "F-NOSTART-2",
		Severity:    "HIGH",
		Status:      RemediationStatusRemediated,
		CompletedAt: &[]time.Time{baseTime.Add(5 * time.Hour)}[0],
		CreatedAt:   baseTime,
	}
	_ = store.SaveRemediationRecord(rec2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID2),
		RemediationID: remID2,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     time.Time{}, // Zero timestamp!
	})
	_ = store.SaveRemediationRecord(rec2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID2),
		RemediationID: remID2,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(5 * time.Hour),
	})

	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if res.CompletedEpisodes != 0 {
		t.Errorf("expected 0 completed episodes, got %d", res.CompletedEpisodes)
	}
	// Neither record had a defensible start event; both must be excluded with explicit counts
	totalExcluded := res.Exclusions.InvalidTimestamps + res.Exclusions.MissingHistory
	if totalExcluded != 2 {
		t.Errorf("expected 2 excluded records lacking verified start, got %d (invalid=%d, missing=%d)",
			totalExcluded, res.Exclusions.InvalidTimestamps, res.Exclusions.MissingHistory)
	}
}

// ============================================================================
// CONCERN 2: INTEGRITY VERIFICATION OF MTTR SOURCE DATA
// ============================================================================

func TestMTTR_Concern2_RemediationRecordTampering(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, err := GenerateIntegrityKey("mttr-tamper-key")
	if err != nil {
		t.Fatalf("GenerateIntegrityKey failed: %v", err)
	}
	kp, _ := NewStaticKeyProvider(key)

	remID := "rem:tamper:rec:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-TAMPER-REC",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(14 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	err = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	if err != nil {
		t.Fatalf("SaveRemediationRecordWithKey failed: %v", err)
	}
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(14 * time.Hour),
	}, kp)

	// Step 1: Verify intact record passes verification
	verBefore, err := store.VerifyRemediationIntegrity(remID, kp)
	if err != nil || verBefore.Status != StatusVerified {
		t.Fatalf("initial verification failed: status=%v err=%v", verBefore.Status, err)
	}

	// Step 2: Tamper with sla_start_time in SQLite
	tamperedTime := baseTime.Add(5 * time.Hour).Format(time.RFC3339Nano)
	_, err = store.db.Exec("UPDATE compliance_remediation_records SET sla_start_time = ? WHERE id = ?", tamperedTime, remID)
	if err != nil {
		t.Fatalf("db tamper failed: %v", err)
	}

	// Step 3: VerifyRemediationIntegrity must detect canonical digest mismatch
	verAfter, err := store.VerifyRemediationIntegrity(remID, kp)
	if err != nil {
		t.Fatalf("VerifyRemediationIntegrity returned error: %v", err)
	}
	if verAfter.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch, got %v", verAfter.Status)
	}

	// Step 4: MTTR default mode excludes the tampered record and reports partial coverage
	resDefault, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR default mode failed: %v", err)
	}
	if resDefault.CompletedEpisodes != 0 {
		t.Errorf("expected tampered record to be excluded; got %d episodes", resDefault.CompletedEpisodes)
	}
	if resDefault.Exclusions.IntegrityFailures != 1 {
		t.Errorf("expected 1 IntegrityFailures exclusion, got %d", resDefault.Exclusions.IntegrityFailures)
	}

	// Step 5: MTTR strict mode fails closed with ErrIntegrityMismatch
	_, strictErr := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if strictErr == nil {
		t.Fatalf("expected strict mode to fail closed, got nil error")
	}
	if !errors.Is(strictErr, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch, got %v", strictErr)
	}
}

func TestMTTR_Concern2_HistoryEventTampering(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("mttr-hist-key")
	kp, _ := NewStaticKeyProvider(key)

	remID := "rem:tamper:hist:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-TAMPER-HIST",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(20 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	evtID := GenerateRemediationEventID(remID)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            evtID,
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(20 * time.Hour),
	}, kp)

	// Tamper with history event timestamp directly in SQLite
	tamperedTimestamp := baseTime.Add(-10 * time.Hour).Format(time.RFC3339Nano)
	_, err := store.db.Exec("UPDATE compliance_remediation_history SET timestamp = ? WHERE id = ?", tamperedTimestamp, evtID)
	if err != nil {
		t.Fatalf("db tamper failed: %v", err)
	}

	// Verify tampering is detected
	ver, err := store.VerifyRemediationIntegrity(remID, kp)
	if err != nil {
		t.Fatalf("VerifyRemediationIntegrity failed: %v", err)
	}
	if ver.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for tampered history timestamp, got %v", ver.Status)
	}

	// Strict mode MTTR fails closed
	_, err = svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if err == nil || !errors.Is(err, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch on strict MTTR, got %v", err)
	}
}

func TestMTTR_Concern2_HistoryRowDeletion(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("mttr-del-key")
	kp, _ := NewStaticKeyProvider(key)

	remID := "rem:tamper:del:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-TAMPER-DEL",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(15 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	evtID := GenerateRemediationEventID(remID)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            evtID,
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(15 * time.Hour),
	}, kp)

	// Delete the assigned history row directly from SQLite
	_, err := store.db.Exec("DELETE FROM compliance_remediation_history WHERE id = ?", evtID)
	if err != nil {
		t.Fatalf("db delete failed: %v", err)
	}

	ver, err := store.VerifyRemediationIntegrity(remID, kp)
	if err != nil {
		t.Fatalf("VerifyRemediationIntegrity failed: %v", err)
	}
	if ver.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch for deleted history event row, got %v", ver.Status)
	}

	// MTTR default mode excludes the record
	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}
	if res.CompletedEpisodes != 0 || res.Exclusions.IntegrityFailures != 1 {
		t.Errorf("expected record excluded with IntegrityFailures=1, got episodes=%d failures=%d",
			res.CompletedEpisodes, res.Exclusions.IntegrityFailures)
	}
}

func TestMTTR_Concern2_IntegrityRowDeletion(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("mttr-delint-key")
	kp, _ := NewStaticKeyProvider(key)

	remID := "rem:tamper:delint:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-TAMPER-DELINT",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(8 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)

	// Delete the integrity row from compliance_remediation_integrity_records
	// Since rec has integrity_version set, it MUST NOT be misclassified as legacy!
	_, err := store.db.Exec("DELETE FROM compliance_remediation_integrity_records WHERE remediation_id = ?", remID)
	if err != nil {
		t.Fatalf("db delete failed: %v", err)
	}

	ver, err := store.VerifyRemediationIntegrity(remID, kp)
	if err != nil {
		t.Fatalf("VerifyRemediationIntegrity failed: %v", err)
	}
	if ver.Status != StatusIntegrityMismatch {
		t.Errorf("expected StatusIntegrityMismatch (NOT legacy) when integrity row is deleted, got %v", ver.Status)
	}

	// MTTR strict mode fails closed
	_, err = svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if err == nil || !errors.Is(err, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch on strict MTTR, got %v", err)
	}
}

func TestMTTR_Concern2_ForgedEvaluationAssociation(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("mttr-assoc-key")
	kp, _ := NewStaticKeyProvider(key)

	// Persist genuine evaluation result that only evaluated finding "F-BOLA-01" under control "AC-3"
	evalRes := sampleValidEvaluationResult("ASM-FORGE-TEST")
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// Create remediation record claiming AssessmentID "ASM-FORGE-TEST" and ControlID "AC-3",
	// but with a forged/spoofed finding ID "F-FORGED-SPOOF" that was NEVER evaluated!
	remID := "rem:forged:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-FORGED-SPOOF", // SPOOFED!
		AssessmentID: "ASM-FORGE-TEST",
		CatalogID:    "nist-sp800-53-sample:5.1.0",
		ControlID:    "AC-3",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(5 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(5 * time.Hour),
	}, kp)

	// Case A: Default MTTR excludes the forged association
	resDefault, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}
	if resDefault.CompletedEpisodes != 0 {
		t.Errorf("expected forged association to be excluded; got %d episodes", resDefault.CompletedEpisodes)
	}
	if resDefault.Exclusions.IntegrityFailures != 1 {
		t.Errorf("expected 1 IntegrityFailures exclusion for forged association, got %d", resDefault.Exclusions.IntegrityFailures)
	}

	// Case B: Strict MTTR fails closed with ErrIntegrityMismatch
	_, strictErr := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if strictErr == nil || !errors.Is(strictErr, ErrIntegrityMismatch) {
		t.Errorf("expected strict MTTR to fail closed with ErrIntegrityMismatch on forged association, got %v", strictErr)
	}
}

func TestMTTR_Concern2_CacheIsolation(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	key, _ := GenerateIntegrityKey("mttr-cache-key")
	kp, _ := NewStaticKeyProvider(key)

	// Create genuine evaluation containing TWO findings under control AC-3
	evalRes := sampleValidEvaluationResult("ASM-SHARED-EVAL")
	evalRes.Evaluations[0].FindingIDs = []string{"F-GOOD", "F-BAD"}

	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// Record A (Good): Valid integrity, valid association
	remIDA := "rem:cache:good"
	recA := &RemediationRecord{
		ID:           remIDA,
		FindingID:    "F-GOOD",
		AssessmentID: "ASM-SHARED-EVAL",
		CatalogID:    "nist-sp800-53-sample:5.1.0",
		ControlID:    "AC-3",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(10 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(recA, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remIDA),
		RemediationID: remIDA,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(recA, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remIDA),
		RemediationID: remIDA,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(10 * time.Hour),
	}, kp)

	// Record B (Bad): Tampered in database!
	remIDB := "rem:cache:bad"
	recB := &RemediationRecord{
		ID:           remIDB,
		FindingID:    "F-BAD",
		AssessmentID: "ASM-SHARED-EVAL",
		CatalogID:    "nist-sp800-53-sample:5.1.0",
		ControlID:    "AC-3",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(20 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecordWithKey(recB, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remIDB),
		RemediationID: remIDB,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}, kp)
	_ = store.SaveRemediationRecordWithKey(recB, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remIDB),
		RemediationID: remIDB,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(20 * time.Hour),
	}, kp)

	// Tamper Record B in SQLite directly
	_, err := store.db.Exec("UPDATE compliance_remediation_records SET sla_start_time = ? WHERE id = ?",
		baseTime.Add(-50*time.Hour).Format(time.RFC3339Nano), remIDB)
	if err != nil {
		t.Fatalf("db tamper failed: %v", err)
	}

	// Calculate MTTR in default mode
	res, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	// Cache isolation check:
	// Record A must pass and produce 1 completed episode (10h).
	// Record B must FAIL integrity check and NOT pass simply because parent evaluation ASM-SHARED-EVAL was cached as valid!
	if res.CompletedEpisodes != 1 {
		t.Errorf("expected exactly 1 completed episode (RecA only), got %d", res.CompletedEpisodes)
	}
	if len(res.Episodes) > 0 && res.Episodes[0].FindingID != "F-GOOD" {
		t.Errorf("expected episode from F-GOOD, got %s", res.Episodes[0].FindingID)
	}
	if res.Exclusions.IntegrityFailures != 1 {
		t.Errorf("expected exactly 1 IntegrityFailure exclusion (RecB), got %d", res.Exclusions.IntegrityFailures)
	}
	if res.CoverageStatus != "PARTIAL" {
		t.Errorf("expected CoverageStatus PARTIAL due to tampered record exclusion, got %s", res.CoverageStatus)
	}

	// In strict mode: entire calculation fails closed due to tampered RecB
	_, strictErr := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if strictErr == nil || !errors.Is(strictErr, ErrIntegrityMismatch) {
		t.Errorf("expected strict MTTR to fail closed with ErrIntegrityMismatch on tampered RecB, got %v", strictErr)
	}
}
