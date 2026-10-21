package compliance

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// Helper to create an in-memory SQLite store for MTTR testing
func setupTestMTTRStore(t *testing.T) *SQLiteComplianceStore {
	t.Helper()
	store, err := NewSQLiteComplianceStore(":memory:")
	if err != nil {
		t.Fatalf("failed creating test sqlite store: %v", err)
	}
	return store
}

func TestMTTR_1_SingleEpisode(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)

	baseTime := clock.Now().UTC()
	rec := &RemediationRecord{
		ID:           "rem:1",
		FindingID:    "F-1",
		FindingTitle: "SQL Injection",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		TimeBasis:    "ELAPSED_TIME",
		Status:       RemediationStatusRemediated,
		CompletedAt:  &[]time.Time{baseTime.Add(24 * time.Hour)}[0],
		CreatedAt:    baseTime,
	}

	hist := []RemediationHistoryEvent{
		{
			ID:            "ev:1",
			RemediationID: "rem:1",
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		},
		{
			ID:            "ev:2",
			RemediationID: "rem:1",
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(24 * time.Hour),
		},
	}

	for _, h := range hist {
		if err := store.SaveRemediationRecord(rec, &h); err != nil {
			t.Fatalf("SaveRemediationRecord failed: %v", err)
		}
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if !result.HasData {
		t.Fatalf("expected HasData true, got false")
	}
	if result.CompletedEpisodes != 1 {
		t.Errorf("expected 1 completed episode, got %d", result.CompletedEpisodes)
	}
	if result.UniqueFindings != 1 {
		t.Errorf("expected 1 unique finding, got %d", result.UniqueFindings)
	}
	if result.MTTR != 24*time.Hour {
		t.Errorf("expected MTTR 24h, got %v", result.MTTR)
	}
	if result.TotalDuration != 24*time.Hour {
		t.Errorf("expected TotalDuration 24h, got %v", result.TotalDuration)
	}
	if result.MinDuration == nil || *result.MinDuration != 24*time.Hour {
		t.Errorf("expected MinDuration 24h, got %v", result.MinDuration)
	}
	if result.MaxDuration == nil || *result.MaxDuration != 24*time.Hour {
		t.Errorf("expected MaxDuration 24h, got %v", result.MaxDuration)
	}
	if result.MedianDuration == nil || *result.MedianDuration != 24*time.Hour {
		t.Errorf("expected MedianDuration 24h, got %v", result.MedianDuration)
	}
}

func TestMTTR_2_MultipleEpisodes_ArithmeticMeanAndMedian(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Create 3 findings with durations: 10h, 20h, 60h
	// Mean = (10 + 20 + 60) / 3 = 30h
	// Median = 20h
	durations := []time.Duration{10 * time.Hour, 20 * time.Hour, 60 * time.Hour}

	for i, dur := range durations {
		remID := fmt.Sprintf("rem:multi:%d", i+1)
		fID := fmt.Sprintf("F-MULTI-%d", i+1)
		rec := &RemediationRecord{
			ID:           remID,
			FindingID:    fID,
			Severity:     "HIGH",
			AssignedAt:   baseTime,
			SLAStartTime: baseTime,
			Deadline:     baseTime.Add(7 * 24 * time.Hour),
			TimeBasis:    "ELAPSED_TIME",
			Status:       RemediationStatusRemediated,
			CreatedAt:    baseTime,
		}

		evtAssign := &RemediationHistoryEvent{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventAssigned,
			ToStatus:      RemediationStatusOpen,
			Timestamp:     baseTime,
		}
		if err := store.SaveRemediationRecord(rec, evtAssign); err != nil {
			t.Fatalf("SaveRemediationRecord assign failed: %v", err)
		}

		evtDone := &RemediationHistoryEvent{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusOpen,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(dur),
		}
		if err := store.SaveRemediationRecord(rec, evtDone); err != nil {
			t.Fatalf("SaveRemediationRecord done failed: %v", err)
		}
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.CompletedEpisodes != 3 {
		t.Fatalf("expected 3 completed episodes, got %d", result.CompletedEpisodes)
	}
	if result.UniqueFindings != 3 {
		t.Fatalf("expected 3 unique findings, got %d", result.UniqueFindings)
	}
	if result.TotalDuration != 90*time.Hour {
		t.Errorf("expected total duration 90h, got %v", result.TotalDuration)
	}
	if result.MTTR != 30*time.Hour {
		t.Errorf("expected MTTR 30h, got %v", result.MTTR)
	}
	if result.MedianDuration == nil || *result.MedianDuration != 20*time.Hour {
		t.Errorf("expected median 20h, got %v", result.MedianDuration)
	}
	if result.MinDuration == nil || *result.MinDuration != 10*time.Hour {
		t.Errorf("expected min 10h, got %v", result.MinDuration)
	}
	if result.MaxDuration == nil || *result.MaxDuration != 60*time.Hour {
		t.Errorf("expected max 60h, got %v", result.MaxDuration)
	}
}

func TestMTTR_3_EmptyPopulationProducesNoDataResult(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.HasData {
		t.Errorf("expected HasData false for empty population, got true")
	}
	if result.CompletedEpisodes != 0 {
		t.Errorf("expected 0 completed episodes, got %d", result.CompletedEpisodes)
	}
	if result.MTTR != 0 {
		t.Errorf("expected MTTR 0, got %v", result.MTTR)
	}
	if result.CoverageStatus != "NO_DATA" {
		t.Errorf("expected CoverageStatus NO_DATA, got %s", result.CoverageStatus)
	}
}

func TestMTTR_4_ReopenedFindings_MultipleSeparateEpisodes(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding 1:
	// Cycle 0: Start at T=0, InProgress at T=5h, Remediated at T=20h (Duration = 20h)
	// Cycle 1: Reopened at T=30h, InProgress at T=32h, Remediated at T=40h (Duration = 10h)
	// Total episodes = 2, Total duration = 30h, Mean = 15h, Unique findings = 1!
	remID := "rem:reopen:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "FINDING-REOPEN-01",
		Severity:     "CRITICAL",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(24 * time.Hour),
		TimeBasis:    "ELAPSED_TIME",
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events := []RemediationHistoryEvent{
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
			ToStatus:      RemediationStatusInProgress,
			Timestamp:     baseTime.Add(5 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusInProgress,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(20 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventReopened,
			FromStatus:    RemediationStatusRemediated,
			ToStatus:      RemediationStatusReopened,
			Timestamp:     baseTime.Add(30 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusReopened,
			ToStatus:      RemediationStatusInProgress,
			Timestamp:     baseTime.Add(32 * time.Hour),
		},
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusInProgress,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(40 * time.Hour),
		},
	}

	for _, e := range events {
		if err := store.SaveRemediationRecord(rec, &e); err != nil {
			t.Fatalf("SaveRemediationRecord failed: %v", err)
		}
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.CompletedEpisodes != 2 {
		t.Errorf("expected 2 completed episodes from reopen cycle, got %d", result.CompletedEpisodes)
	}
	if result.UniqueFindings != 1 {
		t.Errorf("expected exactly 1 unique finding, got %d", result.UniqueFindings)
	}
	if result.TotalDuration != 30*time.Hour {
		t.Errorf("expected total duration 30h, got %v", result.TotalDuration)
	}
	if result.MTTR != 15*time.Hour {
		t.Errorf("expected MTTR 15h, got %v", result.MTTR)
	}
}

func TestMTTR_5_DuplicateCompletionEventsDoNotInflateCounts(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	remID := "rem:dup:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "FINDING-DUP-01",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		TimeBasis:    "ELAPSED_TIME",
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	events := []RemediationHistoryEvent{
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
			Timestamp:     baseTime.Add(12 * time.Hour),
		},
		// Duplicate completion event without reopening
		{
			ID:            GenerateRemediationEventID(remID),
			RemediationID: remID,
			EventType:     HistoryEventStatusChanged,
			FromStatus:    RemediationStatusRemediated,
			ToStatus:      RemediationStatusRemediated,
			Timestamp:     baseTime.Add(14 * time.Hour),
		},
	}

	for _, e := range events {
		if err := store.SaveRemediationRecord(rec, &e); err != nil {
			t.Fatalf("SaveRemediationRecord failed: %v", err)
		}
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.CompletedEpisodes != 1 {
		t.Errorf("expected duplicate completion to be ignored (1 episode), got %d", result.CompletedEpisodes)
	}
	if result.MTTR != 12*time.Hour {
		t.Errorf("expected MTTR 12h, got %v", result.MTTR)
	}
}

func TestMTTR_6_AcceptedRiskNeverTreatedAsRemediationCompletion(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	remID := "rem:risk:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "FINDING-RISK-01",
		Severity:     "MEDIUM",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(30 * 24 * time.Hour),
		TimeBasis:    "ELAPSED_TIME",
		Status:       RemediationStatusAcceptedRisk,
		CreatedAt:    baseTime,
	}

	events := []RemediationHistoryEvent{
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
			Timestamp:     baseTime.Add(5 * 24 * time.Hour),
		},
	}

	for _, e := range events {
		if err := store.SaveRemediationRecord(rec, &e); err != nil {
			t.Fatalf("SaveRemediationRecord failed: %v", err)
		}
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.HasData {
		t.Errorf("accepted risk must not produce completed MTTR data")
	}
	if result.CompletedEpisodes != 0 {
		t.Errorf("expected 0 completed episodes, got %d", result.CompletedEpisodes)
	}
	if result.Exclusions.AcceptedRisk != 1 {
		t.Errorf("expected 1 excluded accepted risk record, got %d", result.Exclusions.AcceptedRisk)
	}
}

func TestMTTR_7_OpenAndInProgressExcludedFromCompletedMTTR(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding 1 is Open, Finding 2 is InProgress
	rem1 := &RemediationRecord{
		ID:           "rem:open:1",
		FindingID:    "F-OPEN-1",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusOpen,
		CreatedAt:    baseTime,
	}
	evt1 := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem1.ID),
		RemediationID: rem1.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	}
	_ = store.SaveRemediationRecord(rem1, evt1)

	rem2 := &RemediationRecord{
		ID:           "rem:prog:2",
		FindingID:    "F-PROG-2",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusInProgress,
		CreatedAt:    baseTime,
	}
	evt2 := &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem2.ID),
		RemediationID: rem2.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusInProgress,
		Timestamp:     baseTime.Add(2 * time.Hour),
	}
	_ = store.SaveRemediationRecord(rem2, evt2)

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.HasData {
		t.Errorf("expected HasData false when all items are open/in_progress")
	}
	if result.CompletedEpisodes != 0 {
		t.Errorf("expected 0 completed episodes, got %d", result.CompletedEpisodes)
	}
	if result.Exclusions.OpenOrInProgress != 2 {
		t.Errorf("expected 2 OpenOrInProgress exclusions, got %d", result.Exclusions.OpenOrInProgress)
	}
}

func TestMTTR_8_InvalidTimestampsSequenceExcluded(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	remID := "rem:inv:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-INV-1",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	// Completion timestamp is BEFORE start timestamp (impossible!)
	events := []RemediationHistoryEvent{
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
			Timestamp:     baseTime.Add(-5 * time.Hour), // 5 hours in the past!
		},
	}

	for _, e := range events {
		_ = store.SaveRemediationRecord(rec, &e)
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.CompletedEpisodes != 0 {
		t.Errorf("impossible timestamps must be excluded from completed episodes; got %d", result.CompletedEpisodes)
	}
	if result.Exclusions.InvalidTimestamps != 1 {
		t.Errorf("expected 1 InvalidTimestamps exclusion, got %d", result.Exclusions.InvalidTimestamps)
	}
}

func TestMTTR_9_SLAPerformanceComparison(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding 1: Completed in 20h, deadline 24h -> ON-TIME
	rem1 := &RemediationRecord{
		ID:           "rem:sla:1",
		FindingID:    "F-SLA-1",
		Severity:     "CRITICAL",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rem1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem1.ID),
		RemediationID: rem1.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rem1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem1.ID),
		RemediationID: rem1.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(20 * time.Hour),
	})

	// Finding 2: Completed in 30h, deadline 24h -> LATE
	rem2 := &RemediationRecord{
		ID:           "rem:sla:2",
		FindingID:    "F-SLA-2",
		Severity:     "CRITICAL",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rem2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem2.ID),
		RemediationID: rem2.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rem2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem2.ID),
		RemediationID: rem2.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(30 * time.Hour),
	})

	// Finding 3: Completed in 10h, NO deadline -> Excluded from SLA denominator
	rem3 := &RemediationRecord{
		ID:           "rem:sla:3",
		FindingID:    "F-SLA-3",
		Severity:     "INFO",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rem3, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem3.ID),
		RemediationID: rem3.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rem3, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem3.ID),
		RemediationID: rem3.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(10 * time.Hour),
	})

	// Advance clock past 24h and add an Open item with passed deadline
	clock.Set(baseTime.Add(35 * time.Hour))
	rem4 := &RemediationRecord{
		ID:           "rem:sla:4",
		FindingID:    "F-SLA-4",
		Severity:     "CRITICAL",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(24 * time.Hour),
		Status:       RemediationStatusOpen,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rem4, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem4.ID),
		RemediationID: rem4.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	sla := result.SLAPerformance
	if sla == nil {
		t.Fatalf("expected SLAPerformance, got nil")
	}

	if sla.VerifiableEpisodes != 2 {
		t.Errorf("expected 2 verifiable SLA episodes, got %d", sla.VerifiableEpisodes)
	}
	if sla.CompletedOnTime != 1 {
		t.Errorf("expected 1 completed on time, got %d", sla.CompletedOnTime)
	}
	if sla.CompletedLate != 1 {
		t.Errorf("expected 1 completed late, got %d", sla.CompletedLate)
	}
	if sla.OnTimeRate != 50.0 {
		t.Errorf("expected 50%% on-time rate, got %.1f%%", sla.OnTimeRate)
	}
	if sla.MissingDeadlineEpisodes != 1 {
		t.Errorf("expected 1 missing deadline episode, got %d", sla.MissingDeadlineEpisodes)
	}
	if sla.CurrentOpenOverdue != 1 {
		t.Errorf("expected 1 current open overdue item, got %d", sla.CurrentOpenOverdue)
	}
}

func TestMTTR_10_FilteringByDimensions(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Finding CRITICAL in apisec
	rem1 := &RemediationRecord{
		ID:              "rem:crit",
		FindingID:       "F-CRIT",
		FindingSource:   "apisec",
		FindingCategory: "authz",
		Severity:        "CRITICAL",
		AssessmentID:    "ASM-1",
		ControlID:       "AC-3",
		PolicyID:        "corp-sla",
		PolicyVersion:   "1.0.0",
		AssignedAt:      baseTime,
		SLAStartTime:    baseTime,
		Deadline:        baseTime.Add(24 * time.Hour),
		Status:          RemediationStatusRemediated,
		CreatedAt:       baseTime,
	}
	_ = store.SaveRemediationRecord(rem1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem1.ID),
		RemediationID: rem1.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rem1, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem1.ID),
		RemediationID: rem1.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(10 * time.Hour),
	})

	// Finding HIGH in webvuln
	rem2 := &RemediationRecord{
		ID:              "rem:high",
		FindingID:       "F-HIGH",
		FindingSource:   "webvuln",
		FindingCategory: "injection",
		Severity:        "HIGH",
		AssessmentID:    "ASM-2",
		ControlID:       "SI-10",
		PolicyID:        "corp-sla",
		PolicyVersion:   "1.0.0",
		AssignedAt:      baseTime,
		SLAStartTime:    baseTime,
		Deadline:        baseTime.Add(7 * 24 * time.Hour),
		Status:          RemediationStatusRemediated,
		CreatedAt:       baseTime,
	}
	_ = store.SaveRemediationRecord(rem2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem2.ID),
		RemediationID: rem2.ID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rem2, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(rem2.ID),
		RemediationID: rem2.ID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(40 * time.Hour),
	})

	// Filter by Severity = CRITICAL
	resCrit, err := svc.CalculateMTTR(context.Background(), MTTRFilter{Severity: "CRITICAL"})
	if err != nil {
		t.Fatalf("CalculateMTTR Severity failed: %v", err)
	}
	if resCrit.CompletedEpisodes != 1 || resCrit.MTTR != 10*time.Hour {
		t.Errorf("expected 1 episode with 10h MTTR for CRITICAL, got %d episodes and %v", resCrit.CompletedEpisodes, resCrit.MTTR)
	}

	// Filter by Category = injection
	resInj, err := svc.CalculateMTTR(context.Background(), MTTRFilter{FindingCategory: "injection"})
	if err != nil {
		t.Fatalf("CalculateMTTR Category failed: %v", err)
	}
	if resInj.CompletedEpisodes != 1 || resInj.MTTR != 40*time.Hour {
		t.Errorf("expected 1 episode with 40h MTTR for injection, got %d episodes and %v", resInj.CompletedEpisodes, resInj.MTTR)
	}

	// Filter by Assessment = ASM-1
	resAsm, err := svc.CalculateMTTR(context.Background(), MTTRFilter{AssessmentID: "ASM-1"})
	if err != nil {
		t.Fatalf("CalculateMTTR Assessment failed: %v", err)
	}
	if resAsm.CompletedEpisodes != 1 || resAsm.Episodes[0].FindingID != "F-CRIT" {
		t.Errorf("expected 1 episode for ASM-1, got %d", resAsm.CompletedEpisodes)
	}
}

func TestMTTR_11_IntegrityFailure_ExcludedOrStrictFail(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// 1. Create a signed evaluation result
	key, _ := GenerateIntegrityKey("compliance-test-key")
	kp, _ := NewStaticKeyProvider(key)
	evalRes := sampleValidEvaluationResult("ASM-MTTR-INT")
	if err := store.SaveEvaluationResultWithKey(evalRes, kp); err != nil {
		t.Fatalf("SaveEvaluationResultWithKey failed: %v", err)
	}

	// 2. Create a remediation record linked to this evaluation
	remID := "rem:int:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-BOLA-01",
		ControlID:    "AC-3",
		AssessmentID: "ASM-MTTR-INT",
		CatalogID:    "nist-sp800-53-sample",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}
	_ = store.SaveRemediationRecord(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventAssigned,
		ToStatus:      RemediationStatusOpen,
		Timestamp:     baseTime,
	})
	_ = store.SaveRemediationRecord(rec, &RemediationHistoryEvent{
		ID:            GenerateRemediationEventID(remID),
		RemediationID: remID,
		EventType:     HistoryEventStatusChanged,
		FromStatus:    RemediationStatusOpen,
		ToStatus:      RemediationStatusRemediated,
		Timestamp:     baseTime.Add(15 * time.Hour),
	})

	// Case A: Before tampering -> MTTR succeeds
	resBefore, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR before tamper failed: %v", err)
	}
	if resBefore.CompletedEpisodes != 1 || resBefore.MTTR != 15*time.Hour {
		t.Errorf("expected 1 episode, got %d", resBefore.CompletedEpisodes)
	}

	// 3. Tamper with the underlying control evaluation row directly in the database
	_, err = store.db.Exec("UPDATE compliance_control_evaluations SET rationale = 'TAMPERED RATIONALE' WHERE assessment_id = 'ASM-MTTR-INT'")
	if err != nil {
		t.Fatalf("db tamper failed: %v", err)
	}

	// Case B: Default mode -> record is excluded with IntegrityFailures count
	resAfter, err := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp})
	if err != nil {
		t.Fatalf("CalculateMTTR default after tamper returned unexpected error: %v", err)
	}
	if resAfter.CompletedEpisodes != 0 {
		t.Errorf("expected tampered record to be excluded; got %d episodes", resAfter.CompletedEpisodes)
	}
	if resAfter.Exclusions.IntegrityFailures != 1 {
		t.Errorf("expected 1 IntegrityFailures exclusion, got %d", resAfter.Exclusions.IntegrityFailures)
	}

	// Case C: StrictIntegrity mode -> fails closed with error wrapping ErrIntegrityMismatch
	_, strictErr := svc.CalculateMTTR(context.Background(), MTTRFilter{KeyProvider: kp, StrictIntegrity: true})
	if strictErr == nil {
		t.Fatalf("expected strict integrity to fail closed on tampered record, got nil error")
	}
	if !errors.Is(strictErr, ErrIntegrityMismatch) {
		t.Errorf("expected ErrIntegrityMismatch, got %v", strictErr)
	}
}

func TestMTTR_12_MissingHistory_Excluded(t *testing.T) {
	store := setupTestMTTRStore(t)
	defer store.Close()

	clock := NewMockClock(time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC))
	svc := NewMTTRService(store, clock)
	baseTime := clock.Now().UTC()

	// Record claims status "remediated", but has ZERO history events in SQLite
	remID := "rem:nohist:1"
	rec := &RemediationRecord{
		ID:           remID,
		FindingID:    "F-NOHIST-1",
		Severity:     "HIGH",
		AssignedAt:   baseTime,
		SLAStartTime: baseTime,
		Deadline:     baseTime.Add(7 * 24 * time.Hour),
		Status:       RemediationStatusRemediated,
		CreatedAt:    baseTime,
	}

	// Save record without any event
	if err := store.SaveRemediationRecord(rec, nil); err != nil {
		t.Fatalf("SaveRemediationRecord failed: %v", err)
	}

	result, err := svc.CalculateMTTR(context.Background(), MTTRFilter{})
	if err != nil {
		t.Fatalf("CalculateMTTR failed: %v", err)
	}

	if result.CompletedEpisodes != 0 {
		t.Errorf("expected record with missing history to be excluded; got %d", result.CompletedEpisodes)
	}
	if result.Exclusions.MissingHistory != 1 {
		t.Errorf("expected 1 MissingHistory exclusion, got %d", result.Exclusions.MissingHistory)
	}
}
