package compliance

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteComplianceStore {
	t.Helper()
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_test.db")
	store, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed creating test store: %v", err)
	}
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

func sampleValidEvaluationResult(assessmentID string) *EvaluationResult {
	evalTime := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	return &EvaluationResult{
		CatalogIdentity:        "nist-sp800-53-sample:5.1.0",
		CatalogDigest:          "sha256:abcdef1234567890",
		MappingRuleSetIdentity: "felix-nist-ruleset:1.0.0",
		MappingRuleSetDigest:   "sha256:123456abcdef7890",
		AssessmentID:           assessmentID,
		ExecutionID:            "EXEC-001",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:          fmt.Sprintf("eval:%s:nist-sp800-53-sample:AC-3", assessmentID),
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "AC-3",
				ControlTitle:          "Access Enforcement",
				AssessmentID:          assessmentID,
				ExecutionID:           "EXEC-001",
				State:                 StateNonCompliant,
				Rationale:             "Control requirement violated: confirmed BOLA finding",
				FindingIDs:            []string{"F-BOLA-01"},
				ContradictingEvidence: []string{"User B accessed order 104"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0.0",
				MappingRuleSetDigest:  "sha256:123456abcdef7890",
				Limitations:           "Logical authorization scope only",
			},
			{
				EvaluationID:          fmt.Sprintf("eval:%s:nist-sp800-53-sample:SI-10", assessmentID),
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "SI-10",
				ControlTitle:          "Information Input Validation",
				AssessmentID:          assessmentID,
				ExecutionID:           "EXEC-001",
				State:                 StateCompliant,
				Rationale:             "Verified positive evidence: SQL parameterized queries active",
				SupportingEvidence:    []string{"Positive verification [PE-SQLI-01] on /api/search"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0.0",
				MappingRuleSetDigest:  "sha256:123456abcdef7890",
				Limitations:           "Web tier input checks only",
			},
		},
		Summary: EvaluationSummary{
			TotalControls:             2,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   0,
			NotAssessedCount:          0,
			InsufficientEvidenceCount: 0,
			NotApplicableCount:        0,
			ErrorCount:                0,
			ApplicableControls:        2,
			AssessedControls:          2,
		},
		LimitationsNotice: EvaluationLimitationsNotice(),
	}
}

// 1. Save and retrieve a valid evaluation without semantic data loss
func TestStoreScenario1_SaveAndRetrieveEvaluation(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-001")

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-001", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}

	if retrieved.AssessmentID != res.AssessmentID {
		t.Errorf("expected AssessmentID %q, got %q", res.AssessmentID, retrieved.AssessmentID)
	}
	if retrieved.CatalogIdentity != res.CatalogIdentity {
		t.Errorf("expected CatalogIdentity %q, got %q", res.CatalogIdentity, retrieved.CatalogIdentity)
	}
	if retrieved.Digest() != res.Digest() {
		t.Errorf("retrieved Digest does not match original: %s vs %s", retrieved.Digest(), res.Digest())
	}
	if len(retrieved.Evaluations) != len(res.Evaluations) {
		t.Fatalf("expected %d evaluations, got %d", len(res.Evaluations), len(retrieved.Evaluations))
	}

	for i := range res.Evaluations {
		orig := res.Evaluations[i]
		ret := retrieved.Evaluations[i]
		if orig.ControlID != ret.ControlID || orig.State != ret.State || orig.Rationale != ret.Rationale {
			t.Errorf("evaluation mismatch for %s: %+v vs %+v", orig.ControlID, orig, ret)
		}
		if (len(orig.FindingIDs) > 0 || len(ret.FindingIDs) > 0) && !reflect.DeepEqual(orig.FindingIDs, ret.FindingIDs) {
			t.Errorf("finding IDs mismatch: %v vs %v", orig.FindingIDs, ret.FindingIDs)
		}
		if (len(orig.SupportingEvidence) > 0 || len(ret.SupportingEvidence) > 0) && !reflect.DeepEqual(orig.SupportingEvidence, ret.SupportingEvidence) {
			t.Errorf("supporting evidence mismatch: %v vs %v", orig.SupportingEvidence, ret.SupportingEvidence)
		}
		if (len(orig.ContradictingEvidence) > 0 || len(ret.ContradictingEvidence) > 0) && !reflect.DeepEqual(orig.ContradictingEvidence, ret.ContradictingEvidence) {
			t.Errorf("contradicting evidence mismatch: %v vs %v", orig.ContradictingEvidence, ret.ContradictingEvidence)
		}
	}
}

// 2. Persist all supported evaluation states
func TestStoreScenario2_PersistAllSupportedEvaluationStates(t *testing.T) {
	store := newTestStore(t)
	evalTime := time.Date(2026, 10, 21, 14, 0, 0, 0, time.UTC)

	res := &EvaluationResult{
		CatalogIdentity: "nist-all-states:1.0.0",
		CatalogDigest:   "sha256:digest123",
		AssessmentID:    "ASM-ALL-STATES",
		EvaluatedAt:     evalTime,
		EngineVersion:   CurrentEvaluationEngineVersion,
		Evaluations: []ControlEvaluationRecord{
			{
				ControlID:          "C-COMPLIANT",
				State:              StateCompliant,
				Rationale:          "Satisfied",
				SupportingEvidence: []string{"Evidence A"},
			},
			{
				ControlID:             "C-NON-COMPLIANT",
				State:                 StateNonCompliant,
				Rationale:             "Violated",
				FindingIDs:            []string{"F-1"},
				ContradictingEvidence: []string{"Finding 1"},
			},
			{
				ControlID:             "C-PARTIAL",
				State:                 StatePartiallyCompliant,
				Rationale:             "Partially compliant",
				FindingIDs:            []string{"F-2"},
				SupportingEvidence:    []string{"Satisfied req"},
				ContradictingEvidence: []string{"Violated req"},
			},
			{
				ControlID: "C-NOT-ASSESSED",
				State:     StateNotAssessed,
				Rationale: "Not tested",
			},
			{
				ControlID: "C-INSUFFICIENT",
				State:     StateInsufficientEvidence,
				Rationale: "Inconclusive probe",
			},
			{
				ControlID:          "C-NOT-APPLICABLE",
				State:              StateNotApplicable,
				Rationale:          "Exempted",
				EvidenceReferences: []string{"POLICY_EXEMPTION"},
			},
			{
				ControlID: "C-ERROR",
				State:     StateError,
				Rationale: "Scanner crash",
			},
		},
		Summary: EvaluationSummary{
			TotalControls:             7,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   1,
			NotAssessedCount:          1,
			InsufficientEvidenceCount: 1,
			NotApplicableCount:        1,
			ErrorCount:                1,
			ApplicableControls:        6,
			AssessedControls:          4,
		},
		LimitationsNotice: EvaluationLimitationsNotice(),
	}

	for i := range res.Evaluations {
		res.Evaluations[i].EvaluationID = fmt.Sprintf("eval:ASM-ALL-STATES:nist-all-states:%s", res.Evaluations[i].ControlID)
		res.Evaluations[i].CatalogID = "nist-all-states"
		res.Evaluations[i].CatalogVersion = "1.0.0"
		res.Evaluations[i].AssessmentID = "ASM-ALL-STATES"
		res.Evaluations[i].EvaluatedAt = evalTime
		res.Evaluations[i].EngineVersion = CurrentEvaluationEngineVersion
	}

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("failed saving all states evaluation: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-ALL-STATES", "nist-all-states")
	if err != nil {
		t.Fatalf("failed retrieving evaluation: %v", err)
	}

	statesFound := make(map[EvaluationState]bool)
	for _, ev := range retrieved.Evaluations {
		statesFound[ev.State] = true
	}

	expectedStates := []EvaluationState{
		StateCompliant,
		StateNonCompliant,
		StatePartiallyCompliant,
		StateNotAssessed,
		StateInsufficientEvidence,
		StateNotApplicable,
		StateError,
	}

	for _, s := range expectedStates {
		if !statesFound[s] {
			t.Errorf("expected state %q to be retrieved, but was missing", s)
		}
	}
}

// 3. Persist and retrieve supporting and contradicting evidence references
func TestStoreScenario3_PersistAndRetrieveEvidenceReferences(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-EV-REFS")

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("failed saving: %v", err)
	}

	// Retrieve evidence links for AC-3 (non-compliant)
	ac3EvalID := fmt.Sprintf("eval:ASM-EV-REFS:nist-sp800-53-sample:AC-3")
	evLinks, err := store.GetEvaluationEvidence(ac3EvalID)
	if err != nil {
		t.Fatalf("GetEvaluationEvidence failed: %v", err)
	}

	hasFinding := false
	hasContra := false
	for _, l := range evLinks {
		if l.EvidenceType == "finding" && l.ReferenceID == "F-BOLA-01" {
			hasFinding = true
		}
		if l.EvidenceType == "contradicting" && strings.Contains(l.Detail, "User B accessed order 104") {
			hasContra = true
		}
	}

	if !hasFinding {
		t.Errorf("expected finding link for F-BOLA-01 in stored evidence links")
	}
	if !hasContra {
		t.Errorf("expected contradicting evidence link in stored evidence links")
	}
}

// 4. Preserve catalog, mapping-rule, and evaluation-policy provenance
func TestStoreScenario4_PreserveProvenance(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-PROV")

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("failed saving: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-PROV", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}

	if retrieved.CatalogIdentity != "nist-sp800-53-sample:5.1.0" {
		t.Errorf("unexpected CatalogIdentity: %q", retrieved.CatalogIdentity)
	}
	if retrieved.CatalogDigest != "sha256:abcdef1234567890" {
		t.Errorf("unexpected CatalogDigest: %q", retrieved.CatalogDigest)
	}
	if retrieved.MappingRuleSetIdentity != "felix-nist-ruleset:1.0.0" {
		t.Errorf("unexpected MappingRuleSetIdentity: %q", retrieved.MappingRuleSetIdentity)
	}
	if retrieved.MappingRuleSetDigest != "sha256:123456abcdef7890" {
		t.Errorf("unexpected MappingRuleSetDigest: %q", retrieved.MappingRuleSetDigest)
	}
	if retrieved.EngineVersion != CurrentEvaluationEngineVersion {
		t.Errorf("unexpected EngineVersion: %q", retrieved.EngineVersion)
	}
}

// 5. Reject invalid evaluation records before saving
func TestStoreScenario5_RejectInvalidEvaluationRecords(t *testing.T) {
	store := newTestStore(t)

	// Nil result
	if err := store.SaveEvaluationResult(nil); !errors.Is(err, ErrInvalidEvaluation) {
		t.Errorf("expected ErrInvalidEvaluation for nil result, got: %v", err)
	}

	// Empty assessment ID
	resEmptyAss := sampleValidEvaluationResult("")
	if err := store.SaveEvaluationResult(resEmptyAss); !errors.Is(err, ErrInvalidEvaluation) {
		t.Errorf("expected ErrInvalidEvaluation for empty assessment ID, got: %v", err)
	}
}

// 6. Reject inconsistent evaluation state/evidence combinations
func TestStoreScenario6_RejectInconsistentStateEvidence(t *testing.T) {
	store := newTestStore(t)

	res := sampleValidEvaluationResult("ASM-INCONSISTENT")
	// StateCompliant without supporting evidence
	res.Evaluations[1].State = StateCompliant
	res.Evaluations[1].SupportingEvidence = []string{} // EMPTY!

	err := store.SaveEvaluationResult(res)
	if err == nil || !errors.Is(err, ErrInvalidEvaluation) {
		t.Errorf("expected ErrInvalidEvaluation for compliant state without supporting evidence, got: %v", err)
	}
}

// 7. Identical repeated submissions are idempotent
func TestStoreScenario7_IdenticalSubmissionsIdempotent(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-IDEMPOTENT")

	// First submission
	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("first save failed: %v", err)
	}

	// Repeated submission with identical content
	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("identical repeated submission failed: %v", err)
	}

	// Verify no duplicates were created
	evals, err := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-IDEMPOTENT"})
	if err != nil {
		t.Fatalf("ListControlEvaluations failed: %v", err)
	}

	if len(evals) != len(res.Evaluations) {
		t.Errorf("expected %d evaluations after retry, got %d (duplicate rows created!)",
			len(res.Evaluations), len(evals))
	}
}

// 8. Conflicting content under the same stable evaluation ID is handled explicitly
func TestStoreScenario8_ConflictingContentRejected(t *testing.T) {
	store := newTestStore(t)
	resOriginal := sampleValidEvaluationResult("ASM-CONFLICT")

	if err := store.SaveEvaluationResult(resOriginal); err != nil {
		t.Fatalf("original save failed: %v", err)
	}

	// Conflicting submission: same assessment and catalog, but different state/rationale
	resConflicting := sampleValidEvaluationResult("ASM-CONFLICT")
	resConflicting.Evaluations[0].Rationale = "ALTERED RATIONALE: Attempting silent overwrite"

	err := store.SaveEvaluationResult(resConflicting)
	if err == nil || !errors.Is(err, ErrConflictingEvaluation) {
		t.Fatalf("expected ErrConflictingEvaluation for conflicting content, got: %v", err)
	}

	// Verify original content was preserved and not mutated
	retrieved, err := store.GetEvaluationResult("ASM-CONFLICT", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}
	if retrieved.Evaluations[0].Rationale != resOriginal.Evaluations[0].Rationale {
		t.Errorf("original rationale was mutated by conflicting write!")
	}
}

// 9. A failed write does not leave a misleading completed record
func TestStoreScenario9_FailedWriteDoesNotLeavePartialRecord(t *testing.T) {
	store := newTestStore(t)

	res := sampleValidEvaluationResult("ASM-ROLLBACK")
	// Introduce failure midway by giving one evaluation record an invalid state
	res.Evaluations[1].State = EvaluationState("invalid_state_unknown")

	err := store.SaveEvaluationResult(res)
	if err == nil {
		t.Fatalf("expected validation failure")
	}

	// Verify database is completely empty
	exists, err := store.EvaluationExists("ASM-ROLLBACK", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("EvaluationExists error: %v", err)
	}
	if exists {
		t.Errorf("failed write left a partial evaluation result record in storage!")
	}

	evals, err := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-ROLLBACK"})
	if err != nil {
		t.Fatalf("ListControlEvaluations error: %v", err)
	}
	if len(evals) != 0 {
		t.Errorf("failed write left %d orphaned control evaluations!", len(evals))
	}
}

// 10. Evaluation and evidence relationships remain consistent after a failed transaction
func TestStoreScenario10_EvidenceConsistencyAfterRollback(t *testing.T) {
	store := newTestStore(t)

	res := sampleValidEvaluationResult("ASM-EV-ROLLBACK")
	res.Evaluations[1].State = EvaluationState("bad_state")

	_ = store.SaveEvaluationResult(res)

	// Check evidence links table directly
	var count int
	row := store.db.QueryRow("SELECT COUNT(1) FROM compliance_evidence_links WHERE assessment_id = ?", "ASM-EV-ROLLBACK")
	if err := row.Scan(&count); err != nil {
		t.Fatalf("query error: %v", err)
	}
	if count != 0 {
		t.Errorf("failed write left %d orphaned evidence links in database!", count)
	}
}

// 11. Retrieval by evaluation ID works
func TestStoreScenario11_GetControlEvaluationByID(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-GET-ID")

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	evalID := res.Evaluations[0].EvaluationID
	rec, err := store.GetControlEvaluation(evalID)
	if err != nil {
		t.Fatalf("GetControlEvaluation failed: %v", err)
	}

	if rec.EvaluationID != evalID || rec.ControlID != "AC-3" || rec.State != StateNonCompliant {
		t.Errorf("retrieved record mismatch: %+v", rec)
	}
}

// 12. Filtering by assessment, catalog, control, and state works
func TestStoreScenario12_FilteringEvaluations(t *testing.T) {
	store := newTestStore(t)

	res1 := sampleValidEvaluationResult("ASM-FILTER-1")
	res2 := sampleValidEvaluationResult("ASM-FILTER-2")

	_ = store.SaveEvaluationResult(res1)
	_ = store.SaveEvaluationResult(res2)

	// Filter by AssessmentID
	f1, err := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-FILTER-1"})
	if err != nil || len(f1) != 2 {
		t.Errorf("expected 2 records for ASM-FILTER-1, got %d (err: %v)", len(f1), err)
	}

	// Filter by State
	fState, err := store.ListControlEvaluations(EvaluationFilter{State: StateCompliant})
	if err != nil || len(fState) != 2 { // 1 from ASM-FILTER-1, 1 from ASM-FILTER-2
		t.Errorf("expected 2 compliant records, got %d (err: %v)", len(fState), err)
	}

	// Filter by ControlID
	fCtrl, err := store.ListControlEvaluations(EvaluationFilter{ControlID: "AC-3"})
	if err != nil || len(fCtrl) != 2 {
		t.Errorf("expected 2 records for AC-3, got %d (err: %v)", len(fCtrl), err)
	}
}

// 13. Empty queries and missing records return correct results
func TestStoreScenario13_EmptyQueriesAndNotFound(t *testing.T) {
	store := newTestStore(t)

	// Missing evaluation result -> ErrNotFound
	_, err := store.GetEvaluationResult("NONEXISTENT_ASSESSMENT", "cat")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing result, got: %v", err)
	}

	// Missing control evaluation -> ErrNotFound
	_, err = store.GetControlEvaluation("eval:NONEXISTENT:cat:ctrl")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing control, got: %v", err)
	}

	// Empty query returns empty slice, not nil
	list, err := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "EMPTY_ASSESSMENT"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if list == nil || len(list) != 0 {
		t.Errorf("expected empty non-nil slice, got: %v", list)
	}
}

// 14. Result ordering is deterministic
func TestStoreScenario14_DeterministicOrdering(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-ORDER")

	_ = store.SaveEvaluationResult(res)

	evals1, _ := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-ORDER"})
	evals2, _ := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-ORDER"})

	for i := range evals1 {
		if evals1[i].EvaluationID != evals2[i].EvaluationID {
			t.Errorf("ordering is not deterministic at index %d: %s vs %s",
				i, evals1[i].EvaluationID, evals2[i].EvaluationID)
		}
	}
}

// 15. Concurrent identical submissions do not produce duplicate logical records
func TestStoreScenario15_ConcurrentIdenticalSubmissions(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-CONCURRENT-IDEM")

	var wg sync.WaitGroup
	workers := 8
	errs := make([]error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerIdx int) {
			defer wg.Done()
			errs[workerIdx] = store.SaveEvaluationResult(res)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d failed during concurrent identical save: %v", i, err)
		}
	}

	evals, err := store.ListControlEvaluations(EvaluationFilter{AssessmentID: "ASM-CONCURRENT-IDEM"})
	if err != nil {
		t.Fatalf("ListControlEvaluations error: %v", err)
	}
	if len(evals) != len(res.Evaluations) {
		t.Errorf("expected %d evaluations, got %d (duplicates created under concurrency!)",
			len(res.Evaluations), len(evals))
	}
}

// 16. Concurrent conflicting submissions are handled safely
func TestStoreScenario16_ConcurrentConflictingSubmissions(t *testing.T) {
	store := newTestStore(t)

	res1 := sampleValidEvaluationResult("ASM-CONCURRENT-CONFLICT")
	res2 := sampleValidEvaluationResult("ASM-CONCURRENT-CONFLICT")
	res2.Evaluations[0].Rationale = "Conflicting Rationale Alpha"

	var wg sync.WaitGroup
	var err1, err2 error

	wg.Add(2)
	go func() {
		defer wg.Done()
		err1 = store.SaveEvaluationResult(res1)
	}()
	go func() {
		defer wg.Done()
		err2 = store.SaveEvaluationResult(res2)
	}()
	wg.Wait()

	// Exactly one must succeed, and one must be rejected with ErrConflictingEvaluation
	successes := 0
	conflicts := 0

	if err1 == nil {
		successes++
	} else if errors.Is(err1, ErrConflictingEvaluation) {
		conflicts++
	}

	if err2 == nil {
		successes++
	} else if errors.Is(err2, ErrConflictingEvaluation) {
		conflicts++
	}

	if successes != 1 || conflicts != 1 {
		t.Errorf("expected 1 success and 1 conflict error, got successes=%d, conflicts=%d (err1=%v, err2=%v)",
			successes, conflicts, err1, err2)
	}
}

// 17. Evidence references cannot silently point to the wrong assessment or catalog context
func TestStoreScenario17_EvidenceReferencesScoping(t *testing.T) {
	store := newTestStore(t)
	res1 := sampleValidEvaluationResult("ASM-SCOPE-A")
	res2 := sampleValidEvaluationResult("ASM-SCOPE-B")

	_ = store.SaveEvaluationResult(res1)
	_ = store.SaveEvaluationResult(res2)

	evalIDA := fmt.Sprintf("eval:ASM-SCOPE-A:nist-sp800-53-sample:AC-3")
	evLinksA, err := store.GetEvaluationEvidence(evalIDA)
	if err != nil {
		t.Fatalf("GetEvaluationEvidence failed: %v", err)
	}

	for _, l := range evLinksA {
		if l.AssessmentID != "ASM-SCOPE-A" {
			t.Errorf("evidence link for ASM-SCOPE-A referenced wrong assessment %q!", l.AssessmentID)
		}
	}
}

// 18. Restart/reopen preserves valid persisted records
func TestStoreScenario18_RestartPreservesRecords(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_restart.db")

	// Phase 1: Open store, write evaluation, close
	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening store1: %v", err)
	}

	res := sampleValidEvaluationResult("ASM-RESTART")
	if err := store1.SaveEvaluationResult(res); err != nil {
		t.Fatalf("failed saving in store1: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("failed closing store1: %v", err)
	}

	// Phase 2: Reopen store from same file
	store2, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("failed opening store2: %v", err)
	}
	defer store2.Close()

	retrieved, err := store2.GetEvaluationResult("ASM-RESTART", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("failed retrieving evaluation from store2: %v", err)
	}

	if retrieved.Digest() != res.Digest() {
		t.Errorf("retrieved digest mismatch after restart: %s vs %s", retrieved.Digest(), res.Digest())
	}
}

// 19. Serialization and deserialization preserve semantic content
func TestStoreScenario19_SerializationPreservesSemantics(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-SERIAL")

	_ = store.SaveEvaluationResult(res)
	retrieved, _ := store.GetEvaluationResult("ASM-SERIAL", "nist-sp800-53-sample")

	if retrieved.Digest() != res.Digest() {
		t.Errorf("Digest mismatch: %s vs %s", retrieved.Digest(), res.Digest())
	}
}

// 20. Malformed persisted data is rejected or explicitly classified
func TestStoreScenario20_CorruptedRowHandling(t *testing.T) {
	store := newTestStore(t)
	res := sampleValidEvaluationResult("ASM-CORRUPT")
	_ = store.SaveEvaluationResult(res)

	// Intentionally corrupt a control evaluation state directly in the database
	_, err := store.db.Exec("UPDATE compliance_control_evaluations SET state = 'CORRUPTED_STATE' WHERE assessment_id = ?", "ASM-CORRUPT")
	if err != nil {
		t.Fatalf("failed corrupting state: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-CORRUPT", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult error: %v", err)
	}

	// ValidateEvaluationResult should detect the invalid state
	err = ValidateEvaluationResult(retrieved, nil)
	if err == nil || !strings.Contains(err.Error(), "invalid evaluation state") {
		t.Errorf("expected validator to reject corrupted persisted state, got: %v", err)
	}
}

// 21. Historical records remain stable after a new catalog version is introduced
func TestStoreScenario21_HistoricalRecordsStableAcrossCatalogVersions(t *testing.T) {
	store := newTestStore(t)

	// Evaluation against v5.1.0
	resV1 := sampleValidEvaluationResult("ASM-HISTORICAL-1")
	resV1.CatalogIdentity = "nist-sp800-53-sample:5.1.0"
	resV1.Evaluations[0].CatalogVersion = "5.1.0"
	resV1.Evaluations[1].CatalogVersion = "5.1.0"
	_ = store.SaveEvaluationResult(resV1)

	// Later evaluation against v6.0.0
	resV2 := sampleValidEvaluationResult("ASM-HISTORICAL-2")
	resV2.CatalogIdentity = "nist-sp800-53-sample:6.0.0"
	resV2.Evaluations[0].CatalogVersion = "6.0.0"
	resV2.Evaluations[1].CatalogVersion = "6.0.0"
	_ = store.SaveEvaluationResult(resV2)

	// Historical v5.1.0 record remains unchanged
	retrievedV1, err := store.GetEvaluationResult("ASM-HISTORICAL-1", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult v1 failed: %v", err)
	}
	if retrievedV1.CatalogIdentity != "nist-sp800-53-sample:5.1.0" {
		t.Errorf("historical catalog version mutated: %q", retrievedV1.CatalogIdentity)
	}
}

// 22. Schema initialization or migrations preserve existing supported data
func TestStoreScenario22_MigrationsPreserveData(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_migrate.db")

	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("store1 init failed: %v", err)
	}

	res := sampleValidEvaluationResult("ASM-MIGRATE")
	_ = store1.SaveEvaluationResult(res)
	_ = store1.Close()

	// Re-run migrations on same database
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed opening raw db: %v", err)
	}
	store2, err := NewSQLiteComplianceStoreWithDB(db)
	if err != nil {
		t.Fatalf("store2 migration failed: %v", err)
	}
	defer store2.Close()

	retrieved, err := store2.GetEvaluationResult("ASM-MIGRATE", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult after migration failed: %v", err)
	}
	if retrieved.Digest() != res.Digest() {
		t.Errorf("digest mismatch after migration rerun")
	}
}

// 23. Test foreign key enforcement across connections
// 23. Test foreign key enforcement across all connections in pool
func TestStoreScenario23_ForeignKeyEnforcementAcrossConnections(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_fk.db")

	store, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	// Verify foreign keys are enforced by attempting an invalid reference on store.db
	_, err = store.db.Exec(`
		INSERT INTO compliance_control_evaluations (
			id, result_id, assessment_id, catalog_id, catalog_version,
			control_id, state, rationale, engine_version, evaluated_at, created_at
		) VALUES (
			'eval-bad-fk', 'nonexistent-result-id', 'ASM-FK', 'cat', '1.0',
			'AC-1', 'compliant', 'rationale', '1.0', datetime('now'), datetime('now')
		);
	`)
	if err == nil {
		t.Fatalf("expected FOREIGN KEY constraint failure for invalid result_id reference, but insert succeeded!")
	}
	if !strings.Contains(strings.ToLower(err.Error()), "foreign key") {
		t.Errorf("expected foreign key error, got: %v", err)
	}

	// Verify that every subsequent connection created in the pool has foreign_keys = 1
	store.db.SetMaxOpenConns(10)
	var conns []*sql.Conn
	for i := 0; i < 5; i++ {
		conn, err := store.db.Conn(context.Background())
		if err != nil {
			t.Fatalf("failed acquiring conn %d: %v", i, err)
		}
		conns = append(conns, conn)
		defer conn.Close()
	}

	for i, conn := range conns {
		var fkStatus int
		if err := conn.QueryRowContext(context.Background(), "PRAGMA foreign_keys").Scan(&fkStatus); err != nil {
			t.Fatalf("failed querying foreign_keys on conn %d: %v", i, err)
		}
		if fkStatus != 1 {
			t.Errorf("connection %d has foreign_keys = %d, expected 1", i, fkStatus)
		}

		// Also verify invalid foreign key insert fails on this specific connection
		_, err = conn.ExecContext(context.Background(), `
			INSERT INTO compliance_control_evaluations (
				id, result_id, assessment_id, catalog_id, catalog_version,
				control_id, state, rationale, engine_version, evaluated_at, created_at
			) VALUES (
				$1, 'nonexistent-result-id', 'ASM-FK', 'cat', '1.0',
				'AC-1', 'compliant', 'rationale', '1.0', datetime('now'), datetime('now')
			);
		`, fmt.Sprintf("eval-bad-fk-%d", i))
		if err == nil {
			t.Errorf("expected foreign key failure on conn %d, but insert succeeded", i)
		}
	}
}

// 24. Targeted Verification: Round-Trip Completeness across all fields, applicability, and limitations
func TestTargetedVerification_1_RoundTripCompleteness(t *testing.T) {
	store := newTestStore(t)
	evalTime := time.Date(2026, 10, 21, 14, 30, 0, 0, time.UTC)

	res := &EvaluationResult{
		CatalogIdentity:        "nist-sample:5.1.0",
		CatalogDigest:          "sha256:abcd0123456789",
		MappingRuleSetIdentity: "ruleset-sample:1.0",
		MappingRuleSetDigest:   "sha256:fedc9876543210",
		AssessmentID:           "ASM-ROUNDTRIP",
		ExecutionID:            "EXEC-RT-01",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		LimitationsNotice:      EvaluationLimitationsNotice(),
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:          "eval:ASM-ROUNDTRIP:nist-sample:AC-1",
				CatalogID:             "nist-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "AC-1",
				ControlTitle:          "Policy and Procedures",
				AssessmentID:          "ASM-ROUNDTRIP",
				ExecutionID:           "EXEC-RT-01",
				State:                 StateCompliant,
				Rationale:             "Access control policy documented and verified in repository",
				SupportingEvidence:    []string{"PE-01: security policy commit hash verified"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
				MappingRuleSetDigest:  "sha256:fedc9876543210",
				Limitations:           "Policy inspection only, operational procedures unverified",
			},
			{
				EvaluationID:          "eval:ASM-ROUNDTRIP:nist-sample:AC-2",
				CatalogID:             "nist-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "AC-2",
				ControlTitle:          "Account Management",
				AssessmentID:          "ASM-ROUNDTRIP",
				ExecutionID:           "EXEC-RT-01",
				State:                 StateNonCompliant,
				Rationale:             "Inactive service accounts not deactivated within SLA",
				FindingIDs:            []string{"F-ACCT-01"},
				ContradictingEvidence: []string{"Active API keys for terminated account user-99"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
				MappingRuleSetDigest:  "sha256:fedc9876543210",
				Limitations:           "Cloud identity provider accounts only",
			},
			{
				EvaluationID:          "eval:ASM-ROUNDTRIP:nist-sample:PE-1",
				CatalogID:             "nist-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "PE-1",
				ControlTitle:          "Physical Access Control",
				AssessmentID:          "ASM-ROUNDTRIP",
				ExecutionID:           "EXEC-RT-01",
				State:                 StateNotApplicable,
				Rationale:             "Physical security managed entirely by cloud infrastructure provider",
				EvidenceReferences:    []string{"CLOUD_PROVIDER_MANAGED", "SOC2_TYPE2_REPORT"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
				MappingRuleSetVersion: "1.0",
				MappingRuleSetDigest:  "sha256:fedc9876543210",
				Limitations:           "Scoped strictly to application layer",
			},
		},
		Summary: EvaluationSummary{
			TotalControls:             3,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   0,
			NotAssessedCount:          0,
			InsufficientEvidenceCount: 0,
			NotApplicableCount:        1,
			ErrorCount:                0,
			ApplicableControls:        2,
			AssessedControls:          3,
		},
	}

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-ROUNDTRIP", "nist-sample:5.1.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}

	// Verify all top-level provenance and metadata fields
	if retrieved.AssessmentID != res.AssessmentID {
		t.Errorf("AssessmentID mismatch: %q != %q", retrieved.AssessmentID, res.AssessmentID)
	}
	if retrieved.ExecutionID != res.ExecutionID {
		t.Errorf("ExecutionID mismatch: %q != %q", retrieved.ExecutionID, res.ExecutionID)
	}
	if retrieved.CatalogIdentity != res.CatalogIdentity {
		t.Errorf("CatalogIdentity mismatch: %q != %q", retrieved.CatalogIdentity, res.CatalogIdentity)
	}
	if retrieved.CatalogDigest != res.CatalogDigest {
		t.Errorf("CatalogDigest mismatch: %q != %q", retrieved.CatalogDigest, res.CatalogDigest)
	}
	if retrieved.MappingRuleSetIdentity != res.MappingRuleSetIdentity {
		t.Errorf("MappingRuleSetIdentity mismatch: %q != %q", retrieved.MappingRuleSetIdentity, res.MappingRuleSetIdentity)
	}
	if retrieved.MappingRuleSetDigest != res.MappingRuleSetDigest {
		t.Errorf("MappingRuleSetDigest mismatch: %q != %q", retrieved.MappingRuleSetDigest, res.MappingRuleSetDigest)
	}
	if retrieved.EngineVersion != res.EngineVersion {
		t.Errorf("EngineVersion mismatch: %q != %q", retrieved.EngineVersion, res.EngineVersion)
	}
	if retrieved.LimitationsNotice != res.LimitationsNotice {
		t.Errorf("LimitationsNotice mismatch: %q != %q", retrieved.LimitationsNotice, res.LimitationsNotice)
	}
	if !retrieved.EvaluatedAt.Equal(res.EvaluatedAt) {
		t.Errorf("EvaluatedAt mismatch: %v != %v", retrieved.EvaluatedAt, res.EvaluatedAt)
	}

	// Verify Summary
	if retrieved.Summary != res.Summary {
		t.Errorf("Summary mismatch: %+v != %+v", retrieved.Summary, res.Summary)
	}

	// Verify all control evaluations and evidence links
	if len(retrieved.Evaluations) != len(res.Evaluations) {
		t.Fatalf("Evaluations count mismatch: %d != %d", len(retrieved.Evaluations), len(res.Evaluations))
	}
	slicesEqual := func(a, b []string) bool {
		if len(a) == 0 && len(b) == 0 {
			return true
		}
		return reflect.DeepEqual(a, b)
	}
	for i, orig := range res.Evaluations {
		ret := retrieved.Evaluations[i]
		if ret.ControlID != orig.ControlID {
			t.Errorf("[%d] ControlID mismatch: %q != %q", i, ret.ControlID, orig.ControlID)
		}
		if ret.ControlTitle != orig.ControlTitle {
			t.Errorf("[%d] ControlTitle mismatch: %q != %q", i, ret.ControlTitle, orig.ControlTitle)
		}
		if ret.State != orig.State {
			t.Errorf("[%d] State mismatch: %q != %q", i, ret.State, orig.State)
		}
		if ret.Rationale != orig.Rationale {
			t.Errorf("[%d] Rationale mismatch: %q != %q", i, ret.Rationale, orig.Rationale)
		}
		if ret.Limitations != orig.Limitations {
			t.Errorf("[%d] Limitations mismatch: %q != %q", i, ret.Limitations, orig.Limitations)
		}
		if ret.CatalogID != orig.CatalogID {
			t.Errorf("[%d] CatalogID mismatch: %q != %q", i, ret.CatalogID, orig.CatalogID)
		}
		if ret.CatalogVersion != orig.CatalogVersion {
			t.Errorf("[%d] CatalogVersion mismatch: %q != %q", i, ret.CatalogVersion, orig.CatalogVersion)
		}
		if !slicesEqual(ret.FindingIDs, orig.FindingIDs) {
			t.Errorf("[%d] FindingIDs mismatch: %v != %v", i, ret.FindingIDs, orig.FindingIDs)
		}
		if !slicesEqual(ret.EvidenceReferences, orig.EvidenceReferences) {
			t.Errorf("[%d] EvidenceReferences mismatch: %v != %v", i, ret.EvidenceReferences, orig.EvidenceReferences)
		}
		if !slicesEqual(ret.SupportingEvidence, orig.SupportingEvidence) {
			t.Errorf("[%d] SupportingEvidence mismatch: %v != %v", i, ret.SupportingEvidence, orig.SupportingEvidence)
		}
		if !slicesEqual(ret.ContradictingEvidence, orig.ContradictingEvidence) {
			t.Errorf("[%d] ContradictingEvidence mismatch: %v != %v", i, ret.ContradictingEvidence, orig.ContradictingEvidence)
		}
	}
}

// 25. Targeted Verification: Evaluation Identity preserves distinct historical runs
func TestTargetedVerification_2_EvaluationIdentity_DistinctHistoricalRuns(t *testing.T) {
	store := newTestStore(t)

	// Run 1: Assessment ASM-HIST with catalog v5.1.0, execution 1
	res1 := sampleValidEvaluationResult("ASM-HIST")
	res1.CatalogIdentity = "nist-sp800-53-sample:5.1.0"
	res1.ExecutionID = "EXEC-001"
	if err := store.SaveEvaluationResult(res1); err != nil {
		t.Fatalf("SaveEvaluationResult Run 1 failed: %v", err)
	}

	// Run 2: Same assessment ASM-HIST, but new catalog revision v5.2.0
	res2 := sampleValidEvaluationResult("ASM-HIST")
	res2.CatalogIdentity = "nist-sp800-53-sample:5.2.0"
	res2.CatalogDigest = "sha256:digest-catalog-v520"
	res2.ExecutionID = "EXEC-001"
	res2.Evaluations[0].CatalogVersion = "5.2.0"
	res2.Evaluations[1].CatalogVersion = "5.2.0"
	if err := store.SaveEvaluationResult(res2); err != nil {
		t.Fatalf("SaveEvaluationResult Run 2 failed: %v", err)
	}

	// Run 3: Same assessment ASM-HIST, catalog v5.2.0, but new execution EXEC-002
	res3 := sampleValidEvaluationResult("ASM-HIST")
	res3.CatalogIdentity = "nist-sp800-53-sample:5.2.0"
	res3.CatalogDigest = "sha256:digest-catalog-v520"
	res3.ExecutionID = "EXEC-002"
	res3.Evaluations[0].CatalogVersion = "5.2.0"
	res3.Evaluations[0].ExecutionID = "EXEC-002"
	res3.Evaluations[1].CatalogVersion = "5.2.0"
	res3.Evaluations[1].ExecutionID = "EXEC-002"
	if err := store.SaveEvaluationResult(res3); err != nil {
		t.Fatalf("SaveEvaluationResult Run 3 failed: %v", err)
	}

	// Run 4: Same assessment ASM-HIST, catalog v5.2.0, EXEC-002, but updated mapping ruleset v2.0
	res4 := sampleValidEvaluationResult("ASM-HIST")
	res4.CatalogIdentity = "nist-sp800-53-sample:5.2.0"
	res4.CatalogDigest = "sha256:digest-catalog-v520"
	res4.ExecutionID = "EXEC-002"
	res4.MappingRuleSetIdentity = "felix-nist-ruleset:2.0.0"
	res4.MappingRuleSetDigest = "sha256:digest-ruleset-v2"
	res4.Evaluations[0].CatalogVersion = "5.2.0"
	res4.Evaluations[0].ExecutionID = "EXEC-002"
	res4.Evaluations[0].MappingRuleSetVersion = "2.0.0"
	res4.Evaluations[0].MappingRuleSetDigest = "sha256:digest-ruleset-v2"
	res4.Evaluations[1].CatalogVersion = "5.2.0"
	res4.Evaluations[1].ExecutionID = "EXEC-002"
	res4.Evaluations[1].MappingRuleSetVersion = "2.0.0"
	res4.Evaluations[1].MappingRuleSetDigest = "sha256:digest-ruleset-v2"
	if err := store.SaveEvaluationResult(res4); err != nil {
		t.Fatalf("SaveEvaluationResult Run 4 failed: %v", err)
	}

	// Verify all 4 distinct historical evaluations exist in the store
	summaries, err := store.ListEvaluationResults(EvaluationResultFilter{AssessmentID: "ASM-HIST"})
	if err != nil {
		t.Fatalf("ListEvaluationResults failed: %v", err)
	}
	if len(summaries) != 4 {
		t.Fatalf("expected 4 distinct historical evaluations, got %d", len(summaries))
	}

	// Verify idempotent retry of Run 4 succeeds with 0 duplicates
	if err := store.SaveEvaluationResult(res4); err != nil {
		t.Fatalf("idempotent retry of Run 4 failed: %v", err)
	}
	summariesAfterRetry, _ := store.ListEvaluationResults(EvaluationResultFilter{AssessmentID: "ASM-HIST"})
	if len(summariesAfterRetry) != 4 {
		t.Errorf("idempotent retry created duplicate evaluation records!")
	}

	// Verify conflicting write under Run 4's identity is rejected
	conflictingRes4 := sampleValidEvaluationResult("ASM-HIST")
	conflictingRes4.CatalogIdentity = "nist-sp800-53-sample:5.2.0"
	conflictingRes4.CatalogDigest = "sha256:digest-catalog-v520"
	conflictingRes4.ExecutionID = "EXEC-002"
	conflictingRes4.MappingRuleSetIdentity = "felix-nist-ruleset:2.0.0"
	conflictingRes4.MappingRuleSetDigest = "sha256:digest-ruleset-v2"
	conflictingRes4.Evaluations[0].Rationale = "TAMPERED RATIONALE"
	conflictingRes4.Evaluations[0].CatalogVersion = "5.2.0"
	conflictingRes4.Evaluations[0].ExecutionID = "EXEC-002"
	conflictingRes4.Evaluations[0].MappingRuleSetVersion = "2.0.0"
	conflictingRes4.Evaluations[0].MappingRuleSetDigest = "sha256:digest-ruleset-v2"
	conflictingRes4.Evaluations[1].CatalogVersion = "5.2.0"
	conflictingRes4.Evaluations[1].ExecutionID = "EXEC-002"
	conflictingRes4.Evaluations[1].MappingRuleSetVersion = "2.0.0"
	conflictingRes4.Evaluations[1].MappingRuleSetDigest = "sha256:digest-ruleset-v2"

	err = store.SaveEvaluationResult(conflictingRes4)
	if err == nil || !errors.Is(err, ErrConflictingEvaluation) {
		t.Errorf("expected ErrConflictingEvaluation, got: %v", err)
	}
}

// 26. Targeted Verification: Real SQLite concurrency (identical retries & conflicting submissions)
func TestTargetedVerification_3_RealSQLiteConcurrency(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_concur.db")

	store, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteComplianceStore failed: %v", err)
	}
	defer store.Close()

	// 1. Concurrent identical submissions against the same result ID
	resIdentical := sampleValidEvaluationResult("ASM-CONCUR-IDEM")
	const numWorkers = 10
	var wg sync.WaitGroup
	errs := make([]error, numWorkers)

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			errs[idx] = store.SaveEvaluationResult(resIdentical)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d returned unexpected error on identical submission: %v", i, err)
		}
	}

	// Confirm exactly one logical result was persisted
	var count int
	row := store.db.QueryRow("SELECT COUNT(1) FROM compliance_evaluation_results WHERE assessment_id = ?", "ASM-CONCUR-IDEM")
	if err := row.Scan(&count); err != nil || count != 1 {
		t.Fatalf("expected 1 evaluation result row, got %d (err: %v)", count, err)
	}

	// 2. Concurrent conflicting submissions against the same result ID
	resOriginal := sampleValidEvaluationResult("ASM-CONCUR-CONF")
	if err := store.SaveEvaluationResult(resOriginal); err != nil {
		t.Fatalf("saving original result failed: %v", err)
	}

	conflictErrs := make([]error, numWorkers)
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conf := sampleValidEvaluationResult("ASM-CONCUR-CONF")
			conf.Evaluations[0].Rationale = fmt.Sprintf("CONFLICTING RATIONALE FROM WORKER %d", idx)
			conflictErrs[idx] = store.SaveEvaluationResult(conf)
		}(i)
	}
	wg.Wait()

	for i, err := range conflictErrs {
		if err == nil || !errors.Is(err, ErrConflictingEvaluation) {
			t.Errorf("worker %d: expected ErrConflictingEvaluation, got: %v", i, err)
		}
	}

	// Confirm original record is unaltered
	retrieved, err := store.GetEvaluationResult("ASM-CONCUR-CONF", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("failed retrieving original: %v", err)
	}
	if retrieved.Evaluations[0].Rationale != resOriginal.Evaluations[0].Rationale {
		t.Errorf("original rationale was overwritten by concurrent conflict!")
	}
}

// 27. Targeted Verification: Atomic failure behavior rolls back parent record
func TestTargetedVerification_4_AtomicFailureRollsBackParentResult(t *testing.T) {
	store := newTestStore(t)

	res := sampleValidEvaluationResult("ASM-ATOMIC-FAIL")
	// Introduce failure at step 5 (duplicate control evaluation ID within same submission)
	res.Evaluations[1].EvaluationID = res.Evaluations[0].EvaluationID

	err := store.SaveEvaluationResult(res)
	if err == nil {
		t.Fatalf("expected save to fail due to duplicate control evaluation ID constraint")
	}

	// Verify that parent evaluation record was rolled back completely
	var parentCount int
	err = store.db.QueryRow("SELECT COUNT(1) FROM compliance_evaluation_results WHERE assessment_id = ?", "ASM-ATOMIC-FAIL").Scan(&parentCount)
	if err != nil {
		t.Fatalf("query failed: %v", err)
	}
	if parentCount != 0 {
		t.Errorf("atomic failure defect: parent record was not rolled back, found %d rows!", parentCount)
	}

	// Verify no control evaluations or evidence links remain
	var ctrlCount int
	_ = store.db.QueryRow("SELECT COUNT(1) FROM compliance_control_evaluations WHERE assessment_id = ?", "ASM-ATOMIC-FAIL").Scan(&ctrlCount)
	if ctrlCount != 0 {
		t.Errorf("found %d orphaned control evaluations after rollback!", ctrlCount)
	}

	exists, _ := store.EvaluationExists("ASM-ATOMIC-FAIL", "nist-sp800-53-sample")
	if exists {
		t.Errorf("EvaluationExists returned true after rolled-back transaction!")
	}
}

// 28. Targeted Verification: Database persistence survives process/store closure and restart
func TestTargetedVerification_5_DatabasePersistenceSurvivesClosure(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "compliance_lifecycle.db")

	// Store and close
	store1, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("store1 init failed: %v", err)
	}
	res := sampleValidEvaluationResult("ASM-SURVIVE")
	if err := store1.SaveEvaluationResult(res); err != nil {
		t.Fatalf("SaveEvaluationResult failed: %v", err)
	}
	if err := store1.Close(); err != nil {
		t.Fatalf("store1.Close failed: %v", err)
	}

	// Reopen with new instance and verify
	store2, err := NewSQLiteComplianceStore(dbPath)
	if err != nil {
		t.Fatalf("store2 init failed: %v", err)
	}
	defer store2.Close()

	retrieved, err := store2.GetEvaluationResult("ASM-SURVIVE", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult after reopening failed: %v", err)
	}
	if retrieved.Digest() != res.Digest() {
		t.Errorf("digest mismatch after store reopening: %q != %q", retrieved.Digest(), res.Digest())
	}
}

// 29. Targeted Verification: Historical stability preserves original provenance and content
func TestTargetedVerification_6_HistoricalStability_PreservesOriginalContent(t *testing.T) {
	store := newTestStore(t)

	// Save v1.0
	resV1 := sampleValidEvaluationResult("ASM-HIST-STABLE")
	resV1.CatalogIdentity = "nist-sp800-53-sample:1.0.0"
	resV1.CatalogDigest = "sha256:v1-catalog-digest"
	resV1.MappingRuleSetIdentity = "felix-nist-ruleset:1.0.0"
	resV1.MappingRuleSetDigest = "sha256:v1-ruleset-digest"
	resV1.Evaluations[0].CatalogVersion = "1.0.0"
	resV1.Evaluations[0].Rationale = "Original v1 evaluation rationale"
	resV1.Evaluations[1].CatalogVersion = "1.0.0"
	if err := store.SaveEvaluationResult(resV1); err != nil {
		t.Fatalf("Save v1 failed: %v", err)
	}

	// Later, evaluate against v2.0
	resV2 := sampleValidEvaluationResult("ASM-HIST-STABLE")
	resV2.CatalogIdentity = "nist-sp800-53-sample:2.0.0"
	resV2.CatalogDigest = "sha256:v2-catalog-digest"
	resV2.MappingRuleSetIdentity = "felix-nist-ruleset:2.0.0"
	resV2.MappingRuleSetDigest = "sha256:v2-ruleset-digest"
	resV2.Evaluations[0].CatalogVersion = "2.0.0"
	resV2.Evaluations[0].Rationale = "Updated v2 evaluation rationale with new requirements"
	resV2.Evaluations[1].CatalogVersion = "2.0.0"
	if err := store.SaveEvaluationResult(resV2); err != nil {
		t.Fatalf("Save v2 failed: %v", err)
	}

	// Verify v1 retains original provenance and content exactly
	retrievedV1, err := store.GetEvaluationResult("ASM-HIST-STABLE", "nist-sp800-53-sample:1.0.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult v1 failed: %v", err)
	}
	if retrievedV1.CatalogIdentity != "nist-sp800-53-sample:1.0.0" {
		t.Errorf("v1 CatalogIdentity mutated: %q", retrievedV1.CatalogIdentity)
	}
	if retrievedV1.CatalogDigest != "sha256:v1-catalog-digest" {
		t.Errorf("v1 CatalogDigest mutated: %q", retrievedV1.CatalogDigest)
	}
	if retrievedV1.Evaluations[0].Rationale != "Original v1 evaluation rationale" {
		t.Errorf("v1 rationale mutated: %q", retrievedV1.Evaluations[0].Rationale)
	}

	// Verify v2 contains new provenance
	retrievedV2, err := store.GetEvaluationResult("ASM-HIST-STABLE", "nist-sp800-53-sample:2.0.0")
	if err != nil {
		t.Fatalf("GetEvaluationResult v2 failed: %v", err)
	}
	if retrievedV2.CatalogIdentity != "nist-sp800-53-sample:2.0.0" {
		t.Errorf("v2 CatalogIdentity mismatch: %q", retrievedV2.CatalogIdentity)
	}

	// Unversioned query retrieves the latest evaluation (v2)
	retrievedLatest, err := store.GetEvaluationResult("ASM-HIST-STABLE", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult latest failed: %v", err)
	}
	if retrievedLatest.CatalogIdentity != "nist-sp800-53-sample:2.0.0" {
		t.Errorf("expected latest to be v2.0.0, got: %q", retrievedLatest.CatalogIdentity)
	}
}

// 30. Targeted Verification: Summary counts reconcile with all 7 discrete evaluation states
func TestTargetedVerification_7_SummaryCorrectness_ReconcilesAll7States(t *testing.T) {
	store := newTestStore(t)
	evalTime := time.Date(2026, 10, 21, 15, 0, 0, 0, time.UTC)

	res := &EvaluationResult{
		CatalogIdentity:        "nist-sp800-53-sample:5.1.0",
		CatalogDigest:          "sha256:digest-7-states",
		MappingRuleSetIdentity: "felix-nist-ruleset:1.0.0",
		MappingRuleSetDigest:   "sha256:ruleset-7-states",
		AssessmentID:           "ASM-7-STATES",
		ExecutionID:            "EXEC-7-STATES",
		EvaluatedAt:            evalTime,
		EngineVersion:          CurrentEvaluationEngineVersion,
		LimitationsNotice:      EvaluationLimitationsNotice(),
		Evaluations: []ControlEvaluationRecord{
			{
				EvaluationID:       "eval:ASM-7-STATES:nist:C-01",
				CatalogID:          "nist-sp800-53-sample",
				CatalogVersion:     "5.1.0",
				ControlID:          "C-01",
				State:              StateCompliant,
				Rationale:          "Compliant state with valid positive evidence",
				SupportingEvidence: []string{"PE-01: valid defense"},
				EvaluatedAt:        evalTime,
				EngineVersion:      CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:          "eval:ASM-7-STATES:nist:C-02",
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "C-02",
				State:                 StateNonCompliant,
				Rationale:             "Non-compliant state with confirmed finding",
				FindingIDs:            []string{"F-01"},
				ContradictingEvidence: []string{"Confirmed vulnerability"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:          "eval:ASM-7-STATES:nist:C-03",
				CatalogID:             "nist-sp800-53-sample",
				CatalogVersion:        "5.1.0",
				ControlID:             "C-03",
				State:                 StatePartiallyCompliant,
				Rationale:             "Partially compliant with mixed evidence",
				FindingIDs:            []string{"F-02"},
				SupportingEvidence:    []string{"PE-02: endpoint defended"},
				ContradictingEvidence: []string{"Endpoint B vulnerable"},
				EvaluatedAt:           evalTime,
				EngineVersion:         CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   "eval:ASM-7-STATES:nist:C-04",
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "C-04",
				State:          StateNotAssessed,
				Rationale:      "Assessment was cancelled; control cannot be evaluated",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   "eval:ASM-7-STATES:nist:C-05",
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "C-05",
				State:          StateInsufficientEvidence,
				Rationale:      "Unverified finding with no verification status",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:       "eval:ASM-7-STATES:nist:C-06",
				CatalogID:          "nist-sp800-53-sample",
				CatalogVersion:     "5.1.0",
				ControlID:          "C-06",
				State:              StateNotApplicable,
				Rationale:          "Control determined not applicable to target",
				EvidenceReferences: []string{"POLICY_EXEMPTION"},
				EvaluatedAt:        evalTime,
				EngineVersion:      CurrentEvaluationEngineVersion,
			},
			{
				EvaluationID:   "eval:ASM-7-STATES:nist:C-07",
				CatalogID:      "nist-sp800-53-sample",
				CatalogVersion: "5.1.0",
				ControlID:      "C-07",
				State:          StateError,
				Rationale:      "Execution error during evaluation: scanner timed out",
				EvaluatedAt:    evalTime,
				EngineVersion:  CurrentEvaluationEngineVersion,
			},
		},
		Summary: EvaluationSummary{
			TotalControls:             7,
			CompliantCount:            1,
			NonCompliantCount:         1,
			PartiallyCompliantCount:   1,
			NotAssessedCount:          1,
			InsufficientEvidenceCount: 1,
			NotApplicableCount:        1,
			ErrorCount:                1,
			ApplicableControls:        6,
			AssessedControls:          6,
		},
	}

	if err := store.SaveEvaluationResult(res); err != nil {
		t.Fatalf("SaveEvaluationResult with 7 states failed: %v", err)
	}

	retrieved, err := store.GetEvaluationResult("ASM-7-STATES", "nist-sp800-53-sample")
	if err != nil {
		t.Fatalf("GetEvaluationResult failed: %v", err)
	}

	// Verify all summary counts match exactly
	sum := retrieved.Summary
	if sum.TotalControls != 7 {
		t.Errorf("TotalControls = %d, expected 7", sum.TotalControls)
	}
	if sum.CompliantCount != 1 {
		t.Errorf("CompliantCount = %d, expected 1", sum.CompliantCount)
	}
	if sum.NonCompliantCount != 1 {
		t.Errorf("NonCompliantCount = %d, expected 1", sum.NonCompliantCount)
	}
	if sum.PartiallyCompliantCount != 1 {
		t.Errorf("PartiallyCompliantCount = %d, expected 1", sum.PartiallyCompliantCount)
	}
	if sum.NotAssessedCount != 1 {
		t.Errorf("NotAssessedCount = %d, expected 1", sum.NotAssessedCount)
	}
	if sum.InsufficientEvidenceCount != 1 {
		t.Errorf("InsufficientEvidenceCount = %d, expected 1", sum.InsufficientEvidenceCount)
	}
	if sum.NotApplicableCount != 1 {
		t.Errorf("NotApplicableCount = %d, expected 1", sum.NotApplicableCount)
	}
	if sum.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, expected 1", sum.ErrorCount)
	}
	if sum.ApplicableControls != 6 {
		t.Errorf("ApplicableControls = %d, expected 6", sum.ApplicableControls)
	}
	if sum.AssessedControls != 6 {
		t.Errorf("AssessedControls = %d, expected 6", sum.AssessedControls)
	}

	// Verify all 7 states present in retrieved control evaluations
	stateCounts := make(map[EvaluationState]int)
	for _, ev := range retrieved.Evaluations {
		stateCounts[ev.State]++
	}
	expectedStates := []EvaluationState{
		StateCompliant, StateNonCompliant, StatePartiallyCompliant,
		StateNotAssessed, StateInsufficientEvidence, StateNotApplicable, StateError,
	}
	for _, expected := range expectedStates {
		if stateCounts[expected] != 1 {
			t.Errorf("expected exactly 1 control in state %q, found %d", expected, stateCounts[expected])
		}
	}
}
