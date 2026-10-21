package assessment

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

func TestStore_FindingResultStatePersistence(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC()
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Test Client"})

	asmID := "asm_test_result_states"
	asmRef := GenerateAssessmentRef()
	asm := &Assessment{
		ID:             asmID,
		Ref:            asmRef,
		ClientID:       clientID,
		Name:           "Result States Assessment",
		AssessmentType: "WEB_SECURITY",
		Status:         StatusDraft,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	targetID := "tgt_1"
	target := &AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	execID := "exec_test_result_states"
	exec := &AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusRunning,
		StartedAt:    now,
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	testCases := []struct {
		findingID string
		status    report.FindingStatus
		severity  string
	}{
		{"fnd_conf", report.FindingStatusConfirmed, report.SeverityCritical},
		{"fnd_susp", report.FindingStatusSuspected, report.SeverityHigh},
		{"fnd_inc", report.FindingStatusInconclusive, report.SeverityMedium},
		{"fnd_nt", report.FindingStatusNotTested, report.SeverityLow},
		{"fnd_err", report.FindingStatusError, report.SeverityInfo},
	}

	var findings []AssessmentFinding
	for _, tc := range testCases {
		findings = append(findings, AssessmentFinding{
			ID:                 tc.findingID,
			AssessmentID:       asmID,
			ExecutionID:        execID,
			TargetID:           targetID,
			OriginalFindingID:  tc.findingID,
			Title:              "Finding with status " + string(tc.status),
			Category:           "web-vuln",
			Severity:           tc.severity,
			Confidence:         report.ConfidenceHigh,
			Status:             tc.status,
			VerificationStatus: report.VerificationVerified,
			TargetURL:          "https://example.com",
			Endpoint:           "https://example.com/" + tc.findingID,
			Method:             "GET",
			Fingerprint:        "fp_" + tc.findingID,
			Score:              80,
			CreatedAt:          now,
		})
	}

	if err := store.SaveFindings(findings); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	retrieved, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}

	if len(retrieved) != len(testCases) {
		t.Fatalf("expected %d findings, got %d", len(testCases), len(retrieved))
	}

	statusMap := make(map[string]report.FindingStatus)
	for _, f := range retrieved {
		statusMap[f.ID] = f.Status
	}

	for _, tc := range testCases {
		gotStatus, exists := statusMap[tc.findingID]
		if !exists {
			t.Errorf("missing retrieved finding %s", tc.findingID)
			continue
		}
		if gotStatus != tc.status {
			t.Errorf("finding %s: expected status %s, got %s", tc.findingID, tc.status, gotStatus)
		}
	}
}

func TestStore_FindingResultStateAliasNormalization(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC()
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Alias Client"})

	asmID := "asm_test_aliases"
	asmRef := GenerateAssessmentRef()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	})

	targetID := "tgt_alias"
	_ = store.AddTarget(&AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://example.com",
		ScopeStatus:  "APPROVED",
	})

	execID := "exec_test_aliases"
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusRunning,
		StartedAt:    now,
	})

	aliasTests := []struct {
		id       string
		alias    report.FindingStatus
		expected report.FindingStatus
	}{
		{"f_blocked", "BLOCKED", report.FindingStatusNotTested},
		{"f_skipped", "SKIPPED", report.FindingStatusNotTested},
		{"f_fail", "FAIL", report.FindingStatusError},
		{"f_crash", "CRASH", report.FindingStatusError},
		{"f_proven", "PROVEN", report.FindingStatusConfirmed},
		{"f_candidate", "CANDIDATE", report.FindingStatusSuspected},
		{"f_indeterminate", "INDETERMINATE", report.FindingStatusInconclusive},
	}

	var findings []AssessmentFinding
	for _, at := range aliasTests {
		findings = append(findings, AssessmentFinding{
			ID:                at.id,
			AssessmentID:      asmID,
			ExecutionID:       execID,
			TargetID:          targetID,
			OriginalFindingID: at.id,
			Title:             "Alias finding " + string(at.alias),
			Category:          "web-vuln",
			Severity:          report.SeverityMedium,
			Confidence:        report.ConfidenceMedium,
			Status:            at.alias,
			TargetURL:         "https://example.com",
			Endpoint:          "https://example.com/" + at.id,
			Method:            "GET",
			Fingerprint:       "fp_" + at.id,
			CreatedAt:         now,
		})
	}

	if err := store.SaveFindings(findings); err != nil {
		t.Fatalf("SaveFindings with aliases failed: %v", err)
	}

	retrieved, err := store.GetFindings(asmID, execID)
	if err != nil {
		t.Fatalf("GetFindings failed: %v", err)
	}

	for _, rf := range retrieved {
		for _, at := range aliasTests {
			if rf.ID == at.id {
				if rf.Status != at.expected {
					t.Errorf("finding %s: alias %s normalized to %s, want %s", at.id, at.alias, rf.Status, at.expected)
				}
			}
		}
	}
}

func TestController_HonestResultStatePreservation(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// Setup local test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<html><body><h1>Controller Test</h1></body></html>`))
	}))
	defer ts.Close()

	now := time.Now().UTC()
	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "SecOps Test"})

	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	asm := &Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Controller States Test",
		Status:    StatusDraft,
		ScopeMode: "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	auth := &AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Lead SecOps",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	}
	if err := store.SetAuthorization(auth); err != nil {
		t.Fatalf("failed to set auth: %v", err)
	}

	target := &AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: asmID,
		TargetURL:    ts.URL,
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("failed to add target: %v", err)
	}

	ctrl := NewController(store)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	runRecord, err := ctrl.RunAssessment(ctx, asmID, ExecutionOptions{
		AllowLoopback: true,
	})
	if err != nil {
		t.Fatalf("RunAssessment failed: %v", err)
	}

	if runRecord.Execution.Status != StatusCompleted && runRecord.Execution.Status != StatusCompletedWithErrors {
		t.Errorf("unexpected execution status: %s", runRecord.Execution.Status)
	}
}
