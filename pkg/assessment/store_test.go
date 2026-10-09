package assessment

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/report"
	"github.com/google/uuid"
)

func newTestStore(t *testing.T) (*SQLiteStore, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "felix_store_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test_assessment.db")

	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		t.Fatalf("failed to open SQLite store: %v", err)
	}

	cleanup := func() {
		_ = store.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return store, cleanup
}

func TestStore_ClientCRUD(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	c := &Client{
		ID:           uuid.New().String(),
		Name:         "Acme Security",
		Organization: "Acme Corp Ltd",
		ContactName:  "Alice Smith",
		ContactEmail: "alice@acme.example",
		Notes:        "Priority client",
	}

	// 1. Create client
	if err := store.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// 2. Get client by ID
	fetched, err := store.GetClient(c.ID)
	if err != nil {
		t.Fatalf("GetClient by ID failed: %v", err)
	}
	if fetched.Name != c.Name || fetched.Organization != c.Organization {
		t.Errorf("mismatch in fetched client fields: %+v", fetched)
	}

	// 3. Get client by Name
	fetchedByName, err := store.GetClient("Acme Security")
	if err != nil {
		t.Fatalf("GetClient by Name failed: %v", err)
	}
	if fetchedByName.ID != c.ID {
		t.Errorf("expected ID %s, got %s", c.ID, fetchedByName.ID)
	}

	// 4. List clients
	list, err := store.ListClients(false)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListClients failed: err=%v, count=%d", err, len(list))
	}

	// 5. Update client
	c.Notes = "Updated notes"
	if err := store.UpdateClient(c); err != nil {
		t.Fatalf("UpdateClient failed: %v", err)
	}

	// 6. Archive client
	if err := store.ArchiveClient(c.ID); err != nil {
		t.Fatalf("ArchiveClient failed: %v", err)
	}

	// Without archived flag
	activeList, err := store.ListClients(false)
	if err != nil || len(activeList) != 0 {
		t.Errorf("expected 0 active clients after archive, got %d", len(activeList))
	}

	// With archived flag
	allList, err := store.ListClients(true)
	if err != nil || len(allList) != 1 {
		t.Errorf("expected 1 client including archived, got %d", len(allList))
	}
}

func TestStore_AssessmentAndTraceability(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// 1. Create Client
	clientID := uuid.New().String()
	client := &Client{
		ID:   clientID,
		Name: "Test Client",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	// 2. Create Assessment
	asmID := uuid.New().String()
	asmRef := GenerateAssessmentRef()
	asm := &Assessment{
		ID:             asmID,
		Ref:            asmRef,
		ClientID:       clientID,
		Name:           "Q1 Security Assessment",
		AssessmentType: "WEB_SECURITY",
		Status:         StatusDraft,
		ScopeMode:      "same-origin",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	// Verify lookup by ID and Ref
	fetchedAsm, err := store.GetAssessment(asmID)
	if err != nil || fetchedAsm.Ref != asmRef {
		t.Fatalf("GetAssessment by ID failed: %v", err)
	}
	fetchedByRef, err := store.GetAssessment(asmRef)
	if err != nil || fetchedByRef.ID != asmID {
		t.Fatalf("GetAssessment by Ref failed: %v", err)
	}

	// 3. Targets
	targetID := uuid.New().String()
	target := &AssessmentTarget{
		ID:           targetID,
		AssessmentID: asmID,
		TargetURL:    "https://app.example.com",
		TargetType:   TargetWebsite,
		ScopeStatus:  "APPROVED",
	}
	if err := store.AddTarget(target); err != nil {
		t.Fatalf("AddTarget failed: %v", err)
	}
	targets, err := store.GetTargets(asmRef) // Using Ref to test resolution
	if err != nil || len(targets) != 1 {
		t.Fatalf("GetTargets failed: err=%v, count=%d", err, len(targets))
	}

	// 4. Authorization
	now := time.Now().UTC()
	auth := &AuthorizationRecord{
		ID:                  uuid.New().String(),
		AssessmentID:        asmID,
		AuthorizingParty:    "Security Officer",
		AuthorizationMethod: "WRITTEN_CONSENT",
		DateReceived:        now,
		Status:              AuthApproved,
	}
	if err := store.SetAuthorization(auth); err != nil {
		t.Fatalf("SetAuthorization failed: %v", err)
	}
	fetchedAuth, err := store.GetAuthorization(asmRef)
	if err != nil || fetchedAuth == nil || fetchedAuth.AuthorizingParty != "Security Officer" {
		t.Fatalf("GetAuthorization failed: err=%v, auth=%+v", err, fetchedAuth)
	}

	// 5. Scope Rules and Exclusions
	sr := &ScopeRule{
		ID:           uuid.New().String(),
		AssessmentID: asmRef, // Test Ref resolution
		RuleType:     "subdomains",
		Pattern:      "example.com",
	}
	if err := store.AddScopeRule(sr); err != nil {
		t.Fatalf("AddScopeRule failed: %v", err)
	}
	rules, err := store.GetScopeRules(asmID)
	if err != nil || len(rules) != 1 {
		t.Fatalf("GetScopeRules failed: err=%v, count=%d", err, len(rules))
	}

	ex := &Exclusion{
		ID:            uuid.New().String(),
		AssessmentID:  asmID,
		ExclusionType: ExclusionPathPrefix,
		Pattern:       "/admin",
		Reason:        "Out of scope",
	}
	if err := store.AddExclusion(ex); err != nil {
		t.Fatalf("AddExclusion failed: %v", err)
	}
	exclusions, err := store.GetExclusions(asmRef)
	if err != nil || len(exclusions) != 1 {
		t.Fatalf("GetExclusions failed: err=%v, count=%d", err, len(exclusions))
	}

	// 6. Execution Run Record
	execID := uuid.New().String()
	exec := &AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusRunning,
		StartedAt:    now,
		ConfigSnapshot: ScanConfigSnapshot{
			ScopeMode:   "same-origin",
			Concurrency: 5,
		},
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 7. Findings Traceability
	findingID := uuid.New().String()
	finding := AssessmentFinding{
		ID:                 findingID,
		AssessmentID:       asmID,
		ExecutionID:        execID,
		TargetID:           targetID,
		OriginalFindingID:  "FELIX-SEC-001",
		Title:              "Exposed API Token in JavaScript",
		Category:           "secrets",
		Severity:           "HIGH",
		Confidence:         "HIGH",
		VerificationStatus: report.VerificationVerified,
		TargetURL:          "https://app.example.com",
		Endpoint:           "https://app.example.com/assets/app.js",
		Method:             "GET",
		Score:              75,
		EvidenceDetails: report.EvidenceDetails{
			Observation: "api_key = \"secret123\"",
		},
		VerificationRecord: report.VerificationRecord{
			Status: report.VerificationVerified,
			Result: "Active token",
		},
	}

	if err := store.SaveFindings([]AssessmentFinding{finding}); err != nil {
		t.Fatalf("SaveFindings failed: %v", err)
	}

	fetchedFindings, err := store.GetFindings(asmRef, execID)
	if err != nil || len(fetchedFindings) != 1 {
		t.Fatalf("GetFindings failed: err=%v, count=%d", err, len(fetchedFindings))
	}
	f := fetchedFindings[0]
	if f.AssessmentID != asmID || f.ExecutionID != execID || f.TargetID != targetID {
		t.Errorf("Finding traceability broken: asm=%s, exec=%s, tgt=%s", f.AssessmentID, f.ExecutionID, f.TargetID)
	}
	if f.EvidenceDetails.Observation != "api_key = \"secret123\"" {
		t.Errorf("EvidenceDetails mismatch: %+v", f.EvidenceDetails)
	}
	if f.VerificationRecord.Status != report.VerificationVerified {
		t.Errorf("VerificationRecord status mismatch: %s", f.VerificationRecord.Status)
	}

	// 8. Report Record
	repID := uuid.New().String()
	rep := &ReportRecord{
		ID:           repID,
		AssessmentID: asmID,
		ExecutionID:  execID,
		Format:       "HTML",
		FilePath:     "report.html",
		FelixVersion: "2.0.0",
		Status:       "GENERATED",
	}
	if err := store.SaveReport(rep); err != nil {
		t.Fatalf("SaveReport failed: %v", err)
	}
	reports, err := store.GetReports(asmRef)
	if err != nil || len(reports) != 1 {
		t.Fatalf("GetReports failed: err=%v, count=%d", err, len(reports))
	}
}

func TestStore_InterruptedRunRecovery(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Test Client"})

	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       "ASM-2026-TEST",
		ClientID:  clientID,
		Name:      "Interrupted Test",
		Status:    StatusRunning,
		CreatedAt: time.Now().UTC(),
	})

	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	})

	// Detect and recover
	recovered, err := store.DetectAndRecoverInterruptedRuns()
	if err != nil {
		t.Fatalf("DetectAndRecoverInterruptedRuns failed: %v", err)
	}
	if recovered != 1 {
		t.Errorf("expected 1 recovered execution, got %d", recovered)
	}

	exec, err := store.GetExecution(execID)
	if err != nil || exec.Status != StatusFailed {
		t.Errorf("expected recovered execution to be FAILED, got status=%s, err=%v", exec.Status, err)
	}

	asm, err := store.GetAssessment(asmID)
	if err != nil || asm.Status != StatusFailed {
		t.Errorf("expected recovered assessment to be FAILED, got status=%s, err=%v", asm.Status, err)
	}
}
