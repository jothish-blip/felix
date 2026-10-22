package assessment

import (
	"testing"
	"time"

	"felix/pkg/correlation"
	"felix/pkg/report"
	"github.com/google/uuid"
)

// TestFindingLifecycle_AllStates verifies all 8 lifecycle classifications and precedence rules.
func TestFindingLifecycle_AllStates(t *testing.T) {
	// Base findings
	baseFindingResolved := report.Finding{
		ID:          "f-resolved",
		RuleID:      "RULE-SQLI",
		Title:       "SQL Injection in Search",
		Severity:    report.SeverityHigh,
		Category:    "Injection",
		Target:      "https://example.com",
		Endpoint:    "/search",
		Confidence:  report.ConfidenceHigh,
		Fingerprint: "fp-sqli-search-0001",
	}

	baseFindingPersistent := report.Finding{
		ID:          "f-persistent",
		RuleID:      "RULE-XSS",
		Title:       "Reflected XSS in Comments",
		Severity:    report.SeverityMedium,
		Category:    "XSS",
		Target:      "https://example.com",
		Endpoint:    "/comments",
		Confidence:  report.ConfidenceMedium,
		Fingerprint: "fp-xss-comments-0002",
	}

	baseFindingSevIncrease := report.Finding{
		ID:          "f-sev-increase",
		RuleID:      "RULE-IDOR",
		Title:       "IDOR in Profile",
		Severity:    report.SeverityLow,
		Category:    "Broken Access Control",
		Target:      "https://example.com",
		Endpoint:    "/profile",
		Confidence:  report.ConfidenceLow,
		Fingerprint: "fp-idor-profile-0003",
	}

	baseFindingSevDecrease := report.Finding{
		ID:          "f-sev-decrease",
		RuleID:      "RULE-CORS",
		Title:       "CORS Misconfiguration",
		Severity:    report.SeverityHigh,
		Category:    "Security Misconfiguration",
		Target:      "https://example.com",
		Endpoint:    "/cors",
		Confidence:  report.ConfidenceMedium,
		Fingerprint: "fp-cors-0004",
	}

	baseFindingAttrChange := report.Finding{
		ID:          "f-attr-change",
		RuleID:      "RULE-CSRF",
		Title:       "CSRF Token Missing",
		Severity:    report.SeverityMedium,
		Category:    "CSRF",
		Target:      "https://example.com",
		Endpoint:    "/change-email",
		Confidence:  report.ConfidenceLow,
		Fingerprint: "fp-csrf-0005",
	}

	baseFindingMultiChange := report.Finding{
		ID:          "f-multi-change",
		RuleID:      "RULE-AUTH-BYPASS",
		Title:       "Authentication Bypass Draft",
		Severity:    report.SeverityMedium,
		Category:    "Authentication",
		Target:      "https://example.com",
		Endpoint:    "/login",
		Confidence:  report.ConfidenceLow,
		Fingerprint: "fp-auth-bypass-0006",
	}

	baseFindingUnchanged := report.Finding{
		ID:          "f-unchanged",
		RuleID:      "RULE-INFO-DISC",
		Title:       "Server Header Information Disclosure",
		Severity:    report.SeverityInfo,
		Category:    "Information Disclosure",
		Target:      "https://example.com",
		Endpoint:    "/info",
		Confidence:  report.ConfidenceHigh,
		Fingerprint: "fp-info-disc-0007",
	}

	baselineFindings := []report.Finding{
		baseFindingResolved,
		baseFindingPersistent,
		baseFindingSevIncrease,
		baseFindingSevDecrease,
		baseFindingAttrChange,
		baseFindingMultiChange,
		baseFindingUnchanged,
	}

	// Current findings
	curFindingNew := report.Finding{
		ID:          "f-new",
		RuleID:      "RULE-SSRF",
		Title:       "SSRF in Webhook Callback",
		Severity:    report.SeverityCritical,
		Category:    "SSRF",
		Target:      "https://example.com",
		Endpoint:    "/webhook",
		Confidence:  report.ConfidenceHigh,
		Fingerprint: "fp-ssrf-webhook-0008",
	}

	curFindingPersistent := baseFindingPersistent // Identical

	curFindingSevIncrease := baseFindingSevIncrease
	curFindingSevIncrease.Severity = report.SeverityCritical // Low -> Critical

	curFindingSevDecrease := baseFindingSevDecrease
	curFindingSevDecrease.Severity = report.SeverityLow // High -> Low

	curFindingAttrChange := baseFindingAttrChange
	curFindingAttrChange.Confidence = report.ConfidenceHigh // Low -> High

	curFindingMultiChange := baseFindingMultiChange
	curFindingMultiChange.Title = "Verified Authentication Bypass" // Title renamed
	curFindingMultiChange.Severity = report.SeverityCritical       // Medium -> Critical
	curFindingMultiChange.Confidence = report.ConfidenceHigh

	curFindingUnchanged := baseFindingUnchanged // Identical

	currentFindings := []report.Finding{
		curFindingNew,
		curFindingPersistent,
		curFindingSevIncrease,
		curFindingSevDecrease,
		curFindingAttrChange,
		curFindingMultiChange,
		curFindingUnchanged,
		// Note: baseFindingResolved is absent!
	}

	opts := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://example.com"},
	}

	cmp := correlation.CompareFindingsWithOptions(baselineFindings, currentFindings, opts)

	for _, it := range cmp.Items {
		t.Logf("ITEM: title=%q fp=%s canonical=%s sevDelta=%s class=%s", it.Title, it.Fingerprint, it.CanonicalDelta, it.SeverityDelta, it.Classification)
	}

	// Validate counts
	if cmp.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", cmp.NewCount)
	}
	if cmp.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved finding, got %d", cmp.ResolvedCount)
	}
	if cmp.SeverityIncreasedCount != 2 { // f-sev-increase and f-multi-change
		t.Errorf("expected 2 severity increased findings, got %d", cmp.SeverityIncreasedCount)
	}
	if cmp.SeverityDecreasedCount != 1 { // f-sev-decrease
		t.Errorf("expected 1 severity decreased finding, got %d", cmp.SeverityDecreasedCount)
	}
	if cmp.ChangedCount != 2 { // f-attr-change and f-sev-decrease
		t.Errorf("expected 2 changed findings, got %d", cmp.ChangedCount)
	}
	if cmp.UnchangedCount != 2 { // f-persistent and f-unchanged
		t.Errorf("expected 2 unchanged findings, got %d", cmp.UnchangedCount)
	}
	if cmp.PersistentCount != 2 { // f-persistent and f-unchanged (DeltaPersistent)
		t.Errorf("expected 2 persistent findings, got %d", cmp.PersistentCount)
	}

	// Verify multi-change preserves both severity increase AND attribute changes without losing either
	var multiItem *correlation.FindingComparisonItem
	for _, it := range cmp.Items {
		if it.Title == curFindingMultiChange.Title {
			multiItem = &it
			break
		}
	}
	if multiItem == nil {
		t.Fatalf("multi-change item not found in items")
	}
	if multiItem.CanonicalDelta != "severity_increased" {
		t.Errorf("expected canonical delta severity_increased, got %s", multiItem.CanonicalDelta)
	}
	if multiItem.SeverityDelta != "severity_increased" {
		t.Errorf("expected severity delta severity_increased, got %s", multiItem.SeverityDelta)
	}
	if len(multiItem.AttributeChanges) == 0 {
		t.Errorf("expected attribute changes to record title/confidence changes, got empty list")
	}

	// Verify semantics through BuildAssessmentComparisonResult and FindingComparisonDelta:
	// 1. LifecycleStatus must be "persistent" for any baseline finding that continues into current
	// 2. CanonicalDelta must capture the specific delta ("severity_increased", "severity_decreased", "changed", "unchanged")
	// 3. Multi-change findings must preserve severity delta AND attribute changes without contradictory labels
	baseAsm := &Assessment{ID: "asm-1", Ref: "ASM-001", Status: StatusCompleted}
	curAsm := &Assessment{ID: "asm-2", Ref: "ASM-002", Status: StatusCompleted}
	res := BuildAssessmentComparisonResult(baseAsm, curAsm, "exec-1", "exec-2", []string{"https://example.com"}, []string{"https://example.com"}, &cmp, "FULL_OVERLAP", nil)

	var multiDelta, unchangedDelta, sevDecreaseDelta, newDelta, resolvedDelta *FindingComparisonDelta
	for i := range res.Items {
		item := &res.Items[i]
		switch item.Title {
		case curFindingMultiChange.Title:
			multiDelta = item
		case curFindingUnchanged.Title:
			unchangedDelta = item
		case curFindingSevDecrease.Title:
			sevDecreaseDelta = item
		case curFindingNew.Title:
			newDelta = item
		case baseFindingResolved.Title:
			resolvedDelta = item
		}
	}

	if multiDelta == nil {
		t.Fatalf("multiDelta finding missing in comparison result")
	}
	if multiDelta.LifecycleStatus != "persistent" {
		t.Errorf("multiDelta expected lifecycle_status 'persistent', got %q", multiDelta.LifecycleStatus)
	}
	if multiDelta.CanonicalDelta != "severity_increased" {
		t.Errorf("multiDelta expected canonical_delta 'severity_increased', got %q", multiDelta.CanonicalDelta)
	}
	if multiDelta.SeverityDelta != "severity_increased" {
		t.Errorf("multiDelta expected severity_delta 'severity_increased', got %q", multiDelta.SeverityDelta)
	}
	if len(multiDelta.AttributeChanges) == 0 {
		t.Errorf("multiDelta expected non-empty attribute_changes")
	}

	if unchangedDelta == nil {
		t.Fatalf("unchangedDelta finding missing in comparison result")
	}
	if unchangedDelta.LifecycleStatus != "persistent" {
		t.Errorf("unchangedDelta expected lifecycle_status 'persistent', got %q", unchangedDelta.LifecycleStatus)
	}
	if unchangedDelta.CanonicalDelta != "unchanged" {
		t.Errorf("unchangedDelta expected canonical_delta 'unchanged', got %q", unchangedDelta.CanonicalDelta)
	}
	if unchangedDelta.SeverityDelta != "unchanged" {
		t.Errorf("unchangedDelta expected severity_delta 'unchanged', got %q", unchangedDelta.SeverityDelta)
	}

	if sevDecreaseDelta == nil {
		t.Fatalf("sevDecreaseDelta finding missing in comparison result")
	}
	if sevDecreaseDelta.LifecycleStatus != "persistent" {
		t.Errorf("sevDecreaseDelta expected lifecycle_status 'persistent', got %q", sevDecreaseDelta.LifecycleStatus)
	}
	if sevDecreaseDelta.CanonicalDelta != "severity_decreased" {
		t.Errorf("sevDecreaseDelta expected canonical_delta 'severity_decreased', got %q", sevDecreaseDelta.CanonicalDelta)
	}
	if sevDecreaseDelta.SeverityDelta != "severity_decreased" {
		t.Errorf("sevDecreaseDelta expected severity_delta 'severity_decreased', got %q", sevDecreaseDelta.SeverityDelta)
	}

	if newDelta == nil || newDelta.LifecycleStatus != "new" || newDelta.CanonicalDelta != "new" {
		t.Errorf("newDelta expected lifecycle_status='new' canonical_delta='new', got %+v", newDelta)
	}
	if resolvedDelta == nil || resolvedDelta.LifecycleStatus != "resolved" || resolvedDelta.CanonicalDelta != "resolved" {
		t.Errorf("resolvedDelta expected lifecycle_status='resolved' canonical_delta='resolved', got %+v", resolvedDelta)
	}
}

// TestFindingIdentity_TitleRenamedAndDuplicateFingerprints tests robust fingerprinting behavior.
func TestFindingIdentity_TitleRenamedAndDuplicateFingerprints(t *testing.T) {
	// A finding whose title changes but endpoint, category, and method remain identical
	base := report.Finding{
		ID:          "f1",
		RuleID:      "RULE-RCE",
		Title:       "Potential Remote Code Execution via Template",
		Severity:    report.SeverityHigh,
		Category:    "RCE",
		Target:      "https://example.com",
		Endpoint:    "/render",
		Method:      "POST",
		Fingerprint: "", // Empty: engine must compute stable fingerprint
	}

	cur := report.Finding{
		ID:          "f2",
		RuleID:      "RULE-RCE",
		Title:       "Server-Side Template Injection (SSTI) Confirmed", // Renamed title!
		Severity:    report.SeverityCritical,                          // Severity increased
		Category:    "RCE",
		Target:      "https://example.com",
		Endpoint:    "/render",
		Method:      "POST",
		Fingerprint: "", // Empty: engine must compute identical stable fingerprint
	}

	baseFP := correlation.ComputeStableFingerprint(base)
	curFP := correlation.ComputeStableFingerprint(cur)
	if baseFP != curFP {
		t.Fatalf("expected stable fingerprint to match despite renamed title: base=%s, cur=%s", baseFP, curFP)
	}

	// Compare
	cmp := correlation.CompareFindingsWithOptions([]report.Finding{base}, []report.Finding{cur}, correlation.DefaultComparisonOptions())
	if cmp.NewCount != 0 {
		t.Errorf("renamed title should NOT be classified as new, got NewCount=%d", cmp.NewCount)
	}
	if cmp.ResolvedCount != 0 {
		t.Errorf("renamed title should NOT cause base to be resolved, got ResolvedCount=%d", cmp.ResolvedCount)
	}
	if cmp.SeverityIncreasedCount != 1 {
		t.Errorf("expected 1 severity increased finding, got %d", cmp.SeverityIncreasedCount)
	}
}

// TestFindingIdentity_SimilarTitlesUnrelatedRules ensures unrelated vulnerabilities do not falsely match.
func TestFindingIdentity_SimilarTitlesUnrelatedRules(t *testing.T) {
	f1 := report.Finding{
		ID:          "f1",
		RuleID:      "RULE-XSS-REFLECTED",
		Title:       "Cross-Site Scripting",
		Category:    "XSS",
		Target:      "https://example.com",
		Endpoint:    "/search",
	}

	f2 := report.Finding{
		ID:          "f2",
		RuleID:      "RULE-XSS-STORED",
		Title:       "Cross-Site Scripting", // Same title!
		Category:    "XSS",
		Target:      "https://example.com",
		Endpoint:    "/profile/bio", // Different endpoint and rule!
	}

	fp1 := correlation.ComputeStableFingerprint(f1)
	fp2 := correlation.ComputeStableFingerprint(f2)
	if fp1 == fp2 {
		t.Fatalf("unrelated vulnerabilities on different endpoints must NOT have identical fingerprints")
	}

	cmp := correlation.CompareFindingsWithOptions([]report.Finding{f1}, []report.Finding{f2}, correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://example.com"},
	})

	if cmp.NewCount != 1 || cmp.ResolvedCount != 1 {
		t.Errorf("expected 1 new and 1 resolved for unrelated vulnerabilities, got new=%d, resolved=%d", cmp.NewCount, cmp.ResolvedCount)
	}
}

// TestAssessmentEligibility_IncompleteAndFailedAssessments verifies safeguards against false resolution claims.
func TestAssessmentEligibility_IncompleteAndFailedAssessments(t *testing.T) {
	baseFindings := []report.Finding{
		{
			ID:          "f-base",
			RuleID:      "RULE-SQLI",
			Title:       "Critical SQLi",
			Severity:    report.SeverityCritical,
			Category:    "Injection",
			Target:      "https://example.com",
			Endpoint:    "/api/query",
			Fingerprint: "fp-sqli-001",
		},
	}

	// Case 1: Newer assessment completed = false (e.g. failed or interrupted scan)
	optsIncomplete := correlation.ComparisonOptions{
		CurrentCompleted: false, // Incomplete!
		ScopedTargets:    []string{"https://example.com"},
	}

	cmpIncomplete := correlation.CompareFindingsWithOptions(baseFindings, nil, optsIncomplete)
	if cmpIncomplete.ResolvedCount != 0 {
		t.Errorf("incomplete assessment must NEVER mark findings as resolved, got ResolvedCount=%d", cmpIncomplete.ResolvedCount)
	}
	if cmpIncomplete.UnknownCount != 1 {
		t.Errorf("missing findings in incomplete assessment must be marked unknown, got UnknownCount=%d", cmpIncomplete.UnknownCount)
	}
	if cmpIncomplete.ComparisonStatus != "PARTIAL" {
		t.Errorf("expected comparison status PARTIAL, got %s", cmpIncomplete.ComparisonStatus)
	}

	// Case 2: Partial target coverage (baseline had target A and target B; current only scanned target A)
	baseFindingsMultiTarget := []report.Finding{
		{
			ID:          "f-target-a",
			Title:       "Vuln on Target A",
			Target:      "https://app.example.com",
			Endpoint:    "/login",
			Fingerprint: "fp-target-a",
		},
		{
			ID:          "f-target-b",
			Title:       "Vuln on Target B",
			Target:      "https://admin.example.com",
			Endpoint:    "/admin",
			Fingerprint: "fp-target-b",
		},
	}

	optsPartialScope := correlation.ComparisonOptions{
		CurrentCompleted: true,
		ScopedTargets:    []string{"https://app.example.com"}, // Target B is NOT in scope!
	}

	// Current run observed 0 findings on target A
	cmpPartial := correlation.CompareFindingsWithOptions(baseFindingsMultiTarget, nil, optsPartialScope)

	// Target A was scanned and clear -> resolved
	if cmpPartial.ResolvedCount != 1 {
		t.Errorf("target in scope should be resolved, got %d", cmpPartial.ResolvedCount)
	}
	// Target B was NOT in scope -> MUST remain unknown / unverified!
	if cmpPartial.UnknownCount != 1 {
		t.Errorf("unscoped target B must remain unknown, got %d", cmpPartial.UnknownCount)
	}
	if cmpPartial.ComparisonStatus != "PARTIAL" {
		t.Errorf("expected comparison status PARTIAL for partial scope, got %s", cmpPartial.ComparisonStatus)
	}
}

// TestAssessmentStore_HistoryAndComparisonIntegration tests store-level history listing and cross-assessment comparison.
func TestAssessmentStore_HistoryAndComparisonIntegration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	clientA := &Client{
		ID:   uuid.New().String(),
		Name: "Client A",
	}
	if err := store.CreateClient(clientA); err != nil {
		t.Fatalf("failed creating client A: %v", err)
	}

	clientB := &Client{
		ID:   uuid.New().String(),
		Name: "Client B",
	}
	if err := store.CreateClient(clientB); err != nil {
		t.Fatalf("failed creating client B: %v", err)
	}

	authCtxA := NewClientAuthContext(clientA.ID)
	authCtxB := NewClientAuthContext(clientB.ID)

	// 1. Create Baseline Assessment for Client A
	now := time.Now().UTC()
	past := now.Add(-2 * time.Hour)
	baseAsm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-2026-0001",
		ClientID:       clientA.ID,
		Name:           "Baseline Audit",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      past,
		CompletedAt:    &past,
	}
	if err := store.CreateAssessment(baseAsm); err != nil {
		t.Fatalf("failed creating baseline assessment: %v", err)
	}
	baseTgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           baseTgtID,
		AssessmentID: baseAsm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})
	baseExecID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           baseExecID,
		AssessmentID: baseAsm.ID,
		ClientID:     clientA.ID,
		Status:       StatusCompleted,
		StartedAt:    past,
		CompletedAt:  &past,
	})

	// Add a baseline finding
	baseFnd := AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      baseAsm.ID,
		ExecutionID:       baseExecID,
		TargetID:          baseTgtID,
		OriginalFindingID: "FELIX-BASE-001",
		Title:             "Cross-Site Request Forgery",
		Severity:          report.SeverityMedium,
		Category:          "CSRF",
		TargetURL:         "https://api.example.com",
		Endpoint:          "/api/transfer",
		Fingerprint:       "fp-csrf-transfer-001",
	}
	if err := store.SaveFindings([]AssessmentFinding{baseFnd}); err != nil {
		t.Fatalf("failed saving baseline finding: %v", err)
	}

	// 2. Create Current Assessment for Client A
	curAsm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-2026-0002",
		ClientID:       clientA.ID,
		Name:           "Re-Audit Follow-Up",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now,
		CompletedAt:    &now,
	}
	if err := store.CreateAssessment(curAsm); err != nil {
		t.Fatalf("failed creating current assessment: %v", err)
	}
	curTgtID := uuid.New().String()
	_ = store.AddTarget(&AssessmentTarget{
		ID:           curTgtID,
		AssessmentID: curAsm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})
	curExecID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           curExecID,
		AssessmentID: curAsm.ID,
		ClientID:     clientA.ID,
		Status:       StatusCompleted,
		StartedAt:    now,
		CompletedAt:  &now,
	})

	// Current assessment resolved the CSRF and found a new Header Disclosure
	curFnd := AssessmentFinding{
		ID:                uuid.New().String(),
		AssessmentID:      curAsm.ID,
		ExecutionID:       curExecID,
		TargetID:          curTgtID,
		OriginalFindingID: "FELIX-CUR-002",
		Title:             "Exposed X-Powered-By Header",
		Severity:          report.SeverityLow,
		Category:          "Information Disclosure",
		TargetURL:         "https://api.example.com",
		Endpoint:          "/api/transfer",
		Fingerprint:       "fp-header-disc-002",
	}
	if err := store.SaveFindings([]AssessmentFinding{curFnd}); err != nil {
		t.Fatalf("failed saving current finding: %v", err)
	}

	// 3. Test ListAssessmentHistory deterministic ordering and pagination
	history, total, err := store.ListAssessmentHistory(clientA.ID, "", authCtxA, 10, 0)
	if err != nil {
		t.Fatalf("ListAssessmentHistory failed: %v", err)
	}
	if total != 2 {
		t.Fatalf("expected total 2 assessments in history, got %d", total)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 items, got %d", len(history))
	}
	// Check reverse chronological order: curAsm (now) should come before baseAsm (past)
	if history[0].ID != curAsm.ID {
		t.Errorf("expected newest assessment first (%s), got %s", curAsm.ID, history[0].ID)
	}
	if !history[0].IsEligibleBaseline {
		t.Errorf("completed assessment should be eligible baseline")
	}

	// 4. Test CompareAssessments
	res, err := store.CompareAssessments(baseAsm.ID, curAsm.ID, authCtxA)
	if err != nil {
		t.Fatalf("CompareAssessments failed: %v", err)
	}
	if !res.IsReliable {
		t.Errorf("expected reliable comparison, got unreliable: %s", res.ComparabilityReason)
	}
	if res.ComparabilityStatus != ComparabilityStatusComparable {
		t.Errorf("expected COMPARABLE, got %s", res.ComparabilityStatus)
	}
	if res.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved finding, got %d", res.ResolvedCount)
	}
	if res.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", res.NewCount)
	}

	// 5. Test Cross-Tenant Access Protection: Client B attempting to view or compare Client A assessments
	_, _, err = store.ListAssessmentHistory(clientA.ID, "", authCtxB, 10, 0)
	if err == nil {
		t.Errorf("expected unauthorized error for Client B accessing Client A history, got nil")
	}

	_, err = store.CompareAssessments(baseAsm.ID, curAsm.ID, authCtxB)
	if err == nil {
		t.Errorf("expected unauthorized error for Client B comparing Client A assessments, got nil")
	}

	// 6. Test Zero Findings Completed Assessment
	emptyAsm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-2026-0003",
		ClientID:       clientA.ID,
		Name:           "Clean Assessment",
		AssessmentType: "BLACK_BOX_WEB",
		Status:         StatusCompleted,
		CreatedAt:      now.Add(1 * time.Hour),
	}
	_ = store.CreateAssessment(emptyAsm)
	_ = store.AddTarget(&AssessmentTarget{
		ID:           uuid.New().String(),
		AssessmentID: emptyAsm.ID,
		TargetURL:    "https://api.example.com",
		ScopeStatus:  "APPROVED",
	})

	emptyRes, err := store.CompareAssessments(curAsm.ID, emptyAsm.ID, authCtxA)
	if err != nil {
		t.Fatalf("comparison with clean assessment failed: %v", err)
	}
	if emptyRes.ResolvedCount != 1 { // curFnd was resolved
		t.Errorf("expected 1 resolved finding when comparing to clean run, got %d", emptyRes.ResolvedCount)
	}
	if emptyRes.NewCount != 0 {
		t.Errorf("expected 0 new findings, got %d", emptyRes.NewCount)
	}
}
