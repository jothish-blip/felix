package assessment

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/discovery"
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

func TestStore_InventoryPersistenceAndTraceability(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC()

	clientID := uuid.New().String()
	_ = store.CreateClient(&Client{ID: clientID, Name: "Inventory Corp"})

	asmID := uuid.New().String()
	_ = store.CreateAssessment(&Assessment{
		ID:        asmID,
		Ref:       "ASM-2026-INV",
		ClientID:  clientID,
		Name:      "Inventory Architecture Test",
		Status:    StatusReady,
		CreatedAt: now,
	})

	execID := uuid.New().String()
	_ = store.CreateExecution(&AssessmentExecution{
		ID:           execID,
		AssessmentID: asmID,
		Status:       StatusCompleted,
		StartedAt:    now,
	})

	// 1. Create assets across different categories
	domainID := uuid.New().String()
	subID := uuid.New().String()
	appID := uuid.New().String()
	formID := uuid.New().String()
	paramID := uuid.New().String()

	assets := []discovery.Asset{
		{
			ID:              domainID,
			AssessmentID:    asmID,
			ExecutionID:     execID,
			Type:            discovery.AssetTypeDomain,
			CanonicalID:     "example.com",
			DisplayName:     "example.com",
			DiscoveryMethod: "SEED",
			DiscoveryStatus: discovery.StatusObserved,
			Confidence:      discovery.ConfidenceHigh,
			InScope:         true,
			FirstSeen:       now,
			LastSeen:        now,
		},
		{
			ID:              subID,
			AssessmentID:    asmID,
			ExecutionID:     execID,
			Type:            discovery.AssetTypeSubdomain,
			CanonicalID:     "app.example.com",
			ParentID:        domainID,
			DisplayName:     "app.example.com",
			DiscoveryMethod: "DNS_LOOKUP",
			DiscoveryStatus: discovery.StatusResolved,
			Confidence:      discovery.ConfidenceHigh,
			InScope:         true,
			FirstSeen:       now,
			LastSeen:        now,
		},
		{
			ID:              appID,
			AssessmentID:    asmID,
			ExecutionID:     execID,
			Type:            discovery.AssetTypeApplication,
			CanonicalID:     "https://app.example.com/",
			ParentID:        subID,
			DisplayName:     "app.example.com (React)",
			DiscoveryMethod: "HTML_ANALYSIS",
			DiscoveryStatus: discovery.StatusObserved,
			Confidence:      discovery.ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"framework": "React",
			},
			FirstSeen: now,
			LastSeen:  now,
		},
		{
			ID:              formID,
			AssessmentID:    asmID,
			ExecutionID:     execID,
			Type:            discovery.AssetTypeForm,
			CanonicalID:     "POST https://app.example.com/login#0",
			ParentID:        appID,
			DisplayName:     "Form [POST] /login",
			DiscoveryMethod: "HTML_PARSING",
			DiscoveryStatus: discovery.StatusObserved,
			Confidence:      discovery.ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"purpose": "LOGIN",
			},
			FirstSeen: now,
			LastSeen:  now,
		},
		{
			ID:              paramID,
			AssessmentID:    asmID,
			ExecutionID:     execID,
			Type:            discovery.AssetTypeParameter,
			CanonicalID:     "https://app.example.com/login:form:password",
			ParentID:        formID,
			DisplayName:     "Field password (password)",
			DiscoveryMethod: "HTML_PARSING",
			DiscoveryStatus: discovery.StatusObserved,
			Confidence:      discovery.ConfidenceHigh,
			InScope:         true,
			Metadata: map[string]any{
				"location": "FORM",
			},
			FirstSeen: now,
			LastSeen:  now,
		},
	}

	// 2. Create relationships between assets
	relations := []discovery.Relation{
		{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: domainID,
			TargetAssetID: subID,
			RelationType:  discovery.RelHasSubdomain,
			Evidence:      "app.example.com is child of example.com",
			Confidence:    discovery.ConfidenceHigh,
			CreatedAt:     now,
		},
		{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: subID,
			TargetAssetID: appID,
			RelationType:  discovery.RelExposesApplication,
			Evidence:      "app.example.com hosts React application",
			Confidence:    discovery.ConfidenceHigh,
			CreatedAt:     now,
		},
		{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: appID,
			TargetAssetID: formID,
			RelationType:  discovery.RelContainsForm,
			Evidence:      "React app contains login form",
			Confidence:    discovery.ConfidenceHigh,
			CreatedAt:     now,
		},
		{
			ID:            uuid.New().String(),
			AssessmentID:  asmID,
			ExecutionID:   execID,
			SourceAssetID: formID,
			TargetAssetID: paramID,
			RelationType:  discovery.RelHasInput,
			Evidence:      "Form accepts password parameter",
			Confidence:    discovery.ConfidenceHigh,
			CreatedAt:     now,
		},
	}

	if err := store.SaveInventory(assets, relations); err != nil {
		t.Fatalf("SaveInventory failed: %v", err)
	}

	// 3. Query all inventory
	fetchedAssets, fetchedRelations, err := store.GetInventory(asmID, execID, "", false)
	if err != nil {
		t.Fatalf("GetInventory failed: %v", err)
	}
	if len(fetchedAssets) != 5 {
		t.Errorf("expected 5 assets, got %d", len(fetchedAssets))
	}
	if len(fetchedRelations) != 4 {
		t.Errorf("expected 4 relations, got %d", len(fetchedRelations))
	}

	// 4. Query with asset type filter
	formAssets, _, err := store.GetInventory(asmID, execID, string(discovery.AssetTypeForm), false)
	if err != nil {
		t.Fatalf("GetInventory with type filter failed: %v", err)
	}
	if len(formAssets) != 1 || formAssets[0].ID != formID {
		t.Errorf("expected 1 form asset matching %s, got %v", formID, formAssets)
	}

	// 5. Query summary
	summary, err := store.GetInventorySummary(asmID, execID)
	if err != nil {
		t.Fatalf("GetInventorySummary failed: %v", err)
	}
	if summary.TotalAssets != 5 {
		t.Errorf("expected TotalAssets = 5, got %d", summary.TotalAssets)
	}
	if summary.DomainsCount != 1 || summary.FormsCount != 1 || summary.ParametersCount != 1 {
		t.Errorf("summary counts mismatch: %+v", summary)
	}
}

func TestStore_AuthInventoryPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	now := time.Now().UTC()
	clientID := uuid.New().String()
	client := &Client{
		ID:   clientID,
		Name: "Auth Client",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asmID := uuid.New().String()
	asmRef := "ASM-2026-AUTH"
	execID := uuid.New().String()
	targetID := uuid.New().String()

	// Setup baseline assessment records
	asm := &Assessment{
		ID:        asmID,
		Ref:       asmRef,
		ClientID:  clientID,
		Name:      "Auth Audit",
		Status:    StatusRunning,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

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

	// 1. Build sample AuthInventory
	authInv := auth.AuthInventory{
		Surfaces: []auth.AuthSurface{
			{
				ID:                 uuid.New().String(),
				AssessmentID:       asmID,
				ExecutionID:        execID,
				TargetID:           targetID,
				CanonicalID:        "LOGIN:/auth/login",
				Category:           auth.CategoryLogin,
				Subtype:            auth.SubtypePassword,
				Identifier:         "/auth/login",
				DiscoveryMethod:    "HTML_FORM",
				Confidence:         auth.ConfidenceHigh,
				VerificationStatus: auth.VerificationDiscovered,
				AuthState:          auth.AuthStateAnonymousObserved,
				InScope:            true,
				Explanation:        "HTML form posting to /auth/login with password field",
				Evidence: map[string]any{
					"action": "/auth/login",
				},
				CreatedAt: now,
				UpdatedAt: now,
			},
			{
				ID:                 uuid.New().String(),
				AssessmentID:       asmID,
				ExecutionID:        execID,
				TargetID:           targetID,
				CanonicalID:        "MFA:/auth/mfa",
				Category:           auth.CategoryMFA,
				Subtype:            auth.SubtypeTOTP,
				Identifier:         "/auth/mfa",
				DiscoveryMethod:    "ROUTE_NAMING",
				Confidence:         auth.ConfidenceHigh,
				VerificationStatus: auth.VerificationDiscovered,
				AuthState:          auth.AuthStateIndicatorPresent,
				InScope:            true,
				Explanation:        "Route matches MFA taxonomy",
				CreatedAt:          now,
				UpdatedAt:          now,
			},
		},
		Cookies: []auth.CookieMetadata{
			{
				ID:               uuid.New().String(),
				AssessmentID:     asmID,
				ExecutionID:      execID,
				TargetID:         targetID,
				Name:             "sid",
				IsSecure:         false,
				IsHTTPOnly:       false,
				SameSite:         "Unset",
				Purpose:          auth.CookiePurposeSession,
				IsSession:        true,
				HasSecurityIssue: true,
				SecurityDefects:  []string{"Missing HttpOnly", "Missing Secure"},
				SourceURL:        "https://app.example.com",
				CreatedAt:        now,
			},
		},
		Tokens: []auth.TokenArtifact{
			{
				ID:              uuid.New().String(),
				AssessmentID:    asmID,
				ExecutionID:     execID,
				TargetID:        targetID,
				TokenType:       "JWT",
				Subtype:         auth.SubtypeBearerToken,
				Name:            "jwt_bearer",
				Location:        "SCRIPT",
				Format:          "JWT_3_PART",
				Algorithm:       "RS256",
				EvidenceSummary: "Observed JWT structure with algorithm RS256",
				SourceAsset:     "https://app.example.com/main.js",
				CreatedAt:       now,
			},
		},
	}

	// 2. Persist Auth Inventory
	if err := store.SaveAuthInventory(authInv); err != nil {
		t.Fatalf("SaveAuthInventory failed: %v", err)
	}

	// 3. Query all Auth Inventory
	fetchedInv, err := store.GetAuthInventory(asmID, execID, "")
	if err != nil {
		t.Fatalf("GetAuthInventory failed: %v", err)
	}
	if len(fetchedInv.Surfaces) != 2 {
		t.Errorf("expected 2 surfaces, got %d", len(fetchedInv.Surfaces))
	}
	if len(fetchedInv.Cookies) != 1 {
		t.Errorf("expected 1 cookie, got %d", len(fetchedInv.Cookies))
	}
	if len(fetchedInv.Tokens) != 1 {
		t.Errorf("expected 1 token, got %d", len(fetchedInv.Tokens))
	}

	// 4. Query with category filter
	loginInv, err := store.GetAuthInventory(asmID, execID, string(auth.CategoryLogin))
	if err != nil {
		t.Fatalf("GetAuthInventory with category filter failed: %v", err)
	}
	if len(loginInv.Surfaces) != 1 || loginInv.Surfaces[0].Category != auth.CategoryLogin {
		t.Errorf("expected 1 LOGIN surface, got: %v", loginInv.Surfaces)
	}

	// 5. Query Auth Summary
	summary, err := store.GetAuthSummary(asmID, execID)
	if err != nil {
		t.Fatalf("GetAuthSummary failed: %v", err)
	}
	if summary.TotalSurfaces != 2 {
		t.Errorf("expected TotalSurfaces = 2, got %d", summary.TotalSurfaces)
	}
	if summary.SessionCookies != 1 || summary.InsecureCookies != 1 {
		t.Errorf("expected 1 session cookie with security issue, got %+v", summary)
	}
}

func TestStore_AuthzPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// Verify Migration 4 was applied
	var currentVersion int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if currentVersion < 4 {
		t.Errorf("expected schema version >= 4, got %d", currentVersion)
	}

	client := &Client{Name: "Authz Client"}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	asm := &Assessment{
		ClientID:       client.ID,
		Name:           "Authz Assessment",
		AssessmentType: "API_AUDIT",
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("failed to create assessment: %v", err)
	}

	exec := &AssessmentExecution{
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("failed to create execution: %v", err)
	}

	// 1. Policy Persistence & Secret Redaction
	policy := &authz.AuthzPolicy{
		AssessmentRef:    asm.Ref,
		AuthorizationDoc: "DOC-AUTHZ-001",
		AllowWriteTests:  true,
		Identities: map[string]authz.TestIdentity{
			"user_a": {
				Alias:          "user_a",
				Role:           "user",
				TenantID:       "tenant_1",
				PrivilegeLevel: 1,
				Headers:        map[string]string{"Authorization": "Bearer secret_token_abc"},
			},
		},
		Resources: map[string]authz.TestResource{
			"order_101": {ID: "order_101", Type: "order", OwnerAlias: "user_a"},
		},
	}

	if err := store.SaveAuthzPolicy(asm.ID, policy); err != nil {
		t.Fatalf("SaveAuthzPolicy failed: %v", err)
	}

	fetchedPolicy, err := store.GetAuthzPolicy(asm.ID)
	if err != nil {
		t.Fatalf("GetAuthzPolicy failed: %v", err)
	}
	if fetchedPolicy == nil {
		t.Fatalf("expected non-nil policy")
	}
	if fetchedPolicy.Identities["user_a"].Headers["Authorization"] == "Bearer secret_token_abc" {
		t.Errorf("LEAK: Raw Authorization token persisted in SQLite database!")
	}
	if fetchedPolicy.Identities["user_a"].Headers["Authorization"] != "[REDACTED]" {
		t.Errorf("expected [REDACTED] authorization header, got %s", fetchedPolicy.Identities["user_a"].Headers["Authorization"])
	}

	// 2. Results Persistence
	results := []authz.AuthzTestResult{
		{
			ID:                uuid.New().String(),
			TestCaseID:        "tc-1",
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          authz.CategoryBOLA,
			VerificationState: authz.StateVerified,
			Endpoint:          "https://example.com/api/orders/order_101",
			Method:            "GET",
			PrimaryIdentity:   "user_b",
			BaselineIdentity:  "user_a",
			TargetResource:    "order_101",
			ObservedStatus:    200,
			BaselineStatus:    200,
			DisclosedData:     true,
			EvidenceSummary:   "CONFIRMED BOLA/IDOR",
		},
		{
			ID:                uuid.New().String(),
			TestCaseID:        "tc-2",
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          authz.CategoryBFLA,
			VerificationState: authz.StateNotVulnerable,
			Endpoint:          "https://example.com/api/admin/users",
			Method:            "GET",
			PrimaryIdentity:   "user_a",
			ObservedStatus:    403,
			EvidenceSummary:   "Function correctly denied",
		},
	}

	if err := store.SaveAuthzResults(results); err != nil {
		t.Fatalf("SaveAuthzResults failed: %v", err)
	}

	fetchedResults, err := store.GetAuthzResults(asm.ID, exec.ID, "")
	if err != nil {
		t.Fatalf("GetAuthzResults failed: %v", err)
	}
	if len(fetchedResults) != 2 {
		t.Errorf("expected 2 results, got %d", len(fetchedResults))
	}

	// 3. Summary calculation
	summary, err := store.GetAuthzSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetAuthzSummary failed: %v", err)
	}
	if summary.TotalTests != 2 {
		t.Errorf("expected TotalTests = 2, got %d", summary.TotalTests)
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected VerifiedCount = 1, got %d", summary.VerifiedCount)
	}
	if summary.NotVulnerableCount != 1 {
		t.Errorf("expected NotVulnerableCount = 1, got %d", summary.NotVulnerableCount)
	}
}



