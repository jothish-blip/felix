package assessment

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"felix/pkg/apisec"
	"felix/pkg/auth"
	"felix/pkg/authz"
	"felix/pkg/businesslogic"
	"felix/pkg/cloudsec"
	"felix/pkg/correlation"
	"felix/pkg/discovery"
	"felix/pkg/report"
	"felix/pkg/sessionsec"
	"felix/pkg/webvuln"
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

func TestStore_APISecPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// 1. Verify schema migration version 5 applied
	var maxVersion int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if maxVersion < 5 {
		t.Fatalf("expected schema version >= 5, got %d", maxVersion)
	}

	// 2. Setup client, assessment, and execution
	c := &Client{
		ID:        uuid.New().String(),
		Name:      "APISec Test Org",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-APISEC-01",
		ClientID:       c.ID,
		Name:           "API Security Assessment",
		AssessmentType: "API_SECURITY",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:             uuid.New().String(),
		AssessmentID:   asm.ID,
		Status:         StatusRunning,
		StartedAt:      time.Now().UTC(),
		ConfigSnapshot: ScanConfigSnapshot{TimeoutSeconds: 10, Concurrency: 5},
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 3. Save and retrieve RunRecord
	run := &apisec.RunRecord{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TotalTests:         10,
		CategoriesAssessed: 10,
		VerifiedCount:      2,
		CandidateCount:     3,
		CoverageJSON:       `{"API1_BOLA":{"category":"API1_BOLA","code":"API1:2023","name":"Broken Object Level Authorization","status":"VERIFIED_VULNERABILITY_FOUND","tests_run":2,"verified_findings":1,"candidate_findings":0,"explanation":"Verified IDOR"}}`,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.SaveAPISecRun(run); err != nil {
		t.Fatalf("SaveAPISecRun failed: %v", err)
	}

	fetchedRun, err := store.GetAPISecRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetAPISecRun failed: %v", err)
	}
	if fetchedRun.TotalTests != 10 || fetchedRun.VerifiedCount != 2 {
		t.Errorf("unexpected run record data: %+v", fetchedRun)
	}

	// 4. Save and retrieve Results
	results := []apisec.Result{
		{
			ID:                uuid.New().String(),
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          apisec.CategoryAPI1_BOLA,
			OWASPCode:         "API1:2023",
			TestName:          "BOLA Verification",
			Endpoint:          "/api/v1/orders/999",
			Method:            "GET",
			VerificationState: apisec.StateVerified,
			Severity:          report.SeverityHigh,
			Confidence:        report.ConfidenceHigh,
			ObservedStatus:    200,
			EvidenceSummary:   "Tenant cross-access successful",
			CreatedAt:         time.Now().UTC(),
		},
		{
			ID:                uuid.New().String(),
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          apisec.CategoryAPI8_Misconfiguration,
			OWASPCode:         "API8:2023",
			TestName:          "Missing Security Headers",
			Endpoint:          "/api/v1/orders/999",
			Method:            "GET",
			VerificationState: apisec.StateCandidate,
			Severity:          report.SeverityLow,
			Confidence:        report.ConfidenceMedium,
			ObservedStatus:    200,
			EvidenceSummary:   "Missing nosniff header",
			CreatedAt:         time.Now().UTC(),
		},
	}

	if err := store.SaveAPISecResults(results); err != nil {
		t.Fatalf("SaveAPISecResults failed: %v", err)
	}

	// 5. Query all results
	fetchedResults, err := store.GetAPISecResults(asm.ID, exec.ID, "", "")
	if err != nil {
		t.Fatalf("GetAPISecResults failed: %v", err)
	}
	if len(fetchedResults) != 2 {
		t.Errorf("expected 2 results, got %d", len(fetchedResults))
	}

	// Filter by category
	filteredResults, err := store.GetAPISecResults(asm.ID, exec.ID, string(apisec.CategoryAPI1_BOLA), "")
	if err != nil {
		t.Fatalf("GetAPISecResults filtered failed: %v", err)
	}
	if len(filteredResults) != 1 {
		t.Errorf("expected 1 BOLA result, got %d", len(filteredResults))
	}

	// Filter by state
	stateResults, err := store.GetAPISecResults(asm.ID, exec.ID, "", string(apisec.StateVerified))
	if err != nil {
		t.Fatalf("GetAPISecResults by state failed: %v", err)
	}
	if len(stateResults) != 1 {
		t.Errorf("expected 1 verified result, got %d", len(stateResults))
	}

	// 6. Test GetAPISecSummary
	summary, err := store.GetAPISecSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetAPISecSummary failed: %v", err)
	}
	if summary.TotalTests != 10 {
		t.Errorf("expected TotalTests = 10 from RunRecord, got %d", summary.TotalTests)
	}
	if summary.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount = 2, got %d", summary.VerifiedCount)
	}
}

func TestStore_WebVulnPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// 1. Verify schema migration version 6 applied
	var maxVersion int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if maxVersion < 6 {
		t.Fatalf("expected schema version >= 6, got %d", maxVersion)
	}

	// 2. Setup client, assessment, and execution
	c := &Client{
		ID:        uuid.New().String(),
		Name:      "WebVuln Test Org",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-WEBVULN-01",
		ClientID:       c.ID,
		Name:           "Web Vulnerability Assessment",
		AssessmentType: "WEB_VULNERABILITY",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 3. Test SaveWebVulnRun and GetWebVulnRun
	runRec := &webvuln.RunRecord{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TotalTests:         13,
		CategoriesAssessed: 13,
		VerifiedCount:      3,
		CandidateCount:     2,
		ObservedCount:      1,
		CoverageJSON:       `{"XSS":{"category":"XSS","code":"WV-XSS","name":"Cross-Site Scripting (XSS)","status":"VERIFIED_ISSUE_FOUND","tests_run":5,"verified":1,"candidates":0,"observations":0}}`,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.SaveWebVulnRun(runRec); err != nil {
		t.Fatalf("SaveWebVulnRun failed: %v", err)
	}

	savedRun, err := store.GetWebVulnRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetWebVulnRun failed: %v", err)
	}
	if savedRun == nil {
		t.Fatalf("expected non-nil RunRecord")
	}
	if savedRun.VerifiedCount != 3 {
		t.Errorf("expected VerifiedCount = 3, got %d", savedRun.VerifiedCount)
	}
	if savedRun.CandidateCount != 2 {
		t.Errorf("expected CandidateCount = 2, got %d", savedRun.CandidateCount)
	}

	// 4. Test SaveWebVulnResults and GetWebVulnResults
	results := []webvuln.Result{
		{
			ID:                uuid.New().String(),
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          webvuln.CategoryXSS,
			VulnCode:          "WV-XSS",
			TestName:          "Reflected XSS Probe",
			Endpoint:          "http://example.com/search",
			Method:            "GET",
			VerificationState: webvuln.StateVerified,
			Severity:          report.SeverityHigh,
			Confidence:        report.ConfidenceHigh,
			ObservedStatus:    200,
			EvidenceSummary:   "Raw unescaped probe tag reflected in HTML",
			EvidenceDetails:   map[string]string{"reflection": "unescaped_html"},
			CreatedAt:         time.Now().UTC(),
		},
		{
			ID:                uuid.New().String(),
			AssessmentID:      asm.ID,
			ExecutionID:       exec.ID,
			Category:          webvuln.CategorySQLi,
			VulnCode:          "WV-SQLI",
			TestName:          "SQL Syntax Probe",
			Endpoint:          "http://example.com/items",
			Method:            "GET",
			VerificationState: webvuln.StateCandidate,
			Severity:          report.SeverityMedium,
			Confidence:        report.ConfidenceLow,
			ObservedStatus:    500,
			EvidenceSummary:   "Generic 500 error returned",
			CreatedAt:         time.Now().UTC(),
		},
	}
	if err := store.SaveWebVulnResults(results); err != nil {
		t.Fatalf("SaveWebVulnResults failed: %v", err)
	}

	loadedResults, err := store.GetWebVulnResults(asm.ID, exec.ID, "", "")
	if err != nil {
		t.Fatalf("GetWebVulnResults failed: %v", err)
	}
	if len(loadedResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(loadedResults))
	}

	// Filter by category
	filtered, err := store.GetWebVulnResults(asm.ID, exec.ID, string(webvuln.CategoryXSS), "")
	if err != nil {
		t.Fatalf("GetWebVulnResults filtered failed: %v", err)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 XSS result, got %d", len(filtered))
	}

	// Filter by state
	stateFiltered, err := store.GetWebVulnResults(asm.ID, exec.ID, "", string(webvuln.StateVerified))
	if err != nil {
		t.Fatalf("GetWebVulnResults by state failed: %v", err)
	}
	if len(stateFiltered) != 1 {
		t.Errorf("expected 1 verified result, got %d", len(stateFiltered))
	}

	// 5. Test GetWebVulnSummary
	summary, err := store.GetWebVulnSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetWebVulnSummary failed: %v", err)
	}
	if summary.TotalTests != 13 {
		t.Errorf("expected TotalTests = 13 from RunRecord, got %d", summary.TotalTests)
	}
	if summary.VerifiedCount != 3 {
		t.Errorf("expected VerifiedCount = 3, got %d", summary.VerifiedCount)
	}
}

func TestStore_SessionSecPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// 1. Verify schema migration version 7 applied
	var maxVersion int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if maxVersion < 7 {
		t.Fatalf("expected schema version >= 7, got %d", maxVersion)
	}

	// 2. Setup client, assessment, and execution
	c := &Client{
		ID:        uuid.New().String(),
		Name:      "SessionSec Test Org",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(c); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-SESSIONSEC-01",
		ClientID:       c.ID,
		Name:           "Session Security Assessment",
		AssessmentType: "SESSION_SECURITY",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 3. Test SaveSessionSecRun and GetSessionSecRun
	runRec := &sessionsec.RunRecord{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TotalTests:         11,
		CategoriesAssessed: 11,
		VerifiedCount:      2,
		CandidateCount:     1,
		ObservedCount:      1,
		InconclusiveCount:  1,
		BlockedCount:       0,
		CoverageJSON:       `{"SESSION_FIXATION":{"category":"SESSION_FIXATION","code":"SS-FIXATION","name":"Session Fixation","status":"VERIFIED_ISSUE_FOUND","tests_run":1,"verified":1}}`,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.SaveSessionSecRun(runRec); err != nil {
		t.Fatalf("SaveSessionSecRun failed: %v", err)
	}

	fetchedRun, err := store.GetSessionSecRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetSessionSecRun failed: %v", err)
	}
	if fetchedRun.ID != runRec.ID {
		t.Errorf("expected run ID %s, got %s", runRec.ID, fetchedRun.ID)
	}
	if fetchedRun.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount 2, got %d", fetchedRun.VerifiedCount)
	}

	// 4. Test SaveSessionSecResults and GetSessionSecResults
	res1 := sessionsec.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Category:          sessionsec.CategorySessionFixation,
		VulnCode:          "SS-FIXATION",
		TestID:            "SS-FIXATION-ROTATION",
		TestName:          "Session ID Rotation on Login",
		WSTGRef:           "WSTG-SESS-03",
		Endpoint:          "https://target.local/login",
		Method:            "POST",
		VerificationState: sessionsec.StateVerified,
		Severity:          report.SeverityHigh,
		Confidence:        report.ConfidenceHigh,
		ObservedStatus:    200,
		StateBefore:       sessionsec.StatePreAuth,
		StateAfter:        sessionsec.StateAuthenticated,
		EvidenceSummary:   "Pre-auth cookie was adopted without rotation",
		CreatedAt:         time.Now().UTC(),
	}
	res2 := sessionsec.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Category:          sessionsec.CategoryCookieSecurity,
		VulnCode:          "SS-COOKIE",
		TestID:            "SS-COOKIE-FLAGS",
		TestName:          "Cookie Security Flags",
		WSTGRef:           "WSTG-SESS-02",
		Endpoint:          "https://target.local/api/user",
		Method:            "GET",
		VerificationState: sessionsec.StateNotVulnerable,
		Severity:          report.SeverityInfo,
		Confidence:        report.ConfidenceHigh,
		ObservedStatus:    200,
		EvidenceSummary:   "All cookies declare Secure and HttpOnly flags",
		CreatedAt:         time.Now().UTC(),
	}

	if err := store.SaveSessionSecResults([]sessionsec.Result{res1, res2}); err != nil {
		t.Fatalf("SaveSessionSecResults failed: %v", err)
	}

	allResults, err := store.GetSessionSecResults(asm.ID, exec.ID, "", "")
	if err != nil {
		t.Fatalf("GetSessionSecResults failed: %v", err)
	}
	if len(allResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(allResults))
	}

	// Filter by category
	catFiltered, err := store.GetSessionSecResults(asm.ID, exec.ID, string(sessionsec.CategorySessionFixation), "")
	if err != nil {
		t.Fatalf("GetSessionSecResults by category failed: %v", err)
	}
	if len(catFiltered) != 1 || catFiltered[0].VulnCode != "SS-FIXATION" {
		t.Errorf("expected 1 fixation result, got %d", len(catFiltered))
	}

	// Filter by state
	stateFiltered, err := store.GetSessionSecResults(asm.ID, exec.ID, "", string(sessionsec.StateVerified))
	if err != nil {
		t.Fatalf("GetSessionSecResults by state failed: %v", err)
	}
	if len(stateFiltered) != 1 {
		t.Errorf("expected 1 verified result, got %d", len(stateFiltered))
	}

	// 5. Test GetSessionSecSummary
	summary, err := store.GetSessionSecSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetSessionSecSummary failed: %v", err)
	}
	if summary.TotalTests != 11 {
		t.Errorf("expected TotalTests = 11 from RunRecord, got %d", summary.TotalTests)
	}
	if summary.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount = 2, got %d", summary.VerifiedCount)
	}
}

func TestStore_CloudSecPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// 1. Create client and assessment
	client := &Client{
		ID:        uuid.New().String(),
		Name:      "CloudSec Test Corp",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-CLOUD-001",
		ClientID:       client.ID,
		Name:           "CloudSec Assessment",
		AssessmentType: "CLOUD_SECURITY",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 2. Test SaveCloudSecRun and GetCloudSecRun
	runRec := &cloudsec.RunRecord{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Mode:              cloudsec.ModeCredentialed,
		Provider:          cloudsec.ProviderAWS,
		ScopeIdentifier:   "123456789012",
		VerifiedPrincipal: "arn:aws:iam::123456789012:user/felix-auditor",
		TotalChecks:       8,
		ServicesAssessed:  8,
		VerifiedCount:     1,
		CandidateCount:    1,
		ObservedCount:     2,
		CoverageJSON:      `{"s3":{"provider":"AWS","service":"s3","status":"ASSESSED","checks_run":1,"verified":1}}`,
		CreatedAt:         time.Now().UTC(),
	}
	if err := store.SaveCloudSecRun(runRec); err != nil {
		t.Fatalf("SaveCloudSecRun failed: %v", err)
	}

	fetchedRun, err := store.GetCloudSecRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetCloudSecRun failed: %v", err)
	}
	if fetchedRun.ID != runRec.ID {
		t.Errorf("expected run ID %s, got %s", runRec.ID, fetchedRun.ID)
	}
	if fetchedRun.VerifiedCount != 1 {
		t.Errorf("expected VerifiedCount 1, got %d", fetchedRun.VerifiedCount)
	}
	if fetchedRun.VerifiedPrincipal != runRec.VerifiedPrincipal {
		t.Errorf("expected principal %s, got %s", runRec.VerifiedPrincipal, fetchedRun.VerifiedPrincipal)
	}

	// 3. Test SaveCloudSecResults and GetCloudSecResults
	res1 := cloudsec.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Provider:          cloudsec.ProviderAWS,
		Mode:              cloudsec.ModeCredentialed,
		Service:           "s3",
		CheckID:           "AWS-S3-PUBLIC-BUCKET",
		CheckName:         "S3 Public Bucket Access",
		ResourceID:        "my-open-bucket",
		Region:            "us-east-1",
		VerificationState: cloudsec.StateVerified,
		Severity:          report.SeverityHigh,
		Confidence:        report.ConfidenceHigh,
		EvidenceSummary:   "Bucket policy grants unauthenticated Principal * Allow",
		CreatedAt:         time.Now().UTC(),
	}
	res2 := cloudsec.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Provider:          cloudsec.ProviderAWS,
		Mode:              cloudsec.ModeCredentialed,
		Service:           "iam",
		CheckID:           "AWS-IAM-ADMIN-WILDCARD",
		CheckName:         "IAM Admin Policy Wildcards",
		ResourceID:        "admin-policy",
		Region:            "global",
		VerificationState: cloudsec.StateNotVulnerable,
		Severity:          report.SeverityInfo,
		Confidence:        report.ConfidenceHigh,
		EvidenceSummary:   "No unrestricted admin policies detected",
		CreatedAt:         time.Now().UTC(),
	}

	if err := store.SaveCloudSecResults([]cloudsec.Result{res1, res2}); err != nil {
		t.Fatalf("SaveCloudSecResults failed: %v", err)
	}

	allResults, err := store.GetCloudSecResults(asm.ID, exec.ID, "", "", "")
	if err != nil {
		t.Fatalf("GetCloudSecResults failed: %v", err)
	}
	if len(allResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(allResults))
	}

	// Filter by service
	svcFiltered, err := store.GetCloudSecResults(asm.ID, exec.ID, "", "s3", "")
	if err != nil {
		t.Fatalf("GetCloudSecResults by service failed: %v", err)
	}
	if len(svcFiltered) != 1 || svcFiltered[0].CheckID != "AWS-S3-PUBLIC-BUCKET" {
		t.Errorf("expected 1 S3 result, got %d", len(svcFiltered))
	}

	// Filter by state
	stateFiltered, err := store.GetCloudSecResults(asm.ID, exec.ID, "", "", string(cloudsec.StateVerified))
	if err != nil {
		t.Fatalf("GetCloudSecResults by state failed: %v", err)
	}
	if len(stateFiltered) != 1 {
		t.Errorf("expected 1 verified result, got %d", len(stateFiltered))
	}

	// 4. Test GetCloudSecSummary
	summary, err := store.GetCloudSecSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetCloudSecSummary failed: %v", err)
	}
	if summary.TotalChecks != 8 {
		t.Errorf("expected TotalChecks = 8 from RunRecord, got %d", summary.TotalChecks)
	}
	if summary.VerifiedCount != 1 {
		t.Errorf("expected VerifiedCount = 1, got %d", summary.VerifiedCount)
	}
}

func TestStore_BusinessLogicPersistenceAndMigration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	// Verify schema migration version 9 applied
	var maxVersion int
	err := store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&maxVersion)
	if err != nil {
		t.Fatalf("failed to query schema version: %v", err)
	}
	if maxVersion < 9 {
		t.Fatalf("expected schema version >= 9, got %d", maxVersion)
	}

	// 1. Create client and assessment
	client := &Client{
		ID:        uuid.New().String(),
		Name:      "BizLogic Test Corp",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-BIZLOGIC-001",
		ClientID:       client.ID,
		Name:           "Business Logic Assessment",
		AssessmentType: "BUSINESS_LOGIC",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       StatusRunning,
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 2. Test SaveBusinessLogicRun and GetBusinessLogicRun
	runRec := &businesslogic.RunRecord{
		ID:                 uuid.New().String(),
		AssessmentID:       asm.ID,
		ExecutionID:        exec.ID,
		TargetURL:          "https://shop.example.com",
		TotalChecks:        8,
		CategoriesAssessed: 8,
		WorkflowsModeled:   2,
		VerifiedCount:      2,
		CandidateCount:     1,
		ObservedCount:      0,
		InconclusiveCount:  1,
		BlockedCount:       1,
		NotVulnerableCount: 3,
		SyntheticFixture:   false,
		CoverageJSON:       `{"BL-01":{"category":"BL-01","code":"BL-01","name":"Workflow Circumvention","status":"ACTIVELY_TESTED","checks_run":1,"verified":1}}`,
		CreatedAt:          time.Now().UTC(),
	}
	if err := store.SaveBusinessLogicRun(runRec); err != nil {
		t.Fatalf("SaveBusinessLogicRun failed: %v", err)
	}

	fetchedRun, err := store.GetBusinessLogicRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetBusinessLogicRun failed: %v", err)
	}
	if fetchedRun.ID != runRec.ID {
		t.Errorf("expected run ID %s, got %s", runRec.ID, fetchedRun.ID)
	}
	if fetchedRun.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount 2, got %d", fetchedRun.VerifiedCount)
	}
	if fetchedRun.TargetURL != runRec.TargetURL {
		t.Errorf("expected target URL %s, got %s", runRec.TargetURL, fetchedRun.TargetURL)
	}

	// 3. Test SaveBusinessLogicResults and GetBusinessLogicResults
	res1 := businesslogic.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Category:          businesslogic.CategoryWorkflowCircumvention,
		CheckID:           "BL-01-WF-ORDER",
		CheckName:         "Order Flow Circumvention",
		WorkflowID:        "WF-ORDER",
		WorkflowName:      "E-Commerce Order",
		Endpoint:          "/checkout/fulfill",
		Method:            "POST",
		VerificationState: businesslogic.StateVerified,
		Severity:          report.SeverityHigh,
		Confidence:        report.ConfidenceHigh,
		EvidenceSummary:   "Terminal fulfillment executed without payment",
		CreatedAt:         time.Now().UTC(),
	}
	res2 := businesslogic.Result{
		ID:                uuid.New().String(),
		AssessmentID:      asm.ID,
		ExecutionID:       exec.ID,
		Category:          businesslogic.CategoryUnexpectedStateTransition,
		CheckID:           "BL-02-WF-ORDER",
		CheckName:         "Unexpected State Transition",
		WorkflowID:        "WF-ORDER",
		WorkflowName:      "E-Commerce Order",
		Endpoint:          "/order/status",
		Method:            "POST",
		VerificationState: businesslogic.StateNotVulnerable,
		Severity:          report.SeverityInfo,
		Confidence:        report.ConfidenceHigh,
		EvidenceSummary:   "Invalid transition correctly rejected",
		CreatedAt:         time.Now().UTC(),
	}

	if err := store.SaveBusinessLogicResults([]businesslogic.Result{res1, res2}); err != nil {
		t.Fatalf("SaveBusinessLogicResults failed: %v", err)
	}

	allResults, err := store.GetBusinessLogicResults(asm.ID, exec.ID, "", "")
	if err != nil {
		t.Fatalf("GetBusinessLogicResults failed: %v", err)
	}
	if len(allResults) != 2 {
		t.Fatalf("expected 2 results, got %d", len(allResults))
	}

	// Filter by category
	catFiltered, err := store.GetBusinessLogicResults(asm.ID, exec.ID, string(businesslogic.CategoryWorkflowCircumvention), "")
	if err != nil {
		t.Fatalf("GetBusinessLogicResults by category failed: %v", err)
	}
	if len(catFiltered) != 1 || catFiltered[0].CheckID != "BL-01-WF-ORDER" {
		t.Errorf("expected 1 BL-01 result, got %d", len(catFiltered))
	}

	// Filter by state
	stateFiltered, err := store.GetBusinessLogicResults(asm.ID, exec.ID, "", string(businesslogic.StateVerified))
	if err != nil {
		t.Fatalf("GetBusinessLogicResults by state failed: %v", err)
	}
	if len(stateFiltered) != 1 {
		t.Errorf("expected 1 verified result, got %d", len(stateFiltered))
	}

	// 4. Test GetBusinessLogicSummary
	summary, err := store.GetBusinessLogicSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetBusinessLogicSummary failed: %v", err)
	}
	if summary.TotalChecks != 8 {
		t.Errorf("expected TotalChecks = 8 from RunRecord, got %d", summary.TotalChecks)
	}
	if summary.VerifiedCount != 2 {
		t.Errorf("expected VerifiedCount = 2, got %d", summary.VerifiedCount)
	}
}

func TestStore_BusinessLogicMigrationFromV8(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_v8_to_v9.db")

	// 1. Manually create schema_migrations with versions up to 8
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		);
		INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (2, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (3, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (4, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (5, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (6, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (7, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (8, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to seed v8 schema_migrations: %v", err)
	}
	db.Close()

	// 2. Open with NewSQLiteStore which runs migrate()
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to migrate from v8: %v", err)
	}
	defer store.Close()

	// 3. Verify max version is at least 9
	var currentVersion int
	err = store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		t.Fatalf("failed to query version: %v", err)
	}
	if currentVersion < 9 {
		t.Errorf("expected schema version >= 9 after upgrade from v8, got %d", currentVersion)
	}

	// 4. Verify migration v9 tables exist
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='assessment_businesslogic_runs'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("expected assessment_businesslogic_runs table to exist, count: %d, err: %v", count, err)
	}
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='assessment_businesslogic_results'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("expected assessment_businesslogic_results table to exist, count: %d, err: %v", count, err)
	}
}

func TestStore_CorrelationMigrationFromV9(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_v9_to_v10.db")

	// 1. Manually create schema_migrations with versions up to 9
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite db: %v", err)
	}
	_, err = db.Exec(`
		CREATE TABLE schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL
		);
		INSERT INTO schema_migrations (version, applied_at) VALUES (1, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (2, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (3, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (4, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (5, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (6, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (7, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (8, CURRENT_TIMESTAMP);
		INSERT INTO schema_migrations (version, applied_at) VALUES (9, CURRENT_TIMESTAMP);
	`)
	if err != nil {
		db.Close()
		t.Fatalf("failed to seed v9 schema_migrations: %v", err)
	}
	db.Close()

	// 2. Open with NewSQLiteStore which runs migrate()
	store, err := NewSQLiteStore(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStore failed to migrate from v9: %v", err)
	}
	defer store.Close()

	// 3. Verify max version is 10
	var currentVersion int
	err = store.db.QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&currentVersion)
	if err != nil {
		t.Fatalf("failed to query version: %v", err)
	}
	if currentVersion != 10 {
		t.Errorf("expected schema version 10 after upgrade from v9, got %d", currentVersion)
	}

	// 4. Verify migration v10 tables exist
	var count int
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='assessment_correlation_runs'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("expected assessment_correlation_runs table to exist, count: %d, err: %v", count, err)
	}
	err = store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='assessment_attack_paths'").Scan(&count)
	if err != nil || count != 1 {
		t.Errorf("expected assessment_attack_paths table to exist, count: %d, err: %v", count, err)
	}
}

func TestStore_CorrelationRunAndPaths(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := &Client{
		ID:   uuid.New().String(),
		Name: "Correlation Test Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-COR-001",
		ClientID:       client.ID,
		Name:           "Correlation Engine Assessment",
		AssessmentType: "full",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       "RUNNING",
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec); err != nil {
		t.Fatalf("CreateExecution failed: %v", err)
	}

	// 1. Save and Get CorrelationRun
	runRec := &correlation.RunRecord{
		ID:                     uuid.New().String(),
		AssessmentID:           asm.ID,
		ExecutionID:            exec.ID,
		TotalFindings:          12,
		CandidateRelationships: 6,
		CandidatePaths:         4,
		VerifiedPaths:          2,
		HighestRisk:            report.SeverityCritical,
		CoverageJSON:           `{"total_findings":12,"candidate_paths":4,"verified_paths":2,"highest_risk_score":90,"highest_risk_level":"CRITICAL"}`,
		SyntheticFixture:       false,
		CreatedAt:              time.Now().UTC(),
	}

	if err := store.SaveCorrelationRun(runRec); err != nil {
		t.Fatalf("SaveCorrelationRun failed: %v", err)
	}

	fetchedRun, err := store.GetCorrelationRun(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetCorrelationRun failed: %v", err)
	}
	if fetchedRun.ID != runRec.ID {
		t.Errorf("expected run ID %s, got %s", runRec.ID, fetchedRun.ID)
	}
	if fetchedRun.VerifiedPaths != 2 {
		t.Errorf("expected VerifiedPaths = 2, got %d", fetchedRun.VerifiedPaths)
	}

	// 2. Save and Get AttackPaths
	path1 := correlation.AttackPath{
		ID:                uuid.New().String(),
		Title:             "API Endpoint -> BOLA Customer Record Exposure",
		EntryPoint:        "https://api.example.com/v1/users",
		TargetAsset:       "https://api.example.com",
		PrimaryWeakness:   "Broken Object-Level Authorization",
		TerminalImpact:    "Unauthorized access to tenant records",
		Status:            correlation.PathVerified,
		Confidence:        report.ConfidenceHigh,
		CombinedRiskLevel: report.SeverityCritical,
		CombinedRiskScore: 90,
		RiskRationale:     "Direct verified horizontal IDOR exposes tenant customer records",
		NodeIDs:           []string{"F-01", "F-02"},
		Remediation:       "Implement tenant-isolated authorization checks on object retrieval",
		CreatedAt:         time.Now().UTC(),
	}
	path2 := correlation.AttackPath{
		ID:                uuid.New().String(),
		Title:             "Public S3 Bucket -> Log Exposure",
		EntryPoint:        "https://logs.example.com",
		TargetAsset:       "s3://example-logs",
		PrimaryWeakness:   "Public Cloud Storage",
		TerminalImpact:    "Public access to internal access logs",
		Status:            correlation.PathCandidate,
		Confidence:        report.ConfidenceMedium,
		CombinedRiskLevel: report.SeverityMedium,
		CombinedRiskScore: 50,
		RiskRationale:     "Candidate path connecting public bucket to unauthenticated reading",
		NodeIDs:           []string{"F-03", "F-04"},
		Remediation:       "Apply S3 Block Public Access",
		CreatedAt:         time.Now().UTC(),
	}

	if err := store.SaveAttackPaths(asm.ID, exec.ID, []correlation.AttackPath{path1, path2}); err != nil {
		t.Fatalf("SaveAttackPaths failed: %v", err)
	}

	// Retrieve all
	paths, err := store.GetAttackPaths(asm.ID, exec.ID, "", "")
	if err != nil {
		t.Fatalf("GetAttackPaths failed: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %d", len(paths))
	}

	// Filter by status
	verifiedOnly, err := store.GetAttackPaths(asm.ID, exec.ID, string(correlation.PathVerified), "")
	if err != nil {
		t.Fatalf("GetAttackPaths by status failed: %v", err)
	}
	if len(verifiedOnly) != 1 || verifiedOnly[0].Status != correlation.PathVerified {
		t.Errorf("expected 1 verified path, got %d", len(verifiedOnly))
	}

	// Filter by minRisk
	critOnly, err := store.GetAttackPaths(asm.ID, exec.ID, "", "CRITICAL")
	if err != nil {
		t.Fatalf("GetAttackPaths by minRisk failed: %v", err)
	}
	if len(critOnly) != 1 || critOnly[0].CombinedRiskLevel != report.SeverityCritical {
		t.Errorf("expected 1 critical path, got %d", len(critOnly))
	}

	// 3. GetCorrelationSummary
	summary, err := store.GetCorrelationSummary(asm.ID, exec.ID)
	if err != nil {
		t.Fatalf("GetCorrelationSummary failed: %v", err)
	}
	if summary.VerifiedPaths != 2 {
		t.Errorf("expected VerifiedPaths = 2, got %d", summary.VerifiedPaths)
	}
}

func TestScenarioF_PersistenceAndRepeatExecution(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := &Client{
		ID:   uuid.New().String(),
		Name: "Scenario F Corp",
	}
	if err := store.CreateClient(client); err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}

	asm := &Assessment{
		ID:             uuid.New().String(),
		Ref:            "ASM-SCENARIO-F",
		ClientID:       client.ID,
		Name:           "Scenario F Assessment",
		AssessmentType: "full",
		Status:         StatusRunning,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := store.CreateAssessment(asm); err != nil {
		t.Fatalf("CreateAssessment failed: %v", err)
	}

	exec1 := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       "COMPLETED",
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec1); err != nil {
		t.Fatalf("CreateExecution 1 failed: %v", err)
	}

	exec2 := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       "RUNNING",
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec2); err != nil {
		t.Fatalf("CreateExecution 2 failed: %v", err)
	}

	// 1. Initial run on Execution 1
	run1 := &correlation.RunRecord{
		ID:                     uuid.New().String(),
		AssessmentID:           asm.ID,
		ExecutionID:            exec1.ID,
		TotalFindings:          4,
		CandidateRelationships: 2,
		CandidatePaths:         1,
		VerifiedPaths:          1,
		HighestRisk:            report.SeverityHigh,
		CoverageJSON:           `{"total_findings":4,"candidate_paths":1,"verified_paths":1}`,
		SyntheticFixture:       false,
		CreatedAt:              time.Now().UTC(),
	}
	if err := store.SaveCorrelationRun(run1); err != nil {
		t.Fatalf("SaveCorrelationRun exec1 failed: %v", err)
	}

	sharedPathID := "PATH-F01-F02"
	pathExec1 := correlation.AttackPath{
		ID:                sharedPathID,
		Title:             "Exec 1 Shared Path ID",
		EntryPoint:        "https://api.example.com/v1",
		TargetAsset:       "https://api.example.com",
		PrimaryWeakness:   "Weakness 1",
		TerminalImpact:    "Impact 1",
		Status:            correlation.PathVerified,
		Confidence:        report.ConfidenceHigh,
		CombinedRiskLevel: report.SeverityHigh,
		CombinedRiskScore: 75,
		NodeIDs:           []string{"F01", "F02"},
		CreatedAt:         time.Now().UTC(),
	}
	if err := store.SaveAttackPaths(asm.ID, exec1.ID, []correlation.AttackPath{pathExec1}); err != nil {
		t.Fatalf("SaveAttackPaths exec1 failed: %v", err)
	}

	paths1, err := store.GetAttackPaths(asm.ID, exec1.ID, "", "")
	if err != nil || len(paths1) != 1 {
		t.Fatalf("expected 1 path for exec1, got %d, err: %v", len(paths1), err)
	}

	// 2. Correlation on Execution 2 with identical logical path ID
	run2 := &correlation.RunRecord{
		ID:                     uuid.New().String(),
		AssessmentID:           asm.ID,
		ExecutionID:            exec2.ID,
		TotalFindings:          6,
		CandidateRelationships: 3,
		CandidatePaths:         2,
		VerifiedPaths:          2,
		HighestRisk:            report.SeverityCritical,
		CoverageJSON:           `{"total_findings":6,"candidate_paths":2,"verified_paths":2}`,
		SyntheticFixture:       false,
		CreatedAt:              time.Now().UTC(),
	}
	if err := store.SaveCorrelationRun(run2); err != nil {
		t.Fatalf("SaveCorrelationRun exec2 failed: %v", err)
	}

	pathExec2 := correlation.AttackPath{
		ID:                sharedPathID, // Same logical ID as in exec1
		Title:             "Exec 2 Identical Logical ID Different Data",
		EntryPoint:        "https://api.example.com/v2",
		TargetAsset:       "https://api.example.com/v2",
		PrimaryWeakness:   "Weakness 2",
		TerminalImpact:    "Impact 2",
		Status:            correlation.PathCandidate,
		Confidence:        report.ConfidenceMedium,
		CombinedRiskLevel: report.SeverityMedium,
		CombinedRiskScore: 55,
		NodeIDs:           []string{"F01", "F02"},
		CreatedAt:         time.Now().UTC(),
	}
	// Must succeed without primary key conflict with exec1
	if err := store.SaveAttackPaths(asm.ID, exec2.ID, []correlation.AttackPath{pathExec2}); err != nil {
		t.Fatalf("SaveAttackPaths exec2 with shared ID failed: %v", err)
	}

	// Verify exec1 was NOT overwritten or corrupted
	paths1After, err := store.GetAttackPaths(asm.ID, exec1.ID, "", "")
	if err != nil || len(paths1After) != 1 {
		t.Fatalf("exec1 paths corrupted after exec2 save: len=%d, err=%v", len(paths1After), err)
	}
	if paths1After[0].Title != "Exec 1 Shared Path ID" {
		t.Errorf("exec1 path overwritten by exec2: got title %q", paths1After[0].Title)
	}
	if paths1After[0].Status != correlation.PathVerified {
		t.Errorf("exec1 status overwritten: got %v", paths1After[0].Status)
	}

	// Verify exec2 has its own path
	paths2, err := store.GetAttackPaths(asm.ID, exec2.ID, "", "")
	if err != nil || len(paths2) != 1 {
		t.Fatalf("expected 1 path for exec2, got %d, err=%v", len(paths2), err)
	}
	if paths2[0].Title != "Exec 2 Identical Logical ID Different Data" {
		t.Errorf("exec2 path title unexpected: %q", paths2[0].Title)
	}

	// 3. Rerun on Execution 2 (Repeat execution)
	run2Updated := &correlation.RunRecord{
		ID:                     run2.ID, // Same run record ID on rerun
		AssessmentID:           asm.ID,
		ExecutionID:            exec2.ID,
		TotalFindings:          6,
		CandidateRelationships: 4,
		CandidatePaths:         2,
		VerifiedPaths:          2,
		HighestRisk:            report.SeverityCritical,
		CoverageJSON:           `{"total_findings":6,"candidate_paths":2,"verified_paths":2,"rerun":true}`,
		SyntheticFixture:       false,
		CreatedAt:              time.Now().UTC(),
	}
	if err := store.SaveCorrelationRun(run2Updated); err != nil {
		t.Fatalf("SaveCorrelationRun repeat failed: %v", err)
	}

	pathExec2Updated := correlation.AttackPath{
		ID:                sharedPathID,
		Title:             "Exec 2 Updated Title on Rerun",
		EntryPoint:        "https://api.example.com/v2-updated",
		TargetAsset:       "https://api.example.com/v2",
		PrimaryWeakness:   "Weakness 2 Updated",
		TerminalImpact:    "Impact 2 Updated",
		Status:            correlation.PathVerified,
		Confidence:        report.ConfidenceHigh,
		CombinedRiskLevel: report.SeverityHigh,
		CombinedRiskScore: 70,
		NodeIDs:           []string{"F01", "F02"},
		CreatedAt:         time.Now().UTC(),
	}
	if err := store.SaveAttackPaths(asm.ID, exec2.ID, []correlation.AttackPath{pathExec2Updated}); err != nil {
		t.Fatalf("SaveAttackPaths repeat on exec2 failed: %v", err)
	}

	// Confirm no duplicate entries were created for exec2
	paths2Rerun, err := store.GetAttackPaths(asm.ID, exec2.ID, "", "")
	if err != nil {
		t.Fatalf("GetAttackPaths rerun failed: %v", err)
	}
	if len(paths2Rerun) != 1 {
		t.Fatalf("expected exactly 1 path for exec2 after rerun, got %d (duplicate created)", len(paths2Rerun))
	}
	if paths2Rerun[0].Title != "Exec 2 Updated Title on Rerun" {
		t.Errorf("expected updated title after rerun, got %q", paths2Rerun[0].Title)
	}

	// Confirm exec1 remains untouched
	paths1Final, err := store.GetAttackPaths(asm.ID, exec1.ID, "", "")
	if err != nil || len(paths1Final) != 1 {
		t.Fatalf("exec1 paths damaged after rerun: len=%d, err=%v", len(paths1Final), err)
	}
	if paths1Final[0].Title != "Exec 1 Shared Path ID" {
		t.Errorf("exec1 corrupted after rerun of exec2: %q", paths1Final[0].Title)
	}

	// 4. Empty results handling
	exec3 := &AssessmentExecution{
		ID:           uuid.New().String(),
		AssessmentID: asm.ID,
		Status:       "COMPLETED",
		StartedAt:    time.Now().UTC(),
	}
	if err := store.CreateExecution(exec3); err != nil {
		t.Fatalf("CreateExecution 3 failed: %v", err)
	}

	run3 := &correlation.RunRecord{
		ID:                     uuid.New().String(),
		AssessmentID:           asm.ID,
		ExecutionID:            exec3.ID,
		TotalFindings:          0,
		CandidateRelationships: 0,
		CandidatePaths:         0,
		VerifiedPaths:          0,
		HighestRisk:            "",
		CoverageJSON:           `{"total_findings":0,"candidate_paths":0,"verified_paths":0}`,
		SyntheticFixture:       false,
		CreatedAt:              time.Now().UTC(),
	}
	if err := store.SaveCorrelationRun(run3); err != nil {
		t.Fatalf("SaveCorrelationRun empty exec3 failed: %v", err)
	}
	if err := store.SaveAttackPaths(asm.ID, exec3.ID, []correlation.AttackPath{}); err != nil {
		t.Fatalf("SaveAttackPaths empty exec3 failed: %v", err)
	}

	emptyPaths, err := store.GetAttackPaths(asm.ID, exec3.ID, "", "")
	if err != nil {
		t.Fatalf("GetAttackPaths empty exec3 failed: %v", err)
	}
	if len(emptyPaths) != 0 {
		t.Fatalf("expected 0 paths for empty exec3, got %d", len(emptyPaths))
	}

	emptySummary, err := store.GetCorrelationSummary(asm.ID, exec3.ID)
	if err != nil {
		t.Fatalf("GetCorrelationSummary empty exec3 failed: %v", err)
	}
	if emptySummary.TotalFindings != 0 || emptySummary.VerifiedPaths != 0 {
		t.Errorf("expected 0 findings and 0 verified paths, got %+v", emptySummary)
	}
}
