package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"felix/pkg/api"
	"felix/pkg/crawler"
	"felix/pkg/monitor"
	"felix/pkg/report"
)

func TestPhase14_RealEndToEndIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tempDir := t.TempDir()
	stateDir := filepath.Join(tempDir, "felix-state")
	targetID := "prod-customer-portal"
	canarySecret := "sk_test_secret_canary_phase14_9999"

	// -------------------------------------------------------------------------
	// 0. Setup Local Mock Servers (Webhooks & Application Target)
	// -------------------------------------------------------------------------
	var webhookMu sync.Mutex
	var receivedAlerts []map[string]interface{}

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookMu.Lock()
		defer webhookMu.Unlock()

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err == nil {
			receivedAlerts = append(receivedAlerts, payload)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer webhookServer.Close()

	// Application Target serving client bundle and API endpoints
	appServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static/chunks/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			// Next.js client bundle with server action reference, documented route, and shadow route
			content := fmt.Sprintf(`
				// Bundle canary: Observed token: %s
				self.__BUILD_MANIFEST = {"/": ["static/chunks/main.js"]};
				const actionRef = createServerReference("$$ACTION_ID_9a8b7c6d5e4f3a2b1c0d", "submitOrder");
				function loadUsers() {
					return fetch("/api/v1/users", { method: "GET" });
				}
				function loadOrders() {
					return fetch("/api/v1/orders", { method: "GET" });
				}
			`, canarySecret)
			_, _ = w.Write([]byte(content))

		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			spec := `{
				"openapi": "3.0.0",
				"info": {"title": "Customer Portal API", "version": "1.0.0"},
				"paths": {
					"/api/v1/orders": {
						"get": {
							"operationId": "getOrders",
							"responses": {"200": {"description": "Order list"}}
						}
					}
				}
			}`
			_, _ = w.Write([]byte(spec))

		case "/api/v1/orders":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"orders": [{"id": "ord_101", "total": 42.50}]}`))

		case "/api/v1/users":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"users": [{"id": "usr_01", "name": "Alice"}]}`))

		case "/api/v2/tenants/tenant_alpha/admin":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"admin": true, "tenant_id": "tenant_alpha"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer appServer.Close()

	// -------------------------------------------------------------------------
	// 1. Declarative Multi-Tenant Profile (P14.4)
	// -------------------------------------------------------------------------
	profile := &api.TargetProfile{
		Version: 1,
		Target: api.TargetConfig{
			Name:           targetID,
			BaseURLs:       []string{appServer.URL},
			AllowedHosts:   []string{"127.0.0.1", "localhost"},
			AllowedMethods: []string{"GET", "HEAD"},
		},
		Safety: api.SafetyConfig{
			Mode:                         "non_destructive",
			AllowCrossTenantChecks:       true,
			RequireExplicitAuthorization: false,
			MaxRequests:                  50,
			RequestsPerSecond:            10,
			TimeoutSeconds:               5,
		},
		Tenants: []api.TenantConfig{
			{
				ID:          "tenant_alpha",
				Identity:    "alpha@corp.internal",
				ResourceIDs: []string{"res_100"},
			},
			{
				ID:          "tenant_beta",
				Identity:    "beta@corp.internal",
				ResourceIDs: []string{"res_200"},
			},
		},
		CrossTenantTests: api.CrossTenantTestsConfig{
			Enabled: true,
			Comparisons: []api.TenantComparison{
				{
					RequesterTenant:     "tenant_beta",
					ResourceOwnerTenant: "tenant_alpha",
					ResourceID:          "res_100",
					Path:                "/api/v1/users",
					Method:              "GET",
				},
			},
		},
		Monitoring: &api.MonitoringConfig{
			Enabled:         true,
			RetainSnapshots: 10,
			Webhooks: []api.MonitorWebhookConfig{
				{
					ID:                "slack-alerts",
					Provider:          "slack",
					URL:               webhookServer.URL + "/webhook/alert",
					Enabled:           true,
					AllowInsecureHTTP: true,
					AllowLoopback:     true,
				},
			},
		},
	}

	// -------------------------------------------------------------------------
	// 2. Client Bundle Extraction (P14.1)
	// -------------------------------------------------------------------------
	extractor := crawler.NewBundleExtractor(crawler.BundleAnalysisOptions{
		MaxBundleSize: 5 * 1024 * 1024,
		MaxTokens:     50000,
	})

	bundleURL := appServer.URL + "/static/chunks/main.js"
	bundleResp, err := http.Get(bundleURL)
	if err != nil {
		t.Fatalf("failed fetching mock bundle: %v", err)
	}
	defer bundleResp.Body.Close()
	bundleContent, err := io.ReadAll(bundleResp.Body)
	if err != nil {
		t.Fatalf("failed reading mock bundle body: %v", err)
	}

	candidates, actions, _, warnings := extractor.ExtractFromBundle(bundleContent, bundleURL)
	if len(warnings) > 0 {
		t.Logf("bundle extraction warnings: %v", warnings)
	}

	// Verify server actions are not fabricated into HTTP endpoints
	if len(actions) == 0 {
		t.Fatalf("expected at least 1 ServerActionReference extracted, got 0")
	}
	for _, cand := range candidates {
		if strings.Contains(cand.Path, "ACTION_ID") {
			t.Fatalf("server action ID was incorrectly fabricated into route candidate path: %s", cand.Path)
		}
	}

	// -------------------------------------------------------------------------
	// 3. API Topology Reconciliation (P14.2)
	// -------------------------------------------------------------------------
	specURL := appServer.URL + "/openapi.json"
	specResp, err := http.Get(specURL)
	if err != nil {
		t.Fatalf("failed fetching mock spec: %v", err)
	}
	defer specResp.Body.Close()
	specContent, err := io.ReadAll(specResp.Body)
	if err != nil {
		t.Fatalf("failed reading mock spec body: %v", err)
	}

	specParser := api.NewSpecParser()
	documentedOps, specMeta, err := specParser.ParseSpecificationData(specContent, "openapi.json")
	if err != nil {
		t.Fatalf("failed parsing OpenAPI spec: %v", err)
	}

	reconEngine := api.NewReconciliationEngine([]api.SpecMetadata{*specMeta}, documentedOps, api.DefaultReconciliationOptions())
	reconReport := reconEngine.Reconcile(candidates)

	// Verify documented vs shadow classification
	hasDocumented := false
	hasShadow := false
	for _, item := range reconReport.Items {
		if item.Classification == api.ClassificationDocumentedMatch {
			hasDocumented = true
		}
		if item.Classification == api.ClassificationUndocumentedCandidate {
			hasShadow = true
		}
	}
	if !hasDocumented {
		t.Fatalf("expected at least 1 documented route (/api/v1/orders), found none")
	}
	if !hasShadow {
		t.Fatalf("expected at least 1 shadow route (/api/v1/users), found none")
	}

	// -------------------------------------------------------------------------
	// 4. Safe Exploitability Probing (P14.3)
	// -------------------------------------------------------------------------
	proberOpts := api.DefaultProberOptions()
	proberOpts.AllowLoopback = true
	prober := api.NewProberEngine(proberOpts)

	probeReport := prober.ProbeBatch(ctx, reconReport.Items, appServer.URL)
	if len(probeReport.Results) == 0 {
		t.Fatalf("expected prober results, got 0")
	}

	// -------------------------------------------------------------------------
	// 5. Multi-Tenant Authorization Evaluation (P14.4)
	// -------------------------------------------------------------------------
	mtEngine := api.NewMultiTenantEngine(profile, api.MultiTenantEngineOptions{
		CLIOptIn:      true,
		AllowLoopback: true,
	})
	mtReport := mtEngine.RunCrossTenantChecks(ctx)
	if len(mtReport.Results) == 0 {
		t.Fatalf("expected multi-tenant comparison results, got 0")
	}

	// -------------------------------------------------------------------------
	// 6. Monitor Engine: Step 1 Initial Scan & Baseline (P14.5)
	// -------------------------------------------------------------------------
	monEngine, err := monitor.NewMonitorEngine(profile, stateDir)
	if err != nil {
		t.Fatalf("failed initializing monitor engine: %v", err)
	}

	buildOpts := monitor.SnapshotBuildOptions{
		TargetID:   targetID,
		TargetName: profile.Target.Name,
		BaseURLs:   profile.Target.BaseURLs,
		IsComplete: true,
	}

	snap1, err := monEngine.CaptureSnapshot(ctx, candidates, reconReport, probeReport, buildOpts)
	if err != nil {
		t.Fatalf("failed capturing initial snapshot: %v", err)
	}

	// Baseline comparison on initial scan
	diff1, deliv1, err := monEngine.RunDiff(ctx, snap1, true)
	if err != nil {
		t.Fatalf("initial run diff failed: %v", err)
	}

	// Requirement 1: Initial authorized scan creates valid baseline without alerting on every existing route
	if !diff1.HasBaseline {
		t.Fatalf("expected initial scan to establish baseline, got HasBaseline=false")
	}
	if deliv1.TotalDelivered != 0 {
		t.Fatalf("initial baseline creation should not send alerts for existing baseline routes, sent: %d", deliv1.TotalDelivered)
	}

	webhookMu.Lock()
	initialAlertCount := len(receivedAlerts)
	webhookMu.Unlock()
	if initialAlertCount != 0 {
		t.Fatalf("expected 0 webhook alerts during initial baseline setup, got %d", initialAlertCount)
	}

	// -------------------------------------------------------------------------
	// 7. Step 2 & 3 & 4: Later Scan Discovers New Shadow Route (P14.5 Drift)
	// -------------------------------------------------------------------------
	// Add a new undocumented route candidate with a sensitive tenant identifier
	newCandidate := crawler.RouteCandidate{
		ID:               "cand_new_admin",
		Path:             "/api/v2/tenants/{tenant_id}/admin",
		HTTPMethod:       "GET",
		OriginatingAsset: bundleURL,
		SourceType:       crawler.SourceTypeNextManifest,
		Confidence:       crawler.ConfidenceConfirmed,
		DiscoveredAt:     time.Now().UTC(),
	}
	candidatesV2 := append(candidates, newCandidate)

	reconReportV2 := reconEngine.Reconcile(candidatesV2)
	probeReportV2 := prober.ProbeBatch(ctx, reconReportV2.Items, appServer.URL)

	snap2, err := monEngine.CaptureSnapshot(ctx, candidatesV2, reconReportV2, probeReportV2, buildOpts)
	if err != nil {
		t.Fatalf("failed capturing second snapshot: %v", err)
	}

	// Step 4 & 5: Run diff with alerting enabled
	diff2, deliv2, err := monEngine.RunDiff(ctx, snap2, true)
	if err != nil {
		t.Fatalf("second run diff failed: %v", err)
	}

	// Requirement 2, 3, 4: Detects NEW_SHADOW_ROUTE and classifies with high priority
	foundNewRouteEvent := false
	for _, evt := range diff2.Events {
		if evt.Classification == monitor.ClassificationNewShadowRoute && strings.Contains(evt.CanonicalRoute, "/api/v2/tenants") {
			foundNewRouteEvent = true
			if evt.Priority != monitor.PriorityCritical && evt.Priority != monitor.PriorityHigh {
				t.Fatalf("expected CRITICAL or HIGH priority for sensitive shadow route, got %s", evt.Priority)
			}
		}
	}
	if !foundNewRouteEvent {
		t.Fatalf("expected NEW_SHADOW_ROUTE event detected in drift report, got: %+v", diff2.Events)
	}

	// Requirement 5: Enabled webhook receives a sanitized alert
	if deliv2.TotalDelivered != 1 {
		t.Fatalf("expected exactly 1 alert delivered to webhook, got %d", deliv2.TotalDelivered)
	}

	webhookMu.Lock()
	currentAlertCount := len(receivedAlerts)
	latestAlert := receivedAlerts[len(receivedAlerts)-1]
	webhookMu.Unlock()

	if currentAlertCount != 1 {
		t.Fatalf("expected webhook server to receive 1 alert, got %d", currentAlertCount)
	}

	alertBytes, _ := json.Marshal(latestAlert)
	alertStr := string(alertBytes)
	if !strings.Contains(alertStr, "NEW_SHADOW_ROUTE") {
		t.Fatalf("webhook payload does not mention NEW_SHADOW_ROUTE: %s", alertStr)
	}

	// -------------------------------------------------------------------------
	// 8. Requirement 6: Duplicate Scan Prevention (Deduplication Across Runs)
	// -------------------------------------------------------------------------
	_, deliv3, err := monEngine.RunDiff(ctx, snap2, true)
	if err != nil {
		t.Fatalf("third run diff failed: %v", err)
	}
	if deliv3.TotalDelivered != 0 {
		t.Fatalf("duplicate scan should deliver 0 alerts, got %d", deliv3.TotalDelivered)
	}
	if deliv3.TotalSkippedDedupe < 1 {
		t.Fatalf("expected duplicate drift event to be skipped by deduplication store, skipped: %d", deliv3.TotalSkippedDedupe)
	}

	webhookMu.Lock()
	if len(receivedAlerts) != 1 {
		t.Fatalf("webhook count should remain 1 after repeated scan, got %d", len(receivedAlerts))
	}
	webhookMu.Unlock()

	// -------------------------------------------------------------------------
	// 9. Requirement 7: Incomplete Scan Suppresses False Removals
	// -------------------------------------------------------------------------
	incompleteOpts := buildOpts
	incompleteOpts.IsComplete = false // Scan was interrupted or partial
	// Partial candidate set missing existing routes
	snapIncomplete, err := monEngine.CaptureSnapshot(ctx, []crawler.RouteCandidate{newCandidate}, nil, nil, incompleteOpts)
	if err != nil {
		t.Fatalf("failed capturing incomplete snapshot: %v", err)
	}

	diffIncomplete, _, err := monEngine.RunDiff(ctx, snapIncomplete, false)
	if err != nil {
		t.Fatalf("diff on incomplete snapshot failed: %v", err)
	}

	// Verify route removal events are suppressed
	for _, evt := range diffIncomplete.Events {
		if evt.Classification == monitor.ClassificationRemovedRoute {
			t.Fatalf("incomplete scan improperly generated REMOVED_ROUTE drift event: %+v", evt)
		}
	}

	// -------------------------------------------------------------------------
	// 10. Requirement 8: Persistence and Restart Survival
	// -------------------------------------------------------------------------
	freshMonEngine, err := monitor.NewMonitorEngine(profile, stateDir)
	if err != nil {
		t.Fatalf("failed to re-instantiate monitor engine after restart: %v", err)
	}

	status, err := freshMonEngine.GetStatus(ctx, targetID)
	if err != nil {
		t.Fatalf("failed reading monitor status after restart: %v", err)
	}
	if !status.HasBaseline {
		t.Fatalf("expected baseline to persist across engine restart")
	}
	if status.TotalDelivered < 1 {
		t.Fatalf("expected delivery state to persist across engine restart, recorded: %d", status.TotalDelivered)
	}

	// -------------------------------------------------------------------------
	// 11. Requirement 9: Secret Canary Zero-Leakage
	// -------------------------------------------------------------------------
	// Inspect webhook payload
	if strings.Contains(alertStr, canarySecret) {
		t.Fatalf("CANARY LEAK: Webhook payload contains unredacted canary secret: %s", alertStr)
	}

	// Inspect persistent state files
	targetDir := filepath.Join(stateDir, monitor.SanitizeTargetID(targetID))
	err = filepath.Walk(targetDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(data), canarySecret) {
			return fmt.Errorf("CANARY LEAK: file %s contains unredacted secret", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("%v", err)
	}

	// -------------------------------------------------------------------------
	// 12. Requirement 10: Existing Reporting Workflows Functional
	// -------------------------------------------------------------------------
	sampleFinding := report.Finding{
		ID:          "find_p14_e2e_01",
		Title:       "Undocumented Shadow Endpoint with Sensitive Parameter",
		Description: "Discovered an exposed undocumented route requiring authorization check",
		Severity:    report.SeverityHigh,
		Confidence:  report.ConfidenceHigh,
		Target:      appServer.URL,
		Endpoint:    "/api/v2/tenants/tenant_alpha/admin",
		Method:      "GET",
		Status:      report.FindingStatusConfirmed,
	}

	testRep := report.BuildReport(appServer.URL, []report.Finding{sampleFinding})

	// JSON generation
	jsonData, err := report.GenerateJSON(testRep)
	if err != nil || len(jsonData) == 0 {
		t.Fatalf("failed generating JSON report: %v", err)
	}

	// HTML generation
	htmlStr, err := report.GenerateHTML(testRep)
	if err != nil || len(htmlStr) == 0 {
		t.Fatalf("failed generating HTML report: %v", err)
	}

	// SARIF generation
	sarifBytes, err := report.GenerateSARIF(testRep)
	if err != nil || len(sarifBytes) == 0 {
		t.Fatalf("failed generating SARIF report: %v", err)
	}
}
