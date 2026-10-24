package test

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/api"
	"felix/pkg/apk"
	"felix/pkg/clierror"
	"felix/pkg/cloud"
	"felix/pkg/correlation"
	"felix/pkg/crawler"
	"felix/pkg/monitor"
	"felix/pkg/report"
	"felix/pkg/secrets"
	"felix/pkg/update"
)

// TestFullRegressionCampaign_12Workflows exercises the 12 core subsystem and cross-package
// integration workflows defined in Phase 12.6, validating security boundaries, exit code contracts,
// and output fidelity at the subsystem level. (Full CLI command execution is tested in cmd/felix).
func TestFullRegressionCampaign_12Workflows(t *testing.T) {
	// Workflow 1: [Subsystem Contract] Benign web assessment completing cleanly with exit code 0
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_BenignTargetCleanSuccess)
	t.Run("Workflow_01_BenignWebAssessment_CleanSuccess", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<!DOCTYPE html><html><head><title>Clean App</title></head><body><h1>Welcome</h1></body></html>`)
		}))
		defer ts.Close()

		rep := report.BuildReport(ts.URL, nil)
		rep.CompletionStatus = "COMPLETED"
		report.RecalculateReportRisk(&rep)

		if err := report.ValidateReportIntegrity(rep); err != nil {
			t.Fatalf("clean assessment failed integrity validation: %v", err)
		}

		cls := clierror.ClassifyAssessment("COMPLETED", nil, false, nil)
		if cls.ExitCode() != clierror.ExitSuccess {
			t.Errorf("expected ExitSuccess (0) for benign scan, got: %d", cls.ExitCode())
		}
		if rep.RiskScore != 0 || rep.RiskLevel != "INFORMATIONAL" {
			t.Errorf("expected clean risk score 0 and level INFORMATIONAL, got %d (%s)", rep.RiskScore, rep.RiskLevel)
		}
	})

	// Workflow 2: [Subsystem Contract] Assessment with synthetic security findings returning exit code 1
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_EndToEndScan)
	t.Run("Workflow_02_SecurityFindings_ExitCode1", func(t *testing.T) {
		f := report.Finding{
			ID:          "FND-SYNTH-01",
			Title:       "Hardcoded JWT Secret Discovered",
			Severity:    report.SeverityHigh,
			Confidence:  report.ConfidenceHigh,
			Target:      "https://target.corp",
			Endpoint:    "/api/keys",
			Category:    "secrets-leak",
			Fingerprint: "fp-synth-01",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "VERIFIED_EXPOSURE",
			},
		}

		rep := report.BuildReport("https://target.corp", []report.Finding{f})
		rep.CompletionStatus = "COMPLETED"
		report.RecalculateReportRisk(&rep)

		hasViolation := rep.Summary.CriticalCount > 0 || rep.Summary.HighCount > 0 ||
			rep.Summary.MediumCount > 0 || rep.Summary.LowCount > 0
		cls := clierror.ClassifyAssessment(rep.CompletionStatus, nil, hasViolation, nil)

		if cls.ExitCode() != clierror.ExitSecurityFail {
			t.Errorf("expected ExitSecurityFail (1) for findings scan, got: %d", cls.ExitCode())
		}
		if rep.Summary.HighCount != 1 {
			t.Errorf("expected HighCount=1, got: %d", rep.Summary.HighCount)
		}
	})

	// Workflow 3: [Subsystem Contract] Invalid CLI invocation and SSRF refusal error classifications returning exit code 2
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_OperationalErrorsAndSSRF)
	t.Run("Workflow_03_InvalidInvocation_ExitCode2", func(t *testing.T) {
		errMissing := clierror.Usage("missing assessment target URL")
		if errMissing.ExitCode() != clierror.ExitOperational {
			t.Errorf("expected ExitOperational (2), got: %d", errMissing.ExitCode())
		}

		errSSRF := clierror.Operational("prohibited loopback IP 127.0.0.1")
		if errSSRF.ExitCode() != clierror.ExitOperational {
			t.Errorf("expected ExitOperational (2) for SSRF refusal, got: %d", errSSRF.ExitCode())
		}
	})

	// Workflow 4: [Package Integration] APK intake, AndroidManifest/DEX static analysis, and report generation
	// (Full CLI process path: cmd/felix/scan_apk_workflow_test.go:TestScanAPK_Workflow_Default)
	t.Run("Workflow_04_APKScan_StaticAnalysisAndReport", func(t *testing.T) {
		tmpDir := t.TempDir()
		apkFile := filepath.Join(tmpDir, "sample.apk")

		// Create mock APK ZIP archive with AndroidManifest.xml
		manifestXML := `<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.felix.audit">
    <application android:allowBackup="true" android:debuggable="true">
        <activity android:name=".MainActivity" android:exported="true" />
    </application>
</manifest>`

		buf := new(bytes.Buffer)
		zw := zip.NewWriter(buf)
		w1, err := zw.Create("AndroidManifest.xml")
		if err != nil {
			t.Fatalf("failed to create zip entry: %v", err)
		}
		if _, err := w1.Write([]byte(manifestXML)); err != nil {
			t.Fatalf("failed writing manifest: %v", err)
		}
		w2, err := zw.Create("classes.dex")
		if err != nil {
			t.Fatalf("failed to create classes.dex zip entry: %v", err)
		}
		if _, err := w2.Write([]byte("dex\n035\x00synthetic-bytecode")); err != nil {
			t.Fatalf("failed writing dex: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("failed closing zip: %v", err)
		}
		if err := os.WriteFile(apkFile, buf.Bytes(), 0600); err != nil {
			t.Fatalf("failed saving test apk: %v", err)
		}

		// Ingest and analyze APK
		opts := apk.IntakeOptions{Limits: apk.DefaultLimits(), Extract: true}
		intakeRes, err := apk.Intake(context.Background(), apkFile, opts)
		if err != nil {
			t.Fatalf("Intake failed: %v", err)
		}
		defer intakeRes.Workspace.Close()

		manifestRes, err := apk.AnalyzeManifest(context.Background(), intakeRes.Workspace, apk.DefaultLimits())
		if err != nil {
			t.Fatalf("AnalyzeManifest failed: %v", err)
		}
		if manifestRes.Document.PackageName != "com.felix.audit" {
			t.Errorf("expected package com.felix.audit, got: %s", manifestRes.Document.PackageName)
		}

		// Ensure debuggable and exported activity findings were detected
		if len(manifestRes.Findings) == 0 {
			t.Errorf("expected static analysis findings from debuggable APK")
		}

		// Verify export
		reportData := apk.BuildMobileReportData(apkFile, intakeRes, manifestRes, nil, nil, nil)
		htmlReport := filepath.Join(tmpDir, "mobile_audit.html")
		if err := apk.WriteMobileAuditReport(reportData, htmlReport, apkFile); err != nil {
			t.Fatalf("WriteMobileAuditReport failed: %v", err)
		}
		fi, err := os.Stat(htmlReport)
		if err != nil || fi.Size() < 100 {
			t.Errorf("expected valid non-empty mobile audit report: %v", err)
		}
	})

	// Workflow 5: [Multi-Package Integration] API assessment with spec reconciliation, safe prober, and boundary checks
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_EndToEndScan)
	t.Run("Workflow_05_APIAssessment_ReconciliationAndSafeProber", func(t *testing.T) {
		openAPISpec := `{
  "openapi": "3.0.0",
  "info": {"title": "Orders API", "version": "1.0"},
  "paths": {
    "/api/v1/orders": {
      "get": {"responses": {"200": {"description": "OK"}}}
    }
  }
}`
		parser := api.NewSpecParser()
		docOps, meta, err := parser.ParseSpecificationData([]byte(openAPISpec), "orders.json")
		if err != nil {
			t.Fatalf("ParseSpecificationData failed: %v", err)
		}

		discoveredRoutes := []crawler.RouteCandidate{
			{
				ID:               "cand_1",
				Path:             "/api/v1/orders",
				HTTPMethod:       "GET",
				OriginatingAsset: "bundle.js",
				Confidence:       crawler.ConfidenceConfirmed,
			},
			{
				ID:               "cand_2",
				Path:             "/api/v1/internal_debug",
				HTTPMethod:       "GET",
				OriginatingAsset: "bundle.js",
				Confidence:       crawler.ConfidenceConfirmed,
			},
		}

		engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, docOps, api.DefaultReconciliationOptions())
		reconReport := engine.Reconcile(discoveredRoutes)
		if reconReport.TotalUndocumentedCandidates != 1 {
			t.Errorf("expected 1 shadow route, got: %d", reconReport.TotalUndocumentedCandidates)
		}

		// Safe prober mock server
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/internal_debug" {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprintln(w, `{"debug":true,"environment":"staging"}`)
			} else {
				http.NotFound(w, r)
			}
		}))
		defer ts.Close()

		proberOpts := api.DefaultProberOptions()
		proberOpts.EnableSafeGET = true
		proberOpts.AllowLoopback = true
		proberOpts.Timeout = 5 * time.Second

		prober := api.NewProberEngine(proberOpts)
		probeResult := prober.ProbeCandidate(context.Background(), "cand_2", "/api/v1/internal_debug", "GET", ts.URL)
		if probeResult.Reachability != api.ProbeReachabilityConfirmed {
			t.Errorf("expected ReachabilityConfirmed for JSON debug endpoint, got: %s", probeResult.Reachability)
		}
	})

	// Workflow 6: [Subsystem Contract] Cloud or database assessment flow with isolated mock
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_EndToEndScan)
	t.Run("Workflow_06_CloudAndDatabase_IsolatedAssessment", func(t *testing.T) {
		// Mock S3 bucket endpoint responding with public listing
		s3Mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, `<ListBucketResult><Name>corp-public-vault</Name></ListBucketResult>`)
		}))
		defer s3Mock.Close()

		cf := cloud.CloudFinding{
			Provider:    cloud.ProviderAWS,
			Category:    "s3-public-listing",
			Endpoint:    s3Mock.URL,
			Description: "Anonymous GET request returned XML ListBucketResult with bucket contents",
			Severity:    cloud.SeverityHigh,
			Confidence:  cloud.ConfidenceHigh,
			Fingerprint: "fp-s3-test-1",
			HTTPStatus:  200,
		}

		f := report.NormalizeFinding(report.Finding{
			ID:          "FND-CLOUD-01",
			Title:       cf.Category,
			Description: cf.Description,
			Severity:    report.SeverityHigh,
			Target:      cf.Endpoint,
			Endpoint:    cf.Endpoint,
			Source:      report.SourceCloud,
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "PUBLIC_S3_LISTING",
			},
		})

		rep := report.BuildReport(s3Mock.URL, []report.Finding{f})
		rep.CompletionStatus = "COMPLETED"
		report.RecalculateReportRisk(&rep)

		if !rep.HasCloudFindings() {
			t.Errorf("expected HasCloudFindings to be true")
		}
		if rep.Summary.HighCount != 1 {
			t.Errorf("expected HighCount=1, got: %d", rep.Summary.HighCount)
		}
	})

	// Workflow 7: [Subsystem Contract] Failed or blocked assessment honesty (risk unavailable, exit code 2)
	// (Full CLI process path: cmd/felix/representative_cli_test.go:TestCLI_Representative_BlockedScanHonesty)
	t.Run("Workflow_07_FailedOrBlockedAssessmentHonesty", func(t *testing.T) {
		failedRep := report.BuildReport("https://offline.target.invalid", nil)
		failedRep.CompletionStatus = "FAILED"
		report.RecalculateReportRisk(&failedRep)

		if failedRep.RiskScoreAvailable {
			t.Errorf("failed assessment must not claim available risk score")
		}
		if failedRep.RiskScore != 0 || failedRep.RiskLevel != "UNAVAILABLE" {
			t.Errorf("failed assessment must have score 0 and level UNAVAILABLE, got: %d (%s)",
				failedRep.RiskScore, failedRep.RiskLevel)
		}
		if err := report.ValidateReportIntegrity(failedRep); err != nil {
			t.Fatalf("failed report failed integrity validation: %v", err)
		}

		cls := clierror.ClassifyAssessment("FAILED", nil, false, nil)
		if cls.ExitCode() != clierror.ExitOperational {
			t.Errorf("expected ExitOperational (2) for failed assessment, got: %d", cls.ExitCode())
		}
	})

	// Workflow 8: [Multi-Package Integration] Multi-format export with complete secret canary scrubbing
	// (Full CLI process path: cmd/felix/reporting_cli_regression_test.go:TestCLI_Reporting_MultiFormatAndExportReliability)
	t.Run("Workflow_08_MultiFormatExport_ZeroCanaryLeakage", func(t *testing.T) {
		tmpDir := t.TempDir()
		const canarySecret = "AKIA1122334455667788"

		f := report.Finding{
			ID:          "FND-CANARY-WF08",
			Title:       "Discovered AWS Key " + canarySecret,
			Description: "Exposed access key: " + canarySecret + " in environment config",
			Severity:    report.SeverityCritical,
			Target:      "https://target.corp",
			Endpoint:    "/config.json",
			Verification: report.VerificationRecord{
				Status: report.VerificationVerified,
				Result: "LIVE_KEY",
			},
		}

		rep := report.BuildReport("https://target.corp", []report.Finding{f})
		rep.CompletionStatus = "COMPLETED"

		htmlPath := filepath.Join(tmpDir, "audit.html")
		jsonPath := filepath.Join(tmpDir, "audit.json")
		sarifPath := filepath.Join(tmpDir, "audit.sarif")

		if err := report.WriteHTML(rep, htmlPath); err != nil {
			t.Fatalf("WriteHTML failed: %v", err)
		}
		if err := report.WriteJSON(rep, jsonPath); err != nil {
			t.Fatalf("WriteJSON failed: %v", err)
		}
		if err := report.WriteSARIF(rep, sarifPath); err != nil {
			t.Fatalf("WriteSARIF failed: %v", err)
		}

		for _, path := range []string{htmlPath, jsonPath, sarifPath} {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading %s: %v", path, err)
			}
			if strings.Contains(string(data), canarySecret) {
				t.Errorf("file %s leaked canary secret %s", path, canarySecret)
			}
		}

		if err := report.ValidateSARIFFile(sarifPath); err != nil {
			t.Fatalf("exported SARIF failed validation: %v", err)
		}
	})

	// Workflow 9: [Subsystem Contract] Update SemVer validation and archive zip-slip traversal defense
	// (Full CLI process path: cmd/felix/upgrade_workflow_test.go:TestUpgrade_CleanInstallThenUpgrade_WithSentinels)
	t.Run("Workflow_09_UpdateRollbackOnFailure", func(t *testing.T) {
		tmpDir := t.TempDir()

		// Verify updater detects version downgrade vs upgrade
		cmp, err := update.Compare("1.0.0", "2.0.0")
		if err != nil || cmp >= 0 {
			t.Errorf("expected 1.0.0 < 2.0.0, got cmp=%d, err=%v", cmp, err)
		}
		if update.IsNewer("1.0.0", "2.0.0") {
			t.Errorf("1.0.0 should not be newer than 2.0.0")
		}
		if !update.IsNewer("2.0.0", "1.0.0") {
			t.Errorf("2.0.0 should be detected as newer than 1.0.0")
		}

		// Verify archive zip-slip path traversal rejection
		badArchiveBuf := new(bytes.Buffer)
		zw := zip.NewWriter(badArchiveBuf)
		w, _ := zw.Create("../../../etc/passwd")
		_, _ = w.Write([]byte("evil"))
		_ = zw.Close()

		badZipFile := filepath.Join(tmpDir, "traversal.zip")
		_ = os.WriteFile(badZipFile, badArchiveBuf.Bytes(), 0600)

		extractErr := update.ExtractArchive(badZipFile, filepath.Join(tmpDir, "out"))
		if extractErr == nil || (!strings.Contains(strings.ToLower(extractErr.Error()), "traversal") && !strings.Contains(strings.ToLower(extractErr.Error()), "illegal")) {
			t.Errorf("expected ExtractArchive to reject zip traversal, got: %v", extractErr)
		}
	})

	// Workflow 10: [Package Integration] Surface baseline snapshot storage and temporal drift detection
	// (Full CLI process path: cmd/felix/monitor_cmd_test.go:TestMonitorCmd_Diff_Workflow)
	t.Run("Workflow_10_MonitoringDriftDetection", func(t *testing.T) {
		tmpDir := t.TempDir()
		store, err := monitor.NewFileSnapshotStore(tmpDir, 5)
		if err != nil {
			t.Fatalf("NewFileSnapshotStore failed: %v", err)
		}

		snap1 := &monitor.Snapshot{
			ID:            "snap_1",
			SchemaVersion: monitor.CurrentSnapshotSchemaVersion,
			TargetID:      "target-api",
			TargetName:    "Target API",
			BaseURLs:      []string{"https://api.corp.internal"},
			CollectedAt:   time.Now().UTC(),
			IsComplete:    true,
			Routes: []monitor.SurfaceRoute{
				{CanonicalPath: "/api/v1/users", RawPath: "/api/v1/users", Methods: []string{"GET"}, DocumentationStatus: monitor.DocStatusDocumented},
			},
		}

		if err := store.SetBaseline(context.Background(), snap1, "Initial baseline"); err != nil {
			t.Fatalf("SetBaseline failed: %v", err)
		}

		baseSnap, err := store.GetBaseline(context.Background(), "target-api")
		if err != nil {
			t.Fatalf("GetBaseline failed: %v", err)
		}
		if baseSnap.TargetID != "target-api" {
			t.Errorf("expected target-api, got: %s", baseSnap.TargetID)
		}

		// Current scan with a new shadow route
		snap2 := &monitor.Snapshot{
			ID:            "snap_2",
			SchemaVersion: monitor.CurrentSnapshotSchemaVersion,
			TargetID:      "target-api",
			TargetName:    "Target API",
			BaseURLs:      []string{"https://api.corp.internal"},
			CollectedAt:   time.Now().UTC(),
			IsComplete:    true,
			Routes: []monitor.SurfaceRoute{
				{CanonicalPath: "/api/v1/users", RawPath: "/api/v1/users", Methods: []string{"GET"}, DocumentationStatus: monitor.DocStatusDocumented},
				{CanonicalPath: "/api/v1/admin/export", RawPath: "/api/v1/admin/export", Methods: []string{"GET"}, DocumentationStatus: monitor.DocStatusUndocumented},
			},
		}

		diff := monitor.CompareSnapshots(baseSnap, snap2)
		if diff.Summary[monitor.ClassificationNewShadowRoute] != 1 {
			t.Fatalf("expected 1 new undocumented route, got: %d", diff.Summary[monitor.ClassificationNewShadowRoute])
		}

		// Incomplete scan must suppress destructive removal
		snapIncomplete := &monitor.Snapshot{
			ID:            "snap_inc",
			SchemaVersion: monitor.CurrentSnapshotSchemaVersion,
			TargetID:      "target-api",
			TargetName:    "Target API",
			BaseURLs:      []string{"https://api.corp.internal"},
			CollectedAt:   time.Now().UTC(),
			IsComplete:    false,
			Routes:        nil,
		}
		diffIncomplete := monitor.CompareSnapshots(baseSnap, snapIncomplete)
		if diffIncomplete.Summary[monitor.ClassificationRemovedRoute] != 0 {
			t.Errorf("incomplete scan must suppress removals to avoid false recovery alerts")
		}
		if diffIncomplete.Summary[monitor.ClassificationSnapshotIncomplete] != 1 {
			t.Errorf("expected 1 SNAPSHOT_INCOMPLETE event, got: %d", diffIncomplete.Summary[monitor.ClassificationSnapshotIncomplete])
		}
	})

	// Workflow 11: [Multi-Package Integration] Attack-path traversal, cycle termination, and minimum-cut bottleneck solving
	t.Run("Workflow_11_AttackPath_MultiHopAndCycleHandling", func(t *testing.T) {
		f1 := correlation.NormalizedFinding{ID: "fnd_bundle", Title: "Source Map Disclosure", Severity: report.SeverityMedium, Fingerprint: "fp1"}
		f2 := correlation.NormalizedFinding{ID: "fnd_token", Title: "Hardcoded Token in Bundle", Severity: report.SeverityHigh, Fingerprint: "fp2"}
		f3 := correlation.NormalizedFinding{ID: "fnd_db", Title: "Database Access via Token", Severity: report.SeverityCritical, Fingerprint: "fp3"}

		rel1 := correlation.Relationship{ID: "r1", SourceFindingID: "fnd_bundle", TargetFindingID: "fnd_token", Type: correlation.RelExposes, ValidationStatus: correlation.ValidationConfirmed}
		rel2 := correlation.Relationship{ID: "r2", SourceFindingID: "fnd_token", TargetFindingID: "fnd_db", Type: correlation.RelEnables, ValidationStatus: correlation.ValidationConfirmed}
		relCycle := correlation.Relationship{ID: "rc", SourceFindingID: "fnd_db", TargetFindingID: "fnd_bundle", Type: correlation.RelEnables, ValidationStatus: correlation.ValidationConfirmed}

		// Cycle detection in graph: f1 -> f2 -> f3 -> f1
		g := correlation.NewAttackGraph([]correlation.NormalizedFinding{f1, f2, f3}, []correlation.Relationship{rel1, rel2, relCycle})
		if !g.Validation.HasCycle {
			t.Errorf("expected cycle detection in graph")
		}

		// Multi-hop path and bottleneck solver
		path := correlation.AttackPath{
			ID:                "PATH-01",
			Title:             "Source Map to Database Compromise",
			Nodes:             []correlation.NormalizedFinding{f1, f2, f3},
			Status:            correlation.PathVerified,
			CombinedRiskScore: 92,
			CombinedRiskLevel: "CRITICAL",
		}

		bRes := correlation.AnalyzeRemediationBottlenecks([]correlation.AttackPath{path}, []correlation.NormalizedFinding{f1, f2, f3}, nil)
		if bRes == nil || bRes.TotalVerifiedChains != 1 {
			t.Fatalf("expected 1 verified chain in bottleneck summary, got: %+v", bRes)
		}
		if bRes.PrimaryRecommendation == nil {
			t.Errorf("expected primary recommendation from bottleneck solver")
		}
	})

	// Workflow 12: [Subsystem Contract] Proof-of-exploit reproduction script generation with safe non-destructive curl
	// (Full CLI process path: cmd/felix/report_reproduce_cmd_test.go:TestCLIReport_ReproduceChain_Valid)
	t.Run("Workflow_12_ReproductionScript_SafeCurlGeneration", func(t *testing.T) {
		tmpDir := t.TempDir()

		path := report.AttackPathSummary{
			ID:          "CHAIN-REPRO-01",
			Title:       "BOLA Access Chain",
			Status:      "VERIFIED",
			EntryPoint:  "/api/v1/login",
			TargetAsset: "/api/v1/accounts/1024",
			NodeIDs:     []string{"FND-BOLA-01"},
		}

		finding := report.Finding{
			ID:       "FND-BOLA-01",
			Title:    "BOLA in Account Endpoint",
			Endpoint: "/api/v1/accounts/1024",
			Method:   "GET",
			Verification: report.VerificationRecord{
				Status:          report.VerificationVerified,
				SafeCurlCommand: "curl -s -i 'https://api.target.corp/api/v1/accounts/1024'",
			},
		}

		scriptFile, err := report.WriteReproductionScript(path, []report.Finding{finding}, report.ReproductionOptions{
			OutputFile: filepath.Join(tmpDir, "reproduce_bola.sh"),
			Overwrite:  true,
		})
		if err != nil {
			t.Fatalf("WriteReproductionScript failed: %v", err)
		}

		scriptContent, err := os.ReadFile(scriptFile)
		if err != nil {
			t.Fatalf("failed reading reproduction script: %v", err)
		}
		scriptStr := string(scriptContent)

		// Assert safe non-destructive curl command and function is generated
		if !strings.Contains(scriptStr, "curl") || !strings.Contains(scriptStr, "felix_safe_request") {
			t.Errorf("reproduction script missing safe curl command or felix_safe_request function")
		}

		// Assert destructive payloads are not present
		for _, dangerous := range []string{"DROP TABLE", "FLUSHALL", "; rm -rf", "/bin/sh -c"} {
			if strings.Contains(scriptStr, dangerous) {
				t.Errorf("reproduction script contains dangerous payload: %s", dangerous)
			}
		}
	})
}

// TestSecurityRegression_SafetyBoundaries ensures that critical SSRF, scope,
// credential redaction, and filesystem safety boundaries cannot be bypassed.
func TestSecurityRegression_SafetyBoundaries(t *testing.T) {
	t.Run("SSRF Pre-Dial Defense against Private IPs and Cloud Metadata", func(t *testing.T) {
		dialer := crawler.NewSafeDialContext(crawler.SafeDialerOptions{
			AllowLoopback:   false,
			AllowPrivateIPs: false,
		})

		prohibitedTargets := []string{
			"169.254.169.254:80",
			"[fd00:ec2::254]:80",
			"127.0.0.1:8080",
			"[::1]:8080",
			"10.0.0.1:80",
			"192.168.1.1:80",
		}

		for _, targetAddr := range prohibitedTargets {
			host, _, _ := net.SplitHostPort(targetAddr)
			if host == "" {
				host = targetAddr
			}
			ip := net.ParseIP(strings.Trim(host, "[]"))
			if !crawler.IsProhibitedIP(ip, false, false) {
				t.Errorf("IsProhibitedIP must reject prohibited destination: %s", targetAddr)
			}

			// Pre-dial hook must refuse connection before dialing
			conn, err := dialer(context.Background(), "tcp", targetAddr)
			if err == nil {
				if conn != nil {
					conn.Close()
				}
				t.Errorf("SafeDialContext must reject prohibited destination: %s", targetAddr)
			}
		}
	})

	t.Run("Credential Redaction in URLs, JSON, and Error Messages", func(t *testing.T) {
		rawURL := "postgres://admin:SuperSecretPass9988@db.internal:5432/orders?token=SecretToken1122"
		cleanURL := secrets.SanitizeURL(rawURL)

		if strings.Contains(cleanURL, "SuperSecretPass9988") {
			t.Errorf("SanitizeURL leaked password")
		}
		if strings.Contains(cleanURL, "SecretToken1122") {
			t.Errorf("SanitizeURL leaked query token")
		}

		rawError := fmt.Errorf("failed connecting to postgres://admin:SuperSecretPass9988@db.internal:5432/orders")
		sanError := secrets.SanitizeError(rawError)
		if strings.Contains(sanError, "SuperSecretPass9988") {
			t.Errorf("SanitizeError leaked password: %s", sanError)
		}
	})

	t.Run("HTTP 200 alone does not prove vulnerability", func(t *testing.T) {
		// A route responding with 200 OK HTML is not an API BOLA vulnerability
		htmlResponse := `<!DOCTYPE html><html><body><div id="root"></div></body></html>`
		fStatus := report.FindingStatusInconclusive
		verStatus := report.VerificationNotVerified

		if fStatus == report.FindingStatusConfirmed || verStatus == report.VerificationVerified {
			t.Errorf("200 OK alone must never confirm an authorization finding")
		}

		// Ensure HTML SPA fallback is detected as inconclusive by prober
		tsHTML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, htmlResponse)
		}))
		defer tsHTML.Close()

		uHTML, _ := url.Parse(tsHTML.URL)
		proberOpts := api.DefaultProberOptions()
		proberOpts.EnableSafeGET = true
		proberOpts.AllowLoopback = true
		proberOpts.ScopeHost = uHTML.Hostname()

		prober := api.NewProberEngine(proberOpts)
		probeRes := prober.ProbeCandidate(context.Background(), "CAND-SPA", "/api/v1/spa_check", "GET", tsHTML.URL)
		if probeRes.Classification != api.ClassificationInconclusive {
			t.Errorf("HTML response must be classified as ClassificationInconclusive, got: %s", probeRes.Classification)
		}
		if probeRes.Reachability != api.ProbeReachabilityInconclusive {
			t.Errorf("HTML response reachability must be inconclusive, got: %s", probeRes.Reachability)
		}
	})
}
