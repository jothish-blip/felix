package apk

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/api"
	"felix/pkg/report"
)

// Helper to create synthetic manifest analysis results
func newTestManifestResult() *ManifestAnalysisResult {
	debuggableTrue := true
	backupTrue := true
	cleartextTrue := true

	return &ManifestAnalysisResult{
		Document: &ManifestDocument{
			PackageName: "com.example.secureapp",
			VersionName: "2.4.1",
			VersionCode: "20401",
			MinSDK:      24,
			TargetSDK:   33,
			CompileSDK:  34,
			Format:      "Binary AXML",
			Permissions: []ManifestPermission{
				{Name: "android.permission.INTERNET"},
				{Name: "android.permission.ACCESS_NETWORK_STATE"},
			},
			Application: ApplicationInfo{
				Debuggable:           &debuggableTrue,
				AllowBackup:          &backupTrue,
				UsesCleartextTraffic: &cleartextTrue,
			},
		},
		Findings: []report.Finding{
			{
				ID:          "APK-MAN-DEBUGGABLE",
				RuleID:      "APK-MAN-DEBUGGABLE",
				Title:       "Application is Configured as Debuggable",
				Severity:    report.SeverityHigh,
				Confidence:  report.ConfidenceHigh,
				Category:    "manifest-security",
				Endpoint:    "AndroidManifest.xml",
				Description: "android:debuggable is set to true in AndroidManifest.xml.",
				Evidence:    "android:debuggable=\"true\"",
				Remediation: "Set android:debuggable=\"false\" in release builds.",
				Source:      "manifest_analysis",
				Fingerprint: "fp-debuggable-1",
			},
			{
				ID:          "APK-MAN-CLEARTEXT",
				RuleID:      "APK-MAN-CLEARTEXT",
				Title:       "Cleartext Traffic Explicitly Permitted",
				Severity:    report.SeverityMedium,
				Confidence:  report.ConfidenceHigh,
				Category:    "manifest-security",
				Endpoint:    "AndroidManifest.xml",
				Description: "android:usesCleartextTraffic is set to true.",
				Evidence:    "android:usesCleartextTraffic=\"true\"",
				Remediation: "Set android:usesCleartextTraffic=\"false\" and enforce HTTPS.",
				Source:      "manifest_analysis",
				Fingerprint: "fp-cleartext-1",
			},
		},
		Limitations: []string{"No custom network security config resource declared."},
	}
}

// Helper to create synthetic artifact intelligence results
func newTestArtifactResult() *ArtifactAnalysisResult {
	return &ArtifactAnalysisResult{
		DexFilesAnalyzed: []string{"classes.dex", "classes2.dex"},
		ConfigsAnalyzed:  []string{"res/values/strings.xml"},
		FindingsCount:    2,
		Findings: []report.Finding{
			{
				ID:          "APK-ART-SECRET-AWS",
				RuleID:      "APK-ART-SECRET-AWS",
				Title:       "Exposed AWS Access Key",
				Severity:    report.SeverityCritical,
				Confidence:  report.ConfidenceHigh,
				Category:    "secrets",
				Endpoint:    "classes.dex",
				Description: "Discovered embedded AWS API credential.",
				Evidence:    "AKIAIOSFODNN7EXAMPLE",
				Remediation: "Revoke AWS credential immediately.",
				Source:      "artifact_intelligence",
				Fingerprint: "fp-aws-key-1",
			},
			{
				ID:          "APK-ART-SERVICE-REDIS",
				RuleID:      "APK-ART-SERVICE-REDIS",
				Title:       "Discovered Redis Service Indicator",
				Severity:    report.SeverityInfo,
				Confidence:  report.ConfidenceHigh,
				Category:    "service-indicator",
				Endpoint:    "redis.internal.example.com",
				Description: "Redis connection URI discovered.",
				Evidence:    "redis://:pass@redis.internal.example.com:6379/0",
				Remediation: "Ensure Redis instance is behind a private network ACL.",
				Source:      "artifact_intelligence",
				Fingerprint: "fp-redis-svc-1",
				EvidenceDetails: report.EvidenceDetails{
					Details: map[string]string{
						"scheme":        "redis",
						"host":          "redis.internal.example.com:6379",
						"file_origin":   "classes.dex",
						"sanitized_uri": "redis://:***@redis.internal.example.com:6379/0",
					},
				},
			},
		},
		Summary: ArtifactAnalysisSummary{
			SecretsCount:   1,
			ServicesCount:  1,
			EndpointsCount: 2,
		},
	}
}

// Helper to create synthetic backend inventory
func newTestInventory() *BackendInventory {
	return &BackendInventory{
		APKSHA256:      "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f60000",
		APKFileName:    "testapp.apk",
		TotalEndpoints: 3,
		TotalHosts:     2,
		ConfirmedCount: 2,
		InferredCount:  1,
		Categories:     map[string]int{"api": 2, "storage": 1},
		Hosts: []HostGroup{
			{
				HostIdentity:      "api.example.com:443",
				Hostname:          "api.example.com",
				Port:              443,
				EndpointCount:     2,
				ConfirmedCount:    1,
				InferredCount:     1,
				ServiceIndicators: []string{"API Gateway"},
				ArtifactOrigins:   []string{"classes.dex"},
			},
			{
				HostIdentity:      "my-bucket.s3.amazonaws.com:443",
				Hostname:          "my-bucket.s3.amazonaws.com",
				Port:              443,
				EndpointCount:     1,
				ConfirmedCount:    1,
				ServiceIndicators: []string{"AWS S3"},
				ArtifactOrigins:   []string{"res/values/strings.xml"},
			},
		},
		Endpoints: []EndpointEntry{
			{
				NormalizedURL:  "https://api.example.com/v1/auth",
				Host:           "api.example.com",
				HostIdentity:   "api.example.com:443",
				Path:           "/v1/auth",
				Category:       CategoryAuthentication,
				Classification: ClassificationConfirmedReference,
				Confidence:     report.ConfidenceHigh,
				Provenance:     []ProvenanceRecord{{ArtifactPath: "classes.dex", AnalysisStage: "artifact_intelligence"}},
			},
			{
				NormalizedURL:  "https://api.example.com/v1/users",
				Host:           "api.example.com",
				HostIdentity:   "api.example.com:443",
				Path:           "/v1/users",
				Category:       CategoryAPI,
				Classification: ClassificationInferredRoute,
				Confidence:     report.ConfidenceMedium,
				Provenance:     []ProvenanceRecord{{ArtifactPath: "classes.dex", AnalysisStage: "artifact_intelligence"}},
				InferredDetails: &InferredRouteDetails{
					BaseURL:   "https://api.example.com",
					RoutePath: "/v1/users",
				},
			},
			{
				NormalizedURL:  "/api/unresolved/route",
				HostIdentity:   "(unresolved)",
				Path:           "/api/unresolved/route",
				Category:       CategoryAPI,
				Classification: ClassificationInferredRoute,
				Confidence:     report.ConfidenceLow,
				Provenance:     []ProvenanceRecord{{ArtifactPath: "classes2.dex"}},
			},
		},
	}
}

// 1. Valid Report Generation Test
func TestMobileReport_ValidGeneration(t *testing.T) {
	intake := &IntakeResult{
		SHA256:                 "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f60000",
		FileSize:               1024000,
		EntryCount:             150,
		TotalDecompressedBytes: 2500000,
		DexCount:               2,
		DexFiles:               []string{"classes.dex", "classes2.dex"},
	}
	manifest := newTestManifestResult()
	artifact := newTestArtifactResult()
	inventory := newTestInventory()

	data := BuildMobileReportData("sample.apk", intake, manifest, artifact, inventory, nil)
	if data == nil {
		t.Fatalf("expected non-nil report data")
	}

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("failed generating HTML: %v", err)
	}
	html := string(htmlBytes)

	// Verify required sections exist
	expectedTokens := []string{
		"<!DOCTYPE html>",
		"FELIX Mobile Security Assessment Report",
		"sample.apk",
		"com.example.secureapp",
		"Binary AXML",
		"Application is Configured as Debuggable",
		"Cleartext Traffic Explicitly Permitted",
		"Exposed AWS Access Key",
		"Discovered Redis Service Indicator",
		"Backend Endpoint & Host Inventory",
		"https://api.example.com/v1/auth",
		"Actionable Remediation Guidance",
		"Analysis Scope, Methodology & Limitations",
		"Static Analysis Only",
	}

	for _, token := range expectedTokens {
		if !strings.Contains(html, token) {
			t.Errorf("missing expected token %q in generated HTML", token)
		}
	}
}

// 2. Missing or Partially Available Metadata Test
func TestMobileReport_MissingOrPartialMetadata(t *testing.T) {
	data := BuildMobileReportData("unknown.apk", nil, nil, nil, nil, nil)
	if data == nil {
		t.Fatalf("expected non-nil data")
	}

	if data.PackageName != "Not available" {
		t.Errorf("expected 'Not available' for package name, got %q", data.PackageName)
	}
	if data.VersionCode != "Not available" {
		t.Errorf("expected 'Not available' for version code, got %q", data.VersionCode)
	}
	if data.MinSDK != "Not available" {
		t.Errorf("expected 'Not available' for min SDK, got %q", data.MinSDK)
	}
	if data.TargetSDK != "Not available" {
		t.Errorf("expected 'Not available' for target SDK, got %q", data.TargetSDK)
	}
	if data.ManifestFormat != "Not available" {
		t.Errorf("expected 'Not available' for format, got %q", data.ManifestFormat)
	}

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("unexpected error rendering partial metadata: %v", err)
	}
	html := string(htmlBytes)
	if !strings.Contains(html, "Not available") {
		t.Errorf("expected 'Not available' placeholder in HTML")
	}
}

// 3. Manifest Findings & Severity Reconciliation Invariant Test
func TestMobileReport_SeverityReconciliationInvariant(t *testing.T) {
	manifest := newTestManifestResult()
	artifact := newTestArtifactResult()

	data := BuildMobileReportData("app.apk", nil, manifest, artifact, nil, nil)

	// Invariant: TotalFindings must exactly equal sum of all individual severity counts
	calculatedSum := data.CriticalCount + data.HighCount + data.MediumCount + data.LowCount + data.InfoCount
	if data.TotalFindings != calculatedSum {
		t.Fatalf("severity reconciliation broken: TotalFindings (%d) != sum (%d)", data.TotalFindings, calculatedSum)
	}
	if len(data.Findings) != data.TotalFindings {
		t.Fatalf("findings list length (%d) != TotalFindings (%d)", len(data.Findings), data.TotalFindings)
	}
}

// 4. Service Indicators & Provenance Test
func TestMobileReport_ServiceIndicators(t *testing.T) {
	artifact := newTestArtifactResult()
	inventory := newTestInventory()

	data := BuildMobileReportData("app.apk", nil, nil, artifact, inventory, nil)
	if data.TotalServices == 0 {
		t.Fatalf("expected discovered services, got 0")
	}

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	if !strings.Contains(html, "AWS S3") {
		t.Errorf("expected AWS S3 service indicator in HTML")
	}
	if !strings.Contains(html, "REDIS") {
		t.Errorf("expected REDIS service indicator in HTML")
	}
	if !strings.Contains(html, "classes.dex") {
		t.Errorf("expected source artifact classes.dex in HTML")
	}
}

// 5. Confirmed vs Inferred vs Unresolved Inventory Entries
func TestMobileReport_InventoryClassificationBadges(t *testing.T) {
	inventory := newTestInventory()
	data := BuildMobileReportData("app.apk", nil, nil, nil, inventory, nil)

	if data.ConfirmedCount != 2 {
		t.Errorf("expected 2 confirmed, got %d", data.ConfirmedCount)
	}
	if data.InferredCount != 1 {
		t.Errorf("expected 1 inferred, got %d", data.InferredCount)
	}
	if data.UnresolvedCount != 1 {
		t.Errorf("expected 1 unresolved, got %d", data.UnresolvedCount)
	}

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	if !strings.Contains(html, "badge confirmed") {
		t.Errorf("expected badge confirmed in HTML")
	}
	if !strings.Contains(html, "badge inferred") {
		t.Errorf("expected badge inferred in HTML")
	}
	if !strings.Contains(html, "badge unresolved") {
		t.Errorf("expected badge unresolved in HTML")
	}
}

// 6. Empty Findings and Empty Inventory (Honest Empty States)
func TestMobileReport_EmptyStates(t *testing.T) {
	emptyInv := &BackendInventory{}
	data := BuildMobileReportData("empty.apk", nil, nil, nil, emptyInv, nil)

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	if !strings.Contains(html, "No security exposures or non-standard configurations identified") {
		t.Errorf("expected honest empty findings message")
	}
	if !strings.Contains(html, "No backend API hosts, routes, or storage endpoints were discovered") {
		t.Errorf("expected honest empty inventory message")
	}
}

// 7. Static-Only Notice Test
func TestMobileReport_StaticOnlyNotice(t *testing.T) {
	data := BuildMobileReportData("static.apk", nil, nil, nil, nil, nil)
	htmlBytes, _ := GenerateMobileAuditHTML(data)
	html := string(htmlBytes)

	if !strings.Contains(html, "Active Backend Assessment Not Executed") {
		t.Errorf("expected clear banner stating active assessment was not run")
	}
	if !strings.Contains(html, "offline static-only mode") {
		t.Errorf("expected offline static-only mode disclosure")
	}
}

// 8. Authorized Assessment Results & Mixed Endpoint Dispositions
func TestMobileReport_AuthorizedAssessmentResults(t *testing.T) {
	inventory := newTestInventory()
	startTime := time.Now().Add(-5 * time.Second)
	endTime := time.Now()

	handoff := &HandoffReport{
		APKSHA256:         "a1b2c3d4e5f60000",
		APKFileName:       "sample.apk",
		TotalDiscovered:   4,
		TotalEligible:     2,
		TotalAuthorized:   2,
		TotalTested:       1,
		TotalSkipped:      2,
		TotalFailed:       1,
		TotalInconclusive: 0,
		TotalRequestsSent: 3,
		StartedAt:         startTime,
		CompletedAt:       endTime,
		DurationMs:        5000,
		ScopeMode:         "same-origin",
		AuthorizedTargets: []string{"https://api.example.com"},
		Results: []HandoffEndpointResult{
			{
				EndpointID:        "ep-1",
				NormalizedURL:     "https://api.example.com/v1/auth",
				HostGroup:         "api.example.com:443",
				Disposition:       DispositionTested,
				State:             StateTested,
				ReasonCode:        "TESTED",
				HTTPStatus:        200,
				DurationMs:        45,
				RequestDispatched: true,
				RequestCount:      1,
			},
			{
				EndpointID:        "ep-2",
				NormalizedURL:     "https://api.example.com/v1/users",
				HostGroup:         "api.example.com:443",
				Disposition:       DispositionFailed,
				State:             StateFailed,
				ReasonCode:        "REDIRECT_BLOCKED",
				ReasonMessage:     "redirect to external domain blocked",
				RequestDispatched: true,
				RequestCount:      2,
			},
			{
				EndpointID:        "ep-3",
				NormalizedURL:     "https://unauthorized.external.com/v1",
				HostGroup:         "unauthorized.external.com",
				Disposition:       DispositionSkipped,
				State:             StateSkipped,
				ReasonCode:        "OUT_OF_SCOPE",
				RequestDispatched: false,
				RequestCount:      0,
			},
		},
		Findings: []api.APIFinding{
			{
				Category:    api.CategoryEndpointDiscovered,
				Endpoint:    "https://api.example.com/v1/auth",
				Description: "Authentication endpoint verified accessible",
				Severity:    api.SeverityInfo,
				Confidence:  api.ConfidenceHigh,
				Fingerprint: "fp-auth-endpoint-1",
			},
		},
	}

	data := BuildMobileReportData("sample.apk", nil, nil, nil, inventory, handoff)
	if !data.AssessmentExecuted {
		t.Fatalf("expected AssessmentExecuted=true")
	}

	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	if !strings.Contains(html, "Authorized Assessment Completed") {
		t.Errorf("expected Authorized Assessment Completed status")
	}
	if !strings.Contains(html, "badge tested") {
		t.Errorf("expected badge tested in HTML")
	}
	if !strings.Contains(html, "badge skipped") {
		t.Errorf("expected badge skipped in HTML")
	}
	if !strings.Contains(html, "badge failed") {
		t.Errorf("expected badge failed in HTML")
	}
	if !strings.Contains(html, "REDIRECT_BLOCKED") {
		t.Errorf("expected REDIRECT_BLOCKED reason code in HTML")
	}
}

// 9. Secret Redaction Sentinel Test
func TestMobileReport_SecretRedaction(t *testing.T) {
	rawSecret := "AKIAIOSFODNN7EXAMPLE"
	rawToken := "ghp_123456789012345678901234567890123456"

	manifest := &ManifestAnalysisResult{
		Findings: []report.Finding{
			{
				ID:          "LEAK-1",
				Title:       "Secret exposed in title: " + rawSecret,
				Severity:    report.SeverityCritical,
				Endpoint:    "https://api.example.com/token?secret=" + rawToken,
				Evidence:    "api_key=" + rawSecret,
				Description: "Discovered raw token: " + rawToken,
				Remediation: "Do not leak " + rawSecret,
			},
		},
	}

	data := BuildMobileReportData("app.apk", nil, manifest, nil, nil, nil)
	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	// Assert raw secret strings are ABSENT from the entire generated HTML
	if strings.Contains(html, rawSecret) {
		t.Fatalf("SECURITY VIOLATION: raw AWS secret %q leaked in HTML report!", rawSecret)
	}
	if strings.Contains(html, rawToken) {
		t.Fatalf("SECURITY VIOLATION: raw GitHub token %q leaked in HTML report!", rawToken)
	}

	// Verify [REDACTED] or fingerprint is present
	if !strings.Contains(html, "[REDACTED]") && !strings.Contains(html, "AKIA...") {
		t.Errorf("expected [REDACTED] placeholder in place of leaked secrets")
	}
}

// 10. Hostile HTML / Script Injection (XSS Escaping) Sentinel Test
func TestMobileReport_XSS_HostilePayloadEscaping(t *testing.T) {
	xssPayload := "<script>alert('XSS')</script>"
	attrPayload := "\"><img src=x onerror=alert(1)>"

	manifest := &ManifestAnalysisResult{
		Document: &ManifestDocument{
			PackageName: xssPayload,
			VersionName: attrPayload,
		},
		Findings: []report.Finding{
			{
				ID:          "XSS-1",
				Title:       "Finding Title " + xssPayload,
				Severity:    report.SeverityHigh,
				Endpoint:    attrPayload,
				Description: "Description " + xssPayload,
				Evidence:    "<svg onload=alert('evidence')>",
				Remediation: "Fix: " + attrPayload,
			},
		},
	}

	inventory := &BackendInventory{
		Hosts: []HostGroup{
			{
				HostIdentity: attrPayload,
			},
		},
		Endpoints: []EndpointEntry{
			{
				NormalizedURL:  "https://evil.example.com/" + xssPayload,
				HostIdentity:   attrPayload,
				Classification: ClassificationConfirmedReference,
			},
		},
	}

	data := BuildMobileReportData("app.apk", nil, manifest, nil, inventory, nil)
	htmlBytes, err := GenerateMobileAuditHTML(data)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	html := string(htmlBytes)

	// Verify unescaped hostile script tags do NOT exist in the output
	if strings.Contains(html, "<script>alert('XSS')</script>") {
		t.Fatalf("SECURITY REFUSAL: unescaped executable <script> found in HTML report!")
	}
	if strings.Contains(html, "onerror=alert(1)>") {
		t.Fatalf("SECURITY REFUSAL: unescaped onerror attribute found in HTML report!")
	}
	if strings.Contains(html, "<svg onload=alert('evidence')>") {
		t.Fatalf("SECURITY REFUSAL: unescaped SVG onload tag found in HTML report!")
	}

	// Verify proper HTML entity escaping occurred
	if !strings.Contains(html, "&lt;script&gt;alert(&#39;XSS&#39;)&lt;/script&gt;") &&
		!strings.Contains(html, "&lt;script&gt;alert('XSS')&lt;/script&gt;") {
		t.Errorf("expected HTML-escaped script tag in report")
	}
}

// 11. Sensitive URL Sanitization Test
func TestMobileReport_SanitizeURLRedactingSensitiveQuery(t *testing.T) {
	rawURL := "https://api.mycorp.com/v1/auth?client_id=123&api_key=secret999&token=bearerABC"
	sanitized := SanitizeURLRedactingSensitiveQuery(rawURL)

	if strings.Contains(sanitized, "secret999") {
		t.Errorf("sensitive api_key query value was not redacted: %s", sanitized)
	}
	if strings.Contains(sanitized, "bearerABC") {
		t.Errorf("sensitive token query value was not redacted: %s", sanitized)
	}
	if !strings.Contains(sanitized, "client_id=123") {
		t.Errorf("non-sensitive client_id query param was altered: %s", sanitized)
	}
}

// 12. Output Path Validation & Overwrite Refusal Test
func TestMobileReport_OutputPathSafety(t *testing.T) {
	tmpDir := t.TempDir()
	apkPath := filepath.Join(tmpDir, "target.apk")
	if err := os.WriteFile(apkPath, []byte("fake-apk-binary-content"), 0644); err != nil {
		t.Fatalf("failed writing test apk: %v", err)
	}

	data := BuildMobileReportData(apkPath, nil, nil, nil, nil, nil)

	// Refusal to overwrite the input APK
	err := WriteMobileAuditReport(data, apkPath, apkPath)
	if err == nil || !strings.Contains(err.Error(), "refusing to overwrite input APK") {
		t.Fatalf("expected refusal to overwrite input APK, got: %v", err)
	}

	// Successful write to standard destination
	reportPath := filepath.Join(tmpDir, "mobile_audit.html")
	if err := WriteMobileAuditReport(data, reportPath, apkPath); err != nil {
		t.Fatalf("failed writing report: %v", err)
	}

	fi, err := os.Stat(reportPath)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("expected non-empty written report at %s", reportPath)
	}

	// Confirm input APK bytes were preserved and untouched
	apkBytes, _ := os.ReadFile(apkPath)
	if string(apkBytes) != "fake-apk-binary-content" {
		t.Fatalf("input APK was corrupted by report generation!")
	}
}

// 13. Determinism Test
func TestMobileReport_Determinism(t *testing.T) {
	manifest := newTestManifestResult()
	inventory := newTestInventory()

	data1 := BuildMobileReportData("app.apk", nil, manifest, nil, inventory, nil)
	data2 := BuildMobileReportData("app.apk", nil, manifest, nil, inventory, nil)

	// Pin the timestamp for deterministic byte comparison
	data1.GeneratedAt = "2026-10-18 22:00:00 UTC"
	data2.GeneratedAt = "2026-10-18 22:00:00 UTC"

	b1, err1 := GenerateMobileAuditHTML(data1)
	b2, err2 := GenerateMobileAuditHTML(data2)

	if err1 != nil || err2 != nil {
		t.Fatalf("render error: %v / %v", err1, err2)
	}
	if string(b1) != string(b2) {
		t.Errorf("report generation is non-deterministic!")
	}
}

// 14. Local Offline Guarantee Test (No Remote CDNs / Fonts / Analytics)
func TestMobileReport_OfflineSelfContained(t *testing.T) {
	data := BuildMobileReportData("app.apk", nil, newTestManifestResult(), newTestArtifactResult(), newTestInventory(), nil)
	htmlBytes, _ := GenerateMobileAuditHTML(data)
	html := string(htmlBytes)

	prohibitedRemoteTokens := []string{
		"http://", "https://", // within <link> or <script src=>
		"fonts.googleapis.com",
		"cdnjs.cloudflare.com",
		"cdn.jsdelivr.net",
		"unpkg.com",
		"google-analytics.com",
		"googletagmanager.com",
	}

	for _, token := range prohibitedRemoteTokens {
		// Only check external script or link references
		if strings.Contains(html, "<script src=\""+token) ||
			strings.Contains(html, "<script src='\""+token) ||
			strings.Contains(html, "<link rel=\"stylesheet\" href=\""+token) ||
			strings.Contains(html, "<link rel='stylesheet' href='\""+token) {
			t.Errorf("remote network dependency found in report: %s", token)
		}
	}
}
