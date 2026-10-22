package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper to create a representative mobile report with APK findings.
func createTestMobileReport() Report {
	now := time.Now().UTC()

	findings := []Finding{
		{
			ID:                    "apk-man-exp-activity-001",
			RuleID:                "APK-MAN-EXP-ACTIVITY",
			Status:                FindingStatusConfirmed,
			ClassificationOutcome: OutcomeConfirmed,
			AnalysisMethod:        AnalysisMethodStatic,
			Category:              "android-exported-component",
			Title:                 "Exported Activity Without Permission",
			Severity:              SeverityHigh,
			Confidence:            ConfidenceHigh,
			Target:                "com.example.bankapp",
			Endpoint:              "com.example.bankapp.TransferFundsActivity",
			Method:                "STATIC_ANALYSIS",
			Description:           "The Activity com.example.bankapp.TransferFundsActivity is exported with an intent-filter but lacks an enclosing android:permission attribute.",
			Evidence:              "activity=com.example.bankapp.TransferFundsActivity, exported=true, permission=none",
			EvidenceDetails: EvidenceDetails{
				Observation:     "Exported Activity without required permission protection",
				Location:        "com.example.bankapp.TransferFundsActivity",
				DetectionMethod: "static_manifest_analysis",
				Details: map[string]string{
					"package_name":   "com.example.bankapp",
					"component_name": "com.example.bankapp.TransferFundsActivity",
					"apk_sha256":     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					"permission":     "none",
				},
			},
			Remediation: "Enforce android:permission on the exported activity or set android:exported=\"false\" if the component is purely internal.",
			RemediationAdvice: &RemediationAdvice{
				Summary: "Enforce permission attribute or disable component export.",
			},
			Verification: VerificationRecord{
				Status: VerificationDetected,
				Result: "Exported component without permission",
			},
			Source:      SourceAPK,
			Fingerprint: "fp-exp-activity-001",
			Score:       80,
			Timestamp:   now,
		},
		{
			ID:                    "apk-man-debuggable-002",
			RuleID:                "APK-MAN-DEBUGGABLE",
			Status:                FindingStatusConfirmed,
			ClassificationOutcome: OutcomeConfirmed,
			AnalysisMethod:        AnalysisMethodStatic,
			Category:              "android-debuggable",
			Title:                 "Application Insecurely Debuggable",
			Severity:              SeverityHigh,
			Confidence:            ConfidenceHigh,
			Target:                "com.example.bankapp",
			Endpoint:              "AndroidManifest.xml",
			Method:                "STATIC_ANALYSIS",
			Description:           "The application declares android:debuggable=\"true\" in AndroidManifest.xml, permitting runtime debugger attachment and memory dumping via ADB.",
			Evidence:              "android:debuggable=\"true\"",
			EvidenceDetails: EvidenceDetails{
				Observation:     "android:debuggable=\"true\" discovered in manifest",
				Location:        "AndroidManifest.xml",
				DetectionMethod: "static_manifest_analysis",
				Details: map[string]string{
					"package_name": "com.example.bankapp",
					"attribute":    "android:debuggable",
					"source_line":  "15",
				},
			},
			Remediation: "Ensure android:debuggable is false or omitted in release builds via build.gradle.",
			RemediationAdvice: &RemediationAdvice{
				Summary: "Remove debuggable flag for release variants.",
			},
			Verification: VerificationRecord{
				Status: VerificationDetected,
				Result: "Debuggable flag enabled",
			},
			Source:      SourceAPK,
			Fingerprint: "fp-debuggable-002",
			Score:       80,
			Timestamp:   now,
		},
		{
			ID:                    "apk-man-danger-perm-003",
			RuleID:                "APK-MAN-DANGEROUS-PERMISSION",
			Status:                FindingStatusConfirmed,
			ClassificationOutcome: OutcomeConfirmed,
			AnalysisMethod:        AnalysisMethodStatic,
			Category:              "android-dangerous-permission",
			Title:                 "Dangerous Permission Requested: android.permission.READ_SMS",
			Severity:              SeverityMedium,
			Confidence:            ConfidenceHigh,
			Target:                "com.example.bankapp",
			Endpoint:              "android.permission.READ_SMS",
			Method:                "STATIC_ANALYSIS",
			Description:           "Application requests the dangerous permission android.permission.READ_SMS (Private SMS text messages).",
			Evidence:              "uses-permission=android.permission.READ_SMS",
			EvidenceDetails: EvidenceDetails{
				Observation:     "uses-permission=android.permission.READ_SMS",
				Location:        "android.permission.READ_SMS",
				DetectionMethod: "static_manifest_analysis",
				Details: map[string]string{
					"package_name": "com.example.bankapp",
					"permission":   "android.permission.READ_SMS",
					"category":     "Private SMS text messages",
				},
			},
			Remediation: "Audit requested permissions according to least privilege. Request at runtime only when strictly needed.",
			RemediationAdvice: &RemediationAdvice{
				Summary: "Review and restrict SMS permissions.",
			},
			Verification: VerificationRecord{
				Status: VerificationDetected,
				Result: "Dangerous permission requested",
			},
			Source:      SourceAPK,
			Fingerprint: "fp-danger-perm-003",
			Score:       60,
			Timestamp:   now,
		},
		{
			ID:                    "apk-art-secret-004",
			RuleID:                "APK-ART-SECRET-AWS",
			Status:                FindingStatusConfirmed,
			ClassificationOutcome: OutcomeConfirmed,
			AnalysisMethod:        AnalysisMethodStatic,
			Category:              "hardcoded-secret",
			Title:                 "Discovered Hardcoded Secret in DEX: AWS Access Key",
			Severity:              SeverityCritical,
			Confidence:            ConfidenceHigh,
			Target:                "com.example.bankapp",
			Endpoint:              "classes.dex",
			Method:                "STATIC_ANALYSIS",
			Description:           "Hardcoded AWS Access Key identified within classes.dex bytecode.",
			Evidence:              "AKIAIOSFODNN7EXAMPLE",
			EvidenceDetails: EvidenceDetails{
				Observation:     "Pattern match for AWS Access Key in DEX string constant pool",
				Location:        "classes.dex",
				DetectionMethod: "static_artifact_analysis",
				Details: map[string]string{
					"package_name": "com.example.bankapp",
					"secret_type":  "AWS Access Key",
					"file_origin":  "classes.dex",
					"source_line":  "42",
				},
			},
			Remediation: "Revoke the exposed key immediately and migrate to dynamic IAM role assumption.",
			RemediationAdvice: &RemediationAdvice{
				Summary: "Revoke exposed credential and adopt temporary STS credentials.",
			},
			Verification: VerificationRecord{
				Status: VerificationVerified,
				Result: "Pattern matched AWS access key ID in bytecode",
			},
			Source:      SourceAPK,
			Fingerprint: "fp-secret-004",
			Score:       100,
			Timestamp:   now,
		},
	}

	mobileMeta := map[string]any{
		"apk_file_name":         "bankapp-v2.1.apk",
		"apk_sha256":            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"apk_file_size":         int64(15728640),
		"package_name":          "com.example.bankapp",
		"version_name":          "2.1.0",
		"version_code":          "210",
		"min_sdk":               "24",
		"target_sdk":            "33",
		"compile_sdk":           "34",
		"dex_count":             2,
		"multidex":              "Enabled (2 DEX files)",
		"intake_status":         "Verified & Isolated (Offline Static-Only)",
		"manifest_status":       "Completed",
		"assessment_status":     "Dry-Run Plan (Zero Network Requests Sent)",
		"assessment_scope_mode": "same-origin",
		"total_endpoints":       12,
		"total_hosts":           3,
		"analysis_mode":         "Static Analysis & Authorized Assessment",
		"limitations": []string{
			"Target SDK: 33 (rules evaluated against Android API 33 semantics)",
			"Static manifest and bytecode intelligence only; runtime TLS pinning and native binary internals were not dynamically verified",
		},
	}

	rep := Report{
		Version:          "1.0.0",
		Target:           "com.example.bankapp",
		Targets:          []string{"com.example.bankapp", "bankapp-v2.1.apk"},
		Timestamp:        now.Format(time.RFC3339),
		CompletionStatus: "COMPLETED",
		Findings:         findings,
		Metadata: map[string]any{
			"mobile_metadata": mobileMeta,
		},
	}

	RecalculateReportRisk(&rep)
	cr := BuildCommercialReport(rep, WithCompletionStatus("COMPLETED"))
	rep.CommercialReport = &cr

	return rep
}

// ----------------------------------------------------------------------------
// 1. CANONICAL HTML RENDERING TESTS
// ----------------------------------------------------------------------------

func TestMobileReport_CanonicalHTML_SummaryCard(t *testing.T) {
	rep := createTestMobileReport()
	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	htmlStr := string(html)

	// Summary Card header
	if !strings.Contains(htmlStr, "Android APK Audit &amp; Mobile Assessment Summary") && !strings.Contains(htmlStr, "Android APK Audit & Mobile Assessment Summary") {
		t.Errorf("HTML missing Mobile Assessment Summary card title")
	}

	// Package details
	if !strings.Contains(htmlStr, "com.example.bankapp") {
		t.Errorf("HTML missing package name")
	}
	if !strings.Contains(htmlStr, "2.1.0") || !strings.Contains(htmlStr, "210") {
		t.Errorf("HTML missing version information")
	}

	// SHA-256 Digest
	if !strings.Contains(htmlStr, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") {
		t.Errorf("HTML missing APK SHA-256 digest")
	}

	// SDK posture
	if !strings.Contains(htmlStr, "Min: 24 | Target: 33") {
		t.Errorf("HTML missing Min or Target SDK posture")
	}

	// Component scope
	if !strings.Contains(htmlStr, "distinct Android component(s) evaluated") {
		t.Errorf("HTML missing Component Scope summary")
	}

	// Status & Analysis Mode
	if !strings.Contains(htmlStr, "COMPLETED") {
		t.Errorf("HTML missing assessment status badge")
	}

	// Limitations statement
	if !strings.Contains(htmlStr, "Target SDK: 33") {
		t.Errorf("HTML missing mobile analysis limitations")
	}
}

func TestMobileReport_CanonicalHTML_FindingItems(t *testing.T) {
	rep := createTestMobileReport()
	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	htmlStr := string(html)

	// Finding component & package labels
	if !strings.Contains(htmlStr, "Package:") {
		t.Errorf("HTML finding missing 'Package:' label")
	}
	if !strings.Contains(htmlStr, "Component:") {
		t.Errorf("HTML finding missing 'Component:' label")
	}
	if !strings.Contains(htmlStr, "Permission:") {
		t.Errorf("HTML finding missing 'Permission:' label")
	}

	// Component targets
	if !strings.Contains(htmlStr, "com.example.bankapp.TransferFundsActivity") {
		t.Errorf("HTML missing exported Activity component name")
	}
	if !strings.Contains(htmlStr, "android.permission.READ_SMS") {
		t.Errorf("HTML missing requested permission name")
	}
}

func TestMobileReport_CanonicalHTML_MobileFilter(t *testing.T) {
	rep := createTestMobileReport()
	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	htmlStr := string(html)

	// Filter button
	if !strings.Contains(htmlStr, "filterFindings('MOBILE')") {
		t.Errorf("HTML missing Mobile & APK filter button click handler")
	}
	if !strings.Contains(htmlStr, "Mobile &amp; APK") && !strings.Contains(htmlStr, "Mobile & APK") {
		t.Errorf("HTML missing 'Mobile & APK' filter button text")
	}
}

func TestMobileReport_CanonicalHTML_XSSSanitization(t *testing.T) {
	now := time.Now().UTC()

	maliciousPkg := "<script>alert('pwned-pkg')</script>"
	maliciousComp := "<img src=x onerror=alert('pwned-comp')>"
	maliciousPerm := "android.permission.INJECT\"><script>alert('perm')</script>"
	maliciousObs := "<script>document.location='http://attacker.com'</script>"

	rep := Report{
		Version:          "1.0.0",
		Target:           maliciousPkg,
		Targets:          []string{maliciousPkg},
		Timestamp:        now.Format(time.RFC3339),
		CompletionStatus: "COMPLETED",
		Findings: []Finding{
			{
				ID:                    "apk-xss-001",
				RuleID:                "APK-XSS",
				Status:                FindingStatusConfirmed,
				ClassificationOutcome: OutcomeConfirmed,
				AnalysisMethod:        AnalysisMethodStatic,
				Category:              "android-exported-component",
				Title:                 "Test Malicious Finding Title <script>",
				Severity:              SeverityHigh,
				Confidence:            ConfidenceHigh,
				Target:                maliciousPkg,
				Endpoint:              maliciousComp,
				Method:                "STATIC_ANALYSIS",
				Description:           "Description with <b>raw html</b>",
				Evidence:              maliciousObs,
				EvidenceDetails: EvidenceDetails{
					Observation:     maliciousObs,
					Location:        maliciousComp,
					DetectionMethod: "static_manifest_analysis",
					Details: map[string]string{
						"package_name":   maliciousPkg,
						"component_name": maliciousComp,
						"permission":     maliciousPerm,
					},
				},
				Remediation: "Fix input sanitization <script>",
				Source:      SourceAPK,
				Fingerprint: "fp-xss-001",
				Score:       80,
				Timestamp:   now,
			},
		},
		Metadata: map[string]any{
			"mobile_metadata": map[string]any{
				"package_name":      maliciousPkg,
				"version_name":      "<script>alert(1)</script>",
				"apk_file_name":     "test<script>.apk",
				"intake_status":     "Isolated <script>",
				"assessment_status": "Status <img src=x>",
			},
		},
	}

	RecalculateReportRisk(&rep)

	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	htmlStr := string(html)

	// Raw unescaped dangerous tags must NOT be present
	dangerousPatterns := []string{
		"<script>alert('pwned-pkg')</script>",
		"<img src=x onerror=alert('pwned-comp')>",
		"\"><script>alert('perm')</script>",
		"<script>document.location=",
		"<script>alert(1)</script>",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(htmlStr, pattern) {
			t.Errorf("XSS VULNERABILITY DETECTED! Raw unescaped pattern %q found in HTML report", pattern)
		}
	}
}

// ----------------------------------------------------------------------------
// 2. CANONICAL JSON EXPORT & ROUNDTRIP TESTS
// ----------------------------------------------------------------------------

func TestMobileReport_CanonicalJSON_RoundTrip(t *testing.T) {
	orig := createTestMobileReport()

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var roundtrip Report
	if err := json.Unmarshal(data, &roundtrip); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if !roundtrip.HasMobileScope() {
		t.Errorf("roundtrip report missing HasMobileScope()")
	}
	if !roundtrip.HasMobileFindings() {
		t.Errorf("roundtrip report missing HasMobileFindings()")
	}
	if roundtrip.MobilePackageName() != "com.example.bankapp" {
		t.Errorf("expected MobilePackageName 'com.example.bankapp', got %q", roundtrip.MobilePackageName())
	}
	if !strings.Contains(roundtrip.MobileVersion(), "2.1.0") {
		t.Errorf("expected MobileVersion to contain '2.1.0', got %q", roundtrip.MobileVersion())
	}
	if roundtrip.MobileSHA256() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("expected MobileSHA256 digest match, got %q", roundtrip.MobileSHA256())
	}
	if len(roundtrip.Findings) != len(orig.Findings) {
		t.Errorf("expected %d findings, got %d", len(orig.Findings), len(roundtrip.Findings))
	}
}

// ----------------------------------------------------------------------------
// 3. COMMERCIAL REPORT 2.0 (JSON & HTML) TESTS
// ----------------------------------------------------------------------------

func TestMobileReport_CommercialJSON_AssetClassification(t *testing.T) {
	rep := createTestMobileReport()
	cr := BuildCommercialReport(rep)

	// Asset Inventory Classification
	var foundMobileAsset bool
	for _, asset := range cr.AttackSurface.Assets {
		if asset.AssetType == "MOBILE_APPLICATION" {
			foundMobileAsset = true
			if !strings.Contains(asset.URL, "com.example.bankapp") && !strings.Contains(asset.URL, "bankapp-v2.1.apk") {
				t.Errorf("expected mobile asset URL to contain package or apk name, got %q", asset.URL)
			}
		}
	}
	if !foundMobileAsset {
		t.Errorf("Commercial Report AttackSurface missing asset with AssetType='MOBILE_APPLICATION'")
	}

	// Scope Summary & Posture
	if !strings.Contains(strings.ToLower(cr.ExecutiveSummary.ScopeSummary), "android") && !strings.Contains(strings.ToLower(cr.ExecutiveSummary.ScopeSummary), "mobile") && !strings.Contains(strings.ToLower(cr.ExecutiveSummary.ScopeSummary), "apk") {
		t.Errorf("Commercial Report ScopeSummary should mention android/mobile/apk assessment, got: %s", cr.ExecutiveSummary.ScopeSummary)
	}
	if len(cr.ExecutiveSummary.PostureStatement) == 0 {
		t.Errorf("Commercial Report PostureStatement should not be empty")
	}

	// Technical Findings
	allFindings := append(append([]CommercialFinding{}, cr.VerifiedFindings...), cr.DetectedFindings...)
	if len(allFindings) == 0 {
		t.Errorf("Commercial Report missing findings")
	}
	var foundExportedActivity bool
	for _, f := range allFindings {
		if strings.Contains(f.Title, "Exported Activity") {
			foundExportedActivity = true
			if !strings.Contains(f.AffectedAsset, "TransferFundsActivity") && !strings.Contains(f.AssetLocation, "TransferFundsActivity") {
				t.Errorf("expected Commercial Finding to reference 'TransferFundsActivity', got asset=%q location=%q", f.AffectedAsset, f.AssetLocation)
			}
		}
	}
	if !foundExportedActivity {
		t.Errorf("Commercial Report missing APK-MAN-EXP-ACTIVITY finding")
	}
}

func TestMobileReport_CommercialHTML(t *testing.T) {
	rep := createTestMobileReport()
	cr := BuildCommercialReport(rep)

	html, err := GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}

	htmlStr := string(html)
	if !strings.Contains(htmlStr, "MOBILE APPLICATION") && !strings.Contains(htmlStr, "MOBILE_APPLICATION") {
		t.Errorf("Commercial HTML missing MOBILE APPLICATION asset type indicator")
	}
	if !strings.Contains(htmlStr, "com.example.bankapp") {
		t.Errorf("Commercial HTML missing package name")
	}
	if !strings.Contains(htmlStr, "Exported Activity Without Permission") {
		t.Errorf("Commercial HTML missing finding title")
	}
}

// ----------------------------------------------------------------------------
// 4. SARIF 2.1.0 EXPORT TESTS
// ----------------------------------------------------------------------------

func TestMobileReport_SARIF_LogicalLocations(t *testing.T) {
	rep := createTestMobileReport()

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarif SARIFLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF JSON unmarshal failed: %v", err)
	}

	if len(sarif.Runs) == 0 {
		t.Fatalf("SARIF output has 0 runs")
	}

	run := sarif.Runs[0]
	if len(run.Results) == 0 {
		t.Fatalf("SARIF run has 0 results")
	}

	var foundComponentKind bool
	for _, res := range run.Results {
		if len(res.Locations) > 0 && len(res.Locations[0].LogicalLocations) > 0 {
			kind := res.Locations[0].LogicalLocations[0].Kind
			if kind == "component" {
				foundComponentKind = true
			}
		}
	}

	if !foundComponentKind {
		t.Errorf("SARIF export missing logicalLocation with Kind='component' for mobile finding")
	}
}

func TestMobileReport_SARIF_LineNumberHandling(t *testing.T) {
	rep := createTestMobileReport()

	data, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}

	var sarif SARIFLog
	if err := json.Unmarshal(data, &sarif); err != nil {
		t.Fatalf("SARIF JSON unmarshal failed: %v", err)
	}

	run := sarif.Runs[0]

	for _, res := range run.Results {
		switch res.RuleID {
		case "APK-MAN-EXP-ACTIVITY":
			// No source_line defined in details; must NOT have fabricated fake line number
			if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
				if res.Locations[0].PhysicalLocation.Region != nil && res.Locations[0].PhysicalLocation.Region.StartLine > 0 {
					t.Errorf("SARIF fabricated fake line number %d for finding without source_line!",
						res.Locations[0].PhysicalLocation.Region.StartLine)
				}
			}
		case "APK-MAN-DEBUGGABLE":
			// source_line: "15" is defined
			if len(res.Locations) > 0 && res.Locations[0].PhysicalLocation != nil {
				if res.Locations[0].PhysicalLocation.Region == nil || res.Locations[0].PhysicalLocation.Region.StartLine != 15 {
					t.Errorf("SARIF missing region.startLine=15 for debuggable finding, got %+v",
						res.Locations[0].PhysicalLocation.Region)
				}
			}
		}
	}
}

// ----------------------------------------------------------------------------
// 5. ZERO FINDINGS SCENARIO & LIMITATIONS
// ----------------------------------------------------------------------------

func TestMobileReport_ZeroFindings(t *testing.T) {
	now := time.Now().UTC()

	rep := Report{
		Version:          "1.0.0",
		Target:           "com.clean.secureapp",
		Targets:          []string{"com.clean.secureapp", "secureapp.apk"},
		Timestamp:        now.Format(time.RFC3339),
		CompletionStatus: "COMPLETED",
		Findings:         []Finding{}, // Zero findings
		Metadata: map[string]any{
			"mobile_metadata": map[string]any{
				"package_name":          "com.clean.secureapp",
				"apk_file_name":         "secureapp.apk",
				"intake_status":         "Verified & Isolated (Offline Static-Only)",
				"manifest_status":       "Completed",
				"assessment_status":     "Completed",
				"assessment_scope_mode": "same-origin",
				"analysis_mode":         "Static Analysis Only (Offline)",
				"limitations": []string{
					"Static analysis detected 0 security exposures in manifest and bytecode",
					"Offline static analysis cannot evaluate runtime integrity, server-side business logic, or dynamic runtime instrumentation",
				},
			},
		},
	}

	RecalculateReportRisk(&rep)

	// HTML must render cleanly
	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("GenerateHTML failed on zero findings report: %v", err)
	}

	htmlStr := string(html)
	if !strings.Contains(htmlStr, "com.clean.secureapp") {
		t.Errorf("HTML missing package name on zero findings report")
	}
	if !strings.Contains(htmlStr, "No security findings") && !strings.Contains(htmlStr, "0 Security Findings") && !strings.Contains(htmlStr, "0 findings") {
		t.Errorf("HTML should indicate 0 findings detected")
	}

	// Limitations statement must be prominent
	if !strings.Contains(htmlStr, "Offline static analysis cannot evaluate runtime integrity") {
		t.Errorf("HTML missing prominent zero findings limitation disclaimer")
	}

	// Canonical JSON roundtrip must succeed
	jsonBytes, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	var unmarshaled Report
	if err := json.Unmarshal(jsonBytes, &unmarshaled); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if len(unmarshaled.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(unmarshaled.Findings))
	}

	// Commercial Report must build without errors
	cr := BuildCommercialReport(rep)
	if len(cr.VerifiedFindings) != 0 || len(cr.DetectedFindings) != 0 {
		t.Errorf("expected 0 findings in Commercial Report, got %d verified and %d detected", len(cr.VerifiedFindings), len(cr.DetectedFindings))
	}

	// SARIF must export with 0 results
	sarifBytes, err := GenerateSARIF(rep)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	var sarif SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarif); err != nil {
		t.Fatalf("SARIF unmarshal failed: %v", err)
	}
	if len(sarif.Runs[0].Results) != 0 {
		t.Errorf("expected 0 SARIF results, got %d", len(sarif.Runs[0].Results))
	}
}

// ----------------------------------------------------------------------------
// 6. EXECUTION STATUSES & PARTIAL ANALYSIS
// ----------------------------------------------------------------------------

func TestMobileReport_ExecutionStatuses(t *testing.T) {
	statuses := []string{"COMPLETED", "PARTIAL", "FAILED", "STATIC_ONLY"}

	for _, status := range statuses {
		t.Run("Status_"+status, func(t *testing.T) {
			rep := createTestMobileReport()
			rep.CompletionStatus = status
			if meta, ok := rep.Metadata["mobile_metadata"].(map[string]any); ok {
				meta["assessment_status"] = status
			}

			RecalculateReportRisk(&rep)

			html, err := GenerateHTML(rep)
			if err != nil {
				t.Fatalf("GenerateHTML failed for status %s: %v", status, err)
			}
			if !strings.Contains(string(html), status) {
				t.Errorf("HTML missing status string %q", status)
			}

			cr := BuildCommercialReport(rep, WithCompletionStatus(status))
			if cr.ExecutiveSummary.CompletionStatus != status {
				t.Errorf("Commercial Report Status mismatch: expected %s, got %s", status, cr.ExecutiveSummary.CompletionStatus)
			}
		})
	}
}

// ----------------------------------------------------------------------------
// 7. MODEL HELPER METHODS
// ----------------------------------------------------------------------------

func TestMobileReport_ModelHelperMethods(t *testing.T) {
	rep := createTestMobileReport()

	if !rep.HasMobileScope() {
		t.Errorf("expected HasMobileScope() true")
	}
	if !rep.HasMobileFindings() {
		t.Errorf("expected HasMobileFindings() true")
	}
	if rep.MobilePackageName() != "com.example.bankapp" {
		t.Errorf("expected MobilePackageName 'com.example.bankapp', got %s", rep.MobilePackageName())
	}
	if rep.MobileVersion() != "2.1.0 (build 210)" {
		t.Errorf("expected MobileVersion '2.1.0 (build 210)', got %s", rep.MobileVersion())
	}
	if rep.MobileSHA256() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("expected MobileSHA256 digest match")
	}
	if rep.MobileAssessmentStatus() != "COMPLETED" {
		t.Errorf("unexpected MobileAssessmentStatus: %s", rep.MobileAssessmentStatus())
	}
	if rep.MobileAnalysisMode() != "Static Analysis & Authorized Assessment" {
		t.Errorf("unexpected MobileAnalysisMode: %s", rep.MobileAnalysisMode())
	}

	sdkInfo := rep.MobileSDKInfo()
	if sdkInfo != "Min: 24 | Target: 33" {
		t.Errorf("unexpected MobileSDKInfo: %s", sdkInfo)
	}

	compSummary := rep.MobileComponentSummary()
	if !strings.Contains(compSummary, "distinct Android component(s) evaluated") {
		t.Errorf("unexpected MobileComponentSummary: %s", compSummary)
	}

	limitations := rep.MobileLimitations()
	if len(limitations) != 2 {
		t.Errorf("expected 2 limitations, got %d", len(limitations))
	}
}

// ----------------------------------------------------------------------------
// 8. FILE WRITERS TESTS (HTML, JSON, SARIF, Commercial)
// ----------------------------------------------------------------------------

func TestMobileReport_Writers(t *testing.T) {
	rep := createTestMobileReport()
	tempDir := t.TempDir()

	// WriteHTML
	htmlFile := filepath.Join(tempDir, "report.html")
	if err := WriteHTML(rep, htmlFile); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	if stat, err := os.Stat(htmlFile); err != nil || stat.Size() == 0 {
		t.Errorf("WriteHTML produced empty or missing file")
	}

	// WriteJSON
	jsonFile := filepath.Join(tempDir, "report.json")
	if err := WriteJSON(rep, jsonFile); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if stat, err := os.Stat(jsonFile); err != nil || stat.Size() == 0 {
		t.Errorf("WriteJSON produced empty or missing file")
	}

	// WriteSARIF
	sarifFile := filepath.Join(tempDir, "report.sarif")
	if err := WriteSARIF(rep, sarifFile); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	if stat, err := os.Stat(sarifFile); err != nil || stat.Size() == 0 {
		t.Errorf("WriteSARIF produced empty or missing file")
	}

	// WriteCommercialJSON
	commJSONFile := filepath.Join(tempDir, "commercial.json")
	if err := WriteCommercialJSON(*rep.CommercialReport, commJSONFile); err != nil {
		t.Fatalf("WriteCommercialJSON failed: %v", err)
	}
	if stat, err := os.Stat(commJSONFile); err != nil || stat.Size() == 0 {
		t.Errorf("WriteCommercialJSON produced empty or missing file")
	}

	// WriteCommercialHTML
	commHTMLFile := filepath.Join(tempDir, "commercial.html")
	if err := WriteCommercialHTML(*rep.CommercialReport, commHTMLFile); err != nil {
		t.Fatalf("WriteCommercialHTML failed: %v", err)
	}
	if stat, err := os.Stat(commHTMLFile); err != nil || stat.Size() == 0 {
		t.Errorf("WriteCommercialHTML produced empty or missing file")
	}
}
