package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildCanonicalConsistencyFixture constructs a comprehensive canonical test fixture
// containing a representative cross-section of finding types, severities, verification
// statuses, sources (cloud, mobile, framework, web), secrets, and hostile strings.
func buildCanonicalConsistencyFixture(secretVal string) Report {
	return buildCanonicalConsistencyFixtureWithOrder(secretVal, false)
}

func buildCanonicalConsistencyFixtureWithOrder(secretVal string, reverse bool) Report {
	f1VerifiedSQLi := Finding{
		ID:                    "FND-SQLI-001",
		Title:                 "SQL Injection in Customer Lookup",
		Description:           "User-supplied query parameter 'id' is interpolated into database query without parameterized binding.",
		Category:              "sqli",
		Severity:              SeverityCritical,
		Confidence:            ConfidenceHigh,
		Target:                "https://api.example.com",
		Endpoint:              "/api/v1/customers/lookup?id=101",
		Method:                "GET",
		Source:                SourceAPI,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodActive,
		ClassificationOutcome: OutcomeConfirmed,
		Evidence:              "Database syntax error was triggered by payload ' OR '1'='1: SQLite3::SQLException",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Unescaped query execution confirmed via error oracle",
			Location:        "https://api.example.com/api/v1/customers/lookup?id=101",
			HTTPMethod:      "GET",
			HTTPStatus:      500,
			DetectionMethod: "dynamic_probe",
			DetectionStatus: "CONFIRMED",
		},
		Remediation: "Enforce parameterized queries or prepared statements across all database access layers.",
		RemediationAdvice: &RemediationAdvice{
			Summary:     "Enforce parameterized queries or prepared statements across all database access layers.",
			Steps:       []string{"Replace string concatenation with parameterized SQL bindings", "Add input validation for integer ID parameter"},
			References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"},
			CodeSnippet: "db.Query(\"SELECT * FROM customers WHERE id = ?\", customerID)",
		},
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Result:             "CONFIRMED_VULNERABILITY",
			VerificationMethod: "active_differential_probe",
			AnalysisMethod:     AnalysisMethodActive,
			SafeCurlCommand:    "curl -s 'https://api.example.com/api/v1/customers/lookup?id=101%27'",
			ReproductionSteps:  []string{"Issue GET request with single-quote appended to ID parameter", "Observe database error syntax in response body"},
		},
		Fingerprint: "fp-sqli-api-cust-001",
		Score:       90,
	}

	f2UnverifiedIndicator := Finding{
		ID:                    "FND-CORS-002",
		Title:                 "Permissive CORS Origin Reflection",
		Description:           "Server echoes arbitrary Origin headers without verifying against a corporate allowlist.",
		Category:              "cors-origin-reflection",
		Severity:              SeverityMedium,
		Confidence:            ConfidenceMedium,
		Target:                "https://api.example.com",
		Endpoint:              "/api/v1/feed",
		Method:                "GET",
		Source:                SourceAPI,
		Status:                FindingStatusSuspected,
		AnalysisMethod:        AnalysisMethodActive,
		ClassificationOutcome: OutcomeSuspected,
		Evidence:              "Origin: https://evil.attacker.com was reflected in Access-Control-Allow-Origin header",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Header Access-Control-Allow-Origin matched request origin",
			Location:        "https://api.example.com/api/v1/feed",
			HTTPMethod:      "GET",
			HTTPStatus:      200,
			DetectionMethod: "header_inspection",
			DetectionStatus: "SUSPECTED",
		},
		Remediation: "Validate Origin headers against an explicit, strict whitelist of trusted corporate origins.",
		RemediationAdvice: &RemediationAdvice{
			Summary:    "Validate Origin headers against an explicit, strict whitelist of trusted corporate origins.",
			Steps:      []string{"Configure allowed origins in server middleware"},
			References: []string{"https://owasp.org/www-project-top-ten/"},
		},
		Verification: VerificationRecord{
			Status:             VerificationDetected,
			Result:             "SUSPECTED_EXPOSURE",
			VerificationMethod: "passive_heuristic",
			AnalysisMethod:     AnalysisMethodActive,
		},
		Fingerprint: "fp-cors-feed-002",
		Score:       45,
	}

	f3FrameworkObs := Finding{
		ID:                    "FND-FW-003",
		Title:                 "Laravel Framework Detected",
		Description:           "Application identifies itself as Laravel 10.48.0 via session cookie conventions and debug headers.",
		Category:              "framework-laravel-detected",
		Severity:              SeverityInfo,
		Confidence:            ConfidenceHigh,
		Target:                "https://web.example.com",
		Endpoint:              "https://web.example.com",
		Method:                "GET",
		Source:                SourceCrawler,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodStatic,
		ClassificationOutcome: OutcomeInformational,
		Framework:             "Laravel",
		FrameworkVersion:      "10.48.0",
		Evidence:              "Set-Cookie header contained laravel_session cookie prefix; X-Powered-By indicated PHP/8.2",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Laravel framework footprint identified",
			Location:        "https://web.example.com",
			HTTPMethod:      "GET",
			HTTPStatus:      200,
			DetectionMethod: "fingerprint",
			DetectionStatus: "OBSERVED",
		},
		Remediation: "Disable X-Powered-By headers and rename default framework session cookie names in production.",
		Verification: VerificationRecord{
			Status:             VerificationObserved,
			Result:             "TECHNOLOGY_OBSERVED",
			VerificationMethod: "passive_header_fingerprint",
			AnalysisMethod:     AnalysisMethodStatic,
		},
		Fingerprint: "fp-fw-laravel-003",
		Score:       10,
	}

	f4ProtectedEndpoint := Finding{
		ID:                    "FND-AUTH-004",
		Title:                 "Protected Administrative Endpoint",
		Description:           "Administrative route correctly requires authentication and returned HTTP 403 Forbidden.",
		Category:              "endpoint-protected-403",
		Severity:              SeverityInfo,
		Confidence:            ConfidenceHigh,
		Target:                "https://web.example.com",
		Endpoint:              "https://web.example.com/admin/settings",
		Method:                "GET",
		Source:                SourceAPI,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodActive,
		ClassificationOutcome: OutcomeInformational,
		Evidence:              "Unauthenticated request received HTTP 403 Forbidden with access denied message",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Route correctly protected by access control barrier",
			Location:        "https://web.example.com/admin/settings",
			HTTPMethod:      "GET",
			HTTPStatus:      403,
			DetectionMethod: "status_code_check",
			DetectionStatus: "PROTECTED",
		},
		Remediation: "Maintain existing authorization boundaries and enforce role-based access controls.",
		Verification: VerificationRecord{
			Status:             VerificationObserved,
			Result:             "DEFENSE_VERIFIED",
			VerificationMethod: "negative_access_probe",
			AnalysisMethod:     AnalysisMethodActive,
		},
		Fingerprint: "fp-auth-admin-004",
		Score:       0,
	}

	f5CloudDatabase := Finding{
		ID:                    "FND-CLOUD-005",
		Title:                 "Public AWS S3 Bucket Storage Exposure",
		Description:           "Object storage bucket allows unauthenticated listing of customer asset blobs.",
		Category:              "cloud-storage-public-bucket",
		Severity:              SeverityHigh,
		Confidence:            ConfidenceHigh,
		Target:                "https://storage.example.com",
		Endpoint:              "https://customer-assets.s3.amazonaws.com",
		Method:                "GET",
		Source:                SourceCloud,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodActive,
		ClassificationOutcome: OutcomeConfirmed,
		Evidence:              fmt.Sprintf("Bucket listing returned 250 keys with leaked secret token %s in metadata", secretVal),
		EvidenceDetails: EvidenceDetails{
			Observation:     "Unrestricted object listing in AWS S3 bucket",
			Location:        "https://customer-assets.s3.amazonaws.com",
			HTTPMethod:      "GET",
			HTTPStatus:      200,
			DetectionMethod: "cloud_api_probe",
			DetectionStatus: "CONFIRMED",
			Details: map[string]string{
				"technology":     "aws-s3",
				"provider":       "aws",
				"resource_scope": "customer-assets",
				"resource_id":    "arn:aws:s3:::customer-assets",
				"service_type":   "object-storage",
			},
		},
		Remediation: fmt.Sprintf("Enable S3 Block Public Access and revoke compromised key %s immediately.", secretVal),
		RemediationAdvice: &RemediationAdvice{
			Summary:    fmt.Sprintf("Enable S3 Block Public Access and revoke key %s.", secretVal),
			Steps:      []string{"Enable S3 Block Public Access at bucket and account levels", "Review IAM bucket policy"},
			References: []string{"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"},
		},
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Result:             "CONFIRMED_VULNERABILITY",
			VerificationMethod: "active_storage_probe",
			AnalysisMethod:     AnalysisMethodActive,
		},
		Fingerprint: "fp-cloud-s3-005",
		Score:       80,
	}

	f6MobileAPK := Finding{
		ID:                    "FND-APK-006",
		Title:                 "Exported Android Service Lacks Permission",
		Description:           "Android service is exported without an android:permission restriction, allowing arbitrary IPC invocation.",
		Category:              "android-exported-service",
		Severity:              SeverityMedium,
		Confidence:            ConfidenceHigh,
		Target:                "mobile-client.apk",
		Endpoint:              "com.example.mobile.SyncService",
		Method:                "IPC",
		Source:                SourceAPK,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodStatic,
		ClassificationOutcome: OutcomeConfirmed,
		Evidence:              "AndroidManifest.xml declares <service android:name=\"com.example.mobile.SyncService\" android:exported=\"true\" /> without android:permission attribute",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Service component exported without authorization barrier",
			Location:        "com.example.mobile.SyncService",
			DetectionMethod: "manifest_static_analysis",
			DetectionStatus: "CONFIRMED",
			Details: map[string]string{
				"package_name":   "com.example.mobile",
				"component_name": "com.example.mobile.SyncService",
				"permission":     "android.permission.INTERNET",
				"min_sdk":        "26",
				"target_sdk":     "33",
			},
		},
		Remediation: "Add android:exported=\"false\" or enforce a signature-level android:permission barrier.",
		RemediationAdvice: &RemediationAdvice{
			Summary:    "Add android:exported=\"false\" or enforce a signature-level android:permission barrier.",
			Steps:      []string{"Set android:exported to false unless IPC is required", "Enforce custom signature permission"},
			References: []string{"https://developer.android.com/privacy-and-security/security-best-practices"},
		},
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Result:             "STATIC_MANIFEST_VERIFIED",
			VerificationMethod: "manifest_ast_inspection",
			AnalysisMethod:     AnalysisMethodStatic,
		},
		Fingerprint: "fp-apk-sync-006",
		Score:       50,
	}

	f7HostileXSS := Finding{
		ID:                    "FND-XSS-007",
		Title:                 "Hostile XSS & Injection Payload Test <script>alert('xss')</script>",
		Description:           "Tests escaping of hostile HTML and JS: <img src=x onerror=alert('pwned')> \" ' & < >",
		Category:              "xss-escaping-test",
		Severity:              SeverityLow,
		Confidence:            ConfidenceMedium,
		Target:                "https://web.example.com",
		Endpoint:              "/search?q=<script>alert(1)</script>&tag=\" onmouseover=alert(2)",
		Method:                "GET",
		Source:                SourceAPI,
		Status:                FindingStatusConfirmed,
		AnalysisMethod:        AnalysisMethodActive,
		ClassificationOutcome: OutcomeConfirmed,
		Evidence:              "Response reflected raw payload: <script>alert(1)</script> and attr \" onfocus=alert(3)",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Reflected untrusted string without escaping: <svg onload=alert(4)>",
			Location:        "/search?q=<script>",
			DetectionMethod: "reflection_test",
		},
		Remediation: "HTML-entity escape all untrusted parameters before rendering into DOM.",
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Result:             "CONFIRMED_VULNERABILITY",
			VerificationMethod: "payload_reflection",
			AnalysisMethod:     AnalysisMethodActive,
		},
		Fingerprint: "fp-xss-hostile-007",
		Score:       25,
	}

	rawFindings := []Finding{
		f1VerifiedSQLi,
		f2UnverifiedIndicator,
		f3FrameworkObs,
		f4ProtectedEndpoint,
		f5CloudDatabase,
		f6MobileAPK,
		f7HostileXSS,
	}

	if reverse {
		for i, j := 0, len(rawFindings)-1; i < j; i, j = i+1, j-1 {
			rawFindings[i], rawFindings[j] = rawFindings[j], rawFindings[i]
		}
	}

	rep := BuildMultiTargetReport([]string{"https://api.example.com", "https://web.example.com", "https://storage.example.com", "mobile-client.apk"}, rawFindings)
	rep.CompletionStatus = "COMPLETED"
	return rep
}

// -----------------------------------------------------------------------------
// Test 1: Finding Identity and Count Parity Across All Formats
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_1_FindingIdentityAndCountParity(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("sk_live_" + "SECRETKEY998877665544332211")
	canonicalCount := len(fixture.Findings)
	if canonicalCount != 7 {
		t.Fatalf("expected 7 canonical findings in fixture, got %d", canonicalCount)
	}

	// 1. Canonical JSON
	jsonBytes, err := GenerateJSON(fixture)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	var parsedJSON Report
	if err := json.Unmarshal(jsonBytes, &parsedJSON); err != nil {
		t.Fatalf("unmarshaling Canonical JSON failed: %v", err)
	}
	if len(parsedJSON.Findings) != canonicalCount {
		t.Errorf("Canonical JSON finding count mismatch: expected %d, got %d", canonicalCount, len(parsedJSON.Findings))
	}

	// 2. Standard HTML
	htmlStr, err := GenerateHTML(fixture)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	// Every finding ID should appear in HTML
	for _, f := range fixture.Findings {
		if !strings.Contains(htmlStr, f.ID) {
			t.Errorf("Standard HTML missing finding ID %s", f.ID)
		}
	}

	// 3. Commercial Report (JSON & HTML)
	commRep := BuildCommercialReport(fixture)
	totalCommercialFindings := len(commRep.VerifiedFindings) + len(commRep.DetectedFindings) + len(commRep.Observations)
	if totalCommercialFindings != canonicalCount {
		t.Errorf("Commercial Report finding count mismatch: expected %d total (verified+detected+observed), got %d",
			canonicalCount, totalCommercialFindings)
	}
	commJSONBytes, err := GenerateCommercialJSON(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	var parsedComm CommercialReport
	if err := json.Unmarshal(commJSONBytes, &parsedComm); err != nil {
		t.Fatalf("unmarshaling Commercial JSON failed: %v", err)
	}
	if len(parsedComm.VerifiedFindings)+len(parsedComm.DetectedFindings)+len(parsedComm.Observations) != canonicalCount {
		t.Errorf("Commercial JSON roundtrip count mismatch: expected %d, got %d",
			canonicalCount, len(parsedComm.VerifiedFindings)+len(parsedComm.DetectedFindings)+len(parsedComm.Observations))
	}

	commHTMLStr, err := GenerateCommercialHTML(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	for _, f := range fixture.Findings {
		if !strings.Contains(commHTMLStr, f.ID) {
			t.Errorf("Commercial HTML missing finding ID %s", f.ID)
		}
	}

	// 4. SARIF 2.1.0
	sarifBytes, err := GenerateSARIF(fixture)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	if err := ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("official SARIF 2.1.0 schema validation failed: %v", err)
	}
	var sarifLog SARIFLog
	if err := json.Unmarshal(sarifBytes, &sarifLog); err != nil {
		t.Fatalf("unmarshaling SARIF failed: %v", err)
	}
	if len(sarifLog.Runs) != 1 {
		t.Fatalf("expected 1 SARIF run, got %d", len(sarifLog.Runs))
	}
	results := sarifLog.Runs[0].Results
	if len(results) != canonicalCount {
		t.Errorf("SARIF results count mismatch: expected %d, got %d", canonicalCount, len(results))
	}

	// Verify all finding IDs appear in SARIF results
	sarifFindingIDs := make(map[string]bool)
	for _, r := range results {
		if fid, ok := r.Properties["finding_id"].(string); ok {
			sarifFindingIDs[fid] = true
		}
	}
	for _, f := range fixture.Findings {
		if !sarifFindingIDs[f.ID] {
			t.Errorf("SARIF result missing finding_id property for %s", f.ID)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 2: Severity Mapping Parity
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_2_SeverityMappingParity(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	// Map of finding ID to expected canonical severity and SARIF level
	expectedSeverities := map[string]struct {
		felixSev   string
		sarifLevel string
	}{
		"FND-SQLI-001":  {SeverityCritical, "error"},
		"FND-CORS-002":  {SeverityMedium, "warning"},
		"FND-FW-003":    {SeverityInfo, "none"},
		"FND-AUTH-004":  {SeverityInfo, "none"},
		"FND-CLOUD-005": {SeverityHigh, "error"},
		"FND-APK-006":   {SeverityMedium, "warning"},
		"FND-XSS-007":   {SeverityLow, "note"},
	}

	sarifBytes, err := GenerateSARIF(fixture)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	var sarifLog SARIFLog
	_ = json.Unmarshal(sarifBytes, &sarifLog)

	for _, res := range sarifLog.Runs[0].Results {
		fid := res.Properties["finding_id"].(string)
		exp, ok := expectedSeverities[fid]
		if !ok {
			t.Fatalf("unexpected finding ID in SARIF: %s", fid)
		}
		if res.Level != exp.sarifLevel {
			t.Errorf("finding %s: expected SARIF level %s, got %s", fid, exp.sarifLevel, res.Level)
		}
		if res.Properties["severity"] != exp.felixSev {
			t.Errorf("finding %s: expected preserved severity %s, got %v", fid, exp.felixSev, res.Properties["severity"])
		}
	}

	commRep := BuildCommercialReport(fixture)
	for _, vf := range commRep.VerifiedFindings {
		exp := expectedSeverities[vf.ID]
		if vf.Severity != exp.felixSev {
			t.Errorf("Commercial verified finding %s: expected severity %s, got %s", vf.ID, exp.felixSev, vf.Severity)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 3: Verification and Result State Parity
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_3_VerificationAndResultStateParity(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	// 1. Finding FND-CORS-002 is an UNVERIFIED indicator (DETECTED)
	// It must NEVER be presented as a confirmed vulnerability in any format.
	commRep := BuildCommercialReport(fixture)

	// In Commercial Report, FND-CORS-002 must be in DetectedFindings, NOT in VerifiedFindings
	for _, vf := range commRep.VerifiedFindings {
		if vf.ID == "FND-CORS-002" {
			t.Errorf("unverified finding FND-CORS-002 was wrongly placed in VerifiedFindings")
		}
	}
	foundInDetected := false
	for _, df := range commRep.DetectedFindings {
		if df.ID == "FND-CORS-002" {
			foundInDetected = true
			if df.Verification.Status == VerificationVerified {
				t.Errorf("unverified finding FND-CORS-002 was marked VerificationVerified in DetectedFindings")
			}
		}
	}
	if !foundInDetected {
		t.Errorf("expected FND-CORS-002 in DetectedFindings")
	}

	// In SARIF, FND-CORS-002 property verification_status must NOT be VERIFIED
	sarifBytes, _ := GenerateSARIF(fixture)
	var sarifLog SARIFLog
	_ = json.Unmarshal(sarifBytes, &sarifLog)
	for _, res := range sarifLog.Runs[0].Results {
		if res.Properties["finding_id"] == "FND-CORS-002" {
			if res.Properties["verification_status"] == string(VerificationVerified) {
				t.Errorf("unverified finding FND-CORS-002 had verification_status VERIFIED in SARIF")
			}
		}
	}

	// 2. Finding FND-AUTH-004 is a PROTECTED endpoint (403 Forbidden)
	// It must be placed in Observations, NOT VerifiedFindings or DetectedFindings.
	for _, vf := range commRep.VerifiedFindings {
		if vf.ID == "FND-AUTH-004" {
			t.Errorf("protected endpoint FND-AUTH-004 was wrongly classified as VerifiedFinding")
		}
	}
	for _, df := range commRep.DetectedFindings {
		if df.ID == "FND-AUTH-004" {
			t.Errorf("protected endpoint FND-AUTH-004 was wrongly classified as DetectedFinding")
		}
	}
	foundObs := false
	for _, obs := range commRep.Observations {
		if obs.Category == "endpoint-protected-403" || obs.Title == "Protected Administrative Endpoint" {
			foundObs = true
		}
	}
	if !foundObs {
		t.Errorf("protected endpoint FND-AUTH-004 was missing from Observations")
	}
}

// -----------------------------------------------------------------------------
// Test 4: Secret Redaction Across All Five Formats
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_4_SecretRedactionAcrossAllFormats(t *testing.T) {
	secretVal := "sk_live_" + "998877665544332211aabbccddeeff"
	fixture := buildCanonicalConsistencyFixture(secretVal)

	// 1. Canonical JSON
	jsonBytes, err := GenerateJSON(fixture)
	if err != nil {
		t.Fatalf("GenerateJSON failed: %v", err)
	}
	if strings.Contains(string(jsonBytes), secretVal) {
		t.Errorf("secret leaked in Canonical JSON output")
	}

	// 2. Standard HTML
	htmlStr, err := GenerateHTML(fixture)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	if strings.Contains(htmlStr, secretVal) {
		t.Errorf("secret leaked in Standard HTML output")
	}

	// 3. Commercial JSON
	commRep := BuildCommercialReport(fixture)
	commJSONBytes, err := GenerateCommercialJSON(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	if strings.Contains(string(commJSONBytes), secretVal) {
		t.Errorf("secret leaked in Commercial JSON output")
	}

	// 4. Commercial HTML
	commHTMLStr, err := GenerateCommercialHTML(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	if strings.Contains(commHTMLStr, secretVal) {
		t.Errorf("secret leaked in Commercial HTML output")
	}

	// 5. SARIF 2.1.0
	sarifBytes, err := GenerateSARIF(fixture)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	if strings.Contains(string(sarifBytes), secretVal) {
		t.Errorf("secret leaked in SARIF output")
	}
}

// -----------------------------------------------------------------------------
// Test 5: Hostile Payload Escaping & XSS Safety
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_5_HostilePayloadEscapingXSSSafety(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	// Check Standard HTML
	htmlStr, err := GenerateHTML(fixture)
	if err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}

	// Raw executable tags must NEVER appear unescaped in HTML body
	hostileRawSnippets := []string{
		"<script>alert('xss')</script>",
		"<script>alert(1)</script>",
		"<img src=x onerror=alert('pwned')>",
		"<svg onload=alert(4)>",
	}

	for _, raw := range hostileRawSnippets {
		if strings.Contains(htmlStr, raw) {
			t.Errorf("hostile unescaped payload %q found in Standard HTML", raw)
		}
	}

	// Check Commercial HTML
	commRep := BuildCommercialReport(fixture)
	commHTMLStr, err := GenerateCommercialHTML(commRep)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	for _, raw := range hostileRawSnippets {
		if strings.Contains(commHTMLStr, raw) {
			t.Errorf("hostile unescaped payload %q found in Commercial HTML", raw)
		}
	}

	// Verify properly escaped entity presence in HTML
	if !strings.Contains(htmlStr, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped &lt;script&gt; in Standard HTML")
	}
	if !strings.Contains(commHTMLStr, "&lt;script&gt;") {
		t.Errorf("expected HTML-escaped &lt;script&gt; in Commercial HTML")
	}
}

// -----------------------------------------------------------------------------
// Test 6: Remediation Guidance Parity
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_6_RemediationGuidanceParity(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	// 1. Canonical JSON preserves Remediation and structured advice
	jsonBytes, _ := GenerateJSON(fixture)
	var parsedJSON Report
	_ = json.Unmarshal(jsonBytes, &parsedJSON)
	var sqliFinding *Finding
	for _, f := range parsedJSON.Findings {
		if f.ID == "FND-SQLI-001" {
			fCopy := f
			sqliFinding = &fCopy
			break
		}
	}
	if sqliFinding == nil {
		t.Fatalf("FND-SQLI-001 missing in parsed JSON")
	}
	if !strings.Contains(sqliFinding.Remediation, "parameterized queries") {
		t.Errorf("Canonical JSON missing remediation text: %s", sqliFinding.Remediation)
	}
	if sqliFinding.RemediationAdvice == nil || len(sqliFinding.RemediationAdvice.Steps) == 0 {
		t.Errorf("Canonical JSON missing structured RemediationAdvice steps")
	}

	// 2. Standard HTML renders remediation text
	htmlStr, _ := GenerateHTML(fixture)
	if !strings.Contains(htmlStr, "parameterized queries") {
		t.Errorf("Standard HTML missing remediation advice for SQLi")
	}

	// 3. SARIF preserves remediation in rule help and result properties
	sarifBytes, _ := GenerateSARIF(fixture)
	var sarifLog SARIFLog
	_ = json.Unmarshal(sarifBytes, &sarifLog)
	foundInSARIFResult := false
	for _, res := range sarifLog.Runs[0].Results {
		if res.Properties["finding_id"] == "FND-SQLI-001" {
			rem, ok := res.Properties["remediation"].(string)
			if ok && strings.Contains(rem, "parameterized queries") {
				foundInSARIFResult = true
			}
		}
	}
	if !foundInSARIFResult {
		t.Errorf("SARIF result properties missing remediation text")
	}

	// SARIF rule descriptor help also contains remediation
	foundInSARIFRule := false
	for _, rule := range sarifLog.Runs[0].Tool.Driver.Rules {
		if rule.Help != nil && strings.Contains(rule.Help.Text, "parameterized queries") {
			foundInSARIFRule = true
		}
	}
	if !foundInSARIFRule {
		t.Errorf("SARIF rule descriptor Help.Text missing remediation")
	}
}

// -----------------------------------------------------------------------------
// Test 7: Assessment Status Honesty (COMPLETED, PARTIAL, FAILED, BLOCKED, EMPTY)
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_7_AssessmentStatusHonesty(t *testing.T) {
	testCases := []struct {
		status           string
		expectScoreNA    bool
		expectSuccessful bool
		bannerPhrase     string
	}{
		{"COMPLETED", false, true, ""},
		{"PARTIAL", false, false, "Partial"},
		{"FAILED", true, false, "Failed"},
		{"BLOCKED", true, false, "Blocked"},
	}

	for _, tc := range testCases {
		t.Run("Status_"+tc.status, func(t *testing.T) {
			rep := buildCanonicalConsistencyFixture("dummy")
			rep.CompletionStatus = tc.status
			if tc.expectScoreNA {
				rep.RiskScore = 0
				rep.RiskLevel = "UNAVAILABLE"
			}

			// 1. Standard HTML
			htmlStr, err := GenerateHTML(rep)
			if err != nil {
				t.Fatalf("GenerateHTML failed: %v", err)
			}
			if tc.expectScoreNA {
				if !strings.Contains(htmlStr, "N/A") {
					t.Errorf("expected N/A risk score in Standard HTML for status %s", tc.status)
				}
			}
			if tc.bannerPhrase != "" {
				if !strings.Contains(strings.ToLower(htmlStr), strings.ToLower(tc.bannerPhrase)) {
					t.Errorf("expected banner containing %q in Standard HTML for status %s", tc.bannerPhrase, tc.status)
				}
			}

			// 2. Commercial HTML
			commRep := BuildCommercialReport(rep, WithCompletionStatus(tc.status))
			commHTML, err := GenerateCommercialHTML(commRep)
			if err != nil {
				t.Fatalf("GenerateCommercialHTML failed: %v", err)
			}
			if tc.expectScoreNA {
				if !strings.Contains(commHTML, "N/A") {
					t.Errorf("expected N/A risk score in Commercial HTML for status %s", tc.status)
				}
			}
			if tc.bannerPhrase != "" {
				if !strings.Contains(strings.ToLower(commHTML), strings.ToLower(tc.bannerPhrase)) {
					t.Errorf("expected banner containing %q in Commercial HTML for status %s", tc.bannerPhrase, tc.status)
				}
			}

			// 3. SARIF execution invocation
			sarifBytes, err := GenerateSARIF(rep)
			if err != nil {
				t.Fatalf("GenerateSARIF failed: %v", err)
			}
			var sarifLog SARIFLog
			_ = json.Unmarshal(sarifBytes, &sarifLog)
			if len(sarifLog.Runs[0].Invocations) == 0 {
				t.Fatalf("expected invocations in SARIF run")
			}
			inv := sarifLog.Runs[0].Invocations[0]
			if inv.ExecutionSuccessful != tc.expectSuccessful {
				t.Errorf("expected SARIF ExecutionSuccessful=%v for status %s, got %v",
					tc.expectSuccessful, tc.status, inv.ExecutionSuccessful)
			}
		})
	}

	// Zero-finding assessment must NOT claim target is 100% secure
	t.Run("ZeroFindingsPostureHonesty", func(t *testing.T) {
		emptyRep := BuildMultiTargetReport([]string{"https://example.com"}, nil)
		commRep := BuildCommercialReport(emptyRep)
		if strings.Contains(strings.ToLower(commRep.ExecutiveSummary.PostureStatement), "100% secure") {
			t.Errorf("empty assessment posture statement claimed 100%% security")
		}
		if !strings.Contains(commRep.ExecutiveSummary.PostureStatement, "does not guarantee that the target is completely secure") {
			t.Errorf("empty assessment lacked honest disclaimer")
		}
	})
}

// -----------------------------------------------------------------------------
// Test 8: Deterministic Output Parity (Shuffled Findings)
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_8_DeterministicOutputParity(t *testing.T) {
	fixture1 := buildCanonicalConsistencyFixtureWithOrder("dummy", false)
	fixture2 := buildCanonicalConsistencyFixtureWithOrder("dummy", true)
	fixture1.Timestamp = "2026-10-22T00:00:00Z"
	fixture2.Timestamp = "2026-10-22T00:00:00Z"

	// 1. Canonical JSON determinism
	j1, err1 := GenerateJSON(fixture1)
	j2, err2 := GenerateJSON(fixture2)
	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateJSON failed: %v, %v", err1, err2)
	}
	if string(j1) != string(j2) {
		t.Errorf("Canonical JSON output differed between shuffled inputs")
	}

	// 2. Standard HTML determinism
	h1, errH1 := GenerateHTML(fixture1)
	h2, errH2 := GenerateHTML(fixture2)
	if errH1 != nil || errH2 != nil {
		t.Fatalf("GenerateHTML failed: %v, %v", errH1, errH2)
	}
	if h1 != h2 {
		t.Errorf("Standard HTML output differed between shuffled inputs")
	}

	// 3. SARIF determinism
	s1, errS1 := GenerateSARIF(fixture1)
	s2, errS2 := GenerateSARIF(fixture2)
	if errS1 != nil || errS2 != nil {
		t.Fatalf("GenerateSARIF failed: %v, %v", errS1, errS2)
	}
	if string(s1) != string(s2) {
		t.Errorf("SARIF output differed between shuffled inputs")
	}
}

// -----------------------------------------------------------------------------
// Test 9: Cloud and Mobile Metadata Parity
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_9_CloudAndMobileMetadataParity(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	sarifBytes, err := GenerateSARIF(fixture)
	if err != nil {
		t.Fatalf("GenerateSARIF failed: %v", err)
	}
	var sarifLog SARIFLog
	_ = json.Unmarshal(sarifBytes, &sarifLog)

	var cloudRes, mobileRes *SARIFResult
	for _, r := range sarifLog.Runs[0].Results {
		if r.Properties["finding_id"] == "FND-CLOUD-005" {
			rCopy := r
			cloudRes = &rCopy
		}
		if r.Properties["finding_id"] == "FND-APK-006" {
			rCopy := r
			mobileRes = &rCopy
		}
	}

	if cloudRes == nil {
		t.Fatalf("cloud finding missing from SARIF results")
	}
	if cloudRes.Properties["technology"] != "aws-s3" {
		t.Errorf("expected technology 'aws-s3', got %v", cloudRes.Properties["technology"])
	}
	if cloudRes.Properties["provider"] != "aws" {
		t.Errorf("expected provider 'aws', got %v", cloudRes.Properties["provider"])
	}
	if cloudRes.Properties["resource_scope"] != "customer-assets" {
		t.Errorf("expected resource_scope 'customer-assets', got %v", cloudRes.Properties["resource_scope"])
	}
	if len(cloudRes.Locations) > 0 {
		if cloudRes.Locations[0].LogicalLocations[0].Kind != "cloud_resource" {
			t.Errorf("expected location kind 'cloud_resource', got %s", cloudRes.Locations[0].LogicalLocations[0].Kind)
		}
	}

	if mobileRes == nil {
		t.Fatalf("mobile finding missing from SARIF results")
	}
	if mobileRes.Properties["package_name"] != "com.example.mobile" {
		t.Errorf("expected package_name 'com.example.mobile', got %v", mobileRes.Properties["package_name"])
	}
	if mobileRes.Properties["component_name"] != "com.example.mobile.SyncService" {
		t.Errorf("expected component_name 'com.example.mobile.SyncService', got %v", mobileRes.Properties["component_name"])
	}
	if len(mobileRes.Locations) > 0 {
		if mobileRes.Locations[0].LogicalLocations[0].Kind != "component" {
			t.Errorf("expected location kind 'component', got %s", mobileRes.Locations[0].LogicalLocations[0].Kind)
		}
	}
}

// -----------------------------------------------------------------------------
// Test 10: Canonical JSON Round-Trip Fidelity
// -----------------------------------------------------------------------------

func TestCrossFormatConsistency_10_CanonicalJSONRoundTrip(t *testing.T) {
	fixture := buildCanonicalConsistencyFixture("dummy")

	// Write to temporary JSON file
	tmpDir := t.TempDir()
	jsonFile := filepath.Join(tmpDir, "report.json")
	if err := WriteJSON(fixture, jsonFile); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}

	// Load via LoadReport
	loaded, err := LoadReport(jsonFile)
	if err != nil {
		t.Fatalf("LoadReport failed: %v", err)
	}

	if len(loaded.Findings) != len(fixture.Findings) {
		t.Errorf("loaded finding count mismatch: expected %d, got %d", len(fixture.Findings), len(loaded.Findings))
	}
	if loaded.Target != fixture.Target {
		t.Errorf("loaded target mismatch: expected %s, got %s", fixture.Target, loaded.Target)
	}
	if loaded.RiskScore != fixture.RiskScore {
		t.Errorf("loaded risk score mismatch: expected %d, got %d", fixture.RiskScore, loaded.RiskScore)
	}

	// Reserialize loaded report and compare to original
	reserialized, err := GenerateJSON(loaded)
	if err != nil {
		t.Fatalf("GenerateJSON on loaded report failed: %v", err)
	}
	origBytes, _ := os.ReadFile(jsonFile)
	if string(reserialized) != string(origBytes) {
		t.Errorf("roundtrip reserialization produced divergent JSON")
	}
}
