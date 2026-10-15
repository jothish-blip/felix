package report

import (
	"encoding/json"
	"strings"
	"testing"

	"felix/pkg/api"
	"felix/pkg/cloud"
	"felix/pkg/crawler"
	"felix/pkg/secrets"
)

func TestAnalysisMethod_EnumsAndNormalization(t *testing.T) {
	if AnalysisMethodStatic != "STATIC_ANALYSIS" {
		t.Fatalf("expected AnalysisMethodStatic to be STATIC_ANALYSIS, got %s", AnalysisMethodStatic)
	}
	if AnalysisMethodActive != "ACTIVE_VERIFICATION" {
		t.Fatalf("expected AnalysisMethodActive to be ACTIVE_VERIFICATION, got %s", AnalysisMethodActive)
	}
	if AnalysisMethodManual != "MANUAL_REVIEW" {
		t.Fatalf("expected AnalysisMethodManual to be MANUAL_REVIEW, got %s", AnalysisMethodManual)
	}

	tests := []struct {
		input AnalysisMethod
		want  AnalysisMethod
	}{
		{AnalysisMethodStatic, AnalysisMethodStatic},
		{"static", AnalysisMethodStatic},
		{"STATIC_CODE_ANALYSIS", AnalysisMethodStatic},
		{AnalysisMethodActive, AnalysisMethodActive},
		{"active", AnalysisMethodActive},
		{"ACTIVE_PROBE", AnalysisMethodActive},
		{"dynamic", AnalysisMethodActive},
		{AnalysisMethodManual, AnalysisMethodManual},
		{"manual", AnalysisMethodManual},
		{"", AnalysisMethodStatic},
		{"unknown", AnalysisMethodStatic},
	}

	for _, tc := range tests {
		got := NormalizeAnalysisMethod(tc.input)
		if got != tc.want {
			t.Errorf("NormalizeAnalysisMethod(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestStaticIndicator_ProducesSuspectedFinding(t *testing.T) {
	sf := secrets.SecretFinding{
		Title:       "AWS Access Key Candidate",
		Type:        secrets.SecretAWSAccessKey,
		Severity:    secrets.SeverityHigh,
		Confidence:  secrets.ConfidenceHigh,
		Redacted:    "AKIA****************",
		Evidence:    "AKIAIOSFODNN7EXAMPLE",
		LineNumber:  42,
		Fingerprint: "aws-key-fp-1",
	}

	finding := FromSecretFinding("https://app.example.com", sf)

	if finding.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected AnalysisMethodStatic, got %s", finding.AnalysisMethod)
	}
	if finding.Status != FindingStatusSuspected {
		t.Errorf("expected FindingStatusSuspected for unverified static indicator, got %s", finding.Status)
	}
	if finding.Verification.Status != VerificationNotVerified {
		t.Errorf("expected VerificationNotVerified, got %s", finding.Verification.Status)
	}
	if finding.Verification.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected verification AnalysisMethodStatic, got %s", finding.Verification.AnalysisMethod)
	}
	if finding.Provenance == nil || finding.Provenance.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected provenance AnalysisMethodStatic, got %+v", finding.Provenance)
	}
	if !strings.Contains(finding.EvidenceDetails.NegativeEvidence, "Static code analysis only") {
		t.Errorf("expected negative evidence explaining no live test was performed, got %s", finding.EvidenceDetails.NegativeEvidence)
	}
}

func TestStaticEvidence_SupportsConfirmedClaimWithoutActiveExploitability(t *testing.T) {
	// Case A: Source map discovered during crawl
	asset := crawler.Asset{
		URL:         "https://example.com/bundle.js.map",
		Type:        crawler.AssetSourceMap,
		IsSourceMap: true,
		Size:        1048576,
	}

	smFinding, ok := FromCrawlerAsset("https://example.com", asset)
	if !ok {
		t.Fatalf("expected FromCrawlerAsset to return finding for source map")
	}

	if smFinding.Status != FindingStatusConfirmed {
		t.Errorf("expected FindingStatusConfirmed for directly observed artifact, got %s", smFinding.Status)
	}
	if smFinding.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected AnalysisMethodStatic for downloaded asset, got %s", smFinding.AnalysisMethod)
	}
	if smFinding.Verification.Status != VerificationObserved {
		t.Errorf("expected VerificationObserved, got %s", smFinding.Verification.Status)
	}
	if !strings.Contains(smFinding.EvidenceDetails.NegativeEvidence, "no active credential compromise or backend exposure demonstrated") {
		t.Errorf("expected honest negative evidence noting backend exploitability was not tested, got %s", smFinding.EvidenceDetails.NegativeEvidence)
	}

	// Case B: Missing security header (configuration state, confirmed absent)
	apiF := api.APIFinding{
		Category:    "missing-content-security-policy",
		Description: "Missing Content-Security-Policy header",
		Severity:    api.SeverityMedium,
		Confidence:  api.ConfidenceHigh,
		Endpoint:    "https://example.com/api",
		Method:      "GET",
		Evidence:    "Response headers evaluated; CSP header absent",
		Fingerprint: "missing-csp-fp",
	}

	hdrFinding := FromAPIFinding("https://example.com", apiF)
	if hdrFinding.Status != FindingStatusConfirmed {
		t.Errorf("expected FindingStatusConfirmed for confirmed absence of header, got %s", hdrFinding.Status)
	}
	if hdrFinding.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected AnalysisMethodStatic for header inspection, got %s", hdrFinding.AnalysisMethod)
	}
	if !strings.Contains(hdrFinding.Verification.Result, "configuration state, not an independently exploitable vulnerability") {
		t.Errorf("expected honest verification note on exploitability bounds, got %s", hdrFinding.Verification.Result)
	}
}

func TestDeduplication_HonestStatusAndAnalysisMethodMerge(t *testing.T) {
	fp := ComputeFingerprint("https://example.com", "sql-injection", "https://example.com/api/users", "GET", "sqli-key")

	// 1. Static indicator: suspected vulnerability
	fStatic := Finding{
		ID:              "FND-STATIC-1",
		RuleID:          "STATIC-SQLI",
		Status:          FindingStatusSuspected,
		AnalysisMethod:  AnalysisMethodStatic,
		Title:           "Potential SQL Injection Parameter",
		Category:        "sql-injection",
		Severity:        SeverityHigh,
		Confidence:      ConfidenceHigh,
		Target:          "https://example.com",
		Endpoint:        "https://example.com/api/users",
		Method:          "GET",
		Fingerprint:     fp,
		Evidence:        "Static analysis observed string concatenation in SQL query",
		Verification:    VerificationRecord{Status: VerificationNotVerified, AnalysisMethod: AnalysisMethodStatic},
	}

	// 2. Inconclusive active test: does NOT upgrade status to CONFIRMED
	fInconclusive := Finding{
		ID:              "FND-ACTIVE-INC",
		RuleID:          "ACTIVE-SQLI",
		Status:          FindingStatusInconclusive,
		AnalysisMethod:  AnalysisMethodActive,
		Title:           "Potential SQL Injection Parameter",
		Category:        "sql-injection",
		Severity:        SeverityHigh,
		Confidence:      ConfidenceMedium,
		Target:          "https://example.com",
		Endpoint:        "https://example.com/api/users",
		Method:          "GET",
		Fingerprint:     fp,
		Evidence:        "Active probe returned ambiguous HTTP 500 error",
		Verification:    VerificationRecord{Status: VerificationNotExposed, AnalysisMethod: AnalysisMethodActive},
	}

	dedupedInc := DeduplicateFindings([]Finding{fStatic, fInconclusive})
	if len(dedupedInc) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(dedupedInc))
	}
	if dedupedInc[0].Status != FindingStatusSuspected {
		t.Errorf("expected finding to remain SUSPECTED after inconclusive test, got %s", dedupedInc[0].Status)
	}

	// 3. Genuine active verification: succeeds and proves exploitability -> upgrades to CONFIRMED + ACTIVE_VERIFICATION
	fActiveConfirmed := Finding{
		ID:              "FND-ACTIVE-CONF",
		RuleID:          "ACTIVE-SQLI",
		Status:          FindingStatusConfirmed,
		AnalysisMethod:  AnalysisMethodActive,
		Title:           "Verified SQL Injection Vulnerability",
		Category:        "sql-injection",
		Severity:        SeverityHigh,
		Confidence:      ConfidenceHigh,
		Target:          "https://example.com",
		Endpoint:        "https://example.com/api/users",
		Method:          "GET",
		Fingerprint:     fp,
		Evidence:        "Active verification confirmed differential response with time delay payload",
		Verification:    VerificationRecord{Status: VerificationVerified, AnalysisMethod: AnalysisMethodActive},
	}

	dedupedConf := DeduplicateFindings([]Finding{fStatic, fActiveConfirmed})
	if len(dedupedConf) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(dedupedConf))
	}
	if dedupedConf[0].Status != FindingStatusConfirmed {
		t.Errorf("expected finding to upgrade to CONFIRMED after genuine active verification, got %s", dedupedConf[0].Status)
	}
	if dedupedConf[0].AnalysisMethod != AnalysisMethodActive {
		t.Errorf("expected AnalysisMethod to upgrade to ACTIVE_VERIFICATION, got %s", dedupedConf[0].AnalysisMethod)
	}
}

func TestReportOutputs_PreserveAnalysisMethodAndHonestStatus(t *testing.T) {
	finding := Finding{
		ID:             "FND-001",
		RuleID:         "RULE-TEST",
		Status:         FindingStatusConfirmed,
		AnalysisMethod: AnalysisMethodActive,
		Title:          "Confirmed Active Vulnerability",
		Category:       "api-security",
		Severity:       SeverityHigh,
		Confidence:     ConfidenceHigh,
		Target:         "https://example.com",
		Endpoint:       "https://example.com/api/test",
		Method:         "POST",
		Description:    "Active probe verified vulnerability",
		Evidence:       "Direct response evidence",
		EvidenceDetails: EvidenceDetails{
			Observation:     "Direct response evidence",
			Location:        "https://example.com/api/test",
			DetectionMethod: "active_probe",
		},
		Verification: VerificationRecord{
			Status:         VerificationVerified,
			AnalysisMethod: AnalysisMethodActive,
			Result:         "Vulnerability confirmed through live testing",
		},
	}

	norm := NormalizeFinding(finding)

	// 1. JSON report serialization
	jsonData, err := json.Marshal(norm)
	if err != nil {
		t.Fatalf("failed to marshal finding to JSON: %v", err)
	}
	jsonStr := string(jsonData)
	if !strings.Contains(jsonStr, `"status":"CONFIRMED"`) {
		t.Errorf("JSON output missing status: CONFIRMED")
	}
	if !strings.Contains(jsonStr, `"analysis_method":"ACTIVE_VERIFICATION"`) {
		t.Errorf("JSON output missing analysis_method: ACTIVE_VERIFICATION")
	}

	// 2. SARIF report export
	report := Report{
		Version:   "2.0.0",
		Target:    "https://example.com",
		Timestamp: "2026-10-15T00:00:00Z",
		Findings:  []Finding{norm},
	}
	sarifLog := BuildSARIFLog(report)
	if len(sarifLog.Runs) == 0 || len(sarifLog.Runs[0].Results) == 0 {
		t.Fatalf("expected SARIF results to be populated")
	}
	resProps := sarifLog.Runs[0].Results[0].Properties
	if resProps["status"] != "CONFIRMED" {
		t.Errorf("SARIF properties missing status CONFIRMED, got %v", resProps["status"])
	}
	if resProps["analysis_method"] != "ACTIVE_VERIFICATION" {
		t.Errorf("SARIF properties missing analysis_method ACTIVE_VERIFICATION, got %v", resProps["analysis_method"])
	}

	// 3. HTML report export
	htmlOutput, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("failed to generate HTML report: %v", err)
	}
	if !strings.Contains(htmlOutput, "badge-CONFIRMED") {
		t.Errorf("HTML report missing badge-CONFIRMED")
	}
	if !strings.Contains(htmlOutput, "badge-ACTIVE_VERIFICATION") {
		t.Errorf("HTML report missing badge-ACTIVE_VERIFICATION")
	}
}

func TestEngineAdapters_RegressionAndAnalysisMethod(t *testing.T) {
	target := "https://example.com"

	// 1. Cloud finding with active probe (bucket listing)
	cfActive := cloud.CloudFinding{
		Provider:    cloud.ProviderAWS,
		Category:    "bucket-listing",
		Description: "S3 bucket listing enabled",
		Severity:    cloud.SeverityHigh,
		Confidence:  cloud.ConfidenceHigh,
		Endpoint:    "https://example-bucket.s3.amazonaws.com",
		Evidence:    "XML ListBucketResult returned",
	}
	fCloudActive := FromCloudFinding(target, cfActive)
	if fCloudActive.AnalysisMethod != AnalysisMethodActive {
		t.Errorf("expected active cloud probe to have AnalysisMethodActive, got %s", fCloudActive.AnalysisMethod)
	}
	if fCloudActive.Status != FindingStatusConfirmed {
		t.Errorf("expected active bucket listing to have FindingStatusConfirmed, got %s", fCloudActive.Status)
	}

	// 2. Cloud finding with static privileged key detection
	cfStatic := cloud.CloudFinding{
		Provider:    cloud.ProviderSupabase,
		Category:    "privileged-service-role-key",
		Description: "Service role key found in script",
		Severity:    cloud.SeverityCritical,
		Confidence:  cloud.ConfidenceHigh,
		Endpoint:    "https://example.com/app.js",
		Evidence:    "eyJhbGciOi...",
	}
	fCloudStatic := FromCloudFinding(target, cfStatic)
	if fCloudStatic.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected static cloud finding to have AnalysisMethodStatic, got %s", fCloudStatic.AnalysisMethod)
	}
	if fCloudStatic.Status != FindingStatusSuspected {
		t.Errorf("expected static cloud secret finding to have FindingStatusSuspected, got %s", fCloudStatic.Status)
	}

	// 3. Crawler generic asset discovery
	crwAsset := crawler.Asset{
		URL:  "https://example.com/style.css",
		Type: crawler.AssetStylesheet,
		Size: 500,
	}
	fCrawler := FromCrawlerDiscovery(target, crwAsset)
	if fCrawler.AnalysisMethod != AnalysisMethodStatic {
		t.Errorf("expected crawler discovery to have AnalysisMethodStatic, got %s", fCrawler.AnalysisMethod)
	}
	if fCrawler.Status != FindingStatusConfirmed {
		t.Errorf("expected crawler discovery to have FindingStatusConfirmed, got %s", fCrawler.Status)
	}
}

func TestDefaultAnalysisMethod_CrossEngineAliases(t *testing.T) {
	activeEngines := []string{
		"api_security_engine",
		"apisec",
		"api_auditor",
		"webvuln",
		"web_vulnerability_engine",
		"felix-webvuln",
		"authz",
		"api_authz",
		"businesslogic",
		"business_logic_security_engine",
		"sessionsec",
		"session_identity_engine",
		"verification",
		"felix-verification",
	}

	for _, eng := range activeEngines {
		got := DefaultAnalysisMethod(eng, "")
		if got != AnalysisMethodActive {
			t.Errorf("expected engine %q to resolve to AnalysisMethodActive, got %s", eng, got)
		}
	}

	staticEngines := []string{
		"crawler",
		"secrets",
		"cloud",
		"auth",
		"unknown_custom_engine",
	}

	for _, eng := range staticEngines {
		got := DefaultAnalysisMethod(eng, "")
		if got != AnalysisMethodStatic {
			t.Errorf("expected engine %q to resolve to AnalysisMethodStatic, got %s", eng, got)
		}
	}
}
