package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Test Commercial Report 2.0 Invariants across all 20 required cases

// 1. A verified finding appears in Verified Findings.
func TestCommercialReport_1_VerifiedFindingAppearsInVerifiedFindings(t *testing.T) {
	f := Finding{
		ID:          "FND-VER-01",
		Title:       "Verified SQL Injection",
		Category:    "sqli",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/api/items",
		Method:      "GET",
		Description: "Verified time-based injection flaw",
		Evidence:    "Sleep delay demonstrated: 5042ms vs 120ms baseline",
		Verification: VerificationRecord{
			Status:             VerificationVerified,
			Result:             "Differential timing established time-based SQLi vulnerability",
			PolicyID:           "POL-WEBVULN-01",
			VerificationMethod: "differential_timing_probe",
			ConfidenceScore:    95,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected 1 verified finding, got %d", len(cr.VerifiedFindings))
	}
	if cr.VerifiedFindings[0].ID != "FND-VER-01" {
		t.Errorf("expected finding ID FND-VER-01, got %s", cr.VerifiedFindings[0].ID)
	}
	if len(cr.DetectedFindings) != 0 {
		t.Errorf("expected 0 detected findings, got %d", len(cr.DetectedFindings))
	}
	if cr.VerifiedFindings[0].Verification.Status != VerificationVerified {
		t.Errorf("expected status VERIFIED, got %s", cr.VerifiedFindings[0].Verification.Status)
	}
}

// 2. A detected but unverified finding appears in Detected Findings.
func TestCommercialReport_2_DetectedFindingAppearsInDetectedFindings(t *testing.T) {
	f1 := Finding{
		ID:          "FND-DET-01",
		Title:       "Candidate CORS Reflection",
		Category:    "cors-origin-reflection",
		Severity:    SeverityMedium,
		Confidence:  ConfidenceMedium,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/api/data",
		Method:      "GET",
		Verification: VerificationRecord{
			Status: VerificationDetected,
			Result: "Pattern matched; cross-origin reflection not yet actively tested",
		},
	}
	f2 := Finding{
		ID:          "FND-NOTVER-01",
		Title:       "Suspected IDOR Endpoint",
		Category:    "bola",
		Severity:    SeverityHigh,
		Confidence:  ConfidenceLow,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/api/users/2",
		Method:      "GET",
		Verification: VerificationRecord{
			Status: VerificationNotVerified,
			Result: "Differential tenant access could not be confirmed",
		},
	}

	rep := BuildReport("https://target.com", []Finding{f1, f2})
	cr := BuildCommercialReport(rep)

	if len(cr.DetectedFindings) != 2 {
		t.Fatalf("expected 2 detected findings, got %d", len(cr.DetectedFindings))
	}
	if len(cr.VerifiedFindings) != 0 {
		t.Errorf("expected 0 verified findings, got %d", len(cr.VerifiedFindings))
	}
	foundDet := false
	foundNotVer := false
	for _, df := range cr.DetectedFindings {
		if df.Verification.Status == VerificationDetected {
			foundDet = true
		}
		if df.Verification.Status == VerificationNotVerified {
			foundNotVer = true
		}
	}
	if !foundDet || !foundNotVer {
		t.Errorf("expected both DETECTED and NOT_VERIFIED statuses preserved")
	}
}

// 3. An inconclusive check is not represented as a verified vulnerability.
func TestCommercialReport_3_InconclusiveCheckNotVerifiedVulnerability(t *testing.T) {
	f := Finding{
		ID:          "FND-INCONC-01",
		Title:       "Rate Limit Inconclusive",
		Category:    "rate-limit",
		Severity:    SeverityLow,
		Confidence:  ConfidenceLow,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/login",
		Verification: VerificationRecord{
			Status: VerificationNotVerified,
			Result: "Check was inconclusive: target returned HTTP 503 during probe burst",
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: inconclusive check placed in Verified Findings!")
	}
	if len(cr.DetectedFindings) != 1 {
		t.Fatalf("expected inconclusive check in Detected Findings, got %d", len(cr.DetectedFindings))
	}
	if cr.DetectedFindings[0].Verification.Status == VerificationVerified {
		t.Fatalf("inconclusive check status upgraded to VERIFIED")
	}
}

// 4. A NOT_EXPOSED result is not classified as a vulnerability.
func TestCommercialReport_4_NotExposedNotClassifiedAsVulnerability(t *testing.T) {
	f := Finding{
		ID:          "FND-NEG-01",
		Title:       "Protected Storage Bucket",
		Category:    "cloud-storage-403",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/storage",
		Evidence:    "HTTP 403 AccessDenied returned for anonymous probe",
		Verification: VerificationRecord{
			Status:   VerificationNotExposed,
			PolicyID: "POL-CLOUD-01",
			Result:   "Anonymous bucket listing rejected with HTTP 403 AccessDenied",
			Limitations: []string{
				"Anonymous probe rejected; does not prove bucket is secure against authenticated users",
			},
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: NOT_EXPOSED placed in Verified Findings!")
	}
	if len(cr.DetectedFindings) != 0 {
		t.Fatalf("CRITICAL INVARIANT VIOLATION: NOT_EXPOSED placed in Detected Findings!")
	}
	if len(cr.TechnicalAppendix.NegativeVerificationOutcomes) != 1 {
		t.Fatalf("expected 1 negative verification outcome in Technical Appendix, got %d",
			len(cr.TechnicalAppendix.NegativeVerificationOutcomes))
	}
	neg := cr.TechnicalAppendix.NegativeVerificationOutcomes[0]
	if neg.FindingID != "FND-NEG-01" {
		t.Errorf("expected finding ID FND-NEG-01 in negative outcomes, got %s", neg.FindingID)
	}
}

// 5. An observation appears in Observations without being promoted to a finding.
func TestCommercialReport_5_ObservationNotPromotedToFinding(t *testing.T) {
	f := Finding{
		ID:          "FND-OBS-01",
		Title:       "Source Map File Identified",
		Category:    "source-map-discovered",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/app.js.map",
		Evidence:    "Source map downloaded successfully (12400 bytes)",
		Verification: VerificationRecord{
			Status: VerificationObserved,
			Result: "Client bundle source map cataloged during site crawl",
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 0 {
		t.Errorf("observation promoted to Verified Findings!")
	}
	if len(cr.DetectedFindings) != 0 {
		t.Errorf("observation promoted to Detected Findings!")
	}
	if len(cr.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(cr.Observations))
	}
	if cr.Observations[0].AffectedAsset != "https://target.com/app.js.map" {
		t.Errorf("expected affected asset preserved in observation, got %s", cr.Observations[0].AffectedAsset)
	}
}

// 6. A finding retains its original severity and confidence.
func TestCommercialReport_6_FindingRetainsOriginalSeverityAndConfidence(t *testing.T) {
	f := Finding{
		ID:         "FND-SEV-01",
		Title:      "Original Attribute Test",
		Category:   "env-exposure",
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Target:     "https://target.com",
		Endpoint:   "https://target.com/.env",
		Verification: VerificationRecord{
			Status:          VerificationVerified,
			ConfidenceScore: 78,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected 1 verified finding")
	}
	vf := cr.VerifiedFindings[0]
	if vf.Severity != SeverityHigh {
		t.Errorf("expected severity HIGH, got %s", vf.Severity)
	}
	if vf.Confidence.DetectionConfidence != ConfidenceMedium {
		t.Errorf("expected detection confidence MEDIUM, got %s", vf.Confidence.DetectionConfidence)
	}
}

// 7. Authentication state is represented correctly, including unknown states.
func TestCommercialReport_7_AuthenticationStateRepresentedCorrectly(t *testing.T) {
	fAuth := Finding{
		ID:       "F-AUTH-1",
		Title:    "Auth Req Test",
		Category: "api-endpoint",
		Endpoint: "https://target.com/api/secure",
		EvidenceDetails: EvidenceDetails{
			Details: map[string]string{"auth_state": "AUTH_REQUIRED"},
		},
		Verification: VerificationRecord{
			Status: VerificationDetected,
		},
	}
	fMulti := Finding{
		ID:       "F-MULTI-1",
		Title:    "BOLA Test",
		Category: "bola",
		Endpoint: "https://target.com/api/users/1",
		EvidenceDetails: EvidenceDetails{
			Details: map[string]string{
				"owner_identity":        "user_1",
				"unauthorized_identity": "user_2",
			},
		},
		Verification: VerificationRecord{
			Status: VerificationDetected,
		},
	}
	fUnknown := Finding{
		ID:       "F-UNK-1",
		Title:    "Unknown Auth Finding",
		Category: "generic-probe",
		Endpoint: "https://target.com/test",
		Verification: VerificationRecord{
			Status: VerificationDetected,
		},
	}

	rep := BuildReport("https://target.com", []Finding{fAuth, fMulti, fUnknown})
	cr := BuildCommercialReport(rep)

	allFindings := append(cr.VerifiedFindings, cr.DetectedFindings...)
	findingMap := make(map[string]CommercialFinding)
	for _, f := range allFindings {
		findingMap[f.ID] = f
	}

	if strings.Contains(strings.ToLower(findingMap["F-AUTH-1"].AuthenticationState), "unauthenticated") == false &&
		strings.Contains(strings.ToLower(findingMap["F-AUTH-1"].AuthenticationState), "auth required") == false {
		t.Errorf("expected auth required state, got: %s", findingMap["F-AUTH-1"].AuthenticationState)
	}
	if !strings.Contains(findingMap["F-MULTI-1"].AuthenticationState, "Multiple") {
		t.Errorf("expected Multiple Identities state for differential test, got: %s", findingMap["F-MULTI-1"].AuthenticationState)
	}
	if findingMap["F-UNK-1"].AuthenticationState != "Unknown" {
		t.Errorf("expected Unknown auth state when unspecified, got: %s", findingMap["F-UNK-1"].AuthenticationState)
	}
}

// 8. Evidence references and provenance are preserved.
func TestCommercialReport_8_EvidenceReferencesAndProvenancePreserved(t *testing.T) {
	f := Finding{
		ID:       "FND-EV-01",
		Title:    "Provenance Check",
		Category: "api-cors",
		Endpoint: "https://target.com/api/test",
		Source:   SourceAPI,
		Evidence: "Access-Control-Allow-Origin: https://evil.com",
		EvidenceDetails: EvidenceDetails{
			Observation: "Reflected origin header in response",
			Location:    "https://target.com/api/test:443",
		},
		Verification: VerificationRecord{
			Status: VerificationVerified,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected 1 verified finding")
	}
	ev := cr.VerifiedFindings[0].Evidence
	if ev.Provenance != "LIVE" {
		t.Errorf("expected LIVE provenance, got %s", ev.Provenance)
	}
	if len(ev.EvidenceReferences) == 0 {
		t.Errorf("expected evidence references preserved")
	}
}

// 9. Synthetic evidence remains explicitly marked.
func TestCommercialReport_9_SyntheticEvidenceExplicitlyMarked(t *testing.T) {
	f := Finding{
		ID:       "FND-SYNTH-01",
		Title:    "[SYNTHETIC FIXTURE] Mock Credential Leak",
		Category: "secrets",
		Endpoint: "https://target.com/bundle.js",
		Evidence: "[SYNTHETIC FIXTURE] token=mock_token_1234",
		Verification: VerificationRecord{
			Status:           VerificationVerified,
			SyntheticFixture: true,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected 1 verified finding")
	}
	if !cr.VerifiedFindings[0].SyntheticFixture {
		t.Errorf("finding SyntheticFixture flag lost in report")
	}
	if cr.VerifiedFindings[0].Evidence.Provenance != "FIXTURE" {
		t.Errorf("expected FIXTURE provenance, got %s", cr.VerifiedFindings[0].Evidence.Provenance)
	}
	if !cr.AssessmentScope.SyntheticFixture {
		t.Errorf("expected scope SyntheticFixture flag set to true")
	}
	if len(cr.TechnicalAppendix.SyntheticFixtureIndicators) == 0 {
		t.Errorf("expected synthetic fixture recorded in Technical Appendix")
	}
}

// 10. Secrets are redacted.
func TestCommercialReport_10_SecretsRedacted(t *testing.T) {
	rawJWT := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	f := Finding{
		ID:          "FND-SECRET-01",
		Title:       "Exposed JWT Token",
		Category:    "jwt-leak",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/main.js",
		Evidence:    "Found password=SuperSecretPassword123 and token=" + rawJWT,
		Description: "Authorization header contained api_key: secret_key_abcdef12345",
		Verification: VerificationRecord{
			Status:          VerificationVerified,
			SafeCurlCommand: "curl -H 'Authorization: Bearer " + rawJWT + "' https://target.com",
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	jsonBytes, err := GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("failed to generate JSON: %v", err)
	}
	jsonStr := string(jsonBytes)

	if strings.Contains(jsonStr, "SuperSecretPassword123") {
		t.Errorf("CRITICAL SECURITY LEAK: password not redacted in JSON output")
	}
	if strings.Contains(jsonStr, rawJWT) {
		t.Errorf("CRITICAL SECURITY LEAK: raw JWT not redacted in JSON output")
	}
	if strings.Contains(jsonStr, "secret_key_abcdef12345") {
		t.Errorf("CRITICAL SECURITY LEAK: API key not redacted in JSON output")
	}

	htmlStr, err := GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("failed to generate HTML: %v", err)
	}
	if strings.Contains(htmlStr, "SuperSecretPassword123") {
		t.Errorf("CRITICAL SECURITY LEAK: password not redacted in HTML output")
	}
	if strings.Contains(htmlStr, rawJWT) {
		t.Errorf("CRITICAL SECURITY LEAK: raw JWT not redacted in HTML output")
	}
}

// 11. Missing evidence is represented honestly.
func TestCommercialReport_11_MissingEvidenceRepresentedHonestly(t *testing.T) {
	f := Finding{
		ID:       "FND-NOEV-01",
		Title:    "No Evidence Finding",
		Category: "missing-header",
		Severity: SeverityLow,
		Target:   "https://target.com",
		Endpoint: "https://target.com",
		Verification: VerificationRecord{
			Status: VerificationDetected,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	allFindings := append(cr.VerifiedFindings, cr.DetectedFindings...)
	if len(allFindings) == 0 {
		t.Fatalf("expected at least 1 finding in report")
	}
	found := false
	for _, finding := range allFindings {
		if finding.ID == "FND-NOEV-01" {
			found = true
			if finding.Evidence.IsAvailable {
				t.Errorf("expected IsAvailable=false when no evidence exists")
			}
		}
	}
	if !found {
		t.Errorf("finding FND-NOEV-01 not found")
	}
}

// 12. Risk contribution is not invented when unavailable.
func TestCommercialReport_12_RiskContributionNotInventedWhenUnavailable(t *testing.T) {
	f := Finding{
		ID:         "FND-SCORE-01",
		Title:      "Scored Finding",
		Category:   "env-exposure",
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Score:      25,
		Verification: VerificationRecord{
			Status: VerificationVerified,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 1 {
		t.Fatalf("expected 1 verified finding")
	}
	contrib := cr.VerifiedFindings[0].RiskContribution
	if contrib.Score != 25 {
		t.Errorf("expected exact source score 25, got %d", contrib.Score)
	}
	if contrib.Model != "felix_deterministic_v1" {
		t.Errorf("expected model felix_deterministic_v1, got %s", contrib.Model)
	}
}

// 13. Correlated findings do not produce duplicate counts or double-counted risk.
func TestCommercialReport_13_CorrelatedFindingsDoNotDuplicateCountsOrDoubleCountRisk(t *testing.T) {
	f1 := Finding{
		ID:       "F-1",
		Title:    "Open Route",
		Category: "endpoint-discovered",
		Endpoint: "https://target.com/api/users",
		Severity: SeverityLow,
		Score:    5,
		Verification: VerificationRecord{
			Status: VerificationVerified,
		},
	}
	f2 := Finding{
		ID:       "F-2",
		Title:    "BOLA Data",
		Category: "bola",
		Endpoint: "https://target.com/api/users/2",
		Severity: SeverityHigh,
		Score:    25,
		Verification: VerificationRecord{
			Status: VerificationVerified,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f1, f2})
	story := SecurityStory{
		ID:               "STORY-1",
		Title:            "User Access Chain",
		RelatedIDs:       []string{"F-1", "F-2"},
		RiskContribution: 5,
	}
	AttachSecurityStories(&rep, []SecurityStory{story})

	cr := BuildCommercialReport(rep)

	if len(cr.VerifiedFindings) != 2 {
		t.Fatalf("expected exactly 2 verified findings without duplicates, got %d", len(cr.VerifiedFindings))
	}
	if cr.RiskOverview.RiskScore > 100 {
		t.Errorf("risk score exceeded 100: %d", cr.RiskOverview.RiskScore)
	}
}

// 14. Candidate attack paths are not presented as verified paths.
func TestCommercialReport_14_CandidateAttackPathsNotPresentedAsVerified(t *testing.T) {
	rep := BuildReport("https://target.com", nil)
	path := AttackPathSummary{
		ID:                "PATH-CAND-01",
		Title:             "Candidate Workflow Pivot",
		Status:            "CANDIDATE",
		CombinedRiskLevel: "HIGH",
		CombinedRiskScore: 65,
	}
	AttachAttackPaths(&rep, []AttackPathSummary{path})

	cr := BuildCommercialReport(rep)

	if len(cr.RiskOverview.AttackPaths) != 1 {
		t.Fatalf("expected 1 attack path, got %d", len(cr.RiskOverview.AttackPaths))
	}
	ap := cr.RiskOverview.AttackPaths[0]
	if ap.Status != "CANDIDATE" {
		t.Errorf("CRITICAL: candidate path upgraded to %s", ap.Status)
	}
}

// 15. Scope limitations and incomplete checks appear in the report.
func TestCommercialReport_15_ScopeLimitationsAndIncompleteChecksAppear(t *testing.T) {
	rep := BuildReport("https://target.com", nil)
	cr := BuildCommercialReport(rep,
		WithScopeExclusions([]string{"Read-only non-destructive audit"}, []string{"https://target.com/admin"}),
		WithExecutionErrors([]string{"Timeout reaching auth service"}),
	)

	if len(cr.AssessmentScope.ExplicitRestrictions) == 0 {
		t.Errorf("expected explicit restrictions in Scope section")
	}
	if len(cr.AssessmentScope.ExcludedTargets) == 0 {
		t.Errorf("expected excluded targets in Scope section")
	}
	if len(cr.AssessmentScope.ExecutionErrors) == 0 {
		t.Errorf("expected execution errors documented in Scope section")
	}
}

// 16. An empty assessment produces a valid report without claiming the target is secure.
func TestCommercialReport_16_EmptyAssessmentDoesNotClaimTargetIsSecure(t *testing.T) {
	rep := BuildReport("https://target.com", nil)
	cr := BuildCommercialReport(rep)

	if cr.RiskOverview.RiskScore != 0 {
		t.Errorf("expected 0 risk score for empty assessment, got %d", cr.RiskOverview.RiskScore)
	}
	if cr.ExecutiveSummary.CompletionStatus != "EMPTY" {
		t.Errorf("expected status EMPTY, got %s", cr.ExecutiveSummary.CompletionStatus)
	}
	// Posture statement must clearly document black-box / non-destructive limitations rather than declaring 100% security
	if !strings.Contains(cr.ExecutiveSummary.PostureStatement, "does not guarantee that the target is completely secure") {
		t.Errorf("expected honest posture statement for empty assessment, got: %s", cr.ExecutiveSummary.PostureStatement)
	}
}

// 17. Repeated report generation from identical data produces deterministic output.
func TestCommercialReport_17_RepeatedReportGenerationProducesDeterministicOutput(t *testing.T) {
	f1 := Finding{
		ID:       "FND-1",
		Title:    "Title 1",
		Category: "cors-wildcard",
		Severity: SeverityInfo,
		Target:   "https://target.com",
		Endpoint: "https://target.com/api",
		Method:   "GET",
		Evidence: "CORS * observed",
	}
	f2 := Finding{
		ID:       "FND-2",
		Title:    "Title 2",
		Category: "missing-csp",
		Severity: SeverityLow,
		Target:   "https://target.com",
		Endpoint: "https://target.com",
		Method:   "GET",
		Evidence: "CSP header absent",
	}

	rep1 := BuildReport("https://target.com", []Finding{f1, f2})
	rep2 := BuildReport("https://target.com", []Finding{f2, f1})

	rep1.Timestamp = "2026-10-10T12:00:00Z"
	rep2.Timestamp = "2026-10-10T12:00:00Z"

	json1, err1 := GenerateJSON(rep1)
	json2, err2 := GenerateJSON(rep2)
	if err1 != nil || err2 != nil {
		t.Fatalf("GenerateJSON failed: %v, %v", err1, err2)
	}

	if string(json1) != string(json2) {
		t.Errorf("JSON output is non-deterministic across identical inputs with shuffled order")
	}

	html1, errH1 := GenerateHTML(rep1)
	html2, errH2 := GenerateHTML(rep2)
	if errH1 != nil || errH2 != nil {
		t.Fatalf("GenerateHTML failed: %v, %v", errH1, errH2)
	}
	if html1 != html2 {
		t.Errorf("HTML output is non-deterministic across identical inputs")
	}
}

// 18. Report generation does not mutate source findings or assessment data.
func TestCommercialReport_18_ReportGenerationDoesNotMutateSourceFindings(t *testing.T) {
	f := Finding{
		ID:          "FND-IMMUTABLE-01",
		Title:       "Immutable Finding",
		Category:    "sqli",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/api",
		Evidence:    "Original evidence value",
		Remediation: "Original remediation text",
		Verification: VerificationRecord{
			Status: VerificationVerified,
			Result: "Original verification result",
		},
	}

	findings := []Finding{f}
	origJSON, _ := json.Marshal(findings)

	rep := BuildReport("https://target.com", findings)
	_ = BuildCommercialReport(rep)

	postJSON, _ := json.Marshal(findings)
	if string(origJSON) != string(postJSON) {
		t.Errorf("source findings were mutated during report generation:\nBefore: %s\nAfter: %s", string(origJSON), string(postJSON))
	}
}

// 19. Report output does not contain remediation recommendations or fix instructions.
func TestCommercialReport_19_NoRemediationRecommendationsInOutput(t *testing.T) {
	f := Finding{
		ID:          "FND-NOREM-01",
		Title:       "Vulnerable Endpoint",
		Category:    "sqli",
		Severity:    SeverityCritical,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/login",
		Remediation: "Add parameterized queries and sanitize user input immediately",
		Verification: VerificationRecord{
			Status: VerificationVerified,
		},
	}

	rep := BuildReport("https://target.com", []Finding{f})
	cr := BuildCommercialReport(rep)

	// Check JSON
	jsonBytes, err := GenerateCommercialJSON(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialJSON failed: %v", err)
	}
	jsonStr := string(jsonBytes)

	// Must NOT contain remediation instructions
	forbiddenPhrases := []string{
		"Add parameterized queries",
		"sanitize user input immediately",
		"enable MFA",
		"remediation_recommendations",
		"step-by-step fix",
	}
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(strings.ToLower(jsonStr), strings.ToLower(phrase)) {
			t.Errorf("forbidden remediation guidance found in Commercial JSON report: %q", phrase)
		}
	}

	// Check HTML
	htmlStr, err := GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("GenerateCommercialHTML failed: %v", err)
	}
	for _, phrase := range forbiddenPhrases {
		if strings.Contains(strings.ToLower(htmlStr), strings.ToLower(phrase)) {
			t.Errorf("forbidden remediation guidance found in Commercial HTML report: %q", phrase)
		}
	}
}

// 20. All eight report sections are present and populated.
func TestCommercialReport_20_AllEightSectionsPresentAndPopulated(t *testing.T) {
	fVer := Finding{
		ID:          "F-VER",
		Title:       "Verified Leak",
		Category:    "secrets",
		Severity:    SeverityCritical,
		Confidence:  ConfidenceHigh,
		Target:      "https://target.com",
		Endpoint:    "https://target.com/key.json",
		Evidence:    "api_key: secret_123",
		Verification: VerificationRecord{Status: VerificationVerified},
	}
	fDet := Finding{
		ID:          "F-DET",
		Title:       "Detected Header",
		Category:    "missing-csp",
		Severity:    SeverityLow,
		Target:      "https://target.com",
		Endpoint:    "https://target.com",
		Verification: VerificationRecord{Status: VerificationDetected},
	}
	fObs := Finding{
		ID:          "F-OBS",
		Title:       "Observed Asset",
		Category:    "asset-chunk",
		Target:      "https://target.com",
		Endpoint:    "https://target.com/chunk.js",
		Verification: VerificationRecord{Status: VerificationObserved},
	}

	rep := BuildReport("https://target.com", []Finding{fVer, fDet, fObs})
	cr := BuildCommercialReport(rep)

	// 1. Executive Summary
	if cr.ExecutiveSummary.Target == "" || cr.ExecutiveSummary.AssessmentID == "" {
		t.Errorf("Section 1 (Executive Summary) missing required target or ID")
	}

	// 2. Assessment Scope
	if len(cr.AssessmentScope.InScopeURLs) == 0 || len(cr.AssessmentScope.EnginesExecuted) == 0 {
		t.Errorf("Section 2 (Assessment Scope) missing URLs or engines")
	}

	// 3. Attack Surface
	if cr.AttackSurface.TotalAssets == 0 || len(cr.AttackSurface.Assets) == 0 {
		t.Errorf("Section 3 (Attack Surface) has 0 assets")
	}

	// 4. Risk Overview
	if cr.RiskOverview.ScoringModelDescription == "" || len(cr.RiskOverview.SeverityDistribution) == 0 {
		t.Errorf("Section 4 (Risk Overview) missing scoring description or distribution")
	}

	// 5. Verified Findings
	if len(cr.VerifiedFindings) != 1 {
		t.Errorf("Section 5 (Verified Findings) expected 1 finding, got %d", len(cr.VerifiedFindings))
	}

	// 6. Detected Findings
	if len(cr.DetectedFindings) != 1 {
		t.Errorf("Section 6 (Detected Findings) expected 1 finding, got %d", len(cr.DetectedFindings))
	}

	// 7. Observations
	if len(cr.Observations) != 1 {
		t.Errorf("Section 7 (Observations) expected 1 observation, got %d", len(cr.Observations))
	}

	// 8. Technical Appendix
	if cr.TechnicalAppendix.ReportSchemaVersion == "" || len(cr.TechnicalAppendix.FindingIndex) != 3 {
		t.Errorf("Section 8 (Technical Appendix) missing schema version or incomplete index")
	}
}

// 21. Regression tests for report consistency: Score attribution, Asset counts, Verification semantics, Attack path omitempty
func TestCommercialReport_RiskScoreAttributionAndReconciliation(t *testing.T) {
	// Baseline findings matching Juice Shop pattern:
	// 3 hardening headers (verified), 1 metrics exposure (observed), 1 story
	findings := []Finding{
		{
			ID:           "API-12c25a80",
			Title:        "Missing CSP header",
			Category:     "missing-csp",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationVerified},
			Score:        5,
		},
		{
			ID:           "API-44eda87b",
			Title:        "Missing Permissions-Policy",
			Category:     "missing-permissions-policy",
			Severity:     SeverityInfo,
			Confidence:   ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationVerified},
			Score:        1,
		},
		{
			ID:           "API-8dae2604",
			Title:        "Missing Referrer-Policy",
			Category:     "missing-referrer-policy",
			Severity:     SeverityInfo,
			Confidence:   ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationVerified},
			Score:        1,
		},
		{
			ID:           "API-4b0b86f9",
			Title:        "Public metrics endpoint",
			Category:     "metrics-exposure",
			Severity:     SeverityLow,
			Confidence:   ConfidenceHigh,
			Verification: VerificationRecord{Status: VerificationObserved},
			Score:        2,
		},
	}

	stories := []SecurityStory{
		{
			ID:               "STORY-DOC-01",
			Title:            "Public API Documentation",
			RiskContribution: 1,
		},
	}

	rep := BuildReport("http://127.0.0.1:3000", findings)
	rep.SecurityStories = stories
	RecalculateReportRisk(&rep)

	// Issue 1: Risk score attribution reconciliation
	// Exposure: 2 * 1.0 = 2.0
	// Hardening: 5 * 1.0 + 1 * 0.5 + 1 * 0.3 = 5.8
	// Story: 1.0
	// Total: round(2.0 + 5.8 + 1.0) = round(8.8) = 9
	if rep.RiskScore != 9 || rep.RiskLevel != "LOW" {
		t.Fatalf("expected risk score 9 (LOW), got score=%d level=%s", rep.RiskScore, rep.RiskLevel)
	}

	cr := *rep.CommercialReport
	ro := cr.RiskOverview

	// Check that ALL 4 contributing findings appear in FindingRiskContributions
	if len(ro.FindingRiskContributions) != 4 {
		t.Fatalf("expected 4 finding risk contributions (including metrics exposure), got %d", len(ro.FindingRiskContributions))
	}

	contribMap := make(map[string]CommercialRiskContribution)
	for _, c := range ro.FindingRiskContributions {
		contribMap[c.FindingID] = c
	}

	// Verify metrics exposure (API-4b0b86f9) contribution
	metricsContrib, ok := contribMap["API-4b0b86f9"]
	if !ok {
		t.Fatalf("observed metrics exposure API-4b0b86f9 must be included in finding risk contributions")
	}
	if metricsContrib.Score != 2 || metricsContrib.Weight != 1.0 || metricsContrib.AdjustedScore != 2.0 {
		t.Errorf("metrics exposure contribution incorrect: score=%d weight=%.1f adjusted=%.2f",
			metricsContrib.Score, metricsContrib.Weight, metricsContrib.AdjustedScore)
	}

	// Verify CSP contribution
	cspContrib := contribMap["API-12c25a80"]
	if cspContrib.Score != 5 || cspContrib.Weight != 1.0 || cspContrib.AdjustedScore != 5.0 {
		t.Errorf("CSP contribution incorrect: score=%d weight=%.1f adjusted=%.2f",
			cspContrib.Score, cspContrib.Weight, cspContrib.AdjustedScore)
	}

	// Verify ScoreBreakdown subtotals
	bd := ro.ScoreBreakdown
	if bd.ExposureSubtotal != 2.0 {
		t.Errorf("expected ExposureSubtotal 2.0, got %.2f", bd.ExposureSubtotal)
	}
	if bd.HardeningSubtotal != 5.8 {
		t.Errorf("expected HardeningSubtotal 5.8, got %.2f", bd.HardeningSubtotal)
	}
	if bd.StoryBonus != 1.0 {
		t.Errorf("expected StoryBonus 1.0, got %.2f", bd.StoryBonus)
	}
	if bd.TotalScore != 9 {
		t.Errorf("expected TotalScore 9, got %d", bd.TotalScore)
	}
	if !strings.Contains(bd.Formula, "= 9") {
		t.Errorf("expected formula to reconcile to 9, got %s", bd.Formula)
	}
}

func TestCommercialReport_AssetCountDefinitions(t *testing.T) {
	// Target with 1 base domain, 2 API endpoints, 1 route, and metadata crawled assets
	findings := []Finding{
		{ID: "F1", Endpoint: "http://target.com/api/v1/users", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationObserved}},
		{ID: "F2", Endpoint: "http://target.com/api/v1/posts", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationObserved}},
		{ID: "F3", Endpoint: "http://target.com/about", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationObserved}},
	}

	rep := BuildReport("http://target.com", findings)
	rep.Metadata = map[string]any{
		"crawled_assets_count": 4,
	}
	RecalculateReportRisk(&rep)

	cr := *rep.CommercialReport

	// Issue 2: Distinct asset count definitions
	// Total attack-surface resources = target + 2 API + 1 route = 4
	if cr.AttackSurface.TotalAssets != 4 {
		t.Errorf("expected 4 total attack surface resources, got %d", cr.AttackSurface.TotalAssets)
	}
	if cr.AttackSurface.FrontendAssetsCount != 4 {
		t.Errorf("expected 4 frontend crawled assets from metadata, got %d", cr.AttackSurface.FrontendAssetsCount)
	}
	if cr.AttackSurface.APIEndpointsCount != 2 {
		t.Errorf("expected 2 API endpoints, got %d", cr.AttackSurface.APIEndpointsCount)
	}
	if cr.AttackSurface.WebRoutesCount != 2 { // target domain (1) + /about (1)
		t.Errorf("expected 2 web routes/domain, got %d", cr.AttackSurface.WebRoutesCount)
	}

	// Check consistency in Executive Summary
	es := cr.ExecutiveSummary
	if es.AssetsDiscoveredCount != 4 || es.FrontendAssetsCount != 4 || es.APIEndpointsCount != 2 || es.WebRoutesCount != 2 {
		t.Errorf("executive summary asset counts inconsistent: discovered=%d frontend=%d api=%d routes=%d",
			es.AssetsDiscoveredCount, es.FrontendAssetsCount, es.APIEndpointsCount, es.WebRoutesCount)
	}

	// Check consistency in Assessment Scope
	as := cr.AssessmentScope
	if as.DiscoveredEndpointsCount != 4 || as.FrontendAssetsCount != 4 || as.APIEndpointsCount != 2 || as.WebRoutesCount != 2 {
		t.Errorf("assessment scope asset counts inconsistent: discovered=%d frontend=%d api=%d routes=%d",
			as.DiscoveredEndpointsCount, as.FrontendAssetsCount, as.APIEndpointsCount, as.WebRoutesCount)
	}
}

func TestCommercialReport_VerificationSummarySemantics(t *testing.T) {
	// 3 VERIFIED, 0 DETECTED, 14 OBSERVED, 6 NOT_EXPOSED, 0 NOT_VERIFIED = 23 total findings
	var findings []Finding
	for i := 0; i < 3; i++ {
		findings = append(findings, Finding{
			ID:           fmt.Sprintf("V%d", i),
			Endpoint:     fmt.Sprintf("http://target.com/verified/%d", i),
			Severity:     SeverityLow,
			Verification: VerificationRecord{Status: VerificationVerified},
		})
	}
	for i := 0; i < 14; i++ {
		findings = append(findings, Finding{
			ID:           fmt.Sprintf("O%d", i),
			Endpoint:     fmt.Sprintf("http://target.com/observed/%d", i),
			Severity:     SeverityInfo,
			Verification: VerificationRecord{Status: VerificationObserved},
		})
	}
	for i := 0; i < 6; i++ {
		findings = append(findings, Finding{
			ID:           fmt.Sprintf("NE%d", i),
			Endpoint:     fmt.Sprintf("http://target.com/defended/%d", i),
			Severity:     SeverityInfo,
			Verification: VerificationRecord{Status: VerificationNotExposed},
		})
	}

	rep := BuildReport("http://target.com", findings)
	cr := *rep.CommercialReport
	es := cr.ExecutiveSummary

	// Issue 3: Verification semantics distinction
	if es.FindingsVerifiedCount != 3 {
		t.Errorf("expected 3 verified findings, got %d", es.FindingsVerifiedCount)
	}
	if es.FindingsDetectedCount != 0 {
		t.Errorf("expected 0 detected findings, got %d", es.FindingsDetectedCount)
	}
	if es.FindingsUnverifiedCount != 0 {
		t.Errorf("expected 0 unverified findings, got %d", es.FindingsUnverifiedCount)
	}
	if es.ObservationsCount != 14 {
		t.Errorf("expected 14 observations, got %d", es.ObservationsCount)
	}
	if es.NotExposedChecksCount != 6 {
		t.Errorf("expected 6 defended/not-exposed checks, got %d", es.NotExposedChecksCount)
	}

	// Check Posture statement explicitly articulates all tiers
	if !strings.Contains(es.PostureStatement, "3 verified") ||
		!strings.Contains(es.PostureStatement, "14 observations") ||
		!strings.Contains(es.PostureStatement, "6 defended checks") {
		t.Errorf("posture statement does not articulate all verification categories: %s", es.PostureStatement)
	}
}

func TestCommercialReport_AttackPathsOmitempty(t *testing.T) {
	// Issue 4: AttackPaths schema omitempty invariant
	findings := []Finding{
		{ID: "F1", Severity: SeverityInfo, Verification: VerificationRecord{Status: VerificationObserved}},
	}
	rep := BuildReport("http://target.com", findings)
	RecalculateReportRisk(&rep)

	jsonBytes, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("failed to generate JSON: %v", err)
	}
	jsonStr := string(jsonBytes)

	// When AttackPaths is empty/nil, attack_paths key MUST be omitted from JSON
	if strings.Contains(jsonStr, `"attack_paths":`) {
		t.Errorf("expected attack_paths to be omitted via omitempty when empty, but found in JSON")
	}

	// Now attach a verified attack path and verify it appears
	path := AttackPathSummary{
		ID:                "AP-01",
		Title:             "Test Path",
		Status:            "VERIFIED",
		CombinedRiskLevel: "HIGH",
		CombinedRiskScore: 65,
		Confidence:        ConfidenceHigh,
	}
	AttachAttackPaths(&rep, []AttackPathSummary{path})

	jsonBytesWithPaths, err := GenerateJSON(rep)
	if err != nil {
		t.Fatalf("failed to generate JSON with paths: %v", err)
	}
	if !strings.Contains(string(jsonBytesWithPaths), `"attack_paths":`) {
		t.Errorf("expected attack_paths to be present when paths exist")
	}
}

func TestAssessmentStates_RiskScoreIntegrityAndPresentation(t *testing.T) {
	// 1. BLOCKED Assessment State
	t.Run("BLOCKED_State", func(t *testing.T) {
		rep := BuildReport("https://blocked-target.example.com", nil)
		rep.CompletionStatus = "BLOCKED"
		RecalculateReportRisk(&rep)

		if rep.RiskScore != 0 {
			t.Errorf("expected risk score 0 for BLOCKED state, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "UNAVAILABLE" {
			t.Errorf("expected risk level UNAVAILABLE for BLOCKED state, got %s", rep.RiskLevel)
		}
		if rep.RiskScoreAvailable {
			t.Errorf("expected RiskScoreAvailable false for BLOCKED state")
		}
		if rep.Summary.ScoreAvailable {
			t.Errorf("expected Summary.ScoreAvailable false for BLOCKED state")
		}
		if rep.CommercialReport == nil {
			t.Fatalf("expected commercial report to be built")
		}
		if rep.CommercialReport.ExecutiveSummary.CompletionStatus != "BLOCKED" {
			t.Errorf("expected CommercialReport CompletionStatus BLOCKED, got %s", rep.CommercialReport.ExecutiveSummary.CompletionStatus)
		}
		if rep.CommercialReport.ExecutiveSummary.RiskLevel != "UNAVAILABLE" {
			t.Errorf("expected CommercialReport RiskLevel UNAVAILABLE, got %s", rep.CommercialReport.ExecutiveSummary.RiskLevel)
		}
		if rep.CommercialReport.ExecutiveSummary.RiskScoreAvailable {
			t.Errorf("expected CommercialReport RiskScoreAvailable false")
		}

		// Standard HTML presentation
		htmlBytes, err := GenerateHTML(rep)
		if err != nil {
			t.Fatalf("failed to generate HTML: %v", err)
		}
		htmlStr := string(htmlBytes)
		if !strings.Contains(htmlStr, "ASSESSMENT BLOCKED") {
			t.Errorf("expected HTML report to contain ASSESSMENT BLOCKED banner")
		}
		if !strings.Contains(htmlStr, "N/A") {
			t.Errorf("expected HTML report to display N/A for risk score")
		}

		// Commercial HTML presentation
		commHTMLBytes, err := GenerateCommercialHTML(*rep.CommercialReport)
		if err != nil {
			t.Fatalf("failed to generate commercial HTML: %v", err)
		}
		commHTMLStr := string(commHTMLBytes)
		if !strings.Contains(commHTMLStr, "ASSESSMENT BLOCKED") {
			t.Errorf("expected commercial HTML report to contain ASSESSMENT BLOCKED banner")
		}
		if !strings.Contains(commHTMLStr, "N/A") {
			t.Errorf("expected commercial HTML report to display N/A for risk score")
		}
	})

	// 2. FAILED Assessment State
	t.Run("FAILED_State", func(t *testing.T) {
		rep := BuildReport("https://failed-target.example.com", nil)
		rep.CompletionStatus = "FAILED"
		RecalculateReportRisk(&rep)

		if rep.RiskScore != 0 {
			t.Errorf("expected risk score 0 for FAILED state, got %d", rep.RiskScore)
		}
		if rep.RiskLevel != "UNAVAILABLE" {
			t.Errorf("expected risk level UNAVAILABLE for FAILED state, got %s", rep.RiskLevel)
		}
		if rep.RiskScoreAvailable {
			t.Errorf("expected RiskScoreAvailable false for FAILED state")
		}

		htmlBytes, err := GenerateHTML(rep)
		if err != nil {
			t.Fatalf("failed to generate HTML: %v", err)
		}
		if !strings.Contains(string(htmlBytes), "ASSESSMENT FAILED") {
			t.Errorf("expected HTML report to contain ASSESSMENT FAILED banner")
		}
	})

	// 3. COMPLETED State with Normal Scoring
	t.Run("COMPLETED_State", func(t *testing.T) {
		findings := []Finding{
			{
				ID:          "API-01",
				Title:       "Missing CSP",
				Category:    "missing-csp",
				Severity:    SeverityLow,
				Confidence:  ConfidenceHigh,
				Score:       5,
				Verification: VerificationRecord{Status: VerificationVerified},
			},
		}
		rep := BuildReport("https://completed-target.example.com", findings)
		rep.CompletionStatus = "COMPLETED"
		RecalculateReportRisk(&rep)

		if rep.RiskScore <= 0 {
			t.Errorf("expected positive risk score for completed assessment, got %d", rep.RiskScore)
		}
		if !rep.RiskScoreAvailable {
			t.Errorf("expected RiskScoreAvailable true for completed assessment")
		}
		if rep.RiskLevel == "UNAVAILABLE" {
			t.Errorf("expected valid categorical risk level, got %s", rep.RiskLevel)
		}
	})
}
