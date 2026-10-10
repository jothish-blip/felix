package report

import (
	"encoding/json"
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
