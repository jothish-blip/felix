package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- PHASE 3.5: SHARED FRAMEWORK RESULT CLASSIFICATION TEST SUITE ---
// Tests the 24 required cross-framework consistency scenarios.

// Scenario 1: Framework header or server identification only
func TestFramework_Scenario01_RuntimeHeaderIdentificationOnly(t *testing.T) {
	cases := []struct {
		name        string
		category    string
		evidence    string
		expectedSev string
	}{
		{"Node_Express", CategoryNodeRuntimeExposure, "X-Powered-By: Express header observed", SeverityInfo},
		{"Go_Fiber", CategoryGoRuntimeExposure, "Server: Fiber header observed", SeverityInfo},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:    tc.category,
				Endpoint:    "https://example.com",
				Method:      "GET",
				HTTPStatus:  200,
				Severity:    tc.expectedSev,
				Confidence:  ConfidenceHigh,
				Description: "Runtime identification",
				Evidence:    tc.evidence,
			}
			norm := NormalizeFrameworkFinding(raw)

			if norm.ClassificationOutcome != OutcomeInformational {
				t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
			}
			if norm.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for runtime identification, got %s", norm.Severity)
			}
			if norm.Reachability != ReachabilityConfirmedReachable {
				t.Errorf("expected ReachabilityConfirmedReachable, got %s", norm.Reachability)
			}
			if norm.AuthContext != AuthContextNoChallenge {
				t.Errorf("expected AuthContextNoChallenge, got %s", norm.AuthContext)
			}
			if len(norm.Limitations) == 0 {
				t.Errorf("expected limitations to state that no diagnostic interface was disclosed")
			}
		})
	}
}

// Scenario 2: Reachable harmless diagnostic index
func TestFramework_Scenario02_ReachableHarmlessDiagnosticIndex(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryGoPprofExposure,
		Endpoint:   "https://example.com/debug/pprof/",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Evidence:   "Go net/http/pprof diagnostic profiling index observed: Types of profiles available",
		Details: map[string]string{
			"interface": "profiling_index",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeInformational {
		t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityLow && norm.Severity != SeverityInfo {
		t.Errorf("expected low/info severity for harmless index, got %s", norm.Severity)
	}
	if norm.Reachability != ReachabilityConfirmedReachable {
		t.Errorf("expected ReachabilityConfirmedReachable, got %s", norm.Reachability)
	}
	if norm.AuthContext != AuthContextNoChallenge {
		t.Errorf("expected AuthContextNoChallenge, got %s", norm.AuthContext)
	}
}

// Scenario 3: Protected endpoint returning an authentication denial
func TestFramework_Scenario03_ProtectedEndpointAuthenticationDenial(t *testing.T) {
	cases := []struct {
		name       string
		category   string
		endpoint   string
		httpStatus int
	}{
		{"Actuator_401", CategoryActuatorRestricted, "https://example.com/actuator/env", 401},
		{"Laravel_403", CategoryLaravelTelescopeProtected, "https://example.com/telescope", 403},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:   tc.category,
				Endpoint:   tc.endpoint,
				Method:     "GET",
				HTTPStatus: tc.httpStatus,
				Severity:   SeverityInfo,
				Confidence: ConfidenceHigh,
				Evidence:   fmt.Sprintf("HTTP %d access denied", tc.httpStatus),
			}
			norm := NormalizeFrameworkFinding(raw)

			if norm.ClassificationOutcome != OutcomeInformational {
				t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
			}
			if norm.Reachability != ReachabilityConfirmedInaccessible {
				t.Errorf("expected ReachabilityConfirmedInaccessible for status %d, got %s", tc.httpStatus, norm.Reachability)
			}
			if norm.AuthContext != AuthContextRequired {
				t.Errorf("expected AuthContextRequired for status %d, got %s", tc.httpStatus, norm.AuthContext)
			}
		})
	}
}

// Scenario 4: Generic HTTP 200 response with no sensitive content
func TestFramework_Scenario04_GenericHTTP200NoSensitiveContent(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryHealthExposure,
		Endpoint:   "https://example.com/health",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Evidence:   `{"status": "UP"}`,
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeInformational {
		t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo, got %s", norm.Severity)
	}
	if norm.Reachability != ReachabilityConfirmedReachable {
		t.Errorf("expected ReachabilityConfirmedReachable, got %s", norm.Reachability)
	}
	if norm.AuthContext != AuthContextNoChallenge {
		t.Errorf("expected AuthContextNoChallenge, got %s", norm.AuthContext)
	}
}

// Scenario 5: Genuine stack trace with internal paths
func TestFramework_Scenario05_GenuineStackTraceWithInternalPaths(t *testing.T) {
	cases := []struct {
		name     string
		category string
		evidence string
	}{
		{"Node_CallStack", CategoryNodeStackTrace, "TypeError: Cannot read properties of undefined\n    at UserController.getProfile (/app/src/controllers/user.js:42:15)"},
		{"Go_PanicDump", CategoryGoDebugPanic, "panic: runtime error: invalid memory address or nil pointer dereference\ngoroutine 1 [running]:\nmain.serveHTTP(0x0, 0x0)\n\t/go/src/app/main.go:88 +0x3d"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:   tc.category,
				Endpoint:   "https://example.com/api/test",
				Method:     "GET",
				HTTPStatus: 500,
				Severity:   SeverityMedium,
				Confidence: ConfidenceHigh,
				Evidence:   tc.evidence,
			}
			norm := NormalizeFrameworkFinding(raw)

			if norm.ClassificationOutcome != OutcomeConfirmed {
				t.Errorf("expected OutcomeConfirmed for genuine stack trace, got %s", norm.ClassificationOutcome)
			}
			if norm.Severity != SeverityMedium {
				t.Errorf("expected SeverityMedium, got %s", norm.Severity)
			}
			if norm.Reachability != ReachabilityConfirmedReachable {
				t.Errorf("expected ReachabilityConfirmedReachable (server responded), got %s", norm.Reachability)
			}
			// Invariant 6: Stack trace must not be marked Critical / RCE
			if norm.Severity == SeverityCritical {
				t.Errorf("CRITICAL DEFECT: stack trace must never be classified as SeverityCritical")
			}
		})
	}
}

// Scenario 6: Isolated internal path disclosure
func TestFramework_Scenario06_IsolatedInternalPathDisclosure(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryNodeDebugError,
		Endpoint:   "https://example.com/api/load",
		Method:     "GET",
		HTTPStatus: 500,
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Evidence:   "Error: Cannot find module '/app/config/database.js'",
		Details: map[string]string{
			"has_stack_trace": "false",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityLow {
		t.Errorf("expected SeverityLow for isolated path disclosure, got %s", norm.Severity)
	}
}

// Scenario 7: Actual sensitive diagnostic information
func TestFramework_Scenario07_ActualSensitiveDiagnosticInformation(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryActuatorEnv,
		Endpoint:   "https://example.com/actuator/env",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Evidence:   "Spring Boot Actuator /env exposed sensitive properties: spring.datasource.password=[REDACTED]",
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh, got %s", norm.Severity)
	}
	if norm.Reachability != ReachabilityConfirmedReachable {
		t.Errorf("expected ReachabilityConfirmedReachable, got %s", norm.Reachability)
	}
}

// Scenario 8: Routine metrics containing benign secret-like words
func TestFramework_Scenario08_RoutineMetricsWithBenignSecretLikeWords(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryGoVarsExposure,
		Endpoint:   "https://example.com/debug/vars",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityMedium,
		Confidence: ConfidenceHigh,
		Evidence:   `{"cmdline":["/usr/bin/app"],"token_bucket_rate":100,"csrf_token_header":"X-CSRF-Token"}`,
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeInformational {
		t.Errorf("expected OutcomeInformational for routine metrics, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityInfo {
		t.Errorf("routine metrics must have SeverityInfo, got %s", norm.Severity)
	}
}

// Scenario 9: Candidate secret with its value redacted
func TestFramework_Scenario09_CandidateSecretWithRedactedValue(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryFastAPISensitiveSchema,
		Endpoint:   "https://example.com/openapi.json",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityHigh,
		Confidence: ConfidenceMedium,
		Evidence:   `Discovered candidate secret: AKIAIOSFODNN7EXAMPLE in schema`,
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed, got %s", norm.ClassificationOutcome)
	}
	// Redaction check: raw canary must not leak
	if strings.Contains(norm.Evidence, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("canary secret was not redacted from evidence: %s", norm.Evidence)
	}
	if norm.Details["credential_validity"] != "unverified" {
		t.Errorf("expected credential_validity unverified, got %s", norm.Details["credential_validity"])
	}
}

// Scenario 10: Confirmed disclosure where credential validity remains unknown
func TestFramework_Scenario10_ConfirmedDisclosureCredentialValidityUnknown(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryLaravelTelescopeData,
		Endpoint:   "https://example.com/telescope/telescope-api/queries",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityHigh,
		Confidence: ConfidenceHigh,
		Evidence:   "Database query exposed authorization bearer token: [REDACTED]",
		Details: map[string]string{
			"credential_validity": "unverified",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed, got %s", norm.ClassificationOutcome)
	}
	foundValidityLim := false
	for _, lim := range norm.Limitations {
		if strings.Contains(lim, "validity") && strings.Contains(lim, "unverified") {
			foundValidityLim = true
			break
		}
	}
	if !foundValidityLim {
		t.Errorf("expected limitation stating credential validity remains unverified: %+v", norm.Limitations)
	}
}

// Scenario 11: Timeout or connection failure
func TestFramework_Scenario11_TimeoutOrConnectionFailure(t *testing.T) {
	reachTimeout := NormalizeReachability("", 0, context.DeadlineExceeded)
	if reachTimeout != ReachabilityInconclusive {
		t.Errorf("expected ReachabilityInconclusive on timeout, got %s", reachTimeout)
	}

	reachRefused := NormalizeReachability("", 0, errors.New("dial tcp 127.0.0.1:8080: connect: connection refused"))
	if reachRefused != ReachabilityConfirmedInaccessible {
		t.Errorf("expected ReachabilityConfirmedInaccessible on connection refused, got %s", reachRefused)
	}

	f := APIFinding{
		Category:     CategoryActuatorEnv,
		Endpoint:     "https://example.com/actuator/env",
		Method:       "GET",
		Reachability: reachTimeout,
		Evidence:     "Connection timed out after 10s",
	}
	norm := NormalizeFrameworkFinding(f)
	if norm.ClassificationOutcome != OutcomeInconclusive {
		t.Errorf("expected OutcomeInconclusive on transport failure, got %s", norm.ClassificationOutcome)
	}
}

// Scenario 12: Gateway-generated error or ambiguous response
func TestFramework_Scenario12_GatewayGeneratedError(t *testing.T) {
	gatewayStatuses := []int{502, 503, 504}
	for _, st := range gatewayStatuses {
		reach := NormalizeReachability("", st, nil)
		if reach != ReachabilityInconclusive {
			t.Errorf("expected ReachabilityInconclusive for gateway status %d, got %s", st, reach)
		}

		f := APIFinding{
			Category:   CategoryActuatorHealthDetailed,
			Endpoint:   "https://example.com/actuator/health",
			HTTPStatus: st,
			Evidence:   fmt.Sprintf("HTTP %d Bad Gateway returned by reverse proxy", st),
		}
		norm := NormalizeFrameworkFinding(f)
		if norm.ClassificationOutcome != OutcomeInconclusive {
			t.Errorf("expected OutcomeInconclusive for status %d, got %s", st, norm.ClassificationOutcome)
		}
	}
}

// Scenario 13: Malformed or truncated JSON
func TestFramework_Scenario13_MalformedOrTruncatedJSON(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"activeProfiles":["prod"],"propertySources":[{`) // truncated JSON
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	// Audit must not panic and must safely discard or bound malformed JSON
	findings := AuditSpringActuator(context.Background(), client, ts.URL, []string{"/actuator/env"})
	for _, f := range findings {
		if f.ClassificationOutcome == OutcomeConfirmed && f.Severity == SeverityCritical {
			t.Errorf("malformed truncated JSON must not produce Critical confirmed vulnerability")
		}
	}
}

// Scenario 14: Oversized response bounded
func TestFramework_Scenario14_OversizedResponseBounded(t *testing.T) {
	hugeEvidence := strings.Repeat("A=1&B=2&C=3\n", 1000) // ~12 KB
	f := APIFinding{
		Category:   CategoryActuatorEnv,
		Endpoint:   "https://example.com/actuator/env",
		Evidence:   hugeEvidence,
		HTTPStatus: 200,
	}
	norm := NormalizeFrameworkFinding(f)
	if len(norm.Evidence) > 4200 {
		t.Errorf("evidence exceeded maximum bounded length: len=%d", len(norm.Evidence))
	}
	if !strings.Contains(norm.Evidence, "[TRUNCATED_BOUNDED_EVIDENCE]") {
		t.Errorf("expected truncation indicator in oversized evidence")
	}
}

// Scenario 15: Conflicting or insufficient evidence
func TestFramework_Scenario15_ConflictingOrInsufficientEvidence(t *testing.T) {
	f := APIFinding{
		Category:   CategoryGoPprofExposure,
		Endpoint:   "https://example.com/debug/pprof/trace",
		HTTPStatus: 200,
		Confidence: ConfidenceLow,
		Evidence:   "Route returned 200 OK with inconclusive keywords",
		Details: map[string]string{
			"classification": "inconclusive",
		},
	}
	norm := NormalizeFrameworkFinding(f)
	if norm.ClassificationOutcome != OutcomeInconclusive {
		t.Errorf("expected OutcomeInconclusive, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo for inconclusive evidence, got %s", norm.Severity)
	}
}

// Scenario 16: Duplicate findings generated through different detector paths
func TestFramework_Scenario16_DuplicateFindingsDeduplicated(t *testing.T) {
	f1 := APIFinding{
		Category:   CategoryFastAPIDocs,
		Endpoint:   "https://example.com/docs",
		Method:     "GET",
		HTTPStatus: 200,
		Evidence:   "FastAPI docs found on /docs",
		Severity:   SeverityInfo,
	}
	f2 := APIFinding{
		Category:   CategoryFastAPIDocs,
		Endpoint:   "https://example.com/docs/",
		Method:     "GET",
		HTTPStatus: 200,
		Evidence:   "FastAPI docs found on /docs/",
		Severity:   SeverityInfo,
	}

	deduped := DeduplicateFrameworkFindings([]APIFinding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected exactly 1 deduplicated finding, got %d", len(deduped))
	}
}

// Scenario 17: Equivalent paths normalize to the same identity
func TestFramework_Scenario17_EquivalentPathsNormalizedIdentity(t *testing.T) {
	p1 := "HTTPS://example.com:443/app//actuator//health/?utm_source=email&b=2&a=1"
	p2 := "https://example.com/app/actuator/health?a=1&b=2"

	norm1 := NormalizeFrameworkEndpoint(p1)
	norm2 := NormalizeFrameworkEndpoint(p2)

	if norm1 != norm2 {
		t.Errorf("expected equivalent normalized endpoints: got %q vs %q", norm1, norm2)
	}

	fp1 := GenerateFrameworkFingerprint(CategoryActuatorHealthDetailed, p1, "GET", "spring-boot")
	fp2 := GenerateFrameworkFingerprint(CategoryActuatorHealthDetailed, p2, "get", "Spring-Boot")
	if fp1 != fp2 {
		t.Errorf("expected identical fingerprints for equivalent paths: fp1=%s, fp2=%s", fp1, fp2)
	}
}

// Scenario 18: Distinct paths or findings must not be merged
func TestFramework_Scenario18_DistinctPathsNotMerged(t *testing.T) {
	f1 := APIFinding{
		Category: CategoryActuatorHealthDetailed,
		Endpoint: "https://example.com/actuator/health",
		Method:   "GET",
	}
	f2 := APIFinding{
		Category: CategoryActuatorEnv,
		Endpoint: "https://example.com/actuator/env",
		Method:   "GET",
	}
	f3 := APIFinding{
		Category: CategoryActuatorEnv,
		Endpoint: "https://example.com/actuator/env",
		Method:   "POST",
	}

	deduped := DeduplicateFrameworkFindings([]APIFinding{f1, f2, f3})
	if len(deduped) != 3 {
		t.Errorf("expected 3 distinct findings preserved, got %d", len(deduped))
	}
}

// Scenario 19: Legacy finding with missing optional fields
func TestFramework_Scenario19_LegacyFindingMissingFields(t *testing.T) {
	raw := APIFinding{
		Category: CategoryDjangoDebugMode,
		Endpoint: "https://example.com/admin/login/",
		Evidence: "Django technical 500 debug template confirmed",
	}
	// Does not panic and cleanly sets canonical fields
	norm := NormalizeFrameworkFinding(raw)

	if norm.Framework != "Django" && norm.Framework != "django" {
		t.Errorf("expected framework Django, got %s", norm.Framework)
	}
	if norm.Method != "GET" {
		t.Errorf("expected default Method GET, got %s", norm.Method)
	}
	if norm.RuleID != "API-DJANGO-DEBUG-MODE" {
		t.Errorf("expected RuleID API-DJANGO-DEBUG-MODE, got %s", norm.RuleID)
	}
	if norm.Reachability == "" {
		t.Errorf("expected non-empty Reachability")
	}
	if norm.AuthContext == "" {
		t.Errorf("expected non-empty AuthContext")
	}
}

// Scenario 20: Repeated normalization of the same finding (Idempotence)
func TestFramework_Scenario20_NormalizationIdempotence(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryLaravelIgnitionDebug,
		Endpoint:   "https://example.com/_ignition/health-check?utm_medium=test&b=2&a=1",
		Method:     "get",
		HTTPStatus: 200,
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Evidence:   "Ignition health check: can_execute_commands is false",
	}

	pass1 := NormalizeFrameworkFinding(raw)
	pass2 := NormalizeFrameworkFinding(pass1)
	pass3 := NormalizeFrameworkFinding(pass2)

	if pass1.Fingerprint != pass2.Fingerprint || pass2.Fingerprint != pass3.Fingerprint {
		t.Errorf("non-deterministic fingerprint across passes: %s vs %s vs %s", pass1.Fingerprint, pass2.Fingerprint, pass3.Fingerprint)
	}
	if pass1.ClassificationOutcome != pass2.ClassificationOutcome {
		t.Errorf("classification mutated on repeated pass: %s vs %s", pass1.ClassificationOutcome, pass2.ClassificationOutcome)
	}
	if pass1.Endpoint != pass2.Endpoint {
		t.Errorf("endpoint mutated on repeated pass: %s vs %s", pass1.Endpoint, pass2.Endpoint)
	}
	if pass1.Severity != pass2.Severity {
		t.Errorf("severity mutated on repeated pass: %s vs %s", pass1.Severity, pass2.Severity)
	}
}

// Scenario 21: Evidence containing nested sensitive fields
func TestFramework_Scenario21_EvidenceNestedSensitiveFields(t *testing.T) {
	raw := APIFinding{
		Category: CategoryActuatorEnv,
		Endpoint: "https://example.com/actuator/env",
		Evidence: "Environment dump contains db_password=supersecret and token=eyJhbGciOi...",
		Details: map[string]string{
			"db_password":   "supersecretpassword",
			"authorization": "Bearer eyJhbGciOi...",
			"public_info":   "production_us_east",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	if strings.Contains(norm.Evidence, "supersecret") {
		t.Errorf("secret leaked in evidence: %s", norm.Evidence)
	}
	if norm.Details["db_password"] != "[REDACTED]" {
		t.Errorf("expected db_password to be [REDACTED], got %s", norm.Details["db_password"])
	}
	if norm.Details["authorization"] != "[REDACTED]" {
		t.Errorf("expected authorization to be [REDACTED], got %s", norm.Details["authorization"])
	}
	if norm.Details["public_info"] != "production_us_east" {
		t.Errorf("expected non-sensitive details preserved, got %s", norm.Details["public_info"])
	}
}

// Scenario 22: Unknown authentication context
func TestFramework_Scenario22_UnknownAuthenticationContext(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryEndpointDiscovered,
		Endpoint:   "https://example.com/api/v1/orders",
		HTTPStatus: 0,
		AuthState:  AuthStateUnknown,
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.AuthContext != AuthContextUnknown {
		t.Errorf("expected AuthContextUnknown for unprobed endpoint, got %s", norm.AuthContext)
	}
	if norm.Reachability != ReachabilityUnknown {
		t.Errorf("expected ReachabilityUnknown for unprobed endpoint, got %s", norm.Reachability)
	}
}

// Scenario 23: Benign endpoint name that resembles a sensitive route
func TestFramework_Scenario23_BenignRouteResemblingSensitivePath(t *testing.T) {
	raw := APIFinding{
		Category:   CategoryFastAPISensitivePaths,
		Endpoint:   "https://example.com/openapi.json",
		HTTPStatus: 200,
		Severity:   SeverityInfo,
		Confidence: ConfidenceLow,
		Evidence:   "OpenAPI schema declared route: /api/admin/system-status",
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeInformational {
		t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo (route name alone is not a vulnerability), got %s", norm.Severity)
	}
}

// Scenario 24: Response where status code and body provide different levels of evidence
func TestFramework_Scenario24_StatusAndBodyDifferentEvidenceLevels(t *testing.T) {
	// 500 error returned, but body is generic HTML with no traceback or debug templates
	raw := APIFinding{
		Category:   CategoryDjangoDebugMode,
		Endpoint:   "https://example.com/api/test",
		HTTPStatus: 500,
		Confidence: ConfidenceLow,
		Severity:   SeverityInfo,
		Evidence:   "Server returned HTTP 500 Internal Server Error without diagnostic traceback",
		Details: map[string]string{
			"classification": "inconclusive",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	// Invariant 4: Status code 500 alone does not establish debug mode exposure
	if norm.ClassificationOutcome == OutcomeConfirmed {
		t.Errorf("CRITICAL DEFECT: HTTP 500 without debug evidence must never be OutcomeConfirmed")
	}
	if norm.ClassificationOutcome != OutcomeInconclusive {
		t.Errorf("expected OutcomeInconclusive for 500 error with no diagnostic markers, got %s", norm.ClassificationOutcome)
	}
}

// ============================================================================
// PHASE 3.5 FINAL CONSISTENCY REGRESSION TESTS
// ============================================================================

// Regression Test 1: Harmless expvar metrics must be OutcomeInformational and SeverityInfo (never Medium/High/Critical)
func TestFramework_Regression_HarmlessExpvarMetrics(t *testing.T) {
	testCases := []struct {
		name        string
		rawSeverity string
		body        string
	}{
		{
			name:        "Benign metrics with default SeverityInfo",
			rawSeverity: SeverityInfo,
			body:        `{"cmdline":["/usr/bin/app"],"memstats":{"Alloc":4096,"TotalAlloc":8192}}`,
		},
		{
			name:        "Benign metrics where detector initially passed SeverityMedium",
			rawSeverity: SeverityMedium,
			body:        `{"cmdline":["/usr/bin/service","-port=8080"],"goroutines":45,"memstats":{"Alloc":1024}}`,
		},
		{
			name:        "Benign metrics containing false-positive keywords",
			rawSeverity: SeverityMedium,
			body:        `{"token_bucket_rate":500,"csrf_token_header":"X-CSRF-Token","auth_mode":"bearer"}`,
		},
		{
			name:        "Benign metrics with improperly inflated SeverityHigh",
			rawSeverity: SeverityHigh,
			body:        `{"cmdline":["app"],"uptime_seconds":86400}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:   CategoryGoVarsExposure,
				Endpoint:   "https://example.com/debug/vars",
				Method:     "GET",
				HTTPStatus: 200,
				Severity:   tc.rawSeverity,
				Confidence: ConfidenceHigh,
				Evidence:   tc.body,
			}
			norm := NormalizeFrameworkFinding(raw)

			if norm.ClassificationOutcome != OutcomeInformational {
				t.Errorf("expected OutcomeInformational, got %s", norm.ClassificationOutcome)
			}
			// Invariant: Informational findings must NOT retain vulnerability severity (Medium, High, Critical)
			if norm.Severity != SeverityInfo {
				t.Errorf("expected SeverityInfo for harmless expvar metrics, got %s (must not retain Medium/High/Critical)", norm.Severity)
			}
			if norm.Reachability != ReachabilityConfirmedReachable {
				t.Errorf("expected ReachabilityConfirmedReachable, got %s", norm.Reachability)
			}
			if norm.AuthContext != AuthContextNoChallenge {
				t.Errorf("expected AuthContextNoChallenge, got %s", norm.AuthContext)
			}
		})
	}
}

// Regression Test 2: Framework identification only must be OutcomeInformational and SeverityInfo
func TestFramework_Regression_FrameworkIdentificationOnly(t *testing.T) {
	cases := []struct {
		name     string
		category string
		evidence string
		details  map[string]string
	}{
		{
			name:     "Node runtime Express header",
			category: CategoryNodeRuntimeExposure,
			evidence: "X-Powered-By: Express",
			details:  map[string]string{"framework": "Express"},
		},
		{
			name:     "Go runtime server header",
			category: CategoryGoRuntimeExposure,
			evidence: "Server: Go-http-server/1.22",
			details:  map[string]string{"framework": "Go"},
		},
		{
			name:     "FastAPI docs exposure without sensitive routes",
			category: CategoryFastAPIDocs,
			evidence: "OpenAPI 3.0.0 documentation interface discovered at /docs",
			details:  map[string]string{"interface": "interactive_api_docs"},
		},
		{
			name:     "Django browsable API shell",
			category: CategoryDjangoBrowsableAPI,
			evidence: "Django REST Framework browsable API rendered at /api/",
			details:  map[string]string{"interface": "browsable_api"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Even if raw finding was inadvertently marked Medium or High
			for _, testSev := range []string{SeverityInfo, SeverityMedium, SeverityHigh} {
				raw := APIFinding{
					Category:   tc.category,
					Endpoint:   "https://example.com/api",
					Method:     "GET",
					HTTPStatus: 200,
					Severity:   testSev,
					Confidence: ConfidenceHigh,
					Evidence:   tc.evidence,
					Details:    tc.details,
				}
				norm := NormalizeFrameworkFinding(raw)

				if norm.ClassificationOutcome != OutcomeInformational {
					t.Errorf("expected OutcomeInformational for %s (sev=%s), got %s", tc.name, testSev, norm.ClassificationOutcome)
				}
				if norm.Severity != SeverityInfo {
					t.Errorf("expected SeverityInfo for %s (sev=%s), got %s", tc.name, testSev, norm.Severity)
				}
			}
		})
	}
}

// Regression Test 3: Genuine sensitive-data disclosures must preserve Medium/High severity and be OutcomeConfirmed
func TestFramework_Regression_GenuineSensitiveDataDisclosures(t *testing.T) {
	cases := []struct {
		name             string
		category         string
		expectedSeverity string
		evidence         string
		details          map[string]string
	}{
		{
			name:             "Spring Boot Actuator /env sensitive properties",
			category:         CategoryActuatorEnv,
			expectedSeverity: SeverityHigh,
			evidence:         "Spring Boot Actuator /env exposed sensitive properties: spring.datasource.password=[REDACTED]",
			details:          map[string]string{"unmasked_count": "3"},
		},
		{
			name:             "Laravel Telescope sensitive telemetry entries",
			category:         CategoryLaravelTelescopeData,
			expectedSeverity: SeverityHigh,
			evidence:         "Laravel Telescope telemetry exposed 15 SQL query entries and request payload: password=[REDACTED]",
			details:          map[string]string{"entries_count": "15"},
		},
		{
			name:             "Django technical 500 debug mode confirmed",
			category:         CategoryDjangoDebugMode,
			expectedSeverity: SeverityHigh,
			evidence:         "Django technical 500 debug page confirmed (DEBUG=True). Developer traceback and settings exposed.",
			details:          map[string]string{"template": "technical_500"},
		},
		{
			name:             "Node.js runtime stack trace with internal frames",
			category:         CategoryNodeStackTrace,
			expectedSeverity: SeverityMedium,
			evidence:         "TypeError: Cannot read properties of undefined at authenticate (/app/src/auth.js:42:15)",
			details:          map[string]string{"has_stack_trace": "true"},
		},
		{
			name:             "Go panic dump disclosing goroutine trace",
			category:         CategoryGoDebugPanic,
			expectedSeverity: SeverityMedium,
			evidence:         "panic: runtime error: invalid memory address or nil pointer dereference\ngoroutine 1 [running]:\nmain.handleRequest(0x0, 0x0)",
			details:          map[string]string{"has_panic_dump": "true"},
		},
		{
			name:             "Spring Boot Actuator route mappings exposure",
			category:         CategoryActuatorMappings,
			expectedSeverity: SeverityMedium,
			evidence:         "Spring Boot Actuator /mappings exposed 42 application endpoint mappings",
			details:          map[string]string{"mappings_count": "42"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:   tc.category,
				Endpoint:   "https://example.com/sensitive",
				Method:     "GET",
				HTTPStatus: 200,
				Severity:   tc.expectedSeverity,
				Confidence: ConfidenceHigh,
				Evidence:   tc.evidence,
				Details:    tc.details,
			}
			norm := NormalizeFrameworkFinding(raw)

			if norm.ClassificationOutcome != OutcomeConfirmed {
				t.Errorf("expected OutcomeConfirmed for genuine disclosure %s, got %s", tc.name, norm.ClassificationOutcome)
			}
			if norm.Severity != tc.expectedSeverity {
				t.Errorf("CRITICAL DEFECT: genuine disclosure %s downgraded from %s to %s", tc.name, tc.expectedSeverity, norm.Severity)
			}
			if norm.Severity == SeverityInfo {
				t.Errorf("CRITICAL DEFECT: genuine security disclosure must never be downgraded to SeverityInfo")
			}
		})
	}
}

// Regression Test 4: Candidate secrets with unverified validity and redacted values
func TestFramework_Regression_CandidateSecretsWithUnverifiedValidity(t *testing.T) {
	cases := []struct {
		name             string
		category         string
		initialSeverity  string
		evidence         string
		details          map[string]string
		expectedSeverity string
	}{
		{
			name:             "FastAPI OpenAPI schema with embedded candidate secret",
			category:         CategoryFastAPISensitiveSchema,
			initialSeverity:  SeverityHigh,
			evidence:         "FastAPI schema exposed candidate secret: AKIAIOSFODNN7EXAMPLE",
			details:          map[string]string{"key_name": "aws_access_key_id"},
			expectedSeverity: SeverityHigh,
		},
		{
			name:             "Go expvar with candidate secret",
			category:         CategoryGoVarsExposure,
			initialSeverity:  SeverityCritical,
			evidence:         `HTTP 200 OK. Candidate secret material observed: [database_password] (active validity was not verified; values redacted).`,
			details: map[string]string{
				"candidate_material_status": "unverified_candidate_material",
				"unmasked_secrets_count":    "1",
			},
			expectedSeverity: SeverityCritical,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := APIFinding{
				Category:   tc.category,
				Endpoint:   "https://example.com/target",
				Method:     "GET",
				HTTPStatus: 200,
				Severity:   tc.initialSeverity,
				Confidence: ConfidenceHigh,
				Evidence:   tc.evidence,
				Details:    tc.details,
			}
			norm := NormalizeFrameworkFinding(raw)

			// Classification must reflect genuine security risk (Confirmed outcome)
			if norm.ClassificationOutcome != OutcomeConfirmed {
				t.Errorf("expected OutcomeConfirmed for candidate secrets, got %s", norm.ClassificationOutcome)
			}
			// Severity must be preserved (High or Critical)
			if norm.Severity != tc.expectedSeverity {
				t.Errorf("expected severity %s, got %s", tc.expectedSeverity, norm.Severity)
			}
			// Invariant 5: Candidate credential validity must explicitly be "unverified"
			if norm.Details["credential_validity"] != "unverified" {
				t.Errorf("expected Details[credential_validity] == 'unverified', got %q", norm.Details["credential_validity"])
			}
			// Limitations must document unverified credential validity
			var hasValidityLimitation bool
			for _, lim := range norm.Limitations {
				if strings.Contains(strings.ToLower(lim), "unverified") || strings.Contains(strings.ToLower(lim), "validity") {
					hasValidityLimitation = true
					break
				}
			}
			if !hasValidityLimitation {
				t.Errorf("expected limitation stating candidate credential validity is unverified, got: %v", norm.Limitations)
			}
		})
	}
}

// Scenario 27: Diagnostic response that exposes sensitive data despite an unusual status code (e.g. HTTP 503 or 500)
func TestFramework_Scenario27_SensitiveDiagnosticExposureWithUnusualStatus(t *testing.T) {
	// Spring Boot Actuator /health returning HTTP 503 because a subsystem is DOWN,
	// but exposing detailed component infrastructure telemetry
	raw := APIFinding{
		Category:   CategoryActuatorHealthDetailed,
		Endpoint:   "https://example.com/actuator/health",
		Method:     "GET",
		HTTPStatus: 503,
		AuthState:  AuthStatePublic,
		Severity:   SeverityLow,
		Confidence: ConfidenceHigh,
		Evidence:   "HTTP 503. Spring Boot Actuator /health exposes detailed internal component telemetry. Status: DOWN. Components: [db, redis, diskSpace].",
		Details: map[string]string{
			"framework":       "Spring Boot",
			"health_status":   "DOWN",
			"component_count": "3",
			"components":      "db, redis, diskSpace",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	if norm.ClassificationOutcome != OutcomeConfirmed {
		t.Errorf("expected OutcomeConfirmed for genuine telemetry despite HTTP 503, got %s", norm.ClassificationOutcome)
	}
	if norm.Reachability != ReachabilityConfirmedReachable {
		t.Errorf("expected ReachabilityConfirmedReachable (endpoint actively responded), got %s", norm.Reachability)
	}
	if norm.Framework != "Spring Boot" {
		t.Errorf("expected framework Spring Boot, got %s", norm.Framework)
	}
}

// Scenario 28: Framework identification that is ambiguous or conflicts with a gateway header
func TestFramework_Scenario28_AmbiguousOrConflictingGatewayHeaders(t *testing.T) {
	// Gateway header (e.g. Cloudflare / Envoy) present along with backend Express header
	raw := APIFinding{
		Category:   CategoryNodeRuntimeExposure,
		Endpoint:   "https://example.com/api",
		Method:     "GET",
		HTTPStatus: 200,
		Severity:   SeverityInfo,
		Confidence: ConfidenceHigh,
		Evidence:   "Server: cloudflare\nX-Powered-By: Express",
		Details: map[string]string{
			"framework":      "Express",
			"gateway_header": "cloudflare",
		},
	}
	norm := NormalizeFrameworkFinding(raw)

	// Framework identification must remain informational
	if norm.ClassificationOutcome != OutcomeInformational {
		t.Errorf("expected OutcomeInformational for framework header behind gateway, got %s", norm.ClassificationOutcome)
	}
	if norm.Severity != SeverityInfo {
		t.Errorf("expected SeverityInfo, got %s", norm.Severity)
	}
	if norm.Framework != "Express" {
		t.Errorf("expected backend framework Express to be identified, got %s", norm.Framework)
	}
}
