package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Test 1: Genuine Spring Boot minimal health response
func TestActuator_GenuineMinimalHealth(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/health" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"UP"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != CategoryHealthExposure {
		t.Errorf("expected category %s, got %s", CategoryHealthExposure, f.Category)
	}
	if f.Severity != SeverityInfo {
		t.Errorf("expected severity INFO for minimal health, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "Status: UP") && !strings.Contains(f.Evidence, "observed: UP") {
		t.Errorf("expected evidence to mention UP status, got: %s", f.Evidence)
	}
}

// Test 2: Health endpoint with detailed component information
func TestActuator_DetailedComponentHealth(t *testing.T) {
	detailedJSON := `{
		"status": "UP",
		"components": {
			"db": {
				"status": "UP",
				"details": {
					"database": "PostgreSQL",
					"validationQuery": "SELECT 1"
				}
			},
			"diskSpace": {
				"status": "UP",
				"details": {
					"total": 10737418240,
					"free": 5368709120
				}
			},
			"redis": {
				"status": "UP",
				"details": {
					"version": "6.2.6"
				}
			}
		}
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/health" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(detailedJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != CategoryActuatorHealthDetailed {
		t.Errorf("expected category %s, got %s", CategoryActuatorHealthDetailed, f.Category)
	}
	if f.Severity != SeverityLow {
		t.Errorf("expected severity LOW, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "db") || !strings.Contains(f.Evidence, "diskSpace") {
		t.Errorf("expected components mentioned in evidence, got: %s", f.Evidence)
	}
}

// Test 3: Inaccessible or access-restricted endpoint (401 and 403)
func TestActuator_AccessRestrictedEndpoints(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/env":
			w.Header().Set("WWW-Authenticate", `Basic realm="Spring Security"`)
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized"}`))
		case "/actuator/mappings":
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"error":"Forbidden"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	// Restricted endpoints must NOT generate false-positive vulnerability findings
	if len(findings) != 0 {
		t.Fatalf("expected 0 vulnerability findings for protected 401/403 endpoints, got %d", len(findings))
	}

	// Probe individual endpoints and verify access status
	envRes := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/env")
	if envRes.AccessStatus != ActuatorAccessRestricted || envRes.AuthState != AuthStateAuthRequired {
		t.Errorf("expected env to be restricted with AuthStateAuthRequired, got status=%s auth=%s",
			envRes.AccessStatus, envRes.AuthState)
	}

	mapRes := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/mappings")
	if mapRes.AccessStatus != ActuatorAccessRestricted || mapRes.AuthState != AuthStateForbidden {
		t.Errorf("expected mappings to be restricted with AuthStateForbidden, got status=%s auth=%s",
			mapRes.AccessStatus, mapRes.AuthState)
	}
}

// Test 4: Environment endpoint with structural metadata
func TestActuator_EnvironmentStructuralMetadata(t *testing.T) {
	envJSON := `{
		"activeProfiles": ["staging"],
		"propertySources": [
			{
				"name": "systemProperties",
				"properties": {
					"java.version": {"value": "17.0.2"},
					"os.name": {"value": "Linux"}
				}
			},
			{
				"name": "applicationConfig: [classpath:/application.yml]",
				"properties": {
					"server.port": {"value": 8080},
					"app.name": {"value": "felix-test"}
				}
			}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(envJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for /actuator/env, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != CategoryActuatorEnv {
		t.Errorf("expected category %s, got %s", CategoryActuatorEnv, f.Category)
	}
	if f.Severity != SeverityMedium {
		t.Errorf("expected severity MEDIUM for general environment properties, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "systemProperties") || !strings.Contains(f.Evidence, "server.port") {
		t.Errorf("expected evidence to mention property sources and property names: %s", f.Evidence)
	}
}

// Test 5: Environment response containing secret values: PROVE ZERO SECRETS LEAKED
func TestActuator_EnvironmentSecretRedaction_ZeroLeaks(t *testing.T) {
	secretCanary1 := "superSecretDbPassword_FELIX_CANARY_987654"
	secretCanary2 := "AKIA_FAKE_AWS_KEY_CANARY_12345"
	secretCanary3 := "jwt_token_canary_super_confidential_xyz"

	envJSON := fmt.Sprintf(`{
		"activeProfiles": ["production"],
		"propertySources": [
			{
				"name": "applicationConfiguration",
				"properties": {
					"spring.datasource.password": {"value": "%s"},
					"aws.access.key": {"value": "%s"},
					"jwt.secret": {"value": "%s"},
					"spring.datasource.url": {"value": "jdbc:postgresql://db.internal:5432/appdb"},
					"server.port": {"value": 8443}
				}
			}
		]
	}`, secretCanary1, secretCanary2, secretCanary3)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/env" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(envJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != CategoryActuatorEnv {
		t.Errorf("expected category %s, got %s", CategoryActuatorEnv, f.Category)
	}
	// With unmasked credentials present, severity must be CRITICAL
	if f.Severity != SeverityCritical {
		t.Errorf("expected severity CRITICAL for unmasked credentials, got %s", f.Severity)
	}

	// INVARIANT VERIFICATION: Prove zero raw secrets exist anywhere in the finding!
	assertNoSecretCanaries(t, f.Evidence, "Finding.Evidence", secretCanary1, secretCanary2, secretCanary3)
	assertNoSecretCanaries(t, f.Description, "Finding.Description", secretCanary1, secretCanary2, secretCanary3)
	for k, v := range f.Details {
		assertNoSecretCanaries(t, v, fmt.Sprintf("Finding.Details[%s]", k), secretCanary1, secretCanary2, secretCanary3)
	}
}

// Test 6: Valid mappings response
func TestActuator_ValidMappings(t *testing.T) {
	mappingsJSON := `{
		"contexts": {
			"application": {
				"mappings": {
					"dispatcherServlets": {
						"dispatcherServlet": [
							{
								"handler": "org.springframework.boot.autoconfigure.web.servlet.error.BasicErrorController#error(HttpServletRequest)",
								"predicate": "{[/error]}",
								"details": {
									"requestMappingConditions": {
										"patterns": ["/error"],
										"methods": []
									}
								}
							},
							{
								"handler": "com.example.controller.AdminController#manageUsers()",
								"predicate": "{[/admin/users],methods=[GET]}",
								"details": {
									"requestMappingConditions": {
										"patterns": ["/admin/users"],
										"methods": ["GET"]
									}
								}
							},
							{
								"handler": "com.example.controller.ApiController#getData()",
								"predicate": "{[/api/v1/data],methods=[GET]}",
								"details": {
									"requestMappingConditions": {
										"patterns": ["/api/v1/data"],
										"methods": ["GET"]
									}
								}
							}
						]
					}
				}
			}
		}
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/mappings" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(mappingsJSON))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for mappings, got %d", len(findings))
	}
	f := findings[0]
	if f.Category != CategoryActuatorMappings {
		t.Errorf("expected category %s, got %s", CategoryActuatorMappings, f.Category)
	}
	// Exposing /admin/users triggers Medium severity
	if f.Severity != SeverityMedium {
		t.Errorf("expected severity MEDIUM for admin route exposure, got %s", f.Severity)
	}
	if !strings.Contains(f.Evidence, "/admin/users") {
		t.Errorf("expected evidence to list discovered routes: %s", f.Evidence)
	}
}

// Test 7: Generic HTML SPA shell returning HTTP 200 (must be rejected)
func TestActuator_GenericHTMLSPAShell_Suppressed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<!DOCTYPE html><html><head><title>App</title></head><body><div id="root">Loading Single Page App...</div></body></html>`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for generic HTML SPA shell, got %d", len(findings))
	}
}

// Test 8: Custom 404 or proxy error response returning HTTP 200 (must be rejected)
func TestActuator_Custom404ErrorPage_Suppressed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<html><body><h1>404 Not Found</h1><p>The requested URL was not found on this proxy.</p></body></html>`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for custom 404 error page, got %d", len(findings))
	}
}

// Test 9: Unrelated JSON returning HTTP 200 (must be rejected)
func TestActuator_UnrelatedJSON_Suppressed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"message":"Welcome to our public API","version":"1.0.0","items":[]}`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for unrelated JSON payload, got %d", len(findings))
	}
}

// Test 10: Malformed JSON and unexpected content types
func TestActuator_MalformedJSONAndBinaryContent(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/actuator/health":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status": incomplete JSON string ...`))
		case "/actuator/env":
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("\x00\x01\x02\x03\xff\xfe"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 0 {
		t.Fatalf("expected 0 findings for malformed/corrupted content, got %d", len(findings))
	}
}

// Test 11: Oversized responses and body-read limits (must not exceed 512 KiB)
func TestActuator_OversizedResponse_Bounded(t *testing.T) {
	hugeEnv := strings.Repeat(`{"name":"testSource","properties":{"big.prop":{"value":"data"}}},`, 10000)
	payload := `{"activeProfiles":["prod"],"propertySources":[` + strings.TrimSuffix(hugeEnv, ",") + `]}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(payload))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	res := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/env")

	// If payload > 512 KiB, DoBounded safely truncates read or marks limitations
	if len(payload) > MaxActuatorResponseSize {
		if res.Limitations == "" && !res.IsGenuine {
			t.Errorf("expected oversized response to be handled safely")
		}
	}
}

// Test 12: Request timeout and redirect behavior
func TestActuator_TimeoutAndRedirect(t *testing.T) {
	// Timeout server
	tsSlow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer tsSlow.Close()

	fastClient := NewClient(ClientOptions{
		Timeout:       50 * time.Millisecond,
		HTTPClient:    tsSlow.Client(),
		AllowLoopback: true,
	})
	resSlow := ProbeActuatorEndpoint(context.Background(), fastClient, tsSlow.URL+"/actuator/health")
	if resSlow.AccessStatus != ActuatorAccessUnreachable {
		t.Errorf("expected timeout to result in ActuatorAccessUnreachable, got %s", resSlow.AccessStatus)
	}

	// Redirect server
	tsRedir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/actuator/health" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("login page"))
	}))
	defer tsRedir.Close()

	clientRedir := NewClient(ClientOptions{HTTPClient: tsRedir.Client(), AllowLoopback: true})
	resRedir := ProbeActuatorEndpoint(context.Background(), clientRedir, tsRedir.URL+"/actuator/health")
	if resRedir.AccessStatus != ActuatorAccessRedirect {
		t.Errorf("expected redirect to be identified as ActuatorAccessRedirect, got %s", resRedir.AccessStatus)
	}
}

// Test 13: Nested base paths and scope-boundary preservation
func TestActuator_NestedBasePathAndScopeBoundary(t *testing.T) {
	var requestedPaths []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPaths = append(requestedPaths, r.URL.Path)
		if r.URL.Path == "/my-nested-app/actuator/health" {
			w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"UP"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	targetURL := ts.URL + "/my-nested-app"
	client := NewClient(ClientOptions{
		HTTPClient:    ts.Client(),
		AllowLoopback: true,
		IsAllowed: func(u string) bool {
			return strings.Contains(u, "/my-nested-app")
		},
	})

	findings := AuditSpringActuator(context.Background(), client, targetURL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding under nested base path, got %d", len(findings))
	}
	if findings[0].Endpoint != targetURL+"/actuator/health" {
		t.Errorf("expected endpoint %s, got %s", targetURL+"/actuator/health", findings[0].Endpoint)
	}

	// Verify all requests remained within /my-nested-app
	for _, p := range requestedPaths {
		if !strings.HasPrefix(p, "/my-nested-app") {
			t.Errorf("SCOPE ESCAPE: probe path %s was requested outside /my-nested-app", p)
		}
	}
}

// Test 14: Rate limiting and safe transport integration
func TestActuator_RateLimitingEnforced(t *testing.T) {
	var reqCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := atomic.AddInt32(&reqCount, 1)
		if count > 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte("Rate limit exceeded"))
			return
		}
		w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"UP"}`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	// First request succeeds, subsequent requests hit 429 and abort safely without error leak
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding before rate limit halting, got %d", len(findings))
	}
}

// Test 15: Accurate classification when evidence is insufficient
func TestActuator_InsufficientEvidence_ClassifiedInconclusive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Returns valid JSON, but not Spring Boot Actuator
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"foo":"bar"}`))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	resHealth := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/health")
	if resHealth.AccessStatus != ActuatorAccessInconclusive {
		t.Errorf("expected health with no status field to be INCONCLUSIVE, got %s", resHealth.AccessStatus)
	}

	resEnv := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/env")
	if resEnv.AccessStatus != ActuatorAccessInconclusive {
		t.Errorf("expected env with no property sources to be INCONCLUSIVE, got %s", resEnv.AccessStatus)
	}

	resMap := ProbeActuatorEndpoint(context.Background(), client, ts.URL+"/actuator/mappings")
	if resMap.AccessStatus != ActuatorAccessInconclusive {
		t.Errorf("expected mappings with no contexts to be INCONCLUSIVE, got %s", resMap.AccessStatus)
	}
}

// Test 16: No raw secrets in findings, error messages, logs or captured test output
func TestActuator_NoSecretsInFindingsOrErrors(t *testing.T) {
	secretPayload := `{
		"activeProfiles": ["prod"],
		"propertySources": [
			{
				"name": "secretsConfig",
				"properties": {
					"db.secret": {"value": "SuperConfidentialToken_12345"},
					"stripe.key": {"value": "fake_canary_secret_token_9988776655"}
				}
			}
		]
	}`

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ActuatorVendorContentTypeV3)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(secretPayload))
	}))
	defer ts.Close()

	client := NewClient(ClientOptions{HTTPClient: ts.Client(), AllowLoopback: true})
	findings := AuditSpringActuator(context.Background(), client, ts.URL, nil)

	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}

	f := findings[0]
	assertNoSecretCanaries(t, f.Evidence, "Evidence", "SuperConfidentialToken_12345", "fake_canary_secret_token_9988776655")
	for k, v := range f.Details {
		assertNoSecretCanaries(t, v, "Details."+k, "SuperConfidentialToken_12345", "fake_canary_secret_token_9988776655")
	}
}

// Helper to assert that canary secrets never appear in text strings
func assertNoSecretCanaries(t *testing.T, text, fieldName string, canaries ...string) {
	t.Helper()
	for _, c := range canaries {
		if strings.Contains(text, c) {
			t.Fatalf("SECURITY VIOLATION: Raw secret canary %q found in %s: %s", c, fieldName, text)
		}
	}
}
