package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"felix/pkg/api"
)

// Helper to construct a representative set of API findings covering all 6 supported backend frameworks:
// Spring Boot, Django, FastAPI, Laravel, Node.js, and Go.
func createTestFrameworkFindings() []Finding {
	target := "https://api.example.com"
	now := time.Now().UTC()

	var findings []Finding

	// 1. Spring Boot: Actuator env exposure (High Confirmed Vulnerability)
	apiSpringEnv := api.APIFinding{
		Category:         api.CategoryActuatorEnv,
		Endpoint:         "https://api.example.com/actuator/env",
		Method:           "GET",
		Description:      "Spring Boot Actuator environment endpoint exposed configuration properties",
		Evidence:         `{"activeProfiles":["production"],"propertySources":[{"name":"systemEnvironment","properties":{"SECRET_KEY":{"value":"******"}}}]}`,
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryActuatorEnv, "https://api.example.com/actuator/env", "GET"),
		HTTPStatus:       200,
		Framework:        "Spring Boot",
		FrameworkVersion: "3.2.0",
		Details: map[string]string{
			"framework":         "Spring Boot",
			"framework_version": "3.2.0",
		},
	}
	fSpringEnv := FromAPIFinding(target, apiSpringEnv)
	fSpringEnv.Timestamp = now
	findings = append(findings, fSpringEnv)

	// 2. Spring Boot: Actuator endpoint restricted / protected (Not Exposed)
	apiSpringRestricted := api.APIFinding{
		Category:         api.CategoryActuatorRestricted,
		Endpoint:         "https://api.example.com/actuator/heapdump",
		Method:           "GET",
		Description:      "Spring Boot Actuator endpoint protected by authentication controls (HTTP 401)",
		Evidence:         "HTTP/1.1 401 Unauthorized\nWWW-Authenticate: Basic realm=\"Actuator\"",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryActuatorRestricted, "https://api.example.com/actuator/heapdump", "GET"),
		HTTPStatus:       401,
		Framework:        "Spring Boot",
		FrameworkVersion: "3.2.0",
		Details: map[string]string{
			"framework":         "Spring Boot",
			"framework_version": "3.2.0",
		},
	}
	fSpringRestricted := FromAPIFinding(target, apiSpringRestricted)
	fSpringRestricted.Timestamp = now
	findings = append(findings, fSpringRestricted)

	// 3. Django: Debug Mode Active (High Confirmed Vulnerability)
	apiDjangoDebug := api.APIFinding{
		Category:         api.CategoryDjangoDebugMode,
		Endpoint:         "https://api.example.com/admin/login/",
		Method:           "GET",
		Description:      "Django technical 500 debug page confirmed (DEBUG=True confirmed). Detailed traceback exposed.",
		Evidence:         "Django Version: 4.2.7\nException Value: Server Misconfiguration\nRequest information and settings exposed.",
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryDjangoDebugMode, "https://api.example.com/admin/login/", "GET"),
		HTTPStatus:       500,
		Framework:        "Django",
		FrameworkVersion: "4.2.7",
		Details: map[string]string{
			"framework":         "Django",
			"framework_version": "4.2.7",
		},
	}
	fDjangoDebug := FromAPIFinding(target, apiDjangoDebug)
	fDjangoDebug.Timestamp = now
	findings = append(findings, fDjangoDebug)

	// 4. Django: DRF Browsable API (Informational Observation)
	apiDjangoDRF := api.APIFinding{
		Category:         api.CategoryDjangoBrowsableAPI,
		Endpoint:         "https://api.example.com/api/v1/orders/",
		Method:           "GET",
		Description:      "Django REST Framework browsable API interface is publicly accessible.",
		Evidence:         "Django REST Framework interactive HTML renderer detected",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryDjangoBrowsableAPI, "https://api.example.com/api/v1/orders/", "GET"),
		HTTPStatus:       200,
		Framework:        "Django",
		FrameworkVersion: "4.2.7",
		Details: map[string]string{
			"framework":         "Django",
			"framework_version": "4.2.7",
		},
	}
	fDjangoDRF := FromAPIFinding(target, apiDjangoDRF)
	fDjangoDRF.Timestamp = now
	findings = append(findings, fDjangoDRF)

	// 5. FastAPI: OpenAPI Documentation Exposure (Informational Observation)
	apiFastAPIDocs := api.APIFinding{
		Category:         api.CategoryFastAPIDocs,
		Endpoint:         "https://api.example.com/docs",
		Method:           "GET",
		Description:      "Public FastAPI / Swagger interactive API documentation discovered and accessible.",
		Evidence:         "SwaggerUI bundle loaded from /docs with OpenAPI 3.0.2 schema reference",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryFastAPIDocs, "https://api.example.com/docs", "GET"),
		HTTPStatus:       200,
		Framework:        "FastAPI",
		FrameworkVersion: "0.104.1",
		Details: map[string]string{
			"framework":         "FastAPI",
			"framework_version": "0.104.1",
		},
	}
	fFastAPIDocs := FromAPIFinding(target, apiFastAPIDocs)
	fFastAPIDocs.Timestamp = now
	findings = append(findings, fFastAPIDocs)

	// 6. FastAPI: Sensitive Schema in OpenAPI Definition (High Confirmed Vulnerability)
	apiFastAPISchema := api.APIFinding{
		Category:         api.CategoryFastAPISensitiveSchema,
		Endpoint:         "https://api.example.com/openapi.json",
		Method:           "GET",
		Description:      "FastAPI OpenAPI specification contains embedded credentials, tokens, or sensitive default values.",
		Evidence:         "components.securitySchemes contains hardcoded master key default: [REDACTED_API_KEY]",
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryFastAPISensitiveSchema, "https://api.example.com/openapi.json", "GET"),
		HTTPStatus:       200,
		Framework:        "FastAPI",
		FrameworkVersion: "0.104.1",
		Details: map[string]string{
			"framework":         "FastAPI",
			"framework_version": "0.104.1",
		},
	}
	fFastAPISchema := FromAPIFinding(target, apiFastAPISchema)
	fFastAPISchema.Timestamp = now
	findings = append(findings, fFastAPISchema)

	// 7. Laravel: Ignition Diagnostic Debug Page (Critical Confirmed Vulnerability)
	apiLaravelIgnition := api.APIFinding{
		Category:         api.CategoryLaravelIgnitionDebug,
		Endpoint:         "https://api.example.com/_ignition/health-check",
		Method:           "GET",
		Description:      "Laravel Ignition developer diagnostic page confirmed. Interactive stack trace and framework metadata exposed.",
		Evidence:         "Ignition 2.5.1 page rendered with interactive execute-solution endpoints",
		Severity:         api.SeverityCritical,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryLaravelIgnitionDebug, "https://api.example.com/_ignition/health-check", "GET"),
		HTTPStatus:       500,
		Framework:        "Laravel",
		FrameworkVersion: "10.0",
		Details: map[string]string{
			"framework":         "Laravel",
			"framework_version": "10.0",
		},
	}
	fLaravelIgnition := FromAPIFinding(target, apiLaravelIgnition)
	fLaravelIgnition.Timestamp = now
	findings = append(findings, fLaravelIgnition)

	// 8. Laravel: Telescope Protected (Not Exposed)
	apiLaravelTelescopeProt := api.APIFinding{
		Category:         api.CategoryLaravelTelescopeProtected,
		Endpoint:         "https://api.example.com/telescope",
		Method:           "GET",
		Description:      "Laravel Telescope monitoring interface access is restricted on probed route (HTTP 403 Forbidden).",
		Evidence:         "HTTP/1.1 403 Forbidden\nAccess to Telescope denied by authorize callback",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryLaravelTelescopeProtected, "https://api.example.com/telescope", "GET"),
		HTTPStatus:       403,
		Framework:        "Laravel",
		FrameworkVersion: "10.0",
		Details: map[string]string{
			"framework":         "Laravel",
			"framework_version": "10.0",
		},
	}
	fLaravelTelescopeProt := FromAPIFinding(target, apiLaravelTelescopeProt)
	fLaravelTelescopeProt.Timestamp = now
	findings = append(findings, fLaravelTelescopeProt)

	// 9. Node.js: Runtime Header Exposure (Informational Observation)
	apiNodeHeader := api.APIFinding{
		Category:         api.CategoryNodeRuntimeExposure,
		Endpoint:         "https://api.example.com/health",
		Method:           "GET",
		Description:      "Node.js Express framework identified via HTTP response header",
		Evidence:         "X-Powered-By: Express\nServer: cloudflare",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryNodeRuntimeExposure, "https://api.example.com/health", "GET"),
		HTTPStatus:       200,
		Framework:        "Node.js",
		FrameworkVersion: "4.18.2",
		Details: map[string]string{
			"framework":         "Node.js",
			"framework_version": "4.18.2",
			"sub_framework":     "Express",
		},
	}
	fNodeHeader := FromAPIFinding(target, apiNodeHeader)
	fNodeHeader.Timestamp = now
	findings = append(findings, fNodeHeader)

	// 10. Node.js: Stack Trace Exposure (Medium Configuration Exposure)
	apiNodeStackTrace := api.APIFinding{
		Category:         api.CategoryNodeStackTrace,
		Endpoint:         "https://api.example.com/debug/error",
		Method:           "GET",
		Description:      "Node.js unhandled exception traceback exposes internal filesystem paths and module locations",
		Evidence:         "Error: Unhandled at /app/server/controllers/user.js:42:15\n    at Layer.handle [as handle_request] (/app/node_modules/express/lib/router/layer.js:95:5)",
		Severity:         api.SeverityMedium,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryNodeStackTrace, "https://api.example.com/debug/error", "GET"),
		HTTPStatus:       500,
		Framework:        "Node.js",
		FrameworkVersion: "4.18.2",
		Details: map[string]string{
			"framework":         "Node.js",
			"framework_version": "4.18.2",
		},
	}
	fNodeStackTrace := FromAPIFinding(target, apiNodeStackTrace)
	fNodeStackTrace.Timestamp = now
	findings = append(findings, fNodeStackTrace)

	// 11. Go: Diagnostic Pprof Exposure (High Confirmed Vulnerability)
	apiGoPprof := api.APIFinding{
		Category:         api.CategoryGoPprofExposure,
		Endpoint:         "https://api.example.com/debug/pprof/goroutine",
		Method:           "GET",
		Description:      "Go runtime profiling data (active execution or goroutine traces) exposed",
		Evidence:         "goroutine profile: total 48\ngoroutine 1 [running]:\nruntime/pprof.writeGoroutine(0x10d2920, 0xc0000a6000)\n\t/usr/local/go/src/runtime/pprof/pprof.go:693 +0x45",
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryGoPprofExposure, "https://api.example.com/debug/pprof/goroutine", "GET"),
		HTTPStatus:       200,
		Framework:        "Go",
		FrameworkVersion: "1.21.4",
		Details: map[string]string{
			"framework":         "Go",
			"framework_version": "1.21.4",
		},
	}
	fGoPprof := FromAPIFinding(target, apiGoPprof)
	fGoPprof.Timestamp = now
	findings = append(findings, fGoPprof)

	// 12. Go: Runtime Fiber Header Observation (Informational Observation)
	apiGoHeader := api.APIFinding{
		Category:         api.CategoryGoRuntimeExposure,
		Endpoint:         "https://api.example.com/ping",
		Method:           "GET",
		Description:      "Go Fiber framework identified via HTTP Server header",
		Evidence:         "Server: Fiber/v2.50.0",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		Fingerprint:      api.GenerateFingerprint(api.CategoryGoRuntimeExposure, "https://api.example.com/ping", "GET"),
		HTTPStatus:       200,
		Framework:        "Go",
		FrameworkVersion: "2.50.0",
		Details: map[string]string{
			"framework":         "Go",
			"framework_version": "2.50.0",
			"sub_framework":     "Fiber",
		},
	}
	fGoHeader := FromAPIFinding(target, apiGoHeader)
	fGoHeader.Timestamp = now
	findings = append(findings, fGoHeader)

	return findings
}

func createTestFrameworkReport() Report {
	now := time.Now().UTC()
	findings := createTestFrameworkFindings()

	rep := Report{
		Version:          "2.0.0",
		Target:           "https://api.example.com",
		Targets:          []string{"https://api.example.com"},
		Timestamp:        now.Format(time.RFC3339),
		Duration:         "1.85s",
		CompletionStatus: "COMPLETED",
		Findings:         findings,
		Summary: Summary{
			TotalFindings: len(findings),
			CriticalCount: 1,
			HighCount:     4,
			MediumCount:   1,
			LowCount:      0,
			InfoCount:     6,
			VerifiedCount: 5,
			DetectedCount: 1,
			ObservedCount: 4,
		},
		RiskScore:          78,
		RiskLevel:          "HIGH",
		RiskScoreAvailable: true,
		Metadata: map[string]any{
			"frameworks_assessed": []string{
				"Spring Boot", "Django", "FastAPI", "Laravel", "Node.js", "Go",
			},
		},
	}

	return rep
}

// 1. Test Model Query Helpers
func TestFramework_ModelHelpers(t *testing.T) {
	rep := createTestFrameworkReport()

	if !rep.HasFrameworkFindings() {
		t.Fatalf("expected HasFrameworkFindings() to return true")
	}
	if !rep.HasFrameworkScope() {
		t.Fatalf("expected HasFrameworkScope() to return true")
	}

	frameworks := rep.DetectedFrameworks()
	if len(frameworks) != 6 {
		t.Fatalf("expected 6 detected frameworks (Spring Boot, Django, FastAPI, Laravel, Node.js, Go), got %d", len(frameworks))
	}

	fwMap := make(map[string]FrameworkSummary)
	for _, fw := range frameworks {
		fwMap[fw.Name] = fw
	}

	// Verify Spring Boot
	sb, exists := fwMap["Spring Boot"]
	if !exists {
		t.Errorf("expected Spring Boot to be detected")
	} else {
		if sb.TotalFindings != 2 {
			t.Errorf("expected 2 Spring Boot findings, got %d", sb.TotalFindings)
		}
		if sb.VerifiedCount != 1 {
			t.Errorf("expected 1 verified Spring Boot vulnerability (actuator-env), got %d", sb.VerifiedCount)
		}
		if sb.ProtectedCount != 1 {
			t.Errorf("expected 1 protected Spring Boot endpoint (actuator-restricted), got %d", sb.ProtectedCount)
		}
		if sb.Status != "VERIFIED_VULNERABILITY" {
			t.Errorf("expected Spring Boot status VERIFIED_VULNERABILITY, got %s", sb.Status)
		}
		if sb.Version != "3.2.0" {
			t.Errorf("expected Spring Boot version 3.2.0, got %s", sb.Version)
		}
	}

	// Verify Django
	dj, exists := fwMap["Django"]
	if !exists {
		t.Errorf("expected Django to be detected")
	} else {
		if dj.TotalFindings != 2 {
			t.Errorf("expected 2 Django findings, got %d", dj.TotalFindings)
		}
		if dj.VerifiedCount != 1 {
			t.Errorf("expected 1 verified Django vulnerability (debug mode), got %d", dj.VerifiedCount)
		}
		if dj.ObservationCount != 1 {
			t.Errorf("expected 1 Django observation (DRF browsable API), got %d", dj.ObservationCount)
		}
		if dj.Status != "VERIFIED_VULNERABILITY" {
			t.Errorf("expected Django status VERIFIED_VULNERABILITY, got %s", dj.Status)
		}
	}

	// Verify FastAPI
	fa, exists := fwMap["FastAPI"]
	if !exists {
		t.Errorf("expected FastAPI to be detected")
	} else {
		if fa.TotalFindings != 2 {
			t.Errorf("expected 2 FastAPI findings, got %d", fa.TotalFindings)
		}
		if fa.VerifiedCount != 1 {
			t.Errorf("expected 1 verified FastAPI vulnerability (sensitive schema), got %d", fa.VerifiedCount)
		}
		if fa.ObservationCount != 1 {
			t.Errorf("expected 1 FastAPI observation (docs exposure), got %d", fa.ObservationCount)
		}
	}

	// Verify Laravel
	lv, exists := fwMap["Laravel"]
	if !exists {
		t.Errorf("expected Laravel to be detected")
	} else {
		if lv.TotalFindings != 2 {
			t.Errorf("expected 2 Laravel findings, got %d", lv.TotalFindings)
		}
		if lv.VerifiedCount != 1 {
			t.Errorf("expected 1 verified Laravel vulnerability (Ignition), got %d", lv.VerifiedCount)
		}
		if lv.ProtectedCount != 1 {
			t.Errorf("expected 1 protected Laravel endpoint (Telescope 403), got %d", lv.ProtectedCount)
		}
	}

	// Verify Node.js
	nd, exists := fwMap["Node.js"]
	if !exists {
		t.Errorf("expected Node.js to be detected")
	} else {
		if nd.TotalFindings != 2 {
			t.Errorf("expected 2 Node.js findings, got %d", nd.TotalFindings)
		}
		if nd.Category != "RUNTIME" {
			t.Errorf("expected Node.js category RUNTIME, got %s", nd.Category)
		}
		if nd.DetectedCount != 1 {
			t.Errorf("expected 1 detected Node.js exposure (stack trace), got %d", nd.DetectedCount)
		}
		if nd.ObservationCount != 1 {
			t.Errorf("expected 1 Node.js observation (header), got %d", nd.ObservationCount)
		}
	}

	// Verify Go
	goFw, exists := fwMap["Go"]
	if !exists {
		t.Errorf("expected Go to be detected")
	} else {
		if goFw.TotalFindings != 2 {
			t.Errorf("expected 2 Go findings, got %d", goFw.TotalFindings)
		}
		if goFw.Category != "RUNTIME" {
			t.Errorf("expected Go category RUNTIME, got %s", goFw.Category)
		}
		if goFw.VerifiedCount != 1 {
			t.Errorf("expected 1 verified Go vulnerability (pprof live profiling), got %d", goFw.VerifiedCount)
		}
		if goFw.ObservationCount != 1 {
			t.Errorf("expected 1 Go observation (Fiber header), got %d", goFw.ObservationCount)
		}
	}

	// Test FrameworkFindingCount
	if c := rep.FrameworkFindingCount("Spring Boot"); c != 2 {
		t.Errorf("expected 2 findings for Spring Boot, got %d", c)
	}
	if c := rep.FrameworkFindingCount("Django"); c != 2 {
		t.Errorf("expected 2 findings for Django, got %d", c)
	}
	if c := rep.FrameworkFindingCount("FastAPI"); c != 2 {
		t.Errorf("expected 2 findings for FastAPI, got %d", c)
	}
	if c := rep.FrameworkFindingCount("Laravel"); c != 2 {
		t.Errorf("expected 2 findings for Laravel, got %d", c)
	}
	if c := rep.FrameworkFindingCount("Node.js"); c != 2 {
		t.Errorf("expected 2 findings for Node.js, got %d", c)
	}
	if c := rep.FrameworkFindingCount("Go"); c != 2 {
		t.Errorf("expected 2 findings for Go, got %d", c)
	}
	if c := rep.FrameworkFindingCount("NonExistentFramework"); c != 0 {
		t.Errorf("expected 0 findings for NonExistentFramework, got %d", c)
	}
}

// 2. Test Identification vs Vulnerability Distinction & Zero Findings Clean Reporting
func TestFramework_DistinctionAndZeroFindings(t *testing.T) {
	// A report with ONLY an informational header observation (X-Powered-By: Express)
	apiF := api.APIFinding{
		Category:         api.CategoryNodeRuntimeExposure,
		Endpoint:         "https://app.example.com",
		Method:           "GET",
		Description:      "Node.js Express framework identified via HTTP response header",
		Evidence:         "X-Powered-By: Express",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		HTTPStatus:       200,
		Framework:        "Node.js",
		FrameworkVersion: "4.17.1",
	}
	f := FromAPIFinding("https://app.example.com", apiF)

	rep := Report{
		Target:   "https://app.example.com",
		Findings: []Finding{f},
		Metadata: map[string]any{
			"frameworks_assessed": []string{"Node.js", "FastAPI"},
		},
	}

	frameworks := rep.DetectedFrameworks()
	fwMap := make(map[string]FrameworkSummary)
	for _, fw := range frameworks {
		fwMap[fw.Name] = fw
	}

	// Node.js had only an informational header -> OBSERVED_SURFACE, NOT a vulnerability
	nodeFw := fwMap["Node.js"]
	if nodeFw.Status != "OBSERVED_SURFACE" {
		t.Errorf("expected Node.js status OBSERVED_SURFACE for header disclosure, got %s", nodeFw.Status)
	}
	if nodeFw.VerifiedCount != 0 {
		t.Errorf("header disclosure must not be classified as verified vulnerability, got %d", nodeFw.VerifiedCount)
	}

	// FastAPI was in scope / assessed, but had 0 findings -> NO_VULNERABILITIES_OBSERVED
	fastFw := fwMap["FastAPI"]
	if fastFw.Status != "NO_VULNERABILITIES_OBSERVED" {
		t.Errorf("expected FastAPI status NO_VULNERABILITIES_OBSERVED for 0 findings, got %s", fastFw.Status)
	}
	if fastFw.TotalFindings != 0 {
		t.Errorf("expected 0 total findings for clean FastAPI, got %d", fastFw.TotalFindings)
	}
}

// 3. Test Protected Routes (HTTP 401/403) Handling
func TestFramework_ProtectedRoutes(t *testing.T) {
	apiF := api.APIFinding{
		Category:         api.CategoryActuatorRestricted,
		Endpoint:         "https://app.example.com/actuator",
		Method:           "GET",
		Description:      "Spring Boot Actuator endpoint protected by authentication controls (HTTP 401)",
		Evidence:         "HTTP/1.1 401 Unauthorized",
		Severity:         api.SeverityInfo,
		Confidence:       api.ConfidenceHigh,
		HTTPStatus:       401,
		Framework:        "Spring Boot",
		FrameworkVersion: "3.1.5",
	}
	f := FromAPIFinding("https://app.example.com", apiF)

	rep := Report{
		Target:   "https://app.example.com",
		Findings: []Finding{f},
	}

	frameworks := rep.DetectedFrameworks()
	if len(frameworks) != 1 {
		t.Fatalf("expected 1 framework, got %d", len(frameworks))
	}
	sb := frameworks[0]
	if sb.Status != "PROTECTED" {
		t.Errorf("expected status PROTECTED for HTTP 401 actuator route, got %s", sb.Status)
	}
	if sb.ProtectedCount != 1 {
		t.Errorf("expected ProtectedCount 1, got %d", sb.ProtectedCount)
	}
}

// 4. Test Standard HTML Report Generation
func TestFramework_HTMLReport(t *testing.T) {
	rep := createTestFrameworkReport()

	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("failed to render HTML report: %v", err)
	}

	// A. Summary card check
	if !strings.Contains(html, "Backend Frameworks &amp; Runtime Assessment Summary") && !strings.Contains(html, "Backend Frameworks & Runtime Assessment Summary") {
		t.Errorf("HTML report missing Framework Assessment Summary section")
	}

	// B. Framework names in HTML
	expectedFWs := []string{"Spring Boot", "Django", "FastAPI", "Laravel", "Node.js", "Go"}
	for _, fw := range expectedFWs {
		if !strings.Contains(html, fw) {
			t.Errorf("HTML report missing framework name: %s", fw)
		}
	}

	// C. Framework versions in HTML
	if !strings.Contains(html, "v3.2.0") {
		t.Errorf("HTML report missing Spring Boot version v3.2.0")
	}
	if !strings.Contains(html, "v4.2.7") {
		t.Errorf("HTML report missing Django version v4.2.7")
	}
	if !strings.Contains(html, "v0.104.1") {
		t.Errorf("HTML report missing FastAPI version v0.104.1")
	}

	// D. Filter button and JavaScript filter
	if !strings.Contains(html, "onclick=\"filterFindings('FRAMEWORK')\"") {
		t.Errorf("HTML report missing Frameworks filter button")
	}
	if !strings.Contains(html, "data-framework=") {
		t.Errorf("HTML report missing data-framework attribute on finding items")
	}

	// E. Policy explanation
	if !strings.Contains(html, "Framework Assessment Policy:") {
		t.Errorf("HTML report missing Framework Assessment Policy explanation")
	}
}

// 5. Test XSS Safety in HTML Report
func TestFramework_HTMLReport_XSSPrevention(t *testing.T) {
	xssPayload := "<script>alert('xss-fw')</script>"
	xssVer := "1.0<img src=x onerror=alert(1)>"

	apiF := api.APIFinding{
		Category:         api.CategoryDjangoDebugMode,
		Endpoint:         "https://app.example.com/" + xssPayload,
		Method:           "GET",
		Description:      "Django debug mode with payload " + xssPayload,
		Evidence:         "Traceback containing " + xssPayload,
		Severity:         api.SeverityHigh,
		Confidence:       api.ConfidenceHigh,
		HTTPStatus:       500,
		Framework:        "Django" + xssPayload,
		FrameworkVersion: xssVer,
		Details: map[string]string{
			"framework":         "Django" + xssPayload,
			"framework_version": xssVer,
		},
	}
	f := FromAPIFinding("https://app.example.com", apiF)

	rep := Report{
		Target:   "https://app.example.com",
		Findings: []Finding{f},
	}

	html, err := GenerateHTML(rep)
	if err != nil {
		t.Fatalf("failed to render HTML: %v", err)
	}

	// Must never contain unescaped raw <script> or <img onerror>
	if strings.Contains(html, "<script>alert('xss-fw')</script>") {
		t.Errorf("HTML report contains unescaped <script> tag from framework name/endpoint")
	}
	if strings.Contains(html, "<img src=x onerror=alert(1)>") {
		t.Errorf("HTML report contains unescaped <img> onerror from framework version")
	}
}

// 6. Test Commercial Report (JSON & HTML)
func TestFramework_CommercialReport(t *testing.T) {
	rep := createTestFrameworkReport()

	cr := BuildCommercialReport(rep)

	// A. Executive summary highlights should mention backend technologies
	foundHighlight := false
	for _, hl := range cr.ExecutiveSummary.AttackSurfaceHighlights {
		if strings.Contains(hl, "Backend technologies identified:") {
			foundHighlight = true
			if !strings.Contains(hl, "Spring Boot") || !strings.Contains(hl, "Django") {
				t.Errorf("Attack surface highlight missing frameworks: %s", hl)
			}
			break
		}
	}
	if !foundHighlight {
		t.Errorf("Commercial ExecutiveSummary missing backend technologies highlight")
	}

	// B. Attack surface categorization: framework routes mapped to API_ENDPOINT
	for _, asset := range cr.AttackSurface.Assets {
		if strings.Contains(asset.URL, "/actuator") || strings.Contains(asset.URL, "/debug/") || strings.Contains(asset.URL, "/docs") {
			if asset.AssetType != "API_ENDPOINT" {
				t.Errorf("expected asset %s to be classified as API_ENDPOINT, got %s", asset.URL, asset.AssetType)
			}
		}
	}

	// C. Finding metadata preservation: Framework and FrameworkVersion in CommercialFinding
	foundVerifiedFW := false
	for _, vf := range cr.VerifiedFindings {
		if vf.Framework != "" {
			foundVerifiedFW = true
			if vf.Framework != "Spring Boot" && vf.Framework != "Django" && vf.Framework != "FastAPI" && vf.Framework != "Laravel" && vf.Framework != "Go" {
				t.Errorf("unexpected verified framework: %s", vf.Framework)
			}
			break
		}
	}
	if !foundVerifiedFW {
		t.Errorf("Commercial VerifiedFindings missing Framework field preservation")
	}

	// D. Commercial HTML rendering
	html, err := GenerateCommercialHTML(cr)
	if err != nil {
		t.Fatalf("failed to render Commercial HTML: %v", err)
	}
	if !strings.Contains(html, "Framework:") {
		t.Errorf("Commercial HTML report missing Framework metadata label")
	}
	if !strings.Contains(html, "Spring Boot") || !strings.Contains(html, "Django") {
		t.Errorf("Commercial HTML report missing framework badges/text")
	}
}

// 7. Test SARIF 2.1.0 Export
func TestFramework_SARIFExport(t *testing.T) {
	rep := createTestFrameworkReport()

	sarifLog := BuildSARIFLog(rep)
	if len(sarifLog.Runs) == 0 {
		t.Fatalf("SARIF log has 0 runs")
	}
	run := sarifLog.Runs[0]

	// A. Rules should include framework property where applicable
	foundRuleFW := false
	for _, rule := range run.Tool.Driver.Rules {
		if fw, ok := rule.Properties["framework"].(string); ok && fw != "" {
			foundRuleFW = true
			break
		}
	}
	if !foundRuleFW {
		t.Errorf("SARIF rules missing framework property")
	}

	// B. Results should preserve framework and framework_version in property bag
	foundResultFW := false
	for _, res := range run.Results {
		if fw, ok := res.Properties["framework"].(string); ok && fw != "" {
			foundResultFW = true
			break
		}
	}
	if !foundResultFW {
		t.Errorf("SARIF results missing framework in property bag")
	}

	// C. Serialization and Validation
	sarifBytes, err := json.Marshal(sarifLog)
	if err != nil {
		t.Fatalf("failed to marshal SARIF JSON: %v", err)
	}
	if err := ValidateSARIF(sarifBytes); err != nil {
		t.Fatalf("SARIF validation failed: %v", err)
	}
	if !strings.Contains(string(sarifBytes), `"framework":`) {
		t.Errorf("SARIF JSON missing serialized framework property")
	}
}

// 8. Test Canonical JSON Serialization and Round-trip
func TestFramework_JSONRoundTrip(t *testing.T) {
	rep := createTestFrameworkReport()

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("failed marshaling Report to JSON: %v", err)
	}

	var rep2 Report
	if err := json.Unmarshal(data, &rep2); err != nil {
		t.Fatalf("failed unmarshaling Report from JSON: %v", err)
	}

	if !rep2.HasFrameworkFindings() {
		t.Errorf("unmarshaled report lost HasFrameworkFindings()")
	}
	if len(rep2.DetectedFrameworks()) != 6 {
		t.Errorf("expected 6 detected frameworks after JSON round-trip, got %d", len(rep2.DetectedFrameworks()))
	}
}

// 9. Test Deduplication Safety on Framework Findings
func TestFramework_DeduplicationSafety(t *testing.T) {
	target := "https://api.example.com"
	now := time.Now().UTC()

	// Finding 1: Initial passive probe (generic detection)
	f1 := Finding{
		ID:          "API-DJANGO-01",
		RuleID:      "API-DJANGO-DEBUG-MODE",
		Target:      target,
		Endpoint:    "https://api.example.com/admin/login/",
		Method:      "GET",
		Category:    "django-debug-mode",
		Severity:    SeverityMedium,
		Confidence:  ConfidenceMedium,
		Framework:   "generic",
		Fingerprint: "fp-django-login-get",
		Status:      FindingStatusConfirmed,
		Timestamp:   now,
	}

	// Finding 2: Active verification (upgraded to Django v4.2)
	f2 := Finding{
		ID:               "API-DJANGO-01",
		RuleID:           "API-DJANGO-DEBUG-MODE",
		Target:           target,
		Endpoint:         "https://api.example.com/admin/login/",
		Method:           "GET",
		Category:         "django-debug-mode",
		Severity:         SeverityHigh,
		Confidence:       ConfidenceHigh,
		Framework:        "Django",
		FrameworkVersion: "4.2.7",
		Fingerprint:      "fp-django-login-get",
		Status:           FindingStatusConfirmed,
		Timestamp:        now.Add(1 * time.Second),
	}

	deduped := DeduplicateFindings([]Finding{f1, f2})
	if len(deduped) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(deduped))
	}

	df := deduped[0]
	if df.Framework != "Django" {
		t.Errorf("expected Framework to be upgraded from generic to Django, got %s", df.Framework)
	}
	if df.FrameworkVersion != "4.2.7" {
		t.Errorf("expected FrameworkVersion 4.2.7, got %s", df.FrameworkVersion)
	}
	if df.Severity != SeverityHigh {
		t.Errorf("expected SeverityHigh after deduplication, got %s", df.Severity)
	}
}

// 10. Test Secret Redaction on Framework Evidence
func TestFramework_SecretRedaction(t *testing.T) {
	target := "https://api.example.com"
	rawSecret := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	apiF := api.APIFinding{
		Category:    api.CategoryActuatorEnv,
		Endpoint:    "https://api.example.com/actuator/env",
		Method:      "GET",
		Description: "Spring Boot Actuator environment exposed live token: " + rawSecret,
		Evidence:    "JWT_TOKEN=" + rawSecret,
		Severity:    api.SeverityHigh,
		Confidence:  api.ConfidenceHigh,
		Framework:   "Spring Boot",
	}
	f := FromAPIFinding(target, apiF)

	// Verify that secret does not leak in description, evidence, or safe curl command
	if strings.Contains(f.Description, rawSecret) {
		t.Errorf("Finding Description leaked unredacted secret: %s", f.Description)
	}
	if strings.Contains(f.Evidence, rawSecret) {
		t.Errorf("Finding Evidence leaked unredacted secret: %s", f.Evidence)
	}
	if strings.Contains(f.Verification.SafeCurlCommand, rawSecret) {
		t.Errorf("SafeCurlCommand leaked unredacted secret: %s", f.Verification.SafeCurlCommand)
	}
}

// 11. Test WriteHTML, WriteJSON, WriteSARIF, and WriteCommercial HTML helpers
func TestFramework_Writers(t *testing.T) {
	rep := createTestFrameworkReport()
	tmpDir := t.TempDir()

	// Export HTML
	htmlFile := filepath.Join(tmpDir, "report.html")
	if err := WriteHTML(rep, htmlFile); err != nil {
		t.Fatalf("WriteHTML failed: %v", err)
	}
	if _, err := os.Stat(htmlFile); os.IsNotExist(err) {
		t.Fatalf("HTML file not created")
	}

	// Export JSON
	jsonFile := filepath.Join(tmpDir, "report.json")
	if err := WriteJSON(rep, jsonFile); err != nil {
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
		t.Fatalf("JSON file not created")
	}

	// Export SARIF
	sarifFile := filepath.Join(tmpDir, "report.sarif")
	if err := WriteSARIF(rep, sarifFile); err != nil {
		t.Fatalf("WriteSARIF failed: %v", err)
	}
	if _, err := os.Stat(sarifFile); os.IsNotExist(err) {
		t.Fatalf("SARIF file not created")
	}

	// Export Commercial HTML
	cr := BuildCommercialReport(rep)
	crHtmlFile := filepath.Join(tmpDir, "commercial.html")
	if err := WriteCommercialHTML(cr, crHtmlFile); err != nil {
		t.Fatalf("WriteCommercialHTML failed: %v", err)
	}
	if _, err := os.Stat(crHtmlFile); os.IsNotExist(err) {
		t.Fatalf("Commercial HTML file not created")
	}
}
