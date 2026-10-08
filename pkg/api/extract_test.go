package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// TestPhaseB_JSEndpointExtraction tests all required JavaScript endpoint extraction patterns.
func TestPhaseB_JSEndpointExtraction(t *testing.T) {
	jsCode := `
		// Fetch calls
		fetch("/api/users");
		fetch('/api/v1/orders');
		fetch('/api/auth/login', { method: "POST", headers: {} });
		fetch('/api/account/update', { method: "put" });

		// Axios calls
		axios.get("/api/products");
		axios.post("/api/checkout");
		axios.put("/api/users/profile");
		axios.delete("/api/items/123");
		axios.patch("/api/settings");

		// Axios request object
		axios.request({ url: "/api/data", method: "POST" });
		axios({ method: "DELETE", url: "/api/records" });

		// Template literals
		fetch(` + "`" + `/api/users/${userId}` + "`" + `);
		fetch(` + "`" + `/api/projects/${projectId}/tasks` + "`" + `);

		// Base URL concatenation
		const API_BASE = "/api/v2";
		fetch(API_BASE + "/inventory");

		// Absolute URLs: same-origin vs third-party
		fetch("https://webjothishanalyst.site/api/projects");
		fetch("https://api.thirdparty-analytics.com/collect");
		fetch("https://fonts.googleapis.com/css2");

		// Direct paths
		const route1 = "/api/billing";
		const route2 = "/graphql";
	`

	target := "https://webjothishanalyst.site"
	endpoints := ExtractEndpointsFromJS("app.js", []byte(jsCode), target)

	if len(endpoints) == 0 {
		t.Fatalf("expected extracted endpoints, got 0")
	}

	foundMap := make(map[string]DiscoveredEndpoint)
	for _, ep := range endpoints {
		foundMap[ep.Path] = ep
	}

	// 1. fetch extraction
	if ep, ok := foundMap["/api/users"]; !ok {
		t.Errorf("missing /api/users from fetch")
	} else if ep.Method != "UNKNOWN" {
		t.Errorf("expected UNKNOWN method for plain fetch, got %s", ep.Method)
	}

	// fetch with explicit POST method
	if ep, ok := foundMap["/api/auth/login"]; !ok {
		t.Errorf("missing /api/auth/login")
	} else if ep.Method != "POST" {
		t.Errorf("expected POST method for fetch with POST option, got %s", ep.Method)
	}

	// 2. axios method extraction
	if ep, ok := foundMap["/api/products"]; !ok {
		t.Errorf("missing /api/products")
	} else if ep.Method != "GET" {
		t.Errorf("expected GET method for axios.get, got %s", ep.Method)
	}

	if ep, ok := foundMap["/api/checkout"]; !ok {
		t.Errorf("missing /api/checkout")
	} else if ep.Method != "POST" {
		t.Errorf("expected POST method for axios.post, got %s", ep.Method)
	}

	// 3. axios.request
	if ep, ok := foundMap["/api/data"]; !ok {
		t.Errorf("missing /api/data from axios.request")
	} else if ep.Method != "POST" {
		t.Errorf("expected POST method, got %s", ep.Method)
	}

	// 4. dynamic template literals normalized to {param}
	if ep, ok := foundMap["/api/users/{param}"]; !ok {
		t.Errorf("missing normalized template literal /api/users/{param}, found keys: %+v", keys(foundMap))
	} else if ep.StaticallyResolved {
		t.Errorf("expected StaticallyResolved=false for parameterized route")
	}

	if _, ok := foundMap["/api/projects/{param}/tasks"]; !ok {
		t.Errorf("missing /api/projects/{param}/tasks")
	}

	// 5. concatenation
	if _, ok := foundMap["/api/v2/inventory"]; !ok {
		t.Errorf("missing concatenated route /api/v2/inventory")
	}

	// 6. absolute same-origin URL accepted
	if _, ok := foundMap["/api/projects"]; !ok {
		t.Errorf("missing same-origin URL /api/projects")
	}

	// 7. third-party out-of-scope rejected
	for p := range foundMap {
		if strings.Contains(p, "thirdparty") || strings.Contains(p, "googleapis") {
			t.Errorf("third-party out-of-scope endpoint was improperly accepted: %s", p)
		}
	}
}

// TestPhaseB_SPADiscovery tests configuration, framework routes, and source map extraction.
func TestPhaseB_SPADiscovery(t *testing.T) {
	jsCode := `
		// Configuration variables
		const NEXT_PUBLIC_API_URL = "/api/v1";
		const VITE_API_URL = "/api/v2";
		const BACKEND_URL = "/api/backend";

		// Router paths
		const routes = [
			{ path: "/users", component: Users },
			{ path: "/admin", component: AdminPanel },
			{ path: "/dashboard", component: Dashboard },
			{ path: "/settings", component: Settings },
		];

		// Next.js data route
		const buildManifest = "/_next/data/build123/projects.json";
	`

	target := "https://webjothishanalyst.site"
	endpoints := DiscoverSPARoutes("spa-bundle.js", []byte(jsCode), target)

	foundMap := make(map[string]DiscoveredEndpoint)
	for _, ep := range endpoints {
		foundMap[ep.Path] = ep
	}

	if _, ok := foundMap["/api/v1"]; !ok {
		t.Errorf("missing NEXT_PUBLIC_API_URL /api/v1")
	}
	if _, ok := foundMap["/users"]; !ok {
		t.Errorf("missing router /users")
	}
	if _, ok := foundMap["/admin"]; !ok {
		t.Errorf("missing router /admin")
	}
	if _, ok := foundMap["/_next/data/build123/projects.json"]; !ok {
		t.Errorf("missing nextjs data route")
	}

	// Source map extraction test
	sourceMapJSON := RawSourceMap{
		Version: 3,
		Sources: []string{"webpack://app/src/api/auth.ts"},
		SourcesContent: []string{
			`export function login() { return axios.post("/api/auth/login"); }`,
		},
	}
	smBytes, _ := json.Marshal(sourceMapJSON)
	smEndpoints := ExtractEndpointsFromSourceMap("bundle.js.map", smBytes, target)

	if len(smEndpoints) == 0 {
		t.Fatalf("expected source map extracted endpoints, got 0")
	}
	if smEndpoints[0].Path != "/api/auth/login" {
		t.Errorf("expected /api/auth/login from source map, got %s", smEndpoints[0].Path)
	}
	if smEndpoints[0].Mechanism != "source_map" {
		t.Errorf("expected mechanism source_map, got %s", smEndpoints[0].Mechanism)
	}
}

// TestPhaseB_EndpointClassification tests the taxonomy classification.
func TestPhaseB_EndpointClassification(t *testing.T) {
	testCases := []struct {
		path     string
		expected EndpointClassification
	}{
		{"/api/login", ClassAuthentication},
		{"/auth/sign-in", ClassAuthentication},
		{"/api/register", ClassAuthentication},
		{"/api/oauth/token", ClassAuthentication},
		{"/auth/permissions", ClassAuthorization},
		{"/api/users", ClassUser},
		{"/api/users/profile", ClassUser},
		{"/api/admin/users", ClassAdmin},
		{"/admin/dashboard", ClassAdmin},
		{"/api/account/settings", ClassAccount},
		{"/api/payment/checkout", ClassPayment},
		{"/api/billing/invoice", ClassPayment},
		{"/graphql", ClassGraphQL},
		{"/swagger.json", ClassDocumentation},
		{"/openapi.json", ClassDocumentation},
		{"/metrics", ClassMetrics},
		{"/actuator/health", ClassHealth},
		{"/healthz", ClassHealth},
		{"/api/upload", ClassUpload},
		{"/api/export/download", ClassDownload},
		{"/api/search", ClassSearch},
		{"/api/webhook/stripe", ClassWebhook},
		{"/static/app.js", ClassStatic},
		{"/images/logo.png", ClassStatic},
		{"/api/unknown-widget", ClassAPI},
		{"/about", ClassUnknown},
	}

	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			got := ClassifyEndpoint(tc.path)
			if got != tc.expected {
				t.Errorf("ClassifyEndpoint(%q) = %s; want %s", tc.path, got, tc.expected)
			}
		})
	}
}

// TestPhaseB_AuthStateReasoning tests empirical response access state modeling.
func TestPhaseB_AuthStateReasoning(t *testing.T) {
	// 1. HTTP 200 OK
	obs200 := ReasonAuthState(http.StatusOK, nil, []byte(`{"status":"success"}`))
	if obs200.State != AuthStatePublic {
		t.Errorf("expected AuthStatePublic, got %s", obs200.State)
	}

	// 2. HTTP 401 Unauthorized
	obs401 := ReasonAuthState(http.StatusUnauthorized, nil, []byte(`{"error":"unauthorized"}`))
	if obs401.State != AuthStateAuthRequired {
		t.Errorf("expected AuthStateAuthRequired, got %s", obs401.State)
	}
	if !strings.Contains(obs401.NegativeEvidence, "HTTP 401 indicates authentication is required") {
		t.Errorf("negative evidence missing 401 note: %s", obs401.NegativeEvidence)
	}

	// 3. HTTP 403 Forbidden
	obs403 := ReasonAuthState(http.StatusForbidden, nil, []byte(`Forbidden`))
	if obs403.State != AuthStateForbidden {
		t.Errorf("expected AuthStateForbidden, got %s", obs403.State)
	}
	if !strings.Contains(obs403.NegativeEvidence, "HTTP 403 indicates access is forbidden") {
		t.Errorf("negative evidence missing 403 note: %s", obs403.NegativeEvidence)
	}

	// 4. HTTP 404 Not Found
	obs404 := ReasonAuthState(http.StatusNotFound, nil, []byte(`Not Found`))
	if obs404.State != AuthStateNotFound {
		t.Errorf("expected AuthStateNotFound, got %s", obs404.State)
	}

	// 5. HTTP 302 Redirect
	headers := http.Header{}
	headers.Set("Location", "/login")
	obs302 := ReasonAuthState(http.StatusFound, headers, []byte(``))
	if obs302.State != AuthStateRedirect {
		t.Errorf("expected AuthStateRedirect, got %s", obs302.State)
	}
}

// Helper to inspect map keys
func keys(m map[string]DiscoveredEndpoint) []string {
	var k []string
	for key := range m {
		k = append(k, key)
	}
	return k
}
