package webvuln

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"felix/pkg/report"
)

func TestPhase7_CmdiFalsePositiveElimination_And_TruePositiveDifferential(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/polyfills.js", "/main.js":
			w.Header().Set("Content-Type", "application/javascript")
			fmt.Fprint(w, `var root="lenovo";var admin="administrator";var sys="nt authority";`)
		case "/index.html", "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<!doctype html><html><body><div id="root">Welcome administrator on lenovo</div></body></html>`)
		case "/rest/products/search":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"status":"success","data":[{"name":"Lenovo ThinkPad","desc":"root access guide"}]}`)
		case "/api/reflect":
			// Negative control: reflects query parameter literally without shell execution
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprintf(w, "echoed=%s", r.URL.Query().Get("cmd"))
		case "/api/ping-vuln":
			// Positive control: emulates POSIX shell quote evaluation
			w.Header().Set("Content-Type", "text/plain")
			host := r.URL.Query().Get("host")
			if strings.Contains(host, ";echo FLX_CMD_9182''7364") {
				fmt.Fprint(w, "PING 127.0.0.1\nFLX_CMD_91827364\n")
				return
			}
			fmt.Fprint(w, "PING idle")
		case "/api/exec-id-vuln":
			w.Header().Set("Content-Type", "text/plain")
			if r.URL.Query().Get("cmd") == "id" {
				fmt.Fprint(w, "uid=1000(runner) gid=1000(runner) groups=1000(runner)")
				return
			}
			fmt.Fprint(w, "ready")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	engine := NewEngine(srv.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-ph7-cmdi",
		ExecutionID:      "exec-ph7-cmdi",
		BaseURL:          srv.URL,
		SyntheticFixture: false,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/polyfills.js?v=1"},
			{Method: "GET", Path: "/main.js"},
			{Method: "GET", Path: "/"},
			{Method: "GET", Path: "/index.html"},
			{Method: "GET", Path: "/rest/products/search", Parameters: []string{"q"}},
			{Method: "GET", Path: "/api/reflect", Parameters: []string{"cmd"}},
			{Method: "GET", Path: "/api/ping-vuln", Parameters: []string{"host"}},
			{Method: "GET", Path: "/api/exec-id-vuln", Parameters: []string{"cmd"}},
		},
	}

	results, findings, cov := engine.assessCmdi(context.Background(), actx, srv.Client())
	if cov.Verified != 2 || len(findings) != 2 {
		t.Fatalf("expected exactly 2 verified CMDI findings (ping-vuln and exec-id-vuln), got verified=%d findings=%d (%+v)", cov.Verified, len(findings), findings)
	}
	for _, f := range findings {
		if f.Severity != report.SeverityCritical {
			t.Errorf("expected CRITICAL severity for verified CMDI, got %s", f.Severity)
		}
		if !strings.Contains(f.Endpoint, "/api/ping-vuln") && !strings.Contains(f.Endpoint, "/api/exec-id-vuln") {
			t.Errorf("unexpected false positive CMDI finding on %s", f.Endpoint)
		}
	}
	for _, r := range results {
		if strings.Contains(r.Endpoint, "/polyfills.js") || strings.Contains(r.Endpoint, "/main.js") {
			t.Errorf("static JS asset %s should not be scanned by CMDI", r.Endpoint)
		}
		if strings.Contains(r.Endpoint, "/api/reflect") && r.VerificationState == StateVerified {
			t.Errorf("literal reflection endpoint /api/reflect must NOT be verified CMDI")
		}
	}
}

func TestPhase7_InfoDisclosure_SPACatchAllAndSSTI_BaselineDiff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/static-number":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<html><body>Order #6383 confirmed for <div id=\"root\"></div></body></html>")
		default:
			// Simulate SPA fallback serving index.html with 200 OK for all paths including /.env
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<!doctype html><html><body><app-root></app-root></body></html>")
		}
	}))
	defer srv.Close()

	engine := NewEngine(srv.Client(), DefaultConfig())
	actx := &AssessmentContext{
		AssessmentID:     "asm-ph7-spa",
		ExecutionID:      "exec-ph7-spa",
		BaseURL:          srv.URL,
		SyntheticFixture: false,
		Endpoints: []TargetEndpoint{
			{Method: "GET", Path: "/static-number", Parameters: []string{"name"}},
		},
	}

	// SPA /.env fallback must NOT trigger StateCandidate
	resInfo, _, covInfo := engine.assessInfoDisclosure(context.Background(), actx, srv.Client())
	if covInfo.Candidates != 0 || covInfo.Verified != 0 {
		t.Errorf("SPA HTML fallback for /.env must produce 0 candidates/verified, got %+v (results=%+v)", covInfo, resInfo)
	}

	// Pre-existing 6383 in baseline must NOT trigger StateVerified SSTI
	resSSTI, fndSSTI, covSSTI := engine.assessSSTI(context.Background(), actx, srv.Client())
	if covSSTI.Verified != 0 || len(fndSSTI) != 0 {
		t.Errorf("pre-existing 6383 in baseline HTML must NOT trigger verified SSTI, got %+v (%+v)", covSSTI, resSSTI)
	}
}

func TestPhase7_BuildEndpointURL_NonRootBasePath(t *testing.T) {
	cases := []struct {
		base string
		path string
		want string
	}{
		{"http://127.0.0.1:5000/ui/", "/", "http://127.0.0.1:5000/ui/"},
		{"http://127.0.0.1:5000/ui/", "/ui/", "http://127.0.0.1:5000/ui/"},
		{"http://127.0.0.1:5000/ui/", "/openapi.json", "http://127.0.0.1:5000/openapi.json"},
		{"http://127.0.0.1:5000/ui/", "swagger-ui.css", "http://127.0.0.1:5000/ui/swagger-ui.css"},
		{"http://127.0.0.1:5000/ui/", "/users/v1", "http://127.0.0.1:5000/users/v1"},
	}
	for _, tc := range cases {
		got := buildEndpointURL(tc.base, tc.path, nil)
		if got != tc.want {
			t.Errorf("buildEndpointURL(%q, %q) = %q, want %q", tc.base, tc.path, got, tc.want)
		}
	}
}
