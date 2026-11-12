package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"felix/pkg/auth"
	"felix/pkg/bola"
)

func TestPhase7_ResolveTargetEndpointURL_NonRootAndRootPaths(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		path     string
		expected string
	}{
		{
			name:     "non_root_target_with_root_relative_api_path",
			target:   "http://127.0.0.1:5000/ui/",
			path:     "/users/v1",
			expected: "http://127.0.0.1:5000/users/v1",
		},
		{
			name:     "non_root_target_with_root_slash_preserves_target_path",
			target:   "http://127.0.0.1:5000/ui/",
			path:     "/",
			expected: "http://127.0.0.1:5000/ui/",
		},
		{
			name:     "non_root_target_with_relative_path",
			target:   "http://127.0.0.1:5000/ui/",
			path:     "swagger-ui.css",
			expected: "http://127.0.0.1:5000/ui/swagger-ui.css",
		},
		{
			name:     "root_target_with_api_path",
			target:   "http://127.0.0.1:5000",
			path:     "/openapi.json",
			expected: "http://127.0.0.1:5000/openapi.json",
		},
		{
			name:     "absolute_url_passthrough",
			target:   "http://127.0.0.1:5000/ui/",
			path:     "http://127.0.0.1:5000/books/v1",
			expected: "http://127.0.0.1:5000/books/v1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveTargetEndpointURL(tc.target, tc.path)
			if got != tc.expected {
				t.Fatalf("resolveTargetEndpointURL(%q, %q) = %q, want %q", tc.target, tc.path, got, tc.expected)
			}
		})
	}

	cands := buildBaseAndOriginCandidateURLs("http://127.0.0.1:5000/ui/", "/openapi.json")
	var hasSub, hasOrigin bool
	for _, c := range cands {
		if c == "http://127.0.0.1:5000/ui/openapi.json" {
			hasSub = true
		}
		if c == "http://127.0.0.1:5000/openapi.json" {
			hasOrigin = true
		}
	}
	if !hasSub || !hasOrigin {
		t.Fatalf("expected both subpath and origin candidates, got %v", cands)
	}
}

func TestPhase7_OpenAPIIngestionFromNonRootUI(t *testing.T) {
	openAPISpec := `{
  "openapi": "3.0.2",
  "info": {"title": "VAmPI Mock", "version": "1.0"},
  "paths": {
    "/users/v1": {
      "get": {"summary": "List users"}
    },
    "/users/v1/{username}": {
      "get": {
        "parameters": [{"name": "username", "in": "path", "required": true}]
      }
    },
    "/books/v1": {
      "get": {"summary": "List books"}
    },
    "/books/v1/{book_title}": {
      "get": {
        "parameters": [{"name": "book_title", "in": "path", "required": true}]
      }
    }
  }
}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ui/":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><html><body>Swagger UI</body></html>`))
		case "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openAPISpec))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	target := srv.URL + "/ui/"
	idMgr, err := auth.NewIdentityManager(auth.IdentityManagerOptions{
		TargetURL:     target,
		AllowLoopback: true,
		Timeout:       2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewIdentityManager: %v", err)
	}

	rt := &AssessmentRuntimeContext{
		TargetURL:   target,
		Client:      srv.Client(),
		IdentityMgr: idMgr,
		Opts:        AssessOptions{TargetURL: target, Timeout: 2 * time.Second},
	}

	ensureOpenAPISpecIngested(rt)

	if rt.OpenAPISpecURL != srv.URL+"/openapi.json" {
		t.Fatalf("expected OpenAPISpecURL=%s/openapi.json, got %q", srv.URL, rt.OpenAPISpecURL)
	}
	if len(rt.OpenAPISpecOps) != 4 {
		t.Fatalf("expected 4 parsed OpenAPI operations, got %d", len(rt.OpenAPISpecOps))
	}

	foundUserTpl := false
	foundBookTpl := false
	for _, ep := range rt.DiscoveredEndpoints {
		if ep.Path == "/users/v1/{username}" && ep.Method == "GET" {
			foundUserTpl = true
		}
		if ep.Path == "/books/v1/{book_title}" && ep.Method == "GET" {
			foundBookTpl = true
		}
		if strings.HasPrefix(ep.Path, "/ui/users") {
			t.Fatalf("duplicated /ui/ prefix on discovered endpoint: %q", ep.Path)
		}
	}
	if !foundUserTpl || !foundBookTpl {
		t.Fatalf("expected OpenAPI endpoints in rt.DiscoveredEndpoints, got %+v", rt.DiscoveredEndpoints)
	}

	// Verify BOLA surface discovery extracts username & book_title from collection JSON + OpenAPI spec
	surface := bola.DiscoverObjectSurface(target, []bola.TestIdentity{
		{Alias: "user_a", Role: "user", Username: "name1"},
		{Alias: "user_b", Role: "user", Username: "name2"},
	}, []bola.DiscoveryObservation{
		{
			Identity:        "USER_A",
			URL:             srv.URL + "/openapi.json",
			Path:            "/openapi.json",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(openAPISpec),
			DiscoveryMethod: "OPENAPI_SPEC",
		},
		{
			Identity:    "USER_A",
			URL:         srv.URL + "/users/v1",
			Path:        "/users/v1",
			Method:      "GET",
			StatusCode:  200,
			ContentType: "application/json",
			Body:        []byte(`{"users":[{"username":"name1","email":"u1@example.com"},{"username":"name2","email":"u2@example.com"}]}`),
		},
	}, 20)

	var sawName1, sawName2 bool
	for _, c := range surface.Candidates {
		if c.TemplatePath == "/users/v1/{username}" && c.ObjectID == "name1" && c.OwnerIdentity == "user_a" {
			sawName1 = true
		}
		if c.TemplatePath == "/users/v1/{username}" && c.ObjectID == "name2" && c.OwnerIdentity == "user_b" {
			sawName2 = true
		}
	}
	if !sawName1 || !sawName2 {
		t.Fatalf("expected BOLA discovery to attribute name1->user_a and name2->user_b, got %+v", surface.Candidates)
	}
}

func TestPhase7_OpenAPIIgnoresSPAFallbackAndMalformedSpecSafely(t *testing.T) {
	t.Run("spa_html_fallback_ignored", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<!doctype html><html><body>"openapi" SPA shell</body></html>`))
		}))
		defer srv.Close()

		rt := &AssessmentRuntimeContext{
			TargetURL: srv.URL,
			Client:    srv.Client(),
			Opts:      AssessOptions{TargetURL: srv.URL, Timeout: 2 * time.Second},
		}
		ensureOpenAPISpecIngested(rt)
		if rt.OpenAPISpecURL != "" || len(rt.OpenAPISpecOps) != 0 {
			t.Fatalf("expected HTML fallback not to be parsed as OpenAPI spec, got URL=%q ops=%d", rt.OpenAPISpecURL, len(rt.OpenAPISpecOps))
		}
	})

	t.Run("malformed_openapi_spec_records_warning_without_panic", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/openapi.json" {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"openapi": "3.0.0", "paths": { BROKEN`))
				return
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()

		rt := &AssessmentRuntimeContext{
			TargetURL: srv.URL,
			Client:    srv.Client(),
			Opts:      AssessOptions{TargetURL: srv.URL, Timeout: 2 * time.Second},
		}
		ensureOpenAPISpecIngested(rt)
		if len(rt.SpecParseWarnings) == 0 {
			t.Fatalf("expected SpecParseWarnings to record malformed JSON error")
		}
		if len(rt.DiscoveredEndpoints) != 0 {
			t.Fatalf("expected zero endpoints from malformed OpenAPI spec")
		}
	})
}
