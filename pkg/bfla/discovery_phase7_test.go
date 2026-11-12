package bfla

import (
	"testing"
)

func TestPhase7_BFLA_DebugUnderscorePathAndStateResetDestructive(t *testing.T) {
	if !IsDestructiveFunction("GET", "/createdb") {
		t.Fatal("expected GET /createdb to be classified destructive")
	}
	if !IsDestructiveFunction("GET", "/api/v1/resetdb") {
		t.Fatal("expected GET /api/v1/resetdb to be classified destructive")
	}

	identities := []TestIdentity{
		{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
		{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
		{Alias: "ANONYMOUS", Role: "anonymous", PrivilegeLevel: 0},
	}

	observations := []DiscoveryObservation{
		{
			Identity:        "ADMIN",
			URL:             "http://127.0.0.1:5000/users/v1/_debug",
			Path:            "/users/v1/_debug",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"users":[{"username":"name1","admin":false,"password":"p1"}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "ANONYMOUS",
			URL:             "http://127.0.0.1:5000/users/v1/_debug",
			Path:            "/users/v1/_debug",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"users":[{"username":"name1","admin":false,"password":"p1"}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "ADMIN",
			URL:             "http://127.0.0.1:5000/api/internal/ping",
			Path:            "/api/internal/ping",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"ok":true}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:5000/api/internal/ping",
			Path:            "/api/internal/ping",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"ok":true}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
	}

	surface := DiscoverFunctionSurface("http://127.0.0.1:5000", identities, observations, 30)
	var debugFound, pingUnestablished bool
	for _, pol := range surface.Policies {
		if pol.Path == "/users/v1/_debug" && pol.Method == "GET" {
			debugFound = true
			if pol.RoleUnestablished {
				t.Fatalf("expected GET /users/v1/_debug policy to be established via _debug path + privileged user/admin indicators")
			}
		}
		if pol.Path == "/api/internal/ping" && pol.Method == "GET" {
			pingUnestablished = pol.RoleUnestablished
		}
	}
	if !debugFound {
		t.Fatalf("expected GET /users/v1/_debug in discovered BFLA policies, got %+v", surface.Policies)
	}
	if !pingUnestablished {
		t.Fatalf("expected benign /api/internal/ping returning {\"ok\":true} to remain PolicyUnestablished=true")
	}
}
