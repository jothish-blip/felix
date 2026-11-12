package bola

import (
	"testing"
)

func TestPhase7_BOLA_NestedMeAnchor_UserOwnerField_AndDebugCollectionBinding(t *testing.T) {
	openAPI := `{
		"openapi": "3.0.1",
		"paths": {
			"/users/v1": {"get": {"summary": "List users"}},
			"/users/v1/_debug": {"get": {"summary": "Debug users"}},
			"/users/v1/{username}": {"get": {"parameters": [{"name": "username", "in": "path"}]}},
			"/books/v1": {"get": {"summary": "List books"}},
			"/books/v1/{book_title}": {"get": {"parameters": [{"name": "book_title", "in": "path"}]}}
		}
	}`

	identities := []TestIdentity{
		{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
		{Alias: "USER_B", Role: "user", PrivilegeLevel: 1},
		{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
	}

	observations := []DiscoveryObservation{
		{
			Identity:        "ADMIN",
			URL:             "http://127.0.0.1:5000/openapi.json",
			Path:            "/openapi.json",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(openAPI),
			DiscoveryMethod: "OPENAPI_SPEC",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:5000/me",
			Path:            "/me",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"status":"success","data":{"username":"p7usera","email":"p7usera@example.local","admin":false}}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_B",
			URL:             "http://127.0.0.1:5000/me",
			Path:            "/me",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"status":"success","data":{"username":"p7userb","email":"p7userb@example.local","admin":false}}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "ADMIN",
			URL:             "http://127.0.0.1:5000/users/v1/_debug",
			Path:            "/users/v1/_debug",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"users":[{"username":"p7usera","email":"p7usera@example.local","password":"secretA","admin":false}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:5000/books/v1",
			Path:            "/books/v1",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"Books":[{"book_title":"p7usera_book1","user":"p7usera"}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
	}

	surface := DiscoverObjectSurface("http://127.0.0.1:5000", identities, observations, 30)

	var foundBook, foundUser bool
	for _, obj := range surface.Objects {
		if obj.TemplatePath == "/users/v1/_debug/{username}" {
			t.Fatalf("unexpected synthetic _debug child object synthesized: %+v", obj)
		}
		if obj.TemplatePath == "/books/v1/{book_title}" && obj.ID == "p7usera_book1" {
			foundBook = true
			if !obj.OwnershipEstablished || obj.OwnerIdentity != "user_a" {
				t.Fatalf("expected p7usera_book1 owned by user_a via nested /me + 'user' owner field, got established=%v owner=%q", obj.OwnershipEstablished, obj.OwnerIdentity)
			}
		}
		if obj.TemplatePath == "/users/v1/{username}" && obj.ID == "p7usera" {
			foundUser = true
			if !obj.OwnershipEstablished || obj.OwnerIdentity != "user_a" {
				t.Fatalf("expected p7usera mapped from _debug onto /users/v1/{username} owned by user_a, got established=%v owner=%q", obj.OwnershipEstablished, obj.OwnerIdentity)
			}
		}
	}
	if !foundBook {
		t.Fatalf("expected book object on /books/v1/{book_title}, got %+v", surface.Objects)
	}
	if !foundUser {
		t.Fatalf("expected user object on /users/v1/{username} bound from _debug, got %+v", surface.Objects)
	}
}
