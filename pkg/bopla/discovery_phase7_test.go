package bopla

import (
	"testing"
)

func TestPhase7_BOPLA_PlaintextPasswordAndNestedOpenAPISchema(t *testing.T) {
	openAPI := `{
		"openapi": "3.0.1",
		"paths": {
			"/users/v1/_debug": {
				"get": {
					"responses": {
						"200": {
							"description": "Users debug",
							"content": {
								"application/json": {
									"schema": {
										"type": "object",
										"properties": {
											"users": {
												"type": "array",
												"items": {
													"type": "object",
													"properties": {
														"username": {"type": "string"},
														"password": {"type": "string", "x-admin-only": true},
														"admin": {"type": "boolean"}
													}
												}
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	}`

	identities := []TestIdentity{
		{Alias: "ADMIN", Role: "admin", PrivilegeLevel: 5},
		{Alias: "USER_A", Role: "user", PrivilegeLevel: 1},
		{Alias: "ANONYMOUS", Role: "anonymous", PrivilegeLevel: 0},
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
			Identity:        "ADMIN",
			URL:             "http://127.0.0.1:5000/users/v1/_debug",
			Path:            "/users/v1/_debug",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"users":[{"username":"name1","password":"pass1","admin":false}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
		{
			Identity:        "USER_A",
			URL:             "http://127.0.0.1:5000/users/v1/_debug",
			Path:            "/users/v1/_debug",
			Method:          "GET",
			StatusCode:      200,
			ContentType:     "application/json",
			Body:            []byte(`{"users":[{"username":"name1","password":"pass1","admin":false}]}`),
			DiscoveryMethod: "JS_ROUTE_CANDIDATE",
			Classification:  "CONFIRMED_ENDPOINT",
		},
	}

	surface := DiscoverPropertySurface("http://127.0.0.1:5000", identities, observations, 30)
	var foundPassword bool
	for _, pol := range surface.Policies {
		if pol.Endpoint == "/users/v1/_debug" && pol.PropertyPath == "users[0].password" {
			foundPassword = true
			if pol.PolicyUnestablished {
				t.Fatalf("expected users[0].password policy to be established, got PolicyUnestablished=true")
			}
		}
	}
	if !foundPassword {
		t.Fatalf("expected BOPLA read policy for users[0].password on /users/v1/_debug, got %+v", surface.Policies)
	}
}
