package api

import (
	"fmt"
	"net/http"
	"strings"
)

// AuthState models the observed access-control requirement of an endpoint.
type AuthState string

const (
	AuthStatePublic       AuthState = "PUBLIC"
	AuthStateAuthRequired AuthState = "AUTH_REQUIRED"
	AuthStateForbidden    AuthState = "FORBIDDEN"
	AuthStateNotFound     AuthState = "NOT_FOUND"
	AuthStateRedirect     AuthState = "REDIRECT"
	AuthStateUnknown      AuthState = "UNKNOWN"
)

// AuthStateObservation summarizes the empirical response of an unauthenticated probe.
type AuthStateObservation struct {
	State            AuthState `json:"state"`
	HTTPStatus       int       `json:"http_status"`
	NegativeEvidence string    `json:"negative_evidence,omitempty"`
	Reason           string    `json:"reason"`
}

// ReasonAuthState determines the access state based strictly on non-destructive HTTP responses.
// It enforces that Discovery != Exposure, and 401/403/404 are protective states.
func ReasonAuthState(statusCode int, respHeaders http.Header, respBody []byte) AuthStateObservation {
	switch {
	case statusCode == http.StatusOK:
		bodyStr := strings.ToLower(string(respBody))
		// If response is a generic HTML login form or single-page app shell redirecting in JS
		if strings.Contains(bodyStr, "login") && strings.Contains(bodyStr, "password") && strings.Contains(bodyStr, "<form") {
			return AuthStateObservation{
				State:            AuthStatePublic,
				HTTPStatus:       statusCode,
				NegativeEvidence: "Endpoint returned public HTML login interface; unauthenticated private data not exposed.",
				Reason:           "Endpoint is publicly accessible but serves an unauthenticated authentication interface.",
			}
		}

		return AuthStateObservation{
			State:            AuthStatePublic,
			HTTPStatus:       statusCode,
			NegativeEvidence: "",
			Reason:           "Endpoint responded with HTTP 200 OK without requiring authentication.",
		}

	case statusCode == http.StatusUnauthorized:
		return AuthStateObservation{
			State:            AuthStateAuthRequired,
			HTTPStatus:       statusCode,
			NegativeEvidence: "HTTP 401 indicates authentication is required. No unauthenticated exposure was verified.",
			Reason:           "Authentication challenge returned (HTTP 401); protected boundary active.",
		}

	case statusCode == http.StatusForbidden:
		return AuthStateObservation{
			State:            AuthStateForbidden,
			HTTPStatus:       statusCode,
			NegativeEvidence: "HTTP 403 indicates access is forbidden. No unauthenticated exposure was verified.",
			Reason:           "Access denied by authorization boundary (HTTP 403); protected resource.",
		}

	case statusCode == http.StatusNotFound:
		return AuthStateObservation{
			State:            AuthStateNotFound,
			HTTPStatus:       statusCode,
			NegativeEvidence: "HTTP 404 indicates endpoint or resource does not exist on this route.",
			Reason:           "Resource not found (HTTP 404).",
		}

	case statusCode == http.StatusMovedPermanently || statusCode == http.StatusFound ||
		statusCode == http.StatusSeeOther || statusCode == http.StatusTemporaryRedirect ||
		statusCode == http.StatusPermanentRedirect:
		location := ""
		if respHeaders != nil {
			location = respHeaders.Get("Location")
		}
		return AuthStateObservation{
			State:            AuthStateRedirect,
			HTTPStatus:       statusCode,
			NegativeEvidence: fmt.Sprintf("HTTP %d redirect observed to %s; no direct unauthenticated access.", statusCode, location),
			Reason:           fmt.Sprintf("Endpoint redirects unauthenticated clients (HTTP %d).", statusCode),
		}

	default:
		return AuthStateObservation{
			State:            AuthStateUnknown,
			HTTPStatus:       statusCode,
			NegativeEvidence: fmt.Sprintf("HTTP %d returned; access state indeterminate without further telemetry.", statusCode),
			Reason:           fmt.Sprintf("Non-standard status code: HTTP %d", statusCode),
		}
	}
}
