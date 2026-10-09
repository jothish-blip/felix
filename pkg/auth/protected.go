package auth

import (
	"fmt"
	"strings"
)

// ProtectedEndpointClassifier evaluates protection evidence for endpoints.
type ProtectedEndpointClassifier struct{}

// NewProtectedEndpointClassifier creates an instance.
func NewProtectedEndpointClassifier() *ProtectedEndpointClassifier {
	return &ProtectedEndpointClassifier{}
}

// EvaluateEndpointProtection determines whether an endpoint is protected, anonymous, or unknown
// based on observed HTTP status codes, headers, and correlated authentication surfaces.
// Safety invariant: Uses only passively observed responses or safe read-only checks; zero bypass attempts.
func (pec *ProtectedEndpointClassifier) EvaluateEndpointProtection(
	endpointPath string,
	method string,
	observedStatus int,
	authHeader string,
	locationHeader string,
	associatedSurfaces []string,
) ProtectedEndpointInfo {
	info := ProtectedEndpointInfo{
		EndpointPath:       endpointPath,
		Method:             method,
		ObservedStatus:     observedStatus,
		AuthChallenge:      authHeader,
		AssociatedSurfaces: associatedSurfaces,
		Confidence:         ConfidenceMedium,
	}

	switch {
	// 401 Unauthorized with WWW-Authenticate header is confirmed protection
	case observedStatus == 401:
		info.ProtectionStatus = "CONFIRMED_PROTECTED"
		info.Confidence = ConfidenceHigh
		if authHeader != "" {
			info.Explanation = fmt.Sprintf("HTTP 401 challenge returned with authentication scheme: %s", authHeader)
		} else {
			info.Explanation = "HTTP 401 Unauthorized returned when accessed anonymously"
		}

	// 403 Forbidden indicates access barrier
	case observedStatus == 403:
		info.ProtectionStatus = "CONFIRMED_PROTECTED"
		info.Confidence = ConfidenceHigh
		info.Explanation = "HTTP 403 Forbidden returned for unauthenticated request"

	// 302/307 Redirect to a login gateway
	case (observedStatus == 301 || observedStatus == 302 || observedStatus == 307 || observedStatus == 308) &&
		(strings.Contains(strings.ToLower(locationHeader), "login") || strings.Contains(strings.ToLower(locationHeader), "signin")):
		info.ProtectionStatus = "INFERRED_PROTECTED"
		info.Confidence = ConfidenceHigh
		info.Explanation = fmt.Sprintf("Anonymous request redirected to authentication portal (%s)", locationHeader)

	// 200 OK on an endpoint correlated with authentication surfaces
	case observedStatus == 200 && len(associatedSurfaces) > 0:
		info.ProtectionStatus = "ANONYMOUS_ACCESSIBLE"
		info.Confidence = ConfidenceMedium
		info.Explanation = "Endpoint returned HTTP 200 OK without authentication challenge despite authentication indicators"

	// 200 OK on standard endpoints
	case observedStatus == 200:
		info.ProtectionStatus = "ANONYMOUS_ACCESSIBLE"
		info.Confidence = ConfidenceLow
		info.Explanation = "Endpoint accessible anonymously"

	default:
		info.ProtectionStatus = "UNKNOWN"
		info.Confidence = ConfidenceLow
		info.Explanation = fmt.Sprintf("Observed status code %d provides insufficient protection evidence", observedStatus)
	}

	return info
}
