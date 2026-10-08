package api

import (
	"path"
	"strings"
)

// EndpointClassification represents the functional category of an endpoint.
type EndpointClassification string

// Standard endpoint classification categories.
const (
	ClassAuth           EndpointClassification = "AUTH"
	ClassAuthentication EndpointClassification = "AUTHENTICATION"
	ClassAuthorization  EndpointClassification = "AUTHORIZATION"
	ClassUser           EndpointClassification = "USER"
	ClassAdmin          EndpointClassification = "ADMIN"
	ClassAccount        EndpointClassification = "ACCOUNT"
	ClassPayment        EndpointClassification = "PAYMENT"
	ClassAPI            EndpointClassification = "API"
	ClassGraphQL        EndpointClassification = "GRAPHQL"
	ClassUpload         EndpointClassification = "UPLOAD"
	ClassDownload       EndpointClassification = "DOWNLOAD"
	ClassSearch         EndpointClassification = "SEARCH"
	ClassWebhook        EndpointClassification = "WEBHOOK"
	ClassHealth         EndpointClassification = "HEALTH"
	ClassMetrics        EndpointClassification = "METRICS"
	ClassDocumentation  EndpointClassification = "DOCUMENTATION"
	ClassStatic         EndpointClassification = "STATIC"
	ClassUnknown        EndpointClassification = "UNKNOWN"
)

// ClassifyEndpoint applies conservative signal-based rules to categorize an endpoint.
// Classification is purely informational and NEVER increases severity by itself.
func ClassifyEndpoint(rawPath string) EndpointClassification {
	clean := strings.ToLower(strings.TrimSpace(rawPath))
	if clean == "" || clean == "/" {
		return ClassUnknown
	}

	// 1. Static asset extension check
	ext := path.Ext(clean)
	switch ext {
	case ".js", ".mjs", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".webp", ".map":
		return ClassStatic
	}

	// 2. GraphQL
	if strings.Contains(clean, "graphql") {
		return ClassGraphQL
	}

	// 3. Documentation (OpenAPI, Swagger, API docs)
	if strings.Contains(clean, "swagger") || strings.Contains(clean, "openapi") ||
		strings.Contains(clean, "api-docs") || strings.Contains(clean, "apidocs") ||
		strings.Contains(clean, "api-spec") || strings.Contains(clean, "redoc") {
		return ClassDocumentation
	}

	// 4. Operational Telemetry: Health & Metrics
	if strings.Contains(clean, "health") || strings.Contains(clean, "healthz") ||
		strings.Contains(clean, "livez") || strings.Contains(clean, "readyz") ||
		strings.HasSuffix(clean, "/ping") || strings.HasSuffix(clean, "/status") {
		return ClassHealth
	}
	if strings.Contains(clean, "metrics") || strings.Contains(clean, "prometheus") ||
		strings.Contains(clean, "actuator/prometheus") {
		return ClassMetrics
	}

	// 5. Admin & Management
	if strings.Contains(clean, "/admin") || strings.HasPrefix(clean, "admin") ||
		strings.Contains(clean, "/dashboard/admin") || strings.Contains(clean, "/manage") ||
		strings.Contains(clean, "/management") || strings.Contains(clean, "/control") {
		return ClassAdmin
	}

	// 6. Authentication & Authorization
	if strings.Contains(clean, "login") || strings.Contains(clean, "signin") ||
		strings.Contains(clean, "sign-in") || strings.Contains(clean, "signup") ||
		strings.Contains(clean, "sign-up") || strings.Contains(clean, "register") ||
		strings.Contains(clean, "logout") || strings.Contains(clean, "signout") ||
		strings.Contains(clean, "sign-out") || strings.Contains(clean, "oauth") ||
		strings.Contains(clean, "/auth/session") || strings.Contains(clean, "/auth/token") ||
		strings.Contains(clean, "saml") {
		return ClassAuthentication
	}
	if strings.Contains(clean, "authorize") || strings.Contains(clean, "permissions") ||
		strings.Contains(clean, "roles") || strings.Contains(clean, "rbac") {
		return ClassAuthorization
	}
	if strings.Contains(clean, "/auth") || strings.HasPrefix(clean, "auth") {
		return ClassAuth
	}

	// 7. User & Identity
	if strings.Contains(clean, "/users") || strings.Contains(clean, "/user") ||
		strings.Contains(clean, "/profile") || strings.Contains(clean, "/members") ||
		strings.Contains(clean, "/member") {
		return ClassUser
	}

	// 8. Account & Settings
	if strings.Contains(clean, "/account") || strings.Contains(clean, "/settings") ||
		strings.Contains(clean, "/preferences") {
		return ClassAccount
	}

	// 9. Webhooks & Callbacks
	if strings.Contains(clean, "webhook") || strings.Contains(clean, "callback") ||
		strings.Contains(clean, "notify") {
		return ClassWebhook
	}

	// 10. Payment & Billing
	if strings.Contains(clean, "payment") || strings.Contains(clean, "billing") ||
		strings.Contains(clean, "checkout") || strings.Contains(clean, "invoice") ||
		strings.Contains(clean, "subscription") || strings.Contains(clean, "stripe") ||
		strings.Contains(clean, "paypal") || strings.Contains(clean, "cart") {
		return ClassPayment
	}

	// 11. File Transfer: Upload & Download
	if strings.Contains(clean, "upload") || strings.Contains(clean, "attachment") {
		return ClassUpload
	}
	if strings.Contains(clean, "download") || strings.Contains(clean, "export") ||
		strings.Contains(clean, "backup") || strings.Contains(clean, "dump") {
		return ClassDownload
	}

	// 12. Search & Query
	if strings.Contains(clean, "search") || strings.Contains(clean, "query") ||
		strings.Contains(clean, "filter") {
		return ClassSearch
	}

	// 13. General API
	if strings.HasPrefix(clean, "/api") || strings.HasPrefix(clean, "/v1") ||
		strings.HasPrefix(clean, "/v2") || strings.HasPrefix(clean, "/v3") ||
		strings.Contains(clean, "/rest/v") {
		return ClassAPI
	}

	return ClassUnknown
}
