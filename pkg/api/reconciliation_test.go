package api_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"felix/pkg/api"
	"felix/pkg/crawler"
)

// 1. Exact documented method and path match
func TestP14_2_ExactDocumentedMatch(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Users API", "version": "1.0.0" },
		"paths": {
			"/api/v1/users/{id}": {
				"get": {
					"operationId": "getUserById",
					"summary": "Get user by ID"
				}
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, err := parser.ParseSpecificationData([]byte(specJSON), "users.json")
	if err != nil {
		t.Fatalf("ParseSpecificationData failed: %v", err)
	}

	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-1",
			Path:             "/api/v1/users/{param}",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/bundle.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if report.TotalDocumentedMatches != 1 {
		t.Fatalf("Expected 1 documented match, got %d", report.TotalDocumentedMatches)
	}

	item := report.Items[0]
	if item.Classification != api.ClassificationDocumentedMatch {
		t.Errorf("Expected DOCUMENTED_MATCH, got %s", item.Classification)
	}
	if item.Priority != api.PriorityDocumented {
		t.Errorf("Expected DOCUMENTED priority, got %s", item.Priority)
	}
	if item.MatchedOperationID != "getUserById" {
		t.Errorf("Expected operation ID getUserById, got %s", item.MatchedOperationID)
	}
}

// 2. Documented path with a different HTTP method
func TestP14_2_DocumentedPathDifferentMethod(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Orders API", "version": "1.0.0" },
		"paths": {
			"/api/v1/orders/{id}": {
				"get": { "operationId": "getOrder" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "orders.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	// Candidate uses DELETE on documented GET path
	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-2",
			Path:             "/api/v1/orders/{param}",
			HTTPMethod:       "DELETE",
			OriginatingAsset: "https://app.local/admin.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if report.TotalUndocumentedCandidates != 1 {
		t.Fatalf("Expected 1 undocumented candidate, got %d", report.TotalUndocumentedCandidates)
	}

	item := report.Items[0]
	if item.Classification != api.ClassificationUndocumentedCandidate {
		t.Errorf("Expected UNDOCUMENTED_CANDIDATE, got %s", item.Classification)
	}
	if item.Priority != api.PriorityHighShadow {
		t.Errorf("Expected HIGH_PRIORITY_SHADOW for undocumented DELETE, got %s", item.Priority)
	}
	if !strings.Contains(item.MatchRationale, "documented under method(s) GET") {
		t.Errorf("Expected rationale to mention documented GET method, got: %s", item.MatchRationale)
	}
}

// 3. Equivalent parameter notation across OpenAPI and discovered routes
func TestP14_2_ParameterEquivalence(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Items API", "version": "1.0.0" },
		"paths": {
			"/items/{itemId}": {
				"get": { "operationId": "getItem" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "items.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	// Route discovered as /items/:itemId or /items/[itemId]
	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-3",
			Path:             "/items/:itemId",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/app.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if report.TotalDocumentedMatches != 1 {
		t.Fatalf("Expected 1 documented match for colon parameter, got %d", report.TotalDocumentedMatches)
	}
	if report.Items[0].Classification != api.ClassificationDocumentedMatch {
		t.Errorf("Expected DOCUMENTED_MATCH, got %s", report.Items[0].Classification)
	}
}

// 4. Different API versions that must not be merged
func TestP14_2_DifferentAPIVersionsNotMerged(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "API v1", "version": "1.0.0" },
		"paths": {
			"/api/v1/reports": {
				"get": { "operationId": "getReportsV1" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "v1.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-4",
			Path:             "/api/v2/reports",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/v2.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if report.TotalDocumentedMatches != 0 {
		t.Errorf("V2 route incorrectly matched V1 documented operation")
	}
	if report.TotalUndocumentedCandidates != 1 {
		t.Errorf("Expected 1 undocumented candidate for V2 route, got %d", report.TotalUndocumentedCandidates)
	}
}

// 5. Same path on distinct service origins
func TestP14_2_DistinctServiceOrigins(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Internal Admin API", "version": "1.0.0" },
		"servers": [{ "url": "https://admin.internal.net" }],
		"paths": {
			"/status": {
				"get": { "operationId": "getAdminStatus" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "admin.json")
	if len(meta.Servers) == 0 || meta.Servers[0] != "https://admin.internal.net" {
		t.Errorf("Expected server origin https://admin.internal.net, got %v", meta.Servers)
	}
	if len(ops) == 0 {
		t.Fatalf("Expected operations from admin spec, got 0")
	}
}

// 6. Unknown HTTP method produces ambiguous classification
func TestP14_2_UnknownHTTPMethodAmbiguous(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Checkout API", "version": "1.0.0" },
		"paths": {
			"/api/v1/checkout": {
				"post": { "operationId": "createCheckout" },
				"get": { "operationId": "getCheckout" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "checkout.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-6",
			Path:             "/api/v1/checkout",
			HTTPMethod:       "UNKNOWN",
			OriginatingAsset: "https://app.local/cart.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if report.TotalAmbiguousMatches != 1 {
		t.Fatalf("Expected 1 ambiguous match, got %d", report.TotalAmbiguousMatches)
	}

	item := report.Items[0]
	if item.Classification != api.ClassificationAmbiguousMatch {
		t.Errorf("Expected AMBIGUOUS_MATCH, got %s", item.Classification)
	}
	if item.Priority != api.PriorityAmbiguous {
		t.Errorf("Expected AMBIGUOUS priority, got %s", item.Priority)
	}
}

// 7. Multiple possible specification matches
func TestP14_2_MultiplePossibleMatches(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Multi Method", "version": "1.0.0" },
		"paths": {
			"/api/v1/items/{id}": {
				"get": { "operationId": "getItem" },
				"put": { "operationId": "updateItem" },
				"delete": { "operationId": "deleteItem" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "multi.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-7",
			Path:             "/api/v1/items/{param}",
			HTTPMethod:       "UNKNOWN",
			OriginatingAsset: "https://app.local/items.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	item := report.Items[0]
	if len(item.AmbiguousMatches) != 3 {
		t.Errorf("Expected 3 ambiguous operation matches, got %d", len(item.AmbiguousMatches))
	}
}

// 8. Multiple specifications with conflicting operations
func TestP14_2_ConflictingSpecifications(t *testing.T) {
	spec1 := `{
		"openapi": "3.0.0",
		"info": { "title": "Service Spec A", "version": "1.0.0" },
		"paths": {
			"/api/v1/webhook": {
				"post": { "operationId": "handleWebhookA", "parameters": [{"name": "sig", "in": "header"}] }
			}
		}
	}`
	spec2 := `{
		"openapi": "3.0.0",
		"info": { "title": "Service Spec B", "version": "1.0.0" },
		"paths": {
			"/api/v1/webhook": {
				"post": { "operationId": "handleWebhookB" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops1, meta1, _ := parser.ParseSpecificationData([]byte(spec1), "specA.json")
	ops2, meta2, _ := parser.ParseSpecificationData([]byte(spec2), "specB.json")

	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta1, *meta2}, append(ops1, ops2...), api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-8",
			Path:             "/api/v1/webhook",
			HTTPMethod:       "POST",
			OriginatingAsset: "https://app.local/webhook.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	item := report.Items[0]
	if item.Classification != api.ClassificationAmbiguousMatch {
		t.Errorf("Expected AMBIGUOUS_MATCH due to conflicting specs, got %s", item.Classification)
	}
}

// 9. Missing, malformed, or unsupported specifications
func TestP14_2_MalformedSpecificationSafety(t *testing.T) {
	malformedJSON := `{"openapi": "3.0.0", "paths": { unclosed ...`

	parser := api.NewSpecParser()
	ops, meta, err := parser.ParseSpecificationData([]byte(malformedJSON), "broken.json")
	if err == nil {
		t.Errorf("Expected error for malformed specification JSON")
	}
	if meta.Format != "MALFORMED" {
		t.Errorf("Expected MALFORMED format, got %s", meta.Format)
	}

	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-9",
			Path:             "/api/v1/users",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/app.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	item := report.Items[0]
	if item.Classification != api.ClassificationUnsupportedOrUnparsed {
		t.Errorf("Expected UNSUPPORTED_OR_UNPARSED, got %s", item.Classification)
	}
	if report.TotalUndocumentedCandidates != 0 {
		t.Errorf("Malformed spec should NOT declare 100%% shadow candidates")
	}
}

// 10. Cyclic local $ref resolution
func TestP14_2_CyclicLocalRefResolution(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "Cyclic API", "version": "1.0.0" },
		"paths": {
			"/api/v1/cyclic": {
				"$ref": "#/components/schemas/NodeA"
			}
		},
		"components": {
			"schemas": {
				"NodeA": {
					"$ref": "#/components/schemas/NodeB"
				},
				"NodeB": {
					"$ref": "#/components/schemas/NodeA"
				}
			}
		}
	}`

	parser := api.NewSpecParser()
	_, meta, err := parser.ParseSpecificationData([]byte(specJSON), "cyclic.json")
	if err != nil {
		t.Fatalf("Parser crashed on cyclic $ref: %v", err)
	}

	foundCycleWarning := false
	for _, w := range meta.Warnings {
		if strings.Contains(w, "Cyclic $ref detected") {
			foundCycleWarning = true
		}
	}
	if !foundCycleWarning {
		t.Errorf("Expected cyclic $ref warning, got: %v", meta.Warnings)
	}
}

// 11. External $ref that must not be fetched automatically
func TestP14_2_ExternalRefBlocked(t *testing.T) {
	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "External Ref API", "version": "1.0.0" },
		"paths": {
			"/api/v1/ext": {
				"$ref": "https://evil.attacker.com/pwn.json"
			}
		}
	}`

	parser := api.NewSpecParser()
	_, meta, err := parser.ParseSpecificationData([]byte(specJSON), "external.json")
	if err != nil {
		t.Fatalf("Parser error: %v", err)
	}

	foundBlockedWarning := false
	for _, w := range meta.Warnings {
		if strings.Contains(w, "External $ref") && strings.Contains(w, "blocked") {
			foundBlockedWarning = true
		}
	}
	if !foundBlockedWarning {
		t.Errorf("Expected external $ref blocked warning, got: %v", meta.Warnings)
	}
}

// 12. Path with user_id or userId
func TestP14_2_SensitiveUserIDDetection(t *testing.T) {
	hits1 := api.DetectSensitiveIdentifiers("/api/v1/users/{userId}/profile", nil, nil, "")
	if len(hits1) == 0 || hits1[0].Type != api.SensitiveTypeUserID {
		t.Fatalf("Expected USER_ID detection for userId, got: %+v", hits1)
	}

	hits2 := api.DetectSensitiveIdentifiers("/api/v1/users/{user_id}/settings", nil, nil, "")
	if len(hits2) == 0 || hits2[0].Type != api.SensitiveTypeUserID {
		t.Fatalf("Expected USER_ID detection for user_id, got: %+v", hits2)
	}
}

// 13. Path or schema containing tenant_id, org_id, or role
func TestP14_2_SensitiveTenantOrgRoleDetection(t *testing.T) {
	path := "/api/v1/tenants/{tenant_id}/orgs/{org_id}/roles"
	hits := api.DetectSensitiveIdentifiers(path, nil, nil, "")

	foundTenant := false
	foundOrg := false
	foundRole := false

	for _, h := range hits {
		if h.Type == api.SensitiveTypeTenantID {
			foundTenant = true
		}
		if h.Type == api.SensitiveTypeOrgID {
			foundOrg = true
		}
		if h.Type == api.SensitiveTypeRole {
			foundRole = true
		}
	}

	if !foundTenant || !foundOrg || !foundRole {
		t.Errorf("Expected tenant_id, org_id, and role detection; got: %+v", hits)
	}
}

// 14. False-positive substrings that should NOT trigger sensitive-identifier classification
func TestP14_2_FalsePositiveSubstringsIgnored(t *testing.T) {
	falsePositivePaths := []string{
		"/api/v1/controller/status",
		"/api/v1/payroll/export",
		"/api/v1/enrolled/students",
		"/api/v1/proletariat/history",
		"/api/v1/protocol/settings",
	}

	for _, fp := range falsePositivePaths {
		hits := api.DetectSensitiveIdentifiers(fp, nil, nil, "")
		for _, h := range hits {
			if h.Type == api.SensitiveTypeRole {
				t.Fatalf("False positive: %q incorrectly matched ROLE identifier: %+v", fp, h)
			}
		}
	}
}

// 15. Repeated discovery of one endpoint from multiple bundles
func TestP14_2_RepeatedDiscoveryProvenancePreserved(t *testing.T) {
	engine := api.NewReconciliationEngine([]api.SpecMetadata{{Source: "empty.json"}}, nil, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-A",
			Path:             "/api/v1/shared",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/bundle1.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
		{
			ID:               "RCAND-B",
			Path:             "/api/v1/shared",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/bundle2.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if len(report.Items) != 1 {
		t.Fatalf("Expected exactly 1 deduplicated item, got %d", len(report.Items))
	}

	item := report.Items[0]
	foundProvenanceNotice := false
	for _, w := range item.Warnings {
		if strings.Contains(w, "Observed across 2 independent discovery locations") {
			foundProvenanceNotice = true
		}
	}
	if !foundProvenanceNotice {
		t.Errorf("Expected multi-bundle provenance notice in item warnings, got: %v", item.Warnings)
	}
}

// 16. Candidate discovered only through a weak or inferred string
func TestP14_2_WeakInferredCandidateHandling(t *testing.T) {
	engine := api.NewReconciliationEngine([]api.SpecMetadata{{Source: "spec.json"}}, nil, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-16",
			Path:             "/api/v1/heuristic",
			HTTPMethod:       "UNKNOWN",
			OriginatingAsset: "https://app.local/app.js",
			Confidence:       crawler.ConfidenceHeuristic,
		},
	}

	report := engine.Reconcile(candidates)
	item := report.Items[0]
	if item.Classification != api.ClassificationIncompleteEvidence {
		t.Errorf("Expected INCOMPLETE_EVIDENCE for heuristic candidate, got %s", item.Classification)
	}
	if item.Priority != api.PriorityLowShadow {
		t.Errorf("Expected LOW_PRIORITY_SHADOW, got %s", item.Priority)
	}
}

// 17. Static assets and non-API strings
func TestP14_2_StaticAssetsHandledGracefully(t *testing.T) {
	engine := api.NewReconciliationEngine([]api.SpecMetadata{{Source: "spec.json"}}, nil, api.DefaultReconciliationOptions())

	candidates := []crawler.RouteCandidate{
		{
			ID:               "RCAND-17",
			Path:             "/assets/logo.png",
			HTTPMethod:       "GET",
			OriginatingAsset: "https://app.local/app.js",
			Confidence:       crawler.ConfidenceConfirmed,
		},
	}

	report := engine.Reconcile(candidates)
	if len(report.Items) != 1 {
		t.Errorf("Expected 1 item, got %d", len(report.Items))
	}
}

// 18. Secret values in query strings, schemas, or source metadata
func TestP14_2_SecretValuesRedactedInEvidence(t *testing.T) {
	rawEvidence := "fetch(/api/v1/export?token=secretXYZ123&api_key=KEY999)"
	hits := api.DetectSensitiveIdentifiers("/api/v1/export", []string{"token=secretXYZ123"}, nil, rawEvidence)

	for _, h := range hits {
		if strings.Contains(h.RawEvidence, "secretXYZ123") {
			t.Errorf("Secret value was not redacted in evidence: %s", h.RawEvidence)
		}
	}
}

// 19. Large specifications and excessive reference depth
func TestP14_2_MaxReferenceDepthProtection(t *testing.T) {
	// Build a chain of 25 nested references: Schema0 -> Schema1 -> ... -> Schema25
	schemas := make(map[string]any)
	for i := 0; i < 25; i++ {
		schemas[fmt.Sprintf("Schema%d", i)] = map[string]any{
			"$ref": fmt.Sprintf("#/components/schemas/Schema%d", i+1),
		}
	}
	schemas["Schema25"] = map[string]any{
		"type": "string",
	}

	spec := map[string]any{
		"openapi": "3.0.0",
		"info":    map[string]any{"title": "Deep Spec", "version": "1.0"},
		"paths": map[string]any{
			"/api/v1/deep": map[string]any{
				"$ref": "#/components/schemas/Schema0",
			},
		},
		"components": map[string]any{
			"schemas": schemas,
		},
	}

	data, _ := json.Marshal(spec)
	parser := api.NewSpecParser()
	_, meta, err := parser.ParseSpecificationData(data, "deep.json")
	if err != nil {
		t.Fatalf("Parser crashed on deep reference: %v", err)
	}

	foundDepthWarning := false
	for _, w := range meta.Warnings {
		if strings.Contains(w, "Maximum $ref resolution depth exceeded") {
			foundDepthWarning = true
		}
	}
	if !foundDepthWarning {
		t.Errorf("Expected maximum $ref depth warning, got: %v", meta.Warnings)
	}
}

// 20. Existing P14.1 integration and backward-compatibility regression tests
func TestP14_2_P14_1_Integration(t *testing.T) {
	// Sample JavaScript bundle parsed by P14.1
	js := `
		axios.get("/api/v1/users/{param}");
		fetch("/api/v1/tenants/123/billing", { method: "POST" });
		fetch("/api/v1/undocumented-route");
	`

	opts := crawler.DefaultBundleAnalysisOptions()
	extractor := crawler.NewBundleExtractor(opts)
	candidates, _, _, _ := extractor.ExtractFromBundle([]byte(js), "https://app.local/bundle.js")

	specJSON := `{
		"openapi": "3.0.0",
		"info": { "title": "App API", "version": "1.0.0" },
		"paths": {
			"/api/v1/users/{id}": {
				"get": { "operationId": "getUsers" }
			}
		}
	}`

	parser := api.NewSpecParser()
	ops, meta, _ := parser.ParseSpecificationData([]byte(specJSON), "spec.json")
	engine := api.NewReconciliationEngine([]api.SpecMetadata{*meta}, ops, api.DefaultReconciliationOptions())

	report := engine.Reconcile(candidates)

	if report.TotalDocumentedMatches != 1 {
		t.Errorf("Expected 1 documented match, got %d", report.TotalDocumentedMatches)
	}
	if report.TotalUndocumentedCandidates < 2 {
		t.Errorf("Expected at least 2 undocumented candidates, got %d", report.TotalUndocumentedCandidates)
	}

	// Verify tenant billing route was prioritized due to tenant identifier + POST mutation
	foundTenantShadow := false
	for _, ss := range report.ShadowSurface {
		if strings.Contains(ss.Path, "billing") {
			foundTenantShadow = true
			if ss.Priority != api.PriorityCriticalShadow && ss.Priority != api.PriorityHighShadow {
				t.Errorf("Expected Critical or High priority for tenant billing route, got: %s", ss.Priority)
			}
		}
	}
	if !foundTenantShadow {
		t.Errorf("Expected tenant billing route in shadow surface list")
	}
}

// Test YAML Specification parsing (OpenAPI 3.0 YAML)
func TestP14_2_YAMLSpecificationParsing(t *testing.T) {
	yamlSpec := `
openapi: 3.0.0
info:
  title: "YAML Users API"
  version: "1.0.0"
servers:
  - url: /api/v1
paths:
  /users:
    get:
      summary: "List users"
      operationId: listUsers
    post:
      summary: "Create user"
      operationId: createUser
  /tenants/{tenant_id}/users:
    get:
      summary: "List tenant users"
`
	tmpDir := t.TempDir()
	specFile := filepath.Join(tmpDir, "spec.yaml")
	if err := os.WriteFile(specFile, []byte(yamlSpec), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	parser := api.NewSpecParser()
	ops, meta, err := parser.ParseSpecificationFile(specFile)
	if err != nil {
		t.Fatalf("ParseSpecificationFile failed: %v", err)
	}

	if meta.Title != "YAML Users API" {
		t.Errorf("Expected title 'YAML Users API', got %q", meta.Title)
	}
	if len(ops) < 3 {
		t.Errorf("Expected at least 3 operations from YAML spec, got %d", len(ops))
	}
}
