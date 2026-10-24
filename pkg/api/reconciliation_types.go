package api

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"felix/pkg/crawler"
)

// MatchClassification defines the outcome of reconciling a discovered route against API specifications.
type MatchClassification string

const (
	ClassificationDocumentedMatch       MatchClassification = "DOCUMENTED_MATCH"
	ClassificationUndocumentedCandidate MatchClassification = "UNDOCUMENTED_CANDIDATE"
	ClassificationAmbiguousMatch        MatchClassification = "AMBIGUOUS_MATCH"
	ClassificationIncompleteEvidence    MatchClassification = "INCOMPLETE_EVIDENCE"
	ClassificationUnsupportedOrUnparsed MatchClassification = "UNSUPPORTED_OR_UNPARSED"
)

// ShadowPriority represents the risk and triage priority of an undocumented or shadow API candidate.
type ShadowPriority string

const (
	PriorityCriticalShadow ShadowPriority = "CRITICAL_SHADOW"     // High confidence, concrete method, sensitive identifier in path
	PriorityHighShadow     ShadowPriority = "HIGH_PRIORITY_SHADOW" // High confidence, concrete method, first-class API endpoint
	PriorityStandardShadow ShadowPriority = "STANDARD_SHADOW"      // Documented or read-only endpoint, moderate sensitivity
	PriorityLowShadow      ShadowPriority = "LOW_PRIORITY_SHADOW"   // Weak inference or low confidence candidate
	PriorityAmbiguous      ShadowPriority = "AMBIGUOUS"            // Method unknown or multiple conflicting matches
	PriorityDocumented     ShadowPriority = "DOCUMENTED"           // Verified match against specification
	PriorityIncomplete     ShadowPriority = "INCOMPLETE"           // Incomplete specification or missing baseline
)

// SensitiveIdentifierType classifies identifiers relevant to authorization boundaries.
type SensitiveIdentifierType string

const (
	SensitiveTypeUserID      SensitiveIdentifierType = "USER_ID"
	SensitiveTypeAccountID   SensitiveIdentifierType = "ACCOUNT_ID"
	SensitiveTypeTenantID    SensitiveIdentifierType = "TENANT_ID"
	SensitiveTypeOrgID       SensitiveIdentifierType = "ORG_ID"
	SensitiveTypeRole        SensitiveIdentifierType = "ROLE"
	SensitiveTypeWorkspaceID SensitiveIdentifierType = "WORKSPACE_ID"
	SensitiveTypeProjectID   SensitiveIdentifierType = "PROJECT_ID"
)

// SensitiveIdentifierHit records evidence of an authorization-relevant parameter or property.
type SensitiveIdentifierHit struct {
	Type        SensitiveIdentifierType `json:"type"`
	MatchedTerm string                  `json:"matched_term"`
	Location    string                  `json:"location"` // "PATH", "QUERY", "SCHEMA", "EVIDENCE"
	RawEvidence string                  `json:"raw_evidence"`
}

// DocumentedOperation models a single HTTP operation defined within an OpenAPI or Swagger specification.
type DocumentedOperation struct {
	ID             string                   `json:"id"`
	SpecSource     string                   `json:"spec_source"`
	SpecTitle      string                   `json:"spec_title"`
	SpecVersion    string                   `json:"spec_version"`
	Origin         string                   `json:"origin,omitempty"`
	Method         string                   `json:"method"`
	Path           string                   `json:"path"`
	CanonicalPath  string                   `json:"canonical_path"`
	OperationID    string                   `json:"operation_id,omitempty"`
	Summary        string                   `json:"summary,omitempty"`
	Description    string                   `json:"description,omitempty"`
	Parameters     []string                 `json:"parameters,omitempty"`
	SensitiveHits  []SensitiveIdentifierHit `json:"sensitive_hits,omitempty"`
}

// SpecMetadata captures provenance and health metrics for a parsed API specification.
type SpecMetadata struct {
	Source        string   `json:"source"`
	Title         string   `json:"title"`
	Version       string   `json:"version"`
	Format        string   `json:"format"` // "OPENAPI_3_0", "OPENAPI_3_1", "SWAGGER_2_0", "MALFORMED"
	Servers       []string `json:"servers,omitempty"`
	OperationsCount int    `json:"operations_count"`
	Warnings      []string `json:"warnings,omitempty"`
}

// ReconciliationItem represents the audit and reconciliation outcome for an individual route candidate.
type ReconciliationItem struct {
	CandidateID             string                    `json:"candidate_id"`
	Method                  string                    `json:"method"`
	Path                    string                    `json:"path"`
	CanonicalPath           string                    `json:"canonical_path"`
	RawPath                 string                    `json:"raw_path"`
	OriginatingAsset        string                    `json:"originating_asset"`
	DiscoverySource         string                    `json:"discovery_source"`
	DiscoveryConfidence     string                    `json:"discovery_confidence"`
	Classification          MatchClassification       `json:"classification"`
	MatchRationale          string                    `json:"match_rationale"`
	Priority                ShadowPriority            `json:"priority"`
	PriorityRationale       string                    `json:"priority_rationale"`
	MatchedSpec             string                    `json:"matched_spec,omitempty"`
	MatchedOperationID      string                    `json:"matched_operation_id,omitempty"`
	MatchedOperation        *DocumentedOperation      `json:"matched_operation,omitempty"`
	AmbiguousMatches        []DocumentedOperation     `json:"ambiguous_matches,omitempty"`
	SensitiveHits           []SensitiveIdentifierHit  `json:"sensitive_hits,omitempty"`
	ServerAction            *crawler.ServerActionReference `json:"server_action,omitempty"`
	DiscoveredAt            time.Time                 `json:"discovered_at"`
	Warnings                []string                  `json:"warnings,omitempty"`
}

// ReconciliationReport compiles the complete topology reconciliation results.
type ReconciliationReport struct {
	TotalDiscoveredCandidates   int                  `json:"total_discovered_candidates"`
	TotalDocumentedOperations   int                  `json:"total_documented_operations"`
	TotalDocumentedMatches      int                  `json:"total_documented_matches"`
	TotalUndocumentedCandidates int                  `json:"total_undocumented_candidates"`
	TotalAmbiguousMatches       int                  `json:"total_ambiguous_matches"`
	TotalIncompleteEvidence     int                  `json:"total_incomplete_evidence"`
	TotalSensitiveShadowRoutes  int                  `json:"total_sensitive_shadow_routes"`
	Specifications              []SpecMetadata       `json:"specifications"`
	Items                       []ReconciliationItem `json:"items"`
	ShadowSurface               []ReconciliationItem `json:"shadow_surface"`
	Warnings                    []string             `json:"warnings,omitempty"`
}

// GenerateOperationID generates a deterministic identifier for a documented operation.
func GenerateOperationID(method, path, specSource string) string {
	raw := fmt.Sprintf("%s|%s|%s", strings.ToUpper(strings.TrimSpace(method)), strings.TrimSpace(path), strings.TrimSpace(specSource))
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("OP-%s", hex.EncodeToString(h[:8]))
}
